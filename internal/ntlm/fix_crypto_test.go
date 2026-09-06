package ntlm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ntlmv2Response builds a minimal NTLMv2 response blob whose AV list carries
// the given MsvAvFlags value (or no MsvAvFlags pair at all when hasFlags is
// false).
func ntlmv2Response(avFlags uint32, hasFlags bool) []byte {
	var pairs []AVPair
	pairs = append(pairs, AVPair{ID: AVNbComputerName, Value: UTF16LE("SERVER")})
	if hasFlags {
		v := make([]byte, 4)
		binary.LittleEndian.PutUint32(v, avFlags)
		pairs = append(pairs, AVPair{ID: AVFlags, Value: v})
	}
	resp := make([]byte, 16+28)
	for i := range resp {
		resp[i] = byte(i)
	}
	return append(resp, EncodeAVList(pairs)...)
}

func TestMICRequired(t *testing.T) {
	if !MICRequired(ntlmv2Response(AVFlagMICPresent, true)) {
		t.Error("MsvAvFlags with the MIC bit set should require a MIC")
	}
	if MICRequired(ntlmv2Response(0x00000001, true)) {
		t.Error("MsvAvFlags without the MIC bit should not require a MIC")
	}
	if MICRequired(ntlmv2Response(0, false)) {
		t.Error("absent MsvAvFlags should not require a MIC")
	}
	if MICRequired(nil) {
		t.Error("empty NT response should not require a MIC")
	}
	if MICRequired(make([]byte, 20)) {
		t.Error("truncated NT response should not require a MIC")
	}
}

// buildAuthenticate assembles a type-3 message with an 88-byte fixed part
// (version + MIC) and the payloads laid out contiguously after it.
func buildAuthenticate(ntResponse []byte, mic [16]byte) []byte {
	return buildAuthenticateFixed(88, ntResponse, mic)
}

// buildAuthenticateFixed is buildAuthenticate with a caller-chosen fixed-part
// size: 64 for a bare message, 72 with a Version field, 88 with a MIC too.
func buildAuthenticateFixed(fixed int, ntResponse []byte, mic [16]byte) []byte {
	domain := UTF16LE("WORKGROUP")
	user := UTF16LE("alice")
	wks := UTF16LE("CLIENT")

	out := make([]byte, fixed)
	copy(out[0:8], Signature[:])
	binary.LittleEndian.PutUint32(out[8:], MessageTypeAuthenticate)
	binary.LittleEndian.PutUint32(out[60:], NegotiateUnicode|NegotiateNTLM|NegotiateVersion)
	if fixed >= MICFieldOffset+16 {
		copy(out[MICFieldOffset:MICFieldOffset+16], mic[:])
	}

	put := func(fieldOff int, payload []byte) {
		binary.LittleEndian.PutUint16(out[fieldOff:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(out[fieldOff+2:], uint16(len(payload)))
		binary.LittleEndian.PutUint32(out[fieldOff+4:], uint32(len(out)))
		out = append(out, payload...)
	}
	put(12, nil)        // LmChallengeResponse
	put(20, ntResponse) // NtChallengeResponse
	put(28, domain)
	put(36, user)
	put(44, wks)
	put(52, nil) // EncryptedRandomSessionKey
	return out
}

// TestAuthenticateLen_TrimsSPNEGOTail is the case that makes or breaks MIC
// verification against a real client: UnwrapNTLM returns everything to the end
// of the SPNEGO blob, and the final negTokenResp carries a mechListMIC after
// the responseToken. Those bytes are not part of the AUTHENTICATE_MESSAGE.
func TestAuthenticateLen_TrimsSPNEGOTail(t *testing.T) {
	auth := buildAuthenticate(ntlmv2Response(AVFlagMICPresent, true), [16]byte{})
	if got := AuthenticateLen(auth); got != len(auth) {
		t.Errorf("AuthenticateLen on an untailed message = %d, want %d", got, len(auth))
	}

	// a2 ... mechListMIC-ish DER tail
	tail := []byte{0xa3, 0x12, 0x04, 0x10}
	tail = append(tail, bytes.Repeat([]byte{0xEE}, 16)...)
	withTail := append(append([]byte(nil), auth...), tail...)
	if got := AuthenticateLen(withTail); got != len(auth) {
		t.Errorf("AuthenticateLen with SPNEGO tail = %d, want %d", got, len(auth))
	}

	// A message with no payload fields at all can't be measured; returning the
	// whole buffer is the documented fallback.
	empty := make([]byte, 88)
	copy(empty[0:8], Signature[:])
	binary.LittleEndian.PutUint32(empty[8:], MessageTypeAuthenticate)
	if got := AuthenticateLen(empty); got != len(empty) {
		t.Errorf("AuthenticateLen on a payload-free message = %d, want %d", got, len(empty))
	}
	if got := AuthenticateLen(make([]byte, 4)); got != 4 {
		t.Errorf("AuthenticateLen on a runt = %d, want 4", got)
	}
}

func TestComputeAndVerifyMIC(t *testing.T) {
	key := bytes.Repeat([]byte{0x9C}, 16)
	negotiate := append([]byte(nil), Signature[:]...)
	negotiate = append(negotiate, bytes.Repeat([]byte{0x01}, 32)...)
	challenge := EncodeChallenge(ChallengeMessage{
		TargetName: "GOSAMBA",
		Flags:      NegotiateUnicode | NegotiateNTLM,
		Challenge:  [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	})

	auth := buildAuthenticate(ntlmv2Response(AVFlagMICPresent, true), [16]byte{})
	mic := ComputeMIC(key, negotiate, challenge, auth)

	// The MIC must not depend on what already sits in the MIC field: the
	// client computed it with that field zeroed, and the message it sends has
	// the MIC in place.
	signed := buildAuthenticate(ntlmv2Response(AVFlagMICPresent, true), mic)
	if got := ComputeMIC(key, negotiate, challenge, signed); got != mic {
		t.Fatal("MIC changed once the MIC field was filled in")
	}
	// ...and computing it must not have mutated the caller's buffer.
	if !bytes.Equal(signed[MICFieldOffset:MICFieldOffset+16], mic[:]) {
		t.Fatal("ComputeMIC zeroed the caller's MIC field in place")
	}

	if !VerifyMIC(key, negotiate, challenge, signed, mic) {
		t.Error("VerifyMIC rejected a correct MIC")
	}

	// Any edit anywhere in the handshake must break it. The NEGOTIATE flags in
	// particular are what nothing else authenticates.
	tampered := append([]byte(nil), negotiate...)
	tampered[12] ^= 0x20
	if VerifyMIC(key, tampered, challenge, signed, mic) {
		t.Error("VerifyMIC accepted a tampered NEGOTIATE_MESSAGE")
	}
	badChallenge := append([]byte(nil), challenge...)
	badChallenge[24] ^= 0x01
	if VerifyMIC(key, negotiate, badChallenge, signed, mic) {
		t.Error("VerifyMIC accepted a tampered CHALLENGE_MESSAGE")
	}
	badAuth := append([]byte(nil), signed...)
	badAuth[60] ^= 0x01
	if VerifyMIC(key, negotiate, challenge, badAuth, mic) {
		t.Error("VerifyMIC accepted a tampered AUTHENTICATE_MESSAGE")
	}
	wrong := mic
	wrong[15] ^= 0x01
	if VerifyMIC(key, negotiate, challenge, signed, wrong) {
		t.Error("VerifyMIC accepted a MIC differing in one byte")
	}
	if VerifyMIC(bytes.Repeat([]byte{0x00}, 16), negotiate, challenge, signed, mic) {
		t.Error("VerifyMIC accepted a MIC under the wrong session key")
	}
}

// TestDecodeAuthenticate_NoMICField covers the other half of the MIC-presence
// test: a message whose payload starts right after the 64-byte fixed part has
// no room for a MIC, and must not be reported as carrying one.
func TestDecodeAuthenticate_NoMICField(t *testing.T) {
	auth := buildAuthenticateFixed(64, ntlmv2Response(0, false), [16]byte{})
	m, err := DecodeAuthenticate(auth)
	if err != nil {
		t.Fatal(err)
	}
	if m.HasMIC {
		t.Error("HasMIC true for a message with no MIC field")
	}

	// 72-byte fixed part: Version but still no MIC.
	auth72 := buildAuthenticateFixed(72, ntlmv2Response(0, false), [16]byte{})
	m72, err := DecodeAuthenticate(auth72)
	if err != nil {
		t.Fatal(err)
	}
	if m72.HasMIC {
		t.Error("HasMIC true for a message with Version but no MIC field")
	}
}

// TestDecodeAuthenticate_MICSurvivesSPNEGOTail confirms the decoder still finds
// the MIC when trailing SPNEGO bytes follow the message.
func TestDecodeAuthenticate_MICSurvivesSPNEGOTail(t *testing.T) {
	want := [16]byte{0xDE, 0xAD, 0xBE, 0xEF}
	auth := buildAuthenticate(ntlmv2Response(AVFlagMICPresent, true), want)
	withTail := append(append([]byte(nil), auth...), bytes.Repeat([]byte{0x00}, 20)...)

	m, err := DecodeAuthenticate(withTail)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasMIC {
		t.Fatal("HasMIC false for a message with a MIC field")
	}
	if m.MIC != want {
		t.Errorf("MIC = %x, want %x", m.MIC, want)
	}
}
