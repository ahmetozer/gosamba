package smb2

import (
	"bytes"
	"testing"
)

// buildNegotiateRequest builds a valid NEGOTIATE request body advertising
// dialect 3.1.1 with PreauthIntegrity (SHA-512) and Encryption contexts.
func buildNegotiateRequest(t *testing.T) []byte {
	t.Helper()

	body := make([]byte, 0, 256)
	hdr := make([]byte, 36)
	hdr[0] = 36
	hdr[2] = 1 // DialectCount
	hdr[4] = 0x01
	hdr[8] = 0x40
	for i := 0; i < 16; i++ {
		hdr[12+i] = 0xAA
	}
	hdr[28] = 104 // ctx offset abs (header(64) + 40)
	hdr[32] = 2

	body = append(body, hdr...)
	body = append(body, 0x11, 0x03)
	body = append(body, 0x00, 0x00) // pad to 8

	preauth := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	preauthData := []byte{0x01, 0x00, 0x20, 0x00, 0x01, 0x00}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(0xC0 + i)
	}
	preauthData = append(preauthData, salt...)
	preauth[2] = byte(len(preauthData))
	preauth[3] = byte(len(preauthData) >> 8)
	preauth = append(preauth, preauthData...)
	for len(preauth)%8 != 0 {
		preauth = append(preauth, 0x00)
	}
	body = append(body, preauth...)

	enc := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encData := []byte{0x02, 0x00, 0x04, 0x00, 0x02, 0x00}
	enc[2] = byte(len(encData))
	enc[3] = byte(len(encData) >> 8)
	enc = append(enc, encData...)
	body = append(body, enc...)

	return body
}

func TestDecodeNegotiateRequest_311(t *testing.T) {
	body := buildNegotiateRequest(t)
	req, err := DecodeNegotiateRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Dialects) != 1 || req.Dialects[0] != Dialect311 {
		t.Errorf("dialects: %v", req.Dialects)
	}
	if req.SecurityMode&NegotiateSigningEnabled == 0 {
		t.Errorf("expected signing-enabled bit")
	}
	if req.Capabilities&CapEncryption == 0 {
		t.Errorf("expected CAP_ENCRYPTION")
	}
	want := [16]byte{}
	for i := range want {
		want[i] = 0xAA
	}
	if req.ClientGuid != want {
		t.Errorf("ClientGuid: %x", req.ClientGuid)
	}
	if len(req.PreauthIntegrity.HashAlgorithms) != 1 || req.PreauthIntegrity.HashAlgorithms[0] != HashSHA512 {
		t.Errorf("preauth hashes: %v", req.PreauthIntegrity.HashAlgorithms)
	}
	if len(req.PreauthIntegrity.Salt) != 32 || req.PreauthIntegrity.Salt[0] != 0xC0 {
		t.Errorf("preauth salt: %x", req.PreauthIntegrity.Salt)
	}
	if req.Encryption == nil || len(req.Encryption.Ciphers) != 2 {
		t.Fatalf("ciphers: %v", req.Encryption)
	}
	if req.Encryption.Ciphers[0] != CipherAES256GCM || req.Encryption.Ciphers[1] != CipherAES128GCM {
		t.Errorf("ciphers: %v", req.Encryption.Ciphers)
	}
	if req.SigningCaps != nil {
		t.Errorf("did not expect a signing-caps context")
	}
}

func TestDecodeNegotiateRequest_TooShort(t *testing.T) {
	_, err := DecodeNegotiateRequest([]byte{0x24, 0x00})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeNegotiateRequest_BadStructureSize(t *testing.T) {
	body := buildNegotiateRequest(t)
	body[0] = 0x25
	_, err := DecodeNegotiateRequest(body)
	if err == nil {
		t.Fatal("expected bad-structure-size error")
	}
}

// keep bytes import in use
var _ = bytes.Equal

func TestSelect_Happy(t *testing.T) {
	req := NegotiateRequest{
		Dialects:         []Dialect{Dialect311},
		PreauthIntegrity: PreauthIntegrityContext{HashAlgorithms: []Hash{HashSHA512}},
		Encryption:       &EncryptionContext{Ciphers: []Cipher{CipherAES128GCM, CipherAES256GCM}},
		SigningCaps:      &SigningCapsContext{Algorithms: []SigningAlgo{SigningAESCMAC, SigningAESGMAC}},
	}
	sel, err := Select(req, true)
	if err != nil {
		t.Fatal(err)
	}
	if sel.Dialect != Dialect311 {
		t.Errorf("dialect: %x", sel.Dialect)
	}
	if sel.Cipher != CipherAES256GCM {
		t.Errorf("cipher: %x", sel.Cipher)
	}
	if sel.SigningAlgo != SigningAESCMAC {
		t.Errorf("signing: %x", sel.SigningAlgo)
	}
}

func TestSelect_NoDialect(t *testing.T) {
	// 0x9999 is a fictional dialect not in SupportedDialects.
	req := NegotiateRequest{Dialects: []Dialect{0x9999}}
	_, err := Select(req, false)
	if err != ErrNoCommonDialect {
		t.Errorf("expected ErrNoCommonDialect, got %v", err)
	}
}

func TestSelect_NoSHA512(t *testing.T) {
	req := NegotiateRequest{Dialects: []Dialect{Dialect311}}
	_, err := Select(req, false)
	if err != ErrNoPreauthSHA512 {
		t.Errorf("expected ErrNoPreauthSHA512, got %v", err)
	}
}

func TestSelect_NoCipherButNotRequired(t *testing.T) {
	req := NegotiateRequest{
		Dialects:         []Dialect{Dialect311},
		PreauthIntegrity: PreauthIntegrityContext{HashAlgorithms: []Hash{HashSHA512}},
	}
	sel, err := Select(req, false)
	if err != nil {
		t.Fatal(err)
	}
	if sel.Cipher != 0 {
		t.Errorf("expected no cipher, got %x", sel.Cipher)
	}
	if sel.SigningAlgo != SigningAESCMAC {
		t.Errorf("expected default CMAC, got %x", sel.SigningAlgo)
	}
}

func TestSelect_NoCipherWhenRequired(t *testing.T) {
	req := NegotiateRequest{
		Dialects:         []Dialect{Dialect311},
		PreauthIntegrity: PreauthIntegrityContext{HashAlgorithms: []Hash{HashSHA512}},
	}
	_, err := Select(req, true)
	if err != ErrNoCommonCipher {
		t.Errorf("expected ErrNoCommonCipher, got %v", err)
	}
}

func TestEncodeNegotiateResponse_Shape(t *testing.T) {
	resp := NegotiateResponse{
		SecurityMode:    NegotiateSigningEnabled | NegotiateSigningRequired,
		Dialect:         Dialect311,
		ServerGuid:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Capabilities:    CapLargeMTU | CapEncryption,
		MaxTransactSize: 1 << 20,
		MaxReadSize:     1 << 20,
		MaxWriteSize:    1 << 20,
		SystemTime:      0x01D5_0000_0000_0000,
		ServerStartTime: 0x01D5_1234_5678_9ABC,
		SecurityBuffer:  NegotiateSecurityBlob,
		PreauthIntegrity: &PreauthIntegrityContext{
			HashAlgorithms: []Hash{HashSHA512},
			Salt:           bytes.Repeat([]byte{0xAB}, 32),
		},
		Encryption:  &EncryptionContext{Ciphers: []Cipher{CipherAES256GCM}},
		SigningCaps: &SigningCapsContext{Algorithms: []SigningAlgo{SigningAESGMAC}},
	}
	out, err := EncodeNegotiateResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0x41 || out[1] != 0x00 {
		t.Errorf("StructureSize: %x %x", out[0], out[1])
	}
	if out[4] != 0x11 || out[5] != 0x03 {
		t.Errorf("Dialect: %x %x", out[4], out[5])
	}
	if out[6] != 0x03 {
		t.Errorf("NegotiateContextCount: %d", out[6])
	}
	if !bytes.Equal(out[8:24], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) {
		t.Errorf("ServerGuid: %x", out[8:24])
	}
	off := int(out[56]) | int(out[57])<<8
	length := int(out[58]) | int(out[59])<<8
	if length != len(NegotiateSecurityBlob) {
		t.Errorf("SecurityBufferLength: %d", length)
	}
	bodyOff := off - 64
	if bodyOff < 0 || bodyOff+length > len(out) {
		t.Fatalf("security buffer out of bounds: off=%d len=%d body=%d", bodyOff, length, len(out))
	}
	if !bytes.Equal(out[bodyOff:bodyOff+length], NegotiateSecurityBlob) {
		t.Errorf("security buffer bytes mismatch")
	}
}

func TestEncodeNegotiateResponse_NoEncryption(t *testing.T) {
	resp := NegotiateResponse{
		SecurityMode:   NegotiateSigningEnabled,
		Dialect:        Dialect311,
		Capabilities:   CapLargeMTU,
		SecurityBuffer: NegotiateSecurityBlob,
		PreauthIntegrity: &PreauthIntegrityContext{
			HashAlgorithms: []Hash{HashSHA512},
			Salt:           []byte("saltsaltsaltsaltsaltsalt"),
		},
		Encryption: nil,
	}
	out, err := EncodeNegotiateResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if out[6] != 0x01 {
		t.Errorf("expected single context (preauth only), got %d", out[6])
	}
}
