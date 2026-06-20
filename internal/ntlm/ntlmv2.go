package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
)

var ErrAuthFailure = errors.New("ntlm: authentication failed")

// NTOWFv2 = HMAC_MD5(NT_HASH, UTF16LE(uppercase(USER) || DOMAIN)).
func NTOWFv2(ntHash [16]byte, username, domain string) [16]byte {
	mac := hmac.New(md5.New, ntHash[:])
	mac.Write(utf16leUpper(username))
	mac.Write(utf16leDomain(domain))
	var out [16]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func utf16leUpper(s string) []byte {
	upper := strings.ToUpper(s)
	encoded := utf16.Encode([]rune(upper))
	out := make([]byte, len(encoded)*2)
	for i, c := range encoded {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

func utf16leDomain(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	out := make([]byte, len(encoded)*2)
	for i, c := range encoded {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

// VerifyNTLMv2 checks the NtResponse against NT hash + server challenge.
// Returns SessionBaseKey on success.
func VerifyNTLMv2(ntHash [16]byte, username, domain string, serverChallenge [8]byte, ntResponse []byte) ([16]byte, error) {
	if len(ntResponse) < 16+8 {
		return [16]byte{}, ErrAuthFailure
	}
	clientNTProofStr := ntResponse[:16]
	temp := ntResponse[16:]

	ntowfv2 := NTOWFv2(ntHash, username, domain)

	mac := hmac.New(md5.New, ntowfv2[:])
	mac.Write(serverChallenge[:])
	mac.Write(temp)
	expectedNTProofStr := mac.Sum(nil)

	if subtle.ConstantTimeCompare(clientNTProofStr, expectedNTProofStr) != 1 {
		return [16]byte{}, ErrAuthFailure
	}

	mac2 := hmac.New(md5.New, ntowfv2[:])
	mac2.Write(expectedNTProofStr)
	var sbk [16]byte
	copy(sbk[:], mac2.Sum(nil))
	return sbk, nil
}
