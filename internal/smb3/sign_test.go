package smb3

import (
	"bytes"
	"testing"
)

func TestSignVerify_CMAC_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	msg := bytes.Repeat([]byte{0xAB}, 128)
	SignMessage(SignAlgoAESCMAC, key, msg)
	if !VerifyMessage(SignAlgoAESCMAC, key, msg) {
		t.Error("CMAC signature should verify")
	}
}

func TestSignVerify_GMAC_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	msg := bytes.Repeat([]byte{0xAB}, 128)
	// MessageId bytes at offset 24..32 must be present (valid header layout).
	SignMessage(SignAlgoAESGMAC, key, msg)
	if !VerifyMessage(SignAlgoAESGMAC, key, msg) {
		t.Error("GMAC signature should verify")
	}
}

func TestVerify_TamperedFails(t *testing.T) {
	for _, algo := range []uint16{SignAlgoAESCMAC, SignAlgoAESGMAC} {
		key := bytes.Repeat([]byte{0x42}, 16)
		msg := bytes.Repeat([]byte{0xAB}, 128)
		SignMessage(algo, key, msg)
		msg[100] ^= 0x01
		if VerifyMessage(algo, key, msg) {
			t.Errorf("algo=%x: tampered message should NOT verify", algo)
		}
	}
}

func TestVerify_WrongAlgoFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	msg := bytes.Repeat([]byte{0xAB}, 128)
	SignMessage(SignAlgoAESCMAC, key, msg)
	if VerifyMessage(SignAlgoAESGMAC, key, msg) {
		t.Error("CMAC-signed must not verify as GMAC")
	}
}
