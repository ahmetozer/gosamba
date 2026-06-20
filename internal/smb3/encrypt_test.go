package smb3

import (
	"bytes"
	"testing"
)

func TestTransformRoundTrip_AES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 16)
	plain := []byte("the quick brown SMB jumps over the lazy NETBIOS")
	frame, err := EncryptTransform(CipherAES128GCM, key, 0xDEADBEEFCAFEBABE, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !IsTransform(frame) {
		t.Fatal("encrypted frame doesn't start with 0xFD SMB")
	}
	got, sid, err := DecryptTransform(CipherAES128GCM, key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if sid != 0xDEADBEEFCAFEBABE {
		t.Errorf("session id: %x", sid)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext: %q vs %q", got, plain)
	}
}

func TestTransformRoundTrip_AES128CCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 16)
	plain := []byte("hello SMB CCM world")
	frame, err := EncryptTransform(CipherAES128CCM, key, 1, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := DecryptTransform(CipherAES128CCM, key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch: %q vs %q", got, plain)
	}
}

func TestTransformDecrypt_TamperedFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	frame, err := EncryptTransform(CipherAES128GCM, key, 1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] ^= 1
	if _, _, err := DecryptTransform(CipherAES128GCM, key, frame); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}
