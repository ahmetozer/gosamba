package smb3

import (
	"bytes"
	"testing"
)

func TestKDF_DeterministicAndLength(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 16)
	out1 := KDF(key, []byte("SMBSigningKey"), []byte("ctx"), 128)
	out2 := KDF(key, []byte("SMBSigningKey"), []byte("ctx"), 128)
	if !bytes.Equal(out1, out2) {
		t.Error("KDF should be deterministic")
	}
	if len(out1) != 16 {
		t.Errorf("expected 16 bytes for L=128, got %d", len(out1))
	}
	out3 := KDF(key, []byte("SMBSigningKey"), []byte("DIFFERENT"), 128)
	if bytes.Equal(out1, out3) {
		t.Error("KDF should depend on context")
	}
	out4 := KDF(key, []byte("SMBSigningKey"), []byte("ctx"), 256)
	if len(out4) != 32 {
		t.Errorf("expected 32 bytes for L=256, got %d", len(out4))
	}
}
