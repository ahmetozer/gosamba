package userdb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNTHash_KnownVectors(t *testing.T) {
	cases := []struct {
		password string
		wantHex  string
	}{
		{"Password", "a4f49c406510bdcab6824ee7c30fd852"},
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
	}
	for _, tc := range cases {
		got := NTHash(tc.password)
		want, _ := hex.DecodeString(tc.wantHex)
		if !bytes.Equal(got[:], want) {
			t.Errorf("NTHash(%q) = %x, want %s", tc.password, got, tc.wantHex)
		}
	}
}

func TestNTHash_LengthIs16(t *testing.T) {
	h := NTHash("anything")
	if len(h) != 16 {
		t.Fatalf("got %d bytes, want 16", len(h))
	}
}
