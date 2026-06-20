package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// MS-NLMP §4.2.4: Password "Password", User "User", Domain "Domain".
// NT hash = a4f49c406510bdcab6824ee7c30fd852
// NTOWFv2 expected = 0c868a403bfd7a93a3001ef22ef02e3f
func TestNTOWFv2_KnownVector(t *testing.T) {
	ntHash := [16]byte{0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52}
	got := NTOWFv2(ntHash, "User", "Domain")
	want, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got[:], want) {
		t.Errorf("got %x, want %s", got, hex.EncodeToString(want))
	}
}
