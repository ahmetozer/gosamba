package smb2

import (
	"crypto/sha512"
	"testing"
)

func TestPreauth_InitialIsZero(t *testing.T) {
	p := NewPreauthHash()
	s := p.Sum()
	for i, b := range s {
		if b != 0 {
			t.Errorf("byte %d = %x, want 0", i, b)
		}
	}
}

func TestPreauth_UpdateMatchesManual(t *testing.T) {
	p := NewPreauthHash()
	msg1 := []byte("hello")
	p.Update(msg1)

	h := sha512.New()
	h.Write(make([]byte, 64))
	h.Write(msg1)
	want1 := h.Sum(nil)
	if got := p.Sum(); !bytesEqual(got[:], want1) {
		t.Errorf("after first update, mismatch")
	}

	msg2 := []byte("world")
	p.Update(msg2)

	h2 := sha512.New()
	h2.Write(want1)
	h2.Write(msg2)
	want2 := h2.Sum(nil)
	if got := p.Sum(); !bytesEqual(got[:], want2) {
		t.Errorf("after second update, mismatch")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
