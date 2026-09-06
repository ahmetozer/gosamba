//go:build linux

package parent

import (
	"math"
	"testing"
)

// TestFlockRange proves SMB2 (offset,length) pairs are translated to fcntl
// l_start/l_len rather than cast. A straight int64 cast turned a lock-to-EOF
// length into a negative l_len, which fcntl reads as a range running backwards
// from the offset — locking entirely the wrong bytes.
func TestFlockRange(t *testing.T) {
	// Ordinary range passes through unchanged.
	if s, l, ok := flockRange(100, 50); !ok || s != 100 || l != 50 {
		t.Errorf("flockRange(100,50) = (%d,%d,%v), want (100,50,true)", s, l, ok)
	}
	// Lock-to-EOF: a huge length becomes l_len 0 ("to end of file"), never a
	// negative length.
	if s, l, ok := flockRange(0, math.MaxUint64); !ok || s != 0 || l != 0 {
		t.Errorf("lock-to-EOF = (%d,%d,%v), want (0,0,true)", s, l, ok)
	}
	if s, l, ok := flockRange(4096, math.MaxUint64); !ok || s != 4096 || l != 0 {
		t.Errorf("lock-to-EOF at 4096 = (%d,%d,%v), want (4096,0,true)", s, l, ok)
	}
	// A range that would run past the signed maximum also means to-EOF.
	if _, l, ok := flockRange(math.MaxInt64-10, 1000); !ok || l != 0 {
		t.Errorf("range past MaxInt64 should clamp to l_len 0, got (%d,%v)", l, ok)
	}
	// An offset beyond the signed range is not expressible at all.
	if _, _, ok := flockRange(uint64(math.MaxInt64)+1, 1); ok {
		t.Errorf("offset above MaxInt64 should be rejected")
	}
}
