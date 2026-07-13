package parent

import "testing"

func TestRangesOverlap(t *testing.T) {
	cases := []struct {
		name         string
		aStart, aLen uint64
		bStart, bLen uint64
		want         bool
	}{
		{"identical ranges overlap", 0, 100, 0, 100, true},
		{"partial overlap", 0, 100, 50, 100, true},
		{"adjacent, non-overlapping", 0, 100, 100, 100, false},
		{"disjoint, non-overlapping", 0, 100, 200, 100, false},
		{"b fully inside a", 0, 100, 10, 5, true},
		{"a fully inside b", 10, 5, 0, 100, true},
		{"zero-length a never overlaps", 0, 0, 0, 100, false},
		{"zero-length b never overlaps", 0, 100, 50, 0, false},
		{"both zero-length", 0, 0, 0, 0, false},
		{"reversed adjacent", 100, 100, 0, 100, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rangesOverlap(c.aStart, c.aLen, c.bStart, c.bLen)
			if got != c.want {
				t.Errorf("rangesOverlap(%d,%d,%d,%d) = %v, want %v", c.aStart, c.aLen, c.bStart, c.bLen, got, c.want)
			}
		})
	}
}

func TestRangeTableApply(t *testing.T) {
	key := fileKey{dev: 1, ino: 1}
	ownerA := &Open{Path: "a"}
	ownerB := &Open{Path: "b"}

	t.Run("exclusive vs exclusive overlap from different owners conflicts", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock: %v", err)
		}
		if err := tb.apply(key, ownerB, 50, 100, lockExclusive); err != errLockConflict {
			t.Fatalf("ownerB overlap: want errLockConflict, got %v", err)
		}
	})

	t.Run("same-owner overlap does not conflict", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("first lock: %v", err)
		}
		if err := tb.apply(key, ownerA, 50, 100, lockExclusive); err != nil {
			t.Fatalf("same-owner overlap should not conflict: %v", err)
		}
	})

	t.Run("shared+shared different owners overlap does not conflict", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockShared); err != nil {
			t.Fatalf("ownerA shared: %v", err)
		}
		if err := tb.apply(key, ownerB, 50, 100, lockShared); err != nil {
			t.Fatalf("ownerB shared overlap should not conflict: %v", err)
		}
	})

	t.Run("shared+exclusive different owners overlap conflicts", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockShared); err != nil {
			t.Fatalf("ownerA shared: %v", err)
		}
		if err := tb.apply(key, ownerB, 50, 100, lockExclusive); err != errLockConflict {
			t.Fatalf("ownerB exclusive over shared: want errLockConflict, got %v", err)
		}
	})

	t.Run("exclusive+shared different owners overlap conflicts", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA exclusive: %v", err)
		}
		if err := tb.apply(key, ownerB, 50, 100, lockShared); err != errLockConflict {
			t.Fatalf("ownerB shared over exclusive: want errLockConflict, got %v", err)
		}
	})

	t.Run("non-overlapping different owners does not conflict", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock: %v", err)
		}
		if err := tb.apply(key, ownerB, 200, 100, lockExclusive); err != nil {
			t.Fatalf("ownerB non-overlapping should not conflict: %v", err)
		}
	})

	t.Run("zero-length lock never conflicts", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock: %v", err)
		}
		if err := tb.apply(key, ownerB, 0, 0, lockExclusive); err != nil {
			t.Fatalf("zero-length lock should never conflict: %v", err)
		}
	})

	t.Run("unlock removes a range so a previously-conflicting lock now succeeds", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock: %v", err)
		}
		if err := tb.apply(key, ownerB, 0, 100, lockExclusive); err != errLockConflict {
			t.Fatalf("ownerB overlap: want errLockConflict, got %v", err)
		}
		if err := tb.apply(key, ownerA, 0, 100, lockUnlock); err != nil {
			t.Fatalf("ownerA unlock: %v", err)
		}
		if err := tb.apply(key, ownerB, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerB lock after unlock should succeed: %v", err)
		}
	})

	t.Run("unlock of non-matching range is a no-op", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock: %v", err)
		}
		if err := tb.apply(key, ownerA, 200, 50, lockUnlock); err != nil {
			t.Fatalf("no-match unlock should be a no-op, got err: %v", err)
		}
		// original lock must still be held: a different owner overlapping should conflict.
		if err := tb.apply(key, ownerB, 0, 100, lockExclusive); err != errLockConflict {
			t.Fatalf("original lock should still be held: want errLockConflict, got %v", err)
		}
	})

	t.Run("releaseOwner frees all of an owner's ranges", func(t *testing.T) {
		tb := newRangeTable()
		if err := tb.apply(key, ownerA, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock 1: %v", err)
		}
		if err := tb.apply(key, ownerA, 200, 100, lockExclusive); err != nil {
			t.Fatalf("ownerA lock 2: %v", err)
		}
		tb.releaseOwner(key, ownerA)
		if err := tb.apply(key, ownerB, 0, 100, lockExclusive); err != nil {
			t.Fatalf("ownerB should be able to take released range 1: %v", err)
		}
		if err := tb.apply(key, ownerB, 200, 100, lockExclusive); err != nil {
			t.Fatalf("ownerB should be able to take released range 2: %v", err)
		}
		if len(tb.locks[key]) != 2 {
			t.Fatalf("expected exactly ownerB's 2 ranges remaining, got %d", len(tb.locks[key]))
		}
	})
}
