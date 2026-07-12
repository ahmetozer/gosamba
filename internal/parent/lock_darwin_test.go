//go:build darwin

package parent

import (
	"os"
	"path/filepath"
	"testing"
)

// two Opens over the SAME file must conflict on overlapping exclusive ranges,
// and the SAME Open must not conflict with itself.
func TestLockManagerDarwinConflict(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	fa, _ := os.OpenFile(p, os.O_RDWR, 0)
	fb, _ := os.OpenFile(p, os.O_RDWR, 0)
	defer fa.Close()
	defer fb.Close()
	openA := &Open{Path: p, File: fa}
	openB := &Open{Path: p, File: fb}

	m := newLockManager()
	if err := m.applyLock(openA, 0, 100, lockExclusive); err != nil {
		t.Fatalf("A lock: %v", err)
	}
	if err := m.applyLock(openB, 50, 100, lockExclusive); err != errLockConflict {
		t.Fatalf("B overlapping lock: want errLockConflict, got %v", err)
	}
	if err := m.applyLock(openB, 200, 100, lockExclusive); err != nil {
		t.Fatalf("B non-overlapping lock: %v", err)
	}
	// same-owner re-lock of its own range: no conflict
	if err := m.applyLock(openA, 0, 100, lockExclusive); err != nil {
		t.Fatalf("A re-lock own range: %v", err)
	}
	// after A releases, B can take A's old range
	m.releaseAll(openA)
	if err := m.applyLock(openB, 0, 100, lockExclusive); err != nil {
		t.Fatalf("B lock after A release: %v", err)
	}
	// shared locks from two owners coexist
	m2 := newLockManager()
	if err := m2.applyLock(openA, 0, 10, lockShared); err != nil {
		t.Fatal(err)
	}
	if err := m2.applyLock(openB, 0, 10, lockShared); err != nil {
		t.Fatalf("two shared locks must coexist: %v", err)
	}
}
