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

// TestLockManagerGlobalCrossConnection is the regression test for the
// per-connection lockManager bug: ServeConn used to call newLockManager()
// once per TCP connection, so two different clients (each with their own
// manager instance) never saw each other's locks and could both hold
// conflicting exclusive locks on the same file. sharedLockManager is a
// single process-wide instance (see lockmanager.go), so two *Open values
// that stand in for two independent client connections MUST conflict here.
//
// If this test is pointed at two separate newLockManager() instances instead
// of sharedLockManager, it fails to observe a conflict — that's the bug this
// guards against.
func TestLockManagerGlobalCrossConnection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cross-conn")
	if err := os.WriteFile(p, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	fa, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	fb, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fb.Close()

	// openA/openB stand in for opens made on two different TCP connections.
	openA := &Open{Path: p, File: fa}
	openB := &Open{Path: p, File: fb}

	if err := sharedLockManager.applyLock(openA, 0, 100, lockExclusive); err != nil {
		t.Fatalf("connection A lock: %v", err)
	}
	defer sharedLockManager.releaseAll(openA)
	defer sharedLockManager.releaseAll(openB)

	if err := sharedLockManager.applyLock(openB, 50, 100, lockExclusive); err != errLockConflict {
		t.Fatalf("connection B overlapping lock against connection A: want errLockConflict, got %v", err)
	}
}

// TestLockManagerReleaseAllFreesRanges proves the leak-fix path: once
// releaseAll(open) runs (as now happens on every close path that
// permanently closes an Open's file — connection teardown and durable
// expiry/eviction/reclaim, not just handleClose), a different owner can take
// the freed range with no conflict.
func TestLockManagerReleaseAllFreesRanges(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "release-all")
	if err := os.WriteFile(p, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	fa, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	fb, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fb.Close()

	openA := &Open{Path: p, File: fa}
	openB := &Open{Path: p, File: fb}

	if err := sharedLockManager.applyLock(openA, 0, 100, lockExclusive); err != nil {
		t.Fatalf("A lock: %v", err)
	}

	sharedLockManager.releaseAll(openA)

	if err := sharedLockManager.applyLock(openB, 0, 100, lockExclusive); err != nil {
		t.Fatalf("B lock after A releaseAll: want success, got %v", err)
	}
	sharedLockManager.releaseAll(openB)
}
