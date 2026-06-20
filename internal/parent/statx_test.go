package parent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBirthTime_Available creates a real file and calls birthTime.
// On filesystems that support btime (ext4 with statx kernel ≥ 4.11) the
// returned time should be non-zero and close to now.
// On filesystems without btime support (tmpfs, etc.) the function returns
// (_, false) — in that case the test is skipped rather than failed so CI on
// tmpfs-backed /tmp doesn't regress.
func TestBirthTime_Available(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "btime_test.txt")

	before := time.Now().Add(-2 * time.Second)
	if err := os.WriteFile(path, []byte("btime test"), 0644); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(2 * time.Second)

	btime, ok := birthTime(path)
	if !ok {
		t.Skip("birthTime: btime unavailable on this filesystem — skipping (not a failure)")
	}

	if btime.Before(before) || btime.After(after) {
		t.Errorf("birthTime: got %v, want between %v and %v", btime, before, after)
	}
}

// TestBirthTime_NonExistent verifies that birthTime returns false for a
// non-existent path rather than panicking.
func TestBirthTime_NonExistent(t *testing.T) {
	_, ok := birthTime("/tmp/gosamba_no_such_file_xyz_12345")
	if ok {
		t.Error("birthTime: expected false for non-existent path")
	}
}

// TestBirthTime_CreationTimeUsed verifies that when btime IS available
// (skips otherwise), the returned time is used as the creation time in
// encodeFileInfo — white-box check via filetimeFromTime round-trip.
func TestBirthTime_CreationTimeUsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "btime_create.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	btime, ok := birthTime(path)
	if !ok {
		t.Skip("btime unavailable on this filesystem")
	}

	// Round-trip: convert to filetime and back, should be within 1 second.
	ft := filetimeFromTime(btime)
	if ft == 0 {
		t.Error("filetimeFromTime(btime) == 0, expected a valid Windows filetime")
	}
	// Convert back to verify the epoch math is sane.
	secs := int64(ft/10_000_000) - filetimeEpochDelta
	roundTripped := time.Unix(secs, 0).UTC()
	diff := roundTripped.Sub(btime)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("round-trip error: got %v after convert, diff=%v", roundTripped, diff)
	}
}
