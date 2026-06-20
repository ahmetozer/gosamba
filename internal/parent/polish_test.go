package parent

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// TestF10_FsAttributesCaseSensitive pins the FileFsAttributeInformation bits
// to confirm we advertise FILE_CASE_SENSITIVE_SEARCH (0x1).
//
// Decision (F10, option a): We keep advertising FILE_CASE_SENSITIVE_SEARCH
// because the underlying filesystem (ext4 by default) IS case-sensitive.
// Advertising case-insensitive while the FS remains case-sensitive would be
// a lie that could cause name collisions that the server cannot resolve.
// Clients (Windows, macOS) handle case-sensitive shares correctly; they simply
// cannot create two files differing only in case (their shells prevent it).
// This is the lowest-risk, self-consistent choice.
func TestF10_FsAttributesCaseSensitive(t *testing.T) {
	// Construct a minimal Open so encodeFsInfo doesn't panic.
	o := &Open{
		Path: "/tmp",
		Tree: &Tree{
			Share: config.ShareConfig{Name: "test", Path: "/tmp"},
		},
	}

	buf, ok := encodeFsInfo(smb2.FileFsAttributeInformation, o)
	if !ok {
		t.Fatal("encodeFsInfo FileFsAttributeInformation returned false")
	}
	if len(buf) < 4 {
		t.Fatalf("FileFsAttributeInformation buf too short: %d", len(buf))
	}

	fsAttrs := binary.LittleEndian.Uint32(buf[0:4])

	const (
		fileCaseSensitiveSearch = 0x00000001
		fileCasePreservedNames  = 0x00000002
		fileUnicodeOnDisk       = 0x00000004
	)

	// Must advertise case-sensitive search (F10 decision: option a).
	if fsAttrs&fileCaseSensitiveSearch == 0 {
		t.Errorf("FILE_CASE_SENSITIVE_SEARCH (0x1) should be set; fsAttrs=0x%08X", fsAttrs)
	}
	// Must also advertise case-preserved names (we never alter case on disk).
	if fsAttrs&fileCasePreservedNames == 0 {
		t.Errorf("FILE_CASE_PRESERVED_NAMES (0x2) should be set; fsAttrs=0x%08X", fsAttrs)
	}
	// Unicode on disk is expected too.
	if fsAttrs&fileUnicodeOnDisk == 0 {
		t.Errorf("FILE_UNICODE_ON_DISK (0x4) should be set; fsAttrs=0x%08X", fsAttrs)
	}
}

// TestF9_BirthTimeFileBasicInfo verifies that FileBasicInformation's
// CreationTime (offset 0) differs from ModTime when the path has a distinct
// btime, OR equals the ModTime fallback when btime is unavailable.
func TestF9_BirthTimeFileBasicInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "btime_basic.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	// Sleep briefly to ensure mtime and btime could differ.
	time.Sleep(10 * time.Millisecond)

	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	open := &Open{Path: path}
	buf, ok := encodeFileInfo(smb2.FileBasicInformation, st, open)
	if !ok {
		t.Fatal("encodeFileInfo FileBasicInformation failed")
	}
	if len(buf) != 40 {
		t.Fatalf("FileBasicInformation length: got %d, want 40", len(buf))
	}

	creationTime := binary.LittleEndian.Uint64(buf[0:8])
	modTime := binary.LittleEndian.Uint64(buf[16:24]) // LastWriteTime

	btime, btimeOK := birthTime(path)
	if !btimeOK {
		// btime unavailable: CreationTime must equal ModTime (fallback).
		if creationTime != modTime {
			t.Errorf("btime unavailable: CreationTime (0x%X) != ModTime (0x%X)", creationTime, modTime)
		}
		t.Log("F9: btime unavailable — fallback to ModTime verified")
		return
	}

	// btime available: CreationTime should be derived from btime.
	expected := filetimeFromTime(btime)
	if creationTime != expected {
		t.Errorf("F9: CreationTime = 0x%X, want btime-derived 0x%X", creationTime, expected)
	}
	t.Logf("F9: CreationTime from btime = %v", btime)
}
