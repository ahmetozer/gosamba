package parent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"

	"golang.org/x/sys/unix"
)

// TestStream_AFPInfoSynthesizedWhenEmpty proves a freshly-opened AFP_AfpInfo
// metadata stream presents a valid 60-byte blob (signature "AFP") rather than
// 0 bytes — macOS Finder reads this during a copy and aborts the whole copy
// (leaving a 0-byte file) if the read is empty. Opening it read-only must NOT
// persist a spurious xattr.
func TestStream_AFPInfoSynthesizedWhenEmpty(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	rw := discardRW{}

	d.handleCreateNamedStream(rw, smb2.Header{Command: smb2.CommandCreate}, sess, tree, smb2.CreateRequest{}, "doc.txt", "AFP_AfpInfo")
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatal("AFP_AfpInfo open not registered")
	}
	if len(open.streamBuf) != 60 {
		t.Fatalf("AFP_AfpInfo streamBuf len = %d, want 60", len(open.streamBuf))
	}
	if string(open.streamBuf[:3]) != "AFP" {
		t.Fatalf("AFP_AfpInfo magic = %q, want \"AFP\"", open.streamBuf[:3])
	}

	// Close after a read-only open: must NOT create the xattr on disk.
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)
	if xattrSupported(t, base) {
		if _, err := unix.Getxattr(base, "user.gosamba.ads.AFP_AfpInfo", make([]byte, 64)); err == nil {
			t.Fatal("AFP_AfpInfo xattr was persisted on a read-only open; should not litter")
		}
	}
}

// TestStream_AFPInfoPersistsWhenWritten proves that when the client actually
// writes the AFP_AfpInfo stream (real FinderInfo), it IS persisted and read
// back across handles.
func TestStream_AFPInfoPersistsWhenWritten(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, base) {
		t.Skip("filesystem does not support user xattrs")
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	rw := discardRW{}

	d.handleCreateNamedStream(rw, smb2.Header{Command: smb2.CommandCreate}, sess, tree, smb2.CreateRequest{}, "doc.txt", "AFP_AfpInfo")
	open := sess.GetOpen(d.LastCreatedFileID)

	// Client writes a full 60-byte AFPInfo with real FinderInfo bytes.
	blob := synthAFPInfo()
	blob[16] = 0xAB // a FinderInfo byte
	d.handleWrite(rw, smb2.Header{Command: smb2.CommandWrite}, buildWriteBody(open.FileID, 0, blob), sess)
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)

	got := make([]byte, 64)
	n, err := unix.Getxattr(base, "user.gosamba.ads.AFP_AfpInfo", got)
	if err != nil {
		t.Fatalf("written AFP_AfpInfo not persisted: %v", err)
	}
	if n != 60 || got[16] != 0xAB || string(got[:3]) != "AFP" {
		t.Fatalf("persisted AFP_AfpInfo wrong: n=%d magic=%q b16=%#x", n, got[:3], got[16])
	}
}
