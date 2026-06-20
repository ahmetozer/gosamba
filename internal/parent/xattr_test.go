package parent

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"golang.org/x/sys/unix"
)

// xattrSupported returns true if the temp filesystem accepts user xattrs.
// Some CI tmpfs mounts return ENOTSUP; such tests are skipped.
func xattrSupported(t *testing.T, path string) bool {
	t.Helper()
	err := unix.Setxattr(path, "user.gosamba.probe", []byte("x"), 0)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return false
		}
		t.Fatalf("probe Setxattr: %v", err)
	}
	_ = unix.Removexattr(path, "user.gosamba.probe")
	return true
}

func TestXattr_StreamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, path) {
		t.Skip("filesystem does not support user xattrs")
	}

	want := []byte("stream contents \x00 with binary")
	if err := writeStreamXattr(path, "mystream", want); err != nil {
		t.Fatalf("writeStreamXattr: %v", err)
	}

	// Verify with a direct unix.Getxattr on the mapped name.
	raw := make([]byte, 256)
	n, err := unix.Getxattr(path, "user.gosamba.ads.mystream", raw)
	if err != nil {
		t.Fatalf("direct Getxattr: %v", err)
	}
	if !bytes.Equal(raw[:n], want) {
		t.Fatalf("on-disk xattr = %q, want %q", raw[:n], want)
	}

	got, err := readStreamXattr(path, "mystream")
	if err != nil {
		t.Fatalf("readStreamXattr: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readStreamXattr = %q, want %q", got, want)
	}

	// listStreams enumerates it with correct size.
	streams, err := listStreams(path)
	if err != nil {
		t.Fatalf("listStreams: %v", err)
	}
	found := false
	for _, s := range streams {
		if s.Name == "mystream" {
			found = true
			if s.Size != len(want) {
				t.Errorf("stream size = %d, want %d", s.Size, len(want))
			}
		}
	}
	if !found {
		t.Fatalf("listStreams did not include mystream: %+v", streams)
	}

	// Zero-length write still creates the stream.
	if err := writeStreamXattr(path, "empty", nil); err != nil {
		t.Fatalf("writeStreamXattr(empty): %v", err)
	}
	empty, err := readStreamXattr(path, "empty")
	if err != nil || empty == nil {
		t.Fatalf("empty stream should exist: %q err=%v", empty, err)
	}

	// Remove.
	if err := removeStreamXattr(path, "mystream"); err != nil {
		t.Fatalf("removeStreamXattr: %v", err)
	}
	if _, err := unix.Getxattr(path, "user.gosamba.ads.mystream", raw); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("after remove, expected ENODATA, got %v", err)
	}
	// Removing a missing stream is not an error.
	if err := removeStreamXattr(path, "mystream"); err != nil {
		t.Fatalf("removeStreamXattr(missing): %v", err)
	}
}

func TestXattr_EARoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, path) {
		t.Skip("filesystem does not support user xattrs")
	}

	if err := setEA(path, "DOSATTRIB", []byte("hello")); err != nil {
		t.Fatalf("setEA: %v", err)
	}
	// Also drop an ADS stream — listEAs must NOT include it.
	if err := writeStreamXattr(path, "afp", []byte("rsrc")); err != nil {
		t.Fatalf("writeStreamXattr: %v", err)
	}

	// Direct verify: EA name is lower-cased under user.*
	raw := make([]byte, 256)
	n, err := unix.Getxattr(path, "user.dosattrib", raw)
	if err != nil {
		t.Fatalf("direct Getxattr user.dosattrib: %v", err)
	}
	if string(raw[:n]) != "hello" {
		t.Fatalf("on-disk EA = %q, want hello", raw[:n])
	}

	eas, err := listEAs(path)
	if err != nil {
		t.Fatalf("listEAs: %v", err)
	}
	foundEA := false
	for _, e := range eas {
		if e.Name == "gosamba.ads.afp" {
			t.Errorf("listEAs leaked ADS storage: %+v", e)
		}
		if e.Name == "dosattrib" {
			foundEA = true
			if string(e.Value) != "hello" {
				t.Errorf("EA value = %q, want hello", e.Value)
			}
		}
	}
	if !foundEA {
		t.Fatalf("listEAs missing dosattrib: %+v", eas)
	}
}

// newTestDispatcher builds a minimal Dispatcher wired to a single share rooted
// at shareDir, returning the dispatcher, a session, and the tree.
func newTestDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir}
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
	}
	sess := &Session{}
	tree := sess.AddTree(share)
	return d, sess, tree
}

// discardRW is an io.ReadWriter that swallows all writes (responses go nowhere;
// we assert on filesystem/session state instead of parsing the wire).
type discardRW struct{}

func (discardRW) Read(p []byte) (int, error)  { return 0, io.EOF }
func (discardRW) Write(p []byte) (int, error) { return len(p), nil }

// TestStream_PersistAcrossHandles proves that CREATE-stream -> WRITE -> CLOSE
// persists bytes to the on-disk xattr, and a fresh CREATE+READ returns them.
func TestStream_PersistAcrossHandles(t *testing.T) {
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

	// --- Handle 1: CREATE stream, WRITE bytes, CLOSE ---
	createReq := smb2.CreateRequest{}
	hdr := smb2.Header{Command: smb2.CommandCreate}
	d.handleCreateNamedStream(rw, hdr, sess, tree, createReq, "doc.txt", "mystream")
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil || !open.IsStream {
		t.Fatalf("stream open not registered: %+v", open)
	}

	payload := []byte("alternate stream payload")
	d.handleWrite(rw, smb2.Header{Command: smb2.CommandWrite}, buildWriteBody(open.FileID, 0, payload), sess)
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)

	// On-disk xattr must hold the payload.
	raw := make([]byte, 256)
	n, err := unix.Getxattr(base, "user.gosamba.ads.mystream", raw)
	if err != nil {
		t.Fatalf("on-disk Getxattr after close: %v", err)
	}
	if !bytes.Equal(raw[:n], payload) {
		t.Fatalf("on-disk = %q, want %q", raw[:n], payload)
	}

	// --- Handle 2: fresh CREATE + READ returns the same bytes ---
	d.handleCreateNamedStream(rw, hdr, sess, tree, createReq, "doc.txt", "mystream")
	open2 := sess.GetOpen(d.LastCreatedFileID)
	if open2 == nil {
		t.Fatal("second stream open not registered")
	}
	if !bytes.Equal(open2.streamBuf, payload) {
		t.Fatalf("reopened streamBuf = %q, want %q", open2.streamBuf, payload)
	}
}

// TestStream_DeleteOnClose proves DeleteOnClose removes the xattr.
func TestStream_DeleteOnClose(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupported(t, base) {
		t.Skip("filesystem does not support user xattrs")
	}
	if err := writeStreamXattr(base, "gone", []byte("temp")); err != nil {
		t.Fatal(err)
	}

	d, sess, tree := newTestDispatcher(t, shareDir)
	rw := discardRW{}
	d.handleCreateNamedStream(rw, smb2.Header{Command: smb2.CommandCreate}, sess, tree, smb2.CreateRequest{}, "doc.txt", "gone")
	open := sess.GetOpen(d.LastCreatedFileID)
	open.DeleteOnClose = true
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)

	raw := make([]byte, 16)
	if _, err := unix.Getxattr(base, "user.gosamba.ads.gone", raw); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("expected ENODATA after delete-on-close, got %v", err)
	}
}

// TestEA_SetInfoPersists proves SET_INFO FileFullEaInformation persists EAs and
// QUERY_INFO FileFullEaInformation returns them encoded.
func TestEA_SetInfoPersists(t *testing.T) {
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

	// Open the base file (non-stream) so SET_INFO has a path.
	open := &Open{Path: base, Tree: tree, GrantedAccess: 0x001F01FF}
	_, _ = rand.Read(open.FileID[:])
	sess.AddOpen(open)

	// Encode a FILE_FULL_EA_INFORMATION list with two EAs.
	eaBuf := buildFullEaList([]eaInfo{
		{Name: "FOO", Value: []byte("bar")},
		{Name: "BAZ", Value: []byte{1, 2, 3}},
	})
	sbody := buildSetInfoBody(smb2.InfoTypeFile, smb2.FileFullEaInformation, open.FileID, eaBuf)
	d.handleSetInfo(rw, smb2.Header{Command: smb2.CommandSetInfo}, sbody, sess)

	// On-disk: lower-cased.
	raw := make([]byte, 16)
	n, err := unix.Getxattr(base, "user.foo", raw)
	if err != nil {
		t.Fatalf("Getxattr user.foo: %v", err)
	}
	if string(raw[:n]) != "bar" {
		t.Fatalf("user.foo = %q, want bar", raw[:n])
	}

	// QUERY_INFO returns them; decode and verify both present.
	info := openFileInfo(open)
	out, ok := encodeFileInfo(smb2.FileFullEaInformation, info, open)
	if !ok {
		t.Fatal("encodeFileInfo FullEa not ok")
	}
	decoded := decodeFullEaList(t, out)
	if string(decoded["foo"]) != "bar" {
		t.Errorf("decoded foo = %q, want bar", decoded["foo"])
	}
	if !bytes.Equal(decoded["baz"], []byte{1, 2, 3}) {
		t.Errorf("decoded baz = %v, want [1 2 3]", decoded["baz"])
	}
}

// buildFullEaList builds a FILE_FULL_EA_INFORMATION chained list (MS-FSCC
// §2.4.15) for test input. Helper mirrors the parser used by the handler.
func buildFullEaList(eas []eaInfo) []byte {
	var out []byte
	for i, ea := range eas {
		name := []byte(ea.Name)
		entry := make([]byte, 8+len(name)+1+len(ea.Value))
		// NextEntryOffset filled below; Flags=0
		entry[4] = 0
		entry[5] = byte(len(name))
		binary.LittleEndian.PutUint16(entry[6:], uint16(len(ea.Value)))
		copy(entry[8:], name)
		// entry[8+len(name)] = 0 NUL terminator (already zero)
		copy(entry[8+len(name)+1:], ea.Value)
		// pad to 4-byte boundary except last
		if i < len(eas)-1 {
			for len(entry)%4 != 0 {
				entry = append(entry, 0)
			}
			binary.LittleEndian.PutUint32(entry[0:], uint32(len(entry)))
		}
		out = append(out, entry...)
	}
	return out
}

// decodeFullEaList parses a FILE_FULL_EA_INFORMATION list into name->value
// (names lower-cased) for assertions.
func decodeFullEaList(t *testing.T, buf []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	off := 0
	for off < len(buf) {
		if off+8 > len(buf) {
			break
		}
		next := binary.LittleEndian.Uint32(buf[off:])
		nameLen := int(buf[off+5])
		valLen := int(binary.LittleEndian.Uint16(buf[off+6:]))
		nameStart := off + 8
		name := strings.ToLower(string(buf[nameStart : nameStart+nameLen]))
		valStart := nameStart + nameLen + 1
		val := append([]byte{}, buf[valStart:valStart+valLen]...)
		out[name] = val
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out
}

// buildWriteBody constructs a WRITE request body matching DecodeWriteRequest's
// expected wire layout (StructureSize 49, DataOffset absolute from frame start).
func buildWriteBody(fileID [16]byte, offset uint64, data []byte) []byte {
	const headerSize = 64
	body := make([]byte, 48+len(data))
	binary.LittleEndian.PutUint16(body[0:], 49)
	binary.LittleEndian.PutUint16(body[2:], headerSize+48) // DataOffset absolute
	binary.LittleEndian.PutUint32(body[4:], uint32(len(data)))
	binary.LittleEndian.PutUint64(body[8:], offset)
	copy(body[16:32], fileID[:])
	copy(body[48:], data)
	return body
}

// buildCloseBody constructs a CLOSE request body (StructureSize 24).
func buildCloseBody(fileID [16]byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 24)
	copy(body[8:24], fileID[:])
	return body
}

// buildSetInfoBody constructs a SET_INFO request body (StructureSize 33).
func buildSetInfoBody(infoType, infoClass uint8, fileID [16]byte, buf []byte) []byte {
	const headerSize = 64
	body := make([]byte, 32+len(buf))
	binary.LittleEndian.PutUint16(body[0:], 33)
	body[2] = infoType
	body[3] = infoClass
	binary.LittleEndian.PutUint32(body[4:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(body[8:], headerSize+32) // BufferOffset absolute
	copy(body[16:32], fileID[:])
	copy(body[32:], buf)
	return body
}
