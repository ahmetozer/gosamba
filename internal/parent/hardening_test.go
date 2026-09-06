package parent

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// respStatus strips the NBSS prefix from a single buffered response frame and
// returns the SMB2 status. It is a minimal reader for handlers that write one
// frame (no compounding).
func respStatus(t *testing.T, buf *bytes.Buffer) smb2.Status {
	t.Helper()
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize {
		t.Fatalf("response too short: %d bytes", len(frame))
	}
	hdr, err := smb2.DecodeHeader(frame[4 : 4+smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	return smb2.Status(hdr.Status)
}

func buildTreeConnectBody(path string) []byte {
	const headerSize = 64
	p := utf16leName(path)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], 9)                    // StructureSize
	binary.LittleEndian.PutUint16(body[4:], uint16(headerSize+8)) // PathOffset
	binary.LittleEndian.PutUint16(body[6:], uint16(len(p)))       // PathLength
	return append(body, p...)
}

func buildReadBody(fileID [16]byte, offset uint64, length uint32) []byte {
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:], 49) // StructureSize
	binary.LittleEndian.PutUint32(body[4:], length)
	binary.LittleEndian.PutUint64(body[8:], offset)
	copy(body[16:32], fileID[:])
	return body
}

// TestHardening_CompoundNextCommandNoPanic drives a real server connection with
// a compound header whose NextCommand is smaller than the 64-byte SMB2 header.
// Before the fix this sliced body = msgBytes[64:] on an 8-byte message and
// panicked the whole process (there is no recover() in the connection path).
// The server must instead drop the connection cleanly and keep running.
func TestHardening_CompoundNextCommandNoPanic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// If ServeConn panics, the test process crashes and the test fails.
		ServeConn(ctx, c, lg, transport.MaxFrameSize, ConnOptions{})
		close(served)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := transport.WriteFrame(conn, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ReadFrame(conn, transport.MaxFrameSize); err != nil {
		t.Fatalf("negotiate: %v", err)
	}

	hdr := make([]byte, smb2.HeaderSize)
	if err := smb2.EncodeHeader(hdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandTreeConnect,
		MessageID:    1,
		NextCommand:  8, // 0 < 8 < HeaderSize(64): the crash trigger
	}); err != nil {
		t.Fatal(err)
	}
	frame := append(hdr, make([]byte, 64)...)
	if err := transport.WriteFrame(conn, frame); err != nil {
		t.Fatal(err)
	}

	// The server should close the connection without panicking.
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after malformed compound frame")
	}
}

// TestHardening_UnauthenticatedDispatchDenied proves the dispatcher refuses a
// command on a session that exists (registered by the type-1 leg) but has not
// completed authentication. Before the fix this allowed an unauthenticated
// TREE_CONNECT to IPC$ and full share enumeration.
func TestHardening_UnauthenticatedDispatchDenied(t *testing.T) {
	tbl := NewSessionTable()
	sess := tbl.New() // registered pre-auth, Authenticated == false
	d := &Dispatcher{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions: tbl,
		Conn:     &Connection{},
	}
	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandTreeConnect, SessionID: sess.ID}
	cont := d.Dispatch(&buf, hdr, buildTreeConnectBody(`\\srv\IPC$`), nil)
	if cont {
		t.Errorf("Dispatch returned true (kept connection) for unauthenticated command")
	}
	if st := respStatus(t, &buf); st != smb2.StatusAccessDenied {
		t.Errorf("unauthenticated TREE_CONNECT status=0x%08X, want ACCESS_DENIED", st)
	}

	// After authentication the same command must be accepted (reaches the
	// tree-connect handler and succeeds / fails on its own merits, not the gate).
	sess.Authenticated = true
	buf.Reset()
	d.Shares = nil // no such share -> handler returns a share error, not ACCESS_DENIED from the gate
	_ = d.Dispatch(&buf, smb2.Header{Command: smb2.CommandTreeConnect, SessionID: sess.ID}, buildTreeConnectBody(`\\srv\nope`), nil)
	if st := respStatus(t, &buf); st == smb2.StatusAccessDenied {
		t.Errorf("authenticated TREE_CONNECT wrongly denied by auth gate (status=0x%08X)", st)
	}
}

// TestHardening_StreamOffsetNoPanic sends a WRITE and a READ to an in-memory
// stream handle with an offset above 2^63. Before the fix int(req.Offset) went
// negative and panicked the streamBuf slice.
func TestHardening_StreamOffsetNoPanic(t *testing.T) {
	d, sess, tree := newTestDispatcher(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(tree.Share.Path, "doc.txt"), []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	rw := discardRW{}
	d.handleCreateNamedStream(rw, smb2.Header{Command: smb2.CommandCreate}, sess, tree, smb2.CreateRequest{}, "doc.txt", "s")
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil || !open.IsStream {
		t.Fatalf("stream open not registered")
	}

	huge := uint64(0x8000000000000000) // negative when cast to int

	var wbuf bytes.Buffer
	// buildWriteBody offset is uint64; a huge offset must be rejected, not panic.
	d.handleWrite(&wbuf, smb2.Header{Command: smb2.CommandWrite}, buildWriteBody(open.FileID, huge, []byte("x")), sess)
	if st := respStatus(t, &wbuf); st == smb2.StatusSuccess {
		t.Errorf("stream WRITE at huge offset unexpectedly succeeded")
	}

	var rbuf bytes.Buffer
	d.handleRead(&rbuf, smb2.Header{Command: smb2.CommandRead}, buildReadBody(open.FileID, huge, 16), sess)
	if st := respStatus(t, &rbuf); st != smb2.StatusEndOfFile {
		t.Errorf("stream READ at huge offset status=0x%08X, want END_OF_FILE", st)
	}
}

// TestHardening_ReadLengthClamped proves a READ asking for more than the
// negotiated MaxReadSize is rejected instead of driving a giant allocation.
func TestHardening_ReadLengthClamped(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "f.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 8 << 20}

	var cbuf bytes.Buffer
	d.handleCreate(&cbuf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID}, buildCreateBody("f.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil), sess)
	open := sess.GetOpen(d.LastCreatedFileID)
	if open == nil {
		t.Fatalf("create failed")
	}

	var rbuf bytes.Buffer
	d.handleRead(&rbuf, smb2.Header{Command: smb2.CommandRead}, buildReadBody(open.FileID, 0, 0xFFFFFFFF), sess)
	if st := respStatus(t, &rbuf); st != smb2.StatusInvalidParameter {
		t.Errorf("oversized READ status=0x%08X, want INVALID_PARAMETER", st)
	}
}

// TestHardening_GotEncryptedRaceSafe exercises the atomic session flag from
// multiple goroutines. Run under -race to confirm no data race remains between
// the read loop (SetGotEncrypted) and the async notify goroutine (GotEncrypted).
func TestHardening_GotEncryptedRaceSafe(t *testing.T) {
	sess := &Session{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); sess.SetGotEncrypted() }()
		go func() { defer wg.Done(); _ = sess.GotEncrypted() }()
	}
	wg.Wait()
	if !sess.GotEncrypted() {
		t.Errorf("GotEncrypted should be latched true")
	}
}
