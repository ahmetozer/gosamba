package parent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
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
	d.handleCreateNamedStream(rw, smb2.Header{Command: smb2.CommandCreate}, sess, tree, smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}, "doc.txt", "s")
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

// TestHardening_LockRangeOverflow proves a lock-to-EOF range (huge length) is
// compared without wrapping. Before the fix start+length overflowed to a small
// number, so two conflicting exclusive locks were both granted.
func TestHardening_LockRangeOverflow(t *testing.T) {
	const maxLen = ^uint64(0)
	if !rangesOverlap(0, maxLen, 1<<40, 1) {
		t.Errorf("lock-to-EOF from 0 should cover offset 2^40")
	}
	if !rangesOverlap(100, maxLen, 100, maxLen) {
		t.Errorf("two lock-to-EOF ranges at the same offset must overlap")
	}
	if rangesOverlap(0, 10, 10, 5) {
		t.Errorf("adjacent ranges must not overlap")
	}
	if rangesOverlap(0, 0, 0, 10) {
		t.Errorf("a zero-length range covers no bytes")
	}
	if got := rangeEnd(^uint64(0)-1, 100); got != ^uint64(0) {
		t.Errorf("rangeEnd saturated to %d, want max uint64", got)
	}
}

// TestHardening_LockConflictBlocksIO proves an exclusive lock held by one
// handle makes another handle's overlapping read and write fail, rather than
// silently succeeding as before.
func TestHardening_LockConflictBlocksIO(t *testing.T) {
	tbl := newRangeTable()
	key := fileKey{dev: 1, ino: 2}
	holder := &Open{Path: "/x"}
	other := &Open{Path: "/x"}

	if err := tbl.apply(key, holder, 0, 100, lockExclusive); err != nil {
		t.Fatalf("exclusive lock: %v", err)
	}
	if !tbl.conflict(key, other, 50, 10, false) {
		t.Errorf("read overlapping an exclusive lock should conflict")
	}
	if !tbl.conflict(key, other, 50, 10, true) {
		t.Errorf("write overlapping an exclusive lock should conflict")
	}
	if tbl.conflict(key, holder, 50, 10, true) {
		t.Errorf("the lock holder's own I/O must not conflict")
	}
	if tbl.conflict(key, other, 200, 10, true) {
		t.Errorf("I/O outside the locked range must not conflict")
	}

	// A shared lock blocks writes but not reads.
	tbl.releaseOwner(key, holder)
	if err := tbl.apply(key, holder, 0, 100, lockShared); err != nil {
		t.Fatalf("shared lock: %v", err)
	}
	if tbl.conflict(key, other, 10, 5, false) {
		t.Errorf("read overlapping a shared lock must be allowed")
	}
	if !tbl.conflict(key, other, 10, 5, true) {
		t.Errorf("write overlapping a shared lock must conflict")
	}
}

// TestHardening_DurableAttachedNeverExpires proves the sweeper cannot close the
// fd of a durable handle whose connection is still alive. Before the fix the
// deadline started at CREATE, so a handle held open past the timeout had its
// descriptor closed underneath the client.
func TestHardening_DurableAttachedNeverExpires(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x01
	tbl.Register(cg, crg, &Open{Path: "/in-use"}, time.Millisecond, "share", "alice")

	if n := tbl.Expire(time.Now().Add(time.Hour)); n != 0 {
		t.Errorf("Expire evicted %d attached entries, want 0 (connection still live)", n)
	}
	if !tbl.Has(cg, crg) {
		t.Errorf("attached durable entry should still be present")
	}

	// Once the connection drops, the countdown starts and it does expire.
	tbl.Detach(cg, crg)
	if n := tbl.Expire(time.Now().Add(time.Hour)); n != 1 {
		t.Errorf("Expire evicted %d detached entries, want 1", n)
	}
}

// TestHardening_DurableReclaimChecksUser proves a durable handle can only be
// reclaimed by the SMB user that opened it.
func TestHardening_DurableReclaimChecksUser(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x02
	open := &Open{Path: "/owned"}
	tbl.Register(cg, crg, open, time.Minute, "share", "alice")
	// A reconnect is only valid once the owning connection has gone, so
	// simulate the drop before attempting one.
	tbl.Detach(cg, crg)

	if _, ok := tbl.reclaimForReconnect(cg, crg, "share", "mallory"); ok {
		t.Errorf("a different user reclaimed another user's durable handle")
	}
	if _, ok := tbl.reclaimForReconnect(cg, crg, "share", "alice"); !ok {
		t.Errorf("the owning user could not reclaim their own handle")
	}
}

// TestHardening_UTF16SurrogateRoundTrip proves a non-BMP filename (emoji)
// survives decode. Before the fix each UTF-16 code unit became its own rune,
// so a surrogate pair decoded to two unpaired surrogates and the name was
// mangled beyond recovery.
func TestHardening_UTF16SurrogateRoundTrip(t *testing.T) {
	for _, name := range []string{"rocket🚀.txt", "plain.txt", "café.txt", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢"} {
		if got := decodeUTF16LE(utf16leName(name)); got != name {
			t.Errorf("round-trip of %q gave %q", name, got)
		}
	}
}

// TestHardening_ShareEnumRespectsACL proves share enumeration only reveals
// shares the caller could actually connect to.
func TestHardening_ShareEnumRespectsACL(t *testing.T) {
	all := []config.ShareConfig{
		{Name: "public", GuestOK: true},
		{Name: "work"},
		{Name: "hr-payroll-secret"},
	}
	restricted := &Session{User: config.UserConfig{Name: "bob", AllowShares: []string{"work"}}}
	got := visibleShares(all, restricted)
	if len(got) != 1 || got[0].Name != "work" {
		t.Errorf("restricted user saw %v, want only [work]", shareNames(got))
	}

	guest := &Session{IsGuest: true}
	got = visibleShares(all, guest)
	if len(got) != 1 || got[0].Name != "public" {
		t.Errorf("guest saw %v, want only [public]", shareNames(got))
	}

	admin := &Session{User: config.UserConfig{Name: "root", AllowShares: []string{"*"}}}
	if got = visibleShares(all, admin); len(got) != 3 {
		t.Errorf("wildcard user saw %d shares, want 3", len(got))
	}
}

// TestHardening_TeardownClosesHandles proves TREE_DISCONNECT and LOGOFF release
// the file descriptors and locks they own, instead of leaving them until the
// whole connection dies, and that LOGOFF invalidates the SessionId.
func TestHardening_TeardownClosesHandles(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "a.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	tbl := NewSessionTable()
	sess := tbl.New()
	sess.Authenticated = true
	share := config.ShareConfig{Name: "share", Path: shareDir}
	d := &Dispatcher{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares:   []config.ShareConfig{share},
		Sessions: tbl,
		Conn:     &Connection{},
		locks:    sharedLockManager,
	}
	tree := sess.AddTree(share)

	openFile := func() *Open {
		var cbuf bytes.Buffer
		d.handleCreate(&cbuf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			buildCreateBody("a.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil), sess)
		o := sess.GetOpen(d.LastCreatedFileID)
		if o == nil || o.File == nil {
			t.Fatalf("create failed")
		}
		return o
	}

	// TREE_DISCONNECT must close the handle opened on that tree.
	o1 := openFile()
	var tbuf bytes.Buffer
	d.handleTreeDisconnect(&tbuf, smb2.Header{Command: smb2.CommandTreeDisconnect, TreeID: tree.ID},
		[]byte{0x04, 0x00, 0x00, 0x00}, sess)
	if o1.File != nil {
		t.Errorf("TREE_DISCONNECT left the handle open")
	}
	if sess.OpenCount() != 0 {
		t.Errorf("TREE_DISCONNECT left %d opens registered", sess.OpenCount())
	}

	// LOGOFF must close remaining handles and drop the session.
	tree = sess.AddTree(share)
	o2 := openFile()
	var lbuf bytes.Buffer
	d.handleLogoff(&lbuf, smb2.Header{Command: smb2.CommandLogoff, SessionID: sess.ID}, sess)
	if o2.File != nil {
		t.Errorf("LOGOFF left the handle open")
	}
	if tbl.Get(sess.ID) != nil {
		t.Errorf("LOGOFF left the SessionId valid")
	}
}

// TestHardening_ShareRootNotDeletable proves DELETE_ON_CLOSE on the tree root
// cannot remove the shared directory itself.
func TestHardening_ShareRootNotDeletable(t *testing.T) {
	shareDir := t.TempDir()
	d, sess, tree := newTestDispatcher(t, shareDir)

	open := &Open{Path: shareDir, IsDir: true, Tree: tree, DeleteOnClose: true}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		t.Fatal(err)
	}
	sess.AddOpen(open)

	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(open.FileID), sess)

	if _, err := os.Stat(shareDir); err != nil {
		t.Errorf("share root was deleted by DELETE_ON_CLOSE: %v", err)
	}
}

// TestHardening_NotifyFilter proves the CompletionFilter is honoured instead of
// every watch reporting every change.
func TestHardening_NotifyFilter(t *testing.T) {
	// A name-only filter must not deliver content modifications.
	if notifyFilterAllows(smb2.NotifyFileName, smb2.FileActionModified) {
		t.Errorf("FILE_NAME filter should not deliver a Modified action")
	}
	if !notifyFilterAllows(smb2.NotifyFileName, smb2.FileActionAdded) {
		t.Errorf("FILE_NAME filter should deliver an Added action")
	}
	if !notifyFilterAllows(smb2.NotifyLastWrite, smb2.FileActionModified) {
		t.Errorf("LAST_WRITE filter should deliver a Modified action")
	}
	// A zero filter means the client did not care: deliver everything.
	if !notifyFilterAllows(0, smb2.FileActionModified) {
		t.Errorf("an empty filter should deliver everything")
	}
}

// TestHardening_NotifyCancelCompletesRequest proves SMB2_CANCEL completes the
// outstanding notify rather than emitting a second response for the same
// MessageId, and that closing the handle completes it with NOTIFY_CLEANUP.
func TestHardening_NotifyCancelCompletesRequest(t *testing.T) {
	d := &Dispatcher{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	open := &Open{Path: "/watched", IsDir: true}

	reg := &notifyReg{open: open, cancel: make(chan struct{}), status: smb2.StatusCancelled}
	d.registerNotify(42, reg)
	if !d.cancelNotify(42, smb2.StatusCancelled) {
		t.Fatalf("cancelNotify did not find the outstanding request")
	}
	select {
	case <-reg.cancel:
	default:
		t.Errorf("cancel channel was not closed")
	}
	// A second cancel is a no-op (must not double-close the channel).
	if d.cancelNotify(42, smb2.StatusCancelled) {
		t.Errorf("second cancelNotify should report nothing to cancel")
	}

	// Closing the watched handle completes the notify with NOTIFY_CLEANUP.
	reg2 := &notifyReg{open: open, cancel: make(chan struct{}), status: smb2.StatusCancelled}
	d.registerNotify(43, reg2)
	d.cancelNotifiesForOpens([]*Open{open})
	select {
	case <-reg2.cancel:
	default:
		t.Errorf("closing the handle did not complete its notify")
	}
	if reg2.status != smb2.StatusNotifyCleanup {
		t.Errorf("notify completed with 0x%08X, want NOTIFY_CLEANUP", reg2.status)
	}
}

// TestHardening_StreamTruncatingDispositionClearsBuffer proves a truncating
// disposition starts the stream empty. Before the fix the buffer was loaded
// from the existing xattr and a shorter write only overwrote its prefix, so
// CLOSE flushed the new content followed by a stale tail of the old.
func TestHardening_StreamTruncatingDispositionClearsBuffer(t *testing.T) {
	shareDir := t.TempDir()
	base := filepath.Join(shareDir, "doc.txt")
	if err := os.WriteFile(base, []byte("body"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newTestDispatcher(t, shareDir)
	rw := discardRW{}
	hdr := smb2.Header{Command: smb2.CommandCreate}

	// Seed a long stream via a non-truncating open.
	openIf := smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOpenIf}
	d.handleCreateNamedStream(rw, hdr, sess, tree, openIf, "doc.txt", "s")
	o1 := sess.GetOpen(d.LastCreatedFileID)
	if o1 == nil {
		t.Fatal("stream open not registered")
	}
	long := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	d.handleWrite(rw, smb2.Header{Command: smb2.CommandWrite}, buildWriteBody(o1.FileID, 0, long), sess)
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(o1.FileID), sess)

	// Reopen with OVERWRITE_IF: the buffer must start empty, not preloaded.
	over := smb2.CreateRequest{CreateDisposition: smb2.CreateDispositionOverwriteIf}
	d.handleCreateNamedStream(rw, hdr, sess, tree, over, "doc.txt", "s")
	o2 := sess.GetOpen(d.LastCreatedFileID)
	if o2 == nil {
		t.Fatal("second stream open not registered")
	}
	if len(o2.streamBuf) != 0 {
		t.Fatalf("truncating open preloaded %d bytes, want an empty buffer", len(o2.streamBuf))
	}

	// A short write must not leave the old tail behind.
	short := []byte("bb")
	d.handleWrite(rw, smb2.Header{Command: smb2.CommandWrite}, buildWriteBody(o2.FileID, 0, short), sess)
	d.handleClose(rw, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(o2.FileID), sess)

	d.handleCreateNamedStream(rw, hdr, sess, tree, openIf, "doc.txt", "s")
	o3 := sess.GetOpen(d.LastCreatedFileID)
	if o3 == nil {
		t.Fatal("third stream open not registered")
	}
	if string(o3.streamBuf) != string(short) {
		t.Errorf("stream after truncating overwrite = %q, want %q (stale tail survived)", o3.streamBuf, short)
	}
}
