package parent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
	"golang.org/x/sys/unix"
)

// TestOFDLockConflict_ExclusiveBlocked proves that OFD locks on two independent
// file descriptions over the same file produce EAGAIN/EACCES on conflict —
// the exact OS mechanism handleLock maps to STATUS_LOCK_NOT_GRANTED.
func TestOFDLockConflict_ExclusiveBlocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}

	// Open two independent file descriptions (different os.File objects).
	fd1, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd1.Close()

	fd2, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd2.Close()

	// Take an exclusive OFD lock on fd1 over bytes 0–99.
	lock1 := unix.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	if err := unix.FcntlFlock(fd1.Fd(), unix.F_OFD_SETLK, &lock1); err != nil {
		t.Fatalf("FcntlFlock F_OFD_SETLK (fd1 exclusive): %v", err)
	}

	// Attempt overlapping exclusive lock on fd2 — must fail immediately.
	lock2 := unix.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	err = unix.FcntlFlock(fd2.Fd(), unix.F_OFD_SETLK, &lock2)
	if err == nil {
		t.Fatal("expected EAGAIN/EACCES for conflicting OFD lock, got nil")
	}
	if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("expected EAGAIN or EACCES, got %v (%T)", err, err)
	}
	t.Logf("conflicting lock correctly returned: %v (maps to STATUS_LOCK_NOT_GRANTED)", err)

	// Release fd1's lock.
	unlock := unix.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	if err := unix.FcntlFlock(fd1.Fd(), unix.F_OFD_SETLK, &unlock); err != nil {
		t.Fatalf("FcntlFlock F_OFD_SETLK (fd1 unlock): %v", err)
	}

	// Now fd2 should succeed.
	if err := unix.FcntlFlock(fd2.Fd(), unix.F_OFD_SETLK, &lock2); err != nil {
		t.Fatalf("FcntlFlock F_OFD_SETLK (fd2 after unlock): expected success, got %v", err)
	}
	t.Log("fd2 lock acquired after fd1 released: OFD conflict mechanism verified")
}

// TestOFDLockConflict_SharedCompatible proves shared (read) locks are compatible.
func TestOFDLockConflict_SharedCompatible(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sharedfile.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}

	fd1, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd1.Close()

	fd2, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd2.Close()

	sharedLock := unix.Flock_t{
		Type:   syscall.F_RDLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	if err := unix.FcntlFlock(fd1.Fd(), unix.F_OFD_SETLK, &sharedLock); err != nil {
		t.Fatalf("fd1 shared lock: %v", err)
	}
	if err := unix.FcntlFlock(fd2.Fd(), unix.F_OFD_SETLK, &sharedLock); err != nil {
		t.Fatalf("fd2 shared lock (should be compatible): %v", err)
	}
	t.Log("two shared locks coexist: verified")
}

// TestHandleLock_ExclusiveConflict exercises handleLock via constructed
// Session/Open pairs, verifying STATUS_LOCK_NOT_GRANTED is returned.
func TestHandleLock_ExclusiveConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locktest.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}

	// fd1 holds an exclusive OFD lock over the range.
	f1, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()

	f2, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	// Take exclusive OFD lock on f1 (simulates "other client has a lock").
	exLock := unix.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	if err := unix.FcntlFlock(f1.Fd(), unix.F_OFD_SETLK, &exLock); err != nil {
		t.Fatalf("fd1 lock: %v", err)
	}

	// Build a session with f2 as the open file.
	sess := &Session{}
	sess.initTables()
	var fid2 [16]byte
	fid2[0] = 0x42
	open2 := &Open{File: f2, FileID: fid2}
	sess.AddOpen(open2)

	d := &Dispatcher{
		Sessions: NewSessionTable(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Build a LOCK request body for f2 over 0–100 (exclusive, fail immediately).
	body := makeLockBody(fid2, []testLockElem{
		{offset: 0, length: 100, flags: 0x02 | 0x10 /* EXCLUSIVE_LOCK | FAIL_IMMEDIATELY */},
	})

	var buf bytes.Buffer
	hdr := smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandLock,
		MessageID:    42,
	}

	cont := d.handleLock(&buf, hdr, body, sess)
	if !cont {
		t.Error("handleLock returned false (drop connection), want true")
	}

	// Read the NBSS-framed response.
	respFrame, err := transport.ReadFrame(&buf, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if len(respFrame) < smb2.HeaderSize {
		t.Fatalf("response frame too short: %d bytes", len(respFrame))
	}
	respHdr, err := smb2.DecodeHeader(respFrame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode response header: %v", err)
	}
	const wantStatus = smb2.Status(0xC0000055) // STATUS_LOCK_NOT_GRANTED
	if smb2.Status(respHdr.Status) != wantStatus {
		t.Errorf("status: got 0x%08X, want 0x%08X (STATUS_LOCK_NOT_GRANTED)", respHdr.Status, uint32(wantStatus))
	}
	t.Logf("handleLock correctly returned STATUS_LOCK_NOT_GRANTED on conflict")
}

// TestHandleLock_SuccessAndUnlock exercises a successful lock+unlock round-trip.
func TestHandleLock_SuccessAndUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "success.bin")
	if err := os.WriteFile(path, make([]byte, 1024), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sess := &Session{}
	sess.initTables()
	var fid [16]byte
	fid[0] = 0x01
	open := &Open{File: f, FileID: fid}
	sess.AddOpen(open)

	d := &Dispatcher{
		Sessions: NewSessionTable(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	hdr := smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandLock,
		MessageID:    10,
	}

	// Lock bytes 0–99 exclusively.
	body := makeLockBody(fid, []testLockElem{
		{offset: 0, length: 100, flags: 0x02 /* EXCLUSIVE_LOCK */},
	})
	var buf1 bytes.Buffer
	cont := d.handleLock(&buf1, hdr, body, sess)
	if !cont {
		t.Fatal("handleLock returned false on success lock path")
	}
	assertLockStatusSuccess(t, &buf1)

	// Unlock bytes 0–99.
	body2 := makeLockBody(fid, []testLockElem{
		{offset: 0, length: 100, flags: 0x04 /* UNLOCK */},
	})
	var buf2 bytes.Buffer
	hdr.MessageID = 11
	cont2 := d.handleLock(&buf2, hdr, body2, sess)
	if !cont2 {
		t.Fatal("handleLock returned false on unlock path")
	}
	assertLockStatusSuccess(t, &buf2)
	t.Log("lock+unlock round-trip: success")
}

// TestHandleLock_MultiElementRollback verifies that when a multi-element LOCK
// request fails on element[1], any lock already applied for element[0] is
// released before returning STATUS_LOCK_NOT_GRANTED (MS-SMB2 §3.3.5.14
// atomicity requirement).
func TestHandleLock_MultiElementRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rollback.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}

	// fConflict holds a pre-existing exclusive lock on range B (bytes 200-299)
	// so that element[1] of the LOCK request will conflict.
	fConflict, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fConflict.Close()
	conflictLock := unix.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  200,
		Len:    100,
	}
	if err := unix.FcntlFlock(fConflict.Fd(), unix.F_OFD_SETLK, &conflictLock); err != nil {
		t.Fatalf("pre-existing lock on range B: %v", err)
	}

	// fClient is the file description used by handleLock (the "SMB client").
	fClient, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fClient.Close()

	sess := &Session{}
	sess.initTables()
	var fid [16]byte
	fid[0] = 0x77
	open := &Open{File: fClient, FileID: fid}
	sess.AddOpen(open)

	d := &Dispatcher{
		Sessions: NewSessionTable(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Two-element request:
	//   element[0]: exclusive lock on range A (bytes 0-99) — should succeed initially.
	//   element[1]: exclusive lock on range B (bytes 200-299) — conflicts with fConflict.
	body := makeLockBody(fid, []testLockElem{
		{offset: 0, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
		{offset: 200, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
	})

	var buf bytes.Buffer
	hdr := smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandLock,
		MessageID:    99,
	}
	cont := d.handleLock(&buf, hdr, body, sess)
	if !cont {
		t.Error("handleLock returned false (drop connection), want true")
	}

	// Response must be STATUS_LOCK_NOT_GRANTED.
	respFrame, err := transport.ReadFrame(&buf, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if len(respFrame) < smb2.HeaderSize {
		t.Fatalf("response frame too short: %d bytes", len(respFrame))
	}
	respHdr, err := smb2.DecodeHeader(respFrame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode response header: %v", err)
	}
	const wantStatus = smb2.Status(0xC0000055) // STATUS_LOCK_NOT_GRANTED
	if smb2.Status(respHdr.Status) != wantStatus {
		t.Errorf("status: got 0x%08X, want 0x%08X (STATUS_LOCK_NOT_GRANTED)", respHdr.Status, uint32(wantStatus))
	}

	// Verify rollback: range A must NOT be left locked by handleLock.
	// Open a third file description and attempt an exclusive lock on range A —
	// it must succeed (because the rollback released it).
	fVerify, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fVerify.Close()
	verifyLock := unix.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    100,
	}
	if err := unix.FcntlFlock(fVerify.Fd(), unix.F_OFD_SETLK, &verifyLock); err != nil {
		t.Errorf("range A still locked after rollback (handleLock did not release it): %v", err)
	} else {
		t.Log("rollback verified: range A was released after element[1] conflict")
	}
}

// ---- helpers ----------------------------------------------------------------

type testLockElem struct {
	offset uint64
	length uint64
	flags  uint32
}

// makeLockBody crafts a minimal SMB2 LOCK body for test use.
// The fixed portion is 24 bytes (StructureSize(2)+LockCount(2)+LockSeq(4)+FileId(16));
// lock elements start at offset 24 per MS-SMB2 §2.2.26.
func makeLockBody(fileID [16]byte, elems []testLockElem) []byte {
	buf := make([]byte, 24+len(elems)*24)
	binary.LittleEndian.PutUint16(buf[0:], 48) // StructureSize (always 48 per spec)
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(elems)))
	// LockSequenceNumber/Index at [4:8] = 0
	copy(buf[8:], fileID[:]) // FileId at [8:24]
	for i, el := range elems {
		base := 24 + i*24
		binary.LittleEndian.PutUint64(buf[base:], el.offset)
		binary.LittleEndian.PutUint64(buf[base+8:], el.length)
		binary.LittleEndian.PutUint32(buf[base+16:], el.flags)
	}
	return buf
}

func assertLockStatusSuccess(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	frame, err := transport.ReadFrame(buf, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if len(frame) < smb2.HeaderSize {
		t.Fatalf("frame too short: %d", len(frame))
	}
	h, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if h.Status != uint32(smb2.StatusSuccess) {
		t.Errorf("expected STATUS_SUCCESS, got 0x%08X", h.Status)
	}
}
