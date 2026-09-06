package parent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// These tests are deliberately untagged: handleLock and the shared rangeTable
// must behave identically on linux (kernel OFD locks + shadow table) and on
// darwin (the table alone), and the only way to prove that is to run the same
// assertions on both.

// --- helpers -----------------------------------------------------------------

type lockElemSpec struct {
	offset uint64
	length uint64
	flags  uint32
}

// encodeLockBody builds an SMB2 LOCK request body (MS-SMB2 §2.2.26): a 24-byte
// fixed part (StructureSize, LockCount, LockSequence, FileId) followed by
// 24-byte lock elements.
func encodeLockBody(fileID [16]byte, elems []lockElemSpec) []byte {
	buf := make([]byte, 24+len(elems)*24)
	binary.LittleEndian.PutUint16(buf[0:], 48)
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(elems)))
	copy(buf[8:], fileID[:])
	for i, el := range elems {
		base := 24 + i*24
		binary.LittleEndian.PutUint64(buf[base:], el.offset)
		binary.LittleEndian.PutUint64(buf[base+8:], el.length)
		binary.LittleEndian.PutUint32(buf[base+16:], el.flags)
	}
	return buf
}

// syncWriter is an io.ReadWriter the dispatcher can write to from its async
// completion goroutine while the test reads what has arrived so far.
type syncWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *syncWriter) Read(p []byte) (int, error) { return 0, io.EOF }

func (w *syncWriter) snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf...)
}

// awaitFrame waits until at least n complete frames have been written and
// returns the header of frame n (1-based).
func awaitFrame(t *testing.T, w *syncWriter, n int, within time.Duration) smb2.Header {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		r := bytes.NewReader(w.snapshot())
		var last smb2.Header
		got := 0
		for got < n {
			frame, err := transport.ReadFrame(r, transport.MaxFrameSize)
			if err != nil || len(frame) < smb2.HeaderSize {
				break
			}
			h, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
			if err != nil {
				t.Fatalf("decode response header: %v", err)
			}
			got++
			last = h
		}
		if got >= n {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for response frame %d (got %d)", n, got)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// openPair returns two independent handles on one temp file, standing in for
// two clients, plus a dispatcher with its own lock manager.
func openPair(t *testing.T, name string) (*Dispatcher, *Session, *Open, *Open) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	fa, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fa.Close() })
	fb, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fb.Close() })

	var fidA, fidB [16]byte
	fidA[0], fidB[0] = 0xA1, 0xB2
	openA := &Open{Path: path, File: fa, FileID: fidA}
	openB := &Open{Path: path, File: fb, FileID: fidB}

	sess := &Session{}
	sess.initTables()
	sess.AddOpen(openA)
	sess.AddOpen(openB)

	d := &Dispatcher{
		Sessions: NewSessionTable(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		locks:    newLockManager(),
	}
	return d, sess, openA, openB
}

// --- finding 1: atomic rollback ----------------------------------------------

// TestLockRollbackKeepsPreexistingLock proves a failed multi-element LOCK
// request leaves the handle's lock state exactly as it was. The old rollback
// unlocked every element it had applied, so a range the handle already held
// and merely re-requested was released — the client silently lost a lock it
// legitimately owned.
func TestLockRollbackKeepsPreexistingLock(t *testing.T) {
	d, sess, openA, openB := openPair(t, "rollback.bin")

	// A already holds 0-99; B holds 200-299.
	if err := d.locks.applyLock(openA, 0, 100, lockExclusive); err != nil {
		t.Fatalf("A pre-existing lock: %v", err)
	}
	if err := d.locks.applyLock(openB, 200, 100, lockExclusive); err != nil {
		t.Fatalf("B lock: %v", err)
	}

	// A now asks for [already-held 0-99, conflicting 200-299] in one request.
	body := encodeLockBody(openA.FileID, []lockElemSpec{
		{offset: 0, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
		{offset: 200, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
	})
	var buf bytes.Buffer
	hdr := smb2.Header{CreditCharge: 1, Command: smb2.CommandLock, MessageID: 7}
	if !d.handleLock(&buf, hdr, body, sess) {
		t.Fatal("handleLock returned false, want true")
	}

	frame, err := transport.ReadFrame(&buf, transport.MaxFrameSize)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	respHdr, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if smb2.Status(respHdr.Status) != smb2.StatusLockNotGranted {
		t.Fatalf("status = 0x%08X, want STATUS_LOCK_NOT_GRANTED", respHdr.Status)
	}

	// The pre-existing lock on 0-99 must have survived the rollback: B writing
	// into it still has to conflict.
	if !d.locks.conflictsWith(openB, 0, 10, true) {
		t.Error("rollback released a lock the handle held before the request")
	}
	// And the element that failed must not have been left half-applied.
	if !d.locks.conflictsWith(openA, 200, 10, true) {
		t.Error("B's lock disappeared during A's failed request")
	}
}

// TestLockRollbackDropsOnlyNewRanges proves the flip side: ranges the failed
// request actually did acquire are released, so a conflict does not leave the
// handle holding locks the client was told it did not get.
func TestLockRollbackDropsOnlyNewRanges(t *testing.T) {
	d, sess, openA, openB := openPair(t, "rollback-new.bin")

	if err := d.locks.applyLock(openB, 200, 100, lockExclusive); err != nil {
		t.Fatalf("B lock: %v", err)
	}

	body := encodeLockBody(openA.FileID, []lockElemSpec{
		{offset: 1000, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
		{offset: 200, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
	})
	var buf bytes.Buffer
	if !d.handleLock(&buf, smb2.Header{Command: smb2.CommandLock, MessageID: 8}, body, sess) {
		t.Fatal("handleLock returned false")
	}
	if d.locks.conflictsWith(openB, 1000, 10, true) {
		t.Error("a range acquired by the failed request was left locked")
	}
}

// --- finding 2: SMB2_LOCKFLAG_FAIL_IMMEDIATELY -------------------------------

// TestLockFailImmediatelyIsAnsweredAtOnce proves the flag is honoured: a
// conflicting request that sets it gets one synchronous
// STATUS_LOCK_NOT_GRANTED, never an interim STATUS_PENDING.
func TestLockFailImmediatelyIsAnsweredAtOnce(t *testing.T) {
	d, sess, openA, openB := openPair(t, "fail-now.bin")
	if err := d.locks.applyLock(openB, 0, 100, lockExclusive); err != nil {
		t.Fatalf("B lock: %v", err)
	}

	body := encodeLockBody(openA.FileID, []lockElemSpec{
		{offset: 0, length: 100, flags: smb2.LockFlagExclusiveLock | smb2.LockFlagFailImmediately},
	})
	w := &syncWriter{}
	if !d.handleLock(w, smb2.Header{Command: smb2.CommandLock, MessageID: 20}, body, sess) {
		t.Fatal("handleLock returned false")
	}
	h := awaitFrame(t, w, 1, time.Second)
	if smb2.Status(h.Status) != smb2.StatusLockNotGranted {
		t.Errorf("status = 0x%08X, want STATUS_LOCK_NOT_GRANTED", h.Status)
	}
	if h.Flags&smb2.FlagAsyncCommand != 0 {
		t.Error("fail-immediately conflict answered with an async response")
	}
}

// TestLockBlockingWaitsAndCompletesAsync proves a blocking LOCK request (no
// SMB2_LOCKFLAG_FAIL_IMMEDIATELY) is parked instead of being refused: the
// client gets an interim STATUS_PENDING, handleLock returns immediately so the
// connection's read loop keeps serving, and the request completes with
// STATUS_SUCCESS once the conflicting range is released.
func TestLockBlockingWaitsAndCompletesAsync(t *testing.T) {
	d, sess, openA, openB := openPair(t, "blocking.bin")
	if err := d.locks.applyLock(openB, 0, 100, lockExclusive); err != nil {
		t.Fatalf("B lock: %v", err)
	}

	body := encodeLockBody(openA.FileID, []lockElemSpec{
		{offset: 0, length: 100, flags: smb2.LockFlagExclusiveLock},
	})
	w := &syncWriter{}

	done := make(chan bool, 1)
	go func() {
		done <- d.handleLock(w, smb2.Header{Command: smb2.CommandLock, MessageID: 21}, body, sess)
	}()
	select {
	case cont := <-done:
		if !cont {
			t.Fatal("handleLock returned false")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleLock blocked the caller: a blocking lock must not stall the read loop")
	}

	pending := awaitFrame(t, w, 1, 2*time.Second)
	if smb2.Status(pending.Status) != smb2.StatusPending {
		t.Fatalf("interim status = 0x%08X, want STATUS_PENDING", pending.Status)
	}
	if pending.Flags&smb2.FlagAsyncCommand == 0 {
		t.Error("interim response is missing SMB2_FLAGS_ASYNC_COMMAND")
	}

	// Release the conflicting range: the parked request must now be granted.
	if err := d.locks.applyLock(openB, 0, 100, lockUnlock); err != nil {
		t.Fatalf("B unlock: %v", err)
	}
	final := awaitFrame(t, w, 2, 5*time.Second)
	if smb2.Status(final.Status) != smb2.StatusSuccess {
		t.Errorf("completion status = 0x%08X, want STATUS_SUCCESS", final.Status)
	}
	if final.Flags&smb2.FlagAsyncCommand == 0 {
		t.Error("completion is missing SMB2_FLAGS_ASYNC_COMMAND")
	}
	if final.MessageID != 21 {
		t.Errorf("completion MessageId = %d, want 21 (the original request)", final.MessageID)
	}
	d.locks.releaseAll(openA)
}

// TestLockBlockingCancelCompletesRequest proves a parked LOCK is completed —
// not orphaned — when the client cancels it or the handle goes away.
func TestLockBlockingCancelCompletesRequest(t *testing.T) {
	d, sess, openA, openB := openPair(t, "blocking-cancel.bin")
	if err := d.locks.applyLock(openB, 0, 100, lockExclusive); err != nil {
		t.Fatalf("B lock: %v", err)
	}

	body := encodeLockBody(openA.FileID, []lockElemSpec{
		{offset: 0, length: 100, flags: smb2.LockFlagExclusiveLock},
	})
	w := &syncWriter{}
	if !d.handleLock(w, smb2.Header{Command: smb2.CommandLock, MessageID: 22}, body, sess) {
		t.Fatal("handleLock returned false")
	}
	if h := awaitFrame(t, w, 1, 2*time.Second); smb2.Status(h.Status) != smb2.StatusPending {
		t.Fatalf("interim status = 0x%08X, want STATUS_PENDING", h.Status)
	}

	// SMB2_CANCEL for that MessageId.
	if !d.cancelNotify(22, smb2.StatusCancelled) {
		t.Fatal("cancel did not find the parked LOCK request")
	}
	if h := awaitFrame(t, w, 2, 5*time.Second); smb2.Status(h.Status) != smb2.StatusCancelled {
		t.Errorf("completion status = 0x%08X, want STATUS_CANCELLED", h.Status)
	}
	d.locks.releaseAll(openB)
}

// --- finding 3: bounded table, cheap hot path --------------------------------

// TestLockTableCapsTrackedRanges proves a client cannot grow the lock table
// without limit: past the per-handle and per-file caps the table refuses the
// range with errLockLimit (STATUS_INSUFFICIENT_RESOURCES) instead of growing
// the list every READ and WRITE has to scan.
func TestLockTableCapsTrackedRanges(t *testing.T) {
	key := fileKey{dev: 3, ino: 4}

	t.Run("per-owner cap", func(t *testing.T) {
		tb := newRangeTable()
		owner := &Open{Path: "greedy"}
		for i := 0; i < maxLockRangesPerOwner; i++ {
			if err := tb.apply(key, owner, uint64(i)*10, 1, lockExclusive); err != nil {
				t.Fatalf("range %d rejected early: %v", i, err)
			}
		}
		err := tb.apply(key, owner, uint64(maxLockRangesPerOwner)*10, 1, lockExclusive)
		if !errors.Is(err, errLockLimit) {
			t.Fatalf("range past the per-handle cap: got %v, want errLockLimit", err)
		}
		if got := lockStatus(err); got != smb2.StatusInsufficientResources {
			t.Errorf("errLockLimit maps to 0x%08X, want STATUS_INSUFFICIENT_RESOURCES", uint32(got))
		}
	})

	t.Run("per-file cap across handles", func(t *testing.T) {
		tb := newRangeTable()
		// Pre-fill directly: going through apply would make this O(n²) for no
		// extra coverage — the cap check is what's under test.
		fillers := make([]Open, maxLockRangesPerFile)
		ranges := make([]lockRange, maxLockRangesPerFile)
		for i := range ranges {
			ranges[i] = lockRange{owner: &fillers[i], start: uint64(i) * 10, length: 1}
		}
		tb.locks[key] = ranges
		tb.n = len(ranges)

		err := tb.apply(key, &Open{Path: "newcomer"}, 1<<40, 1, lockExclusive)
		if !errors.Is(err, errLockLimit) {
			t.Fatalf("range past the per-file cap: got %v, want errLockLimit", err)
		}
	})

	t.Run("re-locking a held range does not grow the table", func(t *testing.T) {
		tb := newRangeTable()
		owner := &Open{Path: "repeater"}
		for i := 0; i < 1000; i++ {
			if err := tb.apply(key, owner, 0, 100, lockExclusive); err != nil {
				t.Fatalf("repeat %d: %v", i, err)
			}
		}
		if n := len(tb.locks[key]); n != 1 {
			t.Errorf("re-locking one range 1000 times tracked %d entries, want 1", n)
		}
	})
}

// TestLockTableEmptyFastPath proves the I/O hot path can skip the table
// entirely when nothing is locked, and that the counter behind that fast path
// tracks adds and releases correctly.
func TestLockTableEmptyFastPath(t *testing.T) {
	lt := newLockTable()
	key := fileKey{dev: 5, ino: 6}
	owner := &Open{Path: "owner"}
	other := &Open{Path: "other"}

	if !lt.empty() {
		t.Fatal("a fresh table must report empty")
	}
	if lt.conflict(key, other, 0, 10, true) {
		t.Error("nothing is locked, so no I/O can conflict")
	}

	if err := lt.apply(key, owner, 0, 100, lockExclusive); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if lt.empty() {
		t.Error("a table holding a lock must not report empty")
	}
	if !lt.conflict(key, other, 0, 10, true) {
		t.Error("write into a locked range must conflict")
	}

	lt.releaseOwner(key, owner)
	if !lt.empty() {
		t.Error("table must report empty again once every range is released")
	}
}

// TestLockTableReleaseSignal proves parked blocking LOCK requests are woken by
// a release and only by a release.
func TestLockTableReleaseSignal(t *testing.T) {
	lt := newLockTable()
	key := fileKey{dev: 7, ino: 8}
	owner := &Open{Path: "owner"}

	ch := lt.releaseSignal()
	if err := lt.apply(key, owner, 0, 100, lockExclusive); err != nil {
		t.Fatalf("lock: %v", err)
	}
	select {
	case <-ch:
		t.Fatal("taking a lock must not wake waiters")
	default:
	}

	if err := lt.apply(key, owner, 0, 100, lockUnlock); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	select {
	case <-ch:
	default:
		t.Fatal("releasing a range must wake parked waiters")
	}

	// A fresh subscription is handed out after the broadcast fires.
	if next := lt.releaseSignal(); next == ch {
		t.Fatal("releaseSignal must hand out a new channel after firing")
	}
}

// --- finding 4: identical range semantics on both platforms ------------------

// TestLockRangeSemanticsAreShared pins the (offset,length) semantics both the
// linux and darwin managers rely on. Linux drops zero-length ranges before
// fcntl (where a zero length would mean "to end of file") and converts a huge
// length to l_len 0; the shared table has to agree with that, or the same
// client request behaves differently per platform.
func TestLockRangeSemanticsAreShared(t *testing.T) {
	key := fileKey{dev: 11, ino: 12}
	owner := &Open{Path: "owner"}
	other := &Open{Path: "other"}

	t.Run("zero length covers no bytes and is not tracked", func(t *testing.T) {
		lt := newLockTable()
		if err := lt.apply(key, owner, 0, 0, lockExclusive); err != nil {
			t.Fatalf("zero-length lock: %v", err)
		}
		if !lt.empty() {
			t.Error("a zero-length lock must not occupy a table slot")
		}
		if lt.conflict(key, other, 0, 100, true) {
			t.Error("a zero-length lock must not block anyone's I/O")
		}
		// It also must not block a real lock over the same offset.
		if err := lt.apply(key, other, 0, 100, lockExclusive); err != nil {
			t.Errorf("zero-length lock blocked a real one: %v", err)
		}
	})

	t.Run("zero-length I/O never conflicts", func(t *testing.T) {
		lt := newLockTable()
		if err := lt.apply(key, owner, 0, 100, lockExclusive); err != nil {
			t.Fatal(err)
		}
		if lt.conflict(key, other, 50, 0, true) {
			t.Error("an I/O of zero bytes touches nothing and cannot conflict")
		}
	})

	t.Run("huge length means to end of file", func(t *testing.T) {
		lt := newLockTable()
		if err := lt.apply(key, owner, 100, ^uint64(0), lockExclusive); err != nil {
			t.Fatalf("lock-to-EOF: %v", err)
		}
		if !lt.conflict(key, other, 1<<40, 8, false) {
			t.Error("lock-to-EOF must cover every byte above its offset")
		}
		if lt.conflict(key, other, 0, 100, false) {
			t.Error("lock-to-EOF from 100 must not cover the bytes below it")
		}
		if err := lt.apply(key, other, 1<<40, 8, lockExclusive); !errors.Is(err, errLockConflict) {
			t.Errorf("lock inside a lock-to-EOF range: got %v, want errLockConflict", err)
		}
	})

	t.Run("offset past the signed maximum is rejected on both platforms", func(t *testing.T) {
		// fcntl's l_start is an int64 and no POSIX file reaches 2^63, so linux
		// cannot express this range. darwin used to accept and track it.
		if _, ok := decodeLockOps([]smb2.LockElement{
			{Offset: 1 << 63, Length: 1, Flags: smb2.LockFlagExclusiveLock},
		}); ok {
			t.Error("an offset above 2^63-1 must be rejected")
		}
		if _, ok := decodeLockOps([]smb2.LockElement{
			{Offset: 1 << 62, Length: ^uint64(0), Flags: smb2.LockFlagExclusiveLock},
		}); !ok {
			t.Error("a representable offset with a lock-to-EOF length must be accepted")
		}
	})

	t.Run("unknown flags are rejected", func(t *testing.T) {
		if _, ok := decodeLockOps([]smb2.LockElement{{Offset: 0, Length: 1, Flags: 0}}); ok {
			t.Error("an element with no lock/unlock flag must be rejected")
		}
	})
}
