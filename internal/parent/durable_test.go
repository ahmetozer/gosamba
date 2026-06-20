package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
)

// --- DurableTable unit tests ---

func TestDurableTable_RegisterReclaim(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	cg[0] = 0xAA
	crg[0] = 0xBB
	open := &Open{Path: "/tmp/x", GrantedAccess: 0x1F01FF}

	tbl.Register(cg, crg, open, time.Minute, "share")
	got, ok := tbl.Reclaim(cg, crg)
	if !ok {
		t.Fatalf("Reclaim returned ok=false, want true")
	}
	if got != open {
		t.Fatalf("Reclaim returned different open")
	}
	// A second reclaim must fail — Reclaim removes the entry.
	if _, ok := tbl.Reclaim(cg, crg); ok {
		t.Fatalf("second Reclaim returned ok=true, want false")
	}
}

func TestDurableTable_ReclaimAfterExpiry(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	open := &Open{Path: "/tmp/y"}
	tbl.Register(cg, crg, open, 5*time.Millisecond, "share")
	time.Sleep(15 * time.Millisecond)
	if _, ok := tbl.Reclaim(cg, crg); ok {
		t.Fatalf("Reclaim after expiry returned ok=true, want false")
	}
}

func TestDurableTable_Remove(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	tbl.Register(cg, crg, &Open{}, time.Minute, "share")
	tbl.Remove(cg, crg)
	if _, ok := tbl.Reclaim(cg, crg); ok {
		t.Fatalf("Reclaim after Remove returned ok=true, want false")
	}
}

func TestDurableTable_Expire(t *testing.T) {
	tbl := NewDurableTable()
	var cg, a, b [16]byte
	a[0] = 1
	b[0] = 2
	tbl.Register(cg, a, &Open{}, 5*time.Millisecond, "share")
	tbl.Register(cg, b, &Open{}, time.Hour, "share")
	time.Sleep(15 * time.Millisecond)
	if n := tbl.Expire(time.Now()); n != 1 {
		t.Fatalf("Expire evicted %d, want 1", n)
	}
	if got := tbl.len(); got != 1 {
		t.Fatalf("after Expire len=%d, want 1", got)
	}
}

func TestDurableTable_ConcurrentAccess(t *testing.T) {
	tbl := NewDurableTable()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var cg, crg [16]byte
			cg[0] = byte(n)
			crg[1] = byte(n)
			tbl.Register(cg, crg, &Open{}, time.Minute, "share")
			tbl.Reclaim(cg, crg)
			tbl.Register(cg, crg, &Open{}, time.Minute, "share")
			tbl.Remove(cg, crg)
			tbl.Expire(time.Now())
		}(i)
	}
	wg.Wait()
}

// --- create-context parse/encode unit tests ---

func TestParseDurableContexts_DH2Q(t *testing.T) {
	var data [32]byte
	binary.LittleEndian.PutUint32(data[0:], 30000) // timeout ms
	var guid [16]byte
	guid[0] = 0x77
	copy(data[16:32], guid[:])
	raw := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: data[:]}})

	dq, _, _ := parseDurableContexts(raw)
	if !dq.present || !dq.v2 {
		t.Fatalf("DH2Q not parsed: %+v", dq)
	}
	if dq.timeout != 30000 {
		t.Fatalf("timeout=%d, want 30000", dq.timeout)
	}
	if dq.guid != guid {
		t.Fatalf("guid mismatch: %x", dq.guid)
	}
}

func TestParseDurableContexts_RqLs(t *testing.T) {
	data := make([]byte, 32)
	var key [16]byte
	key[0] = 0x55
	copy(data[0:16], key[:])
	binary.LittleEndian.PutUint32(data[16:], leaseReadCaching|leaseWriteCaching)
	raw := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagRqLs, Data: data}})

	_, _, lr := parseDurableContexts(raw)
	if !lr.present {
		t.Fatalf("RqLs not parsed")
	}
	if lr.key != key {
		t.Fatalf("lease key mismatch")
	}
}

// --- white-box handleCreate tests ---

// newDurableDispatcher wires a Dispatcher with a Connection (carrying a
// ClientGuid + DurableTable) so handleCreate can register/reclaim.
func newDurableDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree, *DurableTable) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir}
	tbl := NewDurableTable()
	conn := &Connection{}
	conn.ClientGuid[0] = 0xC1
	conn.Durable = tbl
	conn.DurableTimeout = time.Minute
	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{share},
		Conn:   conn,
	}
	sess := &Session{}
	tree := sess.AddTree(share)
	return d, sess, tree, tbl
}

// buildCreateBody constructs a CREATE request body (StructureSize 57) with the
// given name and create-context blob, matching DecodeCreateRequest's layout.
func buildCreateBody(name string, disposition, options, access uint32, ctxs []byte) []byte {
	const headerSize = 64
	nameU16 := utf16leName(name)
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[24:], access)
	binary.LittleEndian.PutUint32(body[36:], disposition)
	binary.LittleEndian.PutUint32(body[40:], options)
	// Name follows the fixed 56-byte body.
	nameOff := headerSize + 56
	binary.LittleEndian.PutUint16(body[44:], uint16(nameOff))
	binary.LittleEndian.PutUint16(body[46:], uint16(len(nameU16)))
	body = append(body, nameU16...)
	if len(ctxs) > 0 {
		// Pad to 8-byte boundary before the contexts.
		for (len(body)+headerSize)%8 != 0 {
			body = append(body, 0)
		}
		ccOff := headerSize + len(body)
		binary.LittleEndian.PutUint32(body[48:], uint32(ccOff))
		binary.LittleEndian.PutUint32(body[52:], uint32(len(ctxs)))
		body = append(body, ctxs...)
	}
	return body
}

// readCreateResponse parses the NBSS-framed CREATE response from buf.
func readCreateResponse(t *testing.T, buf *bytes.Buffer) (smb2.Header, smb2.CreateResponse, []byte) {
	t.Helper()
	frame := buf.Bytes()
	// Strip the 4-byte NBSS length prefix.
	if len(frame) < 4 {
		t.Fatalf("response too short")
	}
	frame = frame[4:]
	hdr, err := smb2.DecodeHeader(frame[:smb2.HeaderSize])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	body := frame[smb2.HeaderSize:]
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		return hdr, smb2.CreateResponse{}, nil
	}
	// CREATE response fixed part is 88 bytes; FileID at body[64:80].
	var resp smb2.CreateResponse
	copy(resp.FileID[:], body[64:80])
	ccOff := binary.LittleEndian.Uint32(body[80:])
	ccLen := binary.LittleEndian.Uint32(body[84:])
	var ctxs []byte
	if ccLen > 0 {
		start := int(ccOff) - smb2.HeaderSize
		ctxs = body[start : start+int(ccLen)]
	}
	return hdr, resp, ctxs
}

func hasContext(raw []byte, tag []byte) bool {
	found := false
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		if eqTag(c.Name, tag) {
			found = true
			return false
		}
		return true
	})
	return found
}

func TestHandleCreate_DurableGrantAndReconnect(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "dur.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, tbl := newDurableDispatcher(t, shareDir)

	// --- 1: fresh durable open with DH2Q ---
	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0] = 0x9E
	copy(dh2q[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}})
	body := buildCreateBody("dur.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandCreate, TreeID: 2}
	if !d.handleCreate(&buf, hdr, body, sess) {
		t.Fatalf("handleCreate returned false")
	}
	rhdr, resp, rctxs := readCreateResponse(t, &buf)
	if smb2.Status(rhdr.Status) != smb2.StatusSuccess {
		t.Fatalf("durable create status=0x%08X", rhdr.Status)
	}
	if !hasContext(rctxs, tagDH2Q) {
		t.Fatalf("response did not echo DH2Q context")
	}
	if tbl.len() != 1 {
		t.Fatalf("durable table len=%d, want 1", tbl.len())
	}
	firstFileID := resp.FileID

	// --- 2: simulate connection drop. The Open stays in the session in this
	// white-box harness, but the durable entry must survive for reclaim. Drop
	// it from the session to emulate a fresh connection. ---
	sess.RemoveOpen(firstFileID)
	sess2 := &Session{}
	sess2.AddTree(d.Shares[0])

	// --- 3: reconnect with DH2C for the same CreateGuid ---
	var dh2c [36]byte
	copy(dh2c[0:16], firstFileID[:])
	copy(dh2c[16:32], createGuid[:])
	rctxsReq := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2C, Data: dh2c[:]}})
	body2 := buildCreateBody("dur.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, rctxsReq)

	var buf2 bytes.Buffer
	hdr2 := smb2.Header{Command: smb2.CommandCreate, TreeID: 2}
	if !d.handleCreate(&buf2, hdr2, body2, sess2) {
		t.Fatalf("reconnect handleCreate returned false")
	}
	rhdr2, resp2, _ := readCreateResponse(t, &buf2)
	if smb2.Status(rhdr2.Status) != smb2.StatusSuccess {
		t.Fatalf("reconnect status=0x%08X, want SUCCESS", rhdr2.Status)
	}
	if resp2.FileID != firstFileID {
		t.Fatalf("reclaimed FileID=%x, want %x (same handle)", resp2.FileID, firstFileID)
	}
	reclaimed := sess2.GetOpen(firstFileID)
	if reclaimed == nil || reclaimed.Path != filepath.Join(shareDir, "dur.txt") {
		t.Fatalf("reclaimed open not restored on new session: %+v", reclaimed)
	}
}

func TestHandleCreate_ReconnectMissingFails(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "z.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, _ := newDurableDispatcher(t, shareDir)

	var dh2c [36]byte
	dh2c[0] = 0xDE // bogus FileID
	dh2c[16] = 0xAD // bogus CreateGuid
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2C, Data: dh2c[:]}})
	body := buildCreateBody("z.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandCreate, TreeID: 2}
	d.handleCreate(&buf, hdr, body, sess)
	rhdr, _, _ := readCreateResponse(t, &buf)
	if smb2.Status(rhdr.Status) != smb2.StatusObjectNameNotFound {
		t.Fatalf("missing reconnect status=0x%08X, want OBJECT_NAME_NOT_FOUND", rhdr.Status)
	}
}

func TestHandleCreate_DurableRemovedOnClose(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "c.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, tbl := newDurableDispatcher(t, shareDir)

	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0] = 0x42
	copy(dh2q[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}})
	body := buildCreateBody("c.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: 2}, body, sess)
	_, resp, _ := readCreateResponse(t, &buf)
	if tbl.len() != 1 {
		t.Fatalf("after durable create, table len=%d want 1", tbl.len())
	}

	// Clean CLOSE must drop the durable entry.
	var cbuf bytes.Buffer
	d.handleClose(&cbuf, smb2.Header{Command: smb2.CommandClose}, buildCloseBody(resp.FileID), sess)
	if tbl.len() != 0 {
		t.Fatalf("after clean close, table len=%d want 0", tbl.len())
	}
}

func TestHandleCreate_LeaseEcho(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "l.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, _, _ := newDurableDispatcher(t, shareDir)

	data := make([]byte, 32)
	var key [16]byte
	key[0] = 0xAB
	copy(data[0:16], key[:])
	binary.LittleEndian.PutUint32(data[16:], leaseReadCaching|leaseWriteCaching|leaseHandleCaching)
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagRqLs, Data: data}})
	body := buildCreateBody("l.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: 2}, body, sess)
	rhdr, _, rctxs := readCreateResponse(t, &buf)
	if smb2.Status(rhdr.Status) != smb2.StatusSuccess {
		t.Fatalf("lease create status=0x%08X", rhdr.Status)
	}
	if !hasContext(rctxs, tagRqLs) {
		t.Fatalf("response did not echo RqLs")
	}
	// Verify the granted state is exactly READ caching (we never grant W/H).
	var granted uint32
	smb2.IterateCreateContexts(rctxs, func(c smb2.CreateContext) bool {
		if eqTag(c.Name, tagRqLs) && len(c.Data) >= 20 {
			granted = binary.LittleEndian.Uint32(c.Data[16:])
			return false
		}
		return true
	})
	if granted != leaseReadCaching {
		t.Fatalf("granted lease state=0x%X, want 0x%X (READ only)", granted, leaseReadCaching)
	}
}

// TestDurableTable_ExpireClosesFd verifies that Expire closes the underlying
// *os.File so no fd is leaked. We open a real temp file, register it with a
// tiny timeout, advance past the deadline, call Expire, and confirm the file is
// already closed (a second Close returns an error or "use of closed file").
func TestDurableTable_ExpireClosesFd(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0xFD

	f, err := os.CreateTemp(t.TempDir(), "dur-fd-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{File: f}

	// Register with a 1 ms timeout so we can advance past it without sleeping.
	tbl.Register(cg, crg, open, time.Millisecond, "share")

	// Advance time by calling Expire with a future timestamp — no real sleep.
	evicted := tbl.Expire(time.Now().Add(time.Second))
	if evicted != 1 {
		t.Fatalf("Expire evicted %d entries, want 1", evicted)
	}
	if tbl.len() != 0 {
		t.Fatalf("table len=%d after Expire, want 0", tbl.len())
	}

	// The fd should be closed; a second Close must fail.
	if err := f.Close(); err == nil {
		t.Fatalf("second Close on evicted fd succeeded, want error (fd already closed by Expire)")
	}
}

// TestDurableTable_LazyReclaimClosesFd verifies that a lazy-eviction during
// Reclaim (entry expired but not yet swept) also closes the fd.
func TestDurableTable_LazyReclaimClosesFd(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0xFE

	f, err := os.CreateTemp(t.TempDir(), "dur-lazy-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	open := &Open{File: f}
	tbl.Register(cg, crg, open, time.Millisecond, "share")

	// Sleep past the deadline so the entry is expired when Reclaim checks it.
	time.Sleep(10 * time.Millisecond)

	if _, ok := tbl.Reclaim(cg, crg); ok {
		t.Fatalf("Reclaim returned ok=true on expired entry, want false")
	}
	if tbl.len() != 0 {
		t.Fatalf("table len=%d after lazy eviction, want 0", tbl.len())
	}

	// The fd must have been closed during the lazy eviction.
	if err := f.Close(); err == nil {
		t.Fatalf("second Close on lazily-evicted fd succeeded, want error (fd already closed)")
	}
}

// TestDurableTable_ShareBinding verifies that ReclaimForShare rejects a
// reconnect arriving on the wrong share (entry is NOT consumed) and succeeds on
// the correct share.
func TestDurableTable_ShareBinding(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0xAB

	open := &Open{Path: "/tmp/bound"}
	tbl.Register(cg, crg, open, time.Minute, "shareA")

	// Wrong share: must fail without consuming the entry.
	if _, ok := tbl.ReclaimForShare(cg, crg, "shareB"); ok {
		t.Fatalf("ReclaimForShare with wrong share returned ok=true, want false")
	}
	if tbl.len() != 1 {
		t.Fatalf("entry consumed by wrong-share reclaim, len=%d want 1", tbl.len())
	}

	// Correct share: must succeed and consume the entry.
	got, ok := tbl.ReclaimForShare(cg, crg, "shareA")
	if !ok {
		t.Fatalf("ReclaimForShare with correct share returned ok=false, want true")
	}
	if got != open {
		t.Fatalf("ReclaimForShare returned wrong open")
	}
	if tbl.len() != 0 {
		t.Fatalf("entry not consumed after successful ReclaimForShare, len=%d want 0", tbl.len())
	}
}

// TestHandleCreate_DurableReconnectWrongShareFails verifies the end-to-end
// share-binding check: a DH2C reconnect on the wrong share returns
// STATUS_OBJECT_NAME_NOT_FOUND and the entry is NOT consumed.
func TestHandleCreate_DurableReconnectWrongShareFails(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "sb.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// shareA is where the original open lives.
	shareA := config.ShareConfig{Name: "shareA", Path: shareDir}
	// shareB is a different share — reconnect will arrive here.
	shareB := config.ShareConfig{Name: "shareB", Path: shareDir}

	tbl := NewDurableTable()
	conn := &Connection{}
	conn.ClientGuid[0] = 0xC2
	conn.Durable = tbl
	conn.DurableTimeout = time.Minute

	d := &Dispatcher{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares: []config.ShareConfig{shareA, shareB},
		Conn:   conn,
	}
	sessA := &Session{}
	treeA := sessA.AddTree(shareA)

	// --- 1: open on shareA with DH2Q ---
	var dh2q [32]byte
	binary.LittleEndian.PutUint32(dh2q[0:], 30000)
	var createGuid [16]byte
	createGuid[0] = 0x7A
	copy(dh2q[16:32], createGuid[:])
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2Q, Data: dh2q[:]}})
	body := buildCreateBody("sb.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, ctxs)

	var buf bytes.Buffer
	hdr := smb2.Header{Command: smb2.CommandCreate, TreeID: treeA.ID}
	if !d.handleCreate(&buf, hdr, body, sessA) {
		t.Fatalf("initial handleCreate returned false")
	}
	_, resp, _ := readCreateResponse(t, &buf)
	if tbl.len() != 1 {
		t.Fatalf("durable table len=%d after open, want 1", tbl.len())
	}
	firstFileID := resp.FileID

	// Simulate drop: remove open from session.
	sessA.RemoveOpen(firstFileID)

	// --- 2: reconnect on shareB --- must fail, entry untouched ---
	sessB := &Session{}
	treeB := sessB.AddTree(shareB)

	var dh2c [36]byte
	copy(dh2c[0:16], firstFileID[:])
	copy(dh2c[16:32], createGuid[:])
	rctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: tagDH2C, Data: dh2c[:]}})
	body2 := buildCreateBody("sb.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, rctxs)

	var buf2 bytes.Buffer
	hdr2 := smb2.Header{Command: smb2.CommandCreate, TreeID: treeB.ID}
	d.handleCreate(&buf2, hdr2, body2, sessB)
	rhdr2, _, _ := readCreateResponse(t, &buf2)
	if smb2.Status(rhdr2.Status) != smb2.StatusObjectNameNotFound {
		t.Fatalf("wrong-share reconnect status=0x%08X, want OBJECT_NAME_NOT_FOUND", rhdr2.Status)
	}
	// Entry must still be in the table — not consumed.
	if tbl.len() != 1 {
		t.Fatalf("wrong-share reclaim consumed entry: table len=%d, want 1", tbl.len())
	}

	// --- 3: reconnect on correct shareA --- must succeed ---
	sessC := &Session{}
	treeC := sessC.AddTree(shareA)

	var buf3 bytes.Buffer
	hdr3 := smb2.Header{Command: smb2.CommandCreate, TreeID: treeC.ID}
	if !d.handleCreate(&buf3, hdr3, body2, sessC) {
		t.Fatalf("correct-share reconnect handleCreate returned false")
	}
	rhdr3, resp3, _ := readCreateResponse(t, &buf3)
	if smb2.Status(rhdr3.Status) != smb2.StatusSuccess {
		t.Fatalf("correct-share reconnect status=0x%08X, want SUCCESS", rhdr3.Status)
	}
	if resp3.FileID != firstFileID {
		t.Fatalf("reclaimed FileID mismatch: got %x, want %x", resp3.FileID, firstFileID)
	}
}
