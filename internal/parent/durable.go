// Package parent durable-handle implementation.
//
// Limitation — per-user-privdrop: when --per-user-privdrop is enabled, each
// accepted TCP connection is served by a freshly re-exec'd worker process with
// its own private DurableTable. Because the table is process-local, a durable
// handle registered by one connection's worker cannot be reclaimed by a
// subsequent reconnect that arrives on a different (new) worker process.
// Clients will transparently re-open their handles; no data is lost, but the
// server cannot honour the MS-SMB2 durable-reconnect guarantee in this mode.
package parent

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// Create-context tags for durable handles and leases (MS-SMB2 §2.2.13.2).
var (
	tagDH2Q = []byte("DH2Q") // durable handle request v2
	tagDHnQ = []byte("DHnQ") // durable handle request v1
	tagDH2C = []byte("DH2C") // durable handle reconnect v2
	tagDHnC = []byte("DHnC") // durable handle reconnect v1
	tagRqLs = []byte("RqLs") // lease request
)

// Lease state bits (MS-SMB2 §2.2.13.2.8). We only ever grant READ caching.
const (
	leaseNone         uint32 = 0x00
	leaseReadCaching  uint32 = 0x01
	leaseWriteCaching uint32 = 0x02
	leaseHandleCaching uint32 = 0x04
)

// durableRequest is the parsed result of a fresh durable-handle request
// (DH2Q or DHnQ) extracted from a CREATE's create contexts.
type durableRequest struct {
	present bool
	v2      bool        // true for DH2Q, false for DHnQ
	timeout uint32      // requested timeout in ms (v2 only; 0 for v1)
	flags   uint32      // v2 flags (e.g. PERSISTENT)
	guid    [16]byte    // CreateGuid (v2 only; zero for v1)
}

// durableReconnect is the parsed result of a reconnect request (DH2C or DHnC).
type durableReconnect struct {
	present bool
	v2      bool
	fileID  [16]byte
	guid    [16]byte // CreateGuid (v2 only)
}

// leaseRequest is the parsed RqLs create context.
type leaseRequest struct {
	present  bool
	key      [16]byte
	state    uint32
}

// parseDurableContexts walks the raw create-context blob and extracts any
// durable-handle request, reconnect, and lease request present.
func parseDurableContexts(raw []byte) (durableRequest, durableReconnect, leaseRequest) {
	var dq durableRequest
	var dc durableReconnect
	var lr leaseRequest
	if len(raw) == 0 {
		return dq, dc, lr
	}
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		switch {
		case eqTag(c.Name, tagDH2Q):
			// Timeout(4) Flags(4) Reserved(8) CreateGuid(16)
			if len(c.Data) >= 32 {
				dq.present = true
				dq.v2 = true
				dq.timeout = binary.LittleEndian.Uint32(c.Data[0:])
				dq.flags = binary.LittleEndian.Uint32(c.Data[4:])
				copy(dq.guid[:], c.Data[16:32])
			}
		case eqTag(c.Name, tagDHnQ):
			// 16 reserved bytes.
			dq.present = true
			dq.v2 = false
		case eqTag(c.Name, tagDH2C):
			// FileId(16) CreateGuid(16) Flags(4)
			if len(c.Data) >= 36 {
				dc.present = true
				dc.v2 = true
				copy(dc.fileID[:], c.Data[0:16])
				copy(dc.guid[:], c.Data[16:32])
			}
		case eqTag(c.Name, tagDHnC):
			// FileId(16)
			if len(c.Data) >= 16 {
				dc.present = true
				dc.v2 = false
				copy(dc.fileID[:], c.Data[0:16])
			}
		case eqTag(c.Name, tagRqLs):
			// v1: LeaseKey(16) LeaseState(4) Flags(4) Duration(8); v2 adds more.
			if len(c.Data) >= 20 {
				lr.present = true
				copy(lr.key[:], c.Data[0:16])
				lr.state = binary.LittleEndian.Uint32(c.Data[16:])
			}
		}
		return true
	})
	return dq, dc, lr
}

func eqTag(name, tag []byte) bool {
	if len(name) != len(tag) {
		return false
	}
	for i := range name {
		if name[i] != tag[i] {
			return false
		}
	}
	return true
}

// encodeDH2QResponse builds the DH2Q response context payload:
// Timeout(4) Flags(4).
func encodeDH2QResponse(timeout uint32, flags uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], timeout)
	binary.LittleEndian.PutUint32(b[4:], flags)
	return b
}

// encodeDHnQResponse builds the DHnQ v1 response context payload: 8 reserved.
func encodeDHnQResponse() []byte { return make([]byte, 8) }

// encodeRqLsResponse builds an RqLs response echoing the lease key and the
// granted lease state. We use the v1 (32-byte) form: LeaseKey(16) LeaseState(4)
// Flags(4) Duration(8).
func encodeRqLsResponse(key [16]byte, granted uint32) []byte {
	b := make([]byte, 32)
	copy(b[0:16], key[:])
	binary.LittleEndian.PutUint32(b[16:], granted)
	return b
}

// durableKey identifies a durable-handle table entry. Keying by both the
// client's NEGOTIATE GUID and the per-open CreateGuid (v2) means a reconnect
// from the same client machine can reclaim its handle even across a dropped
// TCP connection. For v1 durable handles (no CreateGuid) the FileID stands in
// for the CreateGuid slot.
type durableKey struct {
	clientGuid [16]byte
	createGuid [16]byte
}

// durableEntry is a reclaimable open kept alive past its Connection's death
// until the deadline expires.
type durableEntry struct {
	open      *Open
	deadline  time.Time
	shareName string // original share name; reconnect must arrive on same share
}

// DurableTable holds durable opens keyed by (ClientGuid, CreateGuid). It is
// server-scoped (created once and shared across every ServeConn) so an entry
// survives the drop of the TCP connection that created it: a client that
// reconnects within DurableTimeout can reclaim the handle.
type DurableTable struct {
	mu      sync.Mutex
	entries map[durableKey]*durableEntry
}

// NewDurableTable returns an empty, ready-to-use table.
func NewDurableTable() *DurableTable {
	return &DurableTable{entries: make(map[durableKey]*durableEntry)}
}

// Register records an open as durable, reclaimable until now+timeout. The
// shareName is stored and checked on reclaim (MS-SMB2 §3.3.5.9.7). A zero or
// negative timeout removes any existing entry (treated as non-durable).
func (t *DurableTable) Register(clientGuid, createGuid [16]byte, open *Open, timeout time.Duration, shareName string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	if timeout <= 0 {
		delete(t.entries, k)
		return
	}
	t.entries[k] = &durableEntry{open: open, deadline: time.Now().Add(timeout), shareName: shareName}
}

// Reclaim returns the live open for (clientGuid, createGuid) and removes it from
// the table. It returns ok=false if no entry exists or the entry has expired
// (expired entries are evicted, and their open fd is closed to avoid leaks).
func (t *DurableTable) Reclaim(clientGuid, createGuid [16]byte) (*Open, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return nil, false
	}
	delete(t.entries, k)
	if time.Now().After(e.deadline) {
		// Lazy eviction: close the fd so we don't leak it.
		if e.open != nil && e.open.File != nil {
			e.open.File.Close()
		}
		return nil, false
	}
	return e.open, true
}

// ReclaimForShare is like Reclaim but additionally enforces that the reconnect
// arrives on the same share as the original CREATE (MS-SMB2 §3.3.5.9.7). If
// the share name does not match, it returns ok=false without consuming the
// entry (leaving it available for a correctly-targeted reconnect attempt or
// expiry sweep).
func (t *DurableTable) ReclaimForShare(clientGuid, createGuid [16]byte, shareName string) (*Open, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.deadline) {
		// Lazy eviction: close the fd so we don't leak it.
		if e.open != nil && e.open.File != nil {
			e.open.File.Close()
		}
		delete(t.entries, k)
		return nil, false
	}
	// Share mismatch: reject without consuming the entry.
	if e.shareName != shareName {
		return nil, false
	}
	delete(t.entries, k)
	return e.open, true
}

// Has reports whether the table has a live (non-expired) entry for the given
// (clientGuid, createGuid) pair. It is used during connection teardown to
// distinguish durable opens (which must stay alive for reclaim) from ordinary
// opens (whose fds should be closed).
func (t *DurableTable) Has(clientGuid, createGuid [16]byte) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := durableKey{clientGuid: clientGuid, createGuid: createGuid}
	e, ok := t.entries[k]
	if !ok {
		return false
	}
	return !time.Now().After(e.deadline)
}

// StartSweeper launches a background goroutine that calls Expire at regular
// intervals until ctx is cancelled. It should be called once after the table
// is created.
func (t *DurableTable) StartSweeper(ctx context.Context, interval time.Duration) {
	if t == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.Expire(time.Now())
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Remove deletes the entry for (clientGuid, createGuid) — used on a clean CLOSE
// of a durable handle (a clean close means the handle is not reclaimable).
func (t *DurableTable) Remove(clientGuid, createGuid [16]byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, durableKey{clientGuid: clientGuid, createGuid: createGuid})
}

// Expire evicts every entry whose deadline is before now, closing the
// underlying file handle so we don't leak descriptors. It returns the number
// of entries evicted.
func (t *DurableTable) Expire(now time.Time) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, e := range t.entries {
		if now.After(e.deadline) {
			if e.open != nil && e.open.File != nil {
				e.open.File.Close()
			}
			delete(t.entries, k)
			n++
		}
	}
	return n
}

// len reports the current entry count (test helper).
func (t *DurableTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// durableLookupKey returns the CreateGuid slot used as the table key for a
// reconnect: the real CreateGuid for v2, or the FileID for v1 (which carries
// no CreateGuid).
func durableLookupKey(rec durableReconnect) [16]byte {
	if rec.v2 {
		return rec.guid
	}
	return rec.fileID
}

// handleDurableReconnect attempts to reclaim a durable open for a DH2C/DHnC
// reconnect. On success it re-opens the backing file, restores the original
// FileID into the new session, writes a SUCCESS CREATE response echoing the
// reconnect context, and returns true. It returns false if no live entry
// exists (caller then sends OBJECT_NAME_NOT_FOUND).
func (d *Dispatcher) handleDurableReconnect(rw io.ReadWriter, hdr smb2.Header, sess *Session, tree *Tree, rec durableReconnect) bool {
	if d.Conn == nil || d.Conn.Durable == nil {
		return false
	}
	saved, ok := d.Conn.Durable.ReclaimForShare(d.Conn.ClientGuid, durableLookupKey(rec), tree.Share.Name)
	if !ok {
		return false
	}
	// Enforce share binding (MS-SMB2 §3.3.5.9.7): if the reconnect arrives on
	// a different share than the original CREATE, reject it. ReclaimForShare
	// above already enforced this; saved is non-nil only when shares matched.

	// The saved descriptor belonged to the dropped connection; close it so we
	// don't leak the fd, then re-open fresh below.
	if saved.File != nil {
		saved.File.Close()
	}

	// Re-open the backing file with a fresh descriptor on the same path. The
	// original *os.File belonged to the dropped connection; we cannot assume
	// it is still valid, so we always re-open.
	open := &Open{
		FileID:            saved.FileID,
		Path:              saved.Path,
		IsDir:             saved.IsDir,
		Tree:              tree,
		GrantedAccess:     saved.GrantedAccess,
		DeleteOnClose:     saved.DeleteOnClose,
		IsDurable:         true,
		DurableClientGuid: d.Conn.ClientGuid,
		DurableCreateGuid: durableLookupKey(rec),
	}
	var st os.FileInfo
	if !open.IsDir {
		f, err := os.OpenFile(open.Path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			f, err = os.OpenFile(open.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				// The file vanished while detached — treat as no longer
				// reclaimable.
				return false
			}
		}
		open.File = f
		st, _ = f.Stat()
	} else {
		st, _ = os.Lstat(open.Path)
	}

	sess.AddOpen(open)
	// Re-register so a subsequent drop can reclaim again.
	d.Conn.Durable.Register(open.DurableClientGuid, open.DurableCreateGuid, open, d.Conn.DurableTimeout, tree.Share.Name)
	d.LastCreatedFileID = open.FileID
	d.HasLastCreated = true

	attrs := uint32(smb2.FileAttrNormal)
	var allocSize, endOfFile uint64
	if open.IsDir {
		attrs = smb2.FileAttrDirectory
	} else if st != nil {
		allocSize = uint64(st.Size())
		endOfFile = uint64(st.Size())
	}
	mtime := filetimeFromTime(time.Now())
	if st != nil {
		mtime = filetimeFromTime(st.ModTime())
	}

	// Echo the reconnect context back so the client knows the handle was
	// reclaimed: DH2C is acknowledged with a DH2Q response context.
	var echo []smb2.CreateContext
	if rec.v2 {
		echo = append(echo, smb2.CreateContext{
			Name: tagDH2Q,
			Data: encodeDH2QResponse(uint32(d.Conn.DurableTimeout/time.Millisecond), 0),
		})
	} else {
		echo = append(echo, smb2.CreateContext{Name: tagDHnQ, Data: encodeDHnQResponse()})
	}

	resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
		CreateAction:   smb2.CreateActionOpened,
		CreationTime:   mtime,
		LastAccessTime: mtime,
		LastWriteTime:  mtime,
		ChangeTime:     mtime,
		AllocationSize: allocSize,
		EndOfFile:      endOfFile,
		FileAttributes: attrs,
		FileID:         open.FileID,
		CreateContexts: smb2.EncodeCreateContexts(echo),
	})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

// applyDurableAndLease registers a fresh durable open (DH2Q/DHnQ) and appends
// the matching response contexts plus an RqLs lease grant to baseCtxs. The
// returned blob is the full, re-encoded create-context list for the response.
func (d *Dispatcher) applyDurableAndLease(open *Open, dq durableRequest, lr leaseRequest, baseCtxs []byte) []byte {
	// Decode the AAPL/MxAc contexts already built so we can append to them.
	var ctxs []smb2.CreateContext
	if len(baseCtxs) > 0 {
		smb2.IterateCreateContexts(baseCtxs, func(c smb2.CreateContext) bool {
			ctxs = append(ctxs, smb2.CreateContext{
				Name: append([]byte(nil), c.Name...),
				Data: append([]byte(nil), c.Data...),
			})
			return true
		})
	}

	if dq.present && d.Conn != nil && d.Conn.Durable != nil && d.Conn.DurableTimeout > 0 {
		// Clamp the requested timeout to the server cap.
		timeout := d.Conn.DurableTimeout
		if dq.v2 && dq.timeout > 0 {
			req := time.Duration(dq.timeout) * time.Millisecond
			if req < timeout {
				timeout = req
			}
		}
		open.IsDurable = true
		open.DurableClientGuid = d.Conn.ClientGuid
		if dq.v2 {
			open.DurableCreateGuid = dq.guid
		} else {
			// v1 has no CreateGuid; key the entry by the FileID instead.
			open.DurableCreateGuid = open.FileID
		}
		shareName := ""
		if open.Tree != nil {
			shareName = open.Tree.Share.Name
		}
		d.Conn.Durable.Register(open.DurableClientGuid, open.DurableCreateGuid, open, timeout, shareName)

		if dq.v2 {
			ctxs = append(ctxs, smb2.CreateContext{
				Name: tagDH2Q,
				Data: encodeDH2QResponse(uint32(timeout/time.Millisecond), 0),
			})
		} else {
			ctxs = append(ctxs, smb2.CreateContext{Name: tagDHnQ, Data: encodeDHnQResponse()})
		}
	}

	if lr.present {
		// We grant only READ caching — see durable.go header note. We do not
		// implement a lease-break state machine, so granting write/handle
		// caching would be unsafe (we could not revoke it on a conflicting
		// open). READ caching is always safe to honor.
		ctxs = append(ctxs, smb2.CreateContext{
			Name: tagRqLs,
			Data: encodeRqLsResponse(lr.key, leaseReadCaching),
		})
	}

	return smb2.EncodeCreateContexts(ctxs)
}
