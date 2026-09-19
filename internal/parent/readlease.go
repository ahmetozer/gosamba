package parent

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// Read leases are deliberately restricted to Time Machine shares served by this
// process. The backup directory must not be modified through another server or
// locally: we have no kernel lease manager for out-of-band writers.
//
// We grant R only while every open of the inode belongs to the same lease. Before
// admitting another CREATE we conservatively break all other leases. This also
// covers overwrite-before-open, hard links, COPYCHUNK, truncate and byte locks:
// another lease cannot acquire a handle with which to mutate a cached inode.
// No H/W caching is granted; R -> NONE needs no acknowledgement (MS-SMB2 3.3.4.7).
//
// The mutex protects grant + response enqueue and break + notification enqueue.
// A count, rather than a lock across CREATE, prevents grants during a CREATE
// without blocking the CLOSE that a sharing-conflict waiter needs to finish.
type readLeaseID struct{ client, key [16]byte }
type readLease struct {
	id    readLeaseID
	file  fileKey
	state uint32
	epoch uint16
	v2    bool
	opens map[*Open]*leaseCandidate
}
type leaseCandidate struct {
	open *Open
	sess *Session
	d    *Dispatcher
	req  leaseRequest
	file fileKey
}
type readLeaseTable struct {
	mu       sync.Mutex
	creating int
	leases   map[readLeaseID]*readLease
	owners   map[*Open]*readLease
}

var sharedReadLeases = readLeaseTable{leases: make(map[readLeaseID]*readLease), owners: make(map[*Open]*readLease)}

func (t *readLeaseTable) beginCreate(conn *Connection, req leaseRequest) func() {
	t.mu.Lock()
	t.creating++
	var own readLeaseID
	if conn != nil && req.present {
		own = readLeaseID{conn.ClientGuid, req.key}
	}
	for id, lease := range t.leases {
		if conn != nil && req.present && id == own {
			continue
		}
		if lease.state == leaseNone {
			continue
		}
		lease.state = leaseNone
		if lease.v2 {
			lease.epoch++
		}
		sent := false
		for _, c := range lease.opens {
			if c.open.leaseDisconnected.Load() {
				continue
			}
			if c.sendBreak(lease) == nil {
				sent = true
				break
			}
		}
		// A disconnected durable read lease cannot be reclaimed after an unseen
		// break. Reconnect will discard its saved handle and force a fresh open.
		if !sent {
			for open := range lease.opens {
				open.leaseRevoked.Store(true)
			}
		}
	}
	t.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { t.mu.Lock(); t.creating--; t.mu.Unlock() }) }
}

func (c *leaseCandidate) sendBreak(lease *readLease) error {
	body := make([]byte, 44)
	binary.LittleEndian.PutUint16(body, 44)
	binary.LittleEndian.PutUint16(body[2:], lease.epoch)
	copy(body[8:24], lease.id.key[:])
	binary.LittleEndian.PutUint32(body[24:], leaseReadCaching)
	// Flags and NewLeaseState stay zero: no ACK_REQUIRED for a read lease.
	hdr := smb2.Header{Command: smb2.CommandOplockBreak, Flags: smb2.FlagServerToRedir, MessageID: ^uint64(0)}
	buf := make([]byte, transport.FrameHeaderSize+smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(buf[transport.FrameHeaderSize:], hdr)
	copy(buf[transport.FrameHeaderSize+smb2.HeaderSize:], body)
	if c.d.willEncryptResponse(c.sess) {
		return c.d.sendEncrypted(nil, c.sess, buf[transport.FrameHeaderSize:])
	}
	// MS-SMB2 recommends an unsigned notification, with zero SessionId/TreeId.
	return c.d.sendPreframed(nil, buf)
}

func (t *readLeaseTable) removeLocked(open *Open) {
	lease := t.owners[open]
	if lease == nil {
		return
	}
	delete(t.owners, open)
	delete(lease.opens, open)
	if len(lease.opens) == 0 {
		delete(t.leases, lease.id)
	}
}

// grantLocked edits only the unsealed CREATE response. Called immediately before
// enqueueing it, including for compound replies: a break must never overtake the
// response which first tells the client it has a lease.
func (t *readLeaseTable) grantLocked(c *leaseCandidate, buf []byte) {
	if c == nil {
		return
	}
	id := readLeaseID{c.d.Conn.ClientGuid, c.req.key}
	// Existing lease state is shared by all opens with this client/key pair.
	// A foreign CREATE has already broken it before reaching the object store.
	lease := t.leases[id]
	if lease == nil && t.creating != 0 {
		return
	}
	sharedShareModes.mu.Lock()
	defer sharedShareModes.mu.Unlock()
	if key, ok := sharedShareModes.owners[c.open]; !ok || key != c.file {
		return
	}
	if lease != nil && (lease.file != c.file || lease.v2 != c.req.v2) {
		return
	}
	if lease == nil {
		for _, entry := range sharedShareModes.byFile[c.file] {
			if entry.owner != c.open {
				return
			}
		}
	}
	if lease == nil {
		if c.req.state&leaseReadCaching == 0 {
			return
		}
		lease = &readLease{id: id, file: c.file, state: leaseReadCaching, v2: c.req.v2, opens: make(map[*Open]*leaseCandidate)}
		if lease.v2 {
			lease.epoch = c.req.epoch + 1
		}
		t.leases[id] = lease
	}
	lease.opens[c.open] = c
	t.owners[c.open] = lease
	body := buf[transport.FrameHeaderSize+smb2.HeaderSize:]
	body[2] = 0xff // SMB2_OPLOCK_LEVEL_LEASE, also when an existing lease is NONE.
	offset := int(binary.LittleEndian.Uint32(body[80:])) - smb2.HeaderSize
	smb2.IterateCreateContexts(body[offset:], func(ctx smb2.CreateContext) bool {
		if eqTag(ctx.Name, tagRqLs) {
			binary.LittleEndian.PutUint32(ctx.Data[16:], lease.state)
			if lease.v2 {
				binary.LittleEndian.PutUint16(ctx.Data[48:], lease.epoch)
			}
		}
		return true
	})
}

func (d *Dispatcher) emitLeaseCreate(rw io.Writer, hdr smb2.Header, sess *Session, body []byte, open *Open, req leaseRequest, requested uint8) {
	var candidate *leaseCandidate
	if requested == 0xff && req.present &&
		open.Tree != nil && open.Tree.Share.TimeMachine && !open.IsDir && !open.IsStream && !open.IsPipe &&
		open.File != nil && d.Conn != nil && d.Conn.Selection.Dialect >= smb2.Dialect210 && (!req.v2 || d.Conn.Selection.Dialect >= smb2.Dialect300) && d.out != nil && !IsWorker() {
		if st, err := open.File.Stat(); err == nil && st.Mode().IsRegular() {
			if file, ok := shareKeyForFd(int(open.File.Fd())); ok {
				candidate = &leaseCandidate{open: open, sess: sess, d: d, req: req, file: file}
			}
		}
	}
	if candidate == nil {
		d.respondSuccess(rw, hdr, sess, body)
		return
	}
	d.lastChainStatus = smb2.StatusSuccess
	buf := d.buildResponse(hdr, smb2.StatusSuccess, body)
	encrypt := d.willEncryptResponse(sess)
	if d.pending != nil {
		d.pending.msgs = append(d.pending.msgs, pendingMsg{buf: buf, sess: sess, encrypt: encrypt, lease: candidate})
		return
	}
	sharedReadLeases.mu.Lock()
	defer sharedReadLeases.mu.Unlock()
	sharedReadLeases.grantLocked(candidate, buf)
	_ = d.sealAndSend(rw, sess, buf, encrypt)
}

// reconnect transfers the existing lease together with the durable handle. A
// client must present the same lease key and version; an unseen break on a dead
// connection requires a fresh CREATE instead of trusting the old read cache.
func (t *readLeaseTable) reconnect(from, to *Open, d *Dispatcher, sess *Session, req leaseRequest) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	lease := t.owners[from]
	if from.leaseRevoked.Load() {
		return false
	}
	if lease == nil {
		return true
	}
	if !req.present || lease.id != (readLeaseID{d.Conn.ClientGuid, req.key}) || lease.v2 != req.v2 {
		return false
	}
	// Reopening by pathname must never attach the old cache to a replacement
	// inode (for example after the original was renamed while disconnected).
	if to.File == nil {
		return false
	}
	if file, ok := shareKeyForFd(int(to.File.Fd())); !ok || file != lease.file {
		return false
	}
	delete(t.owners, from)
	delete(lease.opens, from)
	candidate := &leaseCandidate{open: to, d: d, sess: sess, req: req, file: lease.file}
	lease.opens[to] = candidate
	t.owners[to] = lease
	return true
}
