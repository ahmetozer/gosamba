package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
)

type leasePeer struct {
	d    *Dispatcher
	sess *Session
	tree *Tree
}

func newLeasePeer(t *testing.T, dir string, client byte) leasePeer {
	t.Helper()
	d, sess, tree := newTestDispatcher(t, dir)
	tree.Share.TimeMachine = true
	d.Conn = &Connection{ClientGuid: [16]byte{client}, Selection: smb2.Selection{Dialect: smb2.Dialect311}}
	// A real bounded writer queue without a socket: inspect frames in enqueue order.
	d.out = &connWriter{q: make(chan []byte, 32), closed: make(chan struct{})}
	t.Cleanup(func() {
		for _, o := range sess.TakeAllOpens() {
			releaseOpen(o)
		}
	})
	return leasePeer{d, sess, tree}
}

func leaseFrame(t *testing.T, peer leasePeer) (smb2.Header, []byte) {
	t.Helper()
	select {
	case raw := <-peer.d.out.q:
		peer.d.out.queued.Add(-int64(len(raw)))
		hdr, err := smb2.DecodeHeader(raw[4:])
		if err != nil {
			t.Fatal(err)
		}
		return hdr, raw[4+smb2.HeaderSize:]
	case <-time.After(time.Second):
		t.Fatal("no response queued")
		return smb2.Header{}, nil
	}
}

func leaseCreate(t *testing.T, peer leasePeer, name string, key byte, v2 bool, disposition uint32) (*Open, uint32, uint16) {
	t.Helper()
	size := rqLsV1Size
	if v2 {
		size = rqLsV2Size
	}
	ctx := buildRqLs(size, [16]byte{key}, leaseReadCaching|leaseWriteCaching|leaseHandleCaching)
	body := buildCreateBodyShare(name, disposition, 0, wantReadWrite, shareAll, ctx)
	body[3] = 0xff
	peer.d.handleCreate(&bytes.Buffer{}, smb2.Header{Command: smb2.CommandCreate, TreeID: peer.tree.ID}, body, peer.sess)
	hdr, response := leaseFrame(t, peer)
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("CREATE status %#x", hdr.Status)
	}
	data := rqLsResponseData(t, response[88:])
	state := binary.LittleEndian.Uint32(data[16:])
	if state != 0 && response[2] != 0xff {
		t.Fatal("lease grant without OPLOCK_LEVEL_LEASE")
	}
	epoch := uint16(0)
	if v2 {
		epoch = binary.LittleEndian.Uint16(data[48:])
	}
	return peer.sess.GetOpen(createFileID(response)), state, epoch
}

func TestReadLeaseGrantAndBreak(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "v2"}[v2], func(t *testing.T) {
			dir := t.TempDir()
			a, b := newLeasePeer(t, dir, 1), newLeasePeer(t, dir, 2)
			_, state, epoch := leaseCreate(t, a, "band", 1, v2, smb2.CreateDispositionOpenIf)
			if state != leaseReadCaching {
				t.Fatalf("grant = %x", state)
			}
			// A second handle sharing the lease must retain its state without a break.
			_, state, sameEpoch := leaseCreate(t, a, "band", 1, v2, smb2.CreateDispositionOpen)
			if state != leaseReadCaching || sameEpoch != epoch {
				t.Fatal("same lease changed on second open")
			}
			// A different connection overwrites the band. The break is queued before
			// the overwrite response and before any handle can write stale cached data.
			_, state, _ = leaseCreate(t, b, "band", 2, v2, smb2.CreateDispositionOverwrite)
			if state != leaseNone {
				t.Fatal("granted caching alongside a foreign open")
			}
			hdr, body := leaseFrame(t, a)
			if hdr.Command != smb2.CommandOplockBreak || hdr.MessageID != ^uint64(0) || hdr.SessionID != 0 || hdr.TreeID != 0 {
				t.Fatalf("break header = %+v", hdr)
			}
			if len(body) != 44 || binary.LittleEndian.Uint16(body) != 44 || binary.LittleEndian.Uint32(body[4:]) != 0 || binary.LittleEndian.Uint32(body[24:]) != leaseReadCaching || binary.LittleEndian.Uint32(body[28:]) != leaseNone {
				t.Fatalf("break = %x", body)
			}
			wantEpoch := uint16(0)
			if v2 {
				wantEpoch = epoch + 1
			}
			if binary.LittleEndian.Uint16(body[2:]) != wantEpoch {
				t.Fatal("wrong break epoch")
			}
		})
	}
}

func TestReadLeaseHardLinkAndOutstandingOpen(t *testing.T) {
	dir := t.TempDir()
	a, b := newLeasePeer(t, dir, 1), newLeasePeer(t, dir, 2)
	_, state, _ := leaseCreate(t, a, "band", 1, true, smb2.CreateDispositionOpenIf)
	if state != leaseReadCaching {
		t.Fatal("no initial lease")
	}
	if err := os.Link(filepath.Join(dir, "band"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	_, state, _ = leaseCreate(t, b, "alias", 2, true, smb2.CreateDispositionOpen)
	if state != leaseNone {
		t.Fatal("hardlink bypassed lease ownership")
	}
	hdr, _ := leaseFrame(t, a)
	if hdr.Command != smb2.CommandOplockBreak {
		t.Fatal("no break for alias")
	}
}

func TestReadLeaseCompoundPublicationAndClose(t *testing.T) {
	for _, closeInChain := range []bool{false, true} {
		t.Run(map[bool]string{false: "grant", true: "closed"}[closeInChain], func(t *testing.T) {
			dir := t.TempDir()
			a := newLeasePeer(t, dir, 1)
			frame := a.d.forFrame(false)
			req := buildCreateBodyShare("band", smb2.CreateDispositionOpenIf, 0, wantReadWrite, shareAll, buildRqLs(rqLsV2Size, [16]byte{1}, leaseReadCaching))
			req[3] = 0xff
			frame.handleCreate(&bytes.Buffer{}, smb2.Header{Command: smb2.CommandCreate, TreeID: a.tree.ID}, req, a.sess)
			sharedReadLeases.mu.Lock()
			_, granted := sharedReadLeases.owners[a.sess.GetOpen(frame.LastCreatedFileID)]
			sharedReadLeases.mu.Unlock()
			if granted {
				t.Fatal("published lease before CREATE response")
			}
			if closeInChain {
				body := make([]byte, 24)
				binary.LittleEndian.PutUint16(body, 24)
				copy(body[8:], frame.LastCreatedFileID[:])
				frame.handleClose(&bytes.Buffer{}, smb2.Header{Command: smb2.CommandClose}, body, a.sess)
			}
			frame.flush(&bytes.Buffer{})
			_, response := leaseFrame(t, a)
			// Only walk the first response's explicitly sized create-context buffer.
			length := int(binary.LittleEndian.Uint32(response[84:]))
			data := rqLsResponseData(t, response[88:88+length])
			want := uint32(leaseReadCaching)
			if closeInChain {
				want = leaseNone
			}
			if got := binary.LittleEndian.Uint32(data[16:]); got != want {
				t.Fatalf("grant = %x, want %x", got, want)
			}
		})
	}
}

func TestReadLeaseDisconnectedBreakInvalidatesDurable(t *testing.T) {
	dir := t.TempDir()
	a, b := newLeasePeer(t, dir, 1), newLeasePeer(t, dir, 2)
	open, state, _ := leaseCreate(t, a, "band", 1, true, smb2.CreateDispositionOpenIf)
	if state != leaseReadCaching {
		t.Fatal("no lease")
	}
	open.leaseDisconnected.Store(true)
	leaseCreate(t, b, "another", 2, true, smb2.CreateDispositionOpenIf)
	if !open.leaseRevoked.Load() {
		t.Fatal("disconnected read lease remained reclaimable after break")
	}
}

func TestReadLeaseDisabledForOrdinaryShare(t *testing.T) {
	a := newLeasePeer(t, t.TempDir(), 1)
	a.tree.Share.TimeMachine = false
	_, state, _ := leaseCreate(t, a, "band", 1, true, smb2.CreateDispositionOpenIf)
	if state != leaseNone {
		t.Fatal("granted lease on externally mutable ordinary share")
	}
}

func TestReadLeaseDurableReconnect(t *testing.T) {
	for _, breakOffline := range []bool{false, true} {
		t.Run(map[bool]string{false: "retain", true: "revoked"}[breakOffline], func(t *testing.T) {
			dir := t.TempDir()
			a := newLeasePeer(t, dir, 1)
			open, state, epoch := leaseCreate(t, a, "band", 1, true, smb2.CreateDispositionOpenIf)
			if state != leaseReadCaching {
				t.Fatal("no initial lease")
			}
			table := NewDurableTable()
			guid := [16]byte{0x9e}
			if !table.Register(a.d.Conn.ClientGuid, guid, open, time.Minute, a.tree.Share.Name, a.sess.User.Name) {
				t.Fatal("register failed")
			}
			open.IsDurable = true
			open.DurableClientGuid = a.d.Conn.ClientGuid
			open.DurableCreateGuid = guid
			open.leaseDisconnected.Store(true)
			a.sess.RemoveOpen(open.FileID)
			table.Detach(a.d.Conn.ClientGuid, guid)
			if breakOffline {
				other := newLeasePeer(t, dir, 2)
				leaseCreate(t, other, "other", 2, true, smb2.CreateDispositionOpenIf)
			}
			b := newLeasePeer(t, dir, 1)
			b.d.Conn.Durable = table
			b.d.Conn.DurableTimeout = time.Minute
			t.Cleanup(func() { table.Expire(time.Now().Add(2 * time.Minute)) })
			leaseData := make([]byte, rqLsV2Size)
			leaseData[0] = 1
			binary.LittleEndian.PutUint32(leaseData[16:], leaseReadCaching)
			binary.LittleEndian.PutUint16(leaseData[48:], epoch)
			contexts := smb2.EncodeCreateContexts([]smb2.CreateContext{buildDH2C(open.FileID), {Name: tagRqLs, Data: leaseData}})
			req := buildCreateBodyShare("band", smb2.CreateDispositionOpen, 0, wantReadWrite, shareAll, contexts)
			req[3] = 0xff
			b.d.handleCreate(&bytes.Buffer{}, smb2.Header{Command: smb2.CommandCreate, TreeID: b.tree.ID}, req, b.sess)
			hdr, response := leaseFrame(t, b)
			if breakOffline {
				if smb2.Status(hdr.Status) != smb2.StatusObjectNameNotFound {
					t.Fatalf("revoked reconnect status = %x", hdr.Status)
				}
				return
			}
			if smb2.Status(hdr.Status) != smb2.StatusSuccess {
				t.Fatalf("reconnect status = %x", hdr.Status)
			}
			data := rqLsResponseData(t, response[88:])
			if binary.LittleEndian.Uint32(data[16:]) != leaseReadCaching || binary.LittleEndian.Uint16(data[48:]) != epoch || response[2] != 0xff {
				t.Fatalf("reconnect lease = %x", data)
			}
		})
	}
}

func TestReadLeaseEncryptedBreak(t *testing.T) {
	dir := t.TempDir()
	a, b := newLeasePeer(t, dir, 1), newLeasePeer(t, dir, 2)
	leaseCreate(t, a, "band", 1, true, smb2.CreateDispositionOpenIf)
	a.sess.ID = 123
	a.sess.S2CCipherKey = bytes.Repeat([]byte{0x42}, 16)
	a.d.Conn.Selection.Cipher = smb2.CipherAES128GCM
	a.sess.SetGotEncrypted()
	leaseCreate(t, b, "other", 2, true, smb2.CreateDispositionOpenIf)
	select {
	case raw := <-a.d.out.q:
		plain, session, err := smb3.DecryptTransform(uint16(smb2.CipherAES128GCM), a.sess.S2CCipherKey, raw[4:])
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := smb2.DecodeHeader(plain)
		if err != nil {
			t.Fatal(err)
		}
		if session != a.sess.ID || hdr.Command != smb2.CommandOplockBreak || hdr.SessionID != 0 {
			t.Fatal("incorrect encrypted break")
		}
	case <-time.After(time.Second):
		t.Fatal("no encrypted break")
	}
}

func TestReadLeaseCompoundGrantRacesRelease(t *testing.T) {
	a := newLeasePeer(t, t.TempDir(), 1)
	for i := 0; i < 50; i++ {
		frame := a.d.forFrame(false)
		req := buildCreateBodyShare("band", smb2.CreateDispositionOpenIf, 0, wantReadWrite, shareAll, buildRqLs(rqLsV2Size, [16]byte{1}, leaseReadCaching))
		req[3] = 0xff
		frame.handleCreate(&bytes.Buffer{}, smb2.Header{Command: smb2.CommandCreate, TreeID: a.tree.ID}, req, a.sess)
		open := a.sess.RemoveOpen(frame.LastCreatedFileID)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); frame.flush(&bytes.Buffer{}) }()
		go func() { defer wg.Done(); releaseOpen(open) }()
		wg.Wait()
		leaseFrame(t, a)
		sharedReadLeases.mu.Lock()
		_, leaked := sharedReadLeases.owners[open]
		sharedReadLeases.mu.Unlock()
		if leaked {
			t.Fatal("lease survived release of its last handle")
		}
	}
}
