package parent

import (
	"errors"
	"io"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// lockKind is the OS-independent classification of an SMB2 LOCK_ELEMENT,
// mapped from its SMB2_LOCKFLAG_* bits. Both the linux (OFD) and darwin
// (in-process table) lockManager implementations consume this type.
type lockKind int

const (
	lockUnlock lockKind = iota
	lockShared
	lockExclusive
)

// errLockConflict is returned by lockManager.applyLock when a requested lock
// range conflicts with an existing lock held by a different owner. handleLock
// maps it to STATUS_LOCK_NOT_GRANTED.
var errLockConflict = errors.New("lock conflict")

// handleLock processes SMB2 LOCK requests (MS-SMB2 §3.3.5.14).
//
// Each SMB2 LOCK_ELEMENT is mapped to a lockKind and applied via the
// Dispatcher's per-OS lockManager:
//
//	SMB2 flag                       | lockKind
//	--------------------------------|---------------
//	SMB2_LOCKFLAG_SHARED_LOCK       | lockShared
//	SMB2_LOCKFLAG_EXCLUSIVE_LOCK    | lockExclusive
//	SMB2_LOCKFLAG_UNLOCK            | lockUnlock
//
// FAIL_IMMEDIATELY (0x10) is the default for all lock operations here — the
// lockManager never blocks. This is correct for a file server: blocking the
// dispatcher goroutine would stall the entire connection while waiting for a
// lock held by an unknown remote peer. Clients that need blocking semantics
// must retry at their own pacing; STATUS_LOCK_NOT_GRANTED is the documented
// response for non-blocking conflict (MS-SMB2 §3.3.5.14).
//
// On Linux, lockManager delegates to kernel OFD (Open File Description)
// locks so that two independent os.File objects opened on the same path
// produce genuinely independent lock domains — exactly what SMB2 per-handle
// locking requires. OFD locks don't exist on darwin, so the darwin
// lockManager keeps an in-process table keyed by file identity, enforcing
// the same per-open-handle conflict semantics in userspace.
func (d *Dispatcher) handleLock(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeLockRequest(body)
	if err != nil {
		d.Log.Warn("lock: decode failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.Log.Warn("lock: unknown FileID", "fid", req.FileID)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	if open.File == nil {
		// Directories and virtual handles don't support byte-range locking.
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	// acquired tracks lock elements applied so far in this request so that on
	// failure we can roll them back, achieving atomic "all-or-nothing" semantics
	// required by MS-SMB2 §3.3.5.14.  Only newly-acquired locks (not unlocks)
	// need rollback tracking.
	var acquired []smb2.LockElement

	// rollback releases every lock in acquired via the lockManager.
	rollback := func() {
		for _, el := range acquired {
			if err := d.locks.applyLock(open, el.Offset, el.Length, lockUnlock); err != nil {
				d.Log.Warn("lock: rollback unlock failed", "offset", el.Offset, "length", el.Length, "err", err)
			}
		}
	}

	for i, el := range req.Locks {
		var kind lockKind

		switch {
		case el.Flags&smb2.LockFlagUnlock != 0:
			kind = lockUnlock
		case el.Flags&smb2.LockFlagSharedLock != 0:
			kind = lockShared
		case el.Flags&smb2.LockFlagExclusiveLock != 0:
			kind = lockExclusive
		default:
			d.Log.Warn("lock: unknown flags", "element", i, "flags", el.Flags)
			rollback()
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}

		if err := d.locks.applyLock(open, el.Offset, el.Length, kind); err != nil {
			if errors.Is(err, errLockConflict) {
				d.Log.Debug("lock: conflict",
					"element", i,
					"offset", el.Offset,
					"length", el.Length,
					"flags", el.Flags,
				)
				rollback()
				d.respondError(rw, hdr, smb2.StatusLockNotGranted, sess)
				return true
			}
			d.Log.Warn("lock: apply error", "element", i, "err", err)
			rollback()
			d.respondError(rw, hdr, smb2.StatusInternalError, sess)
			return true
		}

		// Track newly-acquired locks (not unlocks) for potential rollback.
		if kind != lockUnlock {
			acquired = append(acquired, el)
		}
	}

	d.respondSuccess(rw, hdr, sess, smb2.EncodeLockResponse())
	return true
}
