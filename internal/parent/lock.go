package parent

import (
	"errors"
	"io"
	"syscall"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"golang.org/x/sys/unix"
)

// handleLock processes SMB2 LOCK requests (MS-SMB2 §3.3.5.14).
//
// Each SMB2 LOCK_ELEMENT is mapped to a POSIX OFD lock via FcntlFlock:
//
//	SMB2 flag                       | fcntl type | syscall
//	--------------------------------|------------|----------------------
//	SMB2_LOCKFLAG_SHARED_LOCK       | F_RDLCK    | F_OFD_SETLK
//	SMB2_LOCKFLAG_EXCLUSIVE_LOCK    | F_WRLCK    | F_OFD_SETLK
//	SMB2_LOCKFLAG_UNLOCK            | F_UNLCK    | F_OFD_SETLK
//
// FAIL_IMMEDIATELY (0x10) is the default for all lock operations here — we
// always use F_OFD_SETLK (non-blocking). This is correct for a file server:
// blocking the dispatcher goroutine would stall the entire connection while
// waiting for a lock held by an unknown remote peer. Clients that need
// blocking semantics must retry at their own pacing; STATUS_LOCK_NOT_GRANTED
// is the documented response for non-blocking conflict (MS-SMB2 §3.3.5.14).
//
// OFD (Open File Description) locks are used rather than traditional POSIX
// flock/fcntl locks so that two independent os.File objects opened on the
// same path produce genuinely independent lock domains — exactly what SMB2
// per-handle locking requires.
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

	fd := open.File.Fd()

	// acquired tracks lock elements applied so far in this request so that on
	// failure we can roll them back, achieving atomic "all-or-nothing" semantics
	// required by MS-SMB2 §3.3.5.14.  Only newly-acquired locks (not unlocks)
	// need rollback tracking.
	var acquired []smb2.LockElement

	// rollback releases every lock in acquired using F_OFD_SETLK / F_UNLCK.
	rollback := func() {
		for _, el := range acquired {
			fl := unix.Flock_t{
				Type:   syscall.F_UNLCK,
				Whence: int16(io.SeekStart),
				Start:  int64(el.Offset),
				Len:    int64(el.Length),
			}
			if err := unix.FcntlFlock(fd, unix.F_OFD_SETLK, &fl); err != nil {
				d.Log.Warn("lock: rollback unlock failed", "offset", el.Offset, "length", el.Length, "err", err)
			}
		}
	}

	for i, el := range req.Locks {
		var lockType int16

		switch {
		case el.Flags&smb2.LockFlagUnlock != 0:
			lockType = syscall.F_UNLCK
		case el.Flags&smb2.LockFlagSharedLock != 0:
			lockType = syscall.F_RDLCK
		case el.Flags&smb2.LockFlagExclusiveLock != 0:
			lockType = syscall.F_WRLCK
		default:
			d.Log.Warn("lock: unknown flags", "element", i, "flags", el.Flags)
			rollback()
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}

		fl := unix.Flock_t{
			Type:   lockType,
			Whence: int16(io.SeekStart),
			Start:  int64(el.Offset),
			Len:    int64(el.Length),
		}

		// Always non-blocking (F_OFD_SETLK). See rationale in the doc comment.
		if err := unix.FcntlFlock(fd, unix.F_OFD_SETLK, &fl); err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
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
			d.Log.Warn("lock: fcntl error", "element", i, "err", err)
			rollback()
			d.respondError(rw, hdr, smb2.StatusInternalError, sess)
			return true
		}

		// Track newly-acquired locks (not unlocks) for potential rollback.
		if lockType != syscall.F_UNLCK {
			acquired = append(acquired, el)
		}
	}

	d.respondSuccess(rw, hdr, sess, smb2.EncodeLockResponse())
	return true
}
