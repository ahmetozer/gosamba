//go:build linux

package parent

import (
	"errors"
	"io"
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockManager on Linux delegates conflict enforcement to the kernel as OFD
// locks, so two os.File handles on one path lock independently and the kernel
// releases them when the fd closes. It additionally mirrors every granted lock
// into an in-process table so READ/WRITE can be checked against SMB2 lock state
// (the kernel never blocks our own process's I/O — POSIX locks are advisory and
// an OFD lock does not conflict with the fd holding it).
type lockManager struct {
	tbl *lockTable
}

func newLockManager() *lockManager { return &lockManager{tbl: newLockTable()} }

// keyFor identifies open's underlying file by (device, inode) via fstat.
func (m *lockManager) keyFor(open *Open) (fileKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(open.File.Fd()), &st); err != nil {
		return fileKey{}, err
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// flockRange converts an SMB2 (offset, length) pair to fcntl l_start/l_len.
//
// Two semantics differ from SMB2 and must be translated rather than cast:
//   - fcntl l_len == 0 means "to end of file", but an SMB2 zero-length range
//     covers no bytes at all. Zero-length requests are handled by the caller.
//   - l_start and l_len are signed. An SMB2 lock-to-EOF (length near 2^64)
//     cast straight to int64 becomes negative, which fcntl reads as a range
//     running *backwards* from the offset — locking the wrong bytes entirely.
//     A range that extends past the signed maximum is expressed as l_len 0.
func flockRange(offset, length uint64) (start, l int64, ok bool) {
	if offset > math.MaxInt64 {
		return 0, 0, false
	}
	start = int64(offset)
	if end := offset + length; end < offset || end > math.MaxInt64 {
		// Runs past the addressable signed range: lock through end of file.
		return start, 0, true
	}
	return start, int64(length), true
}

func (m *lockManager) applyLock(open *Open, offset, length uint64, kind lockKind) error {
	// A zero-length SMB2 range covers no bytes; passing it to fcntl would mean
	// "lock to EOF" and grab the whole tail of the file.
	if length == 0 {
		return nil
	}
	start, l, ok := flockRange(offset, length)
	if !ok {
		return errLockConflict
	}
	var t int16
	switch kind {
	case lockUnlock:
		t = syscall.F_UNLCK
	case lockShared:
		t = syscall.F_RDLCK
	case lockExclusive:
		t = syscall.F_WRLCK
	}
	fl := unix.Flock_t{Type: t, Whence: int16(io.SeekStart), Start: start, Len: l}
	if err := unix.FcntlFlock(open.File.Fd(), unix.F_OFD_SETLK, &fl); err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return errLockConflict
		}
		return err
	}
	// Mirror the kernel's decision into the in-process table so I/O checks see
	// it. The kernel stays authoritative for granting; this is a shadow copy.
	if key, err := m.keyFor(open); err == nil {
		_ = m.tbl.apply(key, open, offset, length, kind)
	}
	return nil
}

// releaseAll drops this handle's shadow entries. The kernel releases the OFD
// locks themselves when the file descriptor closes.
func (m *lockManager) releaseAll(open *Open) {
	key, err := m.keyFor(open)
	if err != nil {
		return
	}
	m.tbl.releaseOwner(key, open)
}

// conflictsWith reports whether an I/O by open over [offset,offset+length)
// collides with a byte-range lock held by a different handle.
func (m *lockManager) conflictsWith(open *Open, offset, length uint64, write bool) bool {
	key, err := m.keyFor(open)
	if err != nil {
		return false
	}
	return m.tbl.conflict(key, open, offset, length, write)
}
