//go:build darwin

package parent

import (
	"golang.org/x/sys/unix"
)

// lockManager on darwin has no OFD-lock equivalent, so it keeps an in-process
// table of byte-range locks keyed by file identity (device + inode), enforcing
// the same per-open-handle conflict semantics that OFD locks give on Linux.
// The conflict logic itself lives in the portable, unit-tested rangeTable
// (lock_ranges.go); this type only adds the mutex and the (dev, ino) lookup.
type lockManager struct {
	tbl *lockTable
}

func newLockManager() *lockManager { return &lockManager{tbl: newLockTable()} }

// keyFor identifies open's underlying file by (device, inode) via fstat, so
// that locks are tracked per file identity rather than per path.
func (m *lockManager) keyFor(open *Open) (fileKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(open.File.Fd()), &st); err != nil {
		return fileKey{}, err
	}
	// darwin: st.Dev is int32, st.Ino is uint64.
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, nil
}

func (m *lockManager) applyLock(open *Open, offset, length uint64, kind lockKind) error {
	key, err := m.keyFor(open)
	if err != nil {
		return err
	}
	return m.tbl.apply(key, open, offset, length, kind)
}

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
	// This runs on every READ and WRITE, so the case where nobody holds a
	// byte-range lock has to be nearly free: one atomic load, no fstat and no
	// process-global mutex.
	if length == 0 || m.tbl.empty() {
		return false
	}
	key, err := m.keyFor(open)
	if err != nil {
		return false
	}
	return m.tbl.conflict(key, open, offset, length, write)
}
