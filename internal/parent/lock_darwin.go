//go:build darwin

package parent

import (
	"sync"

	"golang.org/x/sys/unix"
)

// lockManager on darwin has no OFD-lock equivalent, so it keeps an in-process
// table of byte-range locks keyed by file identity (device + inode), enforcing
// the same per-open-handle conflict semantics that OFD locks give on Linux.
// The conflict logic itself lives in the portable, unit-tested rangeTable
// (lock_ranges.go); this type only adds the mutex and the (dev, ino) lookup.
type lockManager struct {
	mu    sync.Mutex
	table *rangeTable
}

func newLockManager() *lockManager { return &lockManager{table: newRangeTable()} }

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
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.table.apply(key, open, offset, length, kind)
}

func (m *lockManager) releaseAll(open *Open) {
	key, err := m.keyFor(open)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.table.releaseOwner(key, open)
}
