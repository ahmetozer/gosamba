//go:build linux

package parent

import (
	"errors"
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockManager on Linux is stateless: locks live in the kernel as OFD locks, so
// two os.File handles on one path lock independently and the kernel releases
// them when the fd closes.
type lockManager struct{}

func newLockManager() *lockManager { return &lockManager{} }

func (m *lockManager) applyLock(open *Open, offset, length uint64, kind lockKind) error {
	var t int16
	switch kind {
	case lockUnlock:
		t = syscall.F_UNLCK
	case lockShared:
		t = syscall.F_RDLCK
	case lockExclusive:
		t = syscall.F_WRLCK
	}
	fl := unix.Flock_t{Type: t, Whence: int16(io.SeekStart), Start: int64(offset), Len: int64(length)}
	if err := unix.FcntlFlock(open.File.Fd(), unix.F_OFD_SETLK, &fl); err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return errLockConflict
		}
		return err
	}
	return nil
}

// releaseAll is a no-op on Linux: OFD locks are released by the kernel when the
// file descriptor is closed.
func (m *lockManager) releaseAll(open *Open) {}
