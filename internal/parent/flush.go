package parent

import (
	"os"
	"syscall"
)

// flushOpen persists stream buffers before syncing the backing inode. A failed
// xattr write (including ENOTSUP) must not be acknowledged as durable storage.
// The caller holds open.mu exclusively for streams.
func flushOpen(open *Open) error {
	if open.IsPipe {
		return syscall.EINVAL
	}
	if open.File != nil {
		return syncFile(open.File)
	}
	if !open.IsStream && !open.IsDir {
		return os.ErrClosed
	}
	if open.IsStream && open.streamWritten {
		if err := writeStreamXattr(open.Path, open.StreamName, open.streamBuf); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(open.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return syncFile(f)
}
