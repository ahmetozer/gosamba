//go:build darwin

package parent

import (
	"os"

	"golang.org/x/sys/unix"
)

// fsync alone does not flush the device's write cache on macOS.
func syncFile(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	return err
}
