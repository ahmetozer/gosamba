//go:build darwin

package parent

import (
	"errors"

	"golang.org/x/sys/unix"
)

// isXattrNotFound reports whether err means "attribute does not exist".
// macOS uses ENOATTR; ENODATA is accepted too for safety.
func isXattrNotFound(err error) bool {
	return errors.Is(err, unix.ENOATTR) || errors.Is(err, unix.ENODATA)
}
