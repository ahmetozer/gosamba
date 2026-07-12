//go:build linux

package parent

import (
	"errors"

	"golang.org/x/sys/unix"
)

// isXattrNotFound reports whether err means "attribute does not exist".
// Linux uses ENODATA (ENOATTR is an alias for it and not exported by x/sys/unix).
func isXattrNotFound(err error) bool { return errors.Is(err, unix.ENODATA) }
