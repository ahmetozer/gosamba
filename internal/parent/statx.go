package parent

import (
	"time"

	"golang.org/x/sys/unix"
)

// birthTime returns the birth time (btime) of the file at path using statx(2)
// with STATX_BTIME. It returns (btime, true) when the filesystem reports a
// valid birth time, and (zero, false) when btime is unavailable (older kernels,
// tmpfs, or filesystems that don't populate stx_btime).
func birthTime(path string) (time.Time, bool) {
	var stx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_BTIME, &stx)
	if err != nil {
		return time.Time{}, false
	}
	// Check that the kernel actually returned a valid btime (mask bit set).
	if stx.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	// stx.Btime.Sec == 0 means the FS didn't fill it in (tmpfs, etc.)
	if stx.Btime.Sec == 0 && stx.Btime.Nsec == 0 {
		return time.Time{}, false
	}
	t := time.Unix(stx.Btime.Sec, int64(stx.Btime.Nsec)).UTC()
	return t, true
}
