//go:build linux

package parent

import (
	"time"

	"golang.org/x/sys/unix"
)

func birthTime(path string) (time.Time, bool) {
	var stx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_BTIME, &stx)
	if err != nil {
		return time.Time{}, false
	}
	if stx.Mask&unix.STATX_BTIME == 0 {
		return time.Time{}, false
	}
	if stx.Btime.Sec == 0 && stx.Btime.Nsec == 0 {
		return time.Time{}, false
	}
	t := time.Unix(stx.Btime.Sec, int64(stx.Btime.Nsec)).UTC()
	return t, true
}
