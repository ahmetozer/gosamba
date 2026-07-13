//go:build darwin

package parent

import (
	"time"

	"golang.org/x/sys/unix"
)

// birthTime returns the file's creation time via stat(2) st_birthtimespec,
// which APFS and HFS+ populate natively. golang.org/x/sys/unix exposes the
// field as Stat_t.Btim (a unix.Timespec) on darwin.
func birthTime(path string) (time.Time, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return time.Time{}, false
	}
	bt := st.Btim
	if bt.Sec == 0 && bt.Nsec == 0 {
		return time.Time{}, false
	}
	return time.Unix(bt.Sec, bt.Nsec).UTC(), true
}
