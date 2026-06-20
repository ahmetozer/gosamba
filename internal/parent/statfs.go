package parent

import "syscall"

// fsStats reports the underlying filesystem capacity for path. Returns
// reasonable defaults if Statfs fails (so query-info never errors out).
func fsStats(path string) (totalUnits, freeUnits uint64, sectorsPerUnit, bytesPerSector uint32) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		// Fallback: 1 TiB / 1 TiB.
		return 1 << 30, 1 << 30, 1, 4096
	}
	bs := uint32(st.Bsize)
	if bs == 0 {
		bs = 4096
	}
	return st.Blocks, st.Bavail, 1, bs
}
