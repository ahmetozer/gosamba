package inotify

import "strconv"

// dirEntry is a snapshot of one directory child used to diff between scans.
type dirEntry struct {
	ino   uint64
	mtime int64 // unix nanos
	isDir bool
}

func itoa(e EventType) string { return strconv.Itoa(int(e)) }

// diffSnapshot compares two listings of the directory at dir and returns the
// per-entry events. Rename is detected when an inode disappears under one name
// and reappears under another (emitted as MovedFrom + MovedTo). Remaining
// disappearances are Delete; remaining appearances are FileCreate/FolderCreate;
// same-name-same-inode with a changed mtime is Modified.
func diffSnapshot(dir string, before, after map[string]dirEntry) []InotifyEvent {
	var evs []InotifyEvent
	join := func(name string) string { return dir + "/" + name }

	gone := map[uint64]string{}     // ino -> name, present before but not after
	appeared := map[uint64]string{} // ino -> name, present after but not before

	for name, b := range before {
		if _, ok := after[name]; !ok {
			gone[b.ino] = name
		}
	}
	for name, a := range after {
		if _, ok := before[name]; !ok {
			appeared[a.ino] = name
		}
	}
	// rename correlation by inode
	for ino, newName := range appeared {
		if oldName, ok := gone[ino]; ok {
			evs = append(evs, InotifyEvent{Path: join(oldName), Event: MovedFrom})
			evs = append(evs, InotifyEvent{Path: join(newName), Event: MovedTo})
			delete(gone, ino)
			delete(appeared, ino)
		}
	}
	for _, name := range gone {
		evs = append(evs, InotifyEvent{Path: join(name), Event: Delete})
	}
	for ino, name := range appeared {
		ev := FileCreate
		if after[name].isDir {
			ev = FolderCreate
		}
		_ = ino
		evs = append(evs, InotifyEvent{Path: join(name), Event: ev})
	}
	// modify: same name, same inode, changed mtime
	for name, a := range after {
		if b, ok := before[name]; ok && b.ino == a.ino && b.mtime != a.mtime && !a.isDir {
			evs = append(evs, InotifyEvent{Path: join(name), Event: Modified})
		}
	}
	return evs
}
