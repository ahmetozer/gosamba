// Package inotify's OS-independent event vocabulary, shared by every
// platform's watcher implementation.
package inotify

// EventType classifies a filesystem change reported by a Watcher.
type EventType uint8

const (
	FolderCreate EventType = iota
	FileCreate
	Delete
	Modified
	MovedFrom
	MovedTo
	WatchStop
)

// InotifyEvent is a single change reported on Watcher.Events. Path is the
// absolute path of the affected entry; for WatchStop it is empty.
type InotifyEvent struct {
	Path  string
	Event EventType
}
