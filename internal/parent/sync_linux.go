//go:build linux

package parent

import "os"

// fsync asks the filesystem to commit file data and metadata to stable storage.
func syncFile(f *os.File) error { return f.Sync() }
