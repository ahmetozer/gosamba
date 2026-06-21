package vfs

import (
	"os"
	"path/filepath"

	"golang.org/x/text/unicode/norm"
)

// ResolveNorm resolves a leaf name within parentDir to the actual on-disk
// entry using Unicode-normalization-insensitive matching. It is designed
// for the lookup fallback path: first it tries an exact match (fast path),
// and only on a miss it scans the directory for an entry whose NFC form
// equals the NFC form of the requested name (O(dir) slow path).
//
// Returns the resolved leaf name (as stored on disk) and true on success,
// or ("", false) when no matching entry is found.
//
// The caller is responsible for path containment checks (ResolveSecure)
// on the full path after combining parentDir with the returned leaf.
func ResolveNorm(parentDir, requestedLeaf string) (string, bool) {
	// Fast path: exact match.
	candidate := filepath.Join(parentDir, requestedLeaf)
	if _, err := os.Lstat(candidate); err == nil {
		return requestedLeaf, true
	}

	// Slow path: scan directory and compare NFC forms.
	nfcRequested := norm.NFC.String(requestedLeaf)

	entries, err := os.ReadDir(parentDir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if norm.NFC.String(e.Name()) == nfcRequested {
			return e.Name(), true
		}
	}
	return "", false
}
