// Package vfs handles share-relative path resolution and filesystem-info
// helpers for the SMB protocol.
package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrTraversal = errors.New("vfs: path escapes share root")

// Resolve takes a share root (absolute, cleaned) and a client-supplied
// share-relative path (which may use either backslashes or forward slashes,
// may begin with a slash, may be empty for the root). Returns an absolute
// OS path that is guaranteed to lie under root, or ErrTraversal.
func Resolve(root, smbPath string) (string, error) {
	root = filepath.Clean(root)
	// Normalize slashes
	p := strings.ReplaceAll(smbPath, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return root, nil
	}
	full := filepath.Join(root, p)
	full = filepath.Clean(full)
	// Verify still under root.
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", ErrTraversal
	}
	return full, nil
}

// ResolveSecure is like Resolve but additionally enforces that no symlink in
// the resolved path escapes the share root. It does this by:
//
//  1. Performing the lexical Resolve check (dot-dot etc.) first.
//  2. Evaluating symlinks on the deepest existing ancestor of the candidate
//     path and confirming the real path still lives under the canonical
//     (EvalSymlinks'd) root.
//
// For paths whose final component does not exist yet (e.g. a CREATE for a new
// file), the parent directory is validated instead — this avoids a TOCTOU
// window on the leaf while still catching any escaping symlink in the parent
// chain.
//
// An in-share symlink whose resolved target remains within root is allowed and
// the lexical (un-resolved) path is returned so callers continue to see the
// expected share-relative location.
//
// Returns ErrTraversal when the path escapes the share root.
func ResolveSecure(root, smbPath string) (string, error) {
	// Step 1: lexical containment (handles dot-dot, etc.).
	lexical, err := Resolve(root, smbPath)
	if err != nil {
		return "", err
	}

	// Step 2: canonicalize the root itself so we have a stable prefix to
	// compare against.
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		// Root doesn't exist — unexpected; fall back to lexical check only.
		return lexical, nil
	}
	canonRoot = filepath.Clean(canonRoot)

	// Step 3: find the deepest ancestor that exists on disk.
	// We walk from lexical toward root looking for the deepest existing path.
	checkPath := lexical
	for {
		_, statErr := os.Lstat(checkPath)
		if statErr == nil {
			// This path exists; evaluate symlinks to get real path.
			break
		}
		if !os.IsNotExist(statErr) {
			// Permission error or other — treat as not escapable; let the
			// subsequent filesystem op return the appropriate error.
			return lexical, nil
		}
		parent := filepath.Dir(checkPath)
		if parent == checkPath {
			// Reached filesystem root without finding any existing ancestor;
			// can't escape via symlink if nothing exists.
			return lexical, nil
		}
		checkPath = parent
	}

	// Step 4: evaluate all symlinks on the existing ancestor.
	real, err := filepath.EvalSymlinks(checkPath)
	if err != nil {
		// Unable to resolve — deny to be safe.
		return "", ErrTraversal
	}
	real = filepath.Clean(real)

	// Step 5: check that the real path is still under canonRoot.
	if real != canonRoot && !strings.HasPrefix(real, canonRoot+string(filepath.Separator)) {
		return "", ErrTraversal
	}

	return lexical, nil
}

// ResolveSecureNorm is like ResolveSecure but applies a Unicode-normalization-
// insensitive fallback when looking up each path component. This allows a file
// created with an NFD-encoded name (typical on macOS) to be found by an NFC
// lookup (typical on Windows/Linux), and vice-versa.
//
// The fallback is applied component-by-component on the LOOKUP path only —
// directory listings and on-disk names are never rewritten. The resolved OS
// path uses the actual on-disk names, which are then validated by ResolveSecure
// to ensure containment within the share root.
//
// Fast path: if the lexical path resolves without any normalization miss, it
// delegates directly to ResolveSecure (no directory scanning overhead).
func ResolveSecureNorm(root, smbPath string) (string, error) {
	root = filepath.Clean(root)

	// Normalize slashes and split into components.
	p := strings.ReplaceAll(smbPath, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ResolveSecure(root, smbPath)
	}

	// Fast path: try lexical resolution first. If the path exists, no need to
	// walk component-by-component.
	lexical, err := Resolve(root, smbPath)
	if err != nil {
		return "", err
	}
	if _, statErr := os.Lstat(lexical); statErr == nil {
		// Exists as-is; delegate to the full symlink check.
		return ResolveSecure(root, smbPath)
	}

	// Slow path: resolve each component with normalization fallback.
	components := strings.Split(p, "/")
	current := root
	for _, comp := range components {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			current = filepath.Dir(current)
			continue
		}
		resolved, ok := ResolveNorm(current, comp)
		if !ok {
			// Component not found even after normalization — keep the
			// requested name (e.g. for new-file CREATE paths).
			resolved = comp
		}
		current = filepath.Join(current, resolved)
	}

	// Validate the resolved path via ResolveSecure (symlink containment check).
	// We pass the resolved OS path as an already-absolute path. To convert it
	// to a share-relative form for ResolveSecure, compute the relative suffix.
	rel, err := filepath.Rel(root, current)
	if err != nil {
		return "", ErrTraversal
	}
	return ResolveSecure(root, rel)
}
