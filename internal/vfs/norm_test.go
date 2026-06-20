package vfs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// nfdName produces an NFD-encoded version of s for use in test filenames.
// We use a simple example: "café" in NFC vs "café" in NFD.
var (
	// nfcCafe is the NFC form of "café" (single composed codepoint U+00E9).
	nfcCafe = norm.NFC.String("café")
	// nfdCafe is the NFD form of "café" (e + combining acute U+0301).
	nfdCafe = norm.NFD.String("café")
)

// TestResolveNorm_NFDthenNFC creates a file on disk with an NFD-encoded name,
// then looks it up via its NFC form and asserts it resolves to the NFD entry.
func TestResolveNorm_NFDthenNFC(t *testing.T) {
	dir := t.TempDir()

	// Create the file with the NFD name on disk.
	nfdPath := filepath.Join(dir, nfdCafe)
	if err := os.WriteFile(nfdPath, []byte("content"), 0644); err != nil {
		t.Fatalf("create NFD file: %v", err)
	}

	// Fast path (exact NFD match) should work.
	got, ok := ResolveNorm(dir, nfdCafe)
	if !ok {
		t.Error("ResolveNorm: exact NFD lookup should succeed")
	}
	if got != nfdCafe {
		t.Errorf("ResolveNorm exact: got %q, want %q", got, nfdCafe)
	}

	// Slow path (NFC request → NFD on disk) should also work.
	got2, ok2 := ResolveNorm(dir, nfcCafe)
	if !ok2 {
		t.Error("ResolveNorm: NFC lookup for NFD-on-disk should succeed")
	}
	// The returned name should be the on-disk NFD name.
	if got2 != nfdCafe {
		t.Errorf("ResolveNorm NFC→NFD: got %q, want %q", got2, nfdCafe)
	}
}

// TestResolveNorm_NFCthenNFD creates a file with an NFC name, then looks it
// up via NFD form.
func TestResolveNorm_NFCthenNFD(t *testing.T) {
	dir := t.TempDir()

	nfcPath := filepath.Join(dir, nfcCafe)
	if err := os.WriteFile(nfcPath, []byte("content"), 0644); err != nil {
		t.Fatalf("create NFC file: %v", err)
	}

	// Lookup via NFD form.
	got, ok := ResolveNorm(dir, nfdCafe)
	if !ok {
		t.Error("ResolveNorm: NFD lookup for NFC-on-disk should succeed")
	}
	if got != nfcCafe {
		t.Errorf("ResolveNorm NFD→NFC: got %q, want %q", got, nfcCafe)
	}
}

// TestResolveNorm_ExactASCII verifies the fast path for a plain ASCII name.
func TestResolveNorm_ExactASCII(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	got, ok := ResolveNorm(dir, "hello.txt")
	if !ok || got != "hello.txt" {
		t.Errorf("ResolveNorm ascii: ok=%v got=%q", ok, got)
	}
}

// TestResolveNorm_NotFound verifies that a missing entry returns false.
func TestResolveNorm_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, ok := ResolveNorm(dir, "nonexistent.txt")
	if ok {
		t.Error("ResolveNorm: missing file should return false")
	}
}

// TestResolveSecureNorm_DotDotWithinRoot verifies that a within-root path
// containing ".." resolves correctly (subdir/../file.txt → file.txt).
func TestResolveSecureNorm_DotDotWithinRoot(t *testing.T) {
	root := t.TempDir()

	// Create subdir and a file at the root level.
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveSecureNorm(root, "subdir/../file.txt")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	want := filepath.Join(root, "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestResolveSecureNorm_DotDotEscapeRejected verifies that a ".." path that
// would escape the share root is still rejected with ErrTraversal.
func TestResolveSecureNorm_DotDotEscapeRejected(t *testing.T) {
	root := t.TempDir()

	_, err := ResolveSecureNorm(root, "../escape.txt")
	if err != ErrTraversal {
		t.Errorf("expected ErrTraversal, got: %v", err)
	}
}

