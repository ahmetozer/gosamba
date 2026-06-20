package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_Happy(t *testing.T) {
	cases := []struct {
		root, smb, want string
	}{
		{"/srv/share", "", "/srv/share"},
		{"/srv/share", "/", "/srv/share"},
		{"/srv/share", "foo.txt", "/srv/share/foo.txt"},
		{"/srv/share", "/foo.txt", "/srv/share/foo.txt"},
		{"/srv/share", "\\foo.txt", "/srv/share/foo.txt"},
		{"/srv/share", "sub\\dir\\file", "/srv/share/sub/dir/file"},
		{"/srv/share", "sub/dir/../file", "/srv/share/sub/file"},
	}
	for _, tc := range cases {
		got, err := Resolve(tc.root, tc.smb)
		if err != nil {
			t.Errorf("Resolve(%q, %q) error: %v", tc.root, tc.smb, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", tc.root, tc.smb, got, tc.want)
		}
	}
}

func TestResolve_Traversal(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"foo/../../etc",
		"/../escape",
	}
	for _, p := range cases {
		_, err := Resolve("/srv/share", p)
		if !errors.Is(err, ErrTraversal) {
			t.Errorf("Resolve(%q) err=%v, want ErrTraversal", p, err)
		}
	}
}

// TestResolveSecure_EscapingSymlink verifies that a symlink inside the share
// that points outside the root is rejected with ErrTraversal.
func TestResolveSecure_EscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// Create a file outside the share root.
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink inside the share pointing outside.
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	// Accessing the symlink itself should be denied.
	_, err := ResolveSecure(root, "escape")
	if !errors.Is(err, ErrTraversal) {
		t.Errorf("ResolveSecure escape dir: err=%v, want ErrTraversal", err)
	}

	// Accessing a file through the escaping symlink should also be denied.
	_, err = ResolveSecure(root, "escape/secret.txt")
	if !errors.Is(err, ErrTraversal) {
		t.Errorf("ResolveSecure escape/secret.txt: err=%v, want ErrTraversal", err)
	}
}

// TestResolveSecure_InShareSymlink verifies that a symlink inside the share
// whose target is also inside the share resolves and works normally.
func TestResolveSecure_InShareSymlink(t *testing.T) {
	root := t.TempDir()

	// Create a real subdirectory with a file inside the share.
	subdir := filepath.Join(root, "realsubdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create an in-share symlink pointing to the real subdir.
	if err := os.Symlink(subdir, filepath.Join(root, "inlink")); err != nil {
		t.Fatal(err)
	}

	// Accessing through the in-share symlink should succeed.
	got, err := ResolveSecure(root, "inlink")
	if err != nil {
		t.Fatalf("ResolveSecure inlink: unexpected error: %v", err)
	}
	// The returned path should be under root (real path of subdir).
	if got == "" {
		t.Error("ResolveSecure inlink: got empty path")
	}

	// Accessing a file through the in-share symlink should also succeed.
	got2, err := ResolveSecure(root, "inlink/data.txt")
	if err != nil {
		t.Fatalf("ResolveSecure inlink/data.txt: unexpected error: %v", err)
	}
	if got2 == "" {
		t.Error("ResolveSecure inlink/data.txt: got empty path")
	}
}

// TestResolveSecure_NormalPaths verifies that ResolveSecure behaves identically
// to Resolve for paths that contain no symlinks.
func TestResolveSecure_NormalPaths(t *testing.T) {
	root := t.TempDir()

	// Create a real file for the path.
	if err := os.WriteFile(filepath.Join(root, "foo.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(root, "sub")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		smb  string
		want string
	}{
		{"", root},
		{"foo.txt", filepath.Join(root, "foo.txt")},
		{"sub", subdir},
		// Non-existent file: parent (root) must exist.
		{"newfile.txt", filepath.Join(root, "newfile.txt")},
	}
	for _, tc := range cases {
		got, err := ResolveSecure(root, tc.smb)
		if err != nil {
			t.Errorf("ResolveSecure(%q): unexpected error: %v", tc.smb, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolveSecure(%q) = %q, want %q", tc.smb, got, tc.want)
		}
	}
}

// TestResolveSecure_LexicalTraversal verifies that lexical traversal attempts
// are still caught (regression guard on Resolve behaviour).
func TestResolveSecure_LexicalTraversal(t *testing.T) {
	root := t.TempDir()
	cases := []string{
		"../etc/passwd",
		"foo/../../etc",
	}
	for _, p := range cases {
		_, err := ResolveSecure(root, p)
		if !errors.Is(err, ErrTraversal) {
			t.Errorf("ResolveSecure(%q) err=%v, want ErrTraversal", p, err)
		}
	}
}
