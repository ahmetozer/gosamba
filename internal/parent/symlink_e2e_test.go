//go:build smbclient_e2e

package parent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// TestSymlinkContainment verifies that the server blocks access through
// symlinks that escape the share root, and allows access through in-share
// symlinks whose target remains within the root.
func TestSymlinkContainment(t *testing.T) {
	shareDir := t.TempDir()

	// --- Set up escaping symlink scenario ---
	// Create an outside directory with a secret file.
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("TOP SECRET"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create a symlink inside the share pointing outside.
	if err := os.Symlink(outsideDir, filepath.Join(shareDir, "escape")); err != nil {
		t.Fatal(err)
	}

	// --- Set up in-share symlink scenario ---
	// Create a real subdirectory with a file.
	realSubdir := filepath.Join(shareDir, "realsubdir")
	if err := os.Mkdir(realSubdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realSubdir, "data.txt"), []byte("hello from subdir"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create an in-share symlink to the real subdirectory.
	if err := os.Symlink(realSubdir, filepath.Join(shareDir, "inlink")); err != nil {
		t.Fatal(err)
	}

	users := []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
	shares := []config.ShareConfig{{Name: "share", Path: shareDir}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireSigning: true,
		MaxIOSize:      1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()

	// --- Escaping symlink: ls escape\ (open the symlink AS a directory) should be DENIED ---
	// "ls escape" lists the share root filtered to the entry named "escape" — that
	// never follows the symlink. "ls escape\" opens the escape entry as a directory
	// (the client sends CREATE on "escape" with FILE_DIRECTORY_FILE) which is the
	// traversal we need to block.
	t.Run("escape_ls_dir_denied", func(t *testing.T) {
		out, err := smbcliErr(t, port, "share", "alice%test123", `ls escape\`)
		t.Logf("escape ls dir output:\n%s", out)
		if err == nil && !strings.Contains(out, "NT_STATUS") {
			t.Errorf("expected DENIED (NT_STATUS error) for 'ls escape\\', got exit 0 and output: %s", out)
		}
		// err != nil means smbclient exited non-zero — that's the denial we want.
	})

	// --- Escaping symlink: get escape\secret.txt should be DENIED ---
	t.Run("escape_get_denied", func(t *testing.T) {
		downloadPath := filepath.Join(localDir, "should_not_exist.txt")
		out, err := smbcliErr(t, port, "share", "alice%test123",
			fmt.Sprintf("get escape\\secret.txt %s", downloadPath),
		)
		t.Logf("escape get output:\n%s", out)
		// Should be denied: either non-zero exit OR NT_STATUS in output.
		if err == nil && !strings.Contains(out, "NT_STATUS") {
			t.Errorf("expected DENIED for 'get escape\\secret.txt', got exit 0 and output: %s", out)
		}
		// The file must NOT have been downloaded.
		if _, statErr := os.Stat(downloadPath); statErr == nil {
			t.Error("secret.txt was downloaded — symlink escape not blocked!")
		}
	})

	// --- In-share symlink: ls should succeed ---
	t.Run("inlink_ls_allowed", func(t *testing.T) {
		out := smbcli(t, port, "share", "alice%test123", "ls inlink")
		t.Logf("inlink ls output:\n%s", out)
		if strings.Contains(out, "NT_STATUS") {
			t.Errorf("in-share symlink ls failed unexpectedly: %s", out)
		}
	})

	// --- In-share symlink: get data.txt through symlink should succeed ---
	t.Run("inlink_get_allowed", func(t *testing.T) {
		downloadPath := filepath.Join(localDir, "data_via_inlink.txt")
		out := smbcli(t, port, "share", "alice%test123",
			fmt.Sprintf("get inlink\\data.txt %s", downloadPath),
		)
		t.Logf("inlink get output:\n%s", out)
		got, err := os.ReadFile(downloadPath)
		if err != nil {
			t.Fatalf("in-share symlink get failed: %v\noutput: %s", err, out)
		}
		if string(got) != "hello from subdir" {
			t.Errorf("in-share symlink get: got %q, want %q", got, "hello from subdir")
		}
	})

	// --- Leaf symlink: get leaf_link (symlink as the final path component) should be DENIED ---
	// This tests O_NOFOLLOW on the leaf: a symlink placed as the opened file
	// itself (not an ancestor directory) must not be followed even if its
	// target is outside the share.
	t.Run("leaf_link_get_denied", func(t *testing.T) {
		// Create a secret file outside the share.
		secretFile := filepath.Join(outsideDir, "leaf_secret.txt")
		if err := os.WriteFile(secretFile, []byte("LEAF SECRET"), 0644); err != nil {
			t.Fatal(err)
		}
		// Create a leaf symlink inside the share pointing to the outside secret.
		leafLink := filepath.Join(shareDir, "leaf_link")
		if err := os.Symlink(secretFile, leafLink); err != nil {
			t.Fatal(err)
		}

		downloadPath := filepath.Join(localDir, "leaf_should_not_exist.txt")
		out, err := smbcliErr(t, port, "share", "alice%test123",
			fmt.Sprintf("get leaf_link %s", downloadPath),
		)
		t.Logf("leaf_link get output:\n%s", out)
		// Should be denied: either non-zero exit OR NT_STATUS in output.
		if err == nil && !strings.Contains(out, "NT_STATUS") {
			t.Errorf("expected DENIED for 'get leaf_link', got exit 0 and output: %s", out)
		}
		// The secret file must NOT have been downloaded.
		if _, statErr := os.Stat(downloadPath); statErr == nil {
			t.Error("leaf_secret.txt was downloaded — leaf symlink not blocked!")
		}
	})
}
