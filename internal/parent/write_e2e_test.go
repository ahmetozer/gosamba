//go:build smbclient_e2e

package parent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

func TestE2E_Write_CreateWriteRenameDelete(t *testing.T) {
	shareDir := t.TempDir()

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
		RequireSigning: true, MaxIOSize: 1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()

	// --- Create + write: put a file and verify on-disk content ---
	want := []byte("hello write path\n")
	uploadPath := filepath.Join(localDir, "hello.txt")
	if err := os.WriteFile(uploadPath, want, 0644); err != nil {
		t.Fatal(err)
	}

	putOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put hello.txt hello.txt",
	)
	t.Logf("put output:\n%s", putOut)

	disk, err := os.ReadFile(filepath.Join(shareDir, "hello.txt"))
	if err != nil || !bytes.Equal(disk, want) {
		t.Errorf("on-disk: %q err=%v", disk, err)
	}

	// --- get: download and verify byte-identical ---
	downloadPath := filepath.Join(localDir, "hello_got.txt")
	getOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get hello.txt %s", downloadPath),
	)
	t.Logf("get output:\n%s", getOut)

	got, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("get: downloaded file not found: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("get: content mismatch: got %q, want %q", got, want)
	}

	// --- mkdir ---
	mkdirOut := smbcli(t, port, "share", "alice%test123", "mkdir subdir")
	t.Logf("mkdir output:\n%s", mkdirOut)
	if st, err := os.Stat(filepath.Join(shareDir, "subdir")); err != nil || !st.IsDir() {
		t.Errorf("subdir: err=%v", err)
	}

	// --- rename ---
	renameOut := smbcli(t, port, "share", "alice%test123", "rename hello.txt renamed.txt")
	t.Logf("rename output:\n%s", renameOut)
	if _, err := os.Stat(filepath.Join(shareDir, "hello.txt")); err == nil {
		t.Error("hello.txt should be gone after rename")
	}
	if _, err := os.Stat(filepath.Join(shareDir, "renamed.txt")); err != nil {
		t.Errorf("renamed.txt missing: %v", err)
	}

	// --- delete file ---
	delOut := smbcli(t, port, "share", "alice%test123", "del renamed.txt")
	t.Logf("del output:\n%s", delOut)
	if _, err := os.Stat(filepath.Join(shareDir, "renamed.txt")); err == nil {
		t.Error("renamed.txt should be gone after del")
	}

	// --- rmdir ---
	rmdirOut := smbcli(t, port, "share", "alice%test123", "rmdir subdir")
	t.Logf("rmdir output:\n%s", rmdirOut)
	if _, err := os.Stat(filepath.Join(shareDir, "subdir")); err == nil {
		t.Error("subdir should be gone after rmdir")
	}

	// --- truncate: put a 10-byte file, overwrite with a 4-byte file, verify ---
	// smbclient does not have a native truncate command. We simulate truncation
	// by uploading a shorter replacement file, which the server creates with
	// FILE_OVERWRITE_IF semantics (sets the end-of-file to the new size).
	fullPath := filepath.Join(localDir, "trunc.txt")
	if err := os.WriteFile(fullPath, []byte("0123456789"), 0644); err != nil {
		t.Fatal(err)
	}
	smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put trunc.txt trunc.txt",
	)

	// Now overwrite with 4-byte content to simulate truncate(4).
	truncPath := filepath.Join(localDir, "trunc4.txt")
	if err := os.WriteFile(truncPath, []byte("0123"), 0644); err != nil {
		t.Fatal(err)
	}
	smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put trunc4.txt trunc.txt",
	)

	diskTrunc, err := os.ReadFile(filepath.Join(shareDir, "trunc.txt"))
	if err != nil {
		t.Fatalf("trunc.txt: %v", err)
	}
	if string(diskTrunc) != "0123" {
		t.Errorf("after truncate: %q, want %q", diskTrunc, "0123")
	}

	t.Log("write E2E succeeded")
}
