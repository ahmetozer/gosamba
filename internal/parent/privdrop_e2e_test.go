//go:build smbclient_e2e

package parent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// buildGosamba compiles the real cmd/gosamba binary into a temp dir and returns
// its path. The privilege-drop worker model only exists in the real binary
// (it re-execs /proc/self/exe), so these tests must drive the compiled server
// rather than the in-process startTestServer helper.
func buildGosamba(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "gosamba")
	cmd := exec.Command("go", "build", "-tags", "smbclient_e2e", "-o", out, "github.com/ahmetozer/gosamba/cmd/gosamba")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build gosamba: %v\n%s", err, b)
	}
	return out
}

// startRealServer launches the compiled binary on an ephemeral port and waits
// until it accepts connections. extraArgs are appended after the base flags.
// It returns the chosen port.
func startRealServer(t *testing.T, exe string, extraArgs ...string) int {
	t.Helper()

	// Grab a free port, then release it so the server can bind it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	args := append([]string{
		"--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--no-encryption",
		"--log-level", "debug",
	}, extraArgs...)

	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	})

	// Wait for the listener to accept.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return port
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not come up on port %d", port)
	return 0
}

// makeTraversable adds o+x to dir and every ancestor up to /tmp so a
// privilege-dropped (non-root) worker can reach a share created under a
// per-test temp dir (which Go creates mode 0700, owned by root).
func makeTraversable(t *testing.T, dir string) {
	t.Helper()
	for p := dir; p != "/" && p != "" && p != "/tmp"; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return
		}
		if err := os.Chmod(p, st.Mode()|0o111); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
}

func fileOwnerUID(t *testing.T, path string) uint32 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: no Stat_t", path)
	}
	return sys.Uid
}

// TestPrivdrop_OwnerIsTargetUID is the core owner-uid e2e: with per-user
// privilege drop enabled, a user mapped to uid 65534 (nobody) should produce
// on-disk files owned by 65534, proving the worker dropped privileges.
func TestPrivdrop_OwnerIsTargetUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privdrop e2e requires root")
	}
	if _, err := exec.LookPath("smbclient"); err != nil {
		t.Skip("smbclient not found in PATH")
	}

	// t.TempDir() creates ancestor dirs mode 0700 owned by root, which uid
	// 65534 cannot traverse. Make the share itself world-writable AND ensure
	// every ancestor is at least traversable (o+x) so the dropped worker can
	// reach it. (That root previously failed to reach a 0700 dir while the
	// dropped worker now must, is itself proof the drop took effect.)
	shareDir := t.TempDir()
	if err := os.Chmod(shareDir, 0777); err != nil {
		t.Fatal(err)
	}
	makeTraversable(t, shareDir)

	exe := buildGosamba(t)
	port := startRealServer(t, exe,
		"--per-user-privdrop",
		"--share", shareDir+"=share",
		"--user", "nobodyuser:test123:nobody",
	)

	localDir := t.TempDir()
	uploadPath := filepath.Join(localDir, "hello.txt")
	if err := os.WriteFile(uploadPath, []byte("privdrop owner test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out := smbcli(t, port, "share", "nobodyuser%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put hello.txt hello.txt",
	)
	t.Logf("put output:\n%s", out)

	uid := fileOwnerUID(t, filepath.Join(shareDir, "hello.txt"))
	if uid != 65534 {
		t.Errorf("on-disk file owner uid = %d, want 65534 (privilege drop did not take effect)", uid)
	}
}

// TestPrivdrop_RootUserStillWorks confirms that with privdrop enabled, a user
// mapped to uid 0 (root) still creates files successfully (drop is a no-op).
func TestPrivdrop_RootUserStillWorks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privdrop e2e requires root")
	}
	if _, err := exec.LookPath("smbclient"); err != nil {
		t.Skip("smbclient not found in PATH")
	}

	shareDir := t.TempDir()
	exe := buildGosamba(t)
	port := startRealServer(t, exe,
		"--per-user-privdrop",
		"--share", shareDir+"=share",
		"--user", "rootuser:test123:root",
	)

	localDir := t.TempDir()
	uploadPath := filepath.Join(localDir, "root.txt")
	if err := os.WriteFile(uploadPath, []byte("root user content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out := smbcli(t, port, "share", "rootuser%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put root.txt root.txt",
	)
	t.Logf("put output:\n%s", out)

	if _, err := os.Stat(filepath.Join(shareDir, "root.txt")); err != nil {
		t.Errorf("root-mapped user failed to create file: %v", err)
	}
	uid := fileOwnerUID(t, filepath.Join(shareDir, "root.txt"))
	if uid != 0 {
		t.Errorf("root-mapped file owner uid = %d, want 0", uid)
	}
}
