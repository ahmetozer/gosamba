package parent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// allThreadsHelperEnv marks the re-exec'd helper subprocess that performs the
// destructive whole-process privilege drop and the all-threads file-ownership
// check. Privilege dropping is irreversible and would poison the test runner,
// so it must happen in a throwaway child process.
const allThreadsHelperEnv = "GOSAMBA_TEST_ALLTHREADS_HELPER"

// allThreadsTargetUID is the unprivileged uid the helper drops to (nobody).
const allThreadsTargetUID = 65534

// TestMain runs the all-threads helper body when the marker env var is set;
// otherwise it runs the normal test suite. The helper exits the process itself
// so its result is conveyed purely via exit code and stdout.
func TestMain(m *testing.M) {
	if os.Getenv(allThreadsHelperEnv) == "1" {
		runAllThreadsHelper()
		return // unreachable: runAllThreadsHelper calls os.Exit
	}
	os.Exit(m.Run())
}

// threadCred is a per-OS-thread snapshot of the effective credentials, captured
// on a thread that was parked (locked) across the privilege drop.
type threadCred struct {
	idx    int
	euid   int
	egid   int
	groups []int
}

// runAllThreadsHelper executes inside the re-exec'd child (running as root) and
// proves the privilege drop is PROCESS-WIDE (all OS threads), not per-thread.
//
// It does two independent checks:
//
//  1. Thread-credential check (the strong guard). It spawns several goroutines,
//     locks each to its own OS thread, and PARKS them BEFORE the drop. These
//     threads therefore exist and are blocked while dropPrivileges runs on a
//     different thread. After the drop they each report their own effective
//     uid/gid and supplementary group set. With a correct process-wide drop
//     every parked thread reports euid=egid=65534 and groups=[65534]. With a
//     per-thread drop (the old bug — note the raw golang.org/x/sys/unix
//     Setgroups is a RawSyscall that affects only the calling thread) the parked
//     threads keep root's identity (e.g. groups=[0 20]) and the helper exits
//     non-zero.
//
//  2. File-ownership check. Files created from many goroutines (likely on assorted
//     threads) plus the main goroutine must all be owned by uid/gid 65534.
func runAllThreadsHelper() {
	// Encourage the runtime to use multiple OS threads so goroutines can land
	// on threads other than the drop-issuing one.
	runtime.GOMAXPROCS(8)

	dir, err := os.MkdirTemp("", "gosamba-allthreads-*")
	if err != nil {
		fmt.Printf("HELPER FAIL: mkdirtemp: %v\n", err)
		os.Exit(2)
	}
	// MkdirTemp creates the dir mode 0700 owned by root; after the drop the
	// unprivileged uid could not write into it. Make it world-writable while we
	// are still root so the post-drop file creates are a clean test of OWNERSHIP
	// (the bug we guard against), not of directory permissions.
	if err := os.Chmod(dir, 0777); err != nil {
		fmt.Printf("HELPER FAIL: chmod tempdir: %v\n", err)
		os.Exit(2)
	}

	const nThreads = 8

	// --- Phase 1: park nThreads OS threads BEFORE the drop. ---
	started := make(chan struct{}, nThreads)
	release := make(chan struct{})
	creds := make(chan threadCred, nThreads)
	var parkWG sync.WaitGroup
	for i := 0; i < nThreads; i++ {
		parkWG.Add(1)
		go func(i int) {
			defer parkWG.Done()
			// Pin to a dedicated OS thread and never unlock: this thread is
			// distinct from the one dropPrivileges runs on, and it is blocked
			// in <-release while the drop happens.
			runtime.LockOSThread()
			started <- struct{}{}
			<-release
			g, gerr := syscall.Getgroups()
			if gerr != nil {
				g = []int{-1}
			}
			creds <- threadCred{
				idx:    i,
				euid:   syscall.Geteuid(),
				egid:   syscall.Getegid(),
				groups: g,
			}
		}(i)
	}
	for i := 0; i < nThreads; i++ {
		<-started
	}
	// Give the runtime a moment to settle the parked threads.
	time.Sleep(50 * time.Millisecond)

	// --- Phase 2: perform the real, whole-process privilege drop. ---
	if err := dropPrivileges(allThreadsTargetUID, allThreadsTargetUID, []int{allThreadsTargetUID}); err != nil {
		fmt.Printf("HELPER FAIL: dropPrivileges: %v\n", err)
		os.Exit(3)
	}

	// --- Phase 3: collect the parked threads' post-drop credentials. ---
	close(release)
	parkWG.Wait()
	close(creds)
	credBad := 0
	for c := range creds {
		ok := c.euid == allThreadsTargetUID &&
			c.egid == allThreadsTargetUID &&
			len(c.groups) == 1 && c.groups[0] == allThreadsTargetUID
		if !ok {
			fmt.Printf("HELPER BAD THREAD CRED: thread %d euid=%d egid=%d groups=%v want euid=egid=%d groups=[%d]\n",
				c.idx, c.euid, c.egid, c.groups, allThreadsTargetUID, allThreadsTargetUID)
			credBad++
		}
	}
	if credBad > 0 {
		fmt.Printf("HELPER FAIL: %d/%d parked threads kept stale credentials (drop was NOT process-wide)\n",
			credBad, nThreads)
		os.Exit(8)
	}

	// --- Phase 4: file-ownership check across goroutines. ---
	paths := make([]string, 0, nThreads+1)
	var mu sync.Mutex
	var wg sync.WaitGroup
	createErr := make(chan error, nThreads)
	for i := 0; i < nThreads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			p := filepath.Join(dir, fmt.Sprintf("g%d.txt", i))
			if werr := os.WriteFile(p, []byte("x"), 0644); werr != nil {
				createErr <- fmt.Errorf("goroutine %d write: %w", i, werr)
				return
			}
			mu.Lock()
			paths = append(paths, p)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(createErr)
	for werr := range createErr {
		if werr != nil {
			fmt.Printf("HELPER FAIL: %v\n", werr)
			os.Exit(4)
		}
	}

	// Also create one on the main goroutine.
	mainPath := filepath.Join(dir, "main.txt")
	if werr := os.WriteFile(mainPath, []byte("x"), 0644); werr != nil {
		fmt.Printf("HELPER FAIL: main write: %v\n", werr)
		os.Exit(5)
	}
	paths = append(paths, mainPath)

	// Every file must be owned by the dropped uid+gid, NOT root.
	bad := 0
	for _, p := range paths {
		st, serr := os.Stat(p)
		if serr != nil {
			fmt.Printf("HELPER FAIL: stat %s: %v\n", p, serr)
			os.Exit(6)
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			fmt.Printf("HELPER FAIL: %s: no Stat_t\n", p)
			os.Exit(7)
		}
		if sys.Uid != allThreadsTargetUID || sys.Gid != allThreadsTargetUID {
			fmt.Printf("HELPER BAD OWNER: %s owned by uid=%d gid=%d want=%d/%d\n",
				p, sys.Uid, sys.Gid, allThreadsTargetUID, allThreadsTargetUID)
			bad++
		}
	}
	if bad > 0 {
		fmt.Printf("HELPER FAIL: %d/%d files NOT owned by uid/gid=%d (privilege drop was not process-wide)\n",
			bad, len(paths), allThreadsTargetUID)
		os.Exit(9)
	}

	fmt.Printf("HELPER OK: %d parked threads dropped (euid=egid=%d groups=[%d]); all %d files owned by uid/gid=%d\n",
		nThreads, allThreadsTargetUID, allThreadsTargetUID, len(paths), allThreadsTargetUID)
	os.Exit(0)
}

// TestPrivdrop_AllThreads proves the privilege drop is process-wide. It re-execs
// this test binary into the helper subprocess (which must run as root), which
// drops to uid 65534 and creates files from multiple goroutines. The test fails
// if any file ends up root-owned — the exact symptom of the old per-thread
// unix.Setresuid + runtime.LockOSThread approach.
func TestPrivdrop_AllThreads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("all-threads privdrop test requires root")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run", "TestPrivdrop_AllThreads")
	cmd.Env = append(os.Environ(), allThreadsHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("helper output:\n%s", out)
	if err != nil {
		t.Fatalf("helper subprocess failed (privilege drop not process-wide): %v", err)
	}
}
