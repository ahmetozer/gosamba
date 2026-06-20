package parent

import (
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
)

func TestDecidePrivDrop(t *testing.T) {
	tests := []struct {
		name      string
		euid      int
		targetUID int
		wantDrop  bool
		wantSkip  bool
	}{
		{name: "root drops to nobody", euid: 0, targetUID: 65534, wantDrop: true},
		{name: "root to root is no-op", euid: 0, targetUID: 0, wantSkip: true},
		{name: "non-root cannot drop", euid: 1000, targetUID: 65534, wantSkip: true},
		{name: "non-root to self no-op-ish", euid: 1000, targetUID: 1000, wantSkip: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := decidePrivDrop(tc.euid, tc.targetUID, tc.targetUID, nil)
			if p.Drop != tc.wantDrop {
				t.Errorf("Drop = %v, want %v (reason: %s)", p.Drop, tc.wantDrop, p.Reason)
			}
			if p.Skip != tc.wantSkip {
				t.Errorf("Skip = %v, want %v (reason: %s)", p.Skip, tc.wantSkip, p.Reason)
			}
			// Drop and Skip are mutually exclusive; exactly one must be true.
			if p.Drop == p.Skip {
				t.Errorf("Drop(%v) and Skip(%v) must be mutually exclusive", p.Drop, p.Skip)
			}
			if p.Drop && p.UID != tc.targetUID {
				t.Errorf("plan UID = %d, want %d", p.UID, tc.targetUID)
			}
		})
	}
}

func TestApplyPrivDrop_SkipIsNoop(t *testing.T) {
	// A skip/no-op plan must not perform any syscall and must return nil. Safe
	// to run in the test process because Drop is false.
	if err := applyPrivDrop(privDropPlan{Skip: true, Reason: "test"}); err != nil {
		t.Fatalf("skip plan should be a no-op, got err: %v", err)
	}
	if err := applyPrivDrop(privDropPlan{}); err != nil {
		t.Fatalf("empty (no-drop) plan should be a no-op, got err: %v", err)
	}
}

func TestShouldUsePrivdropWorker(t *testing.T) {
	rootUser := config.UserConfig{Name: "r", SystemUID: 0}
	nobody := config.UserConfig{Name: "n", SystemUID: 65534}

	tests := []struct {
		name     string
		explicit bool
		euid     int
		users    []config.UserConfig
		want     bool
	}{
		{name: "explicit always on", explicit: true, euid: 1000, users: nil, want: true},
		{name: "explicit on as root", explicit: true, euid: 0, users: nil, want: true},
		{name: "auto: root + nonroot user", euid: 0, users: []config.UserConfig{nobody}, want: true},
		{name: "auto: root + only root users", euid: 0, users: []config.UserConfig{rootUser}, want: false},
		{name: "auto: non-root never auto", euid: 1000, users: []config.UserConfig{nobody}, want: false},
		{name: "auto: no users", euid: 0, users: nil, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldUsePrivdropWorker(tc.explicit, tc.euid, tc.users); got != tc.want {
				t.Errorf("ShouldUsePrivdropWorker(%v, %d, ...) = %v, want %v", tc.explicit, tc.euid, got, tc.want)
			}
		})
	}
}

func TestIsWorker(t *testing.T) {
	t.Setenv(workerEnvKey, "")
	if IsWorker() {
		t.Error("IsWorker should be false when env unset")
	}
	t.Setenv(workerEnvKey, "1")
	if !IsWorker() {
		t.Error("IsWorker should be true when GOSAMBA_WORKER=1")
	}
}
