package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTimeMachineMultiShareTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../examples/time-machine/gosamba.multi.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, name := range []string{"laptop", "desktop"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Substitute test credentials and local directories without changing the
	// example's share headers, names or access lists.
	source := strings.NewReplacer(
		"/srv/backups", root,
		"REPLACE_WITH_LAPTOP_NT_HASH", "a4f49c406510bdcab6824ee7c30fd852",
		"REPLACE_WITH_DESKTOP_NT_HASH", "a4f49c406510bdcab6824ee7c30fd852",
	).Replace(string(raw))
	file, err := ParseFile(writeTemp(t, source))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(CLI{}, file)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 2 || len(cfg.Users) != 2 {
		t.Fatalf("shares=%d users=%d; want 2 and 2", len(cfg.Shares), len(cfg.Users))
	}
	for i, name := range []string{"TimeMachineLaptop", "TimeMachineDesktop"} {
		share := cfg.Shares[i]
		if share.Name != name || !share.TimeMachine || share.ReadOnly || share.GuestOK {
			t.Errorf("share[%d] = %+v", i, share)
		}
	}
	if cfg.Users[0].Name != "tm_laptop" || !reflect.DeepEqual(cfg.Users[0].AllowShares, []string{"TimeMachineLaptop"}) {
		t.Error("incorrect access list for tm_laptop")
	}
	if cfg.Users[1].Name != "tm_desktop" || !reflect.DeepEqual(cfg.Users[1].AllowShares, []string{"TimeMachineDesktop"}) {
		t.Error("incorrect access list for tm_desktop")
	}
}

func TestTimeMachineConfig(t *testing.T) {
	f, err := ParseFile(writeTemp(t, `
[[share]]
path = "/srv/backups"
time_machine = true
[[share]]
name = "files"
path = "/srv/files"
[[share]]
path = "/srv/disabled"
time_machine = false
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(CLI{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Shares[0].TimeMachine || cfg.Shares[0].Name != "backups" || cfg.Shares[1].TimeMachine || cfg.Shares[2].TimeMachine {
		t.Fatalf("shares: %+v", cfg.Shares)
	}
	if _, err := ParseFile(writeTemp(t, "[[share]]\ntime_machine = \"true\"\n")); err == nil {
		t.Fatal("accepted a string boolean")
	}
}

func TestTimeMachineValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readOnly bool
		bad      bool
	}{
		{"Backup Mac", false, false}, {"Бэкапы", false, false}, {"backup", true, true},
		{"bad,name", false, true}, {"bad=name", false, true}, {strings.Repeat("x", 240), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Shares = []ShareConfig{{Name: tc.name, Path: t.TempDir(), ReadOnly: tc.readOnly, TimeMachine: true}}
			if err := Validate(&cfg); (err != nil) != tc.bad {
				t.Fatalf("Validate = %v; bad=%v", err, tc.bad)
			}
		})
	}
}
