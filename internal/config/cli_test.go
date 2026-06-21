package config

import (
	"reflect"
	"testing"
)

func TestParseCLI_BasicShareAndUser(t *testing.T) {
	args := []string{
		"-s", "/srv/media",
		"-u", "alice:secret:alice",
	}
	got, err := ParseCLI(args)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Shares, []CLIShare{{Path: "/srv/media", Name: ""}}) {
		t.Errorf("shares: %+v", got.Shares)
	}
	want := []CLIUser{{Name: "alice", Password: "secret", SystemUser: "alice"}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Errorf("users: %+v", got.Users)
	}
}

func TestParseCLI_NamedShare(t *testing.T) {
	got, err := ParseCLI([]string{"-s", "/srv/media=movies"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Shares[0].Name != "movies" || got.Shares[0].Path != "/srv/media" {
		t.Errorf("got %+v", got.Shares[0])
	}
}

func TestParseCLI_Repeated(t *testing.T) {
	got, err := ParseCLI([]string{
		"-s", "/a", "-s", "/b=bee",
		"-u", "u1:p1:s1", "-u", "u2:p2:s2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Shares) != 2 || len(got.Users) != 2 {
		t.Errorf("expected 2 shares + 2 users, got %d / %d", len(got.Shares), len(got.Users))
	}
}

func TestParseCLI_TwoFieldUser(t *testing.T) {
	got, err := ParseCLI([]string{"-u", "alice:secret"})
	if err != nil {
		t.Fatal(err)
	}
	want := []CLIUser{{Name: "alice", Password: "secret", SystemUser: ""}}
	if !reflect.DeepEqual(got.Users, want) {
		t.Errorf("users: %+v", got.Users)
	}
}

func TestParseCLI_NumericSystemUser(t *testing.T) {
	got, err := ParseCLI([]string{"-u", "alice:secret:1000"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Users[0].SystemUser != "1000" {
		t.Errorf("SystemUser = %q, want %q", got.Users[0].SystemUser, "1000")
	}
}

func TestParseCLI_BadUserFormat(t *testing.T) {
	for _, spec := range []string{"alice", "a:b:c:d"} {
		if _, err := ParseCLI([]string{"-u", spec}); err == nil {
			t.Errorf("%q: expected error (must be 2 or 3 colon-separated fields)", spec)
		}
	}
}

func TestParseCLI_OptionalFlags(t *testing.T) {
	got, err := ParseCLI([]string{
		"-c", "/etc/gosamba.conf",
		"-l", ":1445",
		"--no-encryption",
		"--log-level", "debug",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigFile == nil || *got.ConfigFile != "/etc/gosamba.conf" {
		t.Errorf("ConfigFile: %+v", got.ConfigFile)
	}
	if got.Listen == nil || *got.Listen != ":1445" {
		t.Errorf("Listen: %+v", got.Listen)
	}
	if got.NoEncryption == nil || *got.NoEncryption != true {
		t.Errorf("NoEncryption: %+v", got.NoEncryption)
	}
	if got.LogLevel == nil || *got.LogLevel != "debug" {
		t.Errorf("LogLevel: %+v", got.LogLevel)
	}
}
