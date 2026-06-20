package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMerge_DefaultsOnly(t *testing.T) {
	got, err := Merge(CLI{}, File{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Listen != ":445" {
		t.Errorf("listen: %s", got.Server.Listen)
	}
	if got.Server.Encryption != EncryptionRequired {
		t.Errorf("encryption: %s", got.Server.Encryption)
	}
	if got.Server.DurableTimeout != 60*time.Second {
		t.Errorf("durable: %v", got.Server.DurableTimeout)
	}
}

func TestMerge_FileOverridesDefaults(t *testing.T) {
	listen := ":1445"
	enc := EncryptionPreferred
	got, err := Merge(CLI{}, File{
		Server: FileServer{Listen: &listen, Encryption: &enc},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Listen != ":1445" {
		t.Errorf("listen: %s", got.Server.Listen)
	}
	if got.Server.Encryption != EncryptionPreferred {
		t.Errorf("encryption: %s", got.Server.Encryption)
	}
	if got.Server.Signing != SigningRequired {
		t.Errorf("signing: should retain default")
	}
}

func TestMerge_CLIOverridesFile(t *testing.T) {
	cli := CLI{}
	cliListen := ":2445"
	cli.Listen = &cliListen
	noEnc := true
	cli.NoEncryption = &noEnc

	fileListen := ":1445"
	got, err := Merge(cli, File{
		Server: FileServer{Listen: &fileListen},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Listen != ":2445" {
		t.Errorf("CLI should win: %s", got.Server.Listen)
	}
	if got.Server.Encryption != EncryptionOff {
		t.Errorf("--no-encryption should set Off, got %s", got.Server.Encryption)
	}
}

func TestMerge_SharesFromFileAndCLI(t *testing.T) {
	cli := CLI{Shares: []CLIShare{{Path: "/cli", Name: ""}}}
	file := File{Shares: []FileShare{{Path: "/file", Name: "filesh"}}}
	got, err := Merge(cli, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(got.Shares))
	}
	if got.Shares[0].Path != "/file" || got.Shares[0].Name != "filesh" {
		t.Errorf("share[0] = %+v", got.Shares[0])
	}
	if got.Shares[1].Path != "/cli" || got.Shares[1].Name != filepath.Base("/cli") {
		t.Errorf("share[1] = %+v (name should default to basename)", got.Shares[1])
	}
}

func TestMerge_UsersFromCLIArePlaintext(t *testing.T) {
	cli := CLI{Users: []CLIUser{{Name: "alice", Password: "secret", SystemUser: "alice"}}}
	got, err := Merge(cli, File{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Users) != 1 {
		t.Fatal()
	}
	var zero [16]byte
	if got.Users[0].NTHash == zero {
		t.Error("expected non-zero NT hash")
	}
	if got.Users[0].SystemUser != "alice" {
		t.Errorf("system_user: %s", got.Users[0].SystemUser)
	}
}

func TestMerge_BadDurationInFile(t *testing.T) {
	bad := "not-a-duration"
	_, err := Merge(CLI{}, File{Server: FileServer{DurableTimeout: &bad}})
	if err == nil {
		t.Fatal("expected error on bad duration")
	}
}
