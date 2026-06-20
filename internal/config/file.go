package config

import (
	"encoding/hex"
	"fmt"
	"os"
)

// File is the TOML schema. All scalars are pointers so we can distinguish
// "not set" from "set to zero value" in the merge step.
type File struct {
	Server FileServer  `toml:"server"`
	Log    FileLog     `toml:"log"`
	Shares []FileShare `toml:"share"`
	Users  []FileUser  `toml:"user"`
}

type FileServer struct {
	Listen          *string         `toml:"listen"`
	Netbios         *bool           `toml:"netbios"`
	MDNS            *bool           `toml:"mdns"`
	Encryption      *EncryptionMode `toml:"encryption"`
	Signing         *SigningMode    `toml:"signing"`
	DurableTimeout  *string         `toml:"durable_timeout"`
	StateDir        *string         `toml:"state_dir"`
	PerUserPrivdrop *bool           `toml:"per_user_privdrop"`
}

type FileLog struct {
	Level  *string `toml:"level"`
	Format *string `toml:"format"`
}

type FileShare struct {
	Name     string `toml:"name"`
	Path     string `toml:"path"`
	ReadOnly bool   `toml:"read_only"`
	GuestOK  bool   `toml:"guest_ok"`
}

type FileUser struct {
	Name        string   `toml:"name"`
	NTHash      [16]byte `toml:"-"`
	NTHashHex   string   `toml:"nt_hash"`
	SystemUser  string   `toml:"system_user"`
	AllowShares []string `toml:"allow_shares"`
}

// ParseFile loads a TOML config from path. Refuses files with mode bits beyond 0640.
func ParseFile(path string) (File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return File{}, err
	}
	mode := st.Mode().Perm()
	if mode&0027 != 0 {
		return File{}, fmt.Errorf("config file %s has too-permissive mode %#o (must be ≤ 0640)", path, mode)
	}

	var f File
	if err := decodeTOMLFile(path, &f); err != nil {
		return File{}, fmt.Errorf("decode %s: %w", path, err)
	}

	for i := range f.Users {
		if f.Users[i].NTHashHex == "" {
			continue
		}
		raw, err := hex.DecodeString(f.Users[i].NTHashHex)
		if err != nil {
			return File{}, fmt.Errorf("user %q: nt_hash not valid hex: %w", f.Users[i].Name, err)
		}
		if len(raw) != 16 {
			return File{}, fmt.Errorf("user %q: nt_hash must be 16 bytes (32 hex chars), got %d", f.Users[i].Name, len(raw))
		}
		copy(f.Users[i].NTHash[:], raw)
	}

	return f, nil
}
