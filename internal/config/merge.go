package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ahmetozer/gosamba/internal/userdb"
)

// Merge combines defaults, file, and CLI into a final Config.
// Precedence (later overrides earlier): defaults < file < CLI.
// Shares: file shares first, then CLI shares appended.
// Users: file users first, then CLI users (plaintext-hashed) appended.
func Merge(cli CLI, file File) (Config, error) {
	cfg := Defaults()

	// --- server: file ---
	if v := file.Server.Listen; v != nil {
		cfg.Server.Listen = *v
	}
	if v := file.Server.Netbios; v != nil {
		cfg.Server.Netbios = *v
	}
	if v := file.Server.MDNS; v != nil {
		cfg.Server.MDNS = *v
	}
	if v := file.Server.Encryption; v != nil {
		cfg.Server.Encryption = *v
	}
	if v := file.Server.Signing; v != nil {
		cfg.Server.Signing = *v
	}
	if v := file.Server.DurableTimeout; v != nil {
		d, err := time.ParseDuration(*v)
		if err != nil {
			return Config{}, fmt.Errorf("durable_timeout in file: %w", err)
		}
		cfg.Server.DurableTimeout = d
	}
	if v := file.Server.StateDir; v != nil {
		cfg.Server.StateDir = *v
	}
	if v := file.Server.PerUserPrivdrop; v != nil {
		cfg.Server.PerUserPrivdrop = *v
	}

	// --- log: file ---
	if v := file.Log.Level; v != nil {
		cfg.Log.Level = *v
	}
	if v := file.Log.Format; v != nil {
		cfg.Log.Format = *v
	}

	// --- server: CLI ---
	if v := cli.Listen; v != nil {
		cfg.Server.Listen = *v
	}
	if v := cli.Netbios; v != nil {
		cfg.Server.Netbios = *v
	}
	if v := cli.MDNS; v != nil {
		cfg.Server.MDNS = *v
	}
	if v := cli.NoEncryption; v != nil && *v {
		cfg.Server.Encryption = EncryptionOff
	}
	if v := cli.NoSigning; v != nil && *v {
		cfg.Server.Signing = SigningPreferred
	}
	if v := cli.DurableTimeout; v != nil {
		d, err := time.ParseDuration(*v)
		if err != nil {
			return Config{}, fmt.Errorf("--durable-timeout: %w", err)
		}
		cfg.Server.DurableTimeout = d
	}
	if v := cli.StateDir; v != nil {
		cfg.Server.StateDir = *v
	}
	if v := cli.PerUserPrivdrop; v != nil {
		cfg.Server.PerUserPrivdrop = *v
	}

	// --- log: CLI ---
	if v := cli.LogLevel; v != nil {
		cfg.Log.Level = *v
	}
	if v := cli.LogFormat; v != nil {
		cfg.Log.Format = *v
	}

	// --- shares: file then CLI ---
	for _, fs := range file.Shares {
		name := fs.Name
		if name == "" {
			name = filepath.Base(fs.Path)
		}
		cfg.Shares = append(cfg.Shares, ShareConfig{
			Name:     name,
			Path:     fs.Path,
			ReadOnly: fs.ReadOnly,
			GuestOK:  fs.GuestOK,
		})
	}
	for _, cs := range cli.Shares {
		name := cs.Name
		if name == "" {
			name = filepath.Base(cs.Path)
		}
		cfg.Shares = append(cfg.Shares, ShareConfig{
			Name: name,
			Path: cs.Path,
		})
	}

	// --- users: file then CLI ---
	for _, fu := range file.Users {
		shares := fu.AllowShares
		if len(shares) == 0 {
			shares = []string{"*"}
		}
		cfg.Users = append(cfg.Users, UserConfig{
			Name:        fu.Name,
			NTHash:      fu.NTHash,
			SystemUser:  fu.SystemUser,
			AllowShares: shares,
		})
	}
	for _, cu := range cli.Users {
		hash := userdb.NTHash(cu.Password)
		cfg.Users = append(cfg.Users, UserConfig{
			Name:        cu.Name,
			NTHash:      hash,
			SystemUser:  cu.SystemUser,
			AllowShares: []string{"*"},
		})
	}

	return cfg, nil
}
