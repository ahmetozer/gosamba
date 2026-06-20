package config

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
)

// Validate inspects cfg, fills SystemUID/SystemGID from SystemUser, and
// rejects invalid configurations.
func Validate(cfg *Config) error {
	if _, _, err := net.SplitHostPort(cfg.Server.Listen); err != nil {
		return fmt.Errorf("listen %q: %w", cfg.Server.Listen, err)
	}

	switch cfg.Server.Encryption {
	case EncryptionRequired, EncryptionPreferred, EncryptionOff:
	default:
		return fmt.Errorf("encryption %q: must be required|preferred|off", cfg.Server.Encryption)
	}
	switch cfg.Server.Signing {
	case SigningRequired, SigningPreferred:
	default:
		return fmt.Errorf("signing %q: must be required|preferred", cfg.Server.Signing)
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q: must be debug|info|warn|error", cfg.Log.Level)
	}
	switch cfg.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format %q: must be text|json", cfg.Log.Format)
	}

	seenShares := make(map[string]struct{})
	for i, s := range cfg.Shares {
		if s.Name == "" {
			return fmt.Errorf("share[%d]: name is empty", i)
		}
		if _, dup := seenShares[s.Name]; dup {
			return fmt.Errorf("share %q: duplicate name", s.Name)
		}
		seenShares[s.Name] = struct{}{}

		st, err := os.Stat(s.Path)
		if err != nil {
			return fmt.Errorf("share %q: path %q: %w", s.Name, s.Path, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("share %q: path %q is not a directory", s.Name, s.Path)
		}
	}

	for i, u := range cfg.Users {
		if u.Name == "" {
			return fmt.Errorf("user[%d]: name is empty", i)
		}
		if u.SystemUser == "" {
			return fmt.Errorf("user %q: system_user is empty", u.Name)
		}
		sysu, err := user.Lookup(u.SystemUser)
		if err != nil {
			return fmt.Errorf("user %q: system_user %q: %w", u.Name, u.SystemUser, err)
		}
		uid, err := strconv.Atoi(sysu.Uid)
		if err != nil {
			return fmt.Errorf("user %q: non-numeric uid %q", u.Name, sysu.Uid)
		}
		gid, err := strconv.Atoi(sysu.Gid)
		if err != nil {
			return fmt.Errorf("user %q: non-numeric gid %q", u.Name, sysu.Gid)
		}
		cfg.Users[i].SystemUID = uid
		cfg.Users[i].SystemGID = gid
	}

	return nil
}
