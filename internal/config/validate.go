package config

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// parseNumericSystemUser interprets a system_user spec as numeric ids so the
// uid/gid can be resolved without reading /etc/passwd.
//
//   - "1000"       -> uid=1000, gid=1000, ok=true
//   - "1000/1001"  -> uid=1000, gid=1001, ok=true
//   - "alice"      -> ok=false (it is a name; caller must look it up)
//
// ok=false with a nil error means the spec is a name, not a number. A non-nil
// error means the spec looked numeric (contains '/') but was malformed.
func parseNumericSystemUser(spec string) (uid, gid int, ok bool, err error) {
	if u, g, hasSlash := strings.Cut(spec, "/"); hasSlash {
		uid, uerr := strconv.Atoi(u)
		gid, gerr := strconv.Atoi(g)
		if uerr != nil || gerr != nil {
			return 0, 0, false, fmt.Errorf("system_user %q: uid/gid form requires two integers", spec)
		}
		return uid, gid, true, nil
	}
	n, nerr := strconv.Atoi(spec)
	if nerr != nil {
		return 0, 0, false, nil // not numeric: treat as a name
	}
	return n, n, true, nil
}

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
		// No system_user: serve as the current process user, never privilege
		// drop. Resolved without touching /etc/passwd.
		if u.SystemUser == "" {
			cfg.Users[i].SystemUID = os.Getuid()
			cfg.Users[i].SystemGID = os.Getgid()
			continue
		}
		// Numeric system_user (uid or uid/gid): use the ids directly, no
		// /etc/passwd lookup. This is what makes minimal images (e.g. scratch)
		// work.
		if uid, gid, ok, err := parseNumericSystemUser(u.SystemUser); err != nil {
			return fmt.Errorf("user %q: %w", u.Name, err)
		} else if ok {
			cfg.Users[i].SystemUID = uid
			cfg.Users[i].SystemGID = gid
			continue
		}
		// Named system_user: resolve via /etc/passwd.
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
