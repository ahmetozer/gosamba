package config

import (
	"flag"
	"fmt"
	"strings"
)

// CLI holds values explicitly set on the command line.
// Pointer fields are nil when not set so the merge step knows what to override.
type CLI struct {
	ConfigFile      *string
	Listen          *string
	Netbios         *bool
	MDNS            *bool
	NoEncryption    *bool
	NoSigning       *bool
	DurableTimeout  *string
	StateDir        *string
	PerUserPrivdrop *bool
	LogLevel        *string
	LogFormat       *string

	Shares []CLIShare
	Users  []CLIUser
}

type CLIShare struct {
	Path string
	Name string
}

type CLIUser struct {
	Name       string
	Password   string
	SystemUser string
}

// stringList is a flag.Value that appends each occurrence (no comma-splitting).
type stringList struct {
	vals *[]string
}

func (s stringList) String() string {
	if s.vals == nil || len(*s.vals) == 0 {
		return ""
	}
	return strings.Join(*s.vals, " ")
}

func (s stringList) Set(v string) error {
	*s.vals = append(*s.vals, v)
	return nil
}

func ParseCLI(args []string) (CLI, error) {
	fs := flag.NewFlagSet("gosamba", flag.ContinueOnError)

	var (
		shareSpecs []string
		userSpecs  []string
		out        CLI
	)

	// Repeatable string-list flags; both short and long names share the same slice.
	shareVal := stringList{vals: &shareSpecs}
	userVal := stringList{vals: &userSpecs}

	fs.Var(shareVal, "share", "share dir, repeatable; <path> or <path>=<name>")
	fs.Var(shareVal, "s", "share dir, repeatable; <path> or <path>=<name> (short for --share)")
	fs.Var(userVal, "user", "user, repeatable; smb_user:password:system_user")
	fs.Var(userVal, "u", "user, repeatable; smb_user:password:system_user (short for --user)")

	// Scalar flags: long+short pairs share the same underlying value variable.
	cfVal := ""
	fs.StringVar(&cfVal, "config", "", "config file (TOML)")
	fs.StringVar(&cfVal, "c", "", "config file (TOML) (short for --config)")

	liVal := ""
	fs.StringVar(&liVal, "listen", "", "listen address (default :445)")
	fs.StringVar(&liVal, "l", "", "listen address (short for --listen)")

	nbVal := false
	fs.BoolVar(&nbVal, "netbios", false, "also bind :139")

	mdnsVal := true
	fs.BoolVar(&mdnsVal, "mdns", true, "advertise SMB service via mDNS/Bonjour (default on)")

	neVal := false
	fs.BoolVar(&neVal, "no-encryption", false, "allow non-encrypted SMB3 sessions")

	nsVal := false
	fs.BoolVar(&nsVal, "no-signing", false, "allow unsigned messages")

	dtVal := ""
	fs.StringVar(&dtVal, "durable-timeout", "", "duration, e.g. 60s")

	sdVal := ""
	fs.StringVar(&sdVal, "state-dir", "", "runtime state directory")

	pdVal := false
	fs.BoolVar(&pdVal, "per-user-privdrop", false, "serve each connection in a worker process that drops to the authenticated user's uid/gid (requires root)")

	llVal := ""
	fs.StringVar(&llVal, "log-level", "", "debug|info|warn|error")

	lfVal := ""
	fs.StringVar(&lfVal, "log-format", "", "text|json")

	if err := fs.Parse(args); err != nil {
		return CLI{}, err
	}

	// Replicate pflag.Changed semantics: collect only flags that were explicitly set.
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})

	if set["config"] || set["c"] {
		out.ConfigFile = &cfVal
	}
	if set["listen"] || set["l"] {
		out.Listen = &liVal
	}
	if set["netbios"] {
		out.Netbios = &nbVal
	}
	if set["mdns"] {
		out.MDNS = &mdnsVal
	}
	if set["no-encryption"] {
		out.NoEncryption = &neVal
	}
	if set["no-signing"] {
		out.NoSigning = &nsVal
	}
	if set["durable-timeout"] {
		out.DurableTimeout = &dtVal
	}
	if set["state-dir"] {
		out.StateDir = &sdVal
	}
	if set["per-user-privdrop"] {
		out.PerUserPrivdrop = &pdVal
	}
	if set["log-level"] {
		out.LogLevel = &llVal
	}
	if set["log-format"] {
		out.LogFormat = &lfVal
	}

	for _, s := range shareSpecs {
		path, name, _ := strings.Cut(s, "=")
		out.Shares = append(out.Shares, CLIShare{Path: path, Name: name})
	}
	for _, u := range userSpecs {
		parts := strings.Split(u, ":")
		// 2 fields: smb_user:password (no privilege drop — serve as the current
		// user). 3 fields: smb_user:password:system_user (name, numeric uid, or
		// uid/gid).
		if len(parts) != 2 && len(parts) != 3 {
			return CLI{}, fmt.Errorf("-u %q: must be smb_user:password[:system_user] (2 or 3 fields, got %d)", u, len(parts))
		}
		cu := CLIUser{Name: parts[0], Password: parts[1]}
		if len(parts) == 3 {
			cu.SystemUser = parts[2]
		}
		out.Users = append(out.Users, cu)
	}

	return out, nil
}
