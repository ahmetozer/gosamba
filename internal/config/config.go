package config

import "time"

// Config is the fully merged, validated runtime configuration.
// All fields are populated; no nil pointers, no zero-value-as-unset.
type Config struct {
	Server ServerConfig
	Log    LogConfig
	Shares []ShareConfig
	Users  []UserConfig
}

type ServerConfig struct {
	Listen         string
	Netbios        bool
	MDNS           bool
	Encryption     EncryptionMode
	Signing        SigningMode
	DurableTimeout time.Duration
	StateDir       string

	// PerUserPrivdrop enables the per-connection re-exec worker model: when set
	// (and the process is root), each accepted connection is served by a child
	// process that drops to the authenticated user's uid/gid. Default false —
	// connections are served in-process exactly as before.
	PerUserPrivdrop bool
}

type EncryptionMode string

const (
	EncryptionRequired  EncryptionMode = "required"
	EncryptionPreferred EncryptionMode = "preferred"
	EncryptionOff       EncryptionMode = "off"
)

type SigningMode string

const (
	SigningRequired  SigningMode = "required"
	SigningPreferred SigningMode = "preferred"
)

type LogConfig struct {
	Level  string
	Format string
}

type ShareConfig struct {
	Name     string
	Path     string
	ReadOnly bool
	GuestOK  bool
}

type UserConfig struct {
	Name        string
	NTHash      [16]byte
	SystemUser  string
	SystemUID   int
	SystemGID   int
	AllowShares []string
}

func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Listen:         ":445",
			Netbios:        false,
			MDNS:           true,
			Encryption:     EncryptionRequired,
			Signing:        SigningRequired,
			DurableTimeout: 60 * time.Second,
			StateDir:       "/var/run/gosamba",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
	}
}
