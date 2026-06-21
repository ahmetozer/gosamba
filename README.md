# gosamba

A small, dependency-light SMB file server written in pure Go.

`gosamba` speaks the SMB2/SMB3 protocol directly — no `libsmbclient`, no Samba
runtime — so it ships as a single static binary. It is designed to be easy to
run on Linux for sharing a few directories with macOS, Windows, and iOS clients
over the network.

> **Status:** early/experimental (`0.0.0-dev`). Expect rough edges; review the
> security notes before exposing it to untrusted networks.

## Features

- **SMB2/SMB3 dialects** — negotiates 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1.
- **Authentication** — NTLMv2 over SPNEGO; passwords stored as NT hashes.
- **Encryption & signing** — SMB3 encryption and message signing, required by
  default (configurable to preferred/off).
- **Durable handles** — opens survive a dropped TCP connection and can be
  reclaimed after reconnect.
- **Locking, oplocks/leases, and change-notify** for correct multi-client access.
- **Apple client support** — AAPL create-context extensions and a synthesized
  `AFP_AfpInfo` stream so macOS Finder and the iOS Files app work smoothly.
- **Extended attributes & alternate data streams.**
- **Safe path handling** — symlink-escape and path-traversal protection keep
  access inside the share root.
- **Per-share access control** — read-only and guest shares, with per-user
  share allow-lists.
- **Per-user privilege drop** *(optional)* — serve each connection in a
  re-exec'd worker that drops to the authenticated user's uid/gid (requires
  root).
- **Zero-config discovery** — advertises the service over mDNS/Bonjour so Apple
  clients find it automatically.
- **Flexible config** — command-line flags, a TOML file, or both.

## Build

Requires Go 1.25 or newer.

```sh
make build        # produces ./gosamba
# or
go build -o gosamba ./cmd/gosamba
```

## Quick start

Share a single directory for one user:

```sh
sudo ./gosamba \
  --share /srv/files=public \
  --user alice:s3cret:alice
```

This listens on `:445` (the privileged SMB port, hence `sudo`), serves
`/srv/files` as the share `public`, and authenticates the SMB user `alice`
(mapping to the local system user `alice`).

Connect from another machine:

```sh
smbclient //your-host/public -U alice
```

> **Note:** passing a password on the command line with `-u` exposes it to other
> processes via `/proc/<pid>/cmdline`. For anything beyond a quick test, use a
> config file with a pre-computed `nt_hash` instead (see below).

## Configuration

### Command-line flags

| Flag | Description |
| --- | --- |
| `-s`, `--share <path>[=<name>]` | Share a directory (repeatable). Name defaults to the basename. |
| `-u`, `--user <smb_user>:<password>[:<system_user>]` | Define a user (repeatable). See [user mapping](#user-mapping). |
| `-c`, `--config <file>` | Load a TOML config file. |
| `-l`, `--listen <addr>` | Listen address (default `:445`). |
| `--netbios` | Also bind the legacy NetBIOS port `:139`. |
| `--mdns` | Advertise via mDNS/Bonjour (default on). |
| `--no-encryption` | Allow non-encrypted SMB3 sessions. |
| `--no-signing` | Allow unsigned messages. |
| `--durable-timeout <dur>` | Durable-handle timeout, e.g. `60s`. |
| `--state-dir <path>` | Runtime state directory. |
| `--per-user-privdrop` | Drop to each authenticated user's uid/gid (requires root). |
| `--log-level <level>` | `debug` \| `info` \| `warn` \| `error`. |
| `--log-format <fmt>` | `text` \| `json`. |
| `-V`, `--version` | Print version and exit. |

### User mapping

The optional `system_user` field decides which OS identity a connection runs as,
and whether `gosamba` privilege-drops:

| `-u` form | Runs as | Privilege drop | Reads `/etc/passwd`? |
| --- | --- | --- | --- |
| `smb:pass` | the current process user | no | no |
| `smb:pass:1000` | uid 1000, gid 1000 | yes, if uid differs from current | no |
| `smb:pass:1000/1001` | uid 1000, gid 1001 | yes, if uid differs from current | no |
| `smb:pass:alice` | system user `alice` | yes, if it differs from current | yes |

Privilege drop only happens when the target uid differs from the current one and
the server runs as root (per-connection, via a re-exec'd worker). Use a **numeric**
`system_user` (or omit it) on minimal images such as the `scratch` container,
which has no `/etc/passwd` — a **named** `system_user` requires it.

### TOML config file

For production use, prefer a config file with NT-hashed passwords. The file must
not be group/world-writable (mode `≤ 0640`).

```toml
[server]
listen     = ":445"
encryption = "required"   # required | preferred | off
signing    = "required"   # required | preferred
mdns       = true

[log]
level  = "info"           # debug | info | warn | error
format = "text"           # text | json

[[share]]
name      = "public"
path      = "/srv/files"
read_only = false
guest_ok  = false

[[user]]
name         = "alice"
nt_hash      = "..."      # 32 hex chars (16-byte NT hash)
system_user  = "alice"
allow_shares = ["public"]
```

Run with:

```sh
sudo ./gosamba -c /etc/gosamba.toml
```

Flags and the config file can be combined — explicit flags override file values.

## Architecture

The codebase is split into focused internal packages:

| Package | Responsibility |
| --- | --- |
| `cmd/gosamba` | Entry point, flag/config wiring, server lifecycle. |
| `internal/config` | CLI + TOML parsing, merge, and validation. |
| `internal/transport` | SMB direct-TCP framing. |
| `internal/smb2` / `internal/smb3` | Protocol message codecs and negotiate logic. |
| `internal/parent` | Connection/session handling, dispatch, and per-connection worker model. |
| `internal/ntlm` | NTLMv2 authentication. |
| `internal/userdb` | In-memory user store. |
| `internal/vfs` | Safe filesystem access (path resolution, traversal guards). |
| `internal/discovery` | mDNS/Bonjour advertisement. |
| `internal/inotify` | Filesystem change notifications. |
| `internal/logging` | Structured logging. |

The only external dependencies are the `golang.org/x` extensions
(`crypto`, `sys`, `net`, `text`).

## Development

```sh
make test         # go test ./...
make test-race    # race detector
make vet          # go vet
make fmt          # go fmt
```

Some end-to-end tests drive a real `smbclient` against the server. Install it
with:

```sh
make e2e-deps     # apt-get install smbclient
```

## Security notes

- Encryption and signing are **required by default**; only relax them
  (`--no-encryption` / `--no-signing`) on trusted networks.
- Prefer config-file `nt_hash` entries over plaintext `-u` passwords.
- Binding `:445` requires elevated privileges; consider `--per-user-privdrop`
  (as root) so each connection runs with the authenticated user's permissions.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
