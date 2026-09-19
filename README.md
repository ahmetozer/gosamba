# gosamba

A small, dependency-light SMB file server written in pure Go.

`gosamba` speaks the SMB2/SMB3 protocol directly, so it ships as a single static
binary. It is designed to be easy to run on Linux for sharing a few directories
with macOS, Windows, and iOS clients over the network.

It also builds and runs natively on macOS (`darwin/amd64`, `darwin/arm64`).
Windows is not supported as a host platform. On macOS, binding `:445`
requires that the built-in SMB service (File Sharing / `smbd`) isn't already
holding the port — disable macOS File Sharing or run `gosamba` on an
alternate port with `-l`.

On macOS the change-notify watcher needs one file descriptor per watched
directory (and per file it watches for in-place edits), so the number of
watches is capped process-wide — roughly an eighth of `RLIMIT_NOFILE`,
clamped to 32–512. Past that cap, creates, deletes and renames are still
reported; only in-place modifications of the extra files are missed, and a
client recovers by re-enumerating the directory. Raise `ulimit -n` if you
watch very large trees and want the cap to scale with it.

## Features

- **SMB2/SMB3 dialects** — negotiates 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1.
- **Authentication** — NTLMv2 over SPNEGO; passwords stored as NT hashes.
- **Encryption & signing** — SMB3 encryption and message signing, required by
  default (configurable to preferred/off).
- **Durable handles** — opens survive a dropped TCP connection and can be
  reclaimed after reconnect.
- **Byte-range locking and change-notify** for correct multi-client access.
  Time Machine shares can grant read leases with R → NONE break notifications.
  Write, handle and directory caching leases are not granted.
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

## Time Machine

Add a dedicated writable backup share to the TOML configuration:

```toml
[[share]]
name = "Backups"
path = "/srv/backups"
time_machine = true
```

For multiple shares, repeat the literal `[[share]]` header and give each a
different `name`. Do not use a share name as a table header such as
`[[TimeMachineLaptop]]`. `allow_shares` refers to the `name` values.

With mDNS enabled (the default), gosamba advertises `_smb._tcp` and
`_adisk._tcp`. Only shares marked `time_machine = true` appear in the `dkN`
TXT entries. Share names containing commas or equals signs, or exceeding the
DNS TXT limit, are rejected. In macOS, select the share in System Settings →
General → Time Machine → Add Backup Disk and authenticate with a configured
SMB user. That user's `allow_shares` must include this share.

FLUSH and WRITE_THROUGH report storage errors, including failed stream/xattr
writes. Linux uses `fsync`; macOS uses `F_FULLFSYNC`. The backing filesystem
must support user extended attributes for Apple metadata streams.

Read leases are enabled only for these dedicated backup shares. They require
all access to the backup files to go through this gosamba process: do not modify
them locally or export the same directory through another server. This server
has no kernel lease mechanism for external writers. A lease is granted only
when the inode has no opens from another lease; other CREATE requests
conservatively break cached reads before opening or overwriting files. This
also protects hard-link aliases, at the cost of more cache invalidations than
a full per-file lease manager. Durable reconnect retains lease state; a
read lease broken while its client was disconnected forces a fresh open.

Time Machine requires a positive `durable_timeout` and in-process serving.
Configurations that select per-user worker processes are rejected for these
shares because workers cannot coordinate leases or durable reconnects. mDNS
currently uses IPv4 multicast, so clients need access to the same multicast
network (or a Bonjour gateway).

After deployment, verify a complete backup, an incremental backup after
reconnecting, and restoration of files on an actual Mac. Protocol tests do not
replace this end-to-end Time Machine check.

### Time Machine with Docker Compose

The repository includes [docker-compose.yml](docker-compose.yml) and a
[configuration template](examples/time-machine/gosamba.toml.example) for a
regular, rootful Docker Engine on Linux. The image is built from this checkout,
so it includes the Time Machine implementation above.

Use Docker Compose 2.27.1 or newer. Build steps also use the host network through
[`build.network` and `build.entitlements`](https://docs.docker.com/reference/compose-file/build/),
so downloading Go modules does not depend on the Docker bridge's DNS/NAT setup.
The service's `network_mode` alone would not configure the build network.
With a custom BuildKit builder, that builder must allow `network.host` as well.

The service uses [host networking](https://docs.docker.com/engine/network/drivers/host/)
for LAN Bonjour multicast and SMB. TCP port 445 must be available on the host;
allow TCP 445 and mDNS UDP 5353 on the trusted LAN in the host firewall.
The Mac must be able to reach IPv4 multicast on that LAN. No `ports:` mapping
is needed with host networking.

Run these commands from the repository root:

```sh
docker compose build
install -m 600 examples/time-machine/gosamba.toml.example gosamba.toml
sudo install -d -m 700 -o root -g root /srv/timemachine
```

If `go mod download` fails with `lookup proxy.golang.org: i/o timeout`, check
DNS and HTTPS access on the Linux host:

```sh
getent ahosts proxy.golang.org
curl -I --connect-timeout 10 https://proxy.golang.org/
```

If these fail too, fix the host's DNS/network access first; using host networking
cannot bypass an outage on the host itself. Then retry `docker compose build`.

Generate the password hash without putting the password in shell history
(the following commands use Bash):

```bash
read -r -s -p 'SMB password: ' tm_password
printf '\n'
printf '%s\n' "$tm_password" | docker run --rm -i --network none gosamba:time-machine hash
unset tm_password
```

Replace `REPLACE_WITH_YOUR_NT_HASH` in `gosamba.toml` with the printed hash.
The placeholder deliberately prevents startup until a password is configured.
Keep the config private and start the service. It can remain owned by the host
user who created it:

```sh
sudo chmod 600 gosamba.toml
docker compose config --quiet
docker compose up -d
docker compose logs -f timemachine
```

The container runs as UID/GID `0:0` with `NET_BIND_SERVICE` and `DAC_OVERRIDE`,
a read-only root filesystem and a writable backup mount. `DAC_OVERRIDE` lets
the process read a host-user-owned `0600` config despite `cap_drop: ALL`;
the config mount remains read-only. These capabilities are described in the
[Docker runtime reference](https://docs.docker.com/engine/containers/run/).
Files in `/srv/timemachine` are owned by root. Do not add `system_user` or enable `per_user_privdrop`: Time
Machine needs one server process for lease coordination and durable reconnects.
The local `gosamba.toml` is excluded from Git and the Docker build context.

The application accepts a private config such as `0600` or `0640`; `0644`
and `0664` are rejected because other users can read the NT password hash.
If you used an earlier version of this Compose example, recreate the container
after updating capabilities (a restart alone does not apply them):

```sh
sudo chmod 600 gosamba.toml
docker compose up -d --force-recreate timemachine
```

If reading still fails, check the actual host mode and numeric ownership with
`stat -Lc 'mode=%a uid=%u gid=%g %n' gosamba.toml` and confirm the config bind
source with `docker compose config`. This example assumes rootful Docker without
user-namespace remapping. `DAC_OVERRIDE` does not bypass SELinux or permissions
enforced by a remote filesystem such as NFS with root squashing.

Optional settings can be placed in a `.env` file alongside `docker-compose.yml`:

```dotenv
TIME_MACHINE_HOSTNAME=backup-nas
TIME_MACHINE_PATH=/mnt/backups/timemachine
```

Create the selected directory beforehand with the same ownership and permissions
as above, on a filesystem with extended-attribute support. The container path
in `gosamba.toml` stays `/srv/backups`. Use a unique hostname on your LAN.
The bind mounts require existing paths; a missing backup directory or config will
not silently become an empty Docker-created directory.

On the Mac, select **Backups** in Time Machine and log in as **timemachine**
with the password used to generate the hash. To check SMB access manually,
connect to `smb://backup-nas.local/Backups` (or the Linux server's LAN IP;
the default hostname is `gosamba-timemachine`). Backup data remains on the host
when the container is recreated. A container restart drops in-memory durable
handles, so the Mac reconnects with fresh file opens.

For multiple Macs, use the
[multi-share template](examples/time-machine/gosamba.multi.toml.example).
It defines `TimeMachineLaptop` and `TimeMachineDesktop`, with a separate SMB
account for each: `tm_laptop` and `tm_desktop`. Each account can access only its
own share. Adapt the names and replace both NT hash placeholders before use.
Both directories are inside the existing `/srv/backups` container mount,
so no additional Compose volumes are needed. For the default host path, create
them with:

```sh
sudo install -d -m 700 -o root -g root \
  /srv/timemachine/laptop /srv/timemachine/desktop
```

If you changed `TIME_MACHINE_PATH`, create these subdirectories there instead.
After updating `gosamba.toml`, recreate the container with
`docker compose up -d --force-recreate timemachine`. The startup log should show
`shares=2 users=2`. Paths in the TOML file are container paths, not host paths.

## Build

Requires Go 1.25 or newer.

```sh
make build        # produces ./gosamba
# or
go build -o gosamba ./cmd/gosamba
```

## Quick start

Share a single directory for one user — no system account required:

```sh
sudo mkdir -p /srv/files
sudo ./gosamba \
  --share /srv/files=public \
  --user alice:s3cret
```

This listens on `:445` (the privileged SMB port, hence `sudo`), serves
`/srv/files` as the share `public`, and authenticates the SMB user `alice` with
password `s3cret`. Because no `system_user` was given, file operations run as the
user that launched the server (here `root`). To drop to a specific account or
uid instead, add a third field — see [user mapping](#user-mapping).

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
| `--netbios` | **Not implemented** — rejected at startup. Nothing binds `:139`; SMB2/3 uses `:445` only. |
| `--mdns` | Advertise via mDNS/Bonjour (default on). |
| `--no-encryption` | Allow non-encrypted SMB3 sessions. |
| `--no-signing` | Allow unsigned messages. |
| `--durable-timeout <dur>` | Durable-handle timeout, e.g. `60s`. |
| `--state-dir <path>` | Reserved — parsed and stored, but nothing reads it yet. |
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
nt_hash      = "d4c619cb16d4632b275658316a7e657e"  # 32 hex chars (16-byte NT hash)
system_user  = "alice"    # optional: name, uid (e.g. "1000"), or uid/gid ("1000/1001")
allow_shares = ["public"]
```

Generate an `nt_hash` from a password with the built-in `hash` subcommand:

```sh
gosamba hash                          # prompts for the password
printf '%s' 's3cret' | gosamba hash   # or read it from stdin
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
make test-e2e     # smbclient-driven end-to-end tests (needs `make e2e-deps`)
make vet          # go vet
make fmt          # go fmt
```

Some end-to-end tests drive a real `smbclient` against the server. They sit
behind the `smbclient_e2e` build tag, so a plain `make test` skips them —
use `make test-e2e` (CI runs it on Linux). Install `smbclient` with:

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
