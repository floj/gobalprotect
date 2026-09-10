# gobalprotect

[![Latest release](https://img.shields.io/github/v/release/floj/gobalprotect)](https://github.com/floj/gobalprotect/releases/latest)
[![License](https://img.shields.io/github/license/floj/gobalprotect)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/floj/gobalprotect)](go.mod)

A Linux-native 🐧 GlobalProtect VPN client written in Go - an open-source alternative to the official Palo Alto client. The name is a portmanteau of **Go** and **GlobalProtect**.

Uses a userspace TUN device and the GlobalProtect SSL tunnel protocol (GPST) to establish VPN connections, with built-in split DNS proxy and route management.

## Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration file](#-configuration-file)
- [Authentication](#-authentication)
- [Split DNS](#-split-dns)
- [Stopping and reconnect](#-stopping-and-reconnect)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- **Split tunneling** - respects server-pushed split routes, or route all traffic via `--default-route`
- **Split DNS** - local DNS proxy forwards queries for VPN domains, caches responses, and dynamically injects host routes
- **MFA / OTP** - interactive prompt, `--otp` flag, `--otp-cmd`, or `--totp-secret` (auto-generated codes, enables re-auth on reconnect)
- **SAML** - pass pre-obtained cookies via `--cookie-name` / `--cookie-value`
- **Config profiles** - YAML config file with multiple named profiles
- **Password commands** - fetch credentials from a password manager via `--password-cmd`
- **Statically compiled** - single binary, no CGO dependencies

## 📋 Requirements

- Linux with TUN kernel support (`/dev/net/tun`)
- `root` or the `CAP_NET_ADMIN` capability (to create the TUN device and manage routes)
- `systemd-resolved` >= 247 - only if DNS integration is used (skip with `--no-dns`)
- Prebuilt static binaries ship for `amd64` and `arm64`

## ⚡ Quick Start

Download the latest release into `~/.local/bin`, verify checksums, and connect:

```bash
mkdir -p ~/.local/bin
VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/floj/gobalprotect/releases/latest | sed 's#.*/##')
ARCH=$(uname -m); [ "$ARCH" = "aarch64" ] && ARCH=arm64
ARCHIVE="gobalprotect_${VERSION#v}_linux_${ARCH}.tar.gz"
BASE="https://github.com/floj/gobalprotect/releases/download/${VERSION}"

curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/checksums.txt"
sha256sum -c --ignore-missing checksums.txt

tar -xzf "$ARCHIVE" -C ~/.local/bin gobalprotect

sudo ~/.local/bin/gobalprotect connect -s vpn.example.com
```

## 📦 Installation

### Download a release

Prebuilt static binaries for Linux (`amd64`, `arm64`) are attached to each [GitHub release](https://github.com/floj/gobalprotect/releases).

```bash
# Pin to a specific release tag for reproducibility, or resolve `latest` as
# shown in Quick Start.
VERSION=v0.1.0
ARCH=$(uname -m); [ "$ARCH" = "aarch64" ] && ARCH=arm64
ARCHIVE="gobalprotect_${VERSION#v}_linux_${ARCH}.tar.gz"
BASE="https://github.com/floj/gobalprotect/releases/download/${VERSION}"

curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/checksums.txt"
sha256sum -c --ignore-missing checksums.txt

tar -xzf "$ARCHIVE" -C ~/.local/bin gobalprotect
```

Optionally install system-wide:

```bash
sudo install -m 0755 ~/.local/bin/gobalprotect /usr/local/bin/
```

### Build from source

Requires Go 1.26+ and Linux.

```bash
./build.sh
```

The resulting `gobalprotect` binary is placed in the project root.

## 🚀 Usage

See [Requirements](#-requirements) - you need root / `CAP_NET_ADMIN` and (for DNS) `systemd-resolved`.

### Examples

Connect to a gateway interactively (you'll be prompted for credentials):

```bash
sudo gobalprotect connect -s vpn.example.com
```

Or provide everything up front:

```bash
sudo -E gobalprotect connect -s vpn.example.com -u jdoe --password "$(pass show vpn/work)"
```

> **Note:** use `sudo -E` (or `sudo --preserve-env`) whenever you rely on `GP_*` environment variables - plain `sudo` sanitizes them out and gobalprotect will fall back to interactive prompts.

### Connect

```
gobalprotect connect [flags]
```

| Flag               | Alias | Env Var             | Description                                       |
| ------------------ | ----- | ------------------- | ------------------------------------------------- |
| `--config`         | `-c`  | `GP_CONFIG`         | Path to YAML config file                          |
| `--profile`        | `-p`  | `GP_PROFILE`        | Profile name from config                          |
| `--server`         | `-s`  | `GP_SERVER`         | Gateway address                                   |
| `--username`       | `-u`  | `GP_USER`           | Username                                          |
| `--password`       |       | `GP_PASSWD`         | Password                                          |
| `--password-cmd`   |       | `GP_PASSWD_CMD`     | Command to retrieve password (10s timeout)        |
| `--otp`            | `-o`  | `GP_OTP`            | OTP code                                          |
| `--otp-cmd`        |       | `GP_OTP_CMD`        | Command to retrieve OTP (10s timeout)             |
| `--totp-secret`    |       | `GP_TOTP_SECRET`    | Base32 TOTP secret; codes are generated on demand |
| `--cookie-name`    |       | `GP_COOKIE_NAME`    | SAML cookie field name                            |
| `--cookie-value`   |       | `GP_COOKIE_VALUE`   | SAML cookie value                                 |
| `--tun`            | `-t`  | `GP_TUN`            | TUN device name                                   |
| `--default-route`  |       | `GP_DEFAULT_ROUTE`  | Route all traffic through VPN                     |
| `--no-routes`      |       | `GP_NO_ROUTES`      | Skip server-pushed split routes                   |
| `--no-dns`         |       | `GP_NO_DNS`         | Skip DNS configuration                            |
| `--no-serve-dns`   |       | `GP_NO_SERVE_DNS`   | Don't start local DNS proxy                       |
| `--serve-dns-port` |       | `GP_SERVE_DNS_PORT` | DNS proxy port (default: 1553)                    |
| `--dns-cache-size` |       | `GP_DNS_CACHE_SIZE` | DNS cache entries (default: 512, 0 to disable)    |
| `--computer`       |       | `GP_COMPUTER`       | Computer name to report (default: hostname)       |
| `--insecure`       | `-k`  | `GP_INSECURE`       | Skip TLS certificate verification                 |
| `--verbose`        | `-v`  | `GP_VERBOSE`        | Debug logging                                     |
| `--log-json`       |       | `GP_LOG_JSON`       | JSON log format                                   |

All flags can also be set via environment variables.

If no credentials are provided, you'll be prompted interactively.

There is **no default config file path** - `--config` (or `GP_CONFIG`) must always be provided explicitly.

### Version

```bash
gobalprotect version
gobalprotect version --json
```

## ⚙️ Configuration File

Instead of passing flags every time, create a YAML config file with one or more profiles:

```yaml
default_profile: work

profiles:
  - name: work
    server: vpn.example.com
    username: jdoe
    password_cmd: "pass show vpn/work"
    otp_cmd: "totp vpn-work"
    tun: gpd0

  - name: lab
    server: lab-vpn.example.com
    username: jdoe
    password_cmd: "pass show vpn/lab"
    insecure: true
```

Then connect with:

```bash
gobalprotect connect -c config.yaml
# or select a specific profile:
gobalprotect connect -c config.yaml -p lab
```

Profile selection priority: `--profile` flag -> `default_profile` field -> automatic (if only one profile exists).

### Profile fields

All fields are optional except `name` and `server`:

| Field              | Description                                                             |
| ------------------ | ----------------------------------------------------------------------- |
| `name`             | Profile name (required)                                                 |
| `server`           | Gateway address (required)                                              |
| `username`         | Username                                                                |
| `password_cmd`     | Shell command to retrieve password (10s timeout)                        |
| `otp_cmd`          | Shell command to retrieve OTP (10s timeout)                             |
| `totp_secret`      | Base32 TOTP secret; codes are generated on demand                       |
| `cookie_name`      | SAML cookie field name. The value itself is CLI-/env-only (`--cookie-value` / `GP_COOKIE_VALUE`) and is intentionally never stored in the config file |
| `insecure`         | Skip TLS verification                                                   |
| `tun`              | TUN device name                                                         |
| `as_default_route` | Route all traffic through VPN                                           |
| `no_routes`        | Skip server-pushed split routes                                         |
| `no_dns`           | Skip DNS configuration                                                  |
| `no_serve_dns`     | Don't start local DNS proxy                                             |
| `serve_dns_port`   | DNS proxy port (default: 1553)                                          |
| `dns_cache_size`   | DNS cache entries (default: 512)                                        |
| `computer`         | Computer name to report (default: hostname)                             |
| `verbose`          | Debug logging                                                           |
| `log_json`         | JSON log format                                                         |

## 🔐 Authentication

**Password auth** - provide via `--password`, `--password-cmd`, env var, config file, or interactive prompt.

**MFA/OTP** - if the server requires a second factor, gobalprotect will prompt interactively, or you can provide it via `--otp` / `--otp-cmd` or `--totp-secret`:

```bash
gobalprotect connect -s vpn.example.com -u jdoe \
  --password "$(pass show vpn/work)" \
  --otp "$(totp vpn-work)"
```

Alternatively, pass the raw base32 TOTP secret with `--totp-secret` (or `GP_TOTP_SECRET`, or `totp_secret` in a config profile). The client then generates fresh codes as the gateway requests them. When **both** `--password` / `--password-cmd` and `--totp-secret` are set, gobalprotect can also **automatically re-authenticate** if the gateway rejects the auth cookie during a reconnect (e.g. after the session lifetime expires), instead of exiting.

```bash
gobalprotect connect -s vpn.example.com -u jdoe \
  --password "$(pass show vpn/work)" \
  --totp-secret "JBSWY3DPEHPK3PXP"
```

**SAML** - obtain the SAML cookie externally and pass it in:

```bash
gobalprotect connect -s vpn.example.com \
  --cookie-name prelogin-cookie \
  --cookie-value "<cookie-value>"
```

## 🌐 Split DNS

By default, gobalprotect starts a local DNS proxy that:

1. Listens on UDP port 1553
2. Forwards DNS queries for the *split-tunneling domains* pushed by the gateway (the `include-split-tunneling-domain` list) to the VPN's DNS servers
3. Caches responses (LRU with TTL-based expiry)
4. Dynamically injects host routes for resolved IPs through the VPN tunnel

DNS integration with `systemd-resolved` is configured automatically via D-Bus using routing domains. Per-server DNS ports require systemd-resolved >= 247.

Disable the local proxy with `--no-serve-dns`, or tune the cache with `--dns-cache-size` (0 disables caching).

## 🛑 Stopping and reconnect

**Graceful shutdown.** Press `Ctrl+C` or send `SIGTERM`. gobalprotect will cleanly tear down the tunnel, remove routes, revert DNS configuration, and log out from the gateway.

**Force quit.** Press `Ctrl+C` a second time (or send another `SIGINT`/`SIGTERM`) to skip cleanup and exit immediately with code `130`. Use this only if graceful shutdown hangs - leftover state may need manual cleanup (`ip link del <tun>`, `resolvectl revert <tun>`).

**Reconnect.** When the tunnel dies mid-session, gobalprotect automatically reconnects with exponential backoff (1s -> 2s -> 4s … capped at 30s). If the gateway rejects the auth cookie (e.g. session lifetime expired) and both `--password` / `--password-cmd` **and** `--totp-secret` are set, it re-authenticates from scratch; otherwise it exits. Failures on the *very first* connection attempt are not retried - they usually indicate a config or permission problem.

## 🩺 Troubleshooting

**`operation not permitted` when creating the TUN device.** You need `root` or `CAP_NET_ADMIN`. Either run under `sudo`, or grant the capability once: `sudo setcap cap_net_admin+ep /path/to/gobalprotect`.

**`SetLinkDNSEx via D-Bus failed` / DNS not configured.** DNS integration requires `systemd-resolved` >= 247 (for per-server DNS port support). Verify with `resolvectl --version`. If systemd-resolved is unavailable, skip DNS configuration with `--no-dns` and manage `/etc/resolv.conf` yourself.

**TLS certificate errors.** Corporate gateways sometimes present certs signed by an internal CA. Install the CA into the system trust store, or bypass verification with `--insecure` (understand the trade-off).

**Stuck on OTP prompt after reconnect.** Static `--otp` values are single-use. For automated reconnects, use `--totp-secret` so codes are generated on demand.

**Environment variables ignored under `sudo`.** Plain `sudo` sanitizes the environment. Use `sudo -E` (or `sudo --preserve-env=GP_SERVER,GP_USER,...`) to pass `GP_*` variables through.

**Split routes not applied.** Check the log output at startup - the gateway must push access routes in `access-routes`. Use `--verbose` to see the parsed VPN config. `--default-route` overrides split routing entirely.

## 🤝 Contributing

Bug reports and pull requests are welcome at <https://github.com/floj/gobalprotect/issues>. Please include the `--verbose` log output (redacted) when filing connection-related issues.

## 📄 License

[MIT](LICENSE)
