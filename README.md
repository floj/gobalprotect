# gobalprotect

A Linux-native 🐧 GlobalProtect VPN client written in Go — an open-source alternative to the official Palo Alto client.

Uses a userspace TUN device and the GlobalProtect SSL tunnel protocol (GPST) to establish VPN connections, with built-in split DNS proxy and route management.

## ✨ Features

- **Split tunneling** — respects server-pushed split routes, or route all traffic via `--default-route`
- **Split DNS** — local DNS proxy forwards queries for VPN domains, caches responses, and dynamically injects host routes
- **MFA / OTP** — interactive prompt, `--otp` flag, or `--otp-cmd` for automation
- **SAML** — pass pre-obtained cookies via `--cookie-name` / `--cookie-value`
- **Config profiles** — YAML config file with multiple named profiles
- **Password commands** — fetch credentials from a password manager via `--password-cmd`
- **Statically compiled** — single binary, no CGO dependencies

## 📦 Installation

### Build from source

Requires Go 1.24+ and Linux.

```bash
./build.sh
```

This compiles the binary.

The resulting `gobalprotect` binary is placed in the project root.

## 🚀 Quick Start

Connect to a gateway interactively (you'll be prompted for credentials):

```bash
sudo gobalprotect connect -s vpn.example.com
```

Or provide everything up front:

```bash
sudo  gobalprotect connect -s vpn.example.com -u jdoe --password "$(pass show vpn/work)"
```

## Usage

### Connect

```
gobalprotect connect [flags]
```

| Flag | Alias | Env Var | Description |
|---|---|---|---|
| `--config` | `-c` | `GP_CONFIG` | Path to YAML config file |
| `--profile` | `-p` | `GP_PROFILE` | Profile name from config |
| `--server` | `-s` | `GP_SERVER` | Gateway address |
| `--username` | `-u` | `GP_USER` | Username |
| `--password` | | `GP_PASSWD` | Password |
| `--password-cmd` | | `GP_PASSWD_CMD` | Command to retrieve password (10s timeout) |
| `--otp` | `-o` | `GP_OTP` | OTP code |
| `--otp-cmd` | | `GP_OTP_CMD` | Command to retrieve OTP |
| `--cookie-name` | | `GP_COOKIE_NAME` | SAML cookie field name |
| `--cookie-value` | | `GP_COOKIE_VALUE` | SAML cookie value |
| `--tun` | `-t` | `GP_TUN` | TUN device name |
| `--default-route` | | `GP_DEFAULT_ROUTE` | Route all traffic through VPN |
| `--no-routes` | | `GP_NO_ROUTES` | Skip server-pushed split routes |
| `--no-dns` | | `GP_NO_DNS` | Skip DNS configuration |
| `--no-serve-dns` | | `GP_NO_SERVE_DNS` | Don't start local DNS proxy |
| `--serve-dns-port` | | `GP_SERVE_DNS_PORT` | DNS proxy port (default: 1553) |
| `--dns-cache-size` | | `GP_DNS_CACHE_SIZE` | DNS cache entries (default: 512, 0 to disable) |
| `--computer` | | `GP_COMPUTER` | Computer name to report |
| `--insecure` | `-k` | `GP_INSECURE` | Skip TLS certificate verification |
| `--verbose` | `-v` | `GP_VERBOSE` | Debug logging |
| `--log-json` | | `GP_LOG_JSON` | JSON log format |

All flags can also be set via environment variables.

If no credentials are provided, you'll be prompted interactively.

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
    dns_cache_size: 256

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

Profile selection priority: `--profile` flag → `default_profile` field → automatic (if only one profile exists).

### Profile fields

All fields are optional except `name` and `server`:

| Field | Description |
|---|---|
| `name` | Profile name (required) |
| `server` | Gateway address (required) |
| `username` | Username |
| `password_cmd` | Shell command to retrieve password |
| `otp_cmd` | Shell command to retrieve OTP |
| `cookie_name` / `cookie_value` | SAML cookie credentials |
| `insecure` | Skip TLS verification |
| `tun` | TUN device name |
| `as_default_route` | Route all traffic through VPN |
| `no_routes` | Skip server-pushed split routes |
| `no_dns` | Skip DNS configuration |
| `no_serve_dns` | Don't start local DNS proxy |
| `serve_dns_port` | DNS proxy port (default: 1553) |
| `dns_cache_size` | DNS cache entries (default: 512) |
| `computer` | Computer name to report |
| `verbose` | Debug logging |
| `log_json` | JSON log format |

## 🔐 Authentication

**Password auth** — provide via `--password`, `--password-cmd`, env var, config file, or interactive prompt.

**MFA/OTP** — if the server requires a second factor, gobalprotect will prompt interactively, or you can provide it via `--otp` / `--otp-cmd`:

```bash
gobalprotect connect -s vpn.example.com -u jdoe \
  --password-cmd "pass show vpn/work" \
  --otp-cmd "totp vpn-work"
```

**SAML** — obtain the SAML cookie externally and pass it in:

```bash
gobalprotect connect -s vpn.example.com \
  --cookie-name prelogin-cookie \
  --cookie-value "<cookie-value>"
```

## 🌐 Split DNS

By default, gobalprotect starts a local DNS proxy that:

1. Listens on UDP port 1553
2. Forwards DNS queries for VPN domains to the VPN's DNS servers
3. Caches responses (LRU with TTL-based expiry)
4. Dynamically injects host routes for resolved IPs through the VPN tunnel

DNS integration with `systemd-resolved` is configured automatically using routing domains.

Disable with `--no-serve-dns` or tune the cache with `--dns-cache-size`.

## Stopping

Press `Ctrl+C` or send `SIGTERM`. gobalprotect will cleanly tear down the tunnel, remove routes, revert DNS configuration, and log out from the gateway.

## 📄 License

[MIT](LICENSE)
