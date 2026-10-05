# tailsacle-cli

Safe TypeScript CLI for real Tailscale deployment workflows. Official binaries are `tailsacle-cli` and `tscli`.

## What it does

`tailsacle-cli` now provides a production-oriented local deployment path:

- resolves configuration and credentials without logging raw secrets;
- discovers the installed Tailscale binary and can explicitly update it;
- creates a Tailscale auth key through the API when `TS_AUTH_KEY` is not supplied;
- joins/configures the current machine with `tailscale up` and verifies `BackendState=Running`;
- auto-provisions the tailnet so a tagged deployment can connect: adds missing `tagOwners`, adds the `funnel` node attribute and enables tailnet HTTPS certificates when `--yes` is passed, each change is warned, validated, backed up and ETag-protected;
- configures private Serve or public Funnel exposures;
- reads tailnet DNS settings;
- performs guarded HuJSON policy validation/diff/write with backup, ETag and confirmation;
- finds and removes only exact matching offline devices after a confirmation gate;
- exposes stable JSON envelopes for automation and an agent manifest.

Policy and cleanup writes are intentionally guarded. Missing permissions and API failures are reported as failures; the CLI never claims a remote side effect it did not verify.

## Requirements

- Node.js 22 or newer
- Tailscale installed and available on `PATH` for `up`, `status`, Serve and Funnel
- For API-driven auth-key/policy/DNS/cleanup operations, one of:
  - `TS_API_KEY`
  - `TS_ACCESS_TOKEN`
  - `TS_OAUTH_CLIENT_ID` + `TS_OAUTH_CLIENT_SECRET`
- Or `TS_AUTH_KEY` for a pre-created node auth key

## Install and run

```bash
npm install
npm run build
node dist/cli.js doctor --detect-credentials --json
node dist/cli.js status --json
```

The published package exposes `tailsacle-cli`, `tscli` and `tailscale-cli-opencode`.

## OpenCode funnel flow (`tailscale-cli-opencode`)

One command turns a machine into a public opencode endpoint: resolve/install
opencode, grant it full permissions, serve it, join the tailnet and publish it
through a Tailscale Funnel, then verify the live endpoint before printing the
public URL.

```bash
export TS_AUTH_KEY='tskey-auth-...'        # or OAuth trust credential / TS_API_KEY
npx tailscale-cli-opencode --yes --apply-policy --enable-https --json
# -> OPencode URL: https://<hostname>.<tailnet>.ts.net/
```

- If `opencode` is not on `PATH`, it is resolved through `npx -y opencode-ai`
  (`--install` forces this even when a binary exists).
- Full permissions: writes `opencode.json` with `"permission": "allow"` — the
  headless equivalent of `opencode --auto` (`serve` has no `--auto` flag);
  nothing is blocked. Override the file with `--opencode-config <path>`.
- `opencode serve` runs detached on `--port <number>` (default 3000) and is
  tracked in the cache pidfile (`daemon stop`-style); its log is
  `cache/opencode-serve.log`.
- The Funnel exposure maps the public port 443 to the local serve port
  (auto-provisions `tagOwners`, the funnel node attribute and tailnet HTTPS
  behind `--apply-policy` / `--enable-https`), then verifies public DNS + a
  live TLS handshake (`--no-verify` skips this).
- `--stop` tears down the tracked opencode serve and the userspace tailscaled.


## PostgreSQL TCP Relays & NexQL MCP (`relay-mcp-postgres`)

Relay one or more PostgreSQL databases across machines/Tailnets and simultaneously serve a [nexql-mcp](https://www.npmjs.com/package/nexql-mcp) HTTP MCP server so AI agents (Cursor, Claude Desktop, Antigravity, OpenCode) can explore live schema and query any relayed database:

```bash
# Multi-DB relay from config file + MCP on :8787 accessible via Tailnet
tailsacle-cli relay-mcp-postgres \
  --file examples/relay-mcp-postgres/multi-db.jsonc \
  --mcp-port 8787 \
  --mcp-bind 0.0.0.0 \
  --token "$MCP_TOKEN" \
  --allow-partial \
  --primary-fallback
```

See **[`docs/relay-mcp-postgres.md`](./docs/relay-mcp-postgres.md)** for the complete guide, flag reference, and client connection setups; see **[`examples/relay-mcp-postgres/`](./examples/relay-mcp-postgres/)** for ready-to-use sample configs and service scripts.

## Examples

- `examples/relay-mcp-postgres/` — Complete configuration examples for 1 DB, multi-DB, systemd/Windows services, and AI Agent MCP client setup.
- `examples/colab/opencode-funnel-colab.sh` — one-cell Google Colab script:
  installs Node.js 22+ and `tailsacle-cli`, then delegates everything to a
  single `tailscale-cli-opencode --install --yes --apply-policy --enable-https`
  run (resolve opencode, grant full permissions, serve, join the tailnet,
  publish the Funnel, verify DNS + TLS) and prints the public Funnel URL.

## GitHub Packages mirror (fast CI installs)

Every tag release is also published to GitHub Packages as
`@ongtrieuphuchieu689-7u/tailsacle-cli`. Installing it with a repo scoped token inside
GitHub Actions avoids the npmjs round-trip and is noticeably faster:

```yaml
- uses: actions/setup-node@v7
  with:
    node-version: 24
    registry-url: https://npm.pkg.github.com
- run: npm i -D @ongtrieuphuchieu689-7u/tailsacle-cli
  env:
    NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

For private packages, keep an `.npmrc` with `@ongtrieuphuchieu689-7u:registry=https://npm.pkg.github.com`
and token auth. `tailsacle-cli` on npmjs remains the canonical package; the scoped copy is
a fast mirror for CI only. GitHub Packages requires the token with `packages: read` scope.

## Common deployment

```bash
export TS_TAILNET='example.com'
export TS_HOSTNAME='web-01'
export TS_TAGS='prod,web'
export TS_API_KEY='...'

npx tailsacle-cli doctor --detect-credentials --json
npx tailsacle-cli deploy --json
```

For a pre-created auth key:

```bash
export TS_AUTH_KEY='tskey-auth-...'
npx tailsacle-cli up --json
```

Dry-run first when changing deployment intent:

```bash
npx tailsacle-cli deploy --dry-run --expose 3000 --json
```

## Serve, Funnel & TCP Relay

```bash
npx tailsacle-cli serve 3000 --https 443 --path api --json
npx tailsacle-cli funnel 3000 --https 443 --path api --yes --json
```

### TCP Forwarding / Relay (Postgres / MySQL / Raw TCP)

**Phương án 1 — Tailscale Native Serve/Funnel Proxy:**
Forward port từ máy này sang máy khác qua tailnet:
```bash
# Expose port 5432 trên máy hiện tại forward thẳng tới IP Tailscale của máy DB target:
npx tailsacle-cli serve --tcp 5432 tcp://100.x.y.z:5432
```

**Phương án 2 — Node.js TCP Relay (Trạm trung chuyển đơn cổng, đa cổng & config file):**
Chạy trạm trung chuyển chuyển tiếp TCP traffic sang máy khác (có thể mở rộng kèm `--serve` hoặc `--funnel`):
```bash
# 1. Đơn cổng: Relay local port 5432 -> target machine 192.168.50.79:5433
npx tailsacle-cli relay --listen 5432 --target 192.168.50.79:5433

# 2. Đa cổng (Multi-port) trong 1 tiến trình:
npx tailsacle-cli relay --target-host 192.168.50.79 --map 5432:5432 --map 5433:5433 --map 5434:5434 --serve

# 3. Chạy qua file cấu hình JSON/JSONC (phù hợp chạy Service/Daemon):
npx tailsacle-cli relay --file ./relays.json
```

Ví dụ file `relays.json`:
```json
[
  { "listen": 5432, "target": "192.168.50.79:5432", "serve": true },
  { "listen": 5433, "target": "192.168.50.79:5433", "serve": true },
  { "listen": 10000, "target": "192.168.50.79:5433", "funnel": true }
]
```

Funnel ports are validated before execution; supported public HTTPS ports are 443, 8443 and 10000.

**Phương án 3 — Relay + PostgreSQL MCP (nexql-mcp HTTP):**
Chạy relay tới PostgreSQL và đồng thời mở MCP HTTP endpoint để agent truy cập **toàn bộ database** trên instance (chọn database runtime qua `setup_connection`, không cần 1 config MCP cho từng DB):
```bash
# Relay local :15433 -> Postgres 192.168.50.79:5433, MCP HTTP trên :8787
PGPASSWORD=*** npx tailsacle-cli relay-mcp-postgres \
  --map 15433:192.168.50.79:5433 --map 15434:192.168.50.79:5434 \
  --mcp-port 8787 --mcp-bind 0.0.0.0 --token "$MCP_TOKEN" --database postgres
```
Bảo mật: password DB chỉ đi qua `--password`/`PGPASSWORD`/`TS_PGPASSWORD` vào env `PGPASSWORD` của child; token MCP đi qua `NEXQL_MCP_HTTP_TOKEN` hoặc `--token`; output và pidfile luôn mask. **Luôn chạy**: MCP server không thoát khi máy Postgres chưa bật — supervisor respawn mỗi `--db-retry-interval` ms (mặc định 5000) cho tới khi DB kết nối được; nếu DB chết giữa chừng rồi quay lại, MCP tự phục hồi. **Giới hạn**: `setup_connection` chỉ target được các port đã khai báo relay sẵn (`--map`/`--file`/`--listen`) — agent không tự mở port mới runtime.
Mỗi mapping có thể mang credentials riêng (user/password/database) khi dùng `--file`:
```json
[
  { "listen": 5433, "target": "192.168.50.79:5433", "user": "postgres", "password": "pw-a", "database": "postgres" },
  { "listen": 5431, "target": "localhost:5432", "user": "report", "password": "pw-b", "database": "reporting" }
]
```
Mapping đầu tiên là MCP primary; nếu target của nó không kết nối được lúc khởi động, CLI tự chọn mapping **reachable đầu tiên** làm primary (cảnh báo `PRIMARY_FALLBACK` + `primaryMappingIndex`/`primaryReason`), MCP lên ngay thay vì respawn liên tục. Log lỗi lặp lại được dedupe/throttle để không spam console khi DB down lâu.

### Service management (`service` — chạy relay như systemd / Windows service)

```bash
# Sinh file cấu hình mẫu, chỉnh sửa rồi cài đặt:
npx tailsacle-cli service init --name tailsacle-relay --out .tailsacle-service.jsonc
sudo npx tailsacle-cli service install --file .tailsacle-service.jsonc --yes   # Linux systemd
npx tailsacle-cli service install --file .tailsacle-service.jsonc --user --yes  # Linux rootless
npx tailsacle-cli service install --file .tailsacle-service.jsonc --yes         # Windows SCM (admin)
npx tailsacle-cli service install --file .tailsacle-service.jsonc --scheduler --yes  # Windows Task Scheduler (no admin)

npx tailsacle-cli service status --name tailsacle-relay --json
npx tailsacle-cli service logs --name tailsacle-relay --follow
npx tailsacle-cli service start|stop|restart --name tailsacle-relay
npx tailsacle-cli service list
npx tailsacle-cli service uninstall --name tailsacle-relay --yes
```

Ví dụ `args` chạy relay multi-port dưới dạng daemon: `["relay", "--file", "/etc/tailsacle/relays.json"]`. Xem `docs/service-install-plan.md` (thiết kế) và `docs/service-install-verification.md` (kiểm chứng).

With `--yes`, `funnel` and `deploy` auto-provision what the tailnet is missing (tagged auth keys, `tagOwners`, the `funnel` node attribute, and tailnet HTTPS certificates) with warnings, so a trust credential can reach a working connection end to end.

## Policy

Policy sync is deliberately destructive-operation gated:

```bash
npx tailsacle-cli policy --file ./policy.hujson --dry-run --json
npx tailsacle-cli policy --file ./policy.hujson --sync --yes --json
```

The workflow fetches the current policy, shows a diff, validates the candidate HuJSON remotely, writes a local backup of the fetched policy, then performs an ETag-protected update and re-reads the policy to verify the write.

## Cleanup

```bash
npx tailsacle-cli cleanup --dry-run --json
npx tailsacle-cli cleanup --yes --json
```

Cleanup is restricted to devices that are offline beyond `TS_CLEANUP_OFFLINE_AFTER` and match the configured hostname/tag set. Protected device names can be supplied through `TS_PROTECTED_DEVICES`.

Deleting a device is irreversible, so confirmation is always required: pass `--yes` for non-interactive runs, or confirm the listed candidates at the interactive prompt. `deploy --cleanup` follows the same rule — it no longer pre-approves the deletion, so without `--yes` it prompts on a TTY and otherwise fails with `CLEANUP_CONFIRMATION_REQUIRED`. If some devices are deleted and others fail, the command reports `CLEANUP_PARTIAL_FAILURE` together with the exact IDs that were removed rather than claiming nothing was deleted.

## Configuration

| Variable | Purpose |
|---|---|
| `TS_TAILNET` | Tailnet/domain used by API calls (custom non-`*.ts.net` domains warn; Funnel relies on a Tailscale-hosted domain) |
| `TS_HOSTNAME` | Node hostname |
| `TS_TAGS` | Comma-separated node tags without or with `tag:` prefix |
| `TS_PROFILE` | `ci`, `container`, `vm`, `windows`, `dev`, `funnel-app`, `subnet-router`, `exit-node` (`funnel-app` defaults to non-ephemeral) |
| `TS_SSH` | Enable SSH intent, default `true` |
| `TS_ACCEPT_DNS` | Accept DNS, default `true` |
| `TS_ACCEPT_ROUTES` | Accept subnet/exit routes when enabled by profile |
| `TS_PREAUTHORIZED` | Create pre-authorized auth keys, default `true` |
| `TS_KEY_EXPIRY` | Auth-key lifetime in seconds, `max` or `unlimited` (default `max`). `max`/`unlimited` use the documented 90-day ceiling — this is NOT an API-discovered maximum. Set `TS_KEY_EXPIRY=3600` to pin a shorter lifetime; explicit values above the ceiling are clamped with a warning. This is the auth-key expiry, not the node key-expiry policy |
| `TS_EPHEMERAL` | Override ephemeral node behavior (ephemeral nodes cannot publish public Funnel DNS) |
| `TS_REUSABLE` | Override auth-key reuse behavior |
| `TS_TAG_BASE` | Base for the deterministic auto-tag when `TS_TAGS` is unset (`tag:<base>`; on CI the `GITHUB_REPOSITORY`/`GITLAB_PROJECT_PATH` is preferred) |
| `TS_AUTH_KEY` | Pre-created node auth key |
| `TS_API_KEY` | Tailscale API key |
| `TS_ACCESS_TOKEN` | Bearer access token |
| `TS_CLIENT_SECRET` | Tailscale OAuth trust credential (`tskey-client-…`); client ID is derived from it |
| `TS_CREDENTIAL_ENV` | Name of the env var holding the OAuth trust credential — the explicit env-level equivalent of `--credential-env` (the config file `credentialEnv` key sets it); beats `TS_CLIENT_SECRET` and auto-detection |
| `TS_CLIENT_ID` | OAuth client ID when the secret is not a self-describing trust credential |
| `TS_OAUTH_CLIENT_ID` | OAuth client ID (alternative to `TS_CLIENT_ID`) |
| `TS_OAUTH_CLIENT_SECRET` | OAuth client secret |
| `TS_POLICY_FILE` | Default policy file path |
| `TS_CLEANUP_OFFLINE_AFTER` | Cleanup threshold in seconds; default 3600 |
| `TS_NO_CLEANUP` | `true`/`1` disables the automatic cleanup step at the end of a `--cleanup` deploy |
| `TS_TAG_OWNER` | Comma-separated owners used when auto-provisioning missing `tagOwners` (otherwise a single existing owner set is reused; mixed-owner policies require this or `--tag-owner`) |
| `TS_PROTECTED_DEVICES` | Comma-separated protected device IDs/names |
| `TS_BIN_DIR` | Binary cache directory for `update-bin`/auto-download |
| `TS_BIN_VERSION` | Pin a specific stable version for `update-bin`/auto-download (e.g. `1.76.0`); unset = latest stable |
| `TS_TAILSCALE_BIN` | Explicit Tailscale binary path |
| `TS_TAILSCALE_SOCKET` | Explicit path to the tailscaled Unix socket (default: `/var/run/tailscale/tailscaled.sock`) |
| `TS_TAILSCALED_STATE` | State path for a userspace tailscaled (default `/var/lib/tailscale/tailscaled.state`) |
| `TS_STATE_DIR` | State directory for a userspace tailscaled; state file is `<dir>/tailscaled.state` (overrides the cache-based default) |
| `TS_CLI_YES` | `true`/`1` answers every confirmation like `--yes` (for embedded automation) |
| `TS_UNATTENDED` | Windows unattended join intent |

### Config file

Instead of exporting environment variables, place a `tailscale-cli.config.json` in your
project root (or pass `--config <path>`). Config file values are used as defaults that
environment variables override:

```json
{
  "profile": "vm",
  "hostname": "web-01",
  "tags": ["prod", "web"],
  "keyExpiry": "max",
  "ephemeral": false,
  "credentialEnv": "CI_TAILSCALE_TRUST"
}
```

Any env var whose value starts with `tskey-client-` is auto-detected as an OAuth trust
credential; use `--credential-env <name>`, `TS_CREDENTIAL_ENV`, or the config file
`credentialEnv` key to select the exact env var when several are present (the value itself
must still come from the environment — the config file only names the variable). Secrets
are never returned raw by `doctor` and are not written to logs; server error text is
scrubbed for `tskey-…` and `Authorization` material.

## Interactive menu and safety flags

Running `tailsacle-cli` with no arguments in a TTY opens an interactive menu that prompts
for the profile, target/port, policy action and binary update, then prints the equivalent
non-interactive command before executing it.

Safety scoping: `--yes` only skips confirmation prompts. Auto-provisioning side effects
are gated behind explicit flags so a plain `--yes` never quietly rewrites tailnet policy:

| Flag | Effect |
|---|---|
| `--apply-policy` | Allow HuJSON-preserving `tagOwners`/`nodeAttrs` provisioning (with plan + warning) |
| `--enable-https` | Allow enabling tailnet-wide HTTPS (required for Serve/Funnel) |
| `--ssh` / `--no-ssh` | Enable/disable Tailscale SSH on the joined node (default `true`; overrides `TS_SSH`) |
| `--state-dir <path>` | State directory for a userspace tailscaled (overrides `TS_STATE_DIR`) |
| `--backup-dir <path>` | Directory for policy backups, default `./.tailscale-cli` (overrides the side-by-side `${file}.bak` default) |
| `--update-bin` (global flag) | Download the latest stable Tailscale client into the package cache, e.g. `tailsacle-cli --update-bin` (same as the `update-bin` subcommand; `TS_BIN_VERSION` pins a version) |
| `--key-expiry <value>` | Auth-key expiry for this run (`max`, `unlimited`, seconds; overrides `TS_KEY_EXPIRY`). `max`/`unlimited` map to the documented 90-day ceiling — not an API-discovered maximum; explicit seconds above the ceiling are clamped with a `KEY_EXPIRY_CLAMPED` warning |
| `--tag-owner <owner...>` | Owner(s) for auto-provisioned `tagOwners` (overrides `TS_TAG_OWNER`) |
| `--cleanup` | Run the exact-match offline device cleanup at the end of a deploy on **any** profile (auto-cleanup otherwise defaults to CI/container) |
| `--verify-timeout <sec>` | Funnel public-DNS + live-endpoint verification timeout (default 120s) |
| `--config <path>` | Path to `tailscale-cli.config.json` config file (default: auto-detect in cwd) |
| `status --show-resolution` | Show credential resolution source and masked value in status output |
| `dns --dry-run` | Preview MagicDNS enablement without applying changes |
| `funnel --tcp 10000:5432` | TCP Funnel instead of HTTPS (public endpoint is verified too) |
| `funnel --expose 443=3000 --expose 443/api=3001` | Multiple HTTPS Funnel targets/paths (all are reported in `resolved.exposures`) |
| `dns --enable-magicdns --yes` | Enable MagicDNS on the tailnet (post + read-after-write verify) |
| `update-bin --force --skip-checksum` | Force a fresh verified download; skip the SHA256 check (not recommended) |
| `daemon status` | Report the local tailscaled state and any userspace daemon tracked in the pidfile |
| `daemon stop` | Stop a userspace tailscaled started and tracked by this tool |

`funnel` refuses ephemeral nodes (they never publish public DNS), auto-detects the target
from `$PORT` when none is given, and verifies both the public A record and the **live
endpoint** before reporting success: HTTPS funnels get a TLS handshake + HTTP probe per
public port, TCP funnels get a raw TCP connect, each retried up to `--verify-timeout`
(default 120s). A published DNS record alone is never reported as success —
`FUNNEL_ENDPOINT_UNREACHABLE` is raised when the record exists but the connection fails.

With `deploy --funnel --yes`, the funnel node attribute is checked **before** the local
`funnel` command runs: it is auto-provisioned when `--apply-policy` is present, otherwise
the deploy fails fast with `FUNNEL_ATTR_REQUIRED`. Enable tailnet HTTPS for Funnel with
`--enable-https`; tailnet HTTPS is never enabled implicitly.

On Windows there is no portable binary: `update-bin`/auto-download resolve the MSI from the
stable index, verify its SHA256 and install it silently when running as Administrator;
without Administrator privileges the exact `msiexec /i "<cache>\…msi" /qn` command is
returned.

## Development

```bash
npm run typecheck
npm test
npm run check
npm run build
npm run pack:check
npm run version:bump:verify   # bump version to now (Asia/Ho_Chi_Minh, 1.YYMMDD.1HHmm)
```

CI tests Linux and Windows on Node 22 and Node 24. Release publishing is tag-based: every
tag `v*.*.*` runs `release.yml`, which builds with cached node_modules on node24-runtime
actions, publishes to npmjs with npm provenance (Trusted Publisher OIDC) and mirrors the
package to GitHub Packages for fast CI installs. Versions use `1.YYMMDD.1HHmm`
(Asia/Ho_Chi_Minh, 24h), e.g. `1.260816.11417`.
