# AGENTS.md — vpn-sub-manager

Personal, 24/7 **free-VPN subscription manager** written in Go. Single static binary.

It fetches **only** the GitHub sources the user whitelists, parses/dedups them,
drops broken, unsupported, unencrypted, and malicious nodes, pings every candidate
3× through a real **xray-core** subprocess (16–32 concurrent workers), keeps the
3–5 best per country by latency, and emits subscriptions for
**sing-box**, **v2rayN/xray**, and **Clash.Meta**. A long-lived in-process scheduler
auto-refreshes (replacing dead/degraded nodes), and a **web management UI**
(package `internal/web`) manages sources and shows status. Cores are
auto-downloaded from official repos and SHA-verified.

> **Язык общения: русский.** Весь диалог с пользователем всегда ведётся на русском языке.

> **Target platform: Ubuntu 22+ (Linux).** Windows/macOS are dev-only; tests run on
> Linux (or an Ubuntu VM). The code is cross-platform — the only OS-specific bit is
> the `.exe` suffix on core binaries.

---

## Pipeline (6 stages + supporting subsystems)

```
user whitelist (config)
   │
   ▼
fetch ──► parse ──► filter ──► test (ping via xray-core/sing-box) ──► select ──► generate (3 formats)
   │                                                                              │
   └──────────────────────── state (SQLite) ◄── scheduler (24/7 ticker) ◄────────┘
                                              │
                                          core (binary mgr) + geo (mmdb)
```

| Stage | Package | Notes |
|---|---|---|
| model | `internal/model` | `Node` + scheme enum (vmess/vless/trojan/hysteria2/tuic kept; ss/wireguard/obfs removed; ssr/snell excluded) |
| config | `internal/config` | user source whitelist (plain-text file registry; deliberate choice to avoid SQLITE_BUSY lock contention). No source fetched unless added + enabled |
| core | `internal/core` | auto-download latest **STABLE** xray-core (+optional sing-box) from GitHub Releases, verify SHA256 |
| state | `internal/state` | SQLite (pure-Go `modernc.org/sqlite`); bounded retention on `results`/`history`/`nodes` |
| fetch | `internal/fetch` | resolve repo/tree → raw; fetch raw; https-only in; GitHub API host required for tree form |
| parse | `internal/parse` | base64 subs + all URI schemes + Clash YAML + sing-box JSON → `Node` |
| filter | `internal/filter` | dedup; drop broken; drop unsupported schemes (SS/WireGuard); drop unencrypted/insecure; malware heuristics (scoped to `Node.Extra`) |
| test | `internal/test` | ping engine: per-worker ephemeral SOCKS5 port, real xray/sing-box subprocess, 3 probes, hard timeout, reaper |
| geo | `internal/geo` | `GeoLite2-Country.mmdb` from `sapics/ip-location-db` (one-time download, offline lookup); fallback to `#fragment` name |
| select | `internal/select` | per-country top-3-5 by latency; emit sing-box JSON + v2rayN base64 + Clash.Meta YAML |
| scheduler | `internal/scheduler` | in-process `time.Ticker`; degrade detection + swap; history-based corpse skip (skip re-ping of nodes dead `CorpseCycles` consecutive cycles, default 5); guards against overwriting good subs on empty cycles |
| web | `internal/web` | web management UI (vanilla-JS SPA + REST API + SSE), reached at `http://<web-addr>/<web-secret>/`; the old bubbletea TUI (`internal/tui`) was removed |

Main entry: `main.go` (wires components, starts scheduler goroutine + web management
server, graceful SIGINT/SIGTERM shutdown that kills all xray/sing-box procs).

## Key decisions

- **Go**, single static binary. No cgo (pure-Go SQLite).
- **xray-core ping engine** only. Shadowsocks, WireGuard, and obfs-SS are removed
  by the `DropUnsupported` filter pass, so no sing-box/SS path is needed.
- **User source whitelist only** — no shipped/hardcoded source list. The manager fetches
  only what the user adds and enables.
- **Cores auto-downloaded latest STABLE + SHA256-verified** from official GitHub Releases.
- **GeoIP** from `sapics/ip-location-db` free `GeoLite2-Country.mmdb`, downloaded once, offline afterward.
- **SQLite state with bounded retention** so the DB grows only boundedly over 24/7 operation.

## Security / malware model

- **Protocol allowlist**: only the strict set is kept — Trojan, VLESS (only `tls`/`reality`), VMess (only `tls`), Hysteria2, and TUIC. Shadowsocks, WireGuard, and obfs-SS (simple-obfs) are removed by `filter.DropUnsupported` (SS is DPI-fingerprintable; simple-obfs is deprecated/bypassable; the WireGuard handshake is trivially recognizable; obfs lives on SS so dropping SS covers obfs). ssr/snell/unknown are rejected at parse time.
- **Generators emit ONLY explicit known `Node` fields and DROP `Node.Extra`/`Node.Raw`**,
  building dedicated output structs/URIs rather than marshalling `Node` — a dangerous key
  can never leak to the user's subscription.
- **Generated xray/sing-box test config** is built solely from known `Node` fields (no `Extra`,
  no `route`/`plugin`/`outbound-hijack` injection from untrusted content).
- **Egress isolation (cross-platform enforced)**: the test config's ONLY outbound is the
  candidate node; host traffic never enters a node (config inspection: no host routing).
  On Linux you MAY add a network namespace that still preserves node+target egress, but
  **never** a bare `CLONE_NEWNET` (it would cut the subprocess's access to the node).
- **Malware check scoped to `Node.Extra` only** (avoids false-positives on benign Clash/sing-box
  fields): rejects `exec`/`command`/`script`/hijack/`route`/embedded-script payloads and
  `ssconf://` links pointing to executable payloads. (Benign obfs was previously
  parsed into `Node.Plugin`; obfs-SS is now removed by `DropUnsupported`, so the
  `Plugin` field is effectively dead and retained only for backward-compat parsing.)
- **Insecure filter** (`internal/filter`, applied via `filter.Apply` in the scheduler before
  generation): VLESS MUST be `tls`/`reality` (drops `security=none` and any other/missing);
  VMess/Trojan MUST use transport TLS (drop otherwise); Hysteria2/TUIC drop only on
  `security=none`; plaintext socks/http and `insecure=1`/`allow_insecure`/`skip-cert-verify`
  (in `Node.Extra`) are dropped. (Shadowsocks/WireGuard are already removed by `DropUnsupported`.)
- **Completeness filter** (`DropBroken`, after `DropUnsupported` in `Apply`): drops nodes with
  empty Host/Port, or missing credential (`User`) for vmess/vless/trojan/hysteria2/tuic — so
  only functional, non-empty configs reach generation.
- **Generator defense-in-depth** (`internal/select`): even if a malformed node reached
  generation, `secureSecurity` omits `security=none`/`tls=none` from emitted v2rayN URIs
  (sing-box/Clash already enable TLS only on `Security=="tls"`). Filters make this unreachable
  in practice, so it is a belt-and-suspenders safety net.
- **History-based corpse skip** (`internal/scheduler`): `Cycle` persists every probe result to
  SQLite (`RecordResult` + `AddHistory`) so state is no longer a write-only no-op.
  `state.ConsecutiveDead` counts back-to-back dead results; `filterCorpses` runs **before**
  probing and skips any node dead for ≥`CorpseCycles` consecutive cycles (`Config.CorpseCycles`,
  default 5; `0` disables), while still probing fresh/unknown nodes. This both saves pings on
  known-dead nodes and reactivates the previously-dormant `DeadCycles`/`results` pruning.

## Build & QA

```bash
make build      # go build ./...
make vet        # go vet ./...
make test       # go test ./...  (full suite: unit + integration)
make test-race  # go test -race ./...
make run        # go run .
```

- **Integration test** (`internal/integration`, `TestEngineSmokeNoXray`) exercises the full
  worker pool + probe + persist path through an in-process fake SOCKS5 — no xray/network needed.
  The real-xray path (`TestIntegrationRealXray`) downloads xray and skips cleanly when network/
  download is unavailable.
- **sing-box check**: when the `sing-box` binary is present, generated sing-box output is
  validated; otherwise that check is skipped.

## Subscription outputs

1. **sing-box JSON** (`outbounds[]` + selector/urltest group) — SFA subscription URL.
2. **v2rayN / xray base64** — newline-joined native URIs for all selected schemes, base64.
3. **Clash.Meta YAML** — `proxies[]` + `proxy-groups` (url-test).

All three are persisted to the config dir, guarded so a failed/empty cycle never overwrites a
working subscription (`MinKeep` floor; previous files kept on empty result).

## Scope (Must-NOT-Have)

No hardcoded source list · no multi-user/server/auth/web API · no payment · no GUI (web UI only; the old bubbletea TUI was removed) ·
no non-xray tester (sing-box path removed with SS) · no Docker/orchestration beyond the binary
+ a systemd unit example.
