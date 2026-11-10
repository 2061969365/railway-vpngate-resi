# Go manager (F6, phases 0-2 skeleton)

Status: **stage 0-2 only**. The production entry point is still the Python
manager. `cmd/vpngate-manager` is an opt-in skeleton that proves the ported
pure layers compile, pass their tests and can serve the read-only status API.
It does not start sing-box, does not refresh snapshots and does not own the
resi data plane.

## Layout

| Path | Status | Contents |
|---|---|---|
| `internal/singbox/` | ported | `types.go`, `tags.go`, `ovpn.go`, `snapshot.go`, `config.go`, `username.go` |
| `internal/measure/` | ported | TCP latency, SOCKS5, exit IP, mixed exit, throwaway sing-box dial, resi rotation, dial gate |
| `internal/probe/client.go` | ported | fail-open probe sidecar client (`health`/`exit`/`delay`/`delay_status`) |
| `cmd/vpngate-manager/` | skeleton | env parsing, `/healthz`, `/api/status`, `MANAGER_IMPL` entry |
| `tests/contract/` | ported | Python golden fixtures + Go semantic replay; sidecar client fail-open tests |
| `scripts/gen_golden.py` | new | regenerates `tests/contract/golden/` from Python |

No existing Python/Go file, `start.sh`, `Dockerfile`, `README.md` or `go.mod`
was modified by this phase.

## Running

```bash
go build ./cmd/vpngate-manager
ADMIN_TOKEN=0123456789abcdef PROXY_PASS=0123456789abcdef ./vpngate-manager
curl -sS http://127.0.0.1:3000/healthz                 # 503 not ready
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://127.0.0.1:3000/api/status | jq .
```

`MANAGER_IMPL` is **documented only; there is no deployment-layer switch**.
The default and only implemented value is `py`: `start.sh` always execs
`railway_manager.py`, and the image neither builds nor copies
`vpngate-manager`. Setting `MANAGER_IMPL=go` has no effect and does not fail
closed — stages 3-6 (including the switch) are not implemented.

- `cmd/vpngate-manager` is an opt-in diagnostic binary built manually.
- It never falls back to Python and never launches a second manager: only one
  manager may hold a VPNGate node session (`duplicate-cn`).

## Token policy (FIX-PLAN P0-1)

| Variable | Missing/empty | Explicit `vpn` or `<16` chars | Explicit valid |
|---|---|---|---|
| `ADMIN_TOKEN` | random 32-char token, printed once | refuse startup unless `ALLOW_INSECURE_ADMIN=1` | accepted |
| `PROXY_PASS` | random 32-char token | refuse startup | accepted |

`/api/*` is fail-closed: an empty token never authorizes. `/healthz` is public.
Comparison is constant-time.

## Environment

The parser mirrors `build_config_from_env` keys/defaults. Bools accept
`1/true/yes/on` and `0/false/no/off`; an invalid bool keeps the default (Python
compatibility). Ints outside their range refuse startup.

Known deviations, fixed only when stages 3-6 land (R2-3-11):

- `RESI_IN_PORT` (40001) and `RESI_ROTATE_BASE` (41000) are hard-coded in Go,
  while Python reads both from the environment.
- Go's `func(string) string` cannot distinguish unset from explicitly empty.
  For `SNAPSHOT_URL`, `RESI_PATH`, `PROXY_USER` and `CLOUDFLARED_BIN` it falls
  back to the default, whereas Python keeps `""` or refuses startup.

| Key | Default | Range / notes |
|---|---|---|
| `PORT` | 3000 | 1..65535, public mux port |
| `ADMIN_PORT` | `PORT` | when set, bind defaults to 127.0.0.1 |
| `ADMIN_BIND` | derived | explicit bind override |
| `MIXED_PORT` | 40000 | 1..65535 |
| `SNAPSHOT_URL` | `https://www.vpngate.net/api/iphone/` | must be https |
| `SNAPSHOT_URLS` | empty | comma list, each https |
| `REFRESH_SECONDS` | 3600 | 60..86400 |
| `LIMIT` | 100 | 0..100 |
| `REAL_TOPK` | 30 | 0..100 |
| `DIAL_WORKERS` | 2 | 1..5 |
| `FULL_PROBE_WORKERS` | 3 | 1..5 |
| `PROBE_WORKERS` | 15 | 1..30 |
| `DIAL_TIMEOUT` | 15 | 5..60 |
| `AUTO_RESCUE` | true | bool |
| `OPENVPN_PERSIST_PINNED` | true | bool |
| `HEALTH_CHECK_INTERVAL` | 20 | 5..300 |
| `FAST_HEALTH_INTERVAL` | 5 | 1..60 |
| `DEEP_HEALTH_INTERVAL` | 30 | 5..300 |
| `CHAIN_SETTLE_GRACE` | 20 | clamped 5..120 |
| `FAST_DELAY_TIMEOUT_MS` | 2500 | clamped 500..5000 |
| `MAX_MUX_CONNECTIONS` | 100 | 1..1000 |
| `CLASH_API_PORT` | 9090 | 0..65535 |
| `DATA_DIR` / `RAILWAY_VOLUME_MOUNT_PATH` | `.` | state directory |
| `VLESS_UUID` | empty | empty disables VLESS and rotate |
| `VLESS_DIRECT_PORT` / `VLESS_CHAIN_PORT` | 8080 / 8082 | 1..65535, must differ |
| `RESI_GATEWAY` | empty | `host:port`; enables gateway mode |
| `RESI_USER` / `RESI_PASS` | empty | required with `RESI_GATEWAY` |
| `RESI_USER_TEMPLATE` | `{user}` | `{user}`, `{session}`, `{ttl}` only |
| `RESI_SESSION_TTL` | 0 | 0..86400; >0 without `{session}` warns and stays rotating |
| `RESI_PROBE_INTERVAL` | 300 | 60..86400 |
| `RESI_PORT` / `RESI_PATH` | 8084 / `/ws-resi` | third path |
| `TUNNEL_TOKEN`, `CLOUDFLARED_BIN`, `DISGUISE_PATH` | empty / `cloudflared` / empty | pass-through |

Port collisions (`MIXED_PORT` vs 8080/8081/8082/4096/VLESS ports, `RESI_PORT`,
admin port vs mux) refuse startup, matching the Python validation.

## HTTP surface

- `GET /healthz` — `200 ok` only when endpoints exist and sing-box is serving;
  the skeleton has no endpoints, so it returns `503 not ready` (honest
  Python-compatible behaviour until phase 4).
- `GET /api/status` — requires `Authorization: Bearer <ADMIN_TOKEN>`. Fields
  match `status_snapshot`; `resi` is `{"enabled": false}` when disabled,
  `pin_health.state` is `"unknown"`, `endpoints` is empty.
- Any other `/api/*` — `501 not implemented in the go manager skeleton`
  (after auth); unknown non-API paths return 404 after auth.

Security headers and `Connection: close` mirror the Python manager. The server
sets `ReadHeaderTimeout`, `IdleTimeout` and `MaxHeaderBytes`.

## Ported functions

`internal/singbox`: `ParseOVPN`, `AllTCPRemotes`/`AllTCPRemotesResolved`,
`PrimaryServer`, `EndpointRemotes`, `AssignStableTags`, `NodesToEndpoints`,
`ParseSnapshot`, `SnapshotToNodes`, `SnapshotToEndpoints`,
`ProbeEndpointLatency`, `BuildConfig`, `RenderResiUsername`.

Limits: 256 KiB/config, 128 KiB/block, 8 remotes (error above the cap),
8 MiB/5000-row snapshot, linear block scanner (no DOTALL regex), remote port
1..65535, private/loopback/link-local/metadata screening with
`ALLOW_PRIVATE_REMOTES=1` escape hatch, cipher/auth whitelists.

`internal/measure`: `TCPLatency`, `Socks5GetText`/`Socks5GetLatency`,
`FetchExitIP`, `MeasureMixedExitIP` (reuses `probe.Exiter`),
`DialProbeConfig`, `MeasureRealLatency`, `MeasureExitIP`,
`MeasureResiExitIP`/`MeasureResiRotation`/`MeasureResiRotate`, `Gate`
(`MAX_CONCURRENT_DIALS=10`). Every read shares the context deadline; response
bodies cap at 64 KiB; TLS verification cannot be disabled through the API.

`internal/probe.Client`: `Health`, `ExitIP`, `Delays`, `DelayStatus`; redirects
are not followed, `HTTP(S)_PROXY` is ignored, and a two-failure/5-second breaker
keeps a sidecar outage from leaking into the manager.

## Golden fixtures

`scripts/gen_golden.py` writes `tests/contract/golden/*.json` from the current
Python implementation and `tests/contract/contract_test.go` replays them
semantically (sorted object keys, order-sensitive arrays).

```bash
python scripts/gen_golden.py
go test ./tests/contract/
```

F3 is changing `vpngate_to_singbox.py` in parallel. The fixtures here were
generated from the F3 working tree at the time of writing (fixed semantics:
merged TCP remotes, uppercase cipher, reserved tags, row limits). **F7 must
re-run `scripts/gen_golden.py` after F3/F5 settle and diff the result.**

## Not implemented (phases 3-6)

| Phase | Remaining work |
|---|---|
| 3 | `internal/tunnel` extraction from `internal/edge`, mux first-byte classification, pump/drain, VLESS path routing |
| 4 | Full HTTP API (auth/settings/nodes/state/logs), snapshot refresh, full probe, single probe/verify, sing-box/cloudflared supervision, persistence |
| 5 | Residential gateway/rotate data plane, pin/rescue/auto-pin, fast/deep health, Clash hot switch, rotate pool/strike/park, fake-clock scenario tests |
| 6 | Default `MANAGER_IMPL=go`, delete Python runtime from image, freeze Python under `tests/oracle/`, README/Dockerfile updates |

Until then `cmd/vpngate-manager` is a read-only diagnostic endpoint, not a
production manager. The resi path, pin/rescue/refresh and sing-box supervision
return 501/are omitted.

## Tests

```bash
go test ./...
go vet ./...
go build ./cmd/vpngate-manager
go test -race ./internal/singbox ./internal/measure ./internal/probe \
  ./cmd/vpngate-manager ./tests/contract
```

The race run needs cgo/gcc. This host has no gcc, so `-race` was not executed
in F6; the packages are race-clean by construction (no shared mutable state
outside `probe.Client`'s breaker and `measure.Gate`/goroutine slices).
