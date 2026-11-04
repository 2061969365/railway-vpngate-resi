# task-9/task-12/task-15/task-25 verification report

- Repo: `F:/worker/railway-vpngate-combined`
- Verifier: `core-audit` (read-only on application code and tests)
- Scope: task-9 independent verification, the F1/F2 and task-12 follow-ups, task-15 Go edge + Python/start.sh integration, and task-25 post-review health/keepalive/performance verification
- Date: 2026-11-04 (Asia/Shanghai); task-25 checks re-run on the current working tree
- Tree: working tree only; no commit made. The only file this verification wrote is this report. All reproduction scripts live under `/tmp` or `F:/dsh-temp`.

## Verdict

**Overall: PASS — 58/58 checks.** The pin/rescue path, the edge data plane, and the post-review health/keepalive/performance batch pass. C1 (`start.sh` only avoided an `EDGE_METRICS_PORT` collision with `$PORT`, not custom `MIXED_PORT`/`RESI_PORT`/`VLESS_*_PORT`) and C2 (the metrics/admin loops did not reserve the optional probe sidecar's `PROBE_LISTEN`) were both fixed by the Lead and independently re-verified. The current `reserved_list` covers `$PORT`, fixed ports, custom mixed/resi/VLESS ports, `CLASH_API_PORT`, and the parsed probe port; the requested cases are pairwise distinct and in range, and a real edge started with the probe port occupied and metrics on 39003. One boundary residual (65535 overflow) is documented in the residual-risks section but is outside the requested cases. task-25 additionally verifies hot-pin `on_demand` reconciliation, pending-deep-failure handling, unknown persistent tags, and the `/v1/delay` latency budget; no new defect was found in those fixes.

The earlier task-9/task-12 findings remain fixed and re-verified:

- F1: `_run_single_probe()` now calls `_measure_for_probe()` only when `_resi_port_for_tag(tag)` exists; the repro has `dial_calls == []` and the `duplicate-cn` error.
- F2: `_auto_pin_best_impl()` captures `_nodes_rev`, and commit requires the revision, pin and `tag -> server:port` mapping to be unchanged. The repro no longer jumps the pin; the revision test passes.
- task-12: `_boot_from_last_good()` publishes `_rotate_routes(_ordered_serving())` after tags are final and before `_restart_singbox()`, without `_apply_config` or a dial; populated boots restore a non-empty pool, empty nodes yield `[]`.
- Current full suite: **670 passed, 2 skipped** (the 629-pass run below is the task-15 snapshot).
- Edge Go suite, CGO-disabled builds, live tunnel/counter checks, 502/fallback checks, metrics loopback validation, and Python edge-status checks all pass.
- task-25: hot manual/rescue/auto-pin reconciliation changed only endpoint `on_demand` and preserved outbounds/routes without restarting; a successful fast delay did not clear a pending failed deep check; unknown persistent tags preserved existing `on_demand`; and `/v1/delay` returned a per-tag 200 in 4.002s for a slow all-failed batch while keeping the fast Clash-unavailable 503.

| # | Check | Result |
|---|-------|--------|
| 1 | `git status --short` has no stray/`_tmp_*` artifacts | PASS |
| 2 | `git diff --stat`, CRLF-aware `git diff --check` | PASS |
| 3 | Added lines contain no trailing space/tab, debugger, absolute host paths, TODO/FIXME | PASS |
| 4 | CRLF preserved (`railway_manager.py`, `tests/test_railway_manager.py`); `www/console.html` exists and parses | PASS |
| 5 | `python -m py_compile railway_manager.py vpngate_to_singbox.py probe_client.py` | PASS |
| 6 | Full `python -m pytest -q` | PASS (670 passed, 2 skipped on the task-25 tree; 629 at the task-15 snapshot) |
| 7 | Required pytest subset | PASS (full suite is a superset; first pass 562 passed, 2 skipped) |
| 8 | `go test -count=1 ./...` | PASS |
| 9 | `go vet ./...` | PASS |
| 10 | `bash -n start.sh` | PASS |
| 11 | `/ui` bytes == `www/console.html`, including from `cwd=/tmp` | PASS |
| 12 | No throwaway dial/`measure_exit_ip`/`verify_fn` for a pin when `want_singbox` | PASS |
| 13 | `_clash_select` reads the selector back before committing | PASS |
| 14 | Manual pin preserved across refresh (compare-and-set under `_pin_switch_lock`) | PASS |
| 15 | Rescue verifies every candidate, records dead-memory, never uses `cands[:1]`/stale fallback | PASS |
| 16 | `assign_stable_tags` pre-reserves old tags before allocating fresh ones | PASS |
| 17 | Dynamic: tag steal (new fast node inserted first) | PASS |
| 18 | Dynamic: dead pin rescues to a verifiable second candidate; failed candidates remembered | PASS |
| 19 | Dynamic: switch from unpinned verifies served exit and commits with `preferred_tag` still `None` | PASS |
| 20 | Dynamic: mixed inbound down then up within the verify budget | PASS |
| 21 | Dynamic: unknown probe (`attempted=False`) does not increment death streaks | PASS |
| 22 | Dynamic: single-node probe on a serving node never dials it | PASS (F1 fixed) |
| 23 | Dynamic: auto-pin commit cannot cross a concurrent refresh (pin integrity) | PASS (F2 fixed) |
| 24 | Bearer comparison uses `secrets.compare_digest` | PASS |
| 25 | Security headers on `/ui`, `/api/*`, 401 responses | PASS |
| 26 | `start.sh` probe sidecar is non-fatal and cleaned up | PASS |
| 27 | Dockerfile builds/copies Go probe, `probe_client.py`, `www` | PASS |
| 28 | CI split: new Go-only `test-combined.yml`, `unit-tests.yml` untouched | PASS |
| 29 | Boot-from-last-good restores rotate routes (task-12) | PASS |
| 30 | Edge Go tests: `go test ./... -count=1` and `go test ./internal/edge -count=20` | PASS |
| 31 | CGO-disabled Linux builds of `vpngate-probe` and `vpngate-edge` | PASS |
| 32 | Edge routing: raw `/ws-node` + `/ws-chain`, 502 on dead backend, empty UUID → admin | PASS |
| 33 | Edge counters: exact bytes, no duplicate count, one connection per tunnel | PASS |
| 34 | Edge idle watchdog: one-way traffic survives; total-idle tunnel closes | PASS |
| 35 | Edge metrics: loopback-only bind, `/v1/traffic`, `/healthz`, POST 405 | PASS |
| 36 | Edge graceful shutdown (SIGINT/SIGTERM → 10s Shutdown) | PASS (code inspection; live signal not observable on Windows) |
| 37 | Python `ADMIN_PORT` loopback bind and edge-absent fallback | PASS |
| 38 | Edge metrics merge into `/api/status` once, fail-open, bytes only | PASS |
| 39 | `start.sh` sidecar cleanup, edge health monitor, immediate-death handling | PASS |
| 40 | Dockerfile builds/copies both edge and probe binaries plus `probe_client.py`/`www` | PASS |
| 41 | Edge docs, dependency hygiene, CRLF/hygiene, no secrets/stray tracked files | PASS |
| 42 | `start.sh` edge metrics port avoids `$PORT`, fixed ports, and custom mixed/resi/VLESS collisions | PASS (C1 fixed) |
| 43 | `start.sh` metrics/admin ports avoid the optional probe sidecar (`PROBE_LISTEN`) | PASS (C2 fixed) |
| 44 | task-28: hot manual/rescue/auto-pin reconciliation updates only endpoint `on_demand`, no restart or outbound rewrite | PASS (dynamic) |
| 45 | task-28: successful fast delay cannot clear a pending failed deep check | PASS |
| 46 | task-29: unknown persistent tags preserve existing `on_demand` | PASS |
| 47 | task-30: `/v1/delay` healthy calls skip `/version`; slow all-failed 200; fast all-dead 503; empty tags unchanged | PASS |
| 48 | Live `/v1/delay` slow all-failed batch returns 200 within the Python 4.5s deadline | PASS (4.002s) |
| 49 | Full `python -m pytest -q` on the task-25 tree | PASS (670 passed, 2 skipped) |
| 50 | `python -m py_compile ...` and `bash -n start.sh` | PASS |
| 51 | `go test ./... -count=1` | PASS |
| 52 | `go test ./internal/edge ./internal/server ./internal/probe -count=20` | PASS |
| 53 | `go vet ./...` | PASS |
| 54 | `CGO_ENABLED=0 go build ./...` | PASS |
| 55 | Fixed-rate health loop cadence and overrun behavior | PASS |
| 56 | Health/env defaults, clamp policy, and persistent-pinned default | PASS |
| 57 | Rescue delay prevalidation skips only explicit `alive=false`, never death-marks from delay | PASS |
| 58 | Edge pool/idle transport, docs, diff hygiene, no secrets/stray tracked files | PASS |

Counts: **58 PASS / 0 FAIL** (58 checks).

---

## task-15 edge verification

### Go suite and builds

```text
$ go test ./... -count=1
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/config
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/edge
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/probe
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/server
?   github.com/2061969365/railway-vpngate-combined/probe/cmd/vpngate-edge   [no test files]
?   github.com/2061969365/railway-vpngate-combined/probe/cmd/vpngate-probe  [no test files]

$ go test -count=20 ./internal/edge
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/edge  10.416s

$ go vet ./...          # exit 0
$ CGO_ENABLED=0 go build -trimpath -o /tmp/vpngate-edge-check.exe ./cmd/vpngate-edge
$ CGO_ENABLED=0 go build -trimpath -o /tmp/vpngate-probe-check.exe ./cmd/vpngate-probe
-rwxr-xr-x 10691584 /tmp/vpngate-edge-check.exe
-rwxr-xr-x 10720256 /tmp/vpngate-probe-check.exe
```

The 20x edge loop passed every run. Edge tests cover config defaults/overrides, direct and chain counting, streaming payloads counted once, one-way traffic surviving the idle timeout, idle close, resi raw-to-admin without counting, admin fallback, empty UUID fallback, GET-with-body fallback, raw dial failure with and without buffered data, metrics/405, loopback validation, and invalid admin URL.

### Live integration with the real binary

Scripts: `F:/dsh-temp/edge_integration.py` and `F:/dsh-temp/edge_integration2.py` (also under `/tmp`). They start the Go binary built from the current tree, a fake TCP echo backend for node/chain, a fake admin HTTP server, and a raw TCP admin listener for resi.

Part 1 (all PASS):

```text
direct backend/client bytes: 138 138
metrics after direct: {'ok': True, 'bytes_up': 138, 'bytes_down': 138, 'connections': 1, 'active': 0}
chain delta: 126 126
metrics after chain: {'ok': True, 'bytes_up': 264, 'bytes_down': 264, 'connections': 2, 'active': 0}
resi response: HTTP/1.0 200 OK ; edge metrics unchanged
admin proxy body: admin:GET:/api/status?x=1:
GET /healthz -> 200 ok
```

The resi path went to the admin TCP listener and did not change edge counters. The direct/chain counters were exact for the bytes actually copied; each tunnel added one connection, and `active` returned to 0 after close.

Part 2 (all PASS):

```text
dead node /ws-node -> 502, body "bad gateway"; metrics remained zero
empty VLESS_UUID: /ws-node and /ws-chain -> 200 admin body; backend bytes 0/0; metrics zero
metrics on 0.0.0.0 -> exit 1:
  EDGE_METRICS_LISTEN "0.0.0.0:58486" is not a loopback address
```

The 502 path closes cleanly and does not leak counters. With no UUID, both tunnel paths fall back to the admin proxy instead of attempting a raw tunnel.

### Code inspection

- Routing: `internal/edge/proxy.go:84-105` only treats bodyless `GET /ws-node` and `GET /ws-chain` as raw tunnels when `VLESSUUID != ""`; `/ws-resi` is always a raw admin tunnel; every other path uses `httputil.NewSingleHostReverseProxy` with an `ErrorHandler` returning 502.
- Raw path: `proxy.go:111-163` replays any buffered bytes after hijack, drains buffered bytes before copying, and wraps both directions in `countingWriter` only for node/chain. `/ws-resi` uses the same copy path without counters.
- Idle watchdog: `proxy.go:165-194` uses one shared `activity` timestamp updated by traffic in either direction, so one-way traffic keeps the tunnel alive; only total idleness past `IdleTimeout` closes it. `copyStream`/`tunnelActivity` at `216-270` and `countingWriter`/`bufferedReadConn` at `285-305`.
- Metrics: `internal/edge/metrics.go:42-64` exposes only `ok`, `bytes_up`, `bytes_down`, `connections`, and `active` on `/v1/traffic`, plus `/healthz`; non-GET on `/v1/traffic` is 405. `internal/edge/config.go:90-109` `ValidateMetricsListen` rejects empty host, `0.0.0.0`, external IPs/hostnames, and accepts loopback forms; `cmd/vpngate-edge/main.go` validates before starting and refuses to start otherwise.
- Shutdown: `cmd/vpngate-edge/main.go:50-71` uses `signal.NotifyContext` for SIGINT/SIGTERM, then `Shutdown` with a 10s timeout and logs `stopped`. This is code-inspected: on this Windows host, `CTRL_C_EVENT`/`SIGTERM` did not reach the Go handler (the process was killed), so a live POSIX signal test could not be performed.
- Python edge integration: `railway_manager.py:1263-1285` fetches `/v1/traffic` with a 0.3s timeout, accepts only a dict with `ok is True`, adds only numeric non-bool `bytes_up`/`bytes_down` to the returned snapshot, and swallows every error (fail-open). `self.status` remains Python-only, so a repeated status call cannot double-add edge bytes.
- `ADMIN_PORT`: `railway_manager.py:250-285` selects port 3000 and binds `0.0.0.0` when `ADMIN_PORT` is unset; with `ADMIN_PORT` set it binds `127.0.0.1` and rejects collisions against mixed/VLESS/resi ports. `start.sh:120-133` resolves and exports the chosen admin port only after the edge path is enabled.
- `start.sh` lifecycle: sidecar starts only when `PROBE_SERVICE != 0` and the binary exists (`start.sh:80-91`), a quick exit is logged and non-fatal; traps at `start.sh:63`/`75` terminate and wait for the sidecar; the health loop at `start.sh:238-262` exits if the manager or edge dies and restarts the CC Switch proxy once.
- Dockerfile: builder stage `golang:1.27-alpine` (`Dockerfile:27`) builds **both** `vpngate-probe` and `vpngate-edge` with `CGO_ENABLED=0` (`32-34`); runtime copies `probe_client.py`, `www`, `start.sh`, the probe binary, and the edge binary (`55-61`).

### Python checks

```text
$ python -m pytest -q
629 passed, 2 skipped in 131.97s

$ python -m pytest -q tests/test_railway_manager.py \
    -k "AdminPort or BindHost or EdgeMetrics or ColdStart"
8 passed, 374 deselected in 1.47s

$ python -m py_compile railway_manager.py vpngate_to_singbox.py probe_client.py
exit 0
$ bash -n start.sh
exit 0
```

One earlier full-suite run under heavy parallel load failed the pre-existing timing test `tests/test_vpngate_to_singbox.py::MixedExitIpTests::test_one_timeout_budget_is_shared_by_all_targets` with 2 CONNECTs instead of 1; it passed alone in 0.53s and the full suite then passed 629/2. This is recorded as a flaky-test risk, not an edge regression.

### C1 — edge metrics port collision (fixed, re-verified PASS)

The first edge pass found that `start.sh` only adjusted `EDGE_METRICS_PORT` when it equaled `${PORT:-}`; a custom `MIXED_PORT`/`RESI_PORT`/`VLESS_DIRECT_PORT`/`VLESS_CHAIN_PORT` equal to the default metrics port 39002 made the edge fail to bind and `start.sh` exit. The Lead fixed this by adding a dedicated metrics collision loop **before** admin selection (`start.sh:108-119`): it increments past `$PORT`, 8080/8081/8082/8084/4096, and the custom mixed/resi/VLESS ports. The admin loop (`start.sh:120-132`) then also reserves the final metrics port.

Re-extracted the current block and ran the requested cases with `USE_EDGE=1`:

```text
PORT=3000 MIXED_PORT=39002              -> metrics=39003 admin=3001
PORT=39002                              -> metrics=39003 admin=3001
RESI_PORT=39002                         -> metrics=39003 admin=3001
VLESS_DIRECT_PORT=39002                 -> metrics=39003 admin=3001
VLESS_CHAIN_PORT=39002                  -> metrics=39003 admin=3001
ADMIN_PORT=39002 (chosen admin == final metrics) -> metrics=39002 admin=39003
ADMIN_PORT=39002 MIXED_PORT=39002       -> metrics=39003 admin=39004
PORT=39002 ADMIN_PORT=39002             -> metrics=39003 admin=39004
metrics 39002 + PORT=39003 + MIXED=39002 -> metrics=39004 admin=3001
EDGE_METRICS_PORT=8081 (reserved)       -> metrics=8083 admin=3001
```

The admin-collision cases show the second loop moving the admin port past the already-final metrics port, so the two listeners cannot overlap.

Real-binary check: a dummy listener occupied `127.0.0.1:39002` (the simulated mixed port), the edge was started with `EDGE_METRICS_LISTEN=127.0.0.1:39003`, and the metrics endpoint returned 200:

```text
edge_alive True metrics_status 200
body {"ok":true,"bytes_up":0,"bytes_down":0,"connections":0,"active":0}
metrics listener 127.0.0.1:39003
```

This is the same setup that previously failed with `bind: Only one usage of each socket address`; after the fix the selected metrics port is free and the edge starts. `bash -n start.sh` passes. **C1: PASS.**

### C2 — probe sidecar port collision (fixed, re-verified PASS)

The pre-fix behavior was real: `PROBE_LISTEN=127.0.0.1:39002` kept metrics 39002, `EDGE_METRICS_PORT=39001` kept the default probe port, and `ADMIN_PORT=39001` kept the probe port; with a listener already on the port, the edge exited 1 with `bind: Only one usage of each socket address` and `start.sh` exited. The Lead fixed it by building one reserved list before selection (`start.sh:105-107`):

```bash
probe_endpoint="${PROBE_LISTEN:-127.0.0.1:39001}"
probe_port="${probe_endpoint##*:}"
reserved_list="8080 8081 8082 8084 4096 40000 ${MIXED_PORT:-40000} ${RESI_PORT:-8084} ${VLESS_DIRECT_PORT:-8080} ${VLESS_CHAIN_PORT:-8082} ${CLASH_API_PORT:-9090} ${probe_port} ${PORT:-}"
```

The metrics loop (`start.sh:108-119`) increments until `EDGE_METRICS_PORT` avoids every entry; the admin loop (`start.sh:120-132`) avoids the same list plus the final metrics port. Re-ran the requested cases with `USE_EDGE=1`:

```text
PROBE_LISTEN=127.0.0.1:39002 -> metrics=39003 admin=3001 probe=39002
PROBE_LISTEN=127.0.0.1:3001  -> metrics=39002 admin=3002 probe=3001
CLASH_API_PORT=39002         -> metrics=39003 admin=3001 clash=39002
MIXED_PORT=39002             -> metrics=39003 admin=3001 mixed=39002
RESI_PORT=39002              -> metrics=39003 admin=3001 resi=39002
VLESS_DIRECT_PORT=39002      -> metrics=39003 admin=3001 direct=39002
VLESS_CHAIN_PORT=39002       -> metrics=39003 admin=3001 chain=39002
PORT=39002                   -> metrics=39003 admin=3001 port=39002
ADMIN_PORT=39002             -> metrics=39002 admin=39003
ADMIN_PORT=39003+MIXED=39002 -> metrics=39003 admin=39004
ADMIN_PORT=39002+MIXED=39002 -> metrics=39003 admin=39004
```

A pairwise checker over `PORT/metrics/admin/probe/mixed/resi/direct/chain/clash` returned `range=True` and `distinct=True` for all 11 cases (all values 1..65535; baseline is `3000/39002/3001/39001/40000/8084/8080/8082/9090`). Real-binary check: a dummy listener occupied `127.0.0.1:39002` (the simulated probe), the edge was started with metrics 39003, and the process stayed alive and served `/v1/traffic`:

```text
edge_alive True metrics_status 200
body {"ok":true,"bytes_up":0,"bytes_down":0,"connections":0,"active":0}
metrics listener 127.0.0.1:39003
```

`bash -n start.sh` passes. **C2: PASS.**

## task-25 health/keepalive/performance verification

### Commands

```text
$ python -m pytest -q
670 passed, 2 skipped in 171.77s

$ python -m py_compile railway_manager.py vpngate_to_singbox.py probe_client.py
$ bash -n start.sh
exit 0

$ go test ./... -count=1
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/config
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/edge
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/probe
ok  github.com/2061969365/railway-vpngate-combined/probe/internal/server
?   .../cmd/vpngate-edge   [no test files]
?   .../cmd/vpngate-probe  [no test files]

$ go test ./internal/edge ./internal/server ./internal/probe -count=20
ok  .../internal/edge    10.393s
ok  .../internal/server  12.171s
ok  .../internal/probe   6.957s

$ go vet ./...
$ CGO_ENABLED=0 go build ./...
exit 0
```

### Contract checks

- **Task-28 hot-pin reconciliation.** A hot switch updates only the Clash selector; `_reconcile_persistent_tags()` (`railway_manager.py:2695-2716`) now updates the config's endpoint `on_demand` flags under `_config_lock` without rebuilding outbounds or restarting. The locked body (`2718-2776`) reads the file, sets `on_demand = tag not in {preferred, backup}`, writes a temp file plus `os.replace`, and copies the result to `last_good`. It is called from the hot rescue path (`2129`), hot manual switch (`2513-2514`), `_repoint_chain()` (`2670-2672`), and auto-pin (`3361-3362`). If `persist_pinned` is off it is a no-op.
- **Pending deep failure.** `_deep_fail_pending` is initialized at `748`, read before the fast delay (`2177`), re-checked under the pin lock (`2195-2198`), and cleared only by a real deep success (`2264-2269`); pin commits also clear it (`2414`). A delay success while a deep failure is pending calls `check_pinned_health()` instead of clearing the fail streaks (`2209-2210`), so a healthy delay cannot erase a failure that has not been confirmed by a deep check.
- **Task-29 unknown persistent tags.** `vpngate_to_singbox.py:1479-1488` now only forces `on_demand=False` for tags actually present in `persistent`; for all other tags it preserves the endpoint's existing `on_demand`. Tests cover a pre-false endpoint plus an unknown persistent tag at `tests/test_vpngate_to_singbox.py:1011-1055`.
- **Task-30 delay budget.** `internal/server/server.go:18-27` adds a `500ms` fallback budget; `handleDelay` (`200-261`) runs the delay batch first, and only if the batch is empty or all-failed does it check Clash `/version`, and only while less than 500ms has elapsed. Slow all-failed batches return 200 with per-tag `alive=false`; a fast Clash-unavailable result still returns 503; empty tags with healthy Clash return 200 `[]`. The per-delay context margin is now 1500ms (`internal/probe/delay.go:25,121`), leaving 500ms under the Python caller's 2s transport margin (`probe_client.py:146`). Tests: `internal/server/server_test.go:225-354`.

### Dynamic validation

Ad-hoc Python (no repository edits) exercised the three hot-switch paths with `_apply_config`/`_restart_singbox` patched to raise:

```text
auto-pin hot:  preferred=vpngate-0 flags={vpngate-0:False, vpngate-1:True, vpngate-2:True}
               outbounds_preserved=True route_preserved=True
manual hot:    preferred=vpngate-1 flags={vpngate-0:True, vpngate-1:False, vpngate-2:True}
               outbounds_preserved=True
rescue hot:    result=rescued preferred=vpngate-1 flags={vpngate-0:True, vpngate-1:False, vpngate-2:True}
               outbounds_preserved=True
               log: chain rescue: test: vpngate-0 -> vpngate-1 (hot switch)
```

This confirms the only rewritten field is `on_demand`, the new pin is persistent (False), the old pin returns to on-demand (True), and neither a rebuild nor restart happens.

A real `/tmp/vpngate-probe-final.exe` (built with `CGO_ENABLED=0`, 10,722,304 bytes) against a fake Clash produced:

```text
slow all-failed, one tag, timeout 2500: HTTP 200 in 4.002s
  {"ok":true,"results":[{"tag":"vpngate-1","alive":false,"ms":null,"error":"... context deadline exceeded"}]}
fast Clash down/500:                    HTTP 503 in 0.003s
  {"ok":false,"error":"clash unavailable"}
empty tags, healthy /version:           HTTP 200 in 0.002s
  {"ok":true,"results":[]}
```

The 4.002s slow result is below the Python client's 4.5s deadline. The focused Python selection covering the task-28/29/30 contracts passed 13 tests (397 deselected); the persistent-endpoint tests passed 8 (486 deselected); the environment tests passed 5 (405 deselected). The focused Go delay suite passed six tests, including `TestDelaySlowFailuresSkipVersionFallback` (0.60s), and the edge idle-transport/pool tests passed.

The edge pool change adds `adminMaxIdleConnsPerHost=32` and a 32KB `sync.Pool` buffer; `copyStream` (`internal/edge/proxy.go:224-226`) gets and returns the buffer synchronously after `io.CopyBuffer`, with no use-after-put found. The existing test only checks buffer length, not ownership, which is a low test-quality gap, not a defect.

### Environment caveats

- Docker/podman are not installed on this host, so `docker build` was not run. The Dockerfile is inspected only; `go build`/`go test`/`go vet` ran on the host.
- Graceful shutdown is verified by code inspection only; Windows termination did not let the Go signal handler run.
- Ignored runtime files exist in the workspace root (`.resi-rot-*`, `.pytest_cache`, `__pycache__`), but `git status --short` shows none of them and they are not copied by the Dockerfile.

## Re-verification after fixes

### F1 — serving probe with no rotate route

Code change: `_run_single_probe()` (`railway_manager.py:3246-3270`) now gates the rotate measurement on the route actually existing:

```python
if (self.resi_rotate and self.vless_uuid and tag
        and self._resi_port_for_tag(tag)):
    ms = self._measure_for_probe(node)
if ms is None:
    error = "node is serving; refused to dial it (duplicate-cn)"
```

Re-ran `/tmp/repro_probe_dupcn.py` (same setup as the failing first pass: `resi_rotate=True`, `vless_uuid` set, `_resi_routes=[]`):

```text
resi_routes: []
serving? True
accepted: True vpngate-0
probe: {'state': 'done', 'tag': 'vpngate-0', 'ms': None, 'error': 'node is serving; refused to dial it (duplicate-cn)'}
dial_calls: []
```

PASS: no dial, `ms=None`, duplicate-cn error. Gateway mode remains safe.

The new regression test exists at `tests/test_railway_manager.py:6409` (`test_single_probe_refuses_a_serving_tag_without_a_rotate_route`), calls `_run_single_probe()` with `_resi_routes=[]` and a recording `dial_fn`, and asserts `dials == []`, `probe["ms"] is None`, `"duplicate-cn" in probe["error"]`. It is not vacuous.

### F2 — auto-pin vs concurrent refresh

Code change: `_auto_pin_best_impl()` captures the node revision while holding `_lock` (`railway_manager.py:3029`), and the commit path (`3082-3090`) now requires:

1. `self._nodes_rev == rev` (a refresh bumped the revision), else `"node set changed during verify"`;
2. `self.preferred_tag == expected`, else `"pin won the race ..."`;
3. the candidate tag still maps to the same `server:port` in `self._nodes`, else `"candidate tag was remapped during verify"`.

`_nodes_rev` is initialized at `railway_manager.py:647` and bumped whenever the node set is replaced (`load_persisted()` `1375-1376`; `_refresh_once_inner()` `2707-2708`). Failed commits call `_restore_runtime_pin()` and record `auto-pin-skipped`.

Re-ran `/tmp/repro_autopin_race.py` (a refresh replaces `_nodes` and remaps `vpngate-0` from `203.0.113.11` to `198.51.100.7` during `_verify_served`):

```text
preferred: None
tag now maps to: None
verified server was: 203.0.113.11
evidence keys: ['203.0.113.11:443']
pin jumped: False
```

PASS: no commit, no pin jump. This repro leaves `_nodes_rev` untouched, so it exercises the **tag-remap** branch. The committed test at `tests/test_railway_manager.py:6431` (`test_auto_pin_rejects_the_commit_when_the_node_set_changed`) bumps `_nodes_rev` inside `_verify_served` and asserts `preferred_tag is None`, the `"node set changed"` history event, and rollback to `None`; it exercises the **revision** branch. Together, both new checks are exercised.

### task-12 — boot-from-last-good restores rotate routes

Code change: `_boot_from_last_good()` (`railway_manager.py:1390-1431`) calls `load_persisted()` first, finalizes tags/status, then at `1422-1427` runs, only in rotate mode:

```python
if self.resi_rotate:
    self._set_resi_routes(self._rotate_routes(self._ordered_serving()))
if self.want_singbox:
    self._restart_singbox()
```

There is no `_apply_config`, no `dial_fn`, and no config rebuild on this path; the last-good payload is already copied to `config_path` before the route table is published. Empty nodes are safe: `_ordered_serving()` returns `[]`, `_rotate_routes([])` returns `[]`, and `_set_resi_routes([])` clears the table.

Independent repro (`/tmp/repro_boot_routes.py`, seeded nodes + valid last-good config, `start_singbox=False`):

```text
populated ok: True routes: [('vpngate-0', 41000), ('vpngate-1', 41001)]
equals expected: True non-empty: True
pool equal: True pool: [('vpngate-0', 41000), ('vpngate-1', 41001)]
endpoint tags: ['vpngate-0', 'vpngate-1']
resi inbounds: 2

empty ok: True routes: [] expected: []
empty pool: [] endpoints: []
empty resi inbounds: 0
```

Ordering / no-side-effect repro (`/tmp/repro_boot_order.py`, `start_singbox=True` but restart mocked):

```text
boot ok: True
order: ['load_persisted', 'set_resi_routes:2', 'restart_singbox']
apply/dial calls: [] []
routes: [('vpngate-0', 41000), ('vpngate-1', 41001)]
```

The new regression test `tests/test_railway_manager.py:1724` (`ColdStartTests::test_boot_from_last_good_restores_rotate_routes`) passes; it asserts the restored routes equal `_rotate_routes(_ordered_serving())`, the pool matches, a seeded endpoint is visible in status, and `status["resi"]["inbounds"]` equals the route count.

### Re-run core evidence (task-12 snapshot)

This block is the earlier task-12 snapshot. The current task-15 tree run is **629 passed, 2 skipped** in the section above.

```text
$ python -m pytest -q
620 passed, 2 skipped in 130.53s

$ python -m pytest -q ...::test_single_probe_refuses_a_serving_tag_without_a_rotate_route \
                     ...::test_auto_pin_rejects_the_commit_when_the_node_set_changed
2 passed in 2.30s

$ python -m pytest -q ...::ColdStartTests::test_boot_from_last_good_restores_rotate_routes
1 passed in 0.04s

$ go test -count=1 ./...
ok  .../probe/internal/config  0.067s
ok  .../probe/internal/probe   0.359s
ok  .../probe/internal/server  0.017s
(./cmd/vpngate-probe: no test files)

$ go vet ./...      # exit 0
$ bash -n start.sh  # exit 0
$ python -m py_compile railway_manager.py vpngate_to_singbox.py probe_client.py
compile exit=0
```

Hygiene after the fix:

```text
$ git status --short
# same 8 modified files + 9 untracked files (including this report) as the first pass.
$ git diff --stat .            # 2372 insertions, 1682 deletions
$ git -c core.whitespace=cr-at-eol diff --check
# exit 0
$ git diff --check | wc -l
3688                            # CRLF-only false positives
```

Added-line scan: **2372** added diff lines, **0** with a real trailing space/tab; **0** debugger/absolute-host-path hits outside the intentional test token fixtures (e.g. `tests/test_railway_manager.py:544`). Line endings: `railway_manager.py` 3949 CRLF / 0 bare LF, 203865 bytes; `tests/test_railway_manager.py` 6556 CRLF / 0 bare LF, 295712 bytes; `www/console.html` 1529 LF / 0 CRLF, 90582 bytes.

---

## First-pass findings (now fixed)

These are kept for the audit trail. Both were reproduced before the fix and are re-verified above.

### F1 (was item 22) — a serving-node probe dialed when `_resi_routes` was empty

Before the fix, `_boot_from_last_good()` did not populate `_resi_routes`; `_run_single_probe()` unconditionally called `_measure_for_probe()` for a serving tag in rotate mode, and `_measure_for_probe()` fell through to `dial_fn` when no rotate route existed. Original repro output:

```text
probe: {'state': 'done', 'tag': 'vpngate-0', 'ms': 10, 'error': None}
dial_calls: ['203.0.113.11']
```

Now fixed by the route-existence gate; repro output above has `dial_calls: []`.

### F2 (was item 23) — auto-pin committed across a refresh

Before the fix, the commit checked only `preferred_tag != expected`, not the node revision or tag mapping. Original repro output:

```text
preferred: vpngate-0
tag now maps to: 198.51.100.7
verified server was: 203.0.113.11
pin jumped: True
```

Now fixed by the `_nodes_rev` capture/check and the tag-remap check; repro output above has `preferred: None`, `pin jumped: False`.

---

## Evidence (first pass, reused where unchanged)

### Tree hygiene

`git status --short` contains only the expected implementation files plus `verification-report.md`:

```text
 M Dockerfile
 M README.md
 M railway_manager.py
 M start.sh
 M tests/test_railway_manager.py
 M tests/test_resi.py
 M tests/test_vpngate_to_singbox.py
 M vpngate_to_singbox.py
?? .github/workflows/test-combined.yml
?? cmd/
?? docs/probe-sidecar.md
?? go.mod
?? internal/
?? probe_client.py
?? tests/test_probe_client.py
?? verification-report.md
?? www/console.html
```

No `_tmp_*`, no stray repro script in the repo. The current `git diff --stat` is 2035 insertions / 1663 deletions across 8 tracked files (`railway_manager.py` 2631 changed lines, `tests/test_railway_manager.py` 588, etc.).

`git diff --check` reports 3350 lines, all false positives from CRLF (`trailing whitespace` on added CRLF lines). The CRLF-aware check is clean:

```text
$ git -c core.whitespace=cr-at-eol diff --check; echo $?
0
```

Independent scan of 2036 added diff lines: **0** real trailing space/tab. Source scan (app, tests, Go, docs, CI): **0** `pdb.set_trace`/`breakpoint()`/`debugger;`/`console.debug`, **0** absolute `C:\Users`/`F:\worker` host paths, **0** TODO/FIXME. The only token-shaped literal is the test fixture `tests/test_railway_manager.py:796` `TOKEN = "test-admin-token-0123456789abcdef"`, which is intentional and not a production secret.

Line endings:

```text
railway_manager.py CRLF 3916 bare_LF 0 bytes 201811
tests/test_railway_manager.py CRLF 6427 bare_LF 0 bytes 289760
www/console.html CRLF 0 bare_LF 1529 bytes 90582
```

`www/console.html` parses as HTML (doctype + `</html>`, one `<style>`, two `<script>`, balanced tags checked with the stdlib parser), 90582 bytes.

### Build and test commands

```text
$ python -m py_compile railway_manager.py vpngate_to_singbox.py probe_client.py
compile exit=0

$ python -m pytest -q
620 passed, 2 skipped in 130.53s

$ python -m pytest -q tests/test_railway_manager.py tests/test_resi.py tests/test_probe_client.py tests/test_vpngate_to_singbox.py
562 passed, 2 skipped in 128.08s   # first pass, before the F1/F2 fix

$ go test -count=1 ./...
ok  .../probe/internal/config  0.067s
ok  .../probe/internal/probe   0.359s
ok  .../probe/internal/server  0.017s
(./cmd/vpngate-probe: no test files)

$ go vet ./...      # exit 0
$ bash -n start.sh  # exit 0
```

Targeted dynamic contract tests (all pass):

```text
$ pytest -q ...::test_switch_from_unpinned_commits_after_served_exit \
            ...::test_verify_waits_for_the_mixed_inbound_to_come_back \
            ...::test_all_candidates_failing_keeps_the_pin_and_remembers_them \
            ...::test_unknown_chain_probe_does_not_increment_death_streaks \
            ...::test_verify_never_uses_a_throwaway_client_on_a_pin \
            ...::test_switch_rejects_a_dead_node_and_rolls_back
6 passed in 4.25s

$ pytest -q ...::test_single_probe_refuses_a_serving_tag_without_a_rotate_route \
            ...::test_auto_pin_rejects_the_commit_when_the_node_set_changed
2 passed in 2.30s
```

### `/ui` byte identity and console loader

```text
sha256 231f263da6a00838a2946f825ff282d5a8cfa9b4852a7ee905aae07af9ed4cf2 len 90582 equal True
cwd=/tmp equal: True len 90582
```

The loader (`railway_manager.py:192-214`) resolves `Path(__file__).resolve().parent / "www" / "console.html"` and reads with `newline=""`, so byte identity is independent of the process cwd. `UI_HTML` matches the on-disk file from both the repo root and `/tmp`.

### Static pin/rescue checks

- No throwaway pin verification: `_run_verify()` (`railway_manager.py:3309-3345`) uses `_served_exit_probe()` whenever `want_singbox`, for gateway and rotate mode; `verify_fn` is only the `not want_singbox` legacy path. `_auto_pin_best_impl()` likewise uses `_verify_served()` (`3077`), and `_run_single_probe()` refuses the serving branch without a rotate route (`3262-3266`).
- Clash read-back: `_clash_select()` (`railway_manager.py:2439-2472`) sends `PUT /proxies/chain`, then reads `GET /proxies/chain` and requires `now == tag` before returning True; failure records `chain-select-unconfirmed` at `2465`.
- Manual pin and refresh: `_refresh_once_inner()` takes `_pin_switch_lock` at `2729`, reads the live pin under `_lock`, and only accepts the snapshot result if the live pin still equals the value captured before the fetch; a mapping change clears the pin as `preferred-gone` (`2733-2759`).
- Auto-pin commit: `_auto_pin_best_impl()` captures `_nodes_rev` at `3029`; commit requires the revision, the pin and the live `tag -> server:port` mapping to match (`3082-3090`); failure restores the runtime pin and records `auto-pin-skipped`.
- Boot route restore: `_boot_from_last_good()` publishes `_set_resi_routes(_rotate_routes(_ordered_serving()))` at `1422-1427`, only when `resi_rotate`, after `load_persisted()`/tag finalization and before `_restart_singbox()`; no `_apply_config` and no dial. Empty nodes yield `[]`.
- Rescue: `_rescue_chain_impl()` walks up to 6 candidates (`1980`), hot-switches or rewrites, calls `_verify_served()` for each (`2011`), records failed candidates in `_chain_dead_until` (`2002-2003`), and on total failure restores the previous selector, keeps the pin, and requests a refresh (`2037-2044`). There is no `cands[:1]` and no “stale fallback” branch.
- Tag stability: `assign_stable_tags()` (`railway_manager.py:305-359`) builds `old_tag_by_key`, reserves every surviving `server:port` tag in pass 1, then allocates fresh tags only from the unused set. Tests: `test_assign_stable_tags_reuses_tag_per_server`, `test_new_fast_node_inserted_first_cannot_steal_an_old_tag`.

### Dynamic reproductions

**Tag steal** (`/tmp/repro_tag_steal.py`): old `.11=vpngate-0`, `.99=vpngate-1`; new order `.12 (new), .11, .99`:

```text
mapping: {'12': 'vpngate-2', '11': 'vpngate-0', '99': 'vpngate-1'}
pin owner .11: vpngate-0
```

**Dead-pin rescue to the second verified candidate** (`/tmp/repro_rescue_second.py`: pin `.11`, candidate `.12` fails the served-exit check, candidate `.13` passes):

```text
chain rescue: repro dead pin: vpngate-0 -> vpngate-2
result: rescued
preferred: vpngate-2
dead-memory: ['vpngate-0', 'vpngate-1']
history: ['verify-invalidated', 'chain-rescue']
```

**Switch from unpinned** (targeted test `test_switch_from_unpinned_commits_after_served_exit`): `ok=True`, effective `chain`, `preferred_tag=vpngate-1`, the probe observed `preferred_tag` as `None`, and evidence for `203.0.113.12:443` carries the served exit IP. PASS.

**Mixed inbound down then up** (`test_verify_waits_for_the_mixed_inbound_to_come_back`): `_verify_served(budget=5.0)` returned `(True, '203.0.113.7', 40, True)` after retries. PASS.

**Unknown probe** (`test_unknown_chain_probe_does_not_increment_death_streaks`): three ticks return `pinned`, `_chain_fail_streak=0`, `_pinned_fail_streak=0`, pin health `unknown`. PASS.

**Serving single probe** (`/tmp/repro_probe_dupcn.py`): `dial_calls=[]`, `ms=None`, duplicate-cn error. PASS (after fix).

**Auto-pin vs refresh** (`/tmp/repro_autopin_race.py`): `preferred=None`, `pin jumped=False`. PASS (after fix).

**Boot-from-last-good route restore** (`/tmp/repro_boot_routes.py`): populated boot restores `[('vpngate-0', 41000), ('vpngate-1', 41001)]`, pool equal, two endpoint tags visible and `resi.inbounds=2`; empty nodes yield `routes=[]`, `pool=[]`, `endpoints=[]`, `resi.inbounds=0`, no exception. PASS (task-12).

### Security and operations

- `_authorized()` (`railway_manager.py:864-878`): length check, then `secrets.compare_digest` on UTF-8 bytes.
- `_http_response()` (`railway_manager.py:431-445`) sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Runtime check: `GET /ui` 200 and body identical to `UI_HTML`; `GET /api/status` without/wrong token 401; valid token 200; `GET /healthz` 503 with the same headers (no sing-box in the check).
- `start.sh:80-91`: the sidecar starts only when the binary exists and `PROBE_SERVICE != 0`; a quick exit is logged and `PROBE_PID=""`, execution continues. `trap _term TERM INT` (`63`) and `trap _cleanup EXIT` (`75`) terminate/wait for the sidecar.
- Dockerfile: Go builder stage `golang:1.27-alpine` (line 27), `go build ./cmd/vpngate-probe` (`32-33`) and `./cmd/vpngate-edge` (`34`), runtime copies `probe_client.py`, `www`, `start.sh` (`55-61`), and both built binaries. `go.mod` has no third-party modules (`go list -m all` returns only the module).
- CI: `.github/workflows/test-combined.yml` is new, runs `go test ./...` and `go vet ./...` only; `git diff -- .github/workflows/` is empty for `unit-tests.yml`.

---

## Residual risks (not counted as FAIL)

The former boot-from-last-good empty-route risk is resolved by task-12 (item 29); populated and empty boots now publish the correct route table.

1. **Evidence is memory-only.** `_node_evidence` starts empty after every restart/boot-from-last-good; the UI shows `unknown` until a probe runs. This is “unknown is not death” by design, but a freshly booted process has no exit proof for its persisted pin.
2. **Docker image build was not run.** The Dockerfile/Go build stage was inspected statically and `go test`/`go vet` ran on the host, but no `docker build` or linux/amd64 cross-build was executed in this verification.
3. **Tag-remap branch has no committed test.** The new test covers the `_nodes_rev` branch; the tag-remap branch is covered by `/tmp/repro_autopin_race.py` but not by a repository test. Adding one would lock the second guard in place.
4. **Plain `git diff --check` is noisy for this repo.** Every added CRLF line is reported; only `git -c core.whitespace=cr-at-eol diff --check` is meaningful here. The real-trailing-whitespace scan is 0.
5. **Auto-pin skips on any `_nodes_rev` change.** A refresh that lands during verification defers the auto-pin to the next probe even when the candidate is unchanged. This is conservative and safe, not a correctness defect.
6. **Collision loops can overflow at port 65535.** If a reserved listener occupies 65535 and `EDGE_METRICS_PORT`/`ADMIN_PORT` starts there, the increment produces 65536 (`EDGE_METRICS_PORT=65535` + `PROBE_LISTEN=127.0.0.1:65535` -> metrics 65536; `ADMIN_PORT=65535` + that probe -> admin 65536). All requested cases and defaults are unaffected; a range guard or explicit error would close this extreme config.
7. **A hot pin change cannot update the already-running sing-box's on_demand flags.** `_reconcile_persistent_tags()` deliberately rewrites only the config and `last_good`; it does not restart, so the current process keeps the old per-endpoint session behavior until its next restart. The file and all future starts are correct. This is the intended trade-off to avoid dropping live connections.
8. **Persistent-tag reconciliation is best-effort.** If `_config_lock` is busy for 5s, the config is malformed, or the temp-file write fails, the reconcile logs and returns False; the hot switch still succeeds and the on-disk `on_demand` flags remain stale until a later rewrite/hot switch. This is observable in logs, not silent.
9. **Auto-pin hot-reconcile has no committed test.** Manual and rescue hot switches are covered by repository tests; the auto-pin hot path was verified with an ad-hoc script in this pass. Adding the auto-pin case would close the last coverage gap.
10. **The health-loop environment policy is mixed.** `CHAIN_SETTLE_GRACE`/`FAST_DELAY_TIMEOUT_MS` clamp out-of-range values while `FAST_HEALTH_INTERVAL`/`DEEP_HEALTH_INTERVAL` raise via `_int_env`. Tests pin the current behavior; operators see clamping for some variables and startup failure for others.
