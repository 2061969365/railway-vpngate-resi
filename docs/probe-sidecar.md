# vpngate-probe sidecar contract (v1)

Loopback-only helper for real exit verification. Python remains the single writer of
sing-box config/pins; the sidecar never mutates configuration, never selects a proxy,
and never starts sing-box.

## Runtime

`start.sh` starts the sidecar when `PROBE_SERVICE` is not `0` and the binary exists;
launch failure is non-fatal (the manager keeps its Python fallback). Logs go to
`/tmp/probe.log`, and SIGTERM triggers a graceful shutdown.

| Env | Default | Meaning |
|---|---|---|
| `PROBE_SERVICE` | `1` | `0` disables startup. The Python client also treats `false`/`no`/`off` as disabled. |
| `PROBE_LISTEN` | `127.0.0.1:39001` | Listen address. Must be loopback (`localhost` or a loopback IP); anything else is rejected at startup. The Python client also uses it as its base URL. |
| `PROBE_TOKEN` | empty | When set, every `/v1/*` request needs `Authorization: Bearer <token>`. |
| `CLASH_URL` | `http://127.0.0.1:9090` | sing-box Clash API used by `/v1/health` and `/v1/delay`. |
| `CLASH_SECRET` | empty | Clash API secret. |
| `PROBE_DEFAULT_TIMEOUT_MS` | `8000` | Default budget for `/v1/exit` and `/v1/delay` when the request omits `timeout_ms`. |
| `PROBE_CONCURRENCY` | `8` | Bound for the Clash delay fan-out. |

There is no `PROBE_URL`: both the listener and the Python client read `PROBE_LISTEN`
(the client prepends `http://` when no scheme is given). Request bodies are capped at
1 MiB and `timeout_ms` at 120000.

## GET /v1/health

```json
{"ok": true, "version": "dev", "clash": true}
```

`clash` is true when `GET {CLASH_URL}/version` answers 200.

## POST /v1/exit

Fetch the real exit IP through a local sing-box mixed inbound (HTTP CONNECT).
This is used to verify the **served chain** without opening a second VPNGate
session: VPNGate allows one session per node, so a throwaway dialer
(`duplicate-cn`) would kick the connection that is currently serving traffic.

Request:

```json
{
  "host": "127.0.0.1",
  "port": 40000,
  "username": "u",
  "password": "p",
  "timeout_ms": 8000
}
```

Response 200:

```json
{"ok": true, "exit_ip": "203.0.113.7", "ms": 412, "target": "api.ipify.org"}
```

Failure: 200 with `{"ok": false, "error": "no exit ip", "ms": null}` (the caller
must treat it as "not verified", not as an outage). 400 for malformed input.
The implementation tries these targets in order within one timeout budget:
`api.ipify.org/?format=text`, `icanhazip.com/`, `ifconfig.me/ip`,
`ipinfo.io/ip`, `cloudflare.com/cdn-cgi/trace` (parse `ip=`).

## POST /v1/delay

Real end-to-end liveness of named outbounds through the sing-box Clash API
(`GET /proxies/{tag}/delay`). It does not switch/select anything.

Request:

```json
{"tags": ["vpngate-1", "vpngate-2"], "url": "https://www.gstatic.com/generate_204", "timeout_ms": 5000}
```

Response 200:

```json
{"ok": true, "results": [
  {"tag": "vpngate-1", "alive": true, "ms": 180, "error": null},
  {"tag": "vpngate-2", "alive": false, "ms": null, "error": "timeout"}
]}
```

If the Clash API is unreachable, return 503 `{"ok": false, "error": "clash unavailable"}`.
Bound concurrency with `PROBE_CONCURRENCY`.

A healthy call does **not** probe Clash `/version`: the sidecar only calls it (2 s
cap) after an empty or all-failed delay batch, and only when that batch finished
within a 500 ms budget; a slower batch returns the per-tag `alive=false` rows
directly instead of adding another round trip. The per-tag delay context is
`timeout_ms + 1.5 s`, keeping even the slow path below the Python caller's
`timeout_ms + 2 s` deadline. There is no `/version` cache; there is simply no
per-request round trip.

The manager uses this endpoint for its fast health tick with
`FAST_DELAY_TIMEOUT_MS` (default 2500 ms, clamped 500..5000). `delay_status`
(see below) preserves an explicit `alive=false`; tags absent from the response
stay unknown, never dead.

## Python client (`probe_client.py`)

`ProbeClient.from_env()` reads `PROBE_LISTEN` (base URL) and `PROBE_TOKEN`; it
returns `None` when `PROBE_SERVICE` is `0`/`false`/`no`/`off`. There is no
`PROBE_URL`. It must be fail-open: any transport error/timeout/401/503 or
malformed response returns `None` (two consecutive failures open a 5 s circuit
breaker) so the caller can fall back to the Python implementation. Methods:

- `health() -> dict | None`
- `exit_ip(host, port, username, password, timeout_ms=8000) -> dict | None`
- `delays(tags, url=..., timeout_ms=5000) -> dict[str, int] | None`
  (returns only alive tags mapped to their ms)
- `delay_status(tags, url=..., timeout_ms=5000) -> dict[str, bool] | None`
  (explicit per-tag verdict; missing tags stay unknown)

`RailwayManager.check_fast_health()` runs on a fixed-rate fast tick every
`FAST_HEALTH_INTERVAL` (default 5 s; a check that overruns restarts the cadence
instead of catching up) and calls `delays([pinned_tag])` with
`FAST_DELAY_TIMEOUT_MS` (default 2500 ms, clamped 500..5000). A live delay is a
real request through the existing outbound, so it proves the data channel
without a second VPNGate session. A missing tag immediately triggers the full
served-exit check; when the sidecar itself does not answer and the last deep
check is younger than `DEEP_HEALTH_INTERVAL` (default 30 s), the tick returns
`unknown` and waits instead of spinning a full probe every 5 s. A live tag only
suppresses the deep served-exit check until it is due (`DEEP_HEALTH_INTERVAL`,
default 30 s), so a dead exit cannot hide behind a healthy delay.

Python fallback (must exist even when the sidecar is absent):
`vpngate_to_singbox.measure_mixed_exit_ip(host, port, username, password,
timeout=8) -> (ip, ms) | (None, None)`, HTTP CONNECT + TLS + same exit-IP
targets, no subprocess.

## Rescue candidate prevalidation

With a sidecar, `_rescue_chain_impl` prevalidates up to six candidates with one
batched `/v1/delay` call using `FAST_DELAY_TIMEOUT_MS`. Only an explicit
`alive=false` row removes a candidate from this rescue; unknown/missing tags
(and the no-sidecar path) are still tried. If every candidate is explicitly
delay-dead, the rescue keeps the current pin, triggers a background refresh and
writes nothing — delay failure alone never marks a node dead or rewrites the
config. Candidates that fail the subsequent real served-exit verification go
into the 900 s dead-memory as before.

## Persistent pinned/backup sessions

When `OPENVPN_PERSIST_PINNED=1` (the default), the manager passes
`persistent_tags=[preferred, backup]` to `build_singbox_config()`; those
endpoints are emitted with `on_demand=false`, so they hold their OpenVPN session
while idle. Every other endpoint stays `on_demand=true` and is released on idle
as before. Set `OPENVPN_PERSIST_PINNED=0` to restore on-demand release for all
endpoints. The sidecar never manages sessions; this is purely a
config-generation concern.
