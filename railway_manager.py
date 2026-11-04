"""Simple Railway VPNGate manager: single-$PORT mux + sing-box supervisor (stdlib only)."""
from __future__ import annotations
import builtins
import json
import math
import os
import random
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from vpngate_to_singbox import (
    _safe_print,
    DEFAULT_RESI_PATH,
    DEFAULT_RESI_PORT,
    RESI_ROTATE_BASE,
    build_singbox_config,
    endpoint_remotes,
    measure_exit_ip,
    measure_real_latency,
    measure_resi_exit_ip,
    measure_resi_rotate,
    measure_resi_rotation,
    nodes_to_endpoints,
    primary_server,
    probe_tcp_latency,
    render_resi_username,
    snapshot_to_nodes,
)
# These two land in sibling files owned by other agents. Import them
# fail-open: the manager must keep working with the pure-Python fallbacks
# while they are absent.
try:
    from probe_client import ProbeClient
except Exception:  # pragma: no cover - absent during incremental rollout
    ProbeClient = None
try:
    from vpngate_to_singbox import measure_mixed_exit_ip
except ImportError:  # pragma: no cover - added by the sidecar owner
    measure_mixed_exit_ip = None


DEFAULT_SNAPSHOT_URL = "https://www.vpngate.net/api/iphone/"
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
MIN_PROXY_PASS_LEN = 16
MIN_ADMIN_TOKEN_LEN = 16
PIPE_IDLE_TIMEOUT = 120
MAX_MUX_CONNECTIONS = 100
MAX_POST_CONNECTIONS = 16
DRAIN_TIMEOUT = 10.0
STALE_RUNNING_AFTER = 180.0
# How long a pool member's exit-IP evidence stays "live".
RESI_LIVE_WINDOW = 120.0
HEALTH_CHECK_INTERVAL = 20
PINNED_FAIL_THRESHOLD = 3
# Rotate mode: a chain pin is only useful if the tunnel actually carries
# traffic. VPNGate nodes routinely accept the TCP handshake and then refuse or
# drop the OpenVPN session, so a handshake-only health check stays green while
# /ws-chain exits nowhere - and, because rotate mode never unpins, the chain sat
# dead on that node forever. Two failed end-to-end probes in a row rescue the
# pin to a node with *live evidence*; the cooldown doubles up to the cap so a
# genuinely broken pool cannot turn into a config-restart storm.
CHAIN_FAIL_THRESHOLD = 2
CHAIN_RESCUE_COOLDOWN = 30.0
CHAIN_RESCUE_COOLDOWN_MAX = 120.0
# A freshly pinned endpoint has to establish its OpenVPN session before the
# chain can carry traffic. Judging it inside that window repinned the chain in
# a loop (every probe "failed", the pool walked node by node, and the chain
# never settled) - so a new pin gets this much grace before probes may fail it.
CHAIN_SETTLE_GRACE = 45.0
# A pin that just failed the end-to-end probe must not be picked again for a
# while: with two dead nodes at the top of the ranking the rescue used to
# bounce A -> B -> A forever while the cooldown grew to five minutes, i.e. the
# chain never came back even though the pool still had live nodes.
CHAIN_DEAD_MEMORY = 900.0
# How long real payload through a rotation node counts as "this tunnel works
# right now" evidence for the chain rescue.
CHAIN_ALIVE_WINDOW = 900.0
SUPERVISE_INTERVAL = 10
EXIT_VERIFY_CAP = 3
MAX_SERVING_ENDPOINTS = 100
VERIFY_STALE_AFTER_SEC = 600
# Third path (rotate mode) runtime health. A node that kicks us out without
# ever carrying payload is failing; three of those in a row park it for a while
# so the balancer stops handing it clients, and success restores it at once.
RESI_NODE_STRIKES_DOWN = 3
RESI_NODE_DOWN_BASE = 120.0
RESI_NODE_DOWN_MAX = 900.0
RESI_PAYLOAD_BYTES = 1024
# A node-initiated close within this window, with no payload, is a failure.
# Longer than this the node plausibly held an idle tunnel (keepalive reaping
# closes idle NAT mappings), so it must not feed the strike counter.
RESI_FAIL_MAX_SECONDS = 30.0
# A node that takes the client's bytes but returns none for this long is dead to
# us, even if it never closes: sing-box holds the inbound connection while its
# endpoint keeps dial-probing an IP that RSTs or blackholes, so without this the
# client waits out the whole PIPE_IDLE_TIMEOUT (120s) and calls it "卡死".
# 20s is above the endpoint dial-probe warm-up (~5s) and below a human's
# patience; a rotation target that needs 20s to its first byte is not usable.
RESI_FIRST_BYTE_TIMEOUT = 20.0
SETTINGS_SPEC: dict = {
    "refresh_seconds": {"type": "int", "min": 300, "max": 86400},
    "dial_timeout": {"type": "int", "min": 5, "max": 60},
    "real_topk": {"type": "int", "min": 0, "max": 100},
    "limit": {"type": "int", "min": 0, "max": 100},
    "dial_workers": {"type": "int", "min": 1, "max": 5},
    "full_probe_workers": {"type": "int", "min": 1, "max": 5},
    "probe_workers": {"type": "int", "min": 5, "max": 30},
    "auto_repin": {"type": "bool"},
    "auto_rescue": {"type": "bool"},
    # Residential sticky window. Credentials stay env-only (settings.json is
    # returned verbatim by /api/settings, so it must never hold them).
    "resi_session_ttl": {"type": "int", "min": 0, "max": 86400},
}
def _int_env(env: dict, name: str, default: int, min_val: int | None = None, max_val: int | None = None) -> int:
    raw = env.get(name, default)
    try:
        val = int(str(raw).strip() if isinstance(raw, str) else raw)
    except (TypeError, ValueError):
        _safe_print(f"refusing to start: {name} must be an integer, got {raw!r}", flush=True)
        raise SystemExit(2)
    if min_val is not None and val < min_val:
        _safe_print(f"refusing to start: {name}={val} below minimum {min_val}", flush=True)
        raise SystemExit(2)
    if max_val is not None and val > max_val:
        _safe_print(f"refusing to start: {name}={val} above maximum {max_val}", flush=True)
        raise SystemExit(2)
    return val
def _env_bool(env: dict, name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default
def _build_resi_from_env(env: dict) -> dict | None:
    """Parse the rotating-residential gateway env (None = path disabled).

    Only the gateway address + credentials are accepted here; they never enter
    settings.json because /api/settings returns that file verbatim. Rotation is
    the default (no session parameter); sticky mode additionally needs a
    template that actually carries {session}, otherwise we stay in rotation
    rather than inventing a provider-specific username format.
    """
    gateway = (env.get("RESI_GATEWAY") or "").strip()
    if not gateway:
        return None
    host, _, port_text = gateway.rpartition(":")
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        gateway_port = int(port_text.strip())
    except ValueError:
        gateway_port = 0
    if not host or not 0 < gateway_port < 65536:
        _safe_print(f"refusing to start: RESI_GATEWAY must be host:port, got {gateway!r}", flush=True)
        raise SystemExit(2)
    user = (env.get("RESI_USER") or "").strip()
    password = env.get("RESI_PASS") or ""
    if not user or not password:
        _safe_print("refusing to start: RESI_GATEWAY needs RESI_USER and RESI_PASS", flush=True)
        raise SystemExit(2)
    ttl = _int_env(env, "RESI_SESSION_TTL", 0, 0, 86400)
    template = env.get("RESI_USER_TEMPLATE", "{user}")
    if ttl > 0 and "{session}" not in template:
        _safe_print("warning: RESI_SESSION_TTL>0 but RESI_USER_TEMPLATE has no {session}; staying in rotation mode", flush=True)
    try:
        render_resi_username(user, template, ttl, "probe")
    except ValueError as exc:
        _safe_print(f"refusing to start: {exc}", flush=True)
        raise SystemExit(2)
    return {"server": host, "server_port": gateway_port, "username": user,
            "password": password, "template": template, "session_ttl": ttl,
            "probe_interval": _int_env(env, "RESI_PROBE_INTERVAL", 300, 60, 86400)}
CRASH_BACKOFFS = (5, 10, 20, 40, 300)

# The console lives in www/console.html so this module stays reviewable; the
# loader is cached and anchored to the module directory, and reading with
# newline="" keeps the served bytes identical to the old literal.
_CONSOLE_HTML_PATH = Path(__file__).resolve().parent / "www" / "console.html"
_CONSOLE_HTML_FALLBACK = (
    "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
    "<title>vpngate console</title></head><body>"
    "<h1>console unavailable</h1>"
    "<p>www/console.html could not be read.</p></body></html>"
)


@lru_cache(maxsize=1)
def _load_console_html() -> str:
    """Read the console once, preserving its line endings byte for byte."""
    try:
        with _CONSOLE_HTML_PATH.open("r", encoding="utf-8", newline="") as handle:
            return handle.read()
    except (OSError, UnicodeError):
        return _CONSOLE_HTML_FALLBACK


UI_HTML = _load_console_html()

def default_fetch(url: str, timeout: int = 20) -> str:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"refusing non-https snapshot url: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")
def build_config_from_env(env: dict) -> dict:
    password = env.get("PROXY_PASS", "")
    if not password:
        password = secrets.token_urlsafe(24)
        _safe_print("PROXY_PASS not set, generated a random one", flush=True)
    elif len(password) < MIN_PROXY_PASS_LEN:
        _safe_print(f"refusing to start: PROXY_PASS must be at least {MIN_PROXY_PASS_LEN} chars", flush=True)
        raise SystemExit(2)
    snapshot_url = env.get("SNAPSHOT_URL", DEFAULT_SNAPSHOT_URL)
    raw_mirrors = env.get("SNAPSHOT_URLS", "")
    snapshot_urls = [u.strip() for u in raw_mirrors.split(",") if u.strip()]
    if not snapshot_urls:
        snapshot_urls = [snapshot_url]
    for url in snapshot_urls:
        if urllib.parse.urlsplit(url).scheme != "https":
            _safe_print(f"refusing to start: snapshot url must be https: {url}", flush=True)
            raise SystemExit(2)
    if "ADMIN_TOKEN" not in env or not env["ADMIN_TOKEN"]:
        admin_token = "vpn"
        generated = False
        _safe_print("ADMIN_TOKEN not set, defaulting to 'vpn'", flush=True)
    else:
        admin_token = env["ADMIN_TOKEN"]
        generated = False
        if len(admin_token) < MIN_ADMIN_TOKEN_LEN:
            admin_token = secrets.token_urlsafe(24)
            generated = True
    mixed_port = _int_env(env, "MIXED_PORT", 40000, 1, 65535)
    port = _int_env(env, "PORT", 3000, 1, 65535)
    admin_raw = str(env.get("ADMIN_PORT", "") or "").strip()
    admin_port = _int_env(env, "ADMIN_PORT", port, 1, 65535) if admin_raw else port
    bind_host = "127.0.0.1" if admin_raw else "0.0.0.0"
    edge_metrics_url = str(env.get("EDGE_METRICS_URL", "") or "").strip()
    vless_direct_port = _int_env(env, "VLESS_DIRECT_PORT", 8080, 1, 65535)
    vless_chain_port = _int_env(env, "VLESS_CHAIN_PORT", 8082, 1, 65535)
    resi_port = _int_env(env, "RESI_PORT", DEFAULT_RESI_PORT, 1, 65535)
    resi = _build_resi_from_env(env)
    # Third path, rotating mode: no external gateway, so rotate over the
    # serving endpoints. Needs VLESS_UUID because its inbounds are VLESS+WS.
    resi_rotate = resi is None and bool(env.get("VLESS_UUID", ""))
    if vless_direct_port == vless_chain_port:
        _safe_print(f"refusing to start: VLESS ports collide ({vless_direct_port})", flush=True)
        raise SystemExit(2)
    if resi is not None and not env.get("VLESS_UUID", ""):
        _safe_print("refusing to start: RESI_GATEWAY needs VLESS_UUID (the resi path is a VLESS+WS inbound)", flush=True)
        raise SystemExit(2)
    if resi is not None or resi_rotate:
        if resi_port in {8080, 8081, 8082, 4096, mixed_port, vless_direct_port, vless_chain_port}:
            _safe_print(f"refusing to start: RESI_PORT={resi_port} collides", flush=True)
            raise SystemExit(2)
    if mixed_port in {8080, 8081, 8082, 4096, vless_direct_port, vless_chain_port}:
        _safe_print(f"refusing to start: MIXED_PORT={mixed_port} collides", flush=True)
        raise SystemExit(2)
    reserved = {8080, 8081, 8082, 4096, mixed_port, vless_direct_port, vless_chain_port}
    if resi is not None or resi_rotate:
        reserved.add(resi_port)
    if admin_port in reserved:
        name = "ADMIN_PORT" if admin_raw else "PORT"
        _safe_print(f"refusing to start: {name}={admin_port} collides {sorted(reserved)}", flush=True)
        raise SystemExit(2)
    if not admin_raw and admin_port != 3000:
        _safe_print(f"warning: PORT={admin_port} is not 3000", flush=True)
    return {
        "port": admin_port, "mixed_port": mixed_port, "bind_host": bind_host,
        "edge_metrics_url": edge_metrics_url,
        "username": env.get("PROXY_USER", "u"), "password": password,
        "admin_token": admin_token, "admin_token_generated": generated,
        "snapshot_url": snapshot_url, "snapshot_urls": snapshot_urls,
        "refresh_seconds": _int_env(env, "REFRESH_SECONDS", 3600, 60, 86400),
        "limit": _int_env(env, "LIMIT", 100, 0, 100),
        "real_topk": _int_env(env, "REAL_TOPK", 30, 0, 100),
        "dial_workers": _int_env(env, "DIAL_WORKERS", 2, 1, 5),
        "full_probe_workers": _int_env(env, "FULL_PROBE_WORKERS", 3, 1, 5),
        "probe_workers": _int_env(env, "PROBE_WORKERS", 15, 1, 30),
        "dial_timeout": _int_env(env, "DIAL_TIMEOUT", 15, 5, 60),
        "auto_rescue": _env_bool(env, "AUTO_RESCUE", True),
        "health_check_interval": _int_env(env, "HEALTH_CHECK_INTERVAL", 20, 5, 300),
        "max_mux_connections": _int_env(env, "MAX_MUX_CONNECTIONS", 100, 1, 1000),
        # Loopback Clash API: how the chain is repinned without rewriting the
        # config / restarting sing-box. 0 disables the hot switch.
        "clash_api_port": _int_env(env, "CLASH_API_PORT", 9090, 0, 65535),
        "data_dir": env.get("DATA_DIR") or env.get("RAILWAY_VOLUME_MOUNT_PATH") or ".",
        "vless_uuid": env.get("VLESS_UUID", ""),
        "vless_direct_port": vless_direct_port, "vless_chain_port": vless_chain_port,
        "resi": resi, "resi_port": resi_port, "resi_rotate": resi_rotate,
        "resi_path": env.get("RESI_PATH", DEFAULT_RESI_PATH),
        "tunnel_token": env.get("TUNNEL_TOKEN", ""),
        "cloudflared_bin": env.get("CLOUDFLARED_BIN", "cloudflared"),
        "disguise_path": env.get("DISGUISE_PATH", ""),
    }
def assign_stable_tags(nodes: list[dict], old_nodes: list[dict], tag_prefix: str = "vpngate") -> None:
    """Give every node a tag that is stable per server:port.

    Two passes on purpose: the old tag of every *surviving* server:port is
    reserved before any node gets a tag. The previous single pass let a new
    fast node inserted at the top of the snapshot take ``vpngate-0`` and only
    then discovered that the old ``vpngate-0`` owner was still present - the
    owner was renamed to a fresh tag, so the persisted pin silently jumped to
    the new server after a refresh.
    """
    def _key(node: dict) -> str:
        return f"{node.get('server')}:{node.get('server_port')}"

    old_tag_by_key: dict[str, str] = {}
    for old in old_nodes:
        old_ep = old.get("endpoint") or {}
        if old_ep.get("tag"):
            old_tag_by_key.setdefault(_key(old), old_ep["tag"])
    # Pass 1: reserve the old tag for every key that survives this refresh.
    reserved_by_key: dict[str, str] = {}
    reserved_tags: set[str] = set()
    for node in nodes:
        key = _key(node)
        tag = old_tag_by_key.get(key)
        if tag and tag not in reserved_tags:
            reserved_by_key[key] = tag
            reserved_tags.add(tag)
    used: set[str] = set(reserved_tags)
    counter = 0
    def _fresh() -> str:
        nonlocal counter
        while f"{tag_prefix}-{counter}" in used:
            counter += 1
        tag = f"{tag_prefix}-{counter}"
        counter += 1
        return tag
    claimed_reserved: set[str] = set()
    for node in nodes:
        endpoint = node.get("endpoint") or {}
        key = _key(node)
        tag = endpoint.get("tag") or ""
        reserved = reserved_by_key.get(key)
        if reserved and reserved not in claimed_reserved:
            endpoint["tag"] = reserved
            node["endpoint"] = endpoint
            claimed_reserved.add(reserved)
            continue
        if tag and tag not in used:
            # An explicit tag survives only when no surviving key owns it.
            used.add(tag)
            continue
        fresh = _fresh()
        endpoint["tag"] = fresh
        node["endpoint"] = endpoint
        used.add(fresh)
def _rss_mb() -> float | None:
    try:
        import resource
    except ImportError:
        return None
    try:
        scale = 1024.0 if os.name == "posix" and not sys.platform.startswith("darwin") else (1024.0 * 1024.0)
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / scale, 1)
    except OSError:
        return None
def _cpu_times(stat_path: str = "/proc/stat") -> tuple[int, int] | None:
    try:
        with open(stat_path, encoding="utf-8") as handle:
            first = handle.readline().split()
    except OSError:
        return None
    if len(first) < 9 or first[0] != "cpu":
        return None
    try:
        nums = [int(v) for v in first[1:9]]
    except ValueError:
        return None
    return nums[3] + nums[4], sum(nums)
def _cpu_pct(old: tuple[int, int], new: tuple[int, int]) -> float | None:
    total_delta = new[1] - old[1]
    if total_delta <= 0:
        return None
    return round((1.0 - (new[0] - old[0]) / total_delta) * 100.0, 1)
def _cpu_model(cpuinfo_path: str = "/proc/cpuinfo") -> str | None:
    try:
        with open(cpuinfo_path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    _, _, name = line.partition(":")
                    name = name.strip()
                    if name:
                        return name
    except OSError:
        return None
    return None
def _mem_pct(meminfo_path: str = "/proc/meminfo") -> float | None:
    total = available = None
    try:
        with open(meminfo_path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1])
                if total is not None and available is not None:
                    break
    except (OSError, ValueError, IndexError):
        return None
    if not total:
        return None
    return round((total - available) / total * 100.0, 1)
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def _query_param(query: str, name: str) -> str:
    """Value of one query parameter ("" when absent); no multi-value support."""
    for part in (query or "").split("&"):
        key, _, value = part.partition("=")
        if key.strip() == name:
            return urllib.parse.unquote(value.strip())
    return ""
def _http_response(status: str, content_type: str, body: bytes, extra_headers: dict | None = None) -> bytes:
    lines = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Content-Security-Policy: frame-ancestors 'none'",
        "Referrer-Policy: no-referrer",
        "Cache-Control: no-store",
    ]
    if extra_headers:
        lines.extend(f"{name}: {value}" for name, value in extra_headers.items())
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body
def _forward(source: socket.socket, dest: socket.socket) -> int:
    moved = 0
    try:
        while True:
            try:
                chunk = source.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            dest.sendall(chunk)
            moved += len(chunk)
    except OSError:
        pass
    return moved
def _forward_counted(source: socket.socket, dest: socket.socket, sink: list,
                     ended: list | None = None, slot: int = 0,
                     timed_out: list | None = None) -> int:
    """Copy one direction and record progress for the health watchdog."""
    moved = 0
    try:
        while True:
            try:
                chunk = source.recv(65536)
            except socket.timeout:
                if timed_out is not None:
                    timed_out[slot] = True
                break
            if not chunk:
                break
            dest.sendall(chunk)
            moved += len(chunk)
            sink[0] = moved
    except OSError:
        pass
    finally:
        if ended is not None:
            ended[slot] = time.monotonic()
    return moved
def _pump_pair(a: socket.socket, b: socket.socket, started: float) -> dict:
    """Byte-copy both directions and tear down as soon as either side ends.

    Waiting only for a->b (the original code) left the client hanging for the
    whole idle timeout whenever the *upstream* dropped the connection first -
    which is exactly what a dead VPNGate node does, so a dead node looked like
    a stall instead of a fast failure the client could retry.

    It also enforces a first-byte deadline: sing-box holds an inbound
    connection while the endpoint is "not ready yet" (dial-probe still trying a
    dead IP), so a node can swallow the client's request and answer nothing for
    a minute or more. Once the client has sent bytes and the node has returned
    none for RESI_FIRST_BYTE_TIMEOUT, the node is dead to us.
    """
    up = [0]; down = [0]; ended = [0.0, 0.0]; timed_out = [False, False]
    first_byte_stalled = [False]
    events = [threading.Event(), threading.Event()]
    def _run(src, dst, sink, slot: int) -> None:
        try:
            _forward_counted(src, dst, sink, ended, slot, timed_out)
        finally:
            events[slot].set()
    first = threading.Thread(target=_run, args=(a, b, up, 0), daemon=True)
    second = threading.Thread(target=_run, args=(b, a, down, 1), daemon=True)
    first.start(); second.start()
    deadline = started + PIPE_IDLE_TIMEOUT + 5
    first_byte_deadline = started + RESI_FIRST_BYTE_TIMEOUT
    while not (events[0].is_set() or events[1].is_set()):
        now = time.monotonic()
        if now > deadline:
            break
        if now > first_byte_deadline and up[0] > 0 and down[0] == 0:
            first_byte_stalled[0] = True
            break
        time.sleep(0.05)
    if events[0].is_set() or events[1].is_set():
        # Flush grace for the direction that is still draining; a watchdog
        # teardown has nothing to drain, so it must not wait at all.
        finished = 0 if events[0].is_set() else 1
        events[1 - finished].wait(timeout=1.0)
    for sock in (a, b):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    first.join(timeout=2); second.join(timeout=2)
    if first.is_alive() or second.is_alive():
        # shutdown() does not reliably wake a blocked recv on every platform;
        # closing does, and both directions are already dead at this point.
        for sock in (a, b):
            try:
                sock.close()
            except OSError:
                pass
        first.join(timeout=2); second.join(timeout=2)
    return {"up": up[0], "down": down[0], "ended": ended,
            "upstream_first": bool(ended[0] and ended[1] and ended[0] <= ended[1]),
            "timed_out": timed_out,
            "first_byte_stalled": first_byte_stalled[0],
            "elapsed": max(0.0, time.monotonic() - started)}
def _reap_process(proc, handle=None) -> None:
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass
def _is_partial_token(data: bytes) -> bool:
    if not data:
        return False
    for token in HTTP_METHODS + (b"CONNECT ",):
        if len(data) < len(token) and token.startswith(data):
            return True
    return False
def _write_private_json(path: str, obj: dict) -> None:
    tmp_path = f"{path}.tmp-{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2)
        handle.write("\n")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    os.replace(tmp_path, path)
_DISGUISE_CACHE: dict[str, tuple[float, bytes | None]] = {}
def classify_first_bytes(data: bytes) -> str:
    if not data:
        return "unknown"
    if data[0] == 0x05:
        return "socks5"
    if data.startswith(b"CONNECT "):
        return "http-connect"
    if data.startswith(HTTP_METHODS):
        return "http"
    return "unknown"

class RailwayManager:
    def __init__(self, port: int = 3000, mixed_port: int = 40000, username: str = "u", password: str = "p",
        admin_token: str | None = None, snapshot_url: str = DEFAULT_SNAPSHOT_URL, snapshot_urls: list | None = None,
        refresh_seconds: int = 3600, limit: int | None = 100, real_topk: int = 30, dial_fn=None, dial_workers: int = 2,
        full_probe_workers: int = 2, probe_workers: int = 15, dial_timeout: int = 15, auto_repin: bool = False,
        auto_rescue: bool = True, verify_fn=None, vless_uuid: str = "", vless_direct_port: int = 8080,
        vless_chain_port: int = 8082, vless_direct_path: str = "/ws-node", vless_chain_path: str = "/ws-chain",
        resi: dict | None = None, resi_port: int = DEFAULT_RESI_PORT, resi_path: str = DEFAULT_RESI_PATH,
        resi_rotate: bool = False, resi_session_ttl: int = 0,
        tunnel_token: str = "", cloudflared_bin: str = "cloudflared", disguise_path: str = "",
        config_path: str = "singbox-railway.json", nodes_path: str = "nodes.json", state_path: str = "state.json",
        settings_path: str | None = None, singbox_bin: str = "sing-box", start_singbox: bool = True,
        auto_refresh: bool = True, fetch_on_start: bool = True, retry_delays: tuple = (5, 10),
        max_mux_connections: int = MAX_MUX_CONNECTIONS, health_check_interval: int = HEALTH_CHECK_INTERVAL, fetcher=None,
        clash_api_port: int = 9090, edge_metrics_url: str = "",
        bind_host: str = "0.0.0.0") -> None:
        self.port = port; self.mixed_port = mixed_port; self.username = username; self.password = password
        self.admin_token = admin_token; self.snapshot_url = snapshot_url
        self.snapshot_urls = list(snapshot_urls) if snapshot_urls else [snapshot_url]
        self.refresh_seconds = refresh_seconds; self.limit = limit; self.real_topk = real_topk
        self.dial_fn = (dial_fn if dial_fn is not None else (lambda node: measure_real_latency(node["endpoint"], self.singbox_bin, self.dial_timeout)))
        self.dial_workers = dial_workers; self.full_probe_workers = max(1, full_probe_workers); self.probe_workers = probe_workers
        self.dial_timeout = dial_timeout; self.auto_repin = auto_repin; self.auto_rescue = auto_rescue
        self._verify_custom = verify_fn is not None
        self.verify_fn = (verify_fn if verify_fn is not None else (lambda endpoint: measure_exit_ip(endpoint, self.singbox_bin, self.dial_timeout)))
        self.config_path = config_path; self.nodes_path = nodes_path; self.state_path = state_path; self.settings_path = settings_path
        self.last_good_path = f"{config_path}.last-good"; self.singbox_bin = singbox_bin
        self.want_singbox = start_singbox; self.auto_refresh = auto_refresh; self.fetch_on_start = fetch_on_start
        self.retry_delays = retry_delays; self.fetcher = fetcher or default_fetch
        self.vless_uuid = vless_uuid; self.vless_direct_port = vless_direct_port; self.vless_chain_port = vless_chain_port
        self.vless_direct_path = vless_direct_path; self.vless_chain_path = vless_chain_path
        self.resi = dict(resi) if resi else None; self.resi_port = resi_port; self.resi_path = resi_path
        self.resi_session_ttl = int(resi_session_ttl or 0)
        self.resi_rotate = bool(resi_rotate)
        self._resi_routes: list[tuple[str, int]] = []; self._resi_cursor = 0; self._resi_listener = None
        self._resi_health: dict[str, dict] = {}
        self._resi_session_id = ""; self._resi_session_started = 0.0; self._resi_lock = threading.Lock(); self._resi_probe_lock = threading.Lock()
        self.tunnel_token = tunnel_token; self.cloudflared_bin = cloudflared_bin; self.disguise_path = disguise_path
        self.edge_metrics_url = edge_metrics_url
        self.bind_host = bind_host
        self._cloudflared_proc = None; self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = False
        # Optional loopback probe sidecar (docs/probe-sidecar.md). Fail-open:
        # every caller still has the pure-Python fallback.
        self.probe = None
        if ProbeClient is not None:
            try:
                self.probe = ProbeClient.from_env()
            except Exception:
                self.probe = None
        # Per-node liveness/exit evidence keyed by "server:port". It is the
        # only evidence that survives a refresh (tags alone are not enough:
        # a tag can be recycled after its server vanished).
        self._node_evidence: dict[str, dict] = {}
        self._nodes: list[dict] = []; self._first_seen: dict[str, str] = {}
        self._nodes_rev = 0
        self._cpu_model = _cpu_model(); self._cpu_cores = os.cpu_count(); self._cpu_last = None
        self._fail_streak = 0; self._pinned_fail_streak = 0; self._rescue_round = 0; self._crash_streak = 0; self._retry_after = 0.0; self._mixed_fail_streak = 0; self._mixed_retry_after = 0.0; self._health_mixed_streak = 0; self._refresh_generation = 0
        self._chain_fail_streak = 0; self._chain_rescue_at = 0.0; self._chain_rescue_attempts = 0
        # 0 = no pin yet, so the very first health tick is not treated as a
        # warm-up window (a restored pin gets a stamp in load_persisted).
        self._chain_pin_at = 0.0
        # Pin whose dead handshake was already announced as "standby carries the
        # chain": the handshake failure repeats every tick, the history line must
        # not.
        self._pinned_standby_noted: str | None = None
        # Chain rescue evidence. `_resi_payload_at` = last time real payload
        # came through a rotation node (proof its tunnel works right now);
        # `_chain_dead_until` = nodes that just failed the chain probe and must
        # not be re-pinned while the memory lasts (see _rescue_chain).
        self._resi_payload_at: dict[str, float] = {}
        # Weaker but earlier proof: the node did return *some* bytes. Enough to
        # prefer it over a node that merely has a stale latency number.
        self._resi_ok_at: dict[str, float] = {}
        self._chain_dead_until: dict[str, float] = {}
        # Runtime pin switching through the sing-box Clash API. Rewriting the
        # config and restarting sing-box for every repin was the collateral
        # damage that took the rotation down with the chain; a selector written
        # with all serving tags as candidates can be moved with one loopback
        # HTTP call instead (design §12.9g). 0 disables the hot path.
        self.clash_api_port = int(clash_api_port or 0)
        self.clash_api_secret = os.urandom(16).hex()
        self._clash_ready_at = 0.0
        self._clash_switch_lock = threading.Lock()
        # Serializes a whole manual switch / rescue: mutate selector, verify
        # the served exit, then commit. Lock order is pin_switch -> config ->
        # clash; the health thread can never start a rescue mid-switch.
        self._pin_switch_lock = threading.RLock()
        self._lock = threading.RLock(); self._refresh_lock = threading.Lock(); self._config_lock = threading.Lock()
        if resi:
            resi_status = {"enabled": True, "mode": ("sticky" if self.resi_session_ttl > 0 else "rotation"),
                "host": resi["server"], "port": resi["server_port"], "path": resi_path,
                "sticky_ttl": self.resi_session_ttl, "session_age": 0, "state": "unknown",
                "exit_ip": None, "ms": None, "checked_at": None, "error": None,
                "last_probe": {"state": "idle", "ips": [], "distinct": 0, "rotating": None, "checked_at": None}}
        elif self.resi_rotate:
            resi_status = {"enabled": True, "mode": "rotate", "listen": "0.0.0.0",
                "port": resi_port, "path": resi_path, "nodes": 0, "cursor": 0,
                "inbounds": 0, "pool": 0, "down": 0,
                "state": "unknown", "exit_ip": None, "ms": None, "checked_at": None, "error": None,
                "last_probe": {"state": "idle", "ips": [], "distinct": 0, "rotating": None, "checked_at": None}}
        else:
            resi_status = {"enabled": False}
        self.status: dict = {"endpoints": [], "countries": [], "preferred_tag": None, "backup_tag": None, "auto_pinned": False,
            "refresh_history": [], "refresh_ok": 0, "refresh_fail": 0, "last_refresh": None, "last_error": None, "started_at": None,
            "proxy": f"127.0.0.1:{mixed_port}", "traffic": {"connections": 0, "bytes_up": 0, "bytes_down": 0},
            "full_probe": {"state": "idle", "done": 0, "total": 0}, "refresh_job": {"state": "idle", "started_at": None, "ok": None, "error": None}, "probe": {"state": "idle", "tag": None, "ms": None, "error": None},
            "verify": {"state": "idle", "exit_ip": None, "ms": None, "via_tag": None, "error": None, "checked_at": None},
            "tunnel": {"state": "off"}, "vless": ({"uuid": vless_uuid, "direct_path": vless_direct_path, "chain_path": vless_chain_path} if vless_uuid else None),
            "chain_switch": {"mode": ("clash" if (clash_api_port and resi_rotate) else "config"),
                             "clash_port": int(clash_api_port or 0), "ready": False, "switches": 0},
            "resi": resi_status}
        self.status["pin_health"] = {"state": "unknown", "fail_streak": 0, "checked_at": None,
            "exit_ip": None, "error": None,
            "chain_switch": {"mode": self.status["chain_switch"]["mode"],
                             "ready": False, "switches": 0}}
        self._full_probe_thread = None; self._single_probe_thread = None; self._verify_thread = None; self._verify_generation = 0; self._refresh_thread = None
        self._stop_event = threading.Event(); self._mux_slots = threading.BoundedSemaphore(max_mux_connections); self._mux_inflight = 0
        # A fourth-path storm must not starve the first two paths. Every mux
        # connection (all three paths) takes one global slot and a full table
        # drops the new connection outright, so without a cap the rotation could
        # eat all 100 and /ws-node + /ws-chain would look dead - the same
        # "one dies, two die" symptom from the other direction.
        self.max_mux_connections = max_mux_connections
        self._resi_mux_cap = max(1, max_mux_connections - max(1, max_mux_connections // 5))
        self._resi_mux_slots = threading.BoundedSemaphore(self._resi_mux_cap)
        self._resi_mux_throttled = 0
        self.status["resi"]["mux_limit"] = self._resi_mux_cap
        self.status["resi"]["throttled"] = 0
        self._post_slots = threading.BoundedSemaphore(MAX_POST_CONNECTIONS); self._health_check_interval = health_check_interval
        self._listener = None; self._singbox_proc = None; self._stderr_handle = None; self.bound_port = port
        self.load_settings()
        if self.resi is not None:
            # settings.json overrides env for the ttl, so re-sync the reported mode.
            self._set_resi(mode=self._resi_mode(), sticky_ttl=self.resi_session_ttl)
    def start(self) -> int:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.bind_host, self.port))
        self._listener.listen(128)
        self._listener.settimeout(1.0)
        self.bound_port = self._listener.getsockname()[1]
        self.status["started_at"] = _now_iso()
        threading.Thread(target=self._accept_loop, daemon=True, name="accept-loop").start()
        if self.auto_refresh:
            threading.Thread(target=self._refresh_loop, daemon=True, name="refresh-loop").start()
        threading.Thread(target=self._supervise_loop, daemon=True, name="supervise-loop").start()
        threading.Thread(target=self._health_monitor_loop, daemon=True, name="health-monitor").start()
        if self.resi is not None or self.resi_rotate:
            threading.Thread(target=self._resi_probe_loop, daemon=True, name="resi-probe").start()
        if self.resi_rotate:
            threading.Thread(target=self._resi_accept_loop, daemon=True, name="resi-balancer").start()
        if self.fetch_on_start:
            threading.Thread(target=self._initial_refresh, daemon=True, name="initial-refresh").start()
        self._start_cloudflared()
        _safe_print(f"listening on {self.bind_host}:{self.bound_port}, backend 127.0.0.1:{self.mixed_port}", flush=True)
        return self.bound_port
    def _initial_refresh(self) -> None:
        if self._boot_from_last_good():
            self._start_refresh_bg()
            return
        if self._start_refresh_bg():
            return
        if not self._boot_from_last_good():
            for delay in (30,):
                if self._stop_event.is_set():
                    return
                time.sleep(delay)
                if self._boot_from_last_good():
                    self._start_refresh_bg()
                    return
                if self._start_refresh_bg():
                    return
    def _drain(self, timeout: float = DRAIN_TIMEOUT) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            with self._lock:
                if self._mux_inflight <= 0:
                    return True
            time.sleep(0.05)
        with self._lock:
            return self._mux_inflight <= 0
    def _log(self, text: str, flush: bool = True) -> None:
        """Log from a background thread, but only while the manager runs.

        A daemon thread that logs after the manager was stopped (or while the
        interpreter is finalizing) can race the interpreter shutdown for the
        stdout lock: CPython 3.13 then aborts the whole process with SIGABRT
        (`_enter_buffered_busy`). `stop()` sets `_stop_event`, so that is
        the signal to stay quiet.
        """
        if self._stop_event.is_set() or sys.is_finalizing():
            return
        _safe_print(text, flush=flush)

    def stop(self) -> None:
        self._stop_event.set()
        balancer = self._resi_listener
        if balancer is not None:
            try:
                balancer.close()
            except OSError:
                pass
            self._resi_listener = None
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        drained = self._drain()
        with self._lock:
            remaining = self._mux_inflight
        _safe_print(f"shutdown: mux drain {'done' if drained else 'timeout'} ({remaining} in flight)", flush=True)
        self._terminate_singbox()
        self._terminate_cloudflared()
    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop_event.is_set():
            try:
                client, _ = self._listener.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
    def _handle_client(self, client: socket.socket) -> None:
        held = False
        try:
            if not self._mux_slots.acquire(blocking=False):
                return
            held = True
            client.settimeout(10)
            peek = client.recv(4096)
            if not peek:
                return
            kind = classify_first_bytes(peek)
            if kind == "unknown" and _is_partial_token(peek):
                deadline = time.monotonic() + 2
                while len(peek) < 4096 and time.monotonic() < deadline:
                    try:
                        chunk = client.recv(4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    peek += chunk
                    kind = classify_first_bytes(peek)
                    if kind != "unknown" or not _is_partial_token(peek):
                        break
            if kind in ("socks5", "http-connect"):
                with self._lock:
                    self.status["traffic"]["connections"] += 1
                    self._mux_inflight += 1
                try:
                    self._pipe_to_backend(client, peek)
                finally:
                    with self._lock:
                        self._mux_inflight -= 1
            elif kind == "http":
                self._handle_http(client, peek)
        except OSError:
            pass
        finally:
            if held:
                try:
                    self._mux_slots.release()
                except Exception:
                    pass
            try:
                client.close()
            except OSError:
                pass

    def _authorized(self, headers: dict) -> bool:
        if not self.admin_token:
            return True
        provided = headers.get("authorization", "")
        if not isinstance(provided, str):
            return False
        expected = f"Bearer {self.admin_token}"
        try:
            provided_bytes = provided.encode("utf-8")
            expected_bytes = expected.encode("utf-8")
        except UnicodeError:
            return False
        if len(provided_bytes) != len(expected_bytes):
            return False
        return secrets.compare_digest(provided_bytes, expected_bytes)
    @staticmethod
    def _parse_request(data: bytes):
        try:
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            path, _, query = target.partition("?")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
            return method.upper(), path, query, headers, body
        except (ValueError, IndexError):
            return None
    def _handle_http(self, client: socket.socket, peek: bytes) -> None:
        data = peek
        while b"\r\n\r\n" not in data and len(data) < 65536:
            try:
                chunk = client.recv(4096)
            except OSError:
                return
            if not chunk:
                break
            data += chunk
        try:
            head_part, _, after = data.partition(b"\r\n\r\n")
            clen = None
            for hline in head_part.decode("latin-1").split("\r\n")[1:]:
                if ":" not in hline:
                    continue
                hn, _, hv = hline.partition(":")
                if hn.strip().lower() == "content-length":
                    try:
                        clen = int(hv.strip())
                    except ValueError:
                        clen = None
                    break
            if clen is not None and clen >= 0 and len(after) < clen:
                want = min(clen, 1024 * 1024)
                client.settimeout(10)
                while len(after) < want:
                    try:
                        chunk = client.recv(min(4096, want - len(after)))
                    except OSError:
                        break
                    if not chunk:
                        break
                    after += chunk
                    data = head_part + b"\r\n\r\n" + after
        except Exception:
            pass
        parsed = self._parse_request(data)
        if parsed is None:
            return
        method, path, query, headers, body = parsed
        if method == "GET":
            # A Cloudflare Tunnel catch-all (/* -> $PORT) must carry the VLESS
            # paths too, otherwise adding a path means editing the tunnel
            # ingress rules - and forgetting that looks exactly like "the
            # third path is broken while the other two work". Forward by path
            # before the admin gate: these are public VLESS+WS endpoints
            # protected by the UUID, not API calls.
            route = self._vless_path_route(path)
            if route is not None:
                kind, port = route
                if kind == "rotate":
                    if not self._resi_mux_slots.acquire(blocking=False):
                        with self._lock:
                            self._resi_mux_throttled += 1
                            self.status["resi"]["throttled"] = self._resi_mux_throttled
                        self._record_history(
                            "resi-mux-throttled",
                            f"rotation holds {self._resi_mux_cap} mux slots, "
                            f"{self.max_mux_connections - self._resi_mux_cap} stay reserved for node/chain")
                        return
                    try:
                        self._handle_resi_client(client, prefix=data, hold_slot=False)
                    finally:
                        try:
                            self._resi_mux_slots.release()
                        except Exception:
                            pass
                else:
                    self._pipe_to_backend(client, data, port=port)
                return
        if path == "/healthz" and method == "GET":
            if self._serving_ok():
                client.sendall(_http_response("200 OK", "text/plain", b"ok"))
            else:
                client.sendall(_http_response("503 Service Unavailable", "text/plain", b"not ready"))
            return
        if path == "/" and method == "GET":
            b = self._disguise_body()
            client.sendall(_http_response("200 OK", "text/html; charset=utf-8", b if b is not None else UI_HTML.encode()))
            return
        if path == "/ui" and method == "GET":
            client.sendall(_http_response("200 OK", "text/html; charset=utf-8", UI_HTML.encode()))
            return
        if not self._authorized(headers):
            client.sendall(_http_response("401 Unauthorized", "text/plain", b"missing or invalid admin token"))
            return
        if path == "/api/status" and method == "GET":
            client.sendall(_http_response("200 OK", "application/json", json.dumps(self.status_snapshot()).encode()))
        elif path == "/api/logs" and method == "GET":
            limit = 50
            for part in query.split("&"):
                name, _, value = part.partition("=")
                if name.strip() == "lines":
                    try:
                        limit = int(value.strip())
                    except ValueError:
                        limit = 50
            limit = max(1, min(200, limit))
            tail = self.tail_singbox_stderr(max_lines=limit)
            client.sendall(_http_response("200 OK", "application/json", json.dumps({"limit": limit, "lines": tail.splitlines() if tail else []}).encode()))
        elif path == "/api/settings" and method == "GET":
            client.sendall(_http_response("200 OK", "application/json", json.dumps(self.settings_snapshot()).encode()))
        elif method == "POST":
            if not self._post_slots.acquire(blocking=False):
                client.sendall(_http_response("503 Service Unavailable", "text/plain", b"busy, retry later", {"Retry-After": "5"}))
                return
            try:
                self._route_post(client, path, headers, body, query)
            finally:
                self._post_slots.release()
            return
        elif path.startswith("/api/"):
            client.sendall(_http_response("405 Method Not Allowed", "text/plain", b"method not allowed"))
        else:
            client.sendall(_http_response("404 Not Found", "text/plain", b"not found"))

    def _route_post(self, client: socket.socket, path: str, headers: dict, body: bytes, query: str = "") -> None:
        if path == "/api/refresh":
            if not self._start_refresh_bg():
                client.sendall(_http_response("409 Conflict", "application/json",
                    json.dumps({"accepted": False, "error": "already running"}).encode()))
                return
            client.sendall(_http_response("202 Accepted", "application/json",
                json.dumps({"accepted": True}).encode()))
        elif path == "/api/full_probe":
            if not self._start_full_probe():
                client.sendall(_http_response("409 Conflict", "application/json", json.dumps({"accepted": False, "error": "already running"}).encode()))
                return
            client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"accepted": True}).encode()))
        elif path == "/api/probe":
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict) or not payload.get("tag"):
                client.sendall(_http_response("400 Bad Request", "text/plain", b"missing tag"))
                return
            node = next((n for n in self._nodes if n.get("endpoint", {}).get("tag") == payload["tag"]), None)
            if node is None:
                client.sendall(_http_response("404 Not Found", "application/json", json.dumps({"ok": False, "error": "unknown tag"}).encode()))
                return
            accepted, running_tag = self._start_single_probe(node)
            if not accepted:
                client.sendall(_http_response("409 Conflict", "application/json", json.dumps({"accepted": False, "error": "already running", "tag": running_tag}).encode()))
                return
            client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"accepted": True, "tag": node["endpoint"]["tag"]}).encode()))
        elif path == "/api/verify":
            if _query_param(query, "path") == "resi":
                if not (self.resi or self.resi_rotate):
                    client.sendall(_http_response("503 Service Unavailable", "application/json", json.dumps({"ok": False, "error": "resi disabled"}).encode()))
                    return
                with self._lock:
                    running = (self.status["resi"].get("last_probe") or {}).get("state") == "running"
                if running:
                    client.sendall(_http_response("409 Conflict", "application/json", json.dumps({"accepted": False, "error": "already running"}).encode()))
                    return
                threading.Thread(target=self._run_resi_verify, daemon=True, name="resi-verify").start()
                client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"accepted": True, "path": "resi"}).encode()))
                return
            node = self._verify_target_node()
            if node is None:
                client.sendall(_http_response("503 Service Unavailable", "application/json", json.dumps({"ok": False, "error": "no nodes"}).encode()))
                return
            accepted, via_tag = self._start_verify(node)
            if not accepted:
                client.sendall(_http_response("409 Conflict", "application/json", json.dumps({"accepted": False, "error": "already running", "tag": via_tag}).encode()))
                return
            client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"accepted": True, "via_tag": node.get("endpoint", {}).get("tag")}).encode()))
        elif path == "/api/switch":
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict):
                client.sendall(_http_response("400 Bad Request", "text/plain", b"invalid json"))
                return
            ok, detail = self.switch(tag=payload.get("tag"), country=payload.get("country"))
            status = "200 OK" if ok else ("409 Conflict" if detail == "busy, retry later" else "400 Bad Request")
            client.sendall(_http_response(status, "application/json", json.dumps({"ok": ok, "preferred_tag": self.preferred_tag, "detail": detail}).encode()))
        elif path == "/api/settings":
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict):
                client.sendall(_http_response("400 Bad Request", "text/plain", b"invalid json"))
                return
            ok, detail = self.update_settings(payload)
            status = "200 OK" if ok else "400 Bad Request"
            client.sendall(_http_response(status, "application/json", json.dumps({"ok": ok, "detail": detail, "settings": self.settings_snapshot()["values"] if ok else None}).encode()))
        elif path == "/api/resi_probe":
            # rotate mode has no self.resi (no gateway credentials), but the
            # third path is very much live: gate on "third path enabled".
            if not (self.resi or self.resi_rotate):
                client.sendall(_http_response("503 Service Unavailable", "application/json", json.dumps({"ok": False, "error": "resi disabled"}).encode()))
                return
            try:
                payload = json.loads((body or b"{}").decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = None
            if not isinstance(payload, dict):
                client.sendall(_http_response("400 Bad Request", "text/plain", b"invalid json"))
                return
            try:
                count = int(payload.get("count", 3))
            except (TypeError, ValueError):
                count = 3
            count = max(1, min(5, count))
            rotate = bool(payload.get("rotate_session"))
            if not self._start_resi_probe(count, rotate_session=rotate):
                client.sendall(_http_response("409 Conflict", "application/json", json.dumps({"accepted": False, "error": "already running"}).encode()))
                return
            if rotate and self.resi_session_ttl > 0:
                self._apply_config_bg()
            client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"accepted": True, "count": count, "rotate_session": rotate}).encode()))
        elif path == "/api/resi_session":
            if not (self.resi or self.resi_rotate):
                client.sendall(_http_response("503 Service Unavailable", "application/json", json.dumps({"ok": False, "error": "resi disabled"}).encode()))
                return
            if not self.resi:
                client.sendall(_http_response("400 Bad Request", "application/json", json.dumps({"ok": False, "error": "sticky session needs the residential gateway; rotate mode has no session"}).encode()))
                return
            if self.resi_session_ttl <= 0:
                client.sendall(_http_response("400 Bad Request", "application/json", json.dumps({"ok": False, "error": "sticky session disabled (RESI_SESSION_TTL=0)"}).encode()))
                return
            with self._resi_lock:
                self._resi_session_id = ""
            self._set_resi(mode=self._resi_mode(), sticky_ttl=self.resi_session_ttl, session_age=0)
            self._apply_config_bg()
            client.sendall(_http_response("202 Accepted", "application/json", json.dumps({"ok": True, "session": "rotated"}).encode()))
        elif path.startswith("/api/"):
            client.sendall(_http_response("405 Method Not Allowed", "text/plain", b"method not allowed"))
        else:
            client.sendall(_http_response("404 Not Found", "text/plain", b"not found"))
    def _disguise_body(self) -> bytes | None:
        if not self.disguise_path:
            return None
        try:
            mtime = os.path.getmtime(self.disguise_path)
        except OSError:
            _DISGUISE_CACHE.pop(self.disguise_path, None)
            return None
        cached = _DISGUISE_CACHE.get(self.disguise_path)
        if cached is not None and cached[0] == mtime:
            return cached[1]
        try:
            with open(self.disguise_path, "rb") as handle:
                data = handle.read()
            if len(data) > 5 * 1024 * 1024:
                return data
            _DISGUISE_CACHE[self.disguise_path] = (mtime, data)
            return data
        except OSError:
            _DISGUISE_CACHE.pop(self.disguise_path, None)
            return None
    def _mixed_reachable(self, timeout: int = 2) -> bool:
        try:
            return probe_tcp_latency("127.0.0.1", self.mixed_port, timeout) > 0
        except Exception:
            return False
    def _serving_ok(self) -> bool:
        with self._lock:
            if not self.status["endpoints"]:
                return False
            if not self.want_singbox:
                return True
            proc = self._singbox_proc
            alive = proc is not None and proc.poll() is None
            if not alive:
                return False
        return self._mixed_reachable(timeout=2)
    def _vless_path_route(self, path: str) -> tuple[str, int] | None:
        """Map a VLESS+WS path to its local origin (``("port", n)`` / ``("rotate", 0)``).

        Why the manager routes these at all: every deployment already points a
        Cloudflare Tunnel catch-all at ``$PORT``, and the per-path ingress
        rules for 8080/8082 are easy to forget when a new path appears - which
        presents as "the third path is broken while the other two work".
        Serving the paths from ``$PORT`` means one catch-all rule is enough;
        existing per-path rules pointed at 8080/8082/8084 keep working too.
        """
        if not self.vless_uuid:
            return None
        if path == self.vless_direct_path:
            return ("port", self.vless_direct_port)
        if path == self.vless_chain_path:
            return ("port", self.vless_chain_port)
        if path == self.resi_path and self.resi_rotate:
            return ("rotate", 0)
        if path == self.resi_path and self.resi:
            return ("port", self.resi_port)
        return None

    def _pipe_to_backend(self, client: socket.socket, peek: bytes,
                         port: int | None = None) -> None:
        try:
            backend = socket.create_connection(
                ("127.0.0.1", self.mixed_port if port is None else port), timeout=10)
        except OSError:
            return
        client.settimeout(PIPE_IDLE_TIMEOUT)
        backend.settimeout(PIPE_IDLE_TIMEOUT)
        try:
            backend.sendall(peek)
            started = time.monotonic()
            stats = _pump_pair(client, backend, started)
            with self._lock:
                self.status["traffic"]["bytes_up"] += stats["up"] + len(peek)
                self.status["traffic"]["bytes_down"] += stats["down"]
        except OSError:
            pass
        finally:
            try:
                backend.close()
            except OSError:
                pass

    def status_snapshot(self) -> dict:
        with self._lock:
            snapshot = json.loads(json.dumps(self.status))
        snapshot["threads"] = threading.active_count()
        with self._lock:
            cpu_now = _cpu_times()
            if self._cpu_last is not None and cpu_now is not None:
                cpu_pct = _cpu_pct(self._cpu_last, cpu_now)
            else:
                cpu_pct = None
            if cpu_now is not None:
                self._cpu_last = cpu_now
        snapshot["cpu"] = {"model": self._cpu_model, "cores": self._cpu_cores, "pct": cpu_pct}
        snapshot["memory"] = {"rss_mb": _rss_mb(), "pct": _mem_pct()}
        now = datetime.now(timezone.utc)
        try:
            started = datetime.strptime(self.status["started_at"] or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            snapshot["uptime_seconds"] = max(0, int((now - started).total_seconds()))
        except (ValueError, TypeError):
            snapshot["uptime_seconds"] = 0
        for ep in snapshot["endpoints"]:
            host, port = primary_server(ep)
            first = self._first_seen.get(f"{host}:{port}")
            ep["first_seen"] = first
            try:
                seen = datetime.strptime(first or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                ep["alive_seconds"] = max(0, int((now - seen).total_seconds()))
            except (ValueError, TypeError):
                ep["alive_seconds"] = 0
            ev = self._node_evidence.get(f"{host}:{port}") or {}
            ep["alive"] = ev.get("alive")
            ep["exit_ip"] = ev.get("exit_ip")
            ep["verified_at"] = ev.get("verified_at")
            ep["verify_ms"] = ev.get("verify_ms")
            ep["verify_error"] = ev.get("verify_error")
            ep["verify_fresh"] = self._evidence_is_fresh(ev)
        pin_health = snapshot.get("pin_health")
        chain_switch = snapshot.get("chain_switch") or {}
        if isinstance(pin_health, dict):
            pin_health["chain_switch"] = {"mode": chain_switch.get("mode"),
                                          "ready": chain_switch.get("ready"),
                                          "switches": chain_switch.get("switches")}
        resi = snapshot.get("resi")
        if isinstance(resi, dict) and resi.get("enabled") and self.resi_rotate:
            with self._lock:
                usable, parked, _ = self._resi_pool_locked()
                resi["pool"] = usable
                resi["down"] = parked
                resi["inbounds"] = len(self._resi_routes)
                resi["nodes"] = usable
                resi["reserved"] = self.status["resi"].get("reserved", 0)
        if self.edge_metrics_url:
            # The Go edge owns /ws-node and /ws-chain byte counts; Python
            # keeps counting /ws-resi and measurement traffic. Merge only into
            # the returned snapshot: self.status stays Python-derived.
            try:
                request = urllib.request.Request(
                    self.edge_metrics_url, headers={"Accept": "application/json"})
                with urllib.request.urlopen(request, timeout=0.3) as response:
                    payload = json.loads(response.read(65536).decode("utf-8"))
                if isinstance(payload, dict) and payload.get("ok") is True:
                    traffic = snapshot.get("traffic")
                    if not isinstance(traffic, dict):
                        traffic = {}
                        snapshot["traffic"] = traffic
                    for key in ("bytes_up", "bytes_down"):
                        value = payload.get(key)
                        if (isinstance(value, (int, float))
                                and not isinstance(value, bool)):
                            traffic[key] = int(traffic.get(key, 0) or 0) + int(value)
            except Exception:
                # Metrics are advisory; a missing/broken sidecar must never
                # break the status endpoint or the manager.
                pass
        return snapshot
    def _record_history(self, event: str, detail: str = "") -> None:
        with self._lock:
            self.status["refresh_history"].append({"ts": _now_iso(), "event": event, "detail": detail})
            del self.status["refresh_history"][:-20]
    def _persist_state(self) -> None:
        _write_private_json(self.state_path, {"preferred_tag": self.preferred_tag, "backup_tag": self.backup_tag, "auto_pinned": self._auto_pinned})
    @staticmethod
    def _coerce_setting(key: str, value) -> tuple[bool, object, str]:
        spec = SETTINGS_SPEC.get(key)
        if spec is None:
            return False, None, f"unknown setting {key}"
        if spec["type"] == "bool":
            if isinstance(value, bool):
                return True, value, ""
            if isinstance(value, (int, float)) and value in (0, 1):
                return True, bool(value), ""
            if isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on"):
                return True, True, ""
            if isinstance(value, str) and value.strip().lower() in ("0", "false", "no", "off"):
                return True, False, ""
            return False, None, f"{key} must be a boolean"
        try:
            number = int(value)
        except (TypeError, ValueError):
            return False, None, f"{key} must be an integer"
        if isinstance(value, bool) or not spec["min"] <= number <= spec["max"]:
            return False, None, f"{key} must be {spec['min']}..{spec['max']}"
        return True, number, ""
    def settings_snapshot(self) -> dict:
        with self._lock:
            values = {key: getattr(self, key, None) for key in SETTINGS_SPEC}
        bounds = {key: {k: v for k, v in spec.items() if k != "type"} for key, spec in SETTINGS_SPEC.items()}
        return {"values": values, "bounds": bounds}
    def update_settings(self, payload: dict) -> tuple[bool, str]:
        if not isinstance(payload, dict) or not payload:
            return False, "empty settings payload"
        clean: dict = {}
        for key, value in payload.items():
            ok, parsed, error = self._coerce_setting(key, value)
            if not ok:
                return False, error
            clean[key] = parsed
        with self._lock:
            for key, value in clean.items():
                setattr(self, key, value)
        if self.settings_path:
            _write_private_json(self.settings_path, self.settings_snapshot()["values"])
        self._record_history("settings", ", ".join(f"{k}={v}" for k, v in clean.items()))
        if self.resi is not None and "resi_session_ttl" in clean:
            # A new ttl means a new sticky window: mint a fresh session id and
            # rebuild the serving config off-thread (this may restart sing-box).
            with self._resi_lock:
                self._resi_session_id = ""
            self._set_resi(mode=self._resi_mode(), sticky_ttl=int(self.resi_session_ttl or 0))
            self._apply_config_bg()
        return True, "saved"
    def load_settings(self) -> None:
        if not self.settings_path:
            return
        try:
            with open(self.settings_path, encoding="utf-8") as handle:
                saved = json.load(handle)
        except (OSError, ValueError):
            return
        if not isinstance(saved, dict):
            return
        for key, value in saved.items():
            ok, parsed, _ = self._coerce_setting(key, value)
            if ok:
                setattr(self, key, parsed)
    def _persist_nodes(self) -> None:
        _write_private_json(self.nodes_path, {"nodes": self._nodes, "first_seen": self._first_seen})
    def load_persisted(self) -> tuple[list, str | None]:
        nodes: list = []; first_seen: dict = {}
        try:
            with open(self.nodes_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            nodes = saved.get("nodes", []); first_seen = saved.get("first_seen", {})
        except (OSError, ValueError):
            pass
        preferred = backup = None; auto_pinned = False
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                s = json.load(handle)
            preferred = s.get("preferred_tag"); backup = s.get("backup_tag"); auto_pinned = bool(s.get("auto_pinned", False))
        except (OSError, ValueError):
            pass
        with self._lock:
            self._nodes = nodes; self._first_seen = first_seen
            self._nodes_rev += 1
            # Rotate mode reserves exactly one node for the chain; a backup left
            # over from an older version would shrink the rotation pool for a
            # standby the hot switch does not need.
            if self.resi_rotate and not self.clash_api_port:
                self.preferred_tag = preferred; self.backup_tag = backup
            else:
                self.preferred_tag = preferred; self.backup_tag = None if self.resi_rotate else backup
            self._auto_pinned = auto_pinned
            if preferred:
                # A restored pin starts a fresh process: give its endpoint the
                # same warm-up window a repin gets.
                self._chain_pin_at = time.monotonic()
        return nodes, preferred
    def _boot_from_last_good(self) -> bool:
        try:
            with open(self.last_good_path, "rb") as src:
                payload = src.read()
            if not payload:
                return False
            json.loads(payload.decode("utf-8"))
        except (OSError, ValueError):
            return False
        tmp_path = f"{self.config_path}.tmp-{os.getpid()}"
        with open(tmp_path, "wb") as handle:
            handle.write(payload)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, self.config_path)
        nodes, preferred = self.load_persisted()
        endpoints = nodes_to_endpoints(nodes) if nodes else []
        with self._lock:
            self.status["endpoints"] = [{"tag": ep["tag"], "server": primary_server(ep)[0], "server_port": primary_server(ep)[1],
                "country": n.get("country", ""), "country_short": n.get("country_short", ""), "latency_ms": n.get("latency_ms"),
                "real_latency_ms": n.get("real_latency_ms"), "speed": n.get("speed", 0)} for ep, n in zip(endpoints, nodes)]
            self.status["countries"] = self._countries()
            tags = {ep["tag"] for ep in endpoints}
            if preferred and preferred not in tags:
                self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = True; self._persist_state()
            if self.backup_tag is not None and self.backup_tag not in tags:
                self.backup_tag = None; self._persist_state()
            self.status["preferred_tag"] = self.preferred_tag; self.status["backup_tag"] = self.backup_tag
            self.status["auto_pinned"] = self._auto_pinned
            self.status["last_error"] = "booted from last-good config (refresh failed)"
        if self.resi_rotate:
            # The last-good config already bakes one rotate inbound per serving
            # node; rebuild the same tag -> port table so the balancer and
            # /ws-resi work before the first successful refresh/apply. Tags are
            # final here (nodes_to_endpoints assigned them above).
            self._set_resi_routes(self._rotate_routes(self._ordered_serving()))
        if self.want_singbox:
            self._restart_singbox()
        self._record_history("boot-from-last-good", f"{len(endpoints)} endpoints")
        return True
    def _countries(self) -> list[dict]:
        seen: dict[str, str] = {}
        for node in self._nodes:
            code = node.get("country_short", "")
            if code and code not in seen:
                seen[code] = node.get("country", "")
        return [{"code": code, "name": seen[code]} for code in sorted(seen)]
    def _effective_interval(self) -> int:
        if self._fail_streak >= 3:
            return max(300, self.refresh_seconds // 2)
        return self.refresh_seconds
    def _refresh_loop(self) -> None:
        next_run = time.monotonic() + self._effective_interval() + random.uniform(-30, 30)
        _safe_print(f"refresh loop armed: every {self._effective_interval()}s", flush=True)
        while not self._stop_event.wait(max(0.0, next_run - time.monotonic())):
            self._log("scheduled refresh firing", flush=True)
            try:
                self._start_refresh_bg()
            except Exception as exc:
                self._log(f"refresh loop error: {type(exc).__name__}: {exc}", flush=True)
            next_run = time.monotonic() + self._effective_interval() + random.uniform(-30, 30)
    def _supervise_loop(self) -> None:
        while not self._stop_event.wait(SUPERVISE_INTERVAL):
            try:
                self._supervise_once()
            except Exception as exc:
                self._log(f"supervise loop error: {type(exc).__name__}: {exc}", flush=True)
    def _supervise_once(self) -> None:
        with self._lock:
            if not self.want_singbox:
                return
            proc = self._singbox_proc
            alive = proc is not None and proc.poll() is None
            want_cfg = self.config_path
            has_ep = bool(self.status["endpoints"])
        if alive:
            if has_ep and not self._mixed_reachable(timeout=2):
                with self._lock:
                    self._mixed_fail_streak += 1
                    streak = self._mixed_fail_streak
                    now = time.monotonic()
                    if streak < 2 or now < self._mixed_retry_after:
                        if streak == 1:
                            self.status["last_error"] = "mixed unreachable once, watching"
                        return
                    delay = CRASH_BACKOFFS[min(self._crash_streak, len(CRASH_BACKOFFS) - 1)]
                    self._crash_streak = min(self._crash_streak + 1, len(CRASH_BACKOFFS) - 1)
                    self._mixed_retry_after = now + delay
                    self.status["last_error"] = f"mixed unreachable {streak}x, restarting now, next retry in {delay}s"
                self._record_history("supervise-mixed-dead", "mixed unreachable, restarting")
                self._restart_singbox()
                with self._lock:
                    self._mixed_fail_streak = 0
                return
            with self._lock:
                self._mixed_fail_streak = 0
                self._crash_streak = 0
                return
        with self._lock:
            proc = self._singbox_proc
            if proc is None and not os.path.exists(want_cfg):
                return
            now = time.monotonic()
            if now < self._retry_after:
                return
            delay = CRASH_BACKOFFS[min(self._crash_streak, len(CRASH_BACKOFFS) - 1)]
            self._crash_streak = min(self._crash_streak + 1, len(CRASH_BACKOFFS) - 1)
            self._retry_after = now + delay
            exit_info = f" (previous exit code {proc.poll()})" if proc else ""
            self.status["last_error"] = f"sing-box not running{exit_info}, restarting now, next retry in {delay}s"
        self._restart_singbox()
        with self._lock:
            cf = self._cloudflared_proc
            want_cf = bool(self.tunnel_token)
            cf_alive = cf is not None and cf.poll() is None
        if want_cf and not cf_alive:
            self._start_cloudflared()

    def _note_mixed_down(self, reason: str) -> str:
        # NOTE: health and supervise share _mixed_retry_after/_crash_streak
        # backoff but keep separate miss counters (_health_mixed_streak vs
        # _mixed_fail_streak) so a 10s-supervise + 20s-health coincidence
        # cannot fuse into an instant 2x restart.
        """Gated serving-down handling shared by health checks.

        A single 2s mixed miss (GC/refresh burst) must not restart serving:
        needs 2 consecutive misses plus the crash backoff gate. Returns
        "restarted" when a restart was issued, else "watching".
        """
        with self._lock:
            self._health_mixed_streak += 1
            streak = self._health_mixed_streak
            now = time.monotonic()
            if streak < 2 or now < self._mixed_retry_after:
                if streak == 1:
                    self.status["last_error"] = "serving unreachable once, watching"
                return "watching"
            delay = CRASH_BACKOFFS[min(self._crash_streak, len(CRASH_BACKOFFS) - 1)]
            self._crash_streak = min(self._crash_streak + 1, len(CRASH_BACKOFFS) - 1)
            self._mixed_retry_after = now + delay
            self.status["last_error"] = f"serving unreachable {streak}x, restarting now, next retry in {delay}s"
        self._record_history("health-serving-dead", reason)
        try:
            self._restart_singbox()
        except Exception:
            pass
        with self._lock:
            self._health_mixed_streak = 0
        return "restarted"

    def _health_monitor_loop(self) -> None:
        while not self._stop_event.wait(self._health_check_interval):
            try:
                self.check_pinned_health()
            except Exception as exc:
                self._log(f"health monitor error: {type(exc).__name__}: {exc}", flush=True)
    def _trigger_bg_refresh(self, reason: str) -> None:
        try:
            started = self._start_refresh_bg()
        except Exception:
            return
        if started:
            # Printed on purpose: a background refresh rewrites the serving
            # config and therefore restarts sing-box, dropping all three paths.
            # When that happens the reason has to be in the log, otherwise a
            # collateral restart is indistinguishable from third-path churn.
            self._log(f"refresh triggered: {reason}", flush=True)
            self._record_history("health-trigger-refresh", reason)

    @staticmethod
    def _node_key(node: dict) -> str:
        return f"{node.get('server')}:{node.get('server_port')}"

    @staticmethod
    def _tag_key(tag: str | None, nodes: list[dict]) -> str | None:
        if not tag:
            return None
        for node in nodes:
            if (node.get("endpoint") or {}).get("tag") == tag:
                return f"{node.get('server')}:{node.get('server_port')}"
        return None

    @staticmethod
    def _evidence_age(evidence: dict | None) -> float | None:
        if not evidence:
            return None
        stamp = evidence.get("verified_at")
        if not stamp:
            return None
        try:
            then = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
        return max(0.0, (datetime.now(timezone.utc) - then).total_seconds())

    def _evidence_is_fresh(self, evidence: dict | None) -> bool:
        age = self._evidence_age(evidence)
        return age is not None and age <= VERIFY_STALE_AFTER_SEC

    def _record_evidence(self, node: dict, alive: bool | None, exit_ip: str | None,
                         verify_ms: int | None, error: str | None) -> None:
        """Write the single source of truth for one node's liveness."""
        key = self._node_key(node)
        with self._lock:
            self._node_evidence[key] = {"alive": alive, "exit_ip": exit_ip,
                "verified_at": _now_iso(), "verify_ms": verify_ms,
                "verify_error": error}

    def _note_dial_ok(self, node: dict, ms: int | None) -> None:
        """A real dial proved the node is reachable, without an exit IP.

        Never overwrite fresher exit evidence: a probe that carried traffic is
        stronger than a handshake and must survive the next refresh.
        """
        key = self._node_key(node)
        with self._lock:
            ev = self._node_evidence.get(key)
            if self._evidence_is_fresh(ev):
                return
            self._node_evidence[key] = {"alive": True, "exit_ip": None,
                "verified_at": _now_iso(), "verify_ms": ms, "verify_error": None}

    def _fresh_alive_evidence(self, node: dict) -> bool:
        ev = self._node_evidence.get(self._node_key(node))
        return bool(self._evidence_is_fresh(ev) and ev.get("alive") is True)

    def _endpoint_row(self, ep: dict, node: dict) -> dict:
        ev = self._node_evidence.get(self._node_key(node)) or {}
        return {"tag": ep["tag"], "server": primary_server(ep)[0], "server_port": primary_server(ep)[1],
            "country": node.get("country", ""), "country_short": node.get("country_short", ""),
            "latency_ms": node.get("latency_ms"), "real_latency_ms": node.get("real_latency_ms"),
            "speed": node.get("speed", 0),
            "alive": ev.get("alive"), "exit_ip": ev.get("exit_ip"),
            "verified_at": ev.get("verified_at"), "verify_ms": ev.get("verify_ms"),
            "verify_error": ev.get("verify_error"),
            "verify_fresh": self._evidence_is_fresh(ev)}

    def _set_pin_health(self, state: str | None = None, error: str | None = None) -> None:
        with self._lock:
            tag = self.preferred_tag
            node = next((n for n in self._nodes
                         if (n.get("endpoint") or {}).get("tag") == tag), None) if tag else None
            ev = (self._node_evidence.get(self._node_key(node)) or {}) if node else {}
            if state is None:
                if tag is None:
                    state = "unpinned"
                elif self._pinned_fail_streak or self._chain_fail_streak:
                    state = "degraded"
                else:
                    state = "unknown"
            chain = self.status.get("chain_switch") or {}
            self.status["pin_health"] = {
                "state": state,
                "fail_streak": max(int(self._pinned_fail_streak), int(self._chain_fail_streak)),
                "checked_at": _now_iso(),
                "exit_ip": ev.get("exit_ip"),
                "error": error if error is not None else ev.get("verify_error"),
                "chain_switch": {"mode": chain.get("mode"), "ready": chain.get("ready"),
                                 "switches": chain.get("switches")},
            }

    def _probe_delays(self, tags: list[str]) -> dict[str, int] | None:
        probe = getattr(self, "probe", None)
        if probe is None or not tags:
            return None
        try:
            got = probe.delays(list(tags))
        except Exception:
            return None
        return got if isinstance(got, dict) else None

    def _mixed_listening(self, timeout: float = 0.5) -> bool:
        """Is the local mixed inbound accepting connections right now?"""
        try:
            with socket.create_connection(("127.0.0.1", self.mixed_port), timeout=timeout):
                return True
        except OSError:
            return False

    def _verifier_configured(self) -> bool:
        return getattr(self, "probe", None) is not None or callable(measure_mixed_exit_ip)

    def _served_exit_available(self) -> bool:
        return self._verifier_configured() and self._mixed_listening()

    def _served_exit_probe(self) -> tuple[str | None, int | None, bool]:
        """Exit IP through the live mixed inbound, plus "was it attempted".

        The third value separates "the chain answered with no exit IP" (a
        real tunnel failure) from "no verifier is configured" (unknown, which
        must never be treated as death).
        """
        with self._lock:
            mixed_port = self.mixed_port; username = self.username; password = self.password
        if not self.want_singbox:
            return None, None, False
        if not self._mixed_listening():
            # The serving socket itself is down (restart/backoff). That is an
            # unknown node state, not proof that the pinned tunnel is dead.
            return None, None, False
        probe = getattr(self, "probe", None)
        if probe is not None:
            try:
                got = probe.exit_ip("127.0.0.1", mixed_port, username, password)
            except Exception:
                got = None
            if isinstance(got, dict):
                if got.get("ok") and got.get("exit_ip"):
                    return str(got["exit_ip"]), got.get("ms"), True
                return None, None, True
        fallback = measure_mixed_exit_ip
        if callable(fallback):
            try:
                ip, ms = fallback("127.0.0.1", mixed_port, username, password)
            except Exception:
                return None, None, False
            if ip:
                return str(ip), ms, True
            return None, None, True
        return None, None, False

    def _served_exit_ip(self) -> tuple[str | None, int | None]:
        exit_ip, ms, _attempted = self._served_exit_probe()
        return exit_ip, ms

    def _singbox_live(self) -> bool:
        """True for a real running sing-box process (not a unit-test mock)."""
        proc = self._singbox_proc
        if proc is None or proc.poll() is not None:
            return False
        # A Mock's pid is not an int; requiring one keeps unit tests from
        # sleeping out the real restart window.
        return isinstance(getattr(proc, "pid", None), int)

    def _verify_served(self, retries: int = 2,
                       budget: float = 18.0) -> tuple[bool, str | None, int | None, bool]:
        """(ok, exit_ip, ms, attempted) for the served chain.

        A config apply restarts sing-box; the mixed inbound can be down for
        seconds. Waiting for it is mandatory: "not listening yet" is unknown,
        never tunnel death. The whole wait is bounded (~18s by default).
        """
        if not self._verifier_configured():
            return False, None, None, False
        deadline = time.monotonic() + max(0.0, budget)
        attempted = False
        probe_attempts = 0
        while True:
            remaining = deadline - time.monotonic()
            if not self._mixed_listening():
                if not self._singbox_live() or remaining <= 0:
                    return False, None, None, False
                time.sleep(min(0.5, max(0.0, remaining)))
                continue
            exit_ip, ms, attempted = self._served_exit_probe()
            if exit_ip:
                return True, exit_ip, ms, True
            if attempted:
                probe_attempts += 1
                if probe_attempts >= max(1, retries) or remaining <= 0:
                    return False, None, None, True
                time.sleep(min(1.0, max(0.0, remaining)))
                continue
            if remaining <= 0:
                return False, None, None, False
            time.sleep(min(0.5, max(0.0, remaining)))

    def _restore_runtime_pin(self, pin: str | None, hot: bool) -> None:
        if hot and pin:
            self._repin_runtime(pin, "rollback")
            return
        with self._config_lock:
            self._apply_config(final="auto", preferred=pin, backup=None)
    def _fresh_probe_tags(self, cands: list[dict]) -> list[str]:
        """Candidates with fresh evidence right now, in ranking order.

        Stored proof (exit evidence, recent rotation payload/bytes) is free;
        the probe sidecar's real delay check is next; a raw TCP handshake is
        only the last resort. A handshake alone is not tunnel evidence, which
        is why it can no longer be the sole rescue trigger.
        """
        if not cands:
            return []
        order = {((n.get("endpoint") or {}).get("tag")): k for k, n in enumerate(cands)}
        alive: set[str] = set()
        remaining: list[dict] = []
        now = time.monotonic()
        for node in cands:
            tag = (node.get("endpoint") or {}).get("tag")
            if not tag:
                continue
            if self._fresh_alive_evidence(node):
                alive.add(tag)
                continue
            proof = self._resi_payload_at.get(tag, 0.0)
            answered = self._resi_ok_at.get(tag, 0.0)
            if ((proof and now - proof <= CHAIN_ALIVE_WINDOW)
                    or (answered and now - answered <= CHAIN_ALIVE_WINDOW)):
                alive.add(tag)
                continue
            remaining.append(node)
        if remaining:
            delays = self._probe_delays([
                (n.get("endpoint") or {}).get("tag") for n in remaining
                if (n.get("endpoint") or {}).get("tag")])
            if delays is not None:
                alive.update(delays)
                remaining = [n for n in remaining
                             if (n.get("endpoint") or {}).get("tag") not in delays]
        if remaining and self.resi_rotate and self.vless_uuid:
            # The node's own rotate inbound is the only honest witness that
            # is guaranteed not to open a second session.
            still: list[dict] = []
            for node in remaining:
                tag = (node.get("endpoint") or {}).get("tag")
                if tag and self._chain_candidate_carries_traffic(node):
                    alive.add(tag)
                else:
                    still.append(node)
            remaining = still
        if remaining:
            def _one(node: dict) -> None:
                endpoint = node.get("endpoint") or node
                ms = 0
                # Every remote, not just the first: sing-box fails over inside
                # the endpoint, so one dead address must not hide a live node.
                for host, port in endpoint_remotes(endpoint):
                    try:
                        ms = probe_tcp_latency(host, port, 5)
                    except Exception:
                        ms = 0
                    if ms and ms > 0:
                        break
                if ms and ms > 0:
                    tag = (node.get("endpoint") or {}).get("tag")
                    if tag:
                        with alive_lock:
                            alive.add(tag)
            alive_lock = threading.Lock()
            with ThreadPoolExecutor(max_workers=min(len(remaining), 3)) as ex:
                list(ex.map(_one, remaining))
        return sorted(alive, key=lambda t: order.get(t, 10 ** 9))

    def _chain_probe_ok(self) -> bool | None:
        """End-to-end exit-IP probe of the served chain in every mode.

        It rides the live mixed inbound (see `_served_exit_probe`), so it
        applies to a gateway pin exactly like a rotate pin and never opens a
        second VPNGate session. Returns None when the result is unknown
        (no pin, no verifier, serving down): None is NOT tunnel death.
        """
        with self._lock:
            pinned = self.preferred_tag is not None
        if not (pinned and self.want_singbox):
            return None
        if not self._serving_ok():
            return None
        exit_ip, ms, attempted = self._served_exit_probe()
        if not attempted:
            return None
        with self._lock:
            tag = self.preferred_tag
            node = next((n for n in self._nodes
                         if (n.get("endpoint") or {}).get("tag") == tag), None) if tag else None
        if node is not None:
            if exit_ip:
                self._record_evidence(node, True, exit_ip, ms, None)
            else:
                self._record_evidence(node, False, None, None, "served chain has no exit ip")
        return bool(exit_ip)

    def _chain_candidates_locked(self, now: float) -> list[dict]:
        """Nodes the chain may be pinned to, best evidence first.

        Ranking by `real_latency_ms` alone is a trap in rotate mode: the value
        is written when a node was dialed and deliberately never refreshed for
        serving nodes (re-dialing them would steal their only VPNGate session,
        §12.9e D13). After hours the pool is full of stale numbers, so the
        rescue kept pinning nodes that died long ago - the chain stayed dead
        while /ws-resi (which skips parked nodes) kept working, and only a
        manual switch fixed it. Evidence order:

        1. nodes that just carried rotation payload: the tunnel demonstrably
           works right now, whatever the old latency number says;
        2. nodes that at least returned some bytes recently (weaker proof, but
           still fresher than a latency number measured hours ago);
        3. verified nodes the rotation has not parked, by real latency;
        4. parked nodes, soonest to come back first (last resort, exactly how
           the rotation itself falls back).

        Nodes that already failed the chain probe are skipped while their
        dead-memory lasts, so a rescue always moves to a *new* candidate.
        """
        reserved = {self.preferred_tag, self.backup_tag}
        proven: list[dict] = []
        answered: list[dict] = []
        fresh: list[dict] = []
        parked: list[dict] = []
        for node in self._nodes:
            tag = (node.get("endpoint") or {}).get("tag")
            if not tag or tag in reserved:
                continue
            if self._chain_dead_until.get(tag, 0.0) > now:
                continue
            ev = self._node_evidence.get(f"{node.get('server')}:{node.get('server_port')}")
            if self._evidence_is_fresh(ev) and ev.get("alive") is False:
                continue
            entry = self._resi_health.get(tag) or {}
            down_until = float(entry.get("down_until", 0.0))
            proof = self._resi_payload_at.get(tag, 0.0)
            answered_at = self._resi_ok_at.get(tag, 0.0)
            if down_until > now:
                parked.append(node)
            elif proof and now - proof <= CHAIN_ALIVE_WINDOW:
                proven.append(node)
            elif answered_at and now - answered_at <= CHAIN_ALIVE_WINDOW:
                answered.append(node)
            else:
                fresh.append(node)
        def _real(node: dict):
            real = node.get("real_latency_ms")
            return real if real is not None else 10**9
        def _recent(table: dict[str, float]):
            return lambda n: (-table.get((n.get("endpoint") or {}).get("tag") or "", 0.0),
                              _real(n))
        proven.sort(key=_recent(self._resi_payload_at))
        answered.sort(key=_recent(self._resi_ok_at))
        fresh.sort(key=lambda n: (_real(n),
                                  (n.get("endpoint") or {}).get("tag") or ""))
        parked.sort(key=lambda n: (
            float((self._resi_health.get((n.get("endpoint") or {}).get("tag") or "") or {})
                  .get("down_until", 0.0)), _real(n)))
        return proven + answered + fresh + parked

    def _candidate_has_fresh_proof(self, node: dict) -> bool:
        tag = (node.get("endpoint") or {}).get("tag")
        if not tag:
            return False
        if self._fresh_alive_evidence(node):
            return True
        now = time.monotonic()
        proof = self._resi_payload_at.get(tag, 0.0)
        answered = self._resi_ok_at.get(tag, 0.0)
        return bool((proof and now - proof <= CHAIN_ALIVE_WINDOW)
                    or (answered and now - answered <= CHAIN_ALIVE_WINDOW))

    def _rescue_chain(self, reason: str, round_id: int) -> str:
        with self._pin_switch_lock:
            return self._rescue_chain_impl(reason, round_id)

    def _rescue_chain_impl(self, reason: str, round_id: int) -> str:
        """Repin the chain only onto a node that verifies right now.

        Every candidate is tried in ranking order: a hot switch when the
        running selector lists it, otherwise a config rewrite. The served
        chain must then carry a real exit IP (or the candidate must already
        have fresh evidence when no verifier is configured). Failed candidates
        go into the dead-memory, so consecutive rescues walk the pool instead
        of bouncing between two corpses. If nothing verifies the current pin
        is kept and a refresh is requested - never a stale fallback.
        """
        now = time.monotonic()
        with self._lock:
            if not self.auto_rescue:
                self._record_history("chain-rescue-skipped", f"{reason}: auto_rescue off")
                return "pinned"
            if now - self._chain_rescue_at < min(
                    CHAIN_RESCUE_COOLDOWN_MAX,
                    CHAIN_RESCUE_COOLDOWN * (2 ** max(0, self._chain_rescue_attempts - 1))):
                return "pinned"
            if self._rescue_round != round_id:
                self._record_history("chain-rescue-skipped", f"{reason}: manual switch won the race")
                return "pinned"
            tag = self.preferred_tag
            cands = self._chain_candidates_locked(now)
        if not cands:
            with self._lock:
                self._chain_rescue_attempts += 1
                self._chain_rescue_at = now
                if tag:
                    self._chain_dead_until[tag] = now + CHAIN_DEAD_MEMORY
            self._record_history("chain-rescue-skipped", f"{reason}: no alternative candidate")
            self._log(f"chain rescue skipped: {reason}: no alternative candidate", flush=True)
            self._trigger_bg_refresh(f"{reason}: no verified alternative")
            return "pinned"
        failed: list[str] = []
        # Bounded: a dead pool must not make one health tick walk 100 nodes at
        # two multi-second probes each. Six best candidates fit in ~60s.
        cands = cands[:6]
        deadline = time.monotonic() + 60.0
        touched = False
        last_hot = False
        for node in cands:
            best = (node.get("endpoint") or {}).get("tag")
            if not best:
                continue
            if time.monotonic() > deadline:
                self._record_history("chain-rescue-skipped", f"{reason}: deadline reached")
                break
            with self._lock:
                if self._rescue_round != round_id:
                    self._record_history("chain-rescue-skipped", f"{reason}: manual switch won the race")
                    return "pinned"
            hot = self._repin_runtime(best, reason)
            if hot:
                touched = True; last_hot = True
            else:
                with self._config_lock:
                    if not self._apply_config(final="auto", preferred=best, backup=None):
                        failed.append(best)
                        with self._lock:
                            self._chain_dead_until[best] = now + CHAIN_DEAD_MEMORY
                        continue
                touched = True; last_hot = False
            if not self.want_singbox:
                # No serving chain exists (start_singbox=False): there is
                # nothing to verify, and a real dial here would be pointless.
                ok, exit_ip, ms, attempted = True, None, None, False
            else:
                ok, exit_ip, ms, attempted = self._verify_served(retries=2)
                if not ok and not attempted and self._candidate_has_fresh_proof(node):
                    # No verifier is configured yet; a fresh liveness proof is
                    # the best available evidence. It still must not be stale.
                    ok = True
            if ok:
                if exit_ip:
                    self._record_evidence(node, True, exit_ip, ms, None)
                with self._lock:
                    committed = self._commit_rescue(round_id, best, None)
                if committed:
                    with self._lock:
                        self._chain_rescue_attempts += 1
                        self._chain_rescue_at = now
                        self._chain_fail_streak = 0
                        self._pinned_fail_streak = 0
                        if tag and tag != best:
                            self._chain_dead_until[tag] = now + CHAIN_DEAD_MEMORY
                            self._resi_payload_at.pop(tag, None)
                            self._resi_ok_at.pop(tag, None)
                        self._chain_dead_until.pop(best, None)
                    self._invalidate_verify(f"chain rescue to {best}")
                    self._set_pin_health("ok")
                    self._record_history("chain-rescue", f"{reason}: {tag} -> {best}" + (" (hot)" if hot else ""))
                    self._log(f"chain rescue: {reason}: {tag} -> {best}" + (" (hot switch)" if hot else ""), flush=True)
                    return "rescued"
                # Verified but the round changed (refresh): never leave the
                # selector on a candidate the state does not pin.
                with self._lock:
                    restore_tag = self.preferred_tag
                self._restore_runtime_pin(restore_tag, last_hot)
                self._record_history("chain-rescue-skipped", f"{reason}: manual switch won the race")
                return "pinned"
            with self._lock:
                self._chain_dead_until[best] = now + CHAIN_DEAD_MEMORY
                self._resi_payload_at.pop(best, None)
                self._resi_ok_at.pop(best, None)
            failed.append(best)
        if touched:
            # Restore once at abort, not between candidates: the next
            # candidate is about to overwrite the selector anyway.
            with self._lock:
                restore_tag = self.preferred_tag
            self._restore_runtime_pin(restore_tag, last_hot)
        with self._lock:
            self._chain_rescue_attempts += 1
            self._chain_rescue_at = now
            if tag:
                self._chain_dead_until[tag] = now + CHAIN_DEAD_MEMORY
        self._record_history("chain-rescue-skipped",
                             f"{reason}: no candidate verified ({len(failed)} tried)")
        self._log(f"chain rescue skipped: {reason}: no candidate verified", flush=True)
        self._trigger_bg_refresh(f"{reason}: no candidate verified")
        self._set_pin_health("degraded", "no candidate verified for the chain")
        return "pinned"

    def check_pinned_health(self, probe_fn=None) -> str:
        """Judge the pin on handshake + served exit, every tick, every mode.

        Handshake death needs PINNED_FAIL_THRESHOLD strikes; tunnel death needs
        CHAIN_FAIL_THRESHOLD. A None probe result (no verifier / Clash or the
        serving socket unavailable) is unknown, never death. No real dial is
        ever made here: a second VPNGate session would kick the serving one.
        """
        with self._lock:
            tag = self.preferred_tag
            node = next((n for n in self._nodes if n.get("endpoint", {}).get("tag") == tag), None) if tag else None
            self._rescue_round += 1
            round_id = self._rescue_round
            warmed = (time.monotonic() - self._chain_pin_at) < CHAIN_SETTLE_GRACE
        if tag is None:
            self._set_pin_health("unpinned")
            return "no-preferred"
        if node is None:
            # The pinned node fell out of the snapshot. Leaving the pin dangling
            # makes build_singbox_config drop it and route the chain through the
            # all-nodes urltest group, which then competes with the rotation for
            # VPNGate's single session per node ("one dead, two dead").
            result = self._rescue_chain(f"pin {tag} left the snapshot", round_id)
            self._set_pin_health("ok" if result == "rescued" else "degraded")
            return result
        endpoint = node.get("endpoint") or node
        probe = probe_fn or (lambda host, port: probe_tcp_latency(host, port, 5))
        hand = 0
        # The pin is only dead when *every* remote fails: sing-box fails over
        # within the endpoint, so probing just the first address would rescue
        # away from a chain that still carries traffic.
        for host, port in endpoint_remotes(endpoint):
            try:
                hand = probe(host, port)
            except Exception:
                hand = 0
            if hand and hand > 0:
                break
        alive = hand > 0
        # Served-chain evidence in gateway AND rotate mode. None means the
        # verifier itself is unavailable, which must not trigger a rescue.
        chain_ok = self._chain_probe_ok()
        if alive:
            with self._lock:
                node["latency_ms"] = hand
                recovered = self._pinned_fail_streak > 0
                self._pinned_fail_streak = 0
                self._pinned_standby_noted = None
            if recovered:
                self._record_history("health-dial-ok", f"{tag} handshake recovered ms={hand}")
            if self.want_singbox and not self._serving_ok():
                self._note_mixed_down(f"{tag} serving down, watching")
                self._set_pin_health("degraded", "serving unreachable")
                return "pinned"
            if chain_ok is None:
                self._set_pin_health("unknown", "served exit probe unavailable")
                return "pinned"
            with self._lock:
                if chain_ok:
                    chain_recovered = self._chain_fail_streak > 0
                    self._chain_fail_streak = 0
                    self._chain_rescue_attempts = 0
                    # This node carries the chain again: it is not dead.
                    self._chain_dead_until.pop(tag, None)
                    chain_streak = 0
                elif warmed:
                    # Too early to judge: the endpoint may still be dialing.
                    self._chain_fail_streak = 0
                    chain_streak = 0
                else:
                    self._chain_fail_streak += 1
                    chain_streak = self._chain_fail_streak
            if chain_ok:
                if chain_recovered:
                    self._record_history("chain-probe-ok", f"{tag} chain carries traffic again")
                self._set_pin_health("ok")
                return "pinned"
            if chain_streak < CHAIN_FAIL_THRESHOLD:
                self._record_history("chain-probe-fail",
                                     f"{tag} {chain_streak}/{CHAIN_FAIL_THRESHOLD} tunnel probes failed")
                self._set_pin_health("degraded",
                                     f"tunnel probe {chain_streak}/{CHAIN_FAIL_THRESHOLD} failed")
                return "pinned"
            result = self._rescue_chain(f"{tag} tunnel dead {chain_streak}x", round_id)
            self._set_pin_health("ok" if result == "rescued" else "degraded",
                                 None if result == "rescued" else "tunnel dead, no verified alternative")
            return result
        with self._lock:
            self._pinned_fail_streak += 1
            streak = self._pinned_fail_streak
        if warmed:
            # A pin we just moved to needs time to come up before its
            # handshake failure means anything.
            self._set_pin_health("degraded")
            return "pinned"
        if chain_ok is True:
            # The pin's handshake is gone, but the chain still exits a real IP
            # (a hot switch already moved the selector). Repinning here would
            # rewrite the config and restart sing-box for zero benefit, so leave
            # the pair alone; only a real failure - the chain path itself dead -
            # may repin.
            with self._lock:
                if self._pinned_standby_noted != tag:
                    self._pinned_standby_noted = tag
                    self._record_history(
                        "chain-on-standby",
                        f"{tag} handshake dead but the chain still exits")
                self._pinned_fail_streak = 0
            self._set_pin_health("ok")
            return "pinned"
        attempted_rescue = False
        if chain_ok is False:
            with self._lock:
                self._chain_fail_streak += 1
                chain_streak = self._chain_fail_streak
            if chain_streak >= CHAIN_FAIL_THRESHOLD:
                attempted_rescue = True
                result = self._rescue_chain(f"{tag} tunnel dead {chain_streak}x", round_id)
                if result == "rescued":
                    self._set_pin_health("ok")
                    return result
        if streak < PINNED_FAIL_THRESHOLD:
            self._record_history("pin-handshake-fail",
                                 f"{tag} {streak}/{PINNED_FAIL_THRESHOLD} handshakes failed")
            self._set_pin_health("degraded",
                                 f"handshake {streak}/{PINNED_FAIL_THRESHOLD} failed")
            return "pinned"
        with self._lock:
            now = time.monotonic()
            cands = self._chain_candidates_locked(now) if self.auto_rescue else []
            if not cands and self.auto_rescue:
                # Nothing is tunnel-verified yet (cold start): handshake
                # verification is enough to move the pin off a dead node.
                cands = sorted(
                    (n for n in self._nodes
                     if (n.get("endpoint") or {}).get("tag") != tag
                     and n.get("latency_ms") is not None
                     and self._chain_dead_until.get(
                         (n.get("endpoint") or {}).get("tag") or "", 0.0) <= now),
                    key=lambda n: (n.get("latency_ms") or 10**9,))
        alive_tags = self._fresh_probe_tags(cands) if self.auto_rescue else []
        if alive_tags:
            if not attempted_rescue:
                result = self._rescue_chain(f"{tag} handshake failed {streak}x", round_id)
                if result == "rescued":
                    self._set_pin_health("ok")
                    return result
            # A verifiable alternative exists but none passed the served-exit
            # check: keep the pin and ask for a fresh snapshot.
            self._trigger_bg_refresh(f"{tag} no candidate verified")
            self._set_pin_health("degraded", "no verified alternative for the dead pin")
            return "pinned"
        # Every candidate handshake is dead too: the pool is stale.
        self._trigger_bg_refresh(f"{tag} all handshakes dead")
        if self.resi_rotate:
            # Rotate mode keeps the chain pinned to exactly one node. With
            # the pin dropped the chain falls back to urltest over the very
            # endpoints the rotation is dialing, and both paths fight for
            # VPNGate's single session per node: /ws-resi keeps working
            # while /ws-chain silently dies ("one dead, two dead").
            with self._lock:
                self._pinned_fail_streak = 0
            self._record_history("auto-pin-kept", f"{tag} dead but rotate mode keeps the chain pinned")
            self._set_pin_health("dead", "pin dead, rotate mode keeps it")
            return "pinned"
        with self._lock:
            self._pinned_fail_streak = 0
        with self._config_lock:
            with self._lock:
                self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = True
                self.status["preferred_tag"] = None; self.status["backup_tag"] = None; self.status["auto_pinned"] = True
                self._rescue_round += 1
                self._persist_state(); self._invalidate_verify(f"unpinned after {tag} failed")
            self._apply_config(final="auto")
        self._record_history("auto-unpin", f"{tag} handshake failed {PINNED_FAIL_THRESHOLD}x")
        self._set_pin_health("unpinned")
        return "unpinned"

    def _commit_rescue(self, round_id: int, best: str | None, second: str | None) -> bool:
        with self._lock:
            if self._rescue_round != round_id:
                self._record_history("auto-pin-skipped", "manual switch won the race")
                return False
            self.preferred_tag = best; self.backup_tag = second; self._auto_pinned = True
            self._chain_pin_at = time.monotonic()
            self.status["preferred_tag"] = best; self.status["backup_tag"] = second; self.status["auto_pinned"] = True
            self._persist_state()
            return True
    def switch(self, tag: str | None = None, country: str | None = None) -> tuple[bool, str]:
        with self._pin_switch_lock:
            return self._switch_impl(tag=tag, country=country)

    def _switch_impl(self, tag: str | None = None, country: str | None = None) -> tuple[bool, str]:
        with self._lock:
            if not self._nodes:
                return False, "no nodes loaded"
            node = None
            if country:
                wanted = country.strip().upper()
                cands = [n for n in self._nodes if n.get("country_short", "").upper() == wanted or wanted in n.get("country", "").upper()]
                if not cands:
                    return False, f"no nodes for country {country}"
                cands.sort(key=lambda n: ((0, n["real_latency_ms"]) if n.get("real_latency_ms") is not None else (1, n.get("latency_ms") if n.get("latency_ms") is not None else 10**9), -(n.get("speed") or 0)))
                node = cands[0]
            elif tag in (None, "", "auto"):
                target: str | None = None
            else:
                node = next((n for n in self._nodes if n.get("endpoint", {}).get("tag") == tag), None)
                if node is None:
                    return False, f"unknown tag {tag}"
            target = node["endpoint"]["tag"] if node is not None else None
            effective = "chain" if target else "auto"
            old_preferred = self.preferred_tag
            # Invalidate every rescue/verify round that started before this
            # switch BEFORE any side effect, so a slow rescuer cannot commit
            # over the operator's choice while the selector is half moved.
            self._rescue_round += 1
        if target is None:
            # Unpin: back to the urltest group. A config rewrite is the safe
            # path here (the selector may still point at a hot-switched tag).
            if not self._config_lock.acquire(timeout=5):
                return False, "busy, retry later"
            try:
                if not self._apply_config(final="auto", preferred=None):
                    return False, "config check failed, kept previous"
            finally:
                try:
                    self._config_lock.release()
                except Exception:
                    pass
            with self._lock:
                self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = True
                self.status["preferred_tag"] = None; self.status["backup_tag"] = None
                self.status["auto_pinned"] = True
                self._chain_pin_at = time.monotonic()
                self._rescue_round += 1
                self._persist_state()
                self._pinned_fail_streak = 0; self._chain_fail_streak = 0
            if old_preferred is not None:
                self._invalidate_verify("pin-cleared")
            self._set_pin_health("unpinned")
            self._record_history("switch", "final=auto")
            return True, effective
        candidate_node = next(n for n in self._nodes
                              if n.get("endpoint", {}).get("tag") == target)
        fresh_evidence = self._fresh_alive_evidence(candidate_node)
        hot = self._repin_runtime(target, "manual switch")
        if not hot:
            if not self._config_lock.acquire(timeout=5):
                return False, "busy, retry later"
            try:
                if not self._apply_config(final="auto", preferred=target):
                    return False, "config check failed, kept previous"
            finally:
                try:
                    self._config_lock.release()
                except Exception:
                    pass
        if self.want_singbox:
            ok_verify, exit_ip, ms, attempted = self._verify_served(retries=2)
            if not ok_verify and not attempted and fresh_evidence:
                # No verifier configured yet: a fresh tunnel/dial proof is the
                # strongest evidence available, so the switch may proceed.
                ok_verify = True
            if not ok_verify:
                self._restore_runtime_pin(old_preferred, hot)
                detail = ("node tunnel dead: served chain has no exit ip"
                          if attempted else "node tunnel dead: no verifier available")
                self._record_history("switch-rejected", f"{target}: {detail}")
                self._set_pin_health("degraded", detail)
                return False, detail
            if exit_ip:
                self._record_evidence(candidate_node, True, exit_ip, ms, None)
        with self._lock:
            self.preferred_tag = target; self.backup_tag = None; self._auto_pinned = False
            self.status["preferred_tag"] = target; self.status["backup_tag"] = None
            self.status["auto_pinned"] = False
            self._chain_pin_at = time.monotonic()
            self._pinned_fail_streak = 0; self._chain_fail_streak = 0
            self._rescue_round += 1
            self._persist_state()
        if old_preferred != target:
            self._invalidate_verify(f"pin-changed to {target}")
        self._set_pin_health("ok")
        self._record_history("switch", f"final={effective}")
        return True, effective

    def _serving_nodes(self) -> list[dict]:
        with self._lock:
            nodes = list(self._nodes); preferred = self.preferred_tag; backup = self.backup_tag
        def _rank(n: dict):
            real = n.get("real_latency_ms"); hand = n.get("latency_ms")
            if real is not None:
                return (0, real)
            if hand is not None:
                return (1, hand)
            return (2, 10**9)
        ordered = sorted(nodes, key=_rank)
        top = ordered[:MAX_SERVING_ENDPOINTS]
        tags = {(n.get("endpoint") or {}).get("tag") for n in top}
        for t in (preferred, backup):
            if t and t not in tags:
                hit = next((n for n in nodes if (n.get("endpoint") or {}).get("tag") == t), None)
                if hit is not None:
                    top.append(hit); tags.add(t)
        return top

    def _ordered_serving(self) -> list[dict]:
        """Serving nodes in a config-stable order (by endpoint tag).

        Order must not follow latency ranking: every probe reshuffles it, the
        written config would look "changed", and sing-box would restart -
        dropping every live connection of all three paths. The pool selection
        happens at runtime instead (see _resi_pool_locked).
        """
        return sorted(self._serving_nodes(),
                      key=lambda n: ((n.get("endpoint") or {}).get("tag") or "",))

    def _rotate_routes(self, serving: list[dict]) -> list[tuple[str, int]]:
        """(endpoint tag, loopback port) for every serving node, in config order.

        Rotate mode gives *every* serving node its own VLESS inbound; which of
        them may actually serve a client is decided at runtime by the health
        pool, never by rewriting the config. Baking the pool into the config
        was a real bug: each health change rewrote the file and restarted
        sing-box, so one dead VPNGate node took the direct and chain paths down
        with it.
        """
        if not self.resi_rotate:
            return []
        return [((n.get("endpoint") or {}).get("tag") or "", RESI_ROTATE_BASE + i)
                for i, n in enumerate(serving)]

    def _serving_config_unchanged(self, config: dict) -> bool:
        try:
            with open(self.config_path, encoding="utf-8") as handle:
                current = json.load(handle)
        except (OSError, ValueError):
            return False
        for key in ("endpoints", "outbounds", "route", "inbounds"):
            if current.get(key) != config.get(key):
                return False
        return True
    def _clash_call(self, path: str, payload: dict | None = None, timeout: float = 3.0) -> tuple[int, str]:
        """One call against the loopback Clash API (0 = not answerable)."""
        if not self.clash_api_port:
            return 0, ""
        url = f"http://127.0.0.1:{self.clash_api_port}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="PUT" if data is not None else "GET")
        request.add_header("Authorization", f"Bearer {self.clash_api_secret}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return int(response.status), response.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return int(exc.code), ""
        except Exception:
            return 0, ""

    def _clash_api_ready(self, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and self._clash_ready_at and now - self._clash_ready_at < 5.0:
            return True
        code, _ = self._clash_call("/version", timeout=1.5)
        self._clash_ready_at = now if code == 200 else 0.0
        chain_status = self.status.get("chain_switch")
        if isinstance(chain_status, dict):
            chain_status["ready"] = code == 200
        return code == 200

    def _clash_select(self, tag: str) -> bool:
        """Move the "chain" selector to `tag` without touching the config.

        This is the whole point of the Clash API path: a repin must not rewrite
        the config, because a rewrite restarts sing-box and kills every live
        connection of all three paths - the collateral damage that used to take
        /ws-resi down together with the chain.
        """
        if not tag:
            return False
        with self._clash_switch_lock:
            code, _ = self._clash_call("/proxies/chain", {"name": tag})
            if code not in (200, 204):
                return False
            # A 200 from PUT is not proof the selector moved. Read it back
            # before the caller commits the pin; otherwise a "successful"
            # switch reports 200 while the live selector still points at the
            # old node.
            now_code, body = self._clash_call("/proxies/chain", timeout=2.0)
            moved = False
            if now_code == 200:
                try:
                    moved = (json.loads(body).get("now") == tag)
                except (ValueError, AttributeError):
                    moved = False
            if not moved:
                self._record_history("chain-select-unconfirmed", f"{tag} not selected")
                return False
            self._clash_ready_at = time.monotonic()
            chain_status = self.status.get("chain_switch")
            if isinstance(chain_status, dict):
                chain_status["ready"] = True
                chain_status["switches"] = int(chain_status.get("switches", 0)) + 1
            return True

    def _chain_selector_tags(self) -> list[str]:
        """Every serving tag the "chain" selector may hot-switch to.

        Sorted by tag on purpose: the config must stay byte-identical when the
        pin changes, otherwise every repin rewrites the file and restarts
        sing-box again. Which tag is picked is decided at switch time by the
        evidence ranking; only the *candidate set* lives in the config.
        """
        serving = {(node.get("endpoint") or {}).get("tag") for node in self._serving_nodes()}
        return sorted(tag for tag in serving if tag)

    def _repin_runtime(self, tag: str, reason: str) -> bool:
        """Hot-switch the chain; False means "fall back to a config rewrite"."""
        if not (self.resi_rotate and self.want_singbox and tag):
            return False
        if not self._clash_api_ready():
            return False
        if not self._clash_select(tag):
            self._record_history("chain-hot-switch-failed", f"{reason}: {tag}")
            return False
        return True

    def _repoint_chain(self, tag: str | None, round_id: int, reason: str) -> bool:
        """Point the chain at `tag`: hot switch first, config rewrite as fallback."""
        if not tag:
            return False
        hot = self._repin_runtime(tag, reason)
        with self._config_lock:
            if hot:
                return self._commit_rescue(round_id, tag, None)
            if not self._apply_config(final="auto", preferred=tag, backup=None):
                return False
            return self._commit_rescue(round_id, tag, None)

    def _reapply_pin_when_ready(self) -> None:
        """After a restart sing-box starts on the config's default pin.

        A pin that only ever existed as a hot switch is not in the file, so put
        it back as soon as the API answers.
        """
        for _ in range(60):
            tag = self.preferred_tag
            if not tag:
                return
            try:
                if self._clash_api_ready(force=True) and self._clash_select(tag):
                    return
            except Exception:
                pass
            time.sleep(0.5)

    def _apply_config(self, final: str = "auto", preferred: str | None = None, backup: str | None = None) -> bool:
        serving = self._ordered_serving()
        resi_outbound = self._resi_outbound()
        rotate_routes = self._rotate_routes(serving)
        rotate_tags = [tag for tag, _ in rotate_routes]
        with self._lock:
            endpoints = [n["endpoint"] for n in serving]
            username, password = self.username, self.password; mixed_port = self.mixed_port
            vless_uuid = self.vless_uuid or None; direct_port = self.vless_direct_port; chain_port = self.vless_chain_port
            resi_port = self.resi_port; resi_path = self.resi_path
            config_path = self.config_path; last_good_path = self.last_good_path; want_singbox = self.want_singbox
            clash_api = ({"external_controller": f"127.0.0.1:{self.clash_api_port}",
                          "secret": self.clash_api_secret}
                         if (self.clash_api_port and want_singbox) else None)
            candidates = self._chain_selector_tags() if self.resi_rotate else None
        config = build_singbox_config(endpoints, "127.0.0.1", mixed_port, mixed_users=[(username, password)],
            final=final, preferred=preferred, backup=backup, vless_uuid=vless_uuid,
            vless_direct_port=direct_port, vless_chain_port=chain_port,
            resi=resi_outbound, resi_port=resi_port, resi_path=resi_path,
            resi_rotate=self.resi_rotate, resi_rotate_tags=rotate_tags,
            chain_candidates=candidates, clash_api=clash_api)
        if self.resi_rotate:
            self._set_resi_routes(rotate_routes)
        if want_singbox and self._serving_config_unchanged(config):
            with self._lock:
                proc = self._singbox_proc
                if proc is not None and proc.poll() is None:
                    return True
        tmp_path = f"{config_path}.tmp-{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2); handle.write("\n")
        if not self._check_config(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return False
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, config_path)
        try:
            with open(config_path, "rb") as src:
                payload = src.read()
            with open(last_good_path, "wb") as dst:
                dst.write(payload)
            try:
                os.chmod(last_good_path, 0o600)
            except OSError:
                pass
        except OSError:
            pass
        if want_singbox:
            # Only the write path reaches here: an unchanged config returns early
            # above, so this line always means "sing-box is about to restart".
            self._log(f"config rewritten: {len(endpoints)} serving endpoints, restarting sing-box",
                  flush=True)
            self._restart_singbox()
            # A fresh config (and a fresh process) deserves a fresh chain probe:
            # the first attempt after a restart races the endpoints coming up.
            with self._lock:
                self._chain_fail_streak = 0
        return True

    def _start_refresh_bg(self) -> bool:
        """Start a snapshot refresh in background (202-style, single-flight).

        TopK refresh holds the post slot for minutes (TopK x dial_timeout /
        workers); answering sync would wedge every management POST behind
        it. A second starter while one runs gets False (caller answers 409).
        Progress is visible via status refresh_job.
        """
        with self._lock:
            cur = self.status.get("refresh_job") or {}
            if cur.get("state") == "running" and self._refresh_thread is not None and self._refresh_thread.is_alive():
                if time.monotonic() - cur.get("started_at", 0.0) < STALE_RUNNING_AFTER:
                    return False
            self._refresh_generation += 1
            gen = self._refresh_generation
            self.status["refresh_job"] = {"state": "running", "started_at": time.monotonic(), "ok": None, "error": None, "generation": gen}
            thread = threading.Thread(target=self._run_refresh_bg, args=(gen,), daemon=True, name="refresh-bg")
            self._refresh_thread = thread
            thread.start()
        return True

    def _run_refresh_bg(self, gen: int) -> None:
        try:
            ok = self.refresh_once()
            with self._lock:
                err = None if ok else (self.status.get("last_error") or "refresh failed")
        except Exception as exc:
            ok, err = False, f"{type(exc).__name__}: {exc}"
        with self._lock:
            if gen != self._refresh_generation:
                return
            if self._refresh_thread is not None and self._refresh_thread is not threading.current_thread():
                return
            cur = self.status.get("refresh_job") or {}
            if cur.get("generation") is not None and cur.get("generation") != gen:
                return
            self.status["refresh_job"] = {"state": "done",
                "started_at": cur.get("started_at"),
                "ok": ok, "error": err, "generation": gen}

    def refresh_once(self, fetcher=None, probe_pool: int = 0) -> bool:
        if not self._refresh_lock.acquire(blocking=False):
            self._record_history("refresh-busy", "skipped: another refresh in progress")
            return False
        try:
            return self._refresh_once_inner(fetcher, probe_pool)
        finally:
            self._refresh_lock.release()
    def _refresh_once_inner(self, fetcher=None, probe_pool: int = 0) -> bool:
        # Rotate mode never re-dials a node it may be serving right now: that
        # would open a second VPNGate session (duplicate-cn is off) and kick the
        # live one, i.e. the refresh itself would kill good nodes. Those nodes
        # keep their previous verification and are handed back unchanged.
        #
        # In rotate mode it does not dial ANY node: the throwaway client would
        # hold the node's single VPNGate session *before* the serving instance
        # logs in, and the serving endpoint then never gets past the
        # authentication (the session is still taken) - the cloud acceptance
        # saw exactly that: 15 of 16 endpoints had their TCP up but their
        # tunnel never came up, and the only working one was the node that had
        # been dialed first. The full probe measures the same nodes through
        # their own serving endpoints (no second session), so it is the one
        # that fills the pool.
        with self._lock:
            old_nodes = list(self._nodes)
            old_preferred = self.preferred_tag
            old_backup = self.backup_tag
            old_auto = self._auto_pinned
            old_tag_key = {((n.get("endpoint") or {}).get("tag")): f"{n.get('server')}:{n.get('server_port')}"
                           for n in old_nodes if (n.get("endpoint") or {}).get("tag")}
            reserved_tags = {t for t in (old_preferred, old_backup) if t}
        skip_keys: set[tuple[str, int]] = set()
        carried: dict[tuple[str, int], int] = {}
        for node in old_nodes:
            key = (node.get("server"), node.get("server_port"))
            tag = (node.get("endpoint") or {}).get("tag")
            serving = self.resi_rotate or tag in reserved_tags
            if serving:
                skip_keys.add(key)
            real = node.get("real_latency_ms")
            evidence = self._node_evidence.get(f"{key[0]}:{key[1]}")
            if real is not None and (serving or self._evidence_is_fresh(evidence)):
                carried[key] = real
        try:
            fetch = fetcher or self.fetcher
            csv_text = self._fetch_with_retry(fetch)
            nodes = snapshot_to_nodes(csv_text, limit=self.limit, probe_pool=probe_pool,
                probe_fn=lambda h, p: probe_tcp_latency(h, p, 5), probe_workers=self.probe_workers,
                real_topk=(0 if self.resi_rotate else self.real_topk),
                dial_fn=self.dial_fn, dial_workers=self.dial_workers,
                dial_timeout=self.dial_timeout, singbox_bin=self.singbox_bin,
                skip_dial_keys=skip_keys)
            if not nodes:
                return self._refresh_failed("no reachable nodes, kept previous")
        except Exception as exc:
            return self._refresh_failed(f"{type(exc).__name__}: {exc}")
        for node in nodes:
            if node.get("real_latency_ms") is None:
                real = carried.get((node.get("server"), node.get("server_port")))
                if real is not None:
                    node["real_latency_ms"] = real
        for node in nodes:
            # A TCP handshake is weak evidence, so it never overwrites a fresh
            # exit proof; it only revives a node whose evidence went stale.
            if (node.get("real_latency_ms") is not None or node.get("latency_ms") is not None):
                ev = self._node_evidence.get(f"{node.get('server')}:{node.get('server_port')}")
                if not self._evidence_is_fresh(ev):
                    self._note_dial_ok(node, node.get("real_latency_ms"))
        with self._lock:
            old_seen = dict(self._first_seen); now = _now_iso(); cur_keys = set()
            for node in nodes:
                key = f"{node['server']}:{node['server_port']}"
                cur_keys.add(key)
                self._first_seen.setdefault(key, old_seen.get(key, now))
            for key in [k for k in self._first_seen if k not in cur_keys]:
                del self._first_seen[key]
            assign_stable_tags(nodes, old_nodes)
            self._nodes = nodes
            self._nodes_rev += 1
            endpoints = nodes_to_endpoints(nodes)
            tags = {ep["tag"] for ep in endpoints}
            new_tag_key = {ep["tag"]: f"{primary_server(ep)[0]}:{primary_server(ep)[1]}"
                           for ep in endpoints}
            pin_gone = False
            next_preferred = old_preferred
            if old_preferred is not None:
                # A tag is only the same pin when it still maps to the same
                # server:port. If the old owner vanished, the tag may have
                # been recycled by a new node - following it would silently
                # jump the pin to a different server.
                if (old_preferred not in tags
                        or new_tag_key.get(old_preferred) != old_tag_key.get(old_preferred)):
                    pin_gone = True
                    next_preferred = None
            next_backup = old_backup
            if (next_preferred is None or old_backup is None
                    or old_backup not in tags
                    or new_tag_key.get(old_backup) != old_tag_key.get(old_backup)):
                next_backup = None
        with self._pin_switch_lock:
          with self._lock:
            # A manual switch may have landed while the snapshot was fetched
            # and probed. Never overwrite it with the stale snapshot pin.
            live_preferred = self.preferred_tag
            live_backup = self.backup_tag
            live_auto = self._auto_pinned
            pin_gone = False
            if live_preferred != old_preferred or live_backup != old_backup:
                next_preferred = live_preferred
                next_backup = live_backup
                if next_preferred is not None:
                    old_key = old_tag_key.get(next_preferred)
                    if (next_preferred not in tags
                            or (old_key is not None
                                and new_tag_key.get(next_preferred) != old_key)):
                        pin_gone = True
                        next_preferred = None
                if (next_preferred is None or next_backup is None
                        or next_backup not in tags
                        or (old_tag_key.get(next_backup) is not None
                            and new_tag_key.get(next_backup) != old_tag_key.get(next_backup))):
                    next_backup = None
                old_auto = live_auto
          with self._config_lock:
            if not self._apply_config(final="auto", preferred=next_preferred, backup=next_backup):
                return self._refresh_failed("config check failed, kept previous")
            with self._lock:
                pin_changed = (self.preferred_tag != next_preferred) or pin_gone
                if pin_gone and old_preferred:
                    self._record_history("preferred-gone", f"{old_preferred} vanished, back to auto")
                    self._auto_pinned = True
                else:
                    self._auto_pinned = old_auto
                self.preferred_tag = next_preferred; self.backup_tag = next_backup
                if pin_changed:
                    self._rescue_round += 1
                self.status["endpoints"] = [self._endpoint_row(ep, n)
                                            for ep, n in zip(endpoints, nodes)]
                self.status["countries"] = self._countries()
                self.status["preferred_tag"] = self.preferred_tag; self.status["backup_tag"] = self.backup_tag
                self.status["auto_pinned"] = self._auto_pinned; self.status["last_refresh"] = _now_iso()
                self.status["last_error"] = None; self.status["refresh_ok"] += 1
                self._fail_streak = 0; self._crash_streak = 0
                live_keys = {f"{n.get('server')}:{n.get('server_port')}" for n in nodes}
                self._node_evidence = {k: v for k, v in self._node_evidence.items()
                                       if k in live_keys}
        if pin_gone:
            self._invalidate_verify(f"pin {old_preferred} left the snapshot")
        self._persist_nodes(); self._persist_state()
        effective = "chain" if next_preferred else "auto"
        self._record_history("refresh-ok", f"{len(endpoints)} endpoints, final={effective}")
        self._log(f"refreshed {len(endpoints)} endpoints, final={effective}", flush=True)
        # Startup/refresh only real-dials REAL_TOPK nodes so the first serving
        # config lands fast. Kick the full pass in the background: it is what
        # turns the handshake-ranked snapshot into a verified node set (the
        # third path may only rotate over verified nodes).
        self._start_full_probe()
        return True

    def _refresh_failed(self, reason: str) -> bool:
        with self._lock:
            self.status["last_error"] = reason; self.status["refresh_fail"] += 1; self._fail_streak += 1
        self._record_history("refresh-fail", reason)
        self._log(f"refresh failed: {reason}", flush=True)
        return False
    def _start_full_probe(self) -> bool:
        with self._lock:
            cur = self.status.get("full_probe") or {}
            if cur.get("state") == "running" and self._full_probe_thread is not None and self._full_probe_thread.is_alive():
                if time.monotonic() - cur.get("started_at", 0.0) < STALE_RUNNING_AFTER:
                    return False
            self.status["full_probe"] = {"state": "running", "done": 0, "total": len(self._nodes), "started_at": time.monotonic()}
        thread = threading.Thread(target=self._run_full_probe, daemon=True, name="full-probe")
        self._full_probe_thread = thread
        thread.start()
        return True
    def _run_full_probe(self) -> None:
        time.sleep(0.2)
        try:
            self._run_full_probe_inner()
        except Exception as exc:
            self._log(f"full probe error: {type(exc).__name__}: {exc}", flush=True)
        finally:
            with self._lock:
                if self.status.get("full_probe", {}).get("state") == "running":
                    self.status["full_probe"]["state"] = "done"

    def _full_probe_targets_locked(self) -> list[dict]:
        """Nodes a full probe may dial without stealing a live VPNGate session.

        VPNGate allows one OpenVPN session per node (duplicate-cn is off) and
        every node we serve already holds one through its rotate endpoint, so
        dialing a *serving* node kicks the very connection a user is riding on:
        the probe reports the node dead, the rotation parks a healthy node, and
        the chain path can lose its pin the same way ("one dead, two dead").
        Rotate mode therefore re-verifies only nodes that are out of service
        right now (parked, or never tunnel-verified) - exactly the nodes a
        probe can heal - and never the chain's own pin/backup.
        """
        nodes = list(self._nodes)
        reserved = {tag for tag in (self.preferred_tag, self.backup_tag) if tag}
        if not (self.resi_rotate and self.vless_uuid):
            # Gateway mode: one urltest outbound, so only the pin/backup are
            # worth protecting; everything else is a legit probe target.
            return [n for n in nodes
                    if (n.get("endpoint") or {}).get("tag") not in reserved]
        _usable, _parked, eligible = self._resi_pool_locked()
        active = {tag for tag, _ in eligible}
        targets: list[dict] = []
        for node in nodes:
            tag = (node.get("endpoint") or {}).get("tag")
            if tag in reserved or tag in active:
                continue
            targets.append(node)
        return targets

    def _resi_port_for_tag(self, tag: str) -> int | None:
        """The loopback inbound that serves exactly this node (rotate mode)."""
        for served_tag, port in self._resi_routes:
            if served_tag == tag:
                return port
        return None

    def _measure_for_probe(self, node: dict) -> int | None:
        """Measure one node for the full probe, without stealing a session.

        Rotate mode measures through the node's OWN serving endpoint (the
        loopback inbound the rotation already holds), never with a throwaway
        OpenVPN client: a second VPNGate session kicks the serving one
        (duplicate-cn) and the serving side does not retry ("auth-retry
        none"), so the probe used to leave the serving set full of zombies -
        the chain then had to walk dead candidates when its pin died
        (measured: 6.5 minutes). The client here is a plain VLESS client
        against our own loopback port, so no VPNGate session is opened.
        """
        tag = (node.get("endpoint") or {}).get("tag")
        if self.resi_rotate and self.vless_uuid and tag:
            port = self._resi_port_for_tag(tag)
            if port:
                try:
                    got = measure_resi_rotate(
                        self.vless_uuid, port, self.resi_path, count=1,
                        singbox_bin=self.singbox_bin,
                        timeout=self.dial_timeout)
                except Exception:
                    got = None
                if got and got.get("ips"):
                    return got.get("first_ms")
                return None
        try:
            return self.dial_fn(node) if self.dial_fn else None
        except Exception:
            return None

    def _chain_candidate_carries_traffic(self, node: dict) -> bool:
        """Does this node carry traffic RIGHT NOW?

        The rotation's exit-IP evidence is a snapshot: a node that carried
        traffic an hour ago may have a dead OpenVPN session now (the control
        channel stays up while the data channel is gone). The cloud
        acceptance measured exactly that - 15 of 16 nodes were connected but
        silent, and the chain walked them one by one for six minutes.

        In rotate mode the node's own serving endpoint is the only honest
        witness, so ask it. Gateway mode has no per-node endpoint and keeps
        the old behaviour.
        """
        tag = (node.get("endpoint") or {}).get("tag")
        if not (self.resi_rotate and self.vless_uuid and tag):
            return True
        port = self._resi_port_for_tag(tag)
        if not port:
            return False
        try:
            got = measure_resi_rotate(
                self.vless_uuid, port, self.resi_path, count=1,
                singbox_bin=self.singbox_bin, timeout=self.dial_timeout)
        except Exception:
            got = None
        return bool(got and got.get("ips"))

    def _chain_traffic_candidates(self, cands: list[dict]) -> list[dict]:
        """The candidates that carry traffic right now, best first.

        A node's measured latency is not evidence that it still works, so only
        nodes that answer now may be returned. There is deliberately no
        candidate cap and no "best ranked dead node" fallback: a rescue that
        cannot find live traffic must keep the current pin (the caller records
        chain-rescue-skipped and refreshes) instead of moving onto a corpse.
        """
        if not (self.resi_rotate and self.vless_uuid) or not cands:
            return cands
        alive = [n for n in cands if self._chain_candidate_carries_traffic(n)]
        if not alive:
            # A state of the pool, not a rescue failure.
            self._record_history(
                "chain-rescue-blind",
                f"no candidate carries traffic right now "
                f"({len(cands)} candidates asked)")
        return alive

    def _probe_target_started_serving(self, tag: str) -> bool:
        """True when the node started serving while a probe was running.

        The probe's target list is computed when the probe starts, so a node
        can join the rotation in between: dialing it then would open a second
        VPNGate session and duplicate-cn would kick the live one (D13). The
        check therefore has to be repeated right before the dial.
        """
        with self._lock:
            reserved = {t for t in (self.preferred_tag, self.backup_tag) if t}
            if tag in reserved:
                return True
            if not (self.resi_rotate and self.vless_uuid):
                return False
            _usable, _parked, eligible = self._resi_pool_locked()
            return tag in {t for t, _ in eligible}

    def _run_full_probe_inner(self) -> None:
        with self._lock:
            nodes = list(self._nodes)
            targets = self._full_probe_targets_locked()
            self.status["full_probe"]["total"] = len(targets)
            self.status["full_probe"]["skipped"] = len(nodes) - len(targets)
            start_preferred = self.preferred_tag
        ordered = sorted(targets, key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("server") or ""))
        def _dial_one(node: dict) -> None:
            tag = (node.get("endpoint") or {}).get("tag")
            if tag and self._probe_target_started_serving(tag):
                # The node started serving while this probe was running:
                # dialing it now would open a second VPNGate session, and
                # duplicate-cn would kick the live one (D13).
                with self._lock:
                    self.status["full_probe"]["skipped"] += 1
                return
            ms = self._measure_for_probe(node)
            with self._lock:
                # A failed probe must not erase the last working measurement:
                # the node stays ranked by its old number, but its evidence
                # says it is dead right now (and rescue/auto-pin skip it).
                if ms is not None:
                    node["real_latency_ms"] = ms
                self.status["full_probe"]["done"] += 1
            if ms is not None:
                self._note_dial_ok(node, ms)
            elif not self._fresh_alive_evidence(node):
                self._record_evidence(node, False, None, None, "probe failed")
        with ThreadPoolExecutor(max_workers=self.full_probe_workers) as executor:
            list(executor.map(_dial_one, ordered))
        with self._lock:
            self._sync_probe_results(nodes)
        self._auto_pin_best(nodes, start_preferred)
        # The pin may not have changed, but the verified set did: republish so
        # the third path's rotation pool picks up the freshly dialed nodes.
        self._republish_config()
        skipped = len(nodes) - len(ordered)
        self._record_history("full-probe-done",
                             f"{len(ordered)} nodes dialed, {skipped} skipped")
        self._log(f"full probe done: {len(ordered)} of {len(nodes)} nodes dialed, "
              f"{skipped} skipped (serving or reserved), "
              f"{self.status['full_probe'].get('done')} checked", flush=True)
        # Only now is the pass really over: pinning above may rewrite the config
        # and restart sing-box, so publishing "done" earlier let a caller that
        # waits on the flag snapshot a process that was about to be replaced
        # (the restart then looked like unexplained churn).
        with self._lock:
            self.status["full_probe"]["state"] = "done"

    def _republish_config(self) -> None:
        """Re-apply the serving config from the current node set.

        Needed after a probe pass when the verified set changed the *pin* or
        the endpoint list. The rotation pool itself is runtime state now, so a
        plain verification result no longer rewrites the config: _apply_config
        short-circuits on the unchanged file and sing-box keeps running.
        """
        with self._config_lock:
            with self._lock:
                preferred = self.preferred_tag
                backup = self.backup_tag
            self._apply_config(final="auto", preferred=preferred, backup=backup)

    def _auto_pin_best(self, nodes: list[dict], start_preferred: str | None) -> None:
        with self._pin_switch_lock:
            return self._auto_pin_best_impl(nodes, start_preferred)

    def _auto_pin_best_impl(self, nodes: list[dict], start_preferred: str | None) -> None:
        def _fresh_dead(node: dict) -> bool:
            ev = self._node_evidence.get(self._node_key(node))
            return bool(self._evidence_is_fresh(ev) and ev.get("alive") is False)
        measured = sorted((n for n in nodes
                           if n.get("real_latency_ms") is not None
                           and (n.get("endpoint") or {}).get("tag")
                           and not _fresh_dead(n)),
            key=lambda n: (n["real_latency_ms"], (n.get("endpoint") or {}).get("tag") or ""))
        if not measured:
            self._record_history("auto-pin-skipped", "nothing measured")
            return
        with self._lock:
            rev = self._nodes_rev
            current = self.preferred_tag
            current_node = next((n for n in nodes
                                 if (n.get("endpoint") or {}).get("tag") == current), None) if current else None
            if current is not None:
                if not (self._auto_pinned and self.auto_repin):
                    self._record_history("auto-pin-skipped",
                                         "pin exists, manual full-probe keeps pin (use switch to change)")
                    return
                best_real = measured[0].get("real_latency_ms")
                current_real = current_node.get("real_latency_ms") if current_node else None
                if best_real is None or current_real is None or best_real >= current_real * 0.8:
                    self._record_history("auto-pin-skipped",
                                         "auto pin has no materially better verified node")
                    return
            elif start_preferred is not None and current != start_preferred:
                self._record_history("auto-pin-skipped", f"switched mid-run to {current}")
                return
        if not self.want_singbox:
            self._auto_pin_unserved(measured, current)
            return
        # Never pin a node the served chain has not exited through. A fresh
        # tunnel dial alone is not an exit proof, and a throwaway client would
        # kick the serving session (duplicate-cn).
        if not self._verifier_configured():
            self._record_history("auto-pin-skipped", "no served exit verifier")
            return
        if not (self._mixed_listening() or self._singbox_live()):
            # The serving stack is still coming up (or absent in a unit test):
            # do not rewrite/restart the config just to fail verification.
            self._record_history("auto-pin-skipped", "serving stack not ready")
            return
        expected = current
        if current is not None:
            candidates = [measured[0]]
        else:
            candidates = measured[:EXIT_VERIFY_CAP]
        for cand in candidates:
            tag = (cand.get("endpoint") or {}).get("tag")
            if not tag or tag == expected:
                continue
            cand_key = self._node_key(cand)
            hot = self._repin_runtime(tag, "auto-pin verify")
            if not hot:
                with self._config_lock:
                    if not self._apply_config(final="auto", preferred=tag, backup=None):
                        self._record_history("auto-pin-failed", tag)
                        continue
            ok, exit_ip, ms, attempted = self._verify_served(retries=2)
            if ok and exit_ip:
                self._record_evidence(cand, True, exit_ip, ms, None)
                committed = False
                with self._config_lock:
                    with self._lock:
                        live_node = next((n for n in self._nodes
                                          if (n.get("endpoint") or {}).get("tag") == tag), None)
                        if self._nodes_rev != rev:
                            skip = "node set changed during verify"
                        elif self.preferred_tag != expected:
                            skip = f"pin won the race to {self.preferred_tag}"
                        elif live_node is None or self._node_key(live_node) != cand_key:
                            skip = "candidate tag was remapped during verify"
                        else:
                            self.preferred_tag = tag
                            self.backup_tag = None
                            self._auto_pinned = True
                            self._chain_pin_at = time.monotonic()
                            self.status["preferred_tag"] = tag
                            self.status["backup_tag"] = None
                            self.status["auto_pinned"] = True
                            self._rescue_round += 1
                            self._persist_state()
                            committed = True
                            skip = ""
                if committed:
                    self._invalidate_verify(f"auto-pinned to {tag}")
                    self._set_pin_health("ok")
                    self._record_history("auto-pin", tag)
                    return
                with self._lock:
                    cur = self.preferred_tag
                self._restore_runtime_pin(cur, hot)
                self._record_history("auto-pin-skipped", skip)
                return
            with self._lock:
                cur = self.preferred_tag
            self._restore_runtime_pin(cur, hot)
            self._record_history("auto-pin-skipped", f"{tag} served chain did not verify")
        self._record_history("auto-pin-skipped", "no exit ip")

    def _auto_pin_unserved(self, measured: list[dict], current: str | None) -> None:
        """Legacy no-sing-box path: verify with `verify_fn`, which is safe
        because nothing is serving. Kept for start_singbox=False callers and
        cold-start tests."""
        if current is not None:
            self._record_history("auto-pin-skipped", "pin exists")
            return
        pinned = None; pinned_second = None
        if not self.resi_rotate:
            for i, cand in enumerate(measured[:EXIT_VERIFY_CAP]):
                tag = (cand.get("endpoint") or {}).get("tag")
                ep = cand.get("endpoint") or cand
                try:
                    ip, _ = self.verify_fn(ep)
                except Exception:
                    ip = None
                if ip:
                    pinned = tag
                    rest = [n for n in measured[i + 1:]
                            if (n.get("endpoint") or {}).get("tag") != tag]
                    for r in rest[:EXIT_VERIFY_CAP]:
                        try:
                            rip, _ = self.verify_fn(r.get("endpoint") or r)
                        except Exception:
                            rip = None
                        if rip:
                            pinned_second = (r.get("endpoint") or {}).get("tag")
                            break
                    break
        if pinned is None:
            if self.resi_rotate:
                # Rotate mode must never run with the chain unpinned; it may
                # not dial serving nodes either. Pin the best dial-verified
                # node without an exit probe.
                pinned = (measured[0].get("endpoint") or {}).get("tag")
                pinned_second = None
                with self._config_lock:
                    if not self._apply_config(final="auto", preferred=pinned, backup=None):
                        self._record_history("auto-pin-failed", pinned)
                        return
                    with self._lock:
                        if self.preferred_tag is not None:
                            self._record_history("auto-pin-skipped", "pin won the race")
                            return
                        self.preferred_tag = pinned; self.backup_tag = None; self._auto_pinned = True
                        self._chain_pin_at = time.monotonic()
                        self.status["preferred_tag"] = pinned; self.status["backup_tag"] = None
                        self.status["auto_pinned"] = True
                        self._rescue_round += 1
                        self._persist_state()
                self._invalidate_verify(f"auto-pinned to {pinned}")
                self._record_history("auto-pin-unverified", f"rotate mode pins {pinned} without exit ip")
                return
            self._record_history("auto-pin-skipped", "no exit ip")
            return
        with self._config_lock:
            if not self._apply_config(final="auto", preferred=pinned, backup=pinned_second):
                self._record_history("auto-pin-failed", pinned)
                return
            with self._lock:
                if self.preferred_tag is not None:
                    self._record_history("auto-pin-skipped", "pin won the race")
                    self._apply_config(final="auto", preferred=self.preferred_tag,
                                       backup=self.backup_tag)
                    return
                self.preferred_tag = pinned; self.backup_tag = pinned_second; self._auto_pinned = True
                self._chain_pin_at = time.monotonic()
                self.status["preferred_tag"] = pinned
                self.status["backup_tag"] = pinned_second
                self.status["auto_pinned"] = True
                self._rescue_round += 1
                self._persist_state()
        self._invalidate_verify(f"auto-pinned to {pinned}")
        self._record_history("auto-pin", pinned + (f" backup={pinned_second}" if pinned_second else ""))

    def _sync_probe_results(self, nodes: list[dict]) -> None:
        by_key: dict = {}
        for ep in self.status["endpoints"]:
            by_key.setdefault((ep.get("server"), ep.get("server_port")), []).append(ep)
        used = {ep.get("tag") for ep in self.status["endpoints"]}
        counter = 0
        for node in nodes:
            key = (node.get("server"), node.get("server_port"))
            if key in by_key:
                for ep in by_key[key]:
                    ep["real_latency_ms"] = node.get("real_latency_ms")
                continue
            while f"vpngate-{counter}" in used:
                counter += 1
            tag = f"vpngate-{counter}"; counter += 1; used.add(tag)
            self._first_seen.setdefault(f"{key[0]}:{key[1]}", _now_iso())
            entry = {"tag": tag, "server": node.get("server"), "server_port": node.get("server_port"),
                "country": node.get("country", ""), "country_short": node.get("country_short", ""),
                "latency_ms": node.get("latency_ms"), "real_latency_ms": node.get("real_latency_ms"), "speed": node.get("speed", 0)}
            entry.update({"alive": None, "exit_ip": None, "verified_at": None,
                          "verify_ms": None, "verify_error": None, "verify_fresh": False})
            self.status["endpoints"].append(entry)
            by_key[key] = [entry]
    @staticmethod
    def _running_fresh(state: dict, thread) -> bool:
        if state.get("state") != "running":
            return False
        if thread is not None and thread.is_alive():
            age = time.monotonic() - state.get("started_at", 0.0)
            return age < STALE_RUNNING_AFTER
        return False
    def _start_single_probe(self, node: dict) -> tuple[bool, str | None]:
        with self._lock:
            cur = self.status["probe"]
            if self._running_fresh(cur, self._single_probe_thread):
                return False, cur.get("tag")
            tag = node.get("endpoint", {}).get("tag")
            self.status["probe"] = {"state": "running", "tag": tag, "ms": None, "error": None, "started_at": time.monotonic()}
            thread = threading.Thread(target=self._run_single_probe, args=(node,), daemon=True, name=f"single-probe-{tag}")
            self._single_probe_thread = thread
            thread.start()
        return True, tag
    def _tag_may_be_serving(self, tag: str | None) -> bool:
        if not tag:
            return False
        with self._lock:
            if tag in (self.preferred_tag, self.backup_tag):
                return True
            if self.resi_rotate and any(served == tag for served, _ in self._resi_routes):
                return True
        return False

    def _run_single_probe(self, node: dict) -> None:
        time.sleep(0.2)
        tag = node.get("endpoint", {}).get("tag")
        if self._tag_may_be_serving(tag):
            # A throwaway client would open a second VPNGate session for a
            # node that is serving right now; duplicate-cn kicks the live one.
            # Ask the sidecar for its real delay, or measure through the
            # node's own rotate inbound. Refuse rather than dial.
            ms = None
            error = None
            delays = self._probe_delays([tag] if tag else [])
            if delays is not None and tag in delays:
                ms = delays[tag]
            else:
                # Only a real rotate inbound may be measured; _measure_for_probe
                # falls back to dial_fn, which must never run for a serving tag.
                if (self.resi_rotate and self.vless_uuid and tag
                        and self._resi_port_for_tag(tag)):
                    ms = self._measure_for_probe(node)
                if ms is None:
                    error = "node is serving; refused to dial it (duplicate-cn)"
            with self._lock:
                if ms is not None:
                    live = next((n for n in self._nodes
                                 if (n.get("endpoint") or {}).get("tag") == tag), node)
                    live["real_latency_ms"] = ms
                    node["real_latency_ms"] = ms
                    self._sync_probe_results([node])
                self.status["probe"] = {"state": "done", "tag": tag, "ms": ms, "error": error}
            self._record_history("single-probe", f"{tag} ms={ms}" + (" (serving, no dial)" if error else ""))
            return
        try:
            ms = self.dial_fn(node) if self.dial_fn else None
            error = None
        except Exception as exc:
            ms = None
            error = f"{type(exc).__name__}: {exc}"
        with self._lock:
            live = next((n for n in self._nodes if (n.get("endpoint") or {}).get("tag") == tag), node)
            live["real_latency_ms"] = ms
            node["real_latency_ms"] = ms
            self._sync_probe_results([node])
            self.status["probe"] = {"state": "done", "tag": tag, "ms": ms, "error": error}
        self._record_history("single-probe", f"{tag} ms={ms}")
    def _verify_target_node(self) -> dict | None:
        if self.preferred_tag:
            for node in self._nodes:
                if node.get("endpoint", {}).get("tag") == self.preferred_tag:
                    return node
        return self._nodes[0] if self._nodes else None
    def _start_verify(self, node: dict) -> tuple[bool, str | None]:
        with self._lock:
            cur = self.status["verify"]
            if self._running_fresh(cur, self._verify_thread):
                return False, cur.get("via_tag")
            tag = node.get("endpoint", {}).get("tag")
            self._verify_generation += 1
            gen = self._verify_generation
            self.status["verify"] = {"state": "running", "exit_ip": None, "ms": None, "via_tag": tag, "error": None, "checked_at": None, "generation": gen, "started_at": time.monotonic()}
            thread = threading.Thread(target=self._run_verify, args=(node, gen), daemon=True, name=f"verify-{tag}")
            self._verify_thread = thread
            thread.start()
        return True, tag
    def _run_verify(self, node: dict, gen: int) -> None:
        time.sleep(0.2)
        tag = node.get("endpoint", {}).get("tag")
        endpoint = node.get("endpoint") or node
        with self._lock:
            pin_tag = self.preferred_tag
        via_tag = pin_tag or tag
        attempted = False
        if self.want_singbox:
            # Gateway AND rotate mode: verify the chain that is actually
            # served, through the local mixed inbound. Never start a throwaway
            # client while sing-box is running - it opens a second VPNGate
            # session and duplicate-cn kicks the serving one.
            exit_ip, ms, attempted = self._served_exit_probe()
            if exit_ip:
                error = None
            elif attempted:
                error = "served chain has no exit ip"
            else:
                error = "served exit probe unavailable"
            if pin_tag and attempted:
                pin_node = next((n for n in self._nodes
                                 if (n.get("endpoint") or {}).get("tag") == pin_tag), None)
                if pin_node is not None:
                    self._record_evidence(pin_node, bool(exit_ip), exit_ip, ms, error)
        else:
            try:
                result = self.verify_fn(endpoint)
                exit_ip, ms = result if result else (None, None)
                error = None if exit_ip else "no exit ip measured"
                attempted = True
            except Exception as exc:
                exit_ip, ms = None, None
                error = f"{type(exc).__name__}: {exc}"
                attempted = True
            if attempted:
                self._record_evidence(node, bool(exit_ip), exit_ip, ms, error)
        checked_at = _now_iso()
        with self._lock:
            if gen != self._verify_generation:
                self._record_history("verify-discarded", f"{tag} superseded")
                return
            self.status["verify"] = {"state": "done", "exit_ip": exit_ip, "ms": ms,
                                     "via_tag": via_tag, "error": error,
                                     "generation": gen, "checked_at": checked_at}
        self._record_history("verify-done", f"{via_tag} exit={exit_ip} ms={ms}")
    def _invalidate_verify(self, reason: str) -> None:
        with self._lock:
            self._verify_generation += 1
            self.status["verify"] = {"state": "idle", "exit_ip": None, "ms": None, "via_tag": None, "error": None, "checked_at": None, "generation": self._verify_generation}
        self._record_history("verify-invalidated", reason)
    # --- rotating residential SOCKS5 exit ---------------------------------
    def _resi_accept_loop(self) -> None:
        """Listen on the third-path port and hand each connection a node.

        The port belongs to the manager (not sing-box) precisely so the pick
        can happen per connection: sing-box inbounds route by inbound tag, so
        "one inbound per node" plus this balancer is what makes the rotation
        observable from a single client entrypoint.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("0.0.0.0", self.resi_port))
            listener.listen(128)
            listener.settimeout(1.0)
        except OSError as exc:
            self._log(f"resi balancer bind failed on :{self.resi_port}: {exc}", flush=True)
            self._set_resi(state="down", error=f"bind failed: {exc}")
            try:
                listener.close()
            except OSError:
                pass
            return
        self._resi_listener = listener
        while not self._stop_event.is_set():
            try:
                client, _ = listener.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle_resi_client, args=(client,),
                             daemon=True).start()
    @property
    def _resi_ports(self) -> list[int]:
        """Ports of the published rotate inbounds (config order)."""
        with self._lock:
            return [port for _, port in self._resi_routes]

    def _set_resi_routes(self, routes: list[tuple[str, int]]) -> None:
        """Publish the node -> loopback port table (config order = tag order)."""
        routes = [(str(tag), int(port)) for tag, port in routes]
        with self._lock:
            changed = routes != self._resi_routes
            self._resi_routes = routes
            live = {tag for tag, _ in routes}
            for tag in [t for t in self._resi_health if t not in live]:
                del self._resi_health[tag]
            for tag in [t for t in self._resi_payload_at if t not in live]:
                del self._resi_payload_at[tag]
            for tag in [t for t in self._resi_ok_at if t not in live]:
                del self._resi_ok_at[tag]
            for tag in [t for t in self._chain_dead_until if t not in live]:
                del self._chain_dead_until[tag]
            if changed:
                self._resi_cursor = 0
            resi_status = self.status.get("resi")
            if isinstance(resi_status, dict) and resi_status.get("enabled"):
                usable, parked, _ = self._resi_pool_locked()
                resi_status["inbounds"] = len(routes)
                resi_status["nodes"] = usable
                resi_status["pool"] = usable
                resi_status["down"] = parked
                if changed:
                    resi_status["cursor"] = 0

    def _set_resi_ports(self, ports: list[int]) -> None:
        """Compat shim: publish ports without node tags (legacy callers/tests)."""
        self._set_resi_routes([(f"port-{int(p)}", int(p)) for p in ports])

    def _resi_health_ok_locked(self, tag: str, now: float) -> bool:
        entry = self._resi_health.get(tag)
        return entry is None or entry.get("down_until", 0.0) <= now

    def _resi_pool_locked(self) -> tuple[int, int, list[tuple[str, int]]]:
        """(usable, parked, routes) for the third path.

        Only nodes that passed a real dial (`real_latency_ms`) are eligible -
        never the whole snapshot. Nodes that keep kicking clients out without
        carrying payload are parked until their down window expires.

        The chain path's own node (``preferred_tag`` / ``backup_tag``) is
        excluded: VPNGate hands out one OpenVPN session per node, and a rotate
        endpoint keeps a dial-probe session open on every node it serves, so
        rotating onto the chain's node gets one of the two kicked
        ("authentication failed: terminal" in the sing-box log) - the chain
        path then looks dead while `/ws-resi` works, i.e. one dead, two dead.
        Rotating never needs the chain's node, so it stays out of the pool.
        """
        routes = self._resi_routes
        if not routes:
            return 0, 0, []
        verified_by_tag: dict[str, bool] = {}
        for node in self._nodes:
            tag = (node.get("endpoint") or {}).get("tag")
            if tag:
                verified_by_tag[tag] = node.get("real_latency_ms") is not None
        reserved = {tag for tag in (self.preferred_tag, self.backup_tag) if tag}
        now = time.monotonic()
        eligible: list[tuple[str, int]] = []
        parked: list[tuple[str, int]] = []
        for tag, port in routes:
            # A tag with no node behind it (legacy port table) is trusted.
            if verified_by_tag.get(tag) is False:
                continue
            if tag in reserved:
                continue
            if self._resi_health_ok_locked(tag, now):
                eligible.append((tag, port))
            else:
                parked.append((tag, port))
        resi_status = self.status.get("resi")
        if isinstance(resi_status, dict):
            resi_status["reserved"] = sum(1 for tag, _ in routes if tag in reserved)
            # How many pool members are demonstrably alive - the SAME
            # evidence the chain's rescue ranks candidates by ("carried
            # rotation payload" or "answered recently"). A latency number
            # is not evidence: a node can be fast on paper and dead in
            # reality, which is how the chain used to walk dead candidates
            # for six minutes.
            now = time.monotonic()
            live = 0
            for tag, _port in eligible:
                payload = self._resi_payload_at.get(tag, 0.0)
                answered = self._resi_ok_at.get(tag, 0.0)
                if ((payload and now - payload <= RESI_LIVE_WINDOW)
                        or (answered and now - answered <= RESI_LIVE_WINDOW)):
                    live += 1
            resi_status["pool_live"] = live
        if eligible:
            return len(eligible), len(parked), eligible
        if parked:
            # Everything is parked: hand out the node that failed longest ago.
            # A fast failure beats a dead third path, and it may have recovered.
            parked.sort(key=lambda item: (self._resi_health.get(item[0], {}).get("down_until", 0.0), item[0]))
            return 0, len(parked), parked[:1]
        return 0, 0, []

    def _resi_pool(self) -> list[tuple[str, int]]:
        with self._lock:
            return self._resi_pool_locked()[2]

    def _resi_next_route(self) -> tuple[str, int] | None:
        """Round-robin over the *usable* nodes; None when the pool is empty."""
        with self._lock:
            usable, parked, pool = self._resi_pool_locked()
            resi_status = self.status.get("resi")
            if isinstance(resi_status, dict) and resi_status.get("enabled"):
                resi_status["pool"] = usable
                resi_status["down"] = parked
            if not pool:
                return None
            route = pool[self._resi_cursor % len(pool)]
            self._resi_cursor = (self._resi_cursor + 1) % len(pool)
            if isinstance(resi_status, dict) and resi_status.get("enabled"):
                resi_status["cursor"] = self._resi_cursor
            return route

    def _resi_next_port(self) -> int | None:
        """Compat: the loopback port the next connection would use."""
        route = self._resi_next_route()
        return None if route is None else route[1]

    def _resi_mark_ok(self, tag: str) -> None:
        with self._lock:
            entry = self._resi_health.get(tag)
            if entry:
                self._resi_health.pop(tag, None)

    def _resi_proven(self, tag: str) -> None:
        """Real payload came through: this node's tunnel works right now.

        Recorded as evidence for the chain rescue: after hours in the pool the
        `real_latency_ms` of every serving node is stale, so "the rotation is
        carrying traffic through this node" is the only fresh proof that a pin
        candidate is alive.
        """
        with self._lock:
            now = time.monotonic()
            self._resi_payload_at[tag] = now
            self._resi_health.pop(tag, None)
            self._chain_dead_until.pop(tag, None)

    def _resi_mark_fail(self, tag: str) -> None:
        """One failure: park the node once the strike limit is reached."""
        with self._lock:
            now = time.monotonic()
            entry = self._resi_health.setdefault(tag, {"strikes": 0, "downs": 0, "down_until": 0.0})
            if entry.get("down_until", 0.0) > now:
                return
            entry["strikes"] = int(entry.get("strikes", 0)) + 1
            if entry["strikes"] < RESI_NODE_STRIKES_DOWN:
                return
            entry["strikes"] = 0
            entry["downs"] = int(entry.get("downs", 0)) + 1
            delay = min(RESI_NODE_DOWN_BASE * (2 ** (entry["downs"] - 1)), RESI_NODE_DOWN_MAX)
            entry["down_until"] = now + delay
            usable = self._resi_pool_locked()[0]
            self._set_resi(error=f"{tag} parked for {int(delay)}s after {RESI_NODE_STRIKES_DOWN} fast failures")
            if usable == 0:
                self._set_resi(state="down", error="every rotation node is parked, retrying the least recent one")
            self._record_history("resi-node-parked", f"{tag} down for {int(delay)}s")

    def _resi_note_connection(self, tag: str, up_bytes: int, down_bytes: int,
                              elapsed: float, backend_closed_first: bool,
                              down_idle: bool = False,
                              first_byte_stalled: bool = False) -> None:
        """Passive health check on real traffic.

        A healthy node either carried payload or kept the connection open; a
        dead one drops us quickly after only the local WS/VLESS handshake.
        Client-initiated closes never count (that would punish idle clients),
        and a connection that lived past RESI_FAIL_MAX_SECONDS counts as
        healthy: that is an idle-NAT close, not a dead node. Two exceptions are
        still dead nodes: a *node side* that stayed silent for the whole idle
        window (``down_idle``), and a node that swallowed the client's bytes
        without returning a single one for RESI_FIRST_BYTE_TIMEOUT
        (``first_byte_stalled`` - sing-box holding the connection while its
        endpoint dial-probes a dead IP).
        """
        payload = down_bytes >= RESI_PAYLOAD_BYTES
        if down_bytes > 0:
            with self._lock:
                self._resi_ok_at[tag] = time.monotonic()
        if payload:
            self._resi_proven(tag)
            self._set_resi(state="up", error=None)
            return
        if up_bytes <= 0:
            self._resi_mark_ok(tag)
            return
        if first_byte_stalled:
            self._resi_mark_fail(tag)
            return
        if down_idle or (backend_closed_first and elapsed < RESI_FAIL_MAX_SECONDS):
            self._resi_mark_fail(tag)
            return
        self._resi_mark_ok(tag)

    def _handle_resi_client(self, client: socket.socket, prefix: bytes = b"",
                            hold_slot: bool = True) -> None:
        held = False
        tag = None
        stats: dict | None = None
        try:
            if hold_slot:
                if not self._mux_slots.acquire(blocking=False):
                    return
                held = True
            route = self._resi_next_route()
            if route is None:
                self._set_resi(state="down",
                               error="rotation pool empty (waiting for a verified node)")
                return
            tag, port = route
            backend = None
            # Design §4.1: a failed backend dial steps to the next node instead
            # of failing the client outright. Loopback dials are instant, so
            # three tries cost nothing while dead nodes are being parked.
            for attempt in range(3):
                try:
                    backend = socket.create_connection(("127.0.0.1", port), timeout=10)
                    break
                except OSError:
                    # A refused *loopback* dial is not the node's fault: the
                    # rotate inbound only disappears while sing-box is being
                    # restarted, and striking nodes for that would park healthy
                    # ones during a pin change. Just step to the next route.
                    if attempt == 0:
                        self._record_history("resi-inbound-missing",
                                             f"loopback :{port} refused, stepping over {tag}")
                    route = self._resi_next_route() if attempt < 2 else None
                    if route is None:
                        break
                    tag, port = route
            if backend is None:
                self._set_resi(error=f"rotate inbound :{port} unavailable")
                return
            client.settimeout(PIPE_IDLE_TIMEOUT)
            backend.settimeout(PIPE_IDLE_TIMEOUT)
            with self._lock:
                self._mux_inflight += 1
                self.status["traffic"]["connections"] += 1
            try:
                if prefix:
                    # Bytes already consumed by the mux (the VLESS+WS handshake):
                    # replay them to the loopback inbound so nothing is lost.
                    backend.sendall(prefix)
                started = time.monotonic()
                stats = _pump_pair(client, backend, started)
                with self._lock:
                    self.status["traffic"]["bytes_up"] += stats["up"] + len(prefix)
                    self.status["traffic"]["bytes_down"] += stats["down"]
            finally:
                # The close lives in the same try as the replay: a looping
                # rotation hits this path on every bad node, so a socket left
                # open here is a file-descriptor leak that eventually takes the
                # whole manager down.
                try:
                    backend.close()
                except OSError:
                    pass
                with self._lock:
                    self._mux_inflight -= 1
        except OSError:
            pass
        finally:
            if tag is not None and stats is not None:
                # Only a node-initiated close after a short, payload-less
                # connection (or a node side that never delivered for the whole
                # idle window) is a strike; see _resi_note_connection.
                self._resi_note_connection(
                    tag, stats["up"] + len(prefix), stats["down"],
                    stats["elapsed"], not stats["upstream_first"],
                    down_idle=bool(stats.get("timed_out", [False, False])[1]),
                    first_byte_stalled=bool(stats.get("first_byte_stalled")))
            if held:
                try:
                    self._mux_slots.release()
                except Exception:
                    pass
            try:
                client.close()
            except OSError:
                pass
    def _resi_mode(self) -> str:
        if self.resi_rotate:
            return "rotate"
        return "sticky" if int(self.resi_session_ttl or 0) > 0 else "rotation"
    def _resi_session(self) -> str:
        """Sticky session id, stable for the process lifetime.

        The gateway binds an exit to (username, session-id). Rotating the id
        means rewriting the serving config and therefore restarting sing-box,
        so it is an explicit action (POST /api/resi_session). A timer would
        silently drop every VLESS connection mid-transfer every ttl seconds.
        """
        with self._resi_lock:
            if not self._resi_session_id:
                self._resi_session_id = secrets.token_hex(4)
                self._resi_session_started = time.monotonic()
            return self._resi_session_id
    def _resi_outbound(self) -> dict | None:
        """Rendered socks outbound, or None when disabled or template broken."""
        if not self.resi:
            return None
        ttl = int(self.resi_session_ttl or 0)
        sid = self._resi_session() if ttl > 0 else ""
        try:
            username = render_resi_username(self.resi["username"], self.resi.get("template"), ttl, sid)
        except ValueError as exc:
            _safe_print(f"resi template error: {exc}", flush=True)
            return None
        return {"server": self.resi["server"], "server_port": self.resi["server_port"],
                "username": username, "password": self.resi["password"]}
    def _set_resi(self, **fields) -> None:
        with self._lock:
            resi_status = self.status.get("resi")
            if isinstance(resi_status, dict) and resi_status.get("enabled"):
                resi_status.update(fields)
                if self.resi_session_ttl > 0 and self._resi_session_started:
                    resi_status["session_age"] = int(time.monotonic() - self._resi_session_started)
    def _resi_probe_loop(self) -> None:
        interval = int((self.resi or {}).get("probe_interval", 300) or 300)
        while not self._stop_event.wait(interval):
            self._start_resi_probe(1)
    def _start_resi_probe(self, count: int = 3, rotate_session: bool = False) -> bool:
        """Single-flight third-path probe; False when disabled or running."""
        if not self.resi and not self.resi_rotate:
            return False
        with self._lock:
            current = self.status["resi"].get("last_probe") or {}
            if current.get("state") == "running":
                return False
            if rotate_session:
                with self._resi_lock:
                    self._resi_session_id = ""
            self.status["resi"]["last_probe"] = {"state": "running", "ips": [], "distinct": 0,
                                                "rotating": None, "checked_at": None}
        threading.Thread(target=self._run_resi_probe, args=(max(1, min(5, int(count))),),
                         daemon=True, name="resi-probe").start()
        return True
    def _run_resi_probe(self, count: int) -> None:
        result = None
        error = None
        if self.resi_rotate:
            # In rotate mode the mux serves /ws-resi in-process on $PORT (one
            # Cloudflare catch-all rule is enough); nothing listens on
            # RESI_PORT, so probing 127.0.0.1:RESI_PORT always failed and the
            # UI/status showed "no serving endpoint answered" even while real
            # third-path clients were rotating fine.
            try:
                result = measure_resi_rotate(self.vless_uuid, self.port, self.resi_path,
                                             count=count, singbox_bin=self.singbox_bin,
                                             timeout=self.dial_timeout)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            if result is None:
                error = error or "no serving endpoint answered"
        else:
            outbound = self._resi_outbound()
            if outbound is None:
                error = "no residential outbound"
            else:
                try:
                    result = measure_resi_rotation(outbound, count=count, singbox_bin=self.singbox_bin,
                                                   timeout=self.dial_timeout)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
        now = _now_iso()
        if result is None:
            reason = error or "no exit ip"
            self._set_resi(state="down", error=reason, checked_at=now,
                           last_probe={"state": "done", "ips": [], "distinct": 0,
                                       "rotating": False, "checked_at": now, "error": reason})
            self._record_history("resi-probe", f"failed: {reason}")
            return
        ips = result["ips"]
        distinct = result["distinct"]
        rotating = (distinct == 1) if self._resi_mode() == "sticky" else (distinct >= 2)
        self._set_resi(state="up", exit_ip=ips[-1], ms=result["first_ms"], checked_at=now, error=None,
                       last_probe={"state": "done", "ips": ips, "distinct": distinct,
                                   "rotating": rotating, "checked_at": now})
        self._record_history("resi-probe", f"{len(ips)}x ips={','.join(ips)} distinct={distinct}")
    def _run_resi_verify(self) -> None:
        """Verify target for POST /api/verify?path=resi: one exit IP."""
        exit_ip, ms = (None, None)
        error = None
        if self.resi_rotate:
            try:
                sampled = measure_resi_rotate(self.vless_uuid, self.port, self.resi_path,
                                              count=1, singbox_bin=self.singbox_bin,
                                              timeout=self.dial_timeout)
            except Exception as exc:
                sampled, error = None, f"{type(exc).__name__}: {exc}"
            if sampled:
                exit_ip, ms = sampled["ips"][0], sampled["first_ms"]
            elif error is None:
                error = "no serving endpoint answered"
        else:
            outbound = self._resi_outbound()
            if outbound is None:
                error = "no residential outbound"
            else:
                try:
                    exit_ip, ms = measure_resi_exit_ip(outbound, self.singbox_bin, self.dial_timeout)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                if not exit_ip and error is None:
                    error = "no exit ip measured"
        now = _now_iso()
        self._set_resi(state=("up" if exit_ip else "down"), exit_ip=exit_ip, ms=ms,
                       checked_at=now, error=error)
        self._record_history("resi-verify", f"exit={exit_ip} ms={ms}")
    def _apply_config_bg(self) -> None:
        """Re-apply the serving config off-thread (used for ttl/session changes)."""
        def _run() -> None:
            with self._config_lock:
                try:
                    self._apply_config(final="auto", preferred=self.preferred_tag, backup=self.backup_tag)
                except Exception as exc:
                    self._log(f"config apply failed: {type(exc).__name__}: {exc}", flush=True)
        threading.Thread(target=_run, daemon=True, name="apply-config").start()
    def _fetch_with_retry(self, fetch) -> str:
        last_exc: Exception | None = None
        delays = [0] + list(self.retry_delays)
        for wait in delays:
            if wait:
                time.sleep(wait)
            for url in self.snapshot_urls:
                try:
                    return fetch(url, 20)
                except Exception as exc:
                    last_exc = exc
        assert last_exc is not None
        raise last_exc
    def _check_config(self, path: str) -> bool:
        try:
            result = subprocess.run([self.singbox_bin, "check", "-c", path], capture_output=True, timeout=30)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False
    @staticmethod
    def _rotate_stderr_file(stderr_path: str, keep_bytes: int = 200 * 1024) -> None:
        try:
            if os.path.exists(stderr_path) and os.path.getsize(stderr_path) > keep_bytes:
                os.replace(stderr_path, f"{stderr_path}.prev")
        except OSError:
            pass
    def _restart_singbox(self) -> None:
        with self._lock:
            old_proc, self._singbox_proc = self._singbox_proc, None
            old_handle, self._stderr_handle = self._stderr_handle, None
            stderr_path = f"{self.config_path}.stderr.log"
            config_path = self.config_path; singbox_bin = self.singbox_bin
            self._rotate_stderr_file(stderr_path)
            try:
                new_handle = open(stderr_path, "ab")
            except OSError:
                new_handle = None
            try:
                new_proc = subprocess.Popen([singbox_bin, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=new_handle or subprocess.DEVNULL)
            except OSError as exc:
                _safe_print(f"sing-box start failed: {exc}", flush=True)
                new_proc = None
                if new_handle is not None:
                    try:
                        new_handle.close()
                    except OSError:
                        pass
                    new_handle = None
            self._singbox_proc = new_proc; self._stderr_handle = new_handle
        _reap_process(old_proc, old_handle)
        if self.clash_api_port and self.resi_rotate:
            # The fresh process starts on the config's default pin; a pin that
            # only ever existed as a hot switch has to be put back.
            threading.Thread(target=self._reapply_pin_when_ready, daemon=True, name="clash-pin").start()
    def _terminate_singbox(self) -> None:
        with self._lock:
            proc, self._singbox_proc = self._singbox_proc, None
            handle, self._stderr_handle = self._stderr_handle, None
        _reap_process(proc, handle)
    def _start_cloudflared(self) -> bool:
        with self._lock:
            if not self.tunnel_token:
                self.status["tunnel"] = {"state": "no-token"}
                _safe_print("cloudflared skipped: TUNNEL_TOKEN not set", flush=True)
                return False
            binary = shutil.which(self.cloudflared_bin)
            if binary is None:
                self.status["tunnel"] = {"state": "no-binary", "binary": self.cloudflared_bin}
                _safe_print(f"cloudflared skipped: binary {self.cloudflared_bin!r} not found", flush=True)
                return False
            try:
                new_proc = subprocess.Popen([binary, "tunnel", "--no-autoupdate", "run", "--token", self.tunnel_token], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as exc:
                self.status["tunnel"] = {"state": "dead", "error": str(exc)}
                return False
            old_proc, self._cloudflared_proc = self._cloudflared_proc, new_proc
            self.status["tunnel"] = {"state": "running", "since": _now_iso()}
            _safe_print("cloudflared tunnel started", flush=True)
        _reap_process(old_proc)
        return True
    def _terminate_cloudflared(self) -> None:
        with self._lock:
            proc, self._cloudflared_proc = self._cloudflared_proc, None
            self.status["tunnel"] = {"state": "off"}
        _reap_process(proc)
    def tail_singbox_stderr(self, max_lines: int = 20) -> str:
        try:
            with open(f"{self.config_path}.stderr.log", "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 16384))
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
            return "\n".join(lines[-max_lines:])
        except OSError:
            return ""
def main() -> int:
    try:
        cfg = build_config_from_env(dict(os.environ))
    except SystemExit as exc:
        return int(exc.code or 1)
    if cfg["admin_token_generated"]:
        _safe_print(f"generated ADMIN_TOKEN={cfg['admin_token']} (save it to use /ui and /api)", flush=True)
    data_dir = cfg["data_dir"]
    os.makedirs(data_dir, exist_ok=True)
    manager = RailwayManager(port=cfg["port"], mixed_port=cfg["mixed_port"], username=cfg["username"], password=cfg["password"],
        admin_token=cfg["admin_token"], snapshot_url=cfg["snapshot_url"], snapshot_urls=cfg["snapshot_urls"],
        refresh_seconds=cfg["refresh_seconds"], limit=cfg["limit"], real_topk=cfg["real_topk"], dial_workers=cfg["dial_workers"],
        full_probe_workers=cfg["full_probe_workers"], probe_workers=cfg["probe_workers"], dial_timeout=cfg["dial_timeout"],
        auto_rescue=cfg["auto_rescue"], health_check_interval=cfg["health_check_interval"], max_mux_connections=cfg["max_mux_connections"],
        vless_uuid=cfg["vless_uuid"], vless_direct_port=cfg["vless_direct_port"], vless_chain_port=cfg["vless_chain_port"],
        resi=cfg["resi"], resi_port=cfg["resi_port"], resi_path=cfg["resi_path"],
        resi_rotate=cfg["resi_rotate"],
        resi_session_ttl=(cfg["resi"]["session_ttl"] if cfg["resi"] else 0),
        tunnel_token=cfg["tunnel_token"], cloudflared_bin=cfg["cloudflared_bin"], disguise_path=cfg["disguise_path"],
        config_path=os.path.join(data_dir, "singbox-railway.json"), nodes_path=os.path.join(data_dir, "nodes.json"),
        state_path=os.path.join(data_dir, "state.json"), settings_path=os.path.join(data_dir, "settings.json"),
        clash_api_port=cfg["clash_api_port"], edge_metrics_url=cfg["edge_metrics_url"],
        bind_host=cfg["bind_host"])
    stop_event = threading.Event()
    def _on_signal(signum, frame) -> None:
        stop_event.set()
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    manager.start()
    stop_event.wait()
    manager.stop()
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
