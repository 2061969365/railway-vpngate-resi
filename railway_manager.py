"""Simple Railway VPNGate manager: single-$PORT mux + sing-box supervisor (stdlib only)."""
from __future__ import annotations
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
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from vpngate_to_singbox import (
    DEFAULT_RESI_PATH,
    DEFAULT_RESI_PORT,
    RESI_ROTATE_BASE,
    build_singbox_config,
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
DEFAULT_SNAPSHOT_URL = "https://www.vpngate.net/api/iphone/"
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
MIN_PROXY_PASS_LEN = 16
MIN_ADMIN_TOKEN_LEN = 16
PIPE_IDLE_TIMEOUT = 120
MAX_MUX_CONNECTIONS = 100
MAX_POST_CONNECTIONS = 16
DRAIN_TIMEOUT = 10.0
STALE_RUNNING_AFTER = 180.0
HEALTH_CHECK_INTERVAL = 20
PINNED_FAIL_THRESHOLD = 3
SUPERVISE_INTERVAL = 10
EXIT_VERIFY_CAP = 3
REFRESH_PROBE_GRACE = 30.0
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
        print(f"refusing to start: {name} must be an integer, got {raw!r}", flush=True)
        raise SystemExit(2)
    if min_val is not None and val < min_val:
        print(f"refusing to start: {name}={val} below minimum {min_val}", flush=True)
        raise SystemExit(2)
    if max_val is not None and val > max_val:
        print(f"refusing to start: {name}={val} above maximum {max_val}", flush=True)
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
        print(f"refusing to start: RESI_GATEWAY must be host:port, got {gateway!r}", flush=True)
        raise SystemExit(2)
    user = (env.get("RESI_USER") or "").strip()
    password = env.get("RESI_PASS") or ""
    if not user or not password:
        print("refusing to start: RESI_GATEWAY needs RESI_USER and RESI_PASS", flush=True)
        raise SystemExit(2)
    ttl = _int_env(env, "RESI_SESSION_TTL", 0, 0, 86400)
    template = env.get("RESI_USER_TEMPLATE", "{user}")
    if ttl > 0 and "{session}" not in template:
        print("warning: RESI_SESSION_TTL>0 but RESI_USER_TEMPLATE has no {session}; staying in rotation mode", flush=True)
    try:
        render_resi_username(user, template, ttl, "probe")
    except ValueError as exc:
        print(f"refusing to start: {exc}", flush=True)
        raise SystemExit(2)
    return {"server": host, "server_port": gateway_port, "username": user,
            "password": password, "template": template, "session_ttl": ttl,
            "probe_interval": _int_env(env, "RESI_PROBE_INTERVAL", 300, 60, 86400)}
CRASH_BACKOFFS = (5, 10, 20, 40, 300)

UI_HTML = """\
<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>vpngate console</title>
<script>try{document.documentElement.dataset.theme=localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark")}catch(e){document.documentElement.dataset.theme="dark"}</script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(ellipse 55% 40% at 75% 8%,rgba(99,102,241,.28),transparent 70%),radial-gradient(ellipse 45% 35% at 12% 25%,rgba(34,211,238,.16),transparent 70%),radial-gradient(ellipse 50% 45% at 50% 100%,rgba(16,185,129,.14),transparent 70%),#000}
#topnav{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:26px;padding:14px 32px;font-size:14px;background:rgba(10,12,24,.88);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid rgba(255,255,255,.09)}
#topnav .logo{font-weight:800;font-size:16px;background:linear-gradient(90deg,#a5b4fc,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
#topnav .live{font-size:11px;color:#6ee7b7;border:1px solid rgba(110,231,183,.4);border-radius:999px;padding:2px 10px}
#topnav .links{display:flex;gap:22px;color:#ccc}
#topnav .right{margin-left:auto;display:flex;gap:14px;align-items:center}
#topnav .cta{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:7px 18px;cursor:pointer;background:rgba(255,255,255,.06)}
#topnav .cta:hover{background:rgba(255,255,255,.14)}
.wrap{max-width:1180px;margin:0 auto;padding:34px 28px 60px}
.glass-card{background:rgba(255,255,255,.055);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.11);border-radius:22px;padding:28px 30px;margin-bottom:22px;box-shadow:0 18px 50px rgba(0,0,0,.45)}
.glass-card h2{font-size:19px;font-weight:700;margin-bottom:6px}
.glass-card .desc{color:#a8adbd;font-size:13px;line-height:1.7;margin-bottom:16px}
#exit-card{background:linear-gradient(135deg,rgba(99,102,241,.2),rgba(34,211,238,.1)),rgba(255,255,255,.055)}
#hero-kicker{font-size:52px;font-weight:800;letter-spacing:-.03em;line-height:1.08;background:linear-gradient(92deg,#fff,#a5b4fc 60%,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
#hero-sub{color:#c2c7d6;font-size:14px;margin-top:10px}
#verify-result{margin-top:12px;font-size:14px;color:#6ee7b7;min-height:22px}
.verify-ok{color:#6ee7b7}.verify-err{color:#fca5a5}
.linklike{color:#8ab4ff;cursor:pointer;text-decoration:none}
.linklike:hover{text-decoration:underline}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.stat{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:16px 18px;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.stat .k{font-size:12px;color:#8b91a5}
.stat .v{font-size:24px;font-weight:700;margin-top:4px}
.btn{border-radius:999px;padding:10px 24px;font-size:14px;cursor:pointer;border:1px solid rgba(255,255,255,.2);color:#fff;background:rgba(255,255,255,.07);transition:transform .12s ease,background .15s ease}
.btn:hover{background:rgba(255,255,255,.15)}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.55;cursor:wait;transform:none}
.btn.primary{background:linear-gradient(92deg,#4338CA,#0369A3);border:none;font-weight:600;box-shadow:0 6px 24px rgba(99,102,241,.45)}
.btn.busy{animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
#pills{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
#scope{margin:14px 0;min-width:180px}
.opbtn{min-height:28px;padding:5px 16px;border-radius:999px;border:1px solid rgba(138,180,255,.5);background:rgba(138,180,255,.08);color:#8ab4ff;font-size:12.5px;cursor:pointer;margin-right:8px;white-space:nowrap}
.opbtn:hover{background:rgba(138,180,255,.18)}
.opbtn:disabled{opacity:.45;cursor:not-allowed}
.opbtn[aria-disabled="true"]{opacity:.45;cursor:not-allowed}
#node-search::placeholder{color:#9aa0b2}
.ip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
#thinbar{display:none;height:2px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;margin:10px 0 2px}
#thinbar.show{display:block}
#thinbar i{display:block;height:100%;width:30%;border-radius:999px;background:linear-gradient(90deg,#6366f1,#22d3ee);animation:slide 1s ease-in-out infinite}
@keyframes slide{0%{margin-left:-30%}100%{margin-left:100%}}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:rot .7s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes rot{to{transform:rotate(360deg)}}
table.bench.loading tbody{opacity:.55}
#switch-undo{margin-top:8px;font-size:13px;color:#a8adbd}
#switch-undo b{font-family:ui-monospace,Menlo,Consolas,monospace;color:#e5e7eb}
#undo-link{color:#8ab4ff;cursor:pointer;text-decoration:none}
#undo-link:hover{text-decoration:underline}
.actions{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
#btn-verify{background:linear-gradient(92deg,#4338CA,#0369A3);color:#fff;border-radius:999px;padding:10px 26px;font-size:14px;font-weight:600;cursor:pointer;border:none;box-shadow:0 6px 24px rgba(99,102,241,.45)}
#btn-refresh{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:10px 26px;font-size:14px;color:#fff;background:rgba(255,255,255,.07);cursor:pointer}
#btn-fullprobe{border:1px solid rgba(138,180,255,.55);border-radius:999px;padding:10px 26px;font-size:14px;color:#8ab4ff;background:rgba(138,180,255,.08);cursor:pointer}
#btn-verify:disabled,#btn-refresh:disabled,#btn-fullprobe:disabled{opacity:.55;cursor:wait}
#node-search{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#fff;border-radius:10px;padding:8px 14px;font-size:13px;width:230px}
table.bench{width:100%;border-collapse:collapse;font-size:14px}
table.bench th,table.bench td{text-align:left;padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.08)}
table.bench th{color:#8b91a5;font-weight:500;font-size:12px}
table.bench tr:hover td{background:rgba(255,255,255,.035)}
table.bench td.hl{color:#fff;font-weight:600}
.badge{display:inline-block;font-size:11px;border-radius:999px;padding:2px 10px;margin-left:8px;background:linear-gradient(92deg,#4338CA,#0369A3);color:#fff}
.badge.probing{background:rgba(251,191,36,.18);color:#fbbf24;border:1px solid rgba(251,191,36,.4)}
#probe-progress{display:none;margin:14px 0 4px}
#probe-progress.show{display:block}
#probe-progress .bar{height:8px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
#probe-progress .fill{height:100%;width:0;border-radius:999px;background:linear-gradient(90deg,#6366f1,#22d3ee);transition:width .4s ease}
#probe-progress .txt{font-size:12px;color:#8b91a5;margin-top:6px}
#history-line{color:#8b91a5;font-size:13px;margin-top:14px}
#history-list{list-style:none;margin-top:10px;max-height:220px;overflow:auto}
#history-list li{font-size:12.5px;color:#a8adbd;padding:7px 4px;border-bottom:1px dashed rgba(255,255,255,.08)}
#history-list li b{color:#e5e7eb;font-weight:600}
#toast{position:fixed;right:22px;bottom:22px;z-index:100;display:flex;flex-direction:column;gap:10px}
.toast-msg{background:rgba(16,20,36,.92);border:1px solid rgba(110,231,183,.45);color:#d1fae5;border-radius:14px;padding:12px 18px;font-size:13px;max-width:360px;box-shadow:0 10px 30px rgba(0,0,0,.5);animation:slidein .25s ease}
.toast-msg.err{border-color:rgba(248,113,113,.55);color:#fecaca}
@keyframes slidein{from{transform:translateY(12px);opacity:0}to{transform:none;opacity:1}}
.footer{color:#9AA0B2;font-size:12.5px;text-align:center;padding:10px 0 30px}
#login-gate{position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse 55% 40% at 75% 8%,rgba(99,102,241,.28),transparent 70%),radial-gradient(ellipse 45% 35% at 12% 25%,rgba(34,211,238,.16),transparent 70%),rgba(0,0,0,.72);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
#login-gate.hidden{display:none}
.login-card{width:380px;max-width:92vw;text-align:center;padding:40px 36px}
.login-card .logo{font-weight:800;font-size:22px;background:linear-gradient(90deg,#a5b4fc,#67e8f9);-webkit-background-clip:text;background-clip:text;color:transparent}
.login-card .sub{color:#8b91a5;font-size:13px;margin:10px 0 22px}
#login-token{width:100%;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);color:#fff;border-radius:12px;padding:12px 16px;font-size:14px;margin-bottom:14px;text-align:center}
#btn-login{width:100%;background:linear-gradient(92deg,#4338CA,#0369A3);color:#fff;border-radius:12px;padding:12px;font-size:15px;font-weight:600;cursor:pointer;border:none;box-shadow:0 6px 24px rgba(99,102,241,.45)}
#btn-login:disabled{opacity:.55;cursor:wait}
#login-err{color:#fca5a5;font-size:13px;min-height:20px;margin-top:12px}
.shake{animation:shake .4s ease}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-8px)}75%{transform:translateX(8px)}}
#console.hidden{display:none}
#btn-lock{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:7px 18px;cursor:pointer;background:rgba(255,255,255,.06);font-size:13px;color:#ddd}
#btn-lock:hover{background:rgba(255,255,255,.14)}
@media(max-width:768px){#hero-kicker{font-size:34px}.wrap{padding:20px 14px 44px}.stats{grid-template-columns:repeat(2,1fr)}#topnav{gap:14px}#topnav .links{display:flex;gap:8px;overflow-x:auto;flex:none;max-width:46vw}#topnav .links a{padding:6px 10px;font-size:12px;white-space:nowrap}}
#bench-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table.bench{min-width:560px}
@media(max-width:640px){.wrap{padding:16px 12px 40px}.glass-card{padding:20px 16px;border-radius:18px}#hero-kicker{font-size:30px}.stats{gap:10px}.stat{padding:12px 14px}.stat .v{font-size:20px}#node-search{width:100%;max-width:none}.actions .btn{flex:1 1 100%;text-align:center}#topnav{padding:12px 16px;gap:14px}#topnav .live{display:none}.glass-card,.stat{backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}#toast{right:max(12px,env(safe-area-inset-right));bottom:max(12px,env(safe-area-inset-bottom));left:max(12px,env(safe-area-inset-left))}.toast-msg{max-width:none}}
@media(max-width:640px){table.bench th:first-child,table.bench td:first-child{position:sticky;left:0;background:#0b0e1c;z-index:2}table.bench th:last-child,table.bench td:last-child{position:sticky;right:0;background:#0b0e1c;z-index:2}}
html[data-theme="light"] table.bench th:first-child,html[data-theme="light"] table.bench td:first-child,html[data-theme="light"] table.bench th:last-child,html[data-theme="light"] table.bench td:last-child{background:#fff}
/* v2 新增元素（与深色皮肤同语言） */
.num,.stat .v{font-variant-numeric:tabular-nums}
#topnav .links a{color:#ccc;text-decoration:none;font-size:13px;padding:6px 12px;border-radius:10px}
#topnav .links a:hover{color:#fff;background:rgba(255,255,255,.07)}
#topnav .links a.on{color:#fff;background:rgba(255,255,255,.1)}
#btn-theme{border:1px solid rgba(255,255,255,.2);border-radius:999px;padding:7px 18px;cursor:pointer;background:rgba(255,255,255,.06);font-size:13px;color:#ddd}
#btn-theme:hover{background:rgba(255,255,255,.14)}
#statusbar{position:sticky;top:57px;z-index:49;display:flex;gap:20px;align-items:center;flex-wrap:wrap;background:rgba(10,12,24,.88);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);padding:9px 32px;border-bottom:1px solid rgba(255,255,255,.09);font-size:12.5px;color:#a8adbd}
#statusbar b{color:#fff;font-weight:600;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
#statusbar .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#6ee7b7;margin-right:6px;box-shadow:0 0 8px #6ee7b7}
#statusbar .dot.stale{background:#fbbf24;box-shadow:0 0 8px #fbbf24}
#statusbar .dot.err{background:#fca5a5;box-shadow:0 0 8px #fca5a5}
#statusbar .sp{flex:1}
section{scroll-margin-top:130px}
.route-strip{display:flex;gap:12px;margin-top:16px;flex-wrap:wrap}
.route-strip .rt{flex:1;min-width:230px;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:10px 16px;font-size:12.5px;color:#c2c7d6}
.route-strip .rt b{display:block;font-size:11.5px;color:#8b91a5;font-weight:600;margin-bottom:2px}
.route-strip .rt code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#7dd3fc}
#spark{width:100%;height:64px;display:block}
.rate-legend{display:flex;gap:18px;font-size:12px;color:#8b91a5;margin-top:8px}
.rate-legend i{display:inline-block;width:18px;height:2px;vertical-align:middle;margin-right:6px}
#sortsel,#scope,#loglevel,#log-search{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#fff;border-radius:10px;padding:8px 10px;font-size:13px}
#sortsel option,#scope option,#loglevel option{background:#121826}
.node-count{margin-left:auto;font-size:12px;color:#8b91a5}
.errchip{display:inline-block;font-size:11px;border-radius:999px;padding:2px 10px;margin-left:8px;background:rgba(251,191,36,.15);color:#fbbf24;border:1px solid rgba(251,191,36,.4);font-weight:400}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.subtag{display:inline-block;font-size:11px;border-radius:8px;padding:2px 10px;margin-right:10px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#ddd;white-space:nowrap;flex:none}
.hostnote{font-size:12px;color:#8b91a5;margin-top:10px}
.logtools{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.logtools .chk{font-size:12.5px;color:#a8adbd;display:flex;gap:6px;align-items:center;cursor:pointer;white-space:nowrap}
.setgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:4px}
.setgrid label{font-size:12.5px;color:#a8adbd;display:flex;flex-direction:column;gap:6px}
.setgrid label.chk{flex-direction:row;align-items:center;gap:8px;cursor:pointer;min-height:28px}
.setgrid input[type="number"]{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);color:#fff;border-radius:10px;padding:8px 12px;font-size:13px;width:100%}
.setgrid input[type="checkbox"]{width:16px;height:16px;accent-color:#0ea5e9}
#settings-result{margin-top:10px;font-size:13px;color:#6ee7b7;min-height:20px}
#log-search{width:180px}
table.bench th.sortable{cursor:pointer;user-select:none}
table.bench th.sortable:hover{color:#fff}
.thsort{background:none;border:none;color:inherit;font:inherit;font-size:inherit;cursor:pointer;padding:6px 8px;margin:-6px -8px;min-height:28px;border-radius:8px;white-space:nowrap}
.thsort:hover{color:#fff}
table.bench tr.pinned td{background:rgba(99,102,241,.12)}
table.bench tr.pending td{opacity:.55}
.cc{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#7dd3fc;border:1px solid rgba(125,211,252,.35);border-radius:6px;padding:1px 7px;margin-right:8px}
.badge.unmeasured{background:rgba(125,211,252,.13);color:#7dd3fc}
.lat{display:flex;align-items:center;gap:9px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.lat .bar{width:66px;height:6px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
.lat .bar i{display:block;height:100%;border-radius:999px}
.l-good{color:#6ee7b7}.l-mid{color:#fbbf24}.l-bad{color:#fca5a5}.l-na{color:#9AA0B2}
tr.skel td{padding:13px 14px}
.skel .sk{height:13px;border-radius:6px;background:linear-gradient(90deg,rgba(255,255,255,.05),rgba(255,255,255,.14),rgba(255,255,255,.05));background-size:200% 100%;animation:sh 1.1s linear infinite}
@keyframes sh{to{background-position:-200% 0}}
.empty{padding:30px;text-align:center;color:#8b91a5;font-size:13px}
#logbox{background:rgba(0,0,0,.45);border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:14px 18px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.8;max-height:300px;overflow:auto}
#logbox .t{color:#69707f}#logbox .ok{color:#6ee7b7}#logbox .warn{color:#fbbf24}#logbox .err{color:#fca5a5}
.subrow{display:flex;gap:12px;align-items:center;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.09);border-radius:14px;padding:11px 16px;margin-bottom:10px}
.subrow code{flex:1;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#8b91a5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.subrow .btn{padding:7px 18px;font-size:12.5px}
:focus-visible{outline:2px solid #67e8f9;outline-offset:2px}
/* 浅色模式：Google 式白——纯白底、无渐变、无毛玻璃，蓝只用 #1a73e8 一处 */
html[data-theme="light"] body{background:#fff;color:#202124}
html[data-theme="light"] body::before{display:none}
html[data-theme="light"] #topnav,html[data-theme="light"] #statusbar{background:#fff;border-bottom-color:#dadce0}
html[data-theme="light"] #topnav .links a,html[data-theme="light"] #statusbar{color:#5f6368}
html[data-theme="light"] #topnav .links a:hover{color:#202124;background:#f1f3f4}
html[data-theme="light"] #topnav .links a.on{color:#1a73e8;background:#e8f0fe}
html[data-theme="light"] #btn-lock,html[data-theme="light"] #btn-theme{border-color:#dadce0;background:#fff;color:#1a73e8}
html[data-theme="light"] #btn-lock:hover,html[data-theme="light"] #btn-theme:hover{background:#f6fafe}
html[data-theme="light"] #topnav .live{color:#188038;border-color:#188038}
html[data-theme="light"] #topnav .logo{background:none;color:#1a73e8}
html[data-theme="light"] .glass-card,html[data-theme="light"] .stat{background:#fff;border-color:#dadce0;box-shadow:0 1px 2px rgba(60,64,67,.15)}
html[data-theme="light"] .glass-card .desc,html[data-theme="light"] .stat .k,html[data-theme="light"] table.bench th,html[data-theme="light"] #history-line,html[data-theme="light"] #history-list li,html[data-theme="light"] #probe-progress .txt,html[data-theme="light"] .rate-legend,html[data-theme="light"] .empty,html[data-theme="light"] .footer,html[data-theme="light"] .node-count{color:#5f6368}
html[data-theme="light"] #history-list li{border-bottom-color:#e8eaed}
html[data-theme="light"] #history-list li b{color:#202124}
html[data-theme="light"] #hero-kicker{background:none;color:#202124}
html[data-theme="light"] #hero-sub{color:#5f6368}
html[data-theme="light"] #verify-result{color:#188038}
html[data-theme="light"] .verify-ok{color:#188038}
html[data-theme="light"] .verify-err{color:#d93025}
html[data-theme="light"] .linklike{color:#1a73e8}
html[data-theme="light"] #switch-undo{color:#5f6368}
html[data-theme="light"] #switch-undo b{color:#202124}
html[data-theme="light"] #undo-link{color:#1a73e8}
html[data-theme="light"] #exit-card{background:#fff}
html[data-theme="light"] .route-strip .rt{background:#f8f9fa;border-color:#e8eaed;color:#3c4043}
html[data-theme="light"] .route-strip .rt b{color:#5f6368}
html[data-theme="light"] .route-strip .rt code{color:#1a73e8}
html[data-theme="light"] .btn{border-color:#dadce0;color:#1a73e8;background:#fff}
html[data-theme="light"] .btn:hover{background:#f6fafe}
html[data-theme="light"] .btn:active{transform:none}
html[data-theme="light"] #btn-verify{background:#1a73e8;box-shadow:none}
html[data-theme="light"] #btn-verify:hover{background:#1b66c9}
html[data-theme="light"] #btn-fullprobe{border-color:#1a73e8;color:#1a73e8;background:#fff}
html[data-theme="light"] #node-search,html[data-theme="light"] #sortsel,html[data-theme="light"] #scope,html[data-theme="light"] #loglevel,html[data-theme="light"] #log-search{background:#fff;border-color:#dadce0;color:#202124}
html[data-theme="light"] #sortsel option,html[data-theme="light"] #scope option,html[data-theme="light"] #loglevel option{background:#fff}
html[data-theme="light"] #thinbar{background:#e8eaed}
html[data-theme="light"] #thinbar i{background:#1a73e8}
html[data-theme="light"] #probe-progress .bar{background:#e8eaed}
html[data-theme="light"] #probe-progress .fill{background:#1a73e8}
html[data-theme="light"] table.bench th,html[data-theme="light"] table.bench td{border-bottom-color:#e8eaed}
html[data-theme="light"] table.bench tr:hover td{background:#f6fafe}
html[data-theme="light"] table.bench tr.pinned td{background:#e8f0fe}
html[data-theme="light"] table.bench td.hl{color:#202124}
html[data-theme="light"] .opbtn{border-color:#dadce0;background:#fff;color:#1a73e8}
html[data-theme="light"] .opbtn:hover{background:#f6fafe}
html[data-theme="light"] .opbtn:disabled{color:#70757A;border-color:#e8eaed;background:#fff}
html[data-theme="light"] .opbtn[aria-disabled="true"]{color:#70757A;border-color:#e8eaed;background:#fff}
html[data-theme="light"] #node-search::placeholder{color:#5f6368}
html[data-theme="light"] .ip{color:#202124}
html[data-theme="light"] table.bench th.sortable:hover{color:#202124}
html[data-theme="light"] .cc{color:#1a73e8;border-color:#c2dbff}
html[data-theme="light"] .badge{background:#e6f4ea;color:#137333}
html[data-theme="light"] .badge.probing{background:#fef7e0;color:#7A4A00;border-color:#fde293}
html[data-theme="light"] .badge.unmeasured{background:#e8f0fe;color:#174EA6}
html[data-theme="light"] .lat .bar{background:#e8eaed}
html[data-theme="light"] .l-good{color:#188038}html[data-theme="light"] .l-mid{color:#B06000}html[data-theme="light"] .l-bad{color:#d93025}html[data-theme="light"] .l-na{color:#70757A}
html[data-theme="light"] #foot-cpu.l-good,html[data-theme="light"] #foot-mem.l-good{color:#188038}
html[data-theme="light"] #foot-cpu.l-mid,html[data-theme="light"] #foot-mem.l-mid{color:#e37400}
html[data-theme="light"] #foot-cpu.l-bad,html[data-theme="light"] #foot-mem.l-bad{color:#d93025}
html[data-theme="light"] .skel .sk{background:linear-gradient(90deg,#e8eaed,#f1f3f4,#e8eaed);background-size:200% 100%}
html[data-theme="light"] .subrow{background:#f8f9fa;border-color:#e8eaed}
html[data-theme="light"] .subrow code{color:#5f6368}
html[data-theme="light"] #statusbar b{color:#202124}
html[data-theme="light"] #statusbar .dot{background:#188038;box-shadow:none}
html[data-theme="light"] #statusbar .dot.stale{background:#B06000;box-shadow:none}
html[data-theme="light"] #statusbar .dot.err{background:#d93025;box-shadow:none}
html[data-theme="light"] .spin{border-color:rgba(26,115,232,.25);border-top-color:#1a73e8}
html[data-theme="light"] #logbox{background:#f8f9fa;border-color:#e8eaed}
html[data-theme="light"] #logbox .t{color:#70757A}
html[data-theme="light"] #logbox .ok{color:#188038}html[data-theme="light"] #logbox .warn{color:#b06000}html[data-theme="light"] #logbox .err{color:#d93025}
html[data-theme="light"] #login-gate{background:rgba(255,255,255,.9)}
html[data-theme="light"] .login-card{background:#fff;border-color:#dadce0;box-shadow:0 1px 3px rgba(60,64,67,.2)}
html[data-theme="light"] .login-card .logo{background:none;color:#1a73e8}
html[data-theme="light"] .login-card .sub{color:#5f6368}
html[data-theme="light"] #login-token{background:#fff;border-color:#dadce0;color:#202124}
html[data-theme="light"] #btn-login{background:#1a73e8;box-shadow:none}
html[data-theme="light"] #login-err{color:#d93025}
html[data-theme="light"] .errchip{background:#fef7e0;color:#7A4A00;border-color:#fde293}
html[data-theme="light"] .subtag{background:#f1f3f4;border-color:#dadce0;color:#5f6368}
html[data-theme="light"] .hostnote,html[data-theme="light"] .logtools .chk{color:#5f6368}
html[data-theme="light"] .setgrid label{color:#5f6368}
html[data-theme="light"] .setgrid input[type="number"]{background:#fff;border-color:#dadce0;color:#202124}
html[data-theme="light"] #settings-result{color:#188038}
html[data-theme="light"] .toast-msg{background:#fff;color:#3c4043;border-color:#dadce0}
html[data-theme="light"] .toast-msg.err{background:#fff;color:#d93025;border-color:#d93025}
html[data-theme="light"] :focus-visible{outline-color:#1a73e8}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

</style></head>
<body>
<div id="topnav"><span class="logo">vpngate</span><span class="live" title="自动刷新每15秒">● <span lang="en">LIVE</span></span><span class="links"><a href="#sec-overview">总览</a><a href="#sec-nodes">节点</a><a href="#sec-logs">日志</a><a href="#sec-sub" id="nav-sub">订阅</a><a href="#sec-hist">事件</a><a href="#sec-settings">设置</a></span><span class="right"><button id="btn-theme" onclick="toggleTheme()">浅色</button><button id="btn-lock" onclick="lockConsole()">锁定</button></span></div>
<div id="statusbar" aria-label="实时状态"><span><span class="dot" id="sb-dot"></span><span class="vh" id="sb-dot-txt">正常</span>出口 <b id="sb-exit">—</b></span><span>节点 <b id="sb-node">—</b></span><span class="sp"></span><span>↓ <b id="rate-dn">—</b> Mb/s</span><span>↑ <b id="rate-up">—</b> Mb/s</span></div>
<div id="login-gate"><div class="login-card glass-card"><div class="logo">vpngate</div><div class="sub">输入 Railway 环境变量 ADMIN_TOKEN（部署页 Variables 中查看）</div><div style="display:flex;gap:8px;margin-bottom:14px"><input id="login-token" type="password" autocomplete="off" aria-label="ADMIN_TOKEN" aria-describedby="login-err" placeholder="ADMIN_TOKEN" style="margin-bottom:0;flex:1" onkeydown="if(event.key==='Enter')loginEnter()"><button id="btn-show-token" class="btn" style="padding:12px 14px;font-size:13px;white-space:nowrap" aria-pressed="false" onclick="toggleToken()">显示</button></div><button id="btn-login" onclick="loginEnter()">进入控制台</button><button id="btn-theme-gate" class="btn" style="width:100%;margin-top:10px;padding:10px;font-size:13px" onclick="toggleTheme()">浅色</button><p id="login-err" role="alert"></p></div></div>
<div class="wrap" id="console" style="display:none">
<section id="sec-overview" aria-label="总览">
<div id="exit-card" class="glass-card">
<div id="hero-kicker">—<br>—</div>
<p id="hero-sub">加载中…</p>
<p id="verify-result" aria-live="polite"></p>
<p id="switch-undo" hidden>已从 <b id="undo-from"></b> 切换到 <b id="undo-to"></b> · <button id="undo-link" class="opbtn" onclick="onUndo()">撤销换回</button></p>
<div class="route-strip" id="route-strip" hidden>
<div class="rt"><b>/ws-node → Railway 本机</b><code id="route-direct">—</code></div>
<div class="rt"><b>/ws-chain → VPN 节点</b><code id="route-chain">—</code></div>
<div class="rt" id="route-resi-wrap" hidden><b>/ws-resi → <span id="route-resi-kind">出口</span></b><code id="route-resi">—</code></div>
</div>
<div class="actions"><button id="btn-verify" onclick="verifyExit()">验证出口 IP</button></div>
</div>
<div class="glass-card" id="resi-card" hidden>
<h2>第三出口（轮换）</h2>
<p class="desc">默认从所有实测有效节点里按连接环形轮换：第 1 条走节点 1、第 2 条走节点 2，用完一圈回到第 1 个。配置了住宅网关时改为连固定 backconnect 网关。</p>
<p id="resi-line">—</p>
<p id="resi-ips" class="ip" aria-live="polite">—</p>
<div class="actions"><button id="btn-resi-probe" class="btn" onclick="resiProbe()">探测出口 IP</button></div>
</div>
<div class="stats">
<div class="stat"><div class="k">可用节点</div><div class="v" id="stat-nodes">—</div></div>
<div class="stat"><div class="k">最优实测</div><div class="v" id="stat-best">—</div></div>
<div class="stat"><div class="k">运行时间</div><div class="v" id="stat-uptime">—</div></div>
<div class="stat"><div class="k">累计流量 ↓/↑</div><div class="v num" style="font-size:17px;padding-top:7px"><span id="stat-down">—</span> / <span id="stat-up">—</span></div></div>
<div class="stat"><div class="k">刷新成功/失败 <span id="stat-err" class="errchip" hidden></span></div><div class="v" id="stat-refresh">—</div></div>
</div>
<div class="glass-card" id="rate-card" hidden>
<h2>实时速率</h2>
<p class="desc">由 traffic 计数器差分绘制，console 可见时每轮更新。</p>
<canvas id="spark" width="1000" height="64" role="img" aria-label="速率曲线"></canvas><p id="spark-alt" class="vh" role="status"></p>
<div class="rate-legend"><span><i style="background:#6ee7b7"></i>下行</span><span><i style="background:#7dd3fc"></i>上行</span></div>
</div>
</section>
<section id="sec-nodes" aria-label="节点">
<div class="glass-card">
<h2>可用节点</h2>
<p class="desc">全部节点握手发现，真拨先测 TopK（REAL_TOPK）让服务先起来，启动/刷新后会自动在后台补齐全量真测；Speed 排名不等于可拨通，首选由 urltest 实测决定，多 endpoint 兜底。点击表头可排序，未测通节点不可切换。</p>
<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><input id="node-search" aria-label="搜索节点（IP 或国家）" placeholder="搜索 IP / 国家…" oninput="debouncedRefresh()"><select id="sortsel" aria-label="排序"><option value="real">按实测延迟</option><option value="hand">按握手延迟</option><option value="country">按国家</option><option value="alive">按存活时间</option><option value="server">按出口 IP</option></select><button id="btn-refresh" class="btn" onclick="refreshNow()">刷新节点</button><button id="btn-fullprobe" class="btn" onclick="fullProbeNow()">全量真测</button><button id="btn-fullprobe-cancel" class="btn" style="display:none" onclick="cancelFullProbe()">取消真测</button><span class="node-count" id="node-count"></span></div>
<select id="scope" aria-label="范围"><option value="">全部国家</option></select>
<div id="thinbar" aria-hidden="true"><i></i></div><div id="probe-progress"><div class="bar"><div class="fill" id="probe-fill" role="progressbar" aria-label="全量真测进度" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div></div><div class="txt" id="probe-txt"></div></div>
<div id="empty-note" class="empty" hidden></div>
<p id="load-note" class="vh" role="status" hidden>加载中…</p><div id="bench-wrap"><table class="bench" aria-label="可用节点"><thead><tr><th class="sortable" scope="col"><button class="thsort" data-k="server" data-label="出口 IP">出口 IP</button></th><th class="sortable" scope="col"><button class="thsort" data-k="country" data-label="国家">国家</button></th><th class="sortable" scope="col"><button class="thsort" data-k="hand" data-label="握手">握手</button></th><th class="sortable" scope="col"><button class="thsort" data-k="real" data-label="实测">实测</button></th><th class="sortable" scope="col"><button class="thsort" data-k="alive" data-label="存活">存活</button></th><th scope="col">操作</th></tr></thead><tbody id="bench-body"></tbody></table></div>
</div>
</section>
<section id="sec-logs" aria-label="日志">
<div class="glass-card">
<h2>日志</h2>
<p class="desc">sing-box 最近输出，排查拨号失败时看这里。</p>
<div class="logtools"><input id="log-search" placeholder="搜索日志…" aria-label="搜索日志" oninput="renderLogs()"><select id="loglevel" aria-label="级别" title="error≈fail·refus·denied·exception；warn≈timeout·retry；ok≈verify·switch·refresh"><option value="">全部级别</option><option value="info">info</option><option value="warn">warn</option><option value="error">error</option></select><label class="chk"><input type="checkbox" id="log-auto" checked onchange="renderLogs()"> 自动滚动</label><button class="btn" style="padding:7px 18px;font-size:12.5px" id="btn-logrefresh" onclick="refreshLogs(this)">刷新</button></div>
<div id="logbox" role="log" aria-label="服务日志"><div style="color:#8b91a5">加载中…</div></div>
</div>
</section>
<section id="sec-sub" aria-label="订阅" hidden>
<div class="glass-card">
<h2>订阅</h2>
<p class="desc">双路 VLESS，一键复制。域名取当前访问 host。</p>
<div class="subrow"><span class="subtag">直连 /ws-node（VPN 故障时可用）</span><code id="sub-direct">—</code><button class="btn" onclick="copySub('direct',this)">复制</button></div>
<div class="subrow"><span class="subtag">经 VPN /ws-chain（跟随当前出口）</span><code id="sub-chain">—</code><button class="btn" onclick="copySub('chain',this)">复制</button></div>
<div class="subrow" id="sub-resi-row" hidden><span class="subtag">第三出口 /ws-resi（轮换）</span><code id="sub-resi">—</code><button class="btn" onclick="copySub('resi',this)">复制</button></div>
<p class="hostnote" id="sub-host"></p>
<div class="actions" style="margin-top:4px"><button class="btn" id="btn-copy-all" style="padding:7px 18px;font-size:12.5px" onclick="copyAll(this)">复制全部</button></div>
</div>
</section>
<section id="sec-hist" aria-label="事件">
<div class="glass-card">
<h2>事件</h2>
<p class="desc">刷新 / 切换 / 测速 / 验证记录，最近 20 条。</p>
<p id="history-line"></p>
<ul id="history-list"></ul>
</div>
</section>
<section id="sec-settings" aria-label="设置">
<div class="glass-card">
<h2>设置</h2>
<p class="desc">运行参数，保存后下轮生效（刷新间隔、全量并发等），重启不丢失。</p>
<div class="setgrid">
<label>刷新间隔秒<input id="set-refresh" type="number" aria-label="刷新间隔秒"></label>
<label>真拨超时秒<input id="set-timeout" type="number" aria-label="真拨超时秒"></label>
<label>TopK 真拨数<input id="set-topk" type="number" aria-label="TopK 真拨数"></label><label>节点数(0=全量)<input id="set-limit" type="number" aria-label="节点数"></label>
<label>刷新真拨并发<input id="set-dialw" type="number" aria-label="刷新真拨并发"></label>
<label>全量真测并发<input id="set-fpw" type="number" aria-label="全量真测并发"></label>
<label>握手并发<input id="set-probew" type="number" aria-label="握手并发"></label>
<label class="chk"><input type="checkbox" id="set-repin"> 每小时自动重 pin 最优</label>
<label class="chk"><input type="checkbox" id="set-rescue"> 手动 pin 挂了自动救最优</label>
<label>住宅粘性秒(0=旋转)<input id="set-resittl" type="number" aria-label="住宅粘性秒"></label>
</div>
<div class="actions"><button id="btn-settings-save" class="btn" onclick="saveSettings()">保存设置</button></div>
<p id="settings-result" aria-live="polite"></p>
</div>
</section>
<div class="footer"><span id="foot-cpu" class="num">CPU —</span> · <span id="foot-mem" class="num">MEM —</span></div>
</div>
<div id="toast" role="status" aria-live="polite"></div><div id="alerts" role="alert" aria-live="assertive"></div>
<script>
var activeCountry = "";
var lastStatus = null;
var probeSeq = 0, fullSeq = 0, verifySeq = 0, fullT0 = 0, lastOkAt = 0;
var searchTimer = null, probeCtl = null, verifyCtl = null, fullCtl = null, autoVerifiedFor = null;
var sortKey = "real", sortDir = 1, pendingTag = null, pendingTimer = null, scopeSig = null;
var lastBytes = null, rateHist = {dn: [], up: []}, lastLogLines = [];
function authHeaders() {
  return {"Authorization": "Bearer " + (localStorage.getItem("admin_token") || "")};
}
function showConsole() {
  document.getElementById("login-gate").classList.add("hidden");
  document.getElementById("console").style.display = "";
  refresh();
  refreshLogs(null);
  loadSettings();
}
function backToLogin(msg) {
  probeSeq++; fullSeq++; verifySeq++;
  if (probeCtl) { probeCtl.abort(); probeCtl = null; }
  if (verifyCtl) { verifyCtl.abort(); verifyCtl = null; }
  if (fullCtl) { fullCtl.abort(); fullCtl = null; }
  localStorage.removeItem("admin_token");
  document.getElementById("console").style.display = "none";
  const gate = document.getElementById("login-gate");
  gate.classList.remove("hidden");
  const input = document.getElementById("login-token");
  input.value = "";
  document.getElementById("login-err").textContent = msg || "";
  input.focus();
}
function lockConsole() {
  if (pendingTimer) clearTimeout(pendingTimer);
  pendingTag = null;
  if (undoTimer) clearTimeout(undoTimer);
  undoFrom = null;
  const undo = document.getElementById("switch-undo");
  if (undo) undo.hidden = true;
  backToLogin("");
}
async function loginEnter() {
  const input = document.getElementById("login-token");
  const btn = document.getElementById("btn-login");
  if (btn.disabled) return;
  const err = document.getElementById("login-err");
  const trial = input.value.trim();
  if (!trial) { err.textContent = "请先填写 token"; input.focus(); return; }
  btn.disabled = true;
  btn.textContent = "验证中…";
  err.textContent = "";
  localStorage.setItem("admin_token", trial);
  try {
    await api("/api/status");
    showConsole();
  } catch (e) {
    localStorage.removeItem("admin_token");
    err.textContent = "token 不对，请重试";
    input.select();
    input.focus();
    const card = document.querySelector(".login-card");
    card.classList.remove("shake");
    void card.offsetWidth;
    card.classList.add("shake");
  }
  btn.disabled = false;
  btn.textContent = "进入控制台";
}
async function silentLogin() {
  if (!localStorage.getItem("admin_token")) return;
  try {
    await api("/api/status");
    showConsole();
  } catch (e) {
    localStorage.removeItem("admin_token");
  }
}
function toast(msg, isErr) {
  const box = document.getElementById(isErr ? "alerts" : "toast") || document.getElementById("toast");
  if ([...box.children].some(c => c.textContent === msg)) return;
  while (box.children.length >= 3) box.firstChild.remove();
  const el = document.createElement("div");
  el.className = "toast-msg" + (isErr ? " err" : "");
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), isErr ? 6000 : 4500);
}
function setBusy(id, busy, busyText) {
  const el = document.getElementById(id);
  if (!el) return;
  if (busy) {
    if (el.dataset.orig === undefined) el.dataset.orig = el.textContent;
    el.disabled = true;
    el.classList.add("busy");
    el.textContent = busyText || "进行中…";
  } else {
    el.disabled = false;
    el.classList.remove("busy");
    if (el.dataset.orig !== undefined) el.textContent = el.dataset.orig;
  }
}
async function api(path, method, body, signal) {
  const r = await fetch(path, {method: method || "GET", headers: authHeaders(),
    body: body ? JSON.stringify(body) : undefined, signal: signal || undefined});
  if (r.status === 401) throw new Error("unauthorized: save ADMIN_TOKEN first");
  if (!r.ok) {
    const raw = (await r.text()).slice(0, 160);
    let detail = raw;
    try { const j = JSON.parse(raw); detail = j.detail || j.error || raw; } catch (_e) {}
    throw new Error("HTTP " + r.status + ": " + detail);
  }
  return r.json();
}
function runningTagOf(msg) { const m = /"tag"\\s*:\\s*"([^"]+)"/.exec(msg || ""); return m ? m[1] : ""; }
// Charset note: tags are safeTag-stripped ([a-zA-Z0-9-_]) and only minted as
// vpngate-N, so they never contain quotes/escapes that could break [^"]+.
function isAbort(e) { return !!e && e.name === "AbortError"; }
function fmtMs(v) { return v == null ? "—" : v + "ms"; }
function safeTag(t) { return String(t || "").replace(/[^a-zA-Z0-9-_]/g, ""); }
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function latCls(v) { if (v == null) return "l-na"; if (v < 250) return "l-good"; if (v < 600) return "l-mid"; return "l-bad"; }
function latBar(v) {
  if (v == null) return '<span class="l-na">—</span>';
  const w = Math.max(6, Math.min(100, Math.round(v / 8)));
  return '<span class="lat"><span class="bar"><i style="width:' + w + '%;background:currentColor" class="' + latCls(v) + '"></i></span><span class="' + latCls(v) + '">' + v + 'ms</span></span>';
}
function fmtGB(v) { return v == null ? "—" : (v / 1e9).toFixed(1) + " GB"; }
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  if (sec < 3600) return Math.floor(sec / 60) + "m";
  if (sec < 172800) return Math.floor(sec / 3600) + "h" + Math.floor(sec % 3600 / 60) + "m";
  return Math.floor(sec / 86400) + "d" + Math.floor(sec % 86400 / 3600) + "h";
}
function nodeQuery() { const el = document.getElementById("node-search"); return el ? el.value.trim().toLowerCase() : ""; }
function preferredEp(s) { const all = (s && s.endpoints) || []; return all.find(e => e.tag === s.preferred_tag) || all[0]; }
function sortVal(e) {
  if (sortKey === "country") return (e.country || "") + (e.tag || "");
  if (sortKey === "tag") return e.tag || "";
  if (sortKey === "server") return e.server || "";
  if (sortKey === "hand") return e.latency_ms == null ? 1e9 : e.latency_ms;
  if (sortKey === "alive") return -(e.alive_seconds || 0);
  return e.real_latency_ms == null ? 1e9 : e.real_latency_ms;
}
function filteredEndpoints(s) {
  const q = nodeQuery();
  const arr = s.endpoints.filter(e => (!activeCountry || e.country_short === activeCountry) &&
    (!q || (e.tag || "").toLowerCase().includes(q) || (e.country_short || "").toLowerCase().includes(q) ||
      (e.country || "").toLowerCase().includes(q) || (e.server || "").toLowerCase().includes(q)));
  arr.sort((a, b) => { const x = sortVal(a), y = sortVal(b); return (x > y ? 1 : x < y ? -1 : 0) * sortDir; });
  return arr;
}
function debouncedRefresh() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { searchTimer = null; renderFiltered(); }, 300);
}
function clearFilter() {
  activeCountry = "";
  const el = document.getElementById("node-search");
  if (el) el.value = "";
  const sc = document.getElementById("scope");
  if (sc) sc.value = "";
  renderFiltered();
}
async function refresh() {
  try {
    const s = await api("/api/status");
    lastStatus = s;
    renderAll(s);
    lastOkAt = Date.now();
  } catch (e) {
    if (isAbort(e)) return;
    if (/401|unauthorized/.test(e.message || "")) { backToLogin("登录已失效，请重新输入 token"); return; }
    document.getElementById("hero-sub").textContent = "状态拉取失败：" + e.message;
    toast("状态拉取失败: " + e.message, true);
  }
}
function renderFiltered() {
  if (!lastStatus) { refresh(); return; }
  renderAll(lastStatus);
}
function renderAll(s) {
  try {
    const focusEl = document.activeElement;
    let focusBack = null;
    const focusSearch = () => { if (document.getElementById("node-search")) document.getElementById("node-search").focus(); };
    if (focusEl && focusEl.getAttribute) {
      if (focusEl.id === "scope") focusBack = () => document.getElementById("scope").focus();
      else if (focusEl.getAttribute("data-probe")) { const t = focusEl.getAttribute("data-probe"); focusBack = () => { const b = document.querySelector("[data-probe='" + t + "']"); if (b && !b.disabled) b.focus(); else focusSearch(); }; }
      else if (focusEl.getAttribute("data-switch")) { const t = focusEl.getAttribute("data-switch"); focusBack = () => { const b = document.querySelector("[data-switch='" + t + "']"); if (b && !b.disabled) b.focus(); else focusSearch(); }; }
    }
    if (pendingTag && s.preferred_tag === pendingTag && !(s.probe && s.probe.state === "running")) pendingTag = null;
    const eps = filteredEndpoints(s);
    const pref = preferredEp(s);
    document.getElementById("hero-kicker").innerHTML =
      (pref ? esc(pref.country_short) + "<br>" + (pref.real_latency_ms != null ? pref.real_latency_ms + "ms" : fmtMs(pref.latency_ms) + "·未真测") : "—<br>无节点");
    document.getElementById("hero-sub").textContent =
      pref ? ("出口 " + pref.server + ":" + pref.server_port + " · 存活 " + (pref.alive_seconds || 0) + "s") : "暂无可用节点";
    renderVerify(s.verify, pref);
    maybeAutoVerify(s);
    renderStatusbar(s, pref);
    renderTraffic(s);
    renderRoutes(s);
    renderSub(s);
    document.getElementById("stat-nodes").textContent = s.endpoints.length;
    const measured = s.endpoints.filter(e => e.real_latency_ms != null).map(e => e.real_latency_ms);
    document.getElementById("stat-best").textContent = measured.length ? Math.min.apply(null, measured) + "ms" : "—";
    document.getElementById("stat-uptime").textContent = fmtDur(s.uptime_seconds || 0);
    document.getElementById("stat-refresh").textContent = s.refresh_ok + "/" + s.refresh_fail;
    const errChip = document.getElementById("stat-err");
    if (errChip) {
      if (s.last_error) { errChip.hidden = false; errChip.textContent = String(s.last_error).slice(0, 18); errChip.title = String(s.last_error); }
      else errChip.hidden = true;
    }
    const byCountry = {};
    s.endpoints.forEach(e => { byCountry[e.country_short] = (byCountry[e.country_short] || 0) + 1; });
    const scopeSel = document.getElementById("scope");
    if (scopeSel) {
      const codes = {};
      (s.countries || []).forEach(c => { codes[c.code] = c.name; });
      s.endpoints.forEach(e => { if (e.country_short && !codes[e.country_short]) codes[e.country_short] = e.country || e.country_short; });
      const sig = JSON.stringify([codes, byCountry]);
      if (sig !== scopeSig) {
        scopeSig = sig;
        scopeSel.innerHTML = '<option value="">全部国家 ' + s.endpoints.length + "</option>" +
          Object.keys(codes).sort().map(code => '<option value="' + esc(code) + '"' + (activeCountry === code ? " selected" : "") + ">" + esc(code) + " " + (byCountry[code] || 0) + "</option>").join("");
      } else if (scopeSel.value !== activeCountry) {
        scopeSel.value = activeCountry;
      }
    }
    const probingTag = (s.probe && s.probe.state === "running") ? s.probe.tag : null;
    const rows = eps.map(e => {
      const t = safeTag(e.tag);
      const isPinned = e.tag === s.preferred_tag, isPending = e.tag === pendingTag;
      const pinned = isPinned ? '<span class="badge">生效中</span>' : "";
      const pending = isPending ? '<span class="badge probing">切换中</span>' : "";
      const probing = (!isPending && e.tag === probingTag) ? '<span class="badge probing">测速中</span>' : "";
      const unmeasured = e.real_latency_ms == null;
      const unm = (!isPinned && !isPending && unmeasured) ? '<span class="badge unmeasured">未测通</span>' : "";
      const disSw = unmeasured ? " aria-disabled='true' title='先测速再切换：该节点还未测通'" : "";
      const disPb = (e.tag === probingTag) ? " aria-disabled='true' title='测速中，请稍候'" : "";
      return "<tr class='" + (isPinned ? "pinned" : "") + (isPending ? " pending" : "") + "'><td class='hl'><span class='ip'>" + esc(e.server || e.tag) + "</span>" + pinned + pending + probing + unm + "</td><td><span class='cc'>" + esc(e.country_short) + "</span>" + esc(e.country) + "</td><td class='hl'>" + fmtMs(e.latency_ms) +
      "</td><td class='hl'>" + latBar(e.real_latency_ms) + "</td><td>" + (e.alive_seconds || 0) + "s</td>" +
      "<td class='op'><button class='opbtn' data-probe='" + t + "' aria-label='单测 " + esc(e.server || e.tag) + "'" + disPb + ">测速</button><button class='opbtn' data-switch='" + t + "' aria-label='切换到 " + esc(e.server || e.tag) + "'" + disSw + ">切换</button></td></tr>";
    }).join("");
    document.getElementById("bench-body").innerHTML = rows ||
      '<tr><td colspan="6"><div class="empty">无匹配节点，换个关键词或 <a class="linklike" onclick="clearFilter()">清除筛选</a></div></td></tr>';
    document.getElementById("node-count").textContent = eps.length + " / " + s.endpoints.length;
    const loadNote = document.getElementById("load-note");
    if (loadNote) loadNote.hidden = true;
    const emptyNote = document.getElementById("empty-note");
    if (emptyNote) {
      const filtering = activeCountry || nodeQuery();
      if (s.endpoints.length === 0) {
        emptyNote.hidden = false;
        emptyNote.innerHTML = "暂无可用节点" + (s.last_error ? "（快照拉取失败：" + esc(String(s.last_error).slice(0, 120)) + "）" : "") + ' · <a class="linklike" onclick="refreshNow()">重试刷新</a>';
      } else if (!filtering && s.endpoints.every(e => e.real_latency_ms == null)) {
        emptyNote.hidden = false;
        emptyNote.innerHTML = s.endpoints.length + ' 个节点均未真测，请先全量真测再切换 · <a class="linklike" onclick="fullProbeNow()">开始全量真测</a>';
      } else {
        emptyNote.hidden = true;
      }
    }
    if (focusBack) focusBack();
    syncSortHeaders();
    renderProbeProgress(s.full_probe);
    document.getElementById("history-line").textContent =
      "刷新成功/失败：" + s.refresh_ok + "/" + s.refresh_fail + " · 运行：" + fmtDur(s.uptime_seconds || 0) + " · 错误：" + (s.last_error || "—");
    const hist = (s.refresh_history || []).slice().reverse().slice(0, 20);
    document.getElementById("history-list").innerHTML = hist.length ?
      hist.map(h => "<li><b>" + esc(h.event) + "</b> " + esc(h.detail || "") + " · " + esc(h.ts || "") + "</li>").join("") :
      '<li style="color:#8b91a5">暂无事件</li>';
    const cpu = s.cpu || {}, mem = s.mem || s.memory || {};
    const cpuPct = cpu.pct, memPct = mem.pct;
    const footCpu = document.getElementById("foot-cpu"), footMem = document.getElementById("foot-mem");
    if (footCpu) {
      footCpu.textContent = "CPU " + (cpu.model || "—") + " · " + (cpuPct == null ? "—" : cpuPct + "%");
      footCpu.className = "num " + (cpuPct == null || cpuPct < 50 ? "l-good" : (cpuPct < 80 ? "l-mid" : "l-bad"));
    }
    if (footMem) {
      footMem.textContent = "MEM " + (memPct == null ? "—" : memPct + "%");
      footMem.className = "num " + (memPct == null || memPct < 70 ? "l-good" : (memPct < 88 ? "l-mid" : "l-bad"));
    }
  } catch (e) {
    if (isAbort(e)) return;
    document.getElementById("hero-sub").textContent = "状态拉取失败：" + e.message;
    toast("状态拉取失败: " + e.message, true);
  }
}
function renderStatusbar(s, pref) {
  const exitIp = (s.verify && s.verify.exit_ip) ||
    ((s.verify && s.verify.state === "running") ? "验证中…" : "未验证");
  document.getElementById("sb-exit").textContent = exitIp;
  const pinEp = (s.endpoints || []).find(x => x.tag === s.preferred_tag) || {};
  const pinIp = pinEp.server || s.preferred_tag;
  const nodeEl = document.getElementById("sb-node");
  nodeEl.textContent = s.preferred_tag ? (pinIp + " · 已 pin") : (pref ? ((pref.server || pref.tag) + " · 自动") : "—");
  const backupIp = s.backup_tag ? ipOf(s.backup_tag) : null;
  nodeEl.title = s.preferred_tag
    ? ((s.auto_pinned ? "自动优选：全量实测最低" : "已 pin：手动锁定该出口") +
       (backupIp ? " · 备选 " + backupIp : ""))
    : "自动：由 urltest 优选";
  const dot = document.getElementById("sb-dot");
  if (dot) {
    const age = lastOkAt ? Math.round((Date.now() - lastOkAt) / 1000) : 1e9;
    const verified = !!(s.verify && s.verify.exit_ip);
    dot.className = "dot " + (age > 45 ? "err" : ((!verified || age > 30) ? "stale" : ""));
    dot.title = "上次更新" + (age > 1e8 ? "—" : age + "s前") + " · 自动刷新每15s";
    const dtxt = document.getElementById("sb-dot-txt");
    if (dtxt) dtxt.textContent = age > 45 ? "刷新失败" : ((!verified || age > 30) ? "未验证或数据较旧" : "正常");
  }
}
function renderTraffic(s) {
  const t = s.traffic || {};
  document.getElementById("stat-down").textContent = fmtGB(t.bytes_down);
  document.getElementById("stat-up").textContent = fmtGB(t.bytes_up);
  const now = Date.now();
  if (lastBytes && now > lastBytes.at) {
    const dt = (now - lastBytes.at) / 1000;
    const dn = Math.max(0, (t.bytes_down - lastBytes.dn) * 8 / dt / 1e6);
    const up = Math.max(0, (t.bytes_up - lastBytes.up) * 8 / dt / 1e6);
    document.getElementById("rate-dn").textContent = dn.toFixed(2);
    document.getElementById("rate-up").textContent = up.toFixed(2);
    const alt = document.getElementById("spark-alt");
    if (alt) alt.textContent = "下行最新 " + dn.toFixed(2) + " Mb/s，上行 " + up.toFixed(2) + " Mb/s";
    rateHist.dn.push(dn); rateHist.up.push(up);
    if (rateHist.dn.length > 60) { rateHist.dn.shift(); rateHist.up.shift(); }
    document.getElementById("rate-card").hidden = false;
    drawSpark();
  }
  lastBytes = {at: now, dn: t.bytes_down || 0, up: t.bytes_up || 0};
}
function drawSpark() {
  const c = document.getElementById("spark");
  if (!c || !rateHist.dn.length) return;
  const x = c.getContext("2d"), W = c.width, H = c.height;
  x.clearRect(0, 0, W, H);
  const dark = document.documentElement.dataset.theme !== "light";
  const line = (arr, col, max) => {
    x.strokeStyle = col; x.lineWidth = 2; x.beginPath();
    arr.forEach((v, i) => { const px = i / Math.max(1, arr.length - 1) * W, py = H - 4 - Math.min(1, v / max) * (H - 10); i ? x.lineTo(px, py) : x.moveTo(px, py); });
    x.stroke();
  };
  line(rateHist.dn, dark ? "#6ee7b7" : "#047857", Math.max(2, ...rateHist.dn));
  line(rateHist.up, dark ? "#7dd3fc" : "#0284c7", Math.max(1, ...rateHist.up));
}
function renderRoutes(s) {
  const strip = document.getElementById("route-strip");
  if (!strip) return;
  strip.hidden = false;
  document.getElementById("route-direct").textContent = location.hostname + " 本机";
  const exitIp = (s.verify && s.verify.exit_ip) || ((s.verify && s.verify.state === "running") ? "验证中…" : "未验证");
  document.getElementById("route-chain").textContent = exitIp;
  const resi = s.resi || {};
  const wrap = document.getElementById("route-resi-wrap");
  if (wrap) wrap.hidden = !resi.enabled;
  if (resi.enabled) {
    const rotate = resi.mode === "rotate";
    const kind = document.getElementById("route-resi-kind");
    if (kind) kind.textContent = rotate ? "节点轮换" : "住宅出口";
    const cell = document.getElementById("route-resi");
    if (cell) cell.textContent = rotate
      ? ((resi.pool || 0) + " / " + (resi.inbounds || resi.nodes || 0) + " 可用")
      : (resi.exit_ip || "未探测");
  }
  renderResi(s);
}
function renderResi(s) {
  const card = document.getElementById("resi-card");
  if (!card) return;
  const r = s.resi || {};
  if (!r.enabled) { card.hidden = true; return; }
  card.hidden = false;
  const rotate = r.mode === "rotate";
  const mode = rotate
    ? ("节点池 " + (r.pool || 0) + "/" + (r.inbounds || 0) + " 可用 · 每连接轮换" +
       (r.down ? (" · " + r.down + " 个临时剔除") : "") +
       (r.reserved ? (" · " + r.reserved + " 个留给 chain") : ""))
    : (r.mode === "sticky" ? ("粘性 · ttl " + r.sticky_ttl + "s") : "旋转");
  const where = rotate ? ("入口 :" + r.port + r.path) : ("网关 " + r.host + ":" + r.port);
  const state = r.state === "up" ? "正常" : (r.state === "down" ? "不可用" : "未探测");
  const el = document.getElementById("resi-line");
  if (el) el.textContent = where + " · " + mode + " · " + state +
    (r.exit_ip ? (" · 出口 " + r.exit_ip + (r.ms ? (" / " + r.ms + "ms") : "")) : "") +
    (r.error ? (" · " + r.error) : "");
  const p = r.last_probe || {};
  const ips = p.ips || [];
  const box = document.getElementById("resi-ips");
  if (!box) return;
  if (p.state === "running") { box.textContent = "探测中…"; return; }
  if (!ips.length) { box.textContent = p.error ? ("探测失败：" + p.error) : "尚无探测结果"; return; }
  let verdict = "";
  if (p.rotating === true) verdict = " · 轮换正常";
  else if (p.rotating === false) verdict = " · 未轮换（旋转模式请确认客户端已关闭 multiplex/mux）";
  box.textContent = ips.join(" → ") + " · 不同 IP " + p.distinct + " 个" + verdict;
}
async function resiProbe() {
  const btn = document.getElementById("btn-resi-probe");
  if (btn && btn.disabled) return;
  if (btn) { btn.disabled = true; btn.classList.add("busy"); }
  try {
    await api("/api/resi_probe", "POST", {count: 3});
    if (lastStatus) renderAll(lastStatus);
    refresh();
  } catch (e) {
    if (!isAbort(e)) toast("探测失败: " + e.message, true);
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove("busy"); }
  }
}
function renderSub(s) {
  const sec = document.getElementById("sec-sub");
  if (!sec) return;
  const nav = document.getElementById("nav-sub");
  if (!s.vless) { sec.hidden = true; if (nav) nav.style.display = "none"; return; }
  sec.hidden = false;
  if (nav) nav.style.display = "";
  const host = location.hostname, uuid = s.vless.uuid;
  const mk = (path, label) => "vless://" + uuid + "@" + host + ":443?security=tls&sni=" + host + "&type=ws&path=" + path + "#" + label;
  sec.dataset.direct = mk(s.vless.direct_path, "direct");
  sec.dataset.chain = mk(s.vless.chain_path, "vpngate");
  document.getElementById("sub-direct").textContent = sec.dataset.direct;
  document.getElementById("sub-chain").textContent = sec.dataset.chain;
  const resi = s.resi || {};
  const resiRow = document.getElementById("sub-resi-row");
  if (resiRow) {
    resiRow.hidden = !(resi.enabled && resi.path);
    if (!resiRow.hidden) {
      sec.dataset.resi = mk(resi.path, "resi");
      document.getElementById("sub-resi").textContent = sec.dataset.resi;
    }
  }
  const hostNote = document.getElementById("sub-host");
  if (hostNote) hostNote.textContent = "当前 host=" + host + " · 换域名访问会改变链接";
}
async function copySub(which, btn) {
  const sec = document.getElementById("sec-sub");
  const text = which === "direct" ? sec.dataset.direct : (which === "chain" ? sec.dataset.chain : sec.dataset.resi);
  if (!text) return;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand("copy"); } catch (_e) {}
    ta.remove();
  }
  if (!ok) { toast("复制失败，请手动复制", true); return; }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = "已复制 ✓";
    setTimeout(() => { btn.textContent = old; }, 1500);
  }
}
async function copyAll(btn) {
  const sec = document.getElementById("sec-sub");
  const text = [sec.dataset.direct, sec.dataset.chain, sec.dataset.resi].filter(Boolean).join(String.fromCharCode(10));
  if (!text) return;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand("copy"); } catch (_e) {}
    ta.remove();
  }
  if (!ok) { toast("复制失败，请手动复制", true); return; }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = "已复制 ✓";
    setTimeout(() => { btn.textContent = old; }, 1500);
  }
}
async function refreshLogs(btn) {
  if (btn) { btn.disabled = true; }
  try {
    const r = await api("/api/logs?lines=100");
    lastLogLines = r.lines || [];
    renderLogs();
  } catch (e) { if (!isAbort(e)) toast("日志拉取失败: " + e.message, true); }
  if (btn) { btn.disabled = false; }
}
function setVal(id, v) {
  const el = document.getElementById(id);
  if (!el) return;
  if (el.type === "checkbox") el.checked = !!v;
  else el.value = v;
}
function getVal(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  if (el.type === "checkbox") return el.checked;
  const n = parseInt(el.value, 10);
  return isNaN(n) ? el.value : n;
}
async function loadSettings() {
  try {
    const r = await api("/api/settings");
    const v = r.values || {};
    setVal("set-refresh", v.refresh_seconds);
    setVal("set-timeout", v.dial_timeout);
    setVal("set-topk", v.real_topk);
    setVal("set-limit", v.limit);
    setVal("set-dialw", v.dial_workers);
    setVal("set-fpw", v.full_probe_workers);
    setVal("set-probew", v.probe_workers);
    setVal("set-repin", v.auto_repin);
    setVal("set-rescue", v.auto_rescue);
    setVal("set-resittl", v.resi_session_ttl);
  } catch (e) { if (!isAbort(e)) toast("设置拉取失败: " + e.message, true); }
}
async function saveSettings() {
  const btn = document.getElementById("btn-settings-save");
  const note = document.getElementById("settings-result");
  const payload = {
    refresh_seconds: getVal("set-refresh"),
    dial_timeout: getVal("set-timeout"),
    real_topk: getVal("set-topk"),
    limit: getVal("set-limit"),
    dial_workers: getVal("set-dialw"),
    full_probe_workers: getVal("set-fpw"),
    probe_workers: getVal("set-probew"),
    auto_repin: getVal("set-repin"),
    auto_rescue: getVal("set-rescue"),
    resi_session_ttl: getVal("set-resittl")
  };
  if (btn) { btn.disabled = true; }
  try {
    await api("/api/settings", "POST", payload);
    if (note) note.textContent = "已保存 · 下轮生效";
    loadSettings();
  } catch (e) {
    if (!isAbort(e)) {
      if (note) note.textContent = "";
      toast("保存失败: " + e.message, true);
    }
  }
  if (btn) { btn.disabled = false; }
}
function logLevel(line) {
  if (/error|fail|refus|denied|exception/i.test(line)) return "err";
  if (/warn|timeout|retry|invalid/i.test(line)) return "warn";
  if (/verify|switch|refresh-ok|restarted|started|exit=/i.test(line)) return "ok";
  return "info";
}
function renderLogs() {
  const box = document.getElementById("logbox");
  if (!box) return;
  const lv = (document.getElementById("loglevel") || {}).value || "";
  const q = ((document.getElementById("log-search") || {}).value || "").trim().toLowerCase();
  const rows = lastLogLines.filter(l => (!lv || logLevel(l) === lv) && (!q || l.toLowerCase().includes(q)));
  box.innerHTML = rows.length ? rows.map(l => '<div><span class="' + logLevel(l) + '">' + esc(l.slice(0, 300)) + "</span></div>").join("")
    : '<div style="color:#8b91a5">暂无日志</div>';
  const auto = document.getElementById("log-auto");
  if (!auto || auto.checked) box.scrollTop = box.scrollHeight;
}
function toggleTheme() {
  const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = cur;
  try { localStorage.setItem("theme", cur); } catch (e) {}
  syncThemeLabel();
}
function syncThemeLabel() {
  const light = document.documentElement.dataset.theme === "light";
  document.querySelectorAll("#btn-theme,#btn-theme-gate").forEach((b) => { b.textContent = light ? "切换到深色" : "切换到浅色"; });
}
function toggleToken() {
  const input = document.getElementById("login-token");
  const btn = document.getElementById("btn-show-token");
  if (!input || !btn) return;
  const show = input.type !== "text";
  input.type = show ? "text" : "password";
  btn.textContent = show ? "隐藏" : "显示";
  btn.setAttribute("aria-pressed", show ? "true" : "false");
}
function skeletonRows() {
  let s = "";
  for (let i = 0; i < 5; i++) s += "<tr class='skel' aria-hidden='true'><td><div class='sk' style='width:60%'></div></td><td><div class='sk' style='width:40%'></div></td><td><div class='sk' style='width:50%'></div></td><td><div class='sk' style='width:70%'></div></td><td><div class='sk' style='width:30%'></div></td><td><div class='sk' style='width:70%'></div></td></tr>";
  document.getElementById("bench-body").innerHTML = s;
  const note = document.getElementById("load-note");
  if (note) note.hidden = false;
}
function verifyStale(v, preferredTag) {
  if (!v || v.state !== "done" || !v.exit_ip) return false;
  if (v.via_tag && preferredTag && v.via_tag !== preferredTag) return true;
  try {
    if (v.checked_at) {
      const age = Date.now() - Date.parse(v.checked_at);
      if (age > 10*60*1000) return true;
    }
  } catch(e) {}
  return false;
}
function maybeAutoVerify(s) {
  if (!s || !s.preferred_tag) return;
  const v = s.verify;
  const needs = (!v || v.state === "idle" || verifyStale(v, s.preferred_tag));
  if (!needs || autoVerifiedFor === s.preferred_tag) return;
  if (document.querySelector(".btn.busy")) return;
  if (s.probe && s.probe.state === "running") return;
  autoVerifiedFor = s.preferred_tag;
  verifyExit();
}
function renderVerify(v, pref) {
  const el = document.getElementById("verify-result");
  el.className = "";
  const preferredTag = lastStatus ? lastStatus.preferred_tag : null;
  if (verifyStale(v, preferredTag)) {
    el.textContent = "验证已过期或已切换，出口待重新验证";
    return;
  }
  if (!v || v.state === "idle") {
    el.textContent = pref ? "尚未验证当前出口，点击「验证出口 IP」真实走一次 VPN 链路。" : "";
    return;
  }
  if (v.state === "running") {
    el.textContent = "正在验证出口…";
    return;
  }
  if (v.exit_ip) {
    el.className = "verify-ok";
    el.textContent = "当前出口 IP：" + v.exit_ip + "（" + v.ms + "ms）";
  } else {
    el.className = "verify-err";
    el.textContent = "验证失败" + (v.error ? "：" + v.error : "");
  }
}
function renderProbeProgress(fp) {
  const box = document.getElementById("probe-progress");
  if (!fp || fp.state === "idle" || !fp.total) { box.classList.remove("show"); return; }
  box.classList.add("show");
  const pct = fp.total ? Math.round(fp.done / fp.total * 100) : 0;
  const fill = document.getElementById("probe-fill");
  fill.style.width = pct + "%";
  fill.setAttribute("aria-valuenow", String(pct));
  const stName = fp.state === "done" ? "已完成" : "进行中";
  let eta = "";
  if (fp.state !== "done" && fp.done > 0 && fullT0) {
    const left = Math.max(0, Math.round((Date.now() - fullT0) / fp.done * (fp.total - fp.done) / 1000));
    eta = " · 预计还需" + (left >= 60 ? Math.floor(left / 60) + "分" + (left % 60) + "秒" : left + "秒");
  }
  document.getElementById("probe-txt").textContent = "全量真测" + stName + " " + fp.done + "/" + fp.total + "（" + pct + "%）" + eta;
}
var undoFrom = null, undoTimer = null;
function ipOf(tag) {
  const ep = (lastStatus && lastStatus.endpoints || []).find(x => x.tag === tag);
  return (ep && ep.server) || tag;
}
function focusCurrentSwitch() {
  const tag = lastStatus ? lastStatus.preferred_tag : null;
  const b = tag ? document.querySelector("[data-switch='" + safeTag(tag) + "']") : null;
  if (b && !b.disabled) b.focus();
  else { const ns = document.getElementById("node-search"); if (ns) ns.focus(); }
}
function showUndo(fromTag, toTag) {
  if (!fromTag || fromTag === toTag) return;
  undoFrom = fromTag;
  document.getElementById("undo-from").textContent = ipOf(fromTag);
  document.getElementById("undo-to").textContent = ipOf(toTag);
  document.getElementById("switch-undo").hidden = false;
  const link = document.getElementById("undo-link");
  if (link) link.focus();
  if (undoTimer) clearTimeout(undoTimer);
  undoTimer = setTimeout(() => { document.getElementById("switch-undo").hidden = true; undoFrom = null; focusCurrentSwitch(); }, 15000);
}
function onUndo() {
  if (!undoFrom) return;
  const back = undoFrom;
  undoFrom = null;
  document.getElementById("switch-undo").hidden = true;
  switchTag(back);
}
async function switchTag(tag) {
  if (pendingTag && pendingTag !== tag) { toast("正在切换中，请稍候", true); return; }
  const fromTag = lastStatus ? lastStatus.preferred_tag : null;
  const ep = (lastStatus && lastStatus.endpoints || []).find(x => x.tag === tag);
  if (ep && ep.real_latency_ms == null) { toast("先测速再切换：该节点还未测通", true); return; }
  pendingTag = tag;
  if (pendingTimer) clearTimeout(pendingTimer);
  pendingTimer = setTimeout(() => { pendingTag = null; renderFiltered(); }, 20000);
  renderFiltered();
  try {
    const r = await api("/api/switch", "POST", {"tag": tag});
    autoVerifiedFor = r.preferred_tag || tag;
    showUndo(fromTag, r.preferred_tag || tag);
    await verifyExit();
  } catch (e) {
    if (!isAbort(e)) toast("切换失败: " + e.message, true);
    pendingTag = null;
    refresh();
  }
}
async function probeOne(tag) {
  const my = ++probeSeq;
  if (probeCtl) probeCtl.abort();
  probeCtl = new AbortController();
  const sig = probeCtl.signal;
  const probeT0 = Date.now();
  const btn = document.querySelector("[data-probe='" + safeTag(tag) + "']");
  if (btn) btn.textContent = "测速中…";
  try {
    await api("/api/probe", "POST", {"tag": tag}, sig);
    refresh();
    for (let i = 0; i < 60; i++) {
      if (my !== probeSeq) break;
      await new Promise(r => setTimeout(r, 3000));
      if (my !== probeSeq) break;
      const s = await api("/api/status", "GET", null, sig);
      lastStatus = s;
      renderAll(s);
      if (s.probe && s.probe.state === "done" && s.probe.tag === tag) {
        if (s.probe.ms == null) toast("单测 " + tag + " 未打通", true);
        break;
      }
      renderProbeWait(tag, probeT0);
      if (i === 59) toast("单测超时，任务仍在后台运行，请稍后查看", true);
    }
  } catch (e) {
    if (isAbort(e)) { restoreProbeBtn(tag); refresh(); return; }
    if (/409/.test(e.message || "")) { const t = runningTagOf(e.message); toast("已有单测进行中，稍后再试" + (t ? "（" + t + "）" : ""), true); refresh(); return; }
    toast("单测失败: " + e.message, true);
  }
  restoreProbeBtn(tag);
  refresh();
}
function renderProbeWait(tag, t0) {
  const b = document.querySelector("[data-probe='" + safeTag(tag) + "']");
  if (!b) return;
  b.textContent = "测速中…（已等待" + Math.round((Date.now() - t0) / 1000) + "s）";
}
function restoreProbeBtn(tag) {
  // renderAll owns button state; this only resets transient text.
  const b = document.querySelector("[data-probe='" + safeTag(tag) + "']");
  if (b) b.textContent = "测速";
}
async function refreshNow() {
  const btn = document.getElementById("btn-refresh");
  if (btn && btn.disabled) return;
  setBusy("btn-refresh", true, "刷新中…");
  const benchTable = document.querySelector("table.bench");
  const thin = document.getElementById("thinbar");
  if (lastStatus) {
    if (benchTable) benchTable.classList.add("loading");
    if (thin) thin.classList.add("show");
  } else skeletonRows();
  try {
    const r = await api("/api/refresh", "POST", {});
    if (r && r.accepted) {
      for (let i = 0; i < 200; i++) {
        await new Promise(rr => setTimeout(rr, 3000));
        const s = await api("/api/status");
        lastStatus = s;
        renderAll(s);
        const j = s.refresh_job;
        if (j && j.state === "done") {
          if (j.ok === false) toast("刷新完成但有失败" + (j.error ? ": " + j.error : ""), true);
          break;
        }
        if (i === 199) toast("刷新仍在后台运行，请稍后查看", true);
      }
    } else if (r && !r.ok) toast("刷新完成但有失败", true);
    refreshLogs(null);
  } catch (e) {
    if (isAbort(e)) return;
    toast(/409/.test(e.message || "") ? "已有刷新进行中，稍后再试" : ("刷新失败: " + e.message), true);
  }
  if (benchTable) benchTable.classList.remove("loading");
  if (thin) thin.classList.remove("show");
  setBusy("btn-refresh", false);
  refresh();
}
async function fullProbeNow() {
  const my = ++fullSeq;
  if (fullCtl) fullCtl.abort();
  fullCtl = new AbortController();
  const sig = fullCtl.signal;
  setBusy("btn-fullprobe", true, "真测中…");
  const cancelBtn = document.getElementById("btn-fullprobe-cancel");
  try {
    await api("/api/full_probe", "POST", {}, sig);
  } catch (e) {
    setBusy("btn-fullprobe", false);
    if (cancelBtn) cancelBtn.style.display = "none";
    if (isAbort(e)) return;
    toast(/409/.test(e.message || "") ? "已有全量任务进行中，稍后再试" : ("全量真测失败: " + e.message), true);
    return;
  }
  fullT0 = Date.now();
  if (cancelBtn) cancelBtn.style.display = "";
  try {
    for (let i = 0; i < 200; i++) {
      if (my !== fullSeq) break;
      await new Promise(r => setTimeout(r, 3000));
      if (my !== fullSeq) break;
      const s = await api("/api/status", "GET", null, sig);
      lastStatus = s;
      renderAll(s);
      if (s.full_probe && s.full_probe.state === "done") break;
      if (i === 199) toast("全量真测超时，请重试", true);
    }
  } catch (e) { if (!isAbort(e)) toast("全量真测失败: " + e.message, true); }
  setBusy("btn-fullprobe", false);
  if (cancelBtn) cancelBtn.style.display = "none";
  refresh();
}
function cancelFullProbe() {
  fullSeq++;
  if (fullCtl) { fullCtl.abort(); fullCtl = null; }
  setBusy("btn-fullprobe", false);
  const cancelBtn = document.getElementById("btn-fullprobe-cancel");
  if (cancelBtn) cancelBtn.style.display = "none";
  refresh();
}
async function verifyExit() {
  const my = ++verifySeq;
  if (verifyCtl) verifyCtl.abort();
  verifyCtl = new AbortController();
  const sig = verifyCtl.signal;
  setBusy("btn-verify", true, "验证中…");
  document.getElementById("verify-result").textContent = "正在验证新出口…";
  const verifyT0 = Date.now();
  try {
    await api("/api/verify", "POST", {}, sig);
    for (let i = 0; i < 60; i++) {
      if (my !== verifySeq) break;
      await new Promise(r => setTimeout(r, 3000));
      if (my !== verifySeq) break;
      const s = await api("/api/status", "GET", null, sig);
      lastStatus = s;
      const vp = preferredEp(s);
      renderVerify(s.verify, vp);
      if (s.verify && s.verify.state === "done") {
        if (!s.verify.exit_ip) toast("验证未拿到出口 IP", true);
        break;
      }
      if (s.verify && s.verify.state !== "done") {
        const vr = document.getElementById("verify-result");
        vr.textContent += "（已等待 " + Math.round((Date.now() - verifyT0) / 1000) + "s）";
      }
      if (i === 59) toast("验证超时，任务仍在后台运行，请稍后查看", true);
    }
  } catch (e) {
    if (isAbort(e)) { setBusy("btn-verify", false); refresh(); return; }
    if (/409/.test(e.message || "")) {
      const t = runningTagOf(e.message);
      toast("已有验证进行中，稍后再试" + (t ? "（" + t + "）" : ""), true);
      setBusy("btn-verify", false);
      refresh();
      return;
    }
    const el = document.getElementById("verify-result");
    el.textContent = "验证失败：" + e.message;
    el.className = "verify-err";
    toast("验证失败: " + e.message, true);
  }
  setBusy("btn-verify", false);
  refresh();
}
silentLogin();
syncThemeLabel();
document.getElementById("sortsel").addEventListener("change", (ev) => { sortKey = ev.target.value; sortDir = 1; renderFiltered(); });
document.getElementById("scope").addEventListener("change", (ev) => { activeCountry = ev.target.value; renderFiltered(); });
function sortBy(k) {
  if (sortKey === k) sortDir *= -1;
  else { sortKey = k; sortDir = 1; }
  const sel = document.getElementById("sortsel");
  if (sel) sel.value = k;
  renderFiltered();
}
document.querySelectorAll(".thsort").forEach((b) => {
  b.onclick = () => sortBy(b.getAttribute("data-k"));
});
function syncSortHeaders() {
  document.querySelectorAll(".thsort").forEach((b) => {
    const k = b.getAttribute("data-k");
    const label = b.getAttribute("data-label") || "";
    const th = b.closest ? b.closest("th") : null;
    if (k === sortKey) {
      if (th) th.setAttribute("aria-sort", sortDir === 1 ? "ascending" : "descending");
      b.textContent = label + (sortDir === 1 ? " ▲" : " ▼");
    } else {
      if (th) th.removeAttribute("aria-sort");
      b.textContent = label;
    }
  });
}
document.getElementById("loglevel").addEventListener("change", renderLogs);
const spySecs = ["sec-overview", "sec-nodes", "sec-logs", "sec-sub", "sec-hist", "sec-settings"];
window.addEventListener("scroll", () => {
  let cur = spySecs[0];
  spySecs.forEach((id) => { const el = document.getElementById(id); if (el && el.getBoundingClientRect().top < 170) cur = id; });
  document.querySelectorAll("#topnav .links a").forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + cur));
}, {passive: true});
document.getElementById("bench-body").onclick = (ev) => {
  const link = ev.target && ev.target.closest ? ev.target.closest("[data-probe],[data-switch]") : null;
  if (!link) return;
  if (link.getAttribute("aria-disabled") === "true") {
    if (link.getAttribute("data-switch")) toast("先测速再切换：该节点还未测通", true);
    else if (link.getAttribute("data-probe")) toast("该节点测速中，请稍候", true);
    return;
  }
  const p = link.getAttribute("data-probe");
  const sw = link.getAttribute("data-switch");
  if (p) probeOne(p);
  else if (sw) switchTag(sw);
};
document.getElementById("bench-body").onkeydown = (ev) => {
  if (ev.key !== "Enter" && ev.key !== " ") return;
  const link = ev.target && ev.target.closest ? ev.target.closest("[data-probe],[data-switch]") : null;
  if (!link) return;
  if (link.getAttribute("aria-disabled") === "true") {
    if (link.getAttribute("data-switch")) toast("先测速再切换：该节点还未测通", true);
    else if (link.getAttribute("data-probe")) toast("该节点测速中，请稍候", true);
    if (ev.key === " ") ev.preventDefault();
    return;
  }
  if (ev.key === " ") { ev.preventDefault(); return; }
  ev.preventDefault();
  const p = link.getAttribute("data-probe");
  const sw = link.getAttribute("data-switch");
  if (p) probeOne(p);
  else if (sw) switchTag(sw);
};
setInterval(() => {
  if (document.getElementById("console").style.display === "none") return;
  if (document.hidden) return;
  if (document.querySelector(".btn.busy")) return;
  refresh();
  const auto = document.getElementById("log-auto");
  const lv = document.getElementById("loglevel");
  const qs = document.getElementById("log-search");
  if (auto && auto.checked && lv && !lv.value && qs && !qs.value.trim()) refreshLogs(null);
}, 15000);
</script>
</body></html>
"""

def default_fetch(url: str, timeout: int = 20) -> str:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"refusing non-https snapshot url: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")
def build_config_from_env(env: dict) -> dict:
    password = env.get("PROXY_PASS", "")
    if not password:
        password = secrets.token_urlsafe(24)
        print("PROXY_PASS not set, generated a random one", flush=True)
    elif len(password) < MIN_PROXY_PASS_LEN:
        print(f"refusing to start: PROXY_PASS must be at least {MIN_PROXY_PASS_LEN} chars", flush=True)
        raise SystemExit(2)
    snapshot_url = env.get("SNAPSHOT_URL", DEFAULT_SNAPSHOT_URL)
    raw_mirrors = env.get("SNAPSHOT_URLS", "")
    snapshot_urls = [u.strip() for u in raw_mirrors.split(",") if u.strip()]
    if not snapshot_urls:
        snapshot_urls = [snapshot_url]
    for url in snapshot_urls:
        if urllib.parse.urlsplit(url).scheme != "https":
            print(f"refusing to start: snapshot url must be https: {url}", flush=True)
            raise SystemExit(2)
    if "ADMIN_TOKEN" not in env or not env["ADMIN_TOKEN"]:
        admin_token = "vpn"
        generated = False
        print("ADMIN_TOKEN not set, defaulting to 'vpn'", flush=True)
    else:
        admin_token = env["ADMIN_TOKEN"]
        generated = False
        if len(admin_token) < MIN_ADMIN_TOKEN_LEN:
            admin_token = secrets.token_urlsafe(24)
            generated = True
    mixed_port = _int_env(env, "MIXED_PORT", 40000, 1, 65535)
    port = _int_env(env, "PORT", 3000, 1, 65535)
    vless_direct_port = _int_env(env, "VLESS_DIRECT_PORT", 8080, 1, 65535)
    vless_chain_port = _int_env(env, "VLESS_CHAIN_PORT", 8082, 1, 65535)
    resi_port = _int_env(env, "RESI_PORT", DEFAULT_RESI_PORT, 1, 65535)
    resi = _build_resi_from_env(env)
    # Third path, rotating mode: no external gateway, so rotate over the
    # serving endpoints. Needs VLESS_UUID because its inbounds are VLESS+WS.
    resi_rotate = resi is None and bool(env.get("VLESS_UUID", ""))
    if vless_direct_port == vless_chain_port:
        print(f"refusing to start: VLESS ports collide ({vless_direct_port})", flush=True)
        raise SystemExit(2)
    if resi is not None and not env.get("VLESS_UUID", ""):
        print("refusing to start: RESI_GATEWAY needs VLESS_UUID (the resi path is a VLESS+WS inbound)", flush=True)
        raise SystemExit(2)
    if resi is not None or resi_rotate:
        if resi_port in {8080, 8081, 8082, 4096, mixed_port, vless_direct_port, vless_chain_port}:
            print(f"refusing to start: RESI_PORT={resi_port} collides", flush=True)
            raise SystemExit(2)
    if mixed_port in {8080, 8081, 8082, 4096, vless_direct_port, vless_chain_port}:
        print(f"refusing to start: MIXED_PORT={mixed_port} collides", flush=True)
        raise SystemExit(2)
    reserved = {8080, 8081, 8082, 4096, mixed_port, vless_direct_port, vless_chain_port}
    if resi is not None or resi_rotate:
        reserved.add(resi_port)
    if port in reserved:
        print(f"refusing to start: PORT={port} collides {sorted(reserved)}; set PORT=3000", flush=True)
        raise SystemExit(2)
    if port != 3000:
        print(f"warning: PORT={port} is not 3000", flush=True)
    return {
        "port": port, "mixed_port": mixed_port,
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
    tag_by_key: dict[str, str] = {}
    for old in old_nodes:
        old_ep = old.get("endpoint") or {}
        if old_ep.get("tag"):
            tag_by_key.setdefault(f"{old.get('server')}:{old.get('server_port')}", old_ep["tag"])
    used: set[str] = set()
    counter = 0
    def _fresh() -> str:
        nonlocal counter
        while f"{tag_prefix}-{counter}" in used:
            counter += 1
        tag = f"{tag_prefix}-{counter}"
        counter += 1
        return tag
    for node in nodes:
        endpoint = node.get("endpoint") or {}
        tag = endpoint.get("tag") or ""
        if tag and tag not in used:
            used.add(tag)
            continue
        key = f"{node.get('server')}:{node.get('server_port')}"
        reused = tag_by_key.get(key)
        if not reused or reused in used:
            reused = _fresh()
        endpoint["tag"] = reused
        node["endpoint"] = endpoint
        used.add(reused)
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
    lines = [f"HTTP/1.1 {status}", f"Content-Type: {content_type}", f"Content-Length: {len(body)}"]
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
        max_mux_connections: int = MAX_MUX_CONNECTIONS, health_check_interval: int = HEALTH_CHECK_INTERVAL, fetcher=None) -> None:
        self.port = port; self.mixed_port = mixed_port; self.username = username; self.password = password
        self.admin_token = admin_token; self.snapshot_url = snapshot_url
        self.snapshot_urls = list(snapshot_urls) if snapshot_urls else [snapshot_url]
        self.refresh_seconds = refresh_seconds; self.limit = limit; self.real_topk = real_topk
        self.dial_fn = (dial_fn if dial_fn is not None else (lambda node: measure_real_latency(node["endpoint"], self.singbox_bin, self.dial_timeout)))
        self.dial_workers = dial_workers; self.full_probe_workers = max(1, full_probe_workers); self.probe_workers = probe_workers
        self.dial_timeout = dial_timeout; self.auto_repin = auto_repin; self.auto_rescue = auto_rescue
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
        self._cloudflared_proc = None; self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = False
        self._nodes: list[dict] = []; self._first_seen: dict[str, str] = {}
        self._cpu_model = _cpu_model(); self._cpu_cores = os.cpu_count(); self._cpu_last = None
        self._fail_streak = 0; self._pinned_fail_streak = 0; self._rescue_round = 0; self._crash_streak = 0; self._retry_after = 0.0; self._mixed_fail_streak = 0; self._mixed_retry_after = 0.0; self._health_mixed_streak = 0; self._refresh_generation = 0
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
            "resi": resi_status}
        self._full_probe_thread = None; self._single_probe_thread = None; self._verify_thread = None; self._verify_generation = 0; self._refresh_thread = None
        self._stop_event = threading.Event(); self._mux_slots = threading.BoundedSemaphore(max_mux_connections); self._mux_inflight = 0
        self._post_slots = threading.BoundedSemaphore(MAX_POST_CONNECTIONS); self._health_check_interval = health_check_interval
        self._listener = None; self._singbox_proc = None; self._stderr_handle = None; self.bound_port = port
        self.load_settings()
        if self.resi is not None:
            # settings.json overrides env for the ttl, so re-sync the reported mode.
            self._set_resi(mode=self._resi_mode(), sticky_ttl=self.resi_session_ttl)
    def start(self) -> int:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("0.0.0.0", self.port))
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
        print(f"listening on 0.0.0.0:{self.bound_port}, backend 127.0.0.1:{self.mixed_port}", flush=True)
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
        print(f"shutdown: mux drain {'done' if drained else 'timeout'} ({remaining} in flight)", flush=True)
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
        return headers.get("authorization", "") == f"Bearer {self.admin_token}"
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
                    self._handle_resi_client(client, prefix=data, hold_slot=False)
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
        resi = snapshot.get("resi")
        if isinstance(resi, dict) and resi.get("enabled") and self.resi_rotate:
            with self._lock:
                usable, parked, _ = self._resi_pool_locked()
                resi["pool"] = usable
                resi["down"] = parked
                resi["inbounds"] = len(self._resi_routes)
                resi["nodes"] = usable
                resi["reserved"] = self.status["resi"].get("reserved", 0)
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
            self.preferred_tag = preferred; self.backup_tag = backup; self._auto_pinned = auto_pinned
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
        while not self._stop_event.wait(max(0.0, next_run - time.monotonic())):
            try:
                self._start_refresh_bg()
            except Exception as exc:
                print(f"refresh loop error: {type(exc).__name__}: {exc}", flush=True)
            next_run = time.monotonic() + self._effective_interval() + random.uniform(-30, 30)
    def _supervise_loop(self) -> None:
        while not self._stop_event.wait(SUPERVISE_INTERVAL):
            try:
                self._supervise_once()
            except Exception as exc:
                print(f"supervise loop error: {type(exc).__name__}: {exc}", flush=True)
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
                print(f"health monitor error: {type(exc).__name__}: {exc}", flush=True)
    def _trigger_bg_refresh(self, reason: str) -> None:
        try:
            started = self._start_refresh_bg()
        except Exception:
            return
        if started:
            self._record_history("health-trigger-refresh", reason)
    def _fresh_probe_tags(self, cands: list[dict]) -> list[str]:
        """Fresh-handshake filter for rescue targets (bounded, parallel).

        Stale real_latency_ms alone must not decide a rescue: return only
        tags with a live handshake right now, in ranking order.
        """
        short = cands[:EXIT_VERIFY_CAP]
        if not short:
            return []
        alive: dict[str, int] = {}
        alive_lock = threading.Lock()
        def _one(node: dict) -> None:
            try:
                host, port = primary_server(node.get("endpoint") or node)
                ms = probe_tcp_latency(host, port, 5)
            except Exception:
                ms = 0
            if ms and ms > 0:
                with alive_lock:
                    alive[((node.get("endpoint") or {}).get("tag"))] = ms
        with ThreadPoolExecutor(max_workers=min(len(short), 3)) as ex:
            list(ex.map(_one, short))
        order = {((n.get("endpoint") or {}).get("tag")): k for k, n in enumerate(cands)}
        return sorted(alive, key=lambda t: order.get(t, 10 ** 9))

    def check_pinned_health(self, probe_fn=None) -> str:
        """Simple health: pinned handshake must pass; serving handled gated.

        No real tunnel dial here (real dials kill serving via duplicate-cn
        and OOM storms). Real dials only on demand (probe/verify/full_probe).
        Rescue targets are fresh-handshake verified; stale ranking is only a
        stopgap when every handshake is dead (pool likely stale: a background
        refresh is triggered while the stale best holds the pin).
        """
        with self._lock:
            tag = self.preferred_tag
            node = next((n for n in self._nodes if n.get("endpoint", {}).get("tag") == tag), None) if tag else None
            self._rescue_round += 1
            round_id = self._rescue_round
        if tag is None or node is None:
            return "no-preferred"
        host, port = primary_server(node.get("endpoint") or node)
        try:
            hand = probe_tcp_latency(host, port, 5)
        except Exception:
            hand = 0
        alive = hand > 0
        if alive:
            with self._lock:
                node["latency_ms"] = hand
                if self._pinned_fail_streak > 0:
                    self._record_history("health-dial-ok", f"{tag} handshake recovered ms={hand}")
                self._pinned_fail_streak = 0
            if self.want_singbox and not self._serving_ok():
                self._note_mixed_down(f"{tag} serving down, watching")
            return "pinned"
        with self._lock:
            self._pinned_fail_streak += 1
            streak = self._pinned_fail_streak
            if not self.auto_rescue:
                cands = []
            else:
                cands = sorted((n for n in self._nodes if (n.get("endpoint") or {}).get("tag") != tag and n.get("real_latency_ms") is not None),
                    key=lambda n: (n["real_latency_ms"], (n.get("endpoint") or {}).get("tag") or ""))
                if not cands and self._nodes:
                    cands = sorted((n for n in self._nodes if (n.get("endpoint") or {}).get("tag") != tag and n.get("latency_ms") is not None),
                        key=lambda n: (n.get("latency_ms") or 10**9,))
        if not cands:
            if streak < PINNED_FAIL_THRESHOLD:
                return "pinned"
            with self._lock:
                self._pinned_fail_streak = 0
            with self._config_lock:
                with self._lock:
                    self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = True
                    self.status["preferred_tag"] = None; self.status["backup_tag"] = None; self.status["auto_pinned"] = True
                    self._persist_state(); self._invalidate_verify(f"unpinned after {tag} failed")
                self._apply_config(final="auto")
            self._record_history("auto-unpin", f"{tag} handshake failed {PINNED_FAIL_THRESHOLD}x")
            try:
                self._trigger_bg_refresh(f"{tag} pool exhausted")
            except Exception:
                pass
            return "unpinned"
        alive_tags = self._fresh_probe_tags(cands) if self.auto_rescue else []
        stale = False
        if alive_tags:
            best, second = alive_tags[0], (alive_tags[1] if len(alive_tags) > 1 else None)
        else:
            stale = True
            best = ((cands[0].get("endpoint") or {}).get("tag"))
            second = ((cands[1].get("endpoint") or {}).get("tag") if len(cands) > 1 else None)
            try:
                self._trigger_bg_refresh(f"{tag} all handshakes dead")
            except Exception:
                pass
        if streak < PINNED_FAIL_THRESHOLD and not (streak == 1 and best is not None):
            return "pinned"
        with self._lock:
            self._pinned_fail_streak = 0
        with self._config_lock:
            if not self._apply_config(final="auto", preferred=best, backup=second):
                return "pinned"
            if not self._commit_rescue(round_id, best, second):
                with self._lock:
                    cur = self.preferred_tag; cur_b = self.backup_tag
                if cur is not None:
                    self._apply_config(final="auto", preferred=cur, backup=cur_b)
                return "pinned"
        self._invalidate_verify(f"rescued to {best}")
        self._record_history("auto-rescue" + ("-stale" if stale else ""), f"{tag} handshake failed, rescued to {best}" + (f" backup={second}" if second else ""))
        return "rescued"

    def _commit_rescue(self, round_id: int, best: str | None, second: str | None) -> bool:
        with self._lock:
            if self._rescue_round != round_id:
                self._record_history("auto-pin-skipped", "manual switch won the race")
                return False
            self.preferred_tag = best; self.backup_tag = second; self._auto_pinned = True
            self.status["preferred_tag"] = best; self.status["backup_tag"] = second; self.status["auto_pinned"] = True
            self._persist_state()
            return True
    def switch(self, tag: str | None = None, country: str | None = None) -> tuple[bool, str]:
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
        # trylock: a long refresh apply must not wedge switch for minutes.
        if not self._config_lock.acquire(timeout=5):
            return False, "busy, retry later"
        try:
            if not self._apply_config(final="auto", preferred=target):
                return False, "config check failed, kept previous"
            with self._lock:
                old = self.preferred_tag
                self.preferred_tag = target; self.backup_tag = None; self._auto_pinned = False
                self.status["preferred_tag"] = target; self.status["backup_tag"] = None; self.status["auto_pinned"] = False
                self._rescue_round += 1; self._persist_state()
        finally:
            try:
                self._config_lock.release()
            except Exception:
                pass
        with self._lock:
            self._pinned_fail_streak = 0
        if old != target:
            self._invalidate_verify(f"pin-changed to {target}")
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
        config = build_singbox_config(endpoints, "127.0.0.1", mixed_port, mixed_users=[(username, password)],
            final=final, preferred=preferred, backup=backup, vless_uuid=vless_uuid,
            vless_direct_port=direct_port, vless_chain_port=chain_port,
            resi=resi_outbound, resi_port=resi_port, resi_path=resi_path,
            resi_rotate=self.resi_rotate, resi_rotate_tags=rotate_tags)
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
            self._restart_singbox()
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
        try:
            fetch = fetcher or self.fetcher
            csv_text = self._fetch_with_retry(fetch)
            nodes = snapshot_to_nodes(csv_text, limit=self.limit, probe_pool=probe_pool,
                probe_fn=lambda h, p: probe_tcp_latency(h, p, 5), probe_workers=self.probe_workers,
                real_topk=self.real_topk, dial_fn=self.dial_fn, dial_workers=self.dial_workers,
                dial_timeout=self.dial_timeout, singbox_bin=self.singbox_bin)
            if not nodes:
                return self._refresh_failed("no reachable nodes, kept previous")
        except Exception as exc:
            return self._refresh_failed(f"{type(exc).__name__}: {exc}")
        with self._lock:
            old_seen = dict(self._first_seen); now = _now_iso(); cur_keys = set()
            for node in nodes:
                key = f"{node['server']}:{node['server_port']}"
                cur_keys.add(key)
                self._first_seen.setdefault(key, old_seen.get(key, now))
            for key in [k for k in self._first_seen if k not in cur_keys]:
                del self._first_seen[key]
            assign_stable_tags(nodes, self._nodes)
            self._nodes = nodes
            endpoints = nodes_to_endpoints(nodes)
            tags = {ep["tag"] for ep in endpoints}
            if self.preferred_tag is not None and self.preferred_tag not in tags:
                self._record_history("preferred-gone", f"{self.preferred_tag} vanished, back to auto")
                self.preferred_tag = None; self.backup_tag = None; self._auto_pinned = True
            elif self.preferred_tag is None:
                self.backup_tag = None
            preferred = self.preferred_tag
            backup = self.backup_tag if self.backup_tag in tags else None
            if backup != self.backup_tag:
                self.backup_tag = backup
        with self._config_lock:
            with self._lock:
                preferred = self.preferred_tag
                backup = self.backup_tag if (self.backup_tag in tags) else None
                self.backup_tag = backup
            if not self._apply_config(final="auto", preferred=preferred, backup=backup):
                return self._refresh_failed("config check failed, kept previous")
            with self._lock:
                self.status["endpoints"] = [{"tag": ep["tag"], "server": primary_server(ep)[0], "server_port": primary_server(ep)[1],
                    "country": n.get("country", ""), "country_short": n.get("country_short", ""), "latency_ms": n.get("latency_ms"),
                    "real_latency_ms": n.get("real_latency_ms"), "speed": n.get("speed", 0)} for ep, n in zip(endpoints, nodes)]
                self.status["countries"] = self._countries()
                self.status["preferred_tag"] = self.preferred_tag; self.status["backup_tag"] = self.backup_tag
                self.status["auto_pinned"] = self._auto_pinned; self.status["last_refresh"] = _now_iso()
                self.status["last_error"] = None; self.status["refresh_ok"] += 1
                self._fail_streak = 0; self._crash_streak = 0
        self._persist_nodes(); self._persist_state()
        effective = "chain" if preferred else "auto"
        self._record_history("refresh-ok", f"{len(endpoints)} endpoints, final={effective}")
        print(f"refreshed {len(endpoints)} endpoints, final={effective}", flush=True)
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
        print(f"refresh failed: {reason}", flush=True)
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
            print(f"full probe error: {type(exc).__name__}: {exc}", flush=True)
        finally:
            with self._lock:
                if self.status.get("full_probe", {}).get("state") == "running":
                    self.status["full_probe"]["state"] = "done"

    def _run_full_probe_inner(self) -> None:
        with self._lock:
            nodes = list(self._nodes)
            self.status["full_probe"]["total"] = len(nodes)
            start_preferred = self.preferred_tag
        ordered = sorted(nodes, key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("server") or ""))
        def _dial_one(node: dict) -> None:
            try:
                ms = self.dial_fn(node) if self.dial_fn else None
            except Exception:
                ms = None
            with self._lock:
                node["real_latency_ms"] = ms
                self.status["full_probe"]["done"] += 1
        with ThreadPoolExecutor(max_workers=self.full_probe_workers) as executor:
            list(executor.map(_dial_one, ordered))
        with self._lock:
            self.status["full_probe"]["state"] = "done"
            self._sync_probe_results(nodes)
        self._auto_pin_best(nodes, start_preferred)
        # The pin may not have changed, but the verified set did: republish so
        # the third path's rotation pool picks up the freshly dialed nodes.
        self._republish_config()
        self._record_history("full-probe-done", f"{len(nodes)} nodes dialed")

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
        measured = sorted((n for n in nodes if n.get("real_latency_ms") is not None and (n.get("endpoint") or {}).get("tag")),
            key=lambda n: (n["real_latency_ms"], (n.get("endpoint") or {}).get("tag") or ""))
        if not measured:
            self._record_history("auto-pin-skipped", "nothing measured")
            return
        best = (measured[0].get("endpoint") or {}).get("tag")
        second = ((measured[1].get("endpoint") or {}).get("tag") if len(measured) > 1 else None)
        with self._lock:
            if self.preferred_tag is not None:
                self._record_history("auto-pin-skipped", "pin exists, manual full-probe keeps pin (use switch to change)")
                return
            if start_preferred is not None and self.preferred_tag != start_preferred:
                self._record_history("auto-pin-skipped", f"switched mid-run to {self.preferred_tag}")
                return
        pinned = None; pinned_second = None
        for i, cand in enumerate(measured[:EXIT_VERIFY_CAP]):
            tag = (cand.get("endpoint") or {}).get("tag")
            ep = cand.get("endpoint") or cand
            try:
                ip, _ = self.verify_fn(ep)
            except Exception:
                ip = None
            if ip:
                pinned = tag
                rest = [n for n in measured[i+1:] if (n.get("endpoint") or {}).get("tag") != tag]
                pinned_second = None
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
            self._record_history("auto-pin-skipped", "no exit ip")
            return
        with self._config_lock:
            if not self._apply_config(final="auto", preferred=pinned, backup=pinned_second):
                self._record_history("auto-pin-failed", pinned)
                return
            with self._lock:
                if self.preferred_tag is not None:
                    self._record_history("auto-pin-skipped", "pin won the race")
                    self._apply_config(final="auto", preferred=self.preferred_tag, backup=self.backup_tag)
                    return
                self.preferred_tag = pinned; self.backup_tag = pinned_second; self._auto_pinned = True
                self.status["preferred_tag"] = pinned; self.status["backup_tag"] = pinned_second; self.status["auto_pinned"] = True
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
    def _run_single_probe(self, node: dict) -> None:
        time.sleep(0.2)
        tag = node.get("endpoint", {}).get("tag")
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
        try:
            result = self.verify_fn(endpoint)
            exit_ip, ms = result if result else (None, None)
            error = None if exit_ip else "no exit ip measured"
        except Exception as exc:
            exit_ip, ms = None, None
            error = f"{type(exc).__name__}: {exc}"
        if exit_ip and self.want_singbox and not self._serving_ok():
            error = "serving down, throwaway ok"; exit_ip, ms = None, None
        checked_at = _now_iso()
        with self._lock:
            if gen != self._verify_generation:
                self._record_history("verify-discarded", f"{tag} superseded")
                return
            self.status["verify"] = {"state": "done", "exit_ip": exit_ip, "ms": ms, "via_tag": tag, "error": error, "generation": gen, "checked_at": checked_at}
        self._record_history("verify-done", f"{tag} exit={exit_ip} ms={ms}")
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
            print(f"resi balancer bind failed on :{self.resi_port}: {exc}", flush=True)
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
        if payload:
            self._resi_mark_ok(tag)
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
                    self._resi_mark_fail(tag)
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
            print(f"resi template error: {exc}", flush=True)
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
            try:
                result = measure_resi_rotate(self.vless_uuid, self.resi_port, self.resi_path,
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
                sampled = measure_resi_rotate(self.vless_uuid, self.resi_port, self.resi_path,
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
                    print(f"config apply failed: {type(exc).__name__}: {exc}", flush=True)
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
                print(f"sing-box start failed: {exc}", flush=True)
                new_proc = None
                if new_handle is not None:
                    try:
                        new_handle.close()
                    except OSError:
                        pass
                    new_handle = None
            self._singbox_proc = new_proc; self._stderr_handle = new_handle
        _reap_process(old_proc, old_handle)
    def _terminate_singbox(self) -> None:
        with self._lock:
            proc, self._singbox_proc = self._singbox_proc, None
            handle, self._stderr_handle = self._stderr_handle, None
        _reap_process(proc, handle)
    def _start_cloudflared(self) -> bool:
        with self._lock:
            if not self.tunnel_token:
                self.status["tunnel"] = {"state": "no-token"}
                print("cloudflared skipped: TUNNEL_TOKEN not set", flush=True)
                return False
            binary = shutil.which(self.cloudflared_bin)
            if binary is None:
                self.status["tunnel"] = {"state": "no-binary", "binary": self.cloudflared_bin}
                print(f"cloudflared skipped: binary {self.cloudflared_bin!r} not found", flush=True)
                return False
            try:
                new_proc = subprocess.Popen([binary, "tunnel", "--no-autoupdate", "run", "--token", self.tunnel_token], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as exc:
                self.status["tunnel"] = {"state": "dead", "error": str(exc)}
                return False
            old_proc, self._cloudflared_proc = self._cloudflared_proc, new_proc
            self.status["tunnel"] = {"state": "running", "since": _now_iso()}
            print("cloudflared tunnel started", flush=True)
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
        print(f"generated ADMIN_TOKEN={cfg['admin_token']} (save it to use /ui and /api)", flush=True)
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
        state_path=os.path.join(data_dir, "state.json"), settings_path=os.path.join(data_dir, "settings.json"))
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
