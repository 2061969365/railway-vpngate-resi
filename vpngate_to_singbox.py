"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import builtins
import base64
import csv
import io
import json
import re
import socket
import ssl
import subprocess
import tempfile
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_USERNAME = "vpn"
DEFAULT_PASSWORD = "vpn"
# VPNGate uses legacy crypto; sing-box >= 1.14 defaults to AEAD only,
# so the old ciphers must be listed explicitly.
DEFAULT_DATA_CIPHERS = ["AES-128-CBC", "AES-256-CBC", "BF-CBC"]
DEFAULT_AUTH = "SHA1"
# Rotating residential SOCKS5 (backconnect gateway) defaults. The gateway is
# the only address we ever dial: rotating/sticky is a property of the
# username the gateway sees, never of a real home IP we could reach.
DEFAULT_RESI_PORT = 8084
DEFAULT_RESI_PATH = "/ws-resi"
RESI_IN_PORT = 40001
# Rotating third path: one loopback VLESS+WS inbound per serving endpoint,
# so the manager can pick the next node for every new connection.
RESI_ROTATE_BASE = 41000
RESI_TEMPLATE_PLACEHOLDERS = ("user", "session", "ttl")
# Cap concurrent throwaway sing-box dials: refresh (dial_workers) +
# full_probe + single_probe + verify can otherwise stack ~13 processes
# on a 1GB box. Excess dialers queue on the gate instead of OOMing.
MAX_CONCURRENT_DIALS = 10
_DIAL_GATE = threading.BoundedSemaphore(MAX_CONCURRENT_DIALS)

_BLOCK_RE = re.compile(r"<(ca|cert|key|tls-auth|tls-crypt)>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
_REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)\s+(\d+)(?:\s+(\S+))?\s*$", re.IGNORECASE | re.MULTILINE)
_PROTO_RE = re.compile(r"^\s*proto\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_AUTH_RE = re.compile(r"^\s*auth\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_CIPHER_RE = re.compile(r"^\s*cipher\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_REMOTE_RANDOM_RE = re.compile(r"^\s*remote-random\s*$", re.IGNORECASE | re.MULTILINE)
_KEY_DIRECTION_RE = re.compile(r"^\s*key-direction\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_KEEPALIVE_RE = re.compile(r"^\s*keepalive\s+(\d+)\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_PING_RE = re.compile(r"^\s*ping\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_PING_RESTART_RE = re.compile(r"^\s*ping-restart\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_RENEG_SEC_RE = re.compile(r"^\s*reneg-sec\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def _keepalive_fields(config_text: str) -> dict:
    """Map OpenVPN keepalive directives to sing-box openvpn-client fields.

    keepalive <interval> <timeout> == ping <interval> + ping-restart
    <timeout>. Values are clamped to sane ranges; unparsable values are
    ignored. Defaults (10s/60s, the common keepalive 10 60) keep idle NAT
    mappings alive when the profile sets nothing: without them an idle
    tunnel is reaped after ~10min while TCP 443 still answers, which looks
    exactly like "verified IP but cannot connect".
    """
    fields: dict = {}
    try:
        ka = _KEEPALIVE_RE.search(config_text)
        if ka:
            iv, to = int(ka.group(1)), int(ka.group(2))
            if 1 <= iv <= 3600:
                fields["ping_interval"] = f"{iv}s"
            if 1 <= to <= 86400:
                fields["ping_restart"] = f"{to}s"
        else:
            pm = _PING_RE.search(config_text)
            if pm and 1 <= int(pm.group(1)) <= 3600:
                fields["ping_interval"] = f"{int(pm.group(1))}s"
            prm = _PING_RESTART_RE.search(config_text)
            if prm and 1 <= int(prm.group(1)) <= 86400:
                fields["ping_restart"] = f"{int(prm.group(1))}s"
        rs = _RENEG_SEC_RE.search(config_text)
        if rs:
            v = int(rs.group(1))
            if v == 0:
                fields["renegotiate_disabled"] = True
            elif 1 <= v <= 30 * 86400:
                fields["renegotiate_interval"] = f"{v}s"
    except (ValueError, AttributeError):
        pass
    if "ping_interval" not in fields:
        fields["ping_interval"] = "10s"
    if "ping_restart" not in fields:
        fields["ping_restart"] = "60s"
    return fields


def _is_tcp_proto(proto: str) -> bool:
    return proto.lower().startswith("tcp")


def _all_tcp_remotes(config_text: str) -> list[tuple[str, int]]:
    """Return every TCP remote in order (explicit proto first, then global)."""
    global_protos = [m.group(1) for m in _PROTO_RE.finditer(config_text)]
    global_tcp = any(_is_tcp_proto(p) for p in global_protos)
    remotes = [(m.group(1), int(m.group(2)), (m.group(3) or "")) for m in _REMOTE_RE.finditer(config_text)]
    if not remotes:
        raise ValueError("no remote directive found")
    explicit = [(host, port) for host, port, proto in remotes
                if proto and _is_tcp_proto(proto)]
    if explicit:
        return explicit
    if global_tcp:
        fallback = [(host, port) for host, port, proto in remotes
                    if not proto or not proto.lower().startswith("udp")]
        if fallback:
            return fallback
    raise ValueError("no TCP remote found (only UDP available)")


def _pick_tcp_remote(config_text: str) -> tuple[str, int]:
    return _all_tcp_remotes(config_text)[0]


def primary_server(endpoint: dict) -> tuple[str, int]:
    """First reachable address of an endpoint (singular or servers[0])."""
    if "server" in endpoint:
        return endpoint["server"], endpoint["server_port"]
    first = endpoint["servers"][0]
    return first["server"], first["server_port"]


def endpoint_remotes(endpoint: dict) -> list[tuple[str, int]]:
    """Every (server, port) sing-box will try, in failover order.

    VPNGate ovpn configs frequently list several TCP remotes for the same node
    (a literal IP, another port, a DDNS name), which become ``servers[]``. The
    first address being unreachable therefore says nothing about the node: a
    health probe that only looks at primary_server() drops usable nodes from
    the pool for no reason.
    """
    out: list[tuple[str, int]] = []
    host = endpoint.get("server")
    if host:
        out.append((str(host), int(endpoint.get("server_port") or 0)))
    for item in endpoint.get("servers") or []:
        if isinstance(item, dict) and item.get("server"):
            out.append((str(item["server"]), int(item.get("server_port") or 0)))
    return out


def probe_endpoint_latency(endpoint: dict, timeout: int = 5, probe_fn=None) -> int:
    """Handshake latency of the first working remote, 0 when every one is dead."""
    probe = probe_fn or (lambda host, port: probe_tcp_latency(host, port, timeout))
    for host, port in endpoint_remotes(endpoint):
        try:
            ms = probe(host, port)
        except Exception:
            ms = 0
        if ms and ms > 0:
            return int(ms)
    return 0


def render_resi_username(user: str, template: str | None, ttl: int,
                         session_id: str = "") -> str:
    """Render the gateway username for rotation or sticky mode.

    Rotation (ttl <= 0) returns the plain user and never appends a session
    parameter: the gateway then picks a fresh exit per TCP connection. Sticky
    mode only renders when the template really carries {session}; otherwise we
    stay in rotation instead of guessing a provider-specific format (a wrong
    guess silently degrades to "no rotation and no stickiness either").

    Placeholders are limited to {user} / {session} / {ttl}. Unknown ones raise
    ValueError without echoing the rendered string, since it may contain the
    account (and in some vendors' schemes the password-equivalent) material.
    """
    if ttl <= 0:
        return user
    text = (template or "").strip()
    if "{session}" not in text:
        return user
    try:
        return text.format(user=user, session=session_id, ttl=ttl)
    except (KeyError, IndexError, ValueError) as exc:
        name = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        raise ValueError(
            f"RESI_USER_TEMPLATE uses an unsupported placeholder {{{name}}}; "
            f"allowed: {', '.join('{' + p + '}' for p in RESI_TEMPLATE_PLACEHOLDERS)}"
        ) from None


def ovpn_to_endpoint(
    config_text: str,
    tag: str,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> dict:
    """Convert one OpenVPN client config (TCP) to a sing-box openvpn-client endpoint."""
    if not config_text or not config_text.strip():
        raise ValueError("empty openvpn config")
    tcp_remotes = _all_tcp_remotes(config_text)

    blocks: dict[str, str] = {}
    for m in _BLOCK_RE.finditer(config_text):
        blocks[m.group(1).lower()] = m.group(2).strip()
    if "ca" not in blocks or not blocks["ca"]:
        raise ValueError("missing <ca> block")

    auth_m = _AUTH_RE.search(config_text)
    auth = auth_m.group(1).upper() if auth_m else DEFAULT_AUTH
    cipher_m = _CIPHER_RE.search(config_text)
    data_ciphers = list(DEFAULT_DATA_CIPHERS)
    if cipher_m:
        cipher = cipher_m.group(1)
        data_ciphers = [cipher] + [c for c in data_ciphers if c.lower() != cipher.lower()]

    if blocks.get("cert") and not blocks.get("key"):
        raise ValueError("client <cert> without <key> (must be both or neither)")
    if blocks.get("key") and not blocks.get("cert"):
        raise ValueError("client <key> without <cert> (must be both or neither)")
    tls: dict = {
        "certificate": blocks["ca"],
        "certificate_profile": "legacy",
    }
    if blocks.get("cert"):
        tls["client_certificate"] = blocks["cert"]
    if blocks.get("key"):
        tls["client_key"] = blocks["key"]
    # sing-box control_wrap replaces OpenVPN tls-auth/tls-crypt inline keys.
    # Dropping them silently breaks the handshake, so map them explicitly.
    # direction is a "server"/"client" STRING (OpenVPN key-direction 0/1)
    # and only exists for tls_auth; tls_crypt never carries one.
    if blocks.get("tls-crypt"):
        control_wrap: dict = {"type": "tls_crypt", "key": blocks["tls-crypt"]}
    elif blocks.get("tls-auth"):
        control_wrap = {"type": "tls_auth", "key": blocks["tls-auth"]}
        direction_m = _KEY_DIRECTION_RE.search(config_text)
        if direction_m:
            direction = {"0": "server", "1": "client"}.get(
                direction_m.group(1))
            if direction is not None:
                control_wrap["direction"] = direction
    else:
        control_wrap = {}
    if control_wrap:
        tls["control_wrap"] = control_wrap

    return {
        "type": "openvpn-client",
        "tag": tag,
        **_server_fields(tcp_remotes),
        "network": "tcp",
        "username": username,
        "password": password,
        "tls": tls,
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": data_ciphers[0],
        "auth": auth,
        # VPNGate hands out ONE OpenVPN session per node (duplicate-cn is
        # off), so a second login for the same node - the manager's own
        # refresh probe, for instance - gets the serving session rejected
        # ("authentication failed: terminal"). With the default
        # "auth-retry: none" that rejection is final and the serving
        # endpoint stays dead ("endpoint is not ready yet"), which is how a
        # healthy node turns into a corpse the chain has to walk past.
        # "nointeract" retries the authentication instead, so the endpoint
        # recovers as soon as the other session is gone.
        "auth_retry": "nointeract",
        # The keepalive comes from the .ovpn itself (see _keepalive_fields,
        # which falls back to 10s/60s). It is deliberately NOT overridden
        # here: the server-pushed values win, and they are the ones the
        # server actually honours.
        **_keepalive_fields(config_text),
        **({"remote_random": True} if _REMOTE_RANDOM_RE.search(config_text) else {}),
        "system": False,
        "redirect_gateway": True,
    }


def _server_fields(tcp_remotes: list[tuple[str, int]]) -> dict:
    """Singular server/server_port for one remote, servers[] otherwise.

    sing-box requires exactly one of server / servers (they conflict),
    so multi-remote configs move to servers[] for in-order failover.
    """
    if len(tcp_remotes) == 1:
        host, port = tcp_remotes[0]
        return {"server": host, "server_port": port}
    return {"servers": [
        {"server": host, "server_port": port, "network": "tcp"}
        for host, port in tcp_remotes
    ]}


def probe_tcp_latency(host: str, port: int, timeout: int = 5) -> int:
    """Measure TCP handshake latency in ms; return 0 when unreachable.

    This is a real-connection pre-filter: VPNGate advertises Speed values
    that say nothing about whether the node accepts connections right now.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = None
    start = time.monotonic()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return max(1, int((time.monotonic() - start) * 1000))
    except OSError:
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("eof")
        data += chunk
    return data


def _socks5_get_latency_ms(proxy_host: str, proxy_port: int,
                           target_host: str = "www.gstatic.com",
                           target_port: int = 443,
                           path: str = "/generate_204",
                           timeout: float = 20,
                           cafile: str | None = None) -> int | None:
    """One HTTPS GET through a SOCKS5 proxy; ms on HTTP 204, else None.

    The GET goes through a real TLS handshake (SNI=target_host), so the
    measured latency matches what curl reports (TCP+TLS+HTTP).
    """
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return None
        try:
            addr = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
        except OSError:
            encoded = target_host.encode("idna")
            if len(encoded) > 255:
                return None
            request = (b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                       + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return None
        try:
            context = (ssl.create_default_context(cafile=cafile) if cafile
                       else ssl.create_default_context())
            sock = context.wrap_socket(sock, server_hostname=target_host)
        except OSError:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            head += chunk
            if len(head) > 8192:
                return None
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        if code != 204:
            return None
        return max(1, int((time.monotonic() - start) * 1000))
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _socks5_get_text(proxy_host: str, proxy_port: int,
                     target_host: str = "api.ipify.org",
                     target_port: int = 443,
                     path: str = "/?format=text",
                     timeout: float = 20) -> tuple | None:
    """One HTTPS GET through a SOCKS5 proxy; (code, body, ms) or None.

    Same handshake as _socks5_get_latency_ms, but returns the response
    body so callers can read small text APIs (e.g. api.ipify.org).
    """
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return None
        try:
            addr = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
        except OSError:
            encoded = target_host.encode("idna")
            if len(encoded) > 255:
                return None
            request = (b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                       + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return None
        try:
            sock = ssl.create_default_context().wrap_socket(
                sock, server_hostname=target_host)
        except OSError:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        raw = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                return None
        ms = max(1, int((time.monotonic() - start) * 1000))
        head, _, body = raw.partition(b"\r\n\r\n")
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        return (code, body.strip(), ms)
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _looks_like_ipv4(text: bytes) -> bool:
    try:
        socket.inet_aton(text.decode("ascii").strip())
    except (OSError, ValueError, UnicodeError):
        return False
    return text.count(b".") == 3


# Exit-IP echo services, tried in order. One hardcoded service is one more
# thing that can be unreachable from a given VPNGate node: the same node can
# serve gstatic fine and still hang on api.ipify.org (measured locally: the
# direct path reached gstatic/cloudflare/icanhazip while ipify timed out).
# Treating that as "no exit ip" dropped usable nodes from the rotation pool
# and left the chain pinned to a node nobody could verify.
EXIT_IP_TARGETS = (
    ("api.ipify.org", 443, "/?format=text"),
    ("icanhazip.com", 443, "/"),
    ("ifconfig.me", 443, "/ip"),
    ("ipinfo.io", 443, "/ip"),
    ("cloudflare.com", 443, "/cdn-cgi/trace"),
)


def _parse_exit_ip(body: bytes) -> str | None:
    """Pull an IPv4 out of a plain ("1.2.3.4") or keyed ("ip=1.2.3.4") body."""
    if _looks_like_ipv4(body):
        return body.decode("ascii").strip()
    for line in body.decode("ascii", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("ip="):
            candidate = line[3:].strip()
            try:
                socket.inet_aton(candidate)
            except OSError:
                return None
            return candidate
    return None


def _fetch_exit_ip(proxy_host: str, proxy_port: int, timeout: float = 20) -> tuple | None:
    """One exit IP through the SOCKS5 proxy; (200, ip, ms) or None.

    Same shape as _socks5_get_text so call sites only swap the function.
    The whole fallback chain shares one `timeout` budget: a hanging first
    service must not eat the caller's deadline five times over.
    """
    deadline = time.monotonic() + max(2.0, float(timeout))
    for host, port, path in EXIT_IP_TARGETS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        fetched = _socks5_get_text(proxy_host, proxy_port, host, port, path,
                                   timeout=min(remaining, 6.0))
        if fetched is None or fetched[0] != 200:
            continue
        ip = _parse_exit_ip(fetched[1])
        if ip:
            return (fetched[0], ip.encode("ascii"), fetched[2])
    return None


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _safe_print(text: str, flush: bool = True) -> None:
    """print() that cannot take the process down during shutdown.

    A daemon thread that logs while the interpreter is finalizing hits
    CPython 3.13's fatal `_enter_buffered_busy` (the stdout lock is already
    gone) and kills the whole process with SIGABRT. The manager's background
    threads (refresh, full probe, health monitor) and this module's dial /
    verify probes may well outlive the main thread, so every log line goes
    through here.
    """
    if sys.is_finalizing():
        return
    try:
        builtins.print(text, flush=flush)
    except Exception:
        pass


def _log_dial_failure(endpoint: dict, err_path: str) -> None:
    """Print the sing-box stderr tail so CI logs show why a dial failed."""
    try:
        with open(err_path, "rb") as handle:
            tail = handle.read()[-2048:].decode("utf-8", errors="replace").strip()
    except OSError:
        tail = ""
    detail = f"\nsing-box log tail:\n{tail}" if tail else " (no sing-box log captured)"
    _safe_print(f"dial failed for {endpoint.get('server')}:{endpoint.get('server_port')}{detail}",
          flush=True)


def _dial_probe_config(endpoint: dict, port: int) -> dict:
    """Throwaway single-endpoint config with the route pinned to the probe tag.

    The serving config defaults route.final to the "auto" urltest group
    (VPN-only) -- right for serving, wrong for measuring: urltest would route
    around the endpoint under test. Probing must exit only
    through the endpoint, like the proven manual dial path.

    The probe keeps `auth_retry: none` even though the serving endpoints use
    "nointeract": a probe that cannot get the node's single VPNGate session
    (the serving endpoint holds it) must fail fast, so the caller can skip
    that node. With "nointeract" the probe would retry the login until its
    own timeout, which is both slower and exactly backwards.
    """
    probe_endpoint = dict(endpoint)
    probe_endpoint["tag"] = "dial-probe"
    probe_endpoint["auth_retry"] = "none"
    # A probe only measures: it must not wait for a keepalive ping or for a
    # reconnect - "this node is taken" has to be a quick answer. The keys are
    # REMOVED, not set to an empty string: sing-box rejects an empty
    # duration ("time: invalid duration") and the probe client would not
    # start at all.
    probe_endpoint.pop("ping_interval", None)
    probe_endpoint.pop("ping_restart", None)
    probe_endpoint["ping_restart_disabled"] = True
    config = build_singbox_config([probe_endpoint], mixed_listen="127.0.0.1",
                                  mixed_port=port)
    config["route"]["final"] = "dial-probe"
    return config


def measure_real_latency(endpoint: dict, singbox_bin: str = "sing-box",
                         timeout: int = 20, poll_interval: int = 2,
                         target_host: str = "www.gstatic.com",
                         target_port: int = 443,
                         path: str = "/generate_204") -> int | None:
    """Dial one endpoint with a throwaway sing-box; end-to-end GET ms or None."""
    port = _free_port()
    config = _dial_probe_config(endpoint, port)
    tmpdir = tempfile.TemporaryDirectory()
    _DIAL_GATE.acquire()
    try:
        cfg_path = str(Path(tmpdir.name) / "dial.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "dial-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _safe_print(f"dial failed for {endpoint.get('server')}:{endpoint.get('server_port')}: "
                  f"cannot start {singbox_bin}", flush=True)
            return None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                first = _socks5_get_latency_ms(
                    "127.0.0.1", port, target_host, target_port, path,
                    timeout=min(10, max(1, remaining)))
                if first is not None:
                    # The readiness probe already completed a full HTTPS GET
                    # through the tunnel; return it directly. A second timed
                    # GET would only re-race a shrinking deadline (e.g. a 2s
                    # budget when readiness arrives at 118s of 120s).
                    return first
                if proc.poll() is not None:
                    break  # sing-box died; the tunnel will never come up
                time.sleep(poll_interval)
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure(endpoint, err_path)
            return None
        finally:
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
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
    finally:
        _DIAL_GATE.release()
        tmpdir.cleanup()


def measure_exit_ip(endpoint: dict, singbox_bin: str = "sing-box",
                    timeout: int = 20, poll_interval: int = 2) -> tuple:
    """Exit IP through one endpoint: (ip, ms) or (None, None).

    Same throwaway sing-box dial as measure_real_latency, but fetches
    api.ipify.org so the caller learns the actual exit IP, not just
    the end-to-end latency.
    """
    port = _free_port()
    config = _dial_probe_config(endpoint, port)
    tmpdir = tempfile.TemporaryDirectory()
    _DIAL_GATE.acquire()
    try:
        cfg_path = str(Path(tmpdir.name) / "dial.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "dial-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _safe_print(f"verify failed for {endpoint.get('server')}:{endpoint.get('server_port')}: "
                  f"cannot start {singbox_bin}", flush=True)
            return (None, None)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                fetched = _fetch_exit_ip("127.0.0.1", port,
                                         timeout=min(10, max(1, remaining)))
                if (fetched is not None and fetched[0] == 200
                        and _looks_like_ipv4(fetched[1])):
                    return (fetched[1].decode("ascii").strip(), fetched[2])
                if proc.poll() is not None:
                    break  # sing-box died; the tunnel will never come up
                time.sleep(poll_interval)
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure(endpoint, err_path)
            return (None, None)
        finally:
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
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
    finally:
        _DIAL_GATE.release()
        tmpdir.cleanup()


def _resi_probe_config(resi: dict, port: int) -> dict:
    """Throwaway config whose only exit is the residential socks outbound.

    The gateway address comes from RESI_GATEWAY and is the only address we
    ever dial; "which home IP" is decided by the gateway per TCP connection.
    """
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "resi-probe-in",
                      "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [
            {"type": "socks", "tag": "resi-probe",
             "server": resi["server"], "server_port": int(resi["server_port"]),
             "version": "5", "username": resi["username"],
             "password": resi["password"], "network": "tcp"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "resi-probe"},
    }


def _resi_probe_run(resi: dict, count: int, singbox_bin: str, timeout: int,
                    poll_interval: int, gate_timeout: float) -> dict | None:
    """Start one throwaway sing-box and collect up to `count` exit IPs.

    Every sample opens a fresh SOCKS5 connection through the local mixed
    inbound -- exactly the unit a backconnect gateway rotates on. Reusing a
    connection would measure our own pooling instead, and one process for N
    samples keeps a 1 GB box from spawning N binaries.
    """
    count = max(1, int(count))
    port = _free_port()
    config = _resi_probe_config(resi, port)
    tmpdir = tempfile.TemporaryDirectory()
    if not _DIAL_GATE.acquire(timeout=gate_timeout):
        tmpdir.cleanup()
        return None
    proc = None
    err_handle = None
    try:
        cfg_path = str(Path(tmpdir.name) / "resi-probe.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "resi-probe-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            _safe_print(f"resi probe failed: cannot start {singbox_bin}", flush=True)
            return None
        deadline = time.monotonic() + timeout
        ips: list[str] = []
        stamps: list[int] = []
        errors: list[str] = []
        while time.monotonic() < deadline and not ips:
            remaining = deadline - time.monotonic()
            fetched = _fetch_exit_ip("127.0.0.1", port,
                                     timeout=min(10, max(1, remaining)))
            if (fetched is not None and fetched[0] == 200
                    and _looks_like_ipv4(fetched[1])):
                ips.append(fetched[1].decode("ascii").strip())
                stamps.append(fetched[2])
                break
            if proc.poll() is not None:
                errors.append("probe sing-box exited")
                break
            time.sleep(poll_interval)
        total_deadline = deadline + (count - 1) * 15
        while ips and len(ips) < count and time.monotonic() < total_deadline:
            fetched = _fetch_exit_ip("127.0.0.1", port, timeout=15)
            if (fetched is not None and fetched[0] == 200
                    and _looks_like_ipv4(fetched[1])):
                ips.append(fetched[1].decode("ascii").strip())
                stamps.append(fetched[2])
                continue
            errors.append("no exit ip")
            break
        if not ips:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure(resi, err_path)
            return None
        return {"ips": ips, "ms": list(stamps), "count": len(ips),
                "distinct": len(set(ips)), "errors": errors,
                "first_ms": stamps[0], "last_ms": stamps[-1]}
    finally:
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
        if err_handle is not None:
            try:
                err_handle.close()
            except OSError:
                pass
        _DIAL_GATE.release()
        tmpdir.cleanup()


def measure_resi_exit_ip(resi: dict, singbox_bin: str = "sing-box",
                         timeout: int = 20, poll_interval: int = 2) -> tuple:
    """Exit IP through the residential gateway: (ip, ms) or (None, None)."""
    result = _resi_probe_run(resi, 1, singbox_bin, timeout, poll_interval, 30.0)
    if not result:
        return (None, None)
    return (result["ips"][0], result["first_ms"])


def measure_resi_rotation(resi: dict, count: int = 3, singbox_bin: str = "sing-box",
                          timeout: int = 20, poll_interval: int = 2) -> dict | None:
    """Collect `count` sequential exit IPs through the gateway.

    Returns {"ips", "ms", "count", "distinct", "errors", ...} or None when the
    gateway never answered. `distinct` is the number of different IPs seen;
    rotation is healthy when it is >= 2 (a residential pool may legitimately
    hand out the same node twice in a row).
    """
    return _resi_probe_run(resi, count, singbox_bin, timeout, poll_interval, 30.0)


def _resi_rotate_probe_config(vless_uuid: str, port: int, path: str,
                              listen_port: int) -> dict:
    """Throwaway client that speaks VLESS+WS to our own third-path listener.

    Probing through the real listener (instead of an outbound) is what makes
    the measurement meaningful: each SOCKS5 CONNECT opens one new TCP
    connection, and every new connection must pick the next node.
    """
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "resi-rot-probe-in",
                      "listen": "127.0.0.1", "listen_port": listen_port}],
        "outbounds": [
            {"type": "vless", "tag": "resi-rot-probe",
             "server": "127.0.0.1", "server_port": int(port),
             "uuid": vless_uuid,
             "transport": {"type": "ws", "path": path}},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "resi-rot-probe"},
    }


def _collect_rotate_samples(fetch, count: int, deadline: float
                            ) -> tuple[list[str], list[int], list[str]]:
    """Collect up to `count` exit IPs, tolerating dead nodes in the pool.

    Every fetch opens a new connection, so rotation means a dead node is
    simply skipped: the next connection lands on the next node. Aborting the
    whole measurement on one failure would report "not rotating" for a
    perfectly healthy rotating pool (the pool is a VPNGate snapshot, it
    always contains some dead nodes), so walk on instead.
    """
    ips: list[str] = []
    stamps: list[int] = []
    errors: list[str] = []
    attempts = 0
    max_attempts = max(count, 1) * 4
    while len(ips) < count and attempts < max_attempts and time.monotonic() < deadline:
        attempts += 1
        fetched = fetch()
        if (fetched is not None and fetched[0] == 200
                and _looks_like_ipv4(fetched[1])):
            ips.append(fetched[1].decode("ascii").strip())
            stamps.append(fetched[2])
            continue
        errors.append("no exit ip")
    return ips, stamps, errors


def measure_resi_rotate(vless_uuid: str, port: int, path: str, count: int = 3,
                        singbox_bin: str = "sing-box", timeout: int = 20,
                        poll_interval: int = 2) -> dict | None:
    """Sample `count` exit IPs through the rotating third path.

    Returns {"ips", "ms", "count", "distinct", "errors", ...} or None when the
    listener never answered. A residential-side rotation can legitimately hand
    out the same node twice, so health is judged by the caller (distinct >= 2).
    """
    count = max(1, int(count))
    listen_port = _free_port()
    config = _resi_rotate_probe_config(vless_uuid, port, path, listen_port)
    tmpdir = tempfile.TemporaryDirectory()
    if not _DIAL_GATE.acquire(timeout=30.0):
        tmpdir.cleanup()
        return None
    proc = None
    err_handle = None
    try:
        cfg_path = str(Path(tmpdir.name) / "resi-rot-probe.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "resi-rot-probe-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            _safe_print(f"resi rotate probe failed: cannot start {singbox_bin}", flush=True)
            return None
        deadline = time.monotonic() + timeout
        ips: list[str] = []
        stamps: list[int] = []
        errors: list[str] = []
        while time.monotonic() < deadline and not ips:
            remaining = deadline - time.monotonic()
            fetched = _fetch_exit_ip("127.0.0.1", listen_port,
                                     timeout=min(10, max(1, remaining)))
            if (fetched is not None and fetched[0] == 200
                    and _looks_like_ipv4(fetched[1])):
                ips.append(fetched[1].decode("ascii").strip())
                stamps.append(fetched[2])
                break
            if proc.poll() is not None:
                errors.append("probe sing-box exited")
                break
            time.sleep(poll_interval)
        # Give the remaining samples a budget of one dial each: failures are
        # expected (dead nodes in the pool) and are walked past, not fatal.
        total_deadline = deadline + count * 15
        def _fetch():
            remaining = total_deadline - time.monotonic()
            return _fetch_exit_ip("127.0.0.1", listen_port,
                                  timeout=int(min(15, max(1, remaining))))
        more_ips, more_stamps, more_errors = _collect_rotate_samples(
            _fetch, count - 1, total_deadline)
        ips += more_ips
        stamps += more_stamps
        errors += more_errors
        if not ips:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure({"server": "127.0.0.1", "server_port": int(port)},
                              err_path)
            return None
        return {"ips": ips, "ms": list(stamps), "count": len(ips),
                "distinct": len(set(ips)), "errors": errors,
                "first_ms": stamps[0], "last_ms": stamps[-1]}
    finally:
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
        if err_handle is not None:
            try:
                err_handle.close()
            except OSError:
                pass
        _DIAL_GATE.release()
        tmpdir.cleanup()

def _safe_dial(dial_fn, node: dict) -> int | None:
    try:
        result = dial_fn(node)
    except Exception:
        return None
    return result if isinstance(result, int) and result > 0 else None


def _iter_tcp_candidates(csv_text, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD):
    """Yield (speed, country, country_short, untagged-endpoint) for TCP rows."""
    lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        raise ValueError("empty snapshot")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "OpenVPN_ConfigData_Base64" not in reader.fieldnames:
        raise ValueError("snapshot columns are incomplete")

    found = False
    for row in reader:
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not encoded:
            continue
        try:
            config_text = base64.b64decode(encoded, validate=True).decode("utf-8")
            endpoint = ovpn_to_endpoint(config_text, tag="", username=username, password=password)
        except (ValueError, UnicodeError):
            continue  # UDP-only / broken / unsafe rows are skipped
        try:
            speed = int((row.get("Speed") or "0").strip() or "0")
        except ValueError:
            speed = 0
        found = True
        yield (speed, (row.get("CountryLong") or "").strip(),
               (row.get("CountryShort") or "").strip().upper(), endpoint)
    if not found:
        raise ValueError("snapshot contains no TCP-convertible nodes")


def snapshot_to_nodes(
    csv_text: str,
    limit: int | None = 0,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 20,
    probe_pool: int = 30,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 3,
    dial_timeout: int = 20,
    singbox_bin: str = "sing-box",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    skip_dial_keys: set[tuple[str, int]] | None = None,
) -> list[dict]:
    """Parse a snapshot into node dicts with country + measured latency.

    Nodes are real-connection filtered (TCP handshake must succeed) and
    sorted by measured latency. With probe=False falls back to Speed ranking
    with latency_ms=None. limit=0/None means all nodes.

    With real_topk>0 the top-K handshake winners are additionally dialed
    through a real tunnel and re-ranked: measured nodes first by real
    end-to-end latency, the rest by handshake latency. Dial failures are
    refilled from the next handshake-ranked nodes until real_topk measured
    or the pool is exhausted; persistent failures stay unmeasured (None)
    and sort last. Returns [] when nothing is reachable (caller decides
    failure).

    ``skip_dial_keys`` lists ``(server, server_port)`` pairs the caller already
    has a live session on: dialing them would open a second VPNGate session
    (duplicate-cn is off) and kick the first, so they are left unmeasured for
    the caller to carry over instead. Skipped nodes do not consume a slot of
    ``real_topk``; the next handshake-ranked nodes are dialed in their place.
    """
    if probe_pool is not None and probe_pool < 0:
        raise ValueError(f"probe_pool must be >= 0, got {probe_pool}")
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")
    skip_dial = skip_dial_keys or set()
    candidates = list(_iter_tcp_candidates(csv_text, username, password))
    check = probe_fn if probe_fn is not None else (
        lambda host, port: probe_tcp_latency(host, port, probe_timeout))

    def _probe_endpoint(endpoint):
        # Try every remote of the endpoint, not just the first: a node whose
        # first address is down but whose failover address works is still a
        # perfectly usable node (see endpoint_remotes).
        return probe_endpoint_latency(endpoint, probe_timeout, probe_fn=check)

    def _node(speed, country, country_short, endpoint, latency_ms):
        host, port = primary_server(endpoint)
        return {"server": host, "server_port": port,
                "country": country, "country_short": country_short,
                "speed": speed, "latency_ms": latency_ms, "real_latency_ms": None,
                "endpoint": endpoint}

    if not probe:
        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        nodes = [_node(speed, country, short, ep, None)
                 for speed, country, short, ep in ranked]
    else:
        # Speed says nothing about reachability, so probe Speed-ranked
        # chunks until one yields survivors instead of giving up after
        # the first probe_pool rows.
        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        step = probe_pool if probe_pool else len(ranked) or 1
        nodes = []
        for start in range(0, len(ranked), step):
            chunk = ranked[start:start + step]
            latencies: dict[int, int] = {}
            with ThreadPoolExecutor(max_workers=probe_workers) as executor:
                future_map = {executor.submit(_probe_endpoint, ep): index
                              for index, (_, _, _, ep) in enumerate(chunk)}
                for future in future_map:
                    try:
                        latencies[future_map[future]] = future.result()
                    except Exception:
                        latencies[future_map[future]] = 0

            alive = [(latencies[i], speed, country, short, ep)
                     for i, (speed, country, short, ep) in enumerate(chunk)
                     if (latencies.get(i) or 0) > 0]
            alive.sort(key=lambda item: item[0])
            nodes = [_node(speed, country, short, ep, latency)
                     for latency, speed, country, short, ep in alive]
            if nodes:
                break

    if real_topk and real_topk > 0 and nodes:
        dial = dial_fn if dial_fn is not None else (
            lambda node: measure_real_latency(node["endpoint"], singbox_bin, dial_timeout))
        target = min(real_topk, len(nodes))
        with ThreadPoolExecutor(max_workers=dial_workers) as executor:
            idx = 0
            measured = 0
            while measured < target and idx < len(nodes):
                batch = []
                while not batch and idx < len(nodes):
                    chunk = nodes[idx:idx + max(1, target - measured)]
                    idx += len(chunk)
                    batch = [n for n in chunk
                             if (n["server"], n["server_port"]) not in skip_dial]
                if not batch:
                    break
                future_map = {executor.submit(_safe_dial, dial, node): node
                              for node in batch}
                for future in future_map:
                    future_map[future]["real_latency_ms"] = future.result()
                measured = sum(1 for n in nodes[:idx]
                               if n.get("real_latency_ms") is not None)
        nodes.sort(key=lambda n: (0, n["real_latency_ms"])
                   if n["real_latency_ms"] is not None
                   else (1, n["latency_ms"] if n["latency_ms"] is not None else 10 ** 9))

    if limit:
        nodes = nodes[:limit]
    return nodes


def nodes_to_endpoints(nodes: list[dict], tag_prefix: str = "vpngate") -> list[dict]:
    """Assign tags and return clean sing-box endpoint dicts (no metadata keys).

    Endpoints that already carry a tag (stable refresh mapping) keep it;
    only untagged endpoints take the next free ``tag_prefix-N`` slot.
    """
    used = {str(n.get("endpoint", {}).get("tag") or "")
            for n in nodes} - {""}
    next_index = 0
    endpoints = []
    for node in nodes:
        endpoint = dict(node["endpoint"])
        if not endpoint.get("tag"):
            while f"{tag_prefix}-{next_index}" in used:
                next_index += 1
            endpoint["tag"] = f"{tag_prefix}-{next_index}"
            used.add(endpoint["tag"])
            next_index += 1
        node["endpoint"] = endpoint
        endpoints.append(endpoint)
    return endpoints


def snapshot_to_endpoints(
    csv_text: str,
    limit: int | None = 0,
    tag_prefix: str = "vpngate",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 20,
    probe_pool: int = 30,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 3,
    dial_timeout: int = 20,
    singbox_bin: str = "sing-box",
) -> list[dict]:
    """Parse a VPNGate CSV snapshot into tagged sing-box endpoints.

    Prefers nodes with a working TCP handshake, ranked by measured latency.
    With real_topk>0 the top-K are re-ranked by real tunnel latency.
    limit=0/None means all nodes.
    """
    nodes = snapshot_to_nodes(
        csv_text, limit=limit, probe=probe, probe_fn=probe_fn,
        probe_timeout=probe_timeout, probe_workers=probe_workers,
        probe_pool=probe_pool, real_topk=real_topk, dial_fn=dial_fn,
        dial_workers=dial_workers, dial_timeout=dial_timeout,
        singbox_bin=singbox_bin, username=username, password=password)
    if not nodes:
        raise ValueError("snapshot contains no reachable nodes")
    return nodes_to_endpoints(nodes, tag_prefix)


def build_singbox_config(
    endpoints: list[dict],
    mixed_listen: str | None = None,
    mixed_port: int | None = None,
    mixed_users: list[tuple[str, str]] | None = None,
    final: str = "auto",
    preferred: str | None = None,
    backup: str | None = None,
    vless_uuid: str | None = None,
    vless_direct_port: int = 8080,
    vless_direct_path: str = "/ws-node",
    vless_chain_port: int = 8082,
    vless_chain_path: str = "/ws-chain",
    resi: dict | None = None,
    resi_port: int = DEFAULT_RESI_PORT,
    resi_path: str = DEFAULT_RESI_PATH,
    resi_in_port: int = RESI_IN_PORT,
    resi_rotate: bool = False,
    resi_rotate_tags: list[str] | None = None,
    chain_candidates: list[str] | None = None,
    clash_api: dict | None = None,
) -> dict:
    """Wrap endpoints in a minimal checkable sing-box config.

    route.final defaults to the "auto" urltest group so traffic fails over
    across healthy nodes automatically; pass an endpoint tag to pin one.
    The urltest group is VPN-only (fail-closed): "direct" must NOT be in it
    because a local direct outlet always wins urltest on speed and would
    silently route all serving traffic around the VPN. "direct" stays in the
    manual "proxy" selector as an explicit user-chosen fallback.
    The urltest re-picks every 15s (tolerance 150ms) so a dead tunnel fails
    over within seconds instead of minutes.

    When vless_uuid is set, two VLESS+WS inbounds are added for Cloudflare
    Tunnel use: "vless-direct" (Railway-local exit via "direct") and
    "vless-chain" (VPNGate exit via "auto", or via the "chain" selector
    when preferred). Route rules split by inbound tag, so the
    two paths never mix. Requires the mixed inbound (the $PORT mux target).

    When preferred names one of the endpoint tags, a "chain" group becomes
    route.final instead of the bare tag. It is a *selector*, because the
    manager switches it through the Clash API (``PUT /proxies/chain``): a repin
    is then a local HTTP call - no config rewrite, no sing-box restart and no
    dropped connections - which is the only way to move the pin without
    collateral damage to the rotation. ``chain_candidates`` lists every tag the
    selector may be switched to (rotate mode passes all serving endpoints, so
    any live node is one call away); without it the group falls back to
    [preferred, backup?, "auto"]. A selector never fails over by itself, and
    that is fine: the manager probes the chain path every health tick and
    hot-switches it, so a dead pin costs one probe interval, not a dead path.

    ``clash_api`` ({"external_controller", "secret"}) adds the experimental
    Clash API section that makes those runtime switches possible; it is bound
    to loopback only.

    When resi ({"server","server_port","username","password"}) is given, a
    third path is added: a "resi" socks outbound plus a "vless-resi" WS
    inbound that routes into it. The gateway address is fixed; rotation or
    stickiness is decided entirely by the username the gateway sees. resi is
    deliberately kept OUT of the "auto" urltest group and the "proxy"
    selector: urltest probes every 15s and residential traffic is metered,
    so probing it would burn quota nonstop and a stray manual pick could
    drain a whole plan. The loopback-only "resi-in" mixed inbound exists so
    operators/CI can validate rotation through the exact serving stack.

    When resi_rotate is set the third path fans out over the serving
    endpoints instead: one loopback VLESS+WS inbound per endpoint (ports
    RESI_ROTATE_BASE + i), each routed to that endpoint. The manager listens
    on resi_port itself and picks the next loopback port for every new
    connection, so successive connections leave through different nodes.
    resi_rotate_tags narrows that set (and fixes its order) to the nodes the
    manager decided to rotate over; None means all endpoints in given order.
    """
    tags = [ep["tag"] for ep in endpoints]
    if preferred is not None and preferred not in tags:
        preferred = None
    if backup is not None and (backup not in tags or backup == preferred):
        backup = None
    route_final = "chain" if preferred else final
    config: dict = {
        "log": {"level": "info"},
        "endpoints": endpoints,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": tags,
             "interval": "15s", "tolerance": 150},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": route_final, "auto_detect_interface": True},
    }
    if preferred:
        ordered: list[str] = [preferred]
        for tag in (chain_candidates or []):
            if tag in tags and tag not in ordered:
                ordered.append(tag)
        if backup and backup in tags and backup not in ordered:
            ordered.append(backup)
        if chain_candidates is None and "auto" not in ordered:
            ordered.append("auto")
        config["outbounds"].append({
            "type": "selector", "tag": "chain", "outbounds": ordered,
            "default": preferred,
            # A runtime switch must not tear down the connections already
            # riding the chain: only new connections move to the new pin.
            "interrupt_exist_connections": False,
        })
    if mixed_listen is not None and mixed_port is not None:
        inbound: dict = {"type": "mixed", "tag": "mixed-in",
                         "listen": mixed_listen, "listen_port": mixed_port}
        if mixed_users:
            inbound["users"] = [{"username": user, "password": password}
                                for user, password in mixed_users]
        config["inbounds"] = [inbound]
    if vless_uuid is not None:
        if mixed_listen is None or mixed_port is None:
            raise ValueError("vless inbounds need the mixed inbound ($PORT mux target)")
        config.setdefault("inbounds", []).extend([
            {"type": "vless", "tag": "vless-direct",
             "listen": "0.0.0.0", "listen_port": vless_direct_port,
             "users": [{"uuid": vless_uuid}],
             "transport": {"type": "ws", "path": vless_direct_path}},
            {"type": "vless", "tag": "vless-chain",
             "listen": "0.0.0.0", "listen_port": vless_chain_port,
             "users": [{"uuid": vless_uuid}],
             "transport": {"type": "ws", "path": vless_chain_path}},
        ])
        # No loopback hop: vless-chain routes straight into the urltest group
        # (or the "chain" selector when pinned), which is exactly where the
        # old chain-socks -> mixed -> route.final path ended up. One less
        # hop, and a dead mixed inbound no longer kills both VLESS paths.
        chain_target = "chain" if preferred else "auto"
        config["route"]["rules"] = [
            {"inbound": "vless-direct", "outbound": "direct"},
            {"inbound": "vless-chain", "outbound": chain_target},
        ]
    if resi_rotate and resi is not None:
        raise ValueError("resi and resi_rotate are mutually exclusive")
    if resi is not None:
        if vless_uuid is None:
            raise ValueError("resi outbound needs the vless inbound (set VLESS_UUID)")
        config["outbounds"].append({
            "type": "socks", "tag": "resi",
            "server": resi["server"], "server_port": int(resi["server_port"]),
            "version": "5", "username": resi["username"],
            "password": resi["password"],
            # Residential gateways rarely support UDP ASSOCIATE. Forcing tcp
            # makes UDP fail fast at the outbound instead of hanging until the
            # gateway times out.
            "network": "tcp",
        })
        config.setdefault("inbounds", []).extend([
            {"type": "vless", "tag": "vless-resi",
             "listen": "0.0.0.0", "listen_port": resi_port,
             "users": [{"uuid": vless_uuid}],
             "transport": {"type": "ws", "path": resi_path}},
            {"type": "mixed", "tag": "resi-in",
             "listen": "127.0.0.1", "listen_port": resi_in_port},
        ])
        config["route"].setdefault("rules", []).extend([
            {"inbound": "vless-resi", "outbound": "resi"},
            {"inbound": "resi-in", "outbound": "resi"},
        ])
    if resi_rotate:
        if vless_uuid is None:
            raise ValueError("resi_rotate needs VLESS_UUID (its inbounds are VLESS+WS)")
        rotate_eps = endpoints
        if resi_rotate_tags is not None:
            # The manager rotates over the verified nodes only (design §2), so
            # the inbound set is chosen by tag and keeps the caller's order:
            # port RESI_ROTATE_BASE + i must map to rotate order i.
            by_tag = {ep["tag"]: ep for ep in endpoints}
            rotate_eps = [by_tag[t] for t in resi_rotate_tags if t in by_tag]
        config.setdefault("inbounds", [])
        for i, ep in enumerate(rotate_eps):
            config["inbounds"].append({
                "type": "vless", "tag": f"resi-rot-{i}",
                "listen": "127.0.0.1", "listen_port": RESI_ROTATE_BASE + i,
                "users": [{"uuid": vless_uuid}],
                "transport": {"type": "ws", "path": resi_path},
            })
            config["route"].setdefault("rules", []).append(
                {"inbound": f"resi-rot-{i}", "outbound": ep["tag"]})
    if clash_api:
        # Loopback-only REST API: it is how the manager moves the "chain"
        # selector at runtime (PUT /proxies/chain) instead of rewriting this
        # file and restarting sing-box for every repin.
        config["experimental"] = {"clash_api": dict(clash_api)}
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert VPNGate .ovpn (TCP) to sing-box config")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="input .ovpn file")
    group.add_argument("--csv", help="input VPNGate snapshot CSV file")
    parser.add_argument("--output", required=True, help="output sing-box JSON file")
    parser.add_argument("--tag", default="vpngate-0", help="endpoint tag (--input) or prefix (--csv)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max endpoints for --csv mode, 0 = all")
    parser.add_argument("--real-topk", type=int, default=0,
                        help="re-rank top-K by real tunnel latency (0 = off)")
    parser.add_argument("--no-probe", action="store_true",
                        help="skip TCP handshake probing, rank by Speed instead")
    parser.add_argument("--mixed", default=None, help="optional mixed inbound HOST:PORT for dial tests")
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    args = parser.parse_args(argv)

    mixed_listen: str | None = None
    mixed_port: int | None = None
    if args.mixed:
        mixed_listen, _, mixed_port_str = args.mixed.rpartition(":")
        mixed_port = int(mixed_port_str)

    if args.csv:
        csv_text = Path(args.csv).read_text(encoding="utf-8")
        endpoints = snapshot_to_endpoints(
            csv_text, limit=args.limit, tag_prefix=args.tag,
            username=args.username, password=args.password,
            probe=not args.no_probe, real_topk=args.real_topk,
        )
        Path(args.output).write_text(
            json.dumps(build_singbox_config(endpoints, mixed_listen, mixed_port), indent=2) + "\n",
            encoding="utf-8",
        )
        _safe_print(f"wrote {args.output} with {len(endpoints)} endpoints")
        return 0

    config_text = Path(args.input).read_text(encoding="utf-8")
    endpoint = ovpn_to_endpoint(config_text, tag=args.tag, username=args.username, password=args.password)
    Path(args.output).write_text(
        json.dumps(build_singbox_config([endpoint], mixed_listen, mixed_port), indent=2) + "\n",
        encoding="utf-8",
    )
    host, port = primary_server(endpoint)
    _safe_print(f"wrote {args.output} with 1 endpoint ({host}:{port})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
