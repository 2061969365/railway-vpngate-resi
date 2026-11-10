"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import builtins
import base64
import concurrent.futures
import csv
import io
import ipaddress
import json
import os
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


def _env_int(name: str, default: int) -> int:
    """Read a bounded integer from the environment, falling back on garbage."""
    try:
        value = int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default
    return value if 1 <= value <= 65535 else default


# Both ports are env-configurable so a deployment can move them out of the
# Linux ephemeral range (32768-60999) without editing the library.
RESI_IN_PORT = _env_int("RESI_IN_PORT", 40001)
# Rotating third path: one loopback VLESS+WS inbound per serving endpoint,
# so the manager can pick the next node for every new connection.
RESI_ROTATE_BASE = _env_int("RESI_ROTATE_BASE", 41000)
RESI_TEMPLATE_PLACEHOLDERS = ("user", "session", "ttl")
# Cap concurrent throwaway sing-box dials: refresh (dial_workers) +
# full_probe + single_probe + verify can otherwise stack ~13 processes
# on a 1GB box. Excess dialers queue on the gate instead of OOMing.
MAX_CONCURRENT_DIALS = 10
_DIAL_GATE = threading.BoundedSemaphore(MAX_CONCURRENT_DIALS)

# Hard bounds for untrusted third-party input (a VPNGate snapshot is just a
# CSV anyone can publish). Every parser below enforces these before it does
# any meaningful work.
MAX_CONFIG_BYTES = 256 * 1024
MAX_CONFIG_LINE_BYTES = 4 * 1024
MAX_BLOCK_BYTES = 128 * 1024
MAX_TCP_REMOTES = 8
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_ROWS = 5000
DEFAULT_RESOLVE_TIMEOUT = 3.0

SUPPORTED_AUTH = frozenset({"SHA1", "SHA256", "SHA512", "MD5"})
SUPPORTED_CIPHERS = frozenset(
    {cipher.upper() for cipher in DEFAULT_DATA_CIPHERS}
    | {"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
)
_BLOCK_TAGS = ("ca", "cert", "key", "tls-auth", "tls-crypt")
_PEM_BODY_RE = re.compile(r"^[A-Za-z0-9+/=_\-.\s]+$")

# Reserved outbound/tag names owned by build_singbox_config() itself; an
# endpoint must never take one or the generated config becomes ambiguous.
RESERVED_ENDPOINT_TAGS = frozenset(
    {"proxy", "auto", "direct", "chain", "mixed-in", "resi-in", "dial-probe", "resi"}
)
_RESERVED_TAG_PREFIXES = ("vless-",)

_REMOTE_RE = re.compile(r"^[ \t]*remote[ \t]+(\S+)[ \t]+(\d+)(?:[ \t]+(\S+))?[ \t]*$", re.IGNORECASE | re.MULTILINE)
_PROTO_RE = re.compile(r"^[ \t]*proto[ \t]+(\S+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_AUTH_RE = re.compile(r"^[ \t]*auth[ \t]+(\S+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_CIPHER_RE = re.compile(r"^[ \t]*cipher[ \t]+(\S+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_REMOTE_RANDOM_RE = re.compile(r"^[ \t]*remote-random[ \t]*$", re.IGNORECASE | re.MULTILINE)
_KEY_DIRECTION_RE = re.compile(r"^[ \t]*key-direction[ \t]+(\d+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_KEEPALIVE_RE = re.compile(r"^[ \t]*keepalive[ \t]+(\d+)[ \t]+(\d+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_PING_RE = re.compile(r"^[ \t]*ping[ \t]+(\d+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_PING_RESTART_RE = re.compile(r"^[ \t]*ping-restart[ \t]+(\d+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_RENEG_SEC_RE = re.compile(r"^[ \t]*reneg-sec[ \t]+(\d+)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_SNAPSHOT_LINE_BREAK_RE = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")


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
        config_text = _normalize_config_text(config_text)
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


def _allow_private_remotes() -> bool:
    return os.environ.get("ALLOW_PRIVATE_REMOTES", "").strip().lower() in {
        "1", "true", "yes", "on"
    }


# Explicit dangerous ranges. TEST-NET-1/2/3 are deliberately allowed: they
# are documentation fixtures used throughout the test-suite and cannot reach
# an internal service. Everything else is denied unless ``is_global`` says it
# is public; that turns the old blacklist into a default-deny policy.
_FORBIDDEN_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    # 6to4 and Teredo can embed a private IPv4 address; treat the whole
    # transition range as non-public to avoid reaching an internal host.
    "2002::/16",
    "2001::/32",
))

# Documentation-only fixtures. They are not globally routable, but tests use
# them to avoid touching arbitrary Internet hosts.
_FIXTURE_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
))

_SKIPPED_REMOTE_LOCK = threading.Lock()
_SKIPPED_REMOTE_COUNT = 0
_SKIPPED_REMOTE_LOG_LIMIT = 20
_OVERSIZED_CONFIG_LINE_COUNT = 0
_OVERSIZED_CONFIG_LINE_LOCK = threading.Lock()


def _log_skipped_remote(host: str, port, reason) -> None:
    """Record why a remote was rejected, with a hard log-flood cap."""
    global _SKIPPED_REMOTE_COUNT
    with _SKIPPED_REMOTE_LOCK:
        if _SKIPPED_REMOTE_COUNT >= _SKIPPED_REMOTE_LOG_LIMIT:
            return
        _SKIPPED_REMOTE_COUNT += 1
    _safe_print(f"skipping remote {host}:{port}: {reason}", flush=True)


def _record_oversized_config_line() -> None:
    """Count rejected overlong lines without growing an unbounded log."""
    global _OVERSIZED_CONFIG_LINE_COUNT
    with _OVERSIZED_CONFIG_LINE_LOCK:
        _OVERSIZED_CONFIG_LINE_COUNT += 1


def _strip_host_brackets(host: str) -> str:
    text = str(host or "").strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def _ip_is_forbidden(ip) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if any(net.version == ip.version and ip in net for net in _FORBIDDEN_NETWORKS):
        return True
    if any(net.version == ip.version and ip in net for net in _FIXTURE_NETWORKS):
        return False
    # Explicit default-deny: anything Python does not classify as globally
    # routable (CGNAT, documentation, benchmarking, reserved, ...) is rejected.
    return not ip.is_global


def _resolve_with_timeout(host: str, timeout: float = DEFAULT_RESOLVE_TIMEOUT,
                          deadline: float | None = None) -> list[str]:
    """Resolve a host with a hard timeout and an optional absolute deadline.

    ``socket.getaddrinfo`` has no timeout of its own; one slow search-domain
    lookup can otherwise hold a refresh/health worker for many seconds. The
    future is abandoned on timeout (the resolver thread may finish later, but
    the caller never blocks past its budget).
    """
    host_text = _strip_host_brackets(host)
    if not host_text:
        raise ValueError("empty remote host")
    try:
        return [str(ipaddress.ip_address(host_text))]
    except ValueError:
        pass
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = DEFAULT_RESOLVE_TIMEOUT
    budget = max(0.05, budget)
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("dns deadline exceeded")
        budget = min(budget, remaining)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vpngate-dns")
    future = executor.submit(
        socket.getaddrinfo, host_text, 0, type=socket.SOCK_STREAM)
    try:
        infos = future.result(timeout=budget)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise TimeoutError(f"dns lookup for {host_text!r} exceeded {budget:.2f}s") from None
    except OSError as exc:
        raise ValueError(f"cannot resolve remote host: {exc}") from None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    if not infos:
        raise ValueError("remote host did not resolve")
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError(f"unparsable resolved address {address!r}") from None
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("remote host did not resolve")
    return addresses


def _local_service_ports(extra_ports=None) -> set[int]:
    """Ports this process owns locally; the manager health probe uses them.

    probe_tcp_latency() is also the manager's own readiness check against
    127.0.0.1:$MIXED_PORT, so a blanket loopback ban would make every
    deployment look dead. Only known local ports are exempt. Callers that
    know their own ports (RailwayManager passes its constructor values) can
    extend the set explicitly instead of relying on environment variables.
    """
    ports = {DEFAULT_RESI_PORT, RESI_IN_PORT, 40000, 8080, 8082}
    ports.update(range(RESI_ROTATE_BASE, RESI_ROTATE_BASE + 128))
    for name in ("MIXED_PORT", "PORT"):
        try:
            ports.add(int(os.environ.get(name, "").strip()))
        except (TypeError, ValueError):
            pass
    if extra_ports is not None:
        if isinstance(extra_ports, (str, bytes, int)):
            extra_ports = [extra_ports]
        for value in extra_ports:
            try:
                ports.add(int(value))
            except (TypeError, ValueError):
                pass
    return ports


def _validate_remote(host: str, port) -> tuple[str, int]:
    """Validate one remote address and return its pinned literal IP and port.

    Remote values come from untrusted VPNGate/OVPN snapshots. Parsing accepts
    literal IPs only: resolving a snapshot-controlled hostname here would
    create an unbounded DNS cost and a second lookup at connect time (DNS
    rebinding). Operator endpoints use ``_resolve_with_timeout`` explicitly.
    ALLOW_PRIVATE_REMOTES=1 disables the address policy (tests / controlled
    local labs) but still requires a literal IP; the port range is always
    enforced.
    """
    if isinstance(port, bool):
        raise ValueError("invalid port (bool)")
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port {port!r}") from None
    if not 1 <= port_i <= 65535:
        raise ValueError(f"port {port_i} outside 1..65535")
    host_text = _strip_host_brackets(host)
    if not host_text:
        raise ValueError("empty remote host")
    try:
        ip = ipaddress.ip_address(host_text)
    except ValueError:
        raise ValueError(f"remote {host_text!r} is not a literal IP") from None
    if not _allow_private_remotes() and _ip_is_forbidden(ip):
        raise ValueError(f"forbidden remote address {ip}")
    return (str(ip), port_i)


def _normalize_config_text(config_text: str) -> str:
    """Normalize CRLF/CR before line-anchored regexes.

    The regexes deliberately use ``[ \\t]`` instead of ``\\s`` to stay linear;
    normalizing first keeps CRLF configs (common from Windows editors) working
    without reintroducing a whitespace class that can match newlines.
    """
    return config_text.replace("\r\n", "\n").replace("\r", "\n")


def _check_config_size(config_text: str) -> None:
    if not isinstance(config_text, str):
        raise ValueError("openvpn config must be text")
    if len(config_text.encode("utf-8", "replace")) > MAX_CONFIG_BYTES:
        raise ValueError(
            f"openvpn config exceeds {MAX_CONFIG_BYTES} bytes")
    for line in config_text.splitlines():
        if len(line.encode("utf-8", "replace")) > MAX_CONFIG_LINE_BYTES:
            _record_oversized_config_line()
            raise ValueError(
                f"openvpn config line exceeds {MAX_CONFIG_LINE_BYTES} bytes")


def _parse_inline_blocks(config_text: str) -> dict[str, str]:
    """Linear-time parse of <ca>/<cert>/<key>/<tls-auth>/<tls-crypt> blocks.

    The old regex was O(n^2) on a repeated unterminated <ca> tag. This walks
    lines once, raises ValueError on an unterminated block, and enforces the
    per-block byte cap while accumulating.
    """
    _check_config_size(config_text)
    blocks: dict[str, str] = {}
    current: str | None = None
    content: list[str] = []
    block_bytes = 0
    for line in config_text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if current is None:
            matched = False
            for tag in _BLOCK_TAGS:
                opener = f"<{tag}>"
                closer = f"</{tag}>"
                if lowered == opener:
                    current = tag
                    content = []
                    block_bytes = 0
                    matched = True
                    break
                if lowered.startswith(opener) and lowered.endswith(closer):
                    inner = stripped[len(opener):len(stripped) - len(closer)].strip()
                    if len(inner.encode("utf-8", "replace")) > MAX_BLOCK_BYTES:
                        raise ValueError(f"<{tag}> block exceeds {MAX_BLOCK_BYTES} bytes")
                    if inner and not _PEM_BODY_RE.fullmatch(inner):
                        raise ValueError(f"<{tag}> block contains non-PEM characters")
                    blocks[tag] = inner
                    matched = True
                    break
            if matched:
                continue
            continue
        if lowered == f"</{current}>":
            body = "\n".join(content).strip()
            if len(body.encode("utf-8", "replace")) > MAX_BLOCK_BYTES:
                raise ValueError(f"<{current}> block exceeds {MAX_BLOCK_BYTES} bytes")
            if body and not _PEM_BODY_RE.fullmatch(body):
                raise ValueError(f"<{current}> block contains non-PEM characters")
            blocks[current] = body
            current = None
            content = []
            block_bytes = 0
            continue
        content.append(line)
        block_bytes += len(line.encode("utf-8", "replace")) + 1
        if block_bytes > MAX_BLOCK_BYTES:
            raise ValueError(f"<{current}> block exceeds {MAX_BLOCK_BYTES} bytes")
    if current is not None:
        raise ValueError(f"unterminated <{current}> block")
    return blocks


def _all_tcp_remotes(config_text: str) -> list[tuple[str, int]]:
    """Every usable TCP remote in original order, deduped and bounded.

    Explicit TCP remotes and remotes inheriting a global ``proto tcp*`` are
    merged (the old code dropped the inherited ones whenever any explicit
    remote existed). Explicit UDP remotes stay excluded.
    """
    _check_config_size(config_text)
    config_text = _normalize_config_text(config_text)
    global_protos = [m.group(1) for m in _PROTO_RE.finditer(config_text)]
    global_tcp = any(_is_tcp_proto(p) for p in global_protos)
    remotes: list[tuple[str, int, str]] = []
    for match in _REMOTE_RE.finditer(config_text):
        try:
            parsed_port = int(match.group(2))
        except ValueError:
            _log_skipped_remote(match.group(1), match.group(2), "invalid port")
            continue
        remotes.append((match.group(1), parsed_port, (match.group(3) or "")))
    if not remotes:
        raise ValueError("no remote directive found")
    tcp: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for host, port, proto in remotes:
        if proto and not _is_tcp_proto(proto):
            continue
        if not proto and not global_tcp:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        tcp.append(key)
    if not tcp:
        raise ValueError("no TCP remote found (only UDP available)")
    if len(tcp) > MAX_TCP_REMOTES:
        raise ValueError(
            f"too many TCP remotes ({len(tcp)} > {MAX_TCP_REMOTES})")
    usable: list[tuple[str, int]] = []
    for host, port in tcp:
        try:
            usable.append(_validate_remote(host, port))
        except ValueError as exc:
            _log_skipped_remote(host, port, exc)
    if not usable:
        raise ValueError("no usable TCP remote (all rejected)")
    return usable


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
    """Handshake latency of the first working remote, 0 when every one is dead.

    One endpoint gets a total budget of ``timeout * 2`` seconds, no matter how
    many failover remotes it declares: a hostile row cannot fan out into an
    unbounded serial probe chain.
    """
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = 5.0
    budget = max(0.1, budget) * 2
    deadline = time.monotonic() + budget
    remotes = endpoint_remotes(endpoint)
    for host, port in remotes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 0
        try:
            pinned_host, pinned_port = _validate_remote(host, port)
        except ValueError as exc:
            _log_skipped_remote(host, port, exc)
            continue
        try:
            if probe_fn is None:
                ms = probe_tcp_latency(pinned_host, pinned_port,
                                       max(0.1, remaining))
            else:
                ms = probe_fn(pinned_host, pinned_port)
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
    try:
        ttl_value = int(ttl)
    except (TypeError, ValueError):
        raise ValueError("RESI_SESSION_TTL must be an integer") from None
    if isinstance(ttl, bool):
        raise ValueError("RESI_SESSION_TTL must be an integer")
    try:
        user_text = str(user)
        template_text = "" if template is None else str(template)
    except Exception:
        raise ValueError("RESI_USER_TEMPLATE must be text") from None
    if ttl_value <= 0:
        return user_text
    text = template_text.strip()
    if "{session}" not in text:
        return user_text
    try:
        return text.format(user=user_text, session=str(session_id), ttl=ttl_value)
    except (KeyError, IndexError, ValueError, AttributeError, TypeError) as exc:
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
    on_demand: bool = True,
) -> dict:
    """Convert one OpenVPN client config (TCP) to a sing-box openvpn-client endpoint."""
    if not config_text or not config_text.strip():
        raise ValueError("empty openvpn config")
    _check_config_size(config_text)
    config_text = _normalize_config_text(config_text)
    tcp_remotes = _all_tcp_remotes(config_text)
    blocks = _parse_inline_blocks(config_text)
    if "ca" not in blocks or not blocks["ca"]:
        raise ValueError("missing <ca> block")

    auth_m = _AUTH_RE.search(config_text)
    auth = auth_m.group(1).upper() if auth_m else DEFAULT_AUTH
    if auth not in SUPPORTED_AUTH:
        raise ValueError(f"unsupported auth {auth!r}")
    cipher_m = _CIPHER_RE.search(config_text)
    data_ciphers = list(DEFAULT_DATA_CIPHERS)
    if cipher_m:
        cipher = cipher_m.group(1).upper()
        if cipher not in SUPPORTED_CIPHERS:
            raise ValueError(f"unsupported cipher {cipher!r}")
        data_ciphers = [cipher] + [c for c in data_ciphers if c.upper() != cipher]

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
        # Let sing-box disconnect an endpoint that nobody uses. Without it the
        # endpoint keeps the node's single VPNGate session forever - even
        # after the session died - so the node cannot be taken over by a
        # fresh client and the rotation pool slowly goes stale (the cloud
        # acceptance measured every serving endpoint connected but silent,
        # and a fresh client could only get in on half of them). Needs
        # sing-box >= 1.15 (the field does not exist in 1.14); the image
        # pins the version and the CI checks the config with it.
        #
        # Pinned/backup tags deliberately keep their session
        # (on_demand=False) so an idle gap does not release the served
        # chain; every other endpoint still releases when unused. This is
        # duplicate-cn-safe because the same tag only ever reuses its own
        # session - the manager never opens a second dial for that node.
        "on_demand": on_demand,
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
    Callers may only supply the bounded remote list (MAX_TCP_REMOTES).
    """
    if not tcp_remotes:
        raise ValueError("no TCP remote to emit")
    if len(tcp_remotes) > MAX_TCP_REMOTES:
        raise ValueError(
            f"too many TCP remotes ({len(tcp_remotes)} > {MAX_TCP_REMOTES})")
    if len(tcp_remotes) == 1:
        host, port = tcp_remotes[0]
        return {"server": host, "server_port": port}
    return {"servers": [
        {"server": host, "server_port": port, "network": "tcp"}
        for host, port in tcp_remotes
    ]}


def probe_tcp_latency(host: str, port: int, timeout: float = 5,
                      allow_loopback_ports=None) -> int:
    """Measure TCP handshake latency in ms; return 0 when unreachable.

    This is a real-connection pre-filter: VPNGate advertises Speed values
    that say nothing about whether the node accepts connections right now.
    Destinations are validated like every other remote (loopback is only
    allowed for this process's own service ports, which the manager probes).
    ``allow_loopback_ports`` lets the manager pass its constructor ports
    instead of relying only on MIXED_PORT/PORT environment variables.
    """
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return 0
    try:
        pinned_host, pinned_port = _validate_remote(host, port_i)
    except ValueError as exc:
        ip = None
        try:
            ip = ipaddress.ip_address(_strip_host_brackets(host))
        except ValueError:
            pass
        if ip is None or not ip.is_loopback:
            _log_skipped_remote(host, port, exc)
            return 0
        if port_i not in _local_service_ports(allow_loopback_ports):
            _log_skipped_remote(host, port, exc)
            return 0
        pinned_host, pinned_port = str(ip), port_i
    family = socket.AF_INET6 if ":" in pinned_host else socket.AF_INET
    sock = None
    start = time.monotonic()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((pinned_host, pinned_port))
        return max(1, int((time.monotonic() - start) * 1000))
    except (OSError, ValueError, OverflowError):
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, size: int,
                deadline: float | None = None) -> bytes:
    """Read exactly ``size`` bytes, optionally under one absolute deadline.

    A per-recv socket timeout only bounds one syscall; a peer that trickles
    one byte just under that timeout can hold the read loop (and the dial
    gate) for hours. Every caller that reads from an untrusted tunnel passes
    ``deadline`` so the whole read shares one budget.
    """
    data = b""
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("read deadline exceeded")
            sock.settimeout(max(0.05, remaining))
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
    deadline = time.monotonic() + max(0.05, float(timeout))
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2, deadline) != b"\x05\x00":
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
        reply = _recv_exact(sock, 4, deadline)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6, deadline)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1, deadline)[0] + 2, deadline)
        elif atyp == 4:
            _recv_exact(sock, 18, deadline)
        else:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(max(0.05, remaining))
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.05, remaining))
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
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
    deadline = time.monotonic() + max(0.05, float(timeout))
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2, deadline) != b"\x05\x00":
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
        reply = _recv_exact(sock, 4, deadline)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6, deadline)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1, deadline)[0] + 2, deadline)
        elif atyp == 4:
            _recv_exact(sock, 18, deadline)
        else:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(max(0.05, remaining))
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.05, remaining))
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


def _exit_ip_tls_context() -> ssl.SSLContext:
    """Client TLS context for exit-IP probes (patched in unit tests)."""
    return ssl.create_default_context()


def _mixed_connect_get_text(proxy_host: str, proxy_port: int,
                            proxy_auth: str,
                            target_host: str,
                            target_port: int = 443,
                            path: str = "/",
                            timeout: float = 6.0) -> tuple | None:
    """One HTTPS GET through a mixed/HTTP proxy CONNECT tunnel.

    Sends a single CONNECT with the supplied Proxy-Authorization header,
    then does a real TLS handshake (SNI=target_host) and GET inside the
    tunnel. Returns (code, body, ms) like _socks5_get_text, or None.
    """
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    authority = f"{target_host}:{target_port}"
    sock = None
    deadline = time.monotonic() + max(0.05, float(timeout))
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Proxy-Authorization: {proxy_auth}\r\n"
            f"\r\n".encode("ascii")
        )
        head = b""
        while b"\r\n\r\n" not in head:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.05, remaining))
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            head += chunk
            if len(head) > 8192:
                return None
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        if code != 200:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(max(0.05, remaining))
        try:
            sock = _exit_ip_tls_context().wrap_socket(
                sock, server_hostname=target_host)
        except OSError:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        raw = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.05, remaining))
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
        response_head, _, body = raw.partition(b"\r\n\r\n")
        try:
            code = int(response_head.split(b" ", 2)[1])
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


def measure_mixed_exit_ip(proxy_host: str, proxy_port: int, username: str,
                          password: str,
                          timeout: float = 8.0) -> tuple[str | None, int | None]:
    """Measure the real exit IP through a local sing-box mixed inbound.

    Uses HTTP CONNECT (with Basic proxy auth) and TLS to each exit-IP echo
    service, trying EXIT_IP_TARGETS in order inside one total timeout budget.
    Returns (ip, elapsed_ms) on success and (None, None) otherwise. No
    subprocess is spawned, so this is cheap enough for every health tick.
    """
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = 8.0
    try:
        proxy_port_i = int(proxy_port)
    except (TypeError, ValueError):
        return (None, None)
    if not 1 <= proxy_port_i <= 65535:
        return (None, None)
    try:
        loopback = ipaddress.ip_address(
            _strip_host_brackets(proxy_host)).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        try:
            proxy_host, proxy_port_i = _validate_remote(proxy_host, proxy_port_i)
        except ValueError as exc:
            _log_skipped_remote(proxy_host, proxy_port, exc)
            return (None, None)
    else:
        proxy_host = _strip_host_brackets(proxy_host)
    proxy_auth = "Basic " + base64.b64encode(
        f"{username}:{password}".encode("utf-8")).decode("ascii")
    deadline = time.monotonic() + max(0.05, budget)
    for host, port, path in EXIT_IP_TARGETS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        fetched = _mixed_connect_get_text(
            proxy_host, proxy_port, proxy_auth, host, port, path,
            timeout=min(remaining, 6.0))
        if fetched is None or fetched[0] != 200:
            continue
        ip = _parse_exit_ip(fetched[1])
        if ip:
            return (ip, fetched[2])
    return (None, None)


_FREE_PORT_LOCK = threading.Lock()
_FREE_PORT_RECENT: dict[int, float] = {}
_FREE_PORT_COOLDOWN = 30.0


def _free_port() -> int:
    """Pick a loopback port without immediately handing the same one out.

    The old implementation bound port 0, closed the socket and returned the
    number; two concurrent callers could receive the same port, and the OS
    could reuse it before sing-box bound it. We cannot keep the socket open
    (the child must bind it), but a process-wide cooldown at least removes
    the "close then reuse instantly" window between our own callers.
    """
    with _FREE_PORT_LOCK:
        now = time.monotonic()
        for port, seen in list(_FREE_PORT_RECENT.items()):
            if seen <= now - _FREE_PORT_COOLDOWN:
                del _FREE_PORT_RECENT[port]
        for _ in range(64):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            finally:
                sock.close()
            if port not in _FREE_PORT_RECENT:
                _FREE_PORT_RECENT[port] = now
                return port
    raise OSError("could not find a free loopback port")


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


def _pinned_endpoint_remotes(endpoint: dict,
                             deadline: float | None = None
                             ) -> list[tuple[str, int]] | None:
    """Pinned (IP, port) remotes for an endpoint, or None when one is denied.

    Snapshot endpoints must already carry literal IPs (ovpn_to_endpoint pins
    them). This function still revalidates and returns the pinned form so
    call sites can never validate one address and dial another.
    """
    try:
        remotes = endpoint_remotes(endpoint)
    except (TypeError, ValueError):
        return None
    if not remotes:
        return None
    pinned: list[tuple[str, int]] = []
    for host, port in remotes:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        try:
            pinned.append(_validate_remote(host, port))
        except ValueError as exc:
            _log_skipped_remote(host, port, exc)
            return None
    return pinned


def _endpoint_remotes_allowed(endpoint: dict,
                              deadline: float | None = None) -> bool:
    """Every remote of an endpoint must pass the SSRF policy before dialing."""
    return _pinned_endpoint_remotes(endpoint, deadline) is not None


def _pin_endpoint(endpoint: dict, deadline: float | None = None) -> dict | None:
    """Copy an endpoint with its remotes replaced by validated literal IPs."""
    pinned = _pinned_endpoint_remotes(endpoint, deadline)
    if pinned is None:
        return None
    out = {key: value for key, value in endpoint.items()
           if key not in {"server", "server_port", "servers"}}
    if len(pinned) == 1:
        out["server"], out["server_port"] = pinned[0]
    else:
        out["servers"] = [
            {"server": host, "server_port": port, "network": "tcp"}
            for host, port in pinned
        ]
    return out


def _operation_deadline(timeout, deadline: float | None) -> float:
    """Absolute end for one operation, shrunk by an optional caller deadline."""
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = 20.0
    end = time.monotonic() + max(0.0, budget)
    if deadline is not None:
        end = min(end, deadline)
    return end


def measure_real_latency(endpoint: dict, singbox_bin: str = "sing-box",
                         timeout: int = 20, poll_interval: int = 2,
                         target_host: str = "www.gstatic.com",
                         target_port: int = 443,
                         path: str = "/generate_204",
                         deadline: float | None = None) -> int | None:
    """Dial one endpoint with a throwaway sing-box; end-to-end GET ms or None."""
    end = _operation_deadline(timeout, deadline)
    if end <= time.monotonic():
        return None
    pinned_endpoint = _pin_endpoint(endpoint, end)
    if pinned_endpoint is None:
        _safe_print("dial skipped: endpoint has no allowed remote", flush=True)
        return None
    port = _free_port()
    config = _dial_probe_config(pinned_endpoint, port)
    gate_timeout = 30.0
    if deadline is not None:
        gate_timeout = min(30.0, max(0.0, deadline - time.monotonic()))
    if not _DIAL_GATE.acquire(timeout=gate_timeout):
        _safe_print("dial skipped: dial gate queue timeout", flush=True)
        return None
    if time.monotonic() >= end:
        _DIAL_GATE.release()
        return None
    tmpdir = None
    try:
        tmpdir = tempfile.TemporaryDirectory()
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
            while time.monotonic() < end:
                remaining = end - time.monotonic()
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
                pause = min(max(0.0, float(poll_interval)),
                            max(0.0, end - time.monotonic()))
                if pause:
                    time.sleep(pause)
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
        if tmpdir is not None:
            tmpdir.cleanup()


def measure_exit_ip(endpoint: dict, singbox_bin: str = "sing-box",
                    timeout: int = 20, poll_interval: int = 2,
                    deadline: float | None = None) -> tuple:
    """Exit IP through one endpoint: (ip, ms) or (None, None).

    Same throwaway sing-box dial as measure_real_latency, but fetches
    api.ipify.org so the caller learns the actual exit IP, not just
    the end-to-end latency.
    """
    end = _operation_deadline(timeout, deadline)
    if end <= time.monotonic():
        return (None, None)
    pinned_endpoint = _pin_endpoint(endpoint, end)
    if pinned_endpoint is None:
        _safe_print("verify skipped: endpoint has no allowed remote", flush=True)
        return (None, None)
    port = _free_port()
    config = _dial_probe_config(pinned_endpoint, port)
    gate_timeout = 30.0
    if deadline is not None:
        gate_timeout = min(30.0, max(0.0, deadline - time.monotonic()))
    if not _DIAL_GATE.acquire(timeout=gate_timeout):
        _safe_print("verify skipped: dial gate queue timeout", flush=True)
        return (None, None)
    if time.monotonic() >= end:
        _DIAL_GATE.release()
        return (None, None)
    tmpdir = None
    try:
        tmpdir = tempfile.TemporaryDirectory()
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
            while time.monotonic() < end:
                remaining = end - time.monotonic()
                fetched = _fetch_exit_ip("127.0.0.1", port,
                                         timeout=min(10, max(1, remaining)))
                if (fetched is not None and fetched[0] == 200
                        and _looks_like_ipv4(fetched[1])):
                    return (fetched[1].decode("ascii").strip(), fetched[2])
                if proc.poll() is not None:
                    break  # sing-box died; the tunnel will never come up
                pause = min(max(0.0, float(poll_interval)),
                            max(0.0, end - time.monotonic()))
                if pause:
                    time.sleep(pause)
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
        if tmpdir is not None:
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


def _operator_remote_pin(host: str, deadline: float | None = None) -> str:
    """Pin an operator-configured gateway to one address, with bounded DNS.

    RESI_GATEWAY is trusted operator configuration rather than snapshot data,
    so private/loopback addresses are allowed here. Only the lookup itself is
    bounded; this is deliberately not the snapshot SSRF policy.
    """
    host_text = _strip_host_brackets(host)
    if not host_text:
        raise ValueError("empty operator remote host")
    try:
        return str(ipaddress.ip_address(host_text))
    except ValueError:
        return _resolve_with_timeout(
            host_text, DEFAULT_RESOLVE_TIMEOUT, deadline)[0]


def _resi_probe_run(resi: dict, count: int, singbox_bin: str, timeout: int,
                    poll_interval: int, gate_timeout: float,
                    deadline: float | None = None) -> dict | None:
    """Start one throwaway sing-box and collect up to `count` exit IPs.

    Every sample opens a fresh SOCKS5 connection through the local mixed
    inbound -- exactly the unit a backconnect gateway rotates on. Reusing a
    connection would measure our own pooling instead, and one process for N
    samples keeps a 1 GB box from spawning N binaries.
    """
    count = max(1, int(count))
    if deadline is not None and time.monotonic() >= deadline:
        return None
    try:
        pinned_server = _operator_remote_pin(resi.get("server", ""), deadline)
        resi = {**resi, "server": pinned_server}
    except (ValueError, TimeoutError, OSError) as exc:
        _safe_print(f"resi probe skipped: {exc}", flush=True)
        return None
    port = _free_port()
    config = _resi_probe_config(resi, port)
    tmpdir = tempfile.TemporaryDirectory()
    wait = gate_timeout
    if deadline is not None:
        wait = min(wait, max(0.0, deadline - time.monotonic()))
    if not _DIAL_GATE.acquire(timeout=wait):
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
        end = _operation_deadline(timeout, deadline)
        ips: list[str] = []
        stamps: list[int] = []
        errors: list[str] = []
        while time.monotonic() < end and not ips:
            remaining = end - time.monotonic()
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
            pause = min(max(0.0, float(poll_interval)),
                        max(0.0, end - time.monotonic()))
            if pause:
                time.sleep(pause)
        total_deadline = end + (count - 1) * 15
        if deadline is not None:
            total_deadline = min(total_deadline, deadline)
        while ips and len(ips) < count and time.monotonic() < total_deadline:
            remaining = total_deadline - time.monotonic()
            if remaining <= 0:
                break
            fetched = _fetch_exit_ip(
                "127.0.0.1", port,
                timeout=int(min(15, max(1, remaining))))
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
                         timeout: int = 20, poll_interval: int = 2,
                         deadline: float | None = None) -> tuple:
    """Exit IP through the residential gateway: (ip, ms) or (None, None)."""
    result = _resi_probe_run(resi, 1, singbox_bin, timeout, poll_interval,
                             30.0, deadline=deadline)
    if not result:
        return (None, None)
    return (result["ips"][0], result["first_ms"])


def measure_resi_rotation(resi: dict, count: int = 3, singbox_bin: str = "sing-box",
                          timeout: int = 20, poll_interval: int = 2,
                          deadline: float | None = None) -> dict | None:
    """Collect `count` sequential exit IPs through the gateway.

    Returns {"ips", "ms", "count", "distinct", "errors", ...} or None when the
    gateway never answered. `distinct` is the number of different IPs seen;
    rotation is healthy when it is >= 2 (a residential pool may legitimately
    hand out the same node twice in a row).
    """
    return _resi_probe_run(resi, count, singbox_bin, timeout, poll_interval,
                           30.0, deadline=deadline)


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
                        poll_interval: int = 2,
                        deadline: float | None = None) -> dict | None:
    """Sample `count` exit IPs through the rotating third path.

    Returns {"ips", "ms", "count", "distinct", "errors", ...} or None when the
    listener never answered. A residential-side rotation can legitimately hand
    out the same node twice, so health is judged by the caller (distinct >= 2).
    ``deadline`` is an absolute ``time.monotonic()`` value; the dial gate and
    every poll are cut to the remaining budget.
    """
    count = max(1, int(count))
    if deadline is not None and time.monotonic() >= deadline:
        return None
    end = _operation_deadline(timeout, deadline)
    listen_port = _free_port()
    config = _resi_rotate_probe_config(vless_uuid, port, path, listen_port)
    tmpdir = tempfile.TemporaryDirectory()
    if deadline is None:
        gate_wait = 30.0
    else:
        gate_wait = min(30.0, max(0.0, deadline - time.monotonic()))
    if not _DIAL_GATE.acquire(timeout=gate_wait):
        tmpdir.cleanup()
        return None
    if time.monotonic() >= end:
        _DIAL_GATE.release()
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
        ips: list[str] = []
        stamps: list[int] = []
        errors: list[str] = []
        while time.monotonic() < end and not ips:
            remaining = end - time.monotonic()
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
            pause = min(max(0.0, float(poll_interval)),
                        max(0.0, end - time.monotonic()))
            if pause:
                time.sleep(pause)
        # Give the remaining samples a budget of one dial each: failures are
        # expected (dead nodes in the pool) and are walked past, not fatal.
        total_deadline = end + count * 15
        if deadline is not None:
            total_deadline = min(total_deadline, deadline)
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


def _check_snapshot_limits(csv_text: str) -> None:
    """Reject oversized snapshots before splitlines()/CSV parsing allocates.

    Line counting follows ``str.splitlines()`` exactly (including ``\\v``,
    ``\\f``, ``\\x1c``-``\\x1e``, ``\\x85``, ``\\u2028`` and ``\\u2029``), but
    stops as soon as the limit is crossed instead of materializing millions of
    empty strings.
    """
    if not isinstance(csv_text, str):
        raise ValueError("snapshot must be text")
    if len(csv_text.encode("utf-8", "replace")) > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
    if not csv_text:
        return
    lines = 0
    last_end = 0
    for match in _SNAPSHOT_LINE_BREAK_RE.finditer(csv_text):
        lines += 1
        last_end = match.end()
        if lines > MAX_SNAPSHOT_ROWS:
            raise ValueError(f"snapshot exceeds {MAX_SNAPSHOT_ROWS} rows")
    if last_end < len(csv_text):
        lines += 1
    if lines > MAX_SNAPSHOT_ROWS:
        raise ValueError(f"snapshot exceeds {MAX_SNAPSHOT_ROWS} rows")


def _iter_tcp_candidates(csv_text, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD,
                         limit: int | None = None):
    """Yield (speed, country, country_short, untagged-endpoint) for TCP rows.

    ``limit`` is an explicit row budget: every CSV data row consumes one slot,
    including rows whose config is broken, unsafe or UDP-only. snapshot_to_nodes
    passes ``None`` so the hard 8 MiB / 5000-row limits remain the only decode
    bound; the caller's output ``limit`` is applied after ranking.
    """
    _check_snapshot_limits(csv_text)
    lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        raise ValueError("empty snapshot")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "OpenVPN_ConfigData_Base64" not in reader.fieldnames:
        raise ValueError("snapshot columns are incomplete")

    found = False
    rows_seen = 0
    max_encoded = (MAX_CONFIG_BYTES * 4 // 3) + 8
    for row in reader:
        if limit is not None and rows_seen >= limit:
            break
        rows_seen += 1
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not encoded:
            continue
        if len(encoded) > max_encoded:
            _log_skipped_remote("<snapshot>", row.get("IP", "?"),
                                "base64 config too large")
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > MAX_CONFIG_BYTES:
                raise ValueError("decoded config too large")
            config_text = raw.decode("utf-8")
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
    _check_snapshot_limits(csv_text)
    skip_dial = skip_dial_keys or set()
    # Decode every row that fits the hard 8 MiB / 5000-row snapshot budget.
    # ``limit`` is an OUTPUT cap: ranking/probing happens on the full set so a
    # caller asking for Top-N never gets "first N rows of the CSV".
    candidates = list(_iter_tcp_candidates(csv_text, username, password,
                                           limit=None))
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


def _tag_is_reserved(tag: str) -> bool:
    lowered = tag.lower()
    return lowered in RESERVED_ENDPOINT_TAGS or any(
        lowered.startswith(prefix) for prefix in _RESERVED_TAG_PREFIXES)


def nodes_to_endpoints(nodes: list[dict], tag_prefix: str = "vpngate") -> list[dict]:
    """Assign tags and return clean sing-box endpoint dicts (no metadata keys).

    Endpoints that already carry a usable, unique tag (stable refresh
    mapping) keep it; untagged, duplicate or reserved tags (proxy/auto/direct/
    chain/mixed-in/resi-in/vless-*) are re-allocated as ``tag_prefix-N`` so
    two endpoints can never collide in the generated config.
    """
    prefix = str(tag_prefix or "vpngate")
    if _tag_is_reserved(prefix) or _tag_is_reserved(f"{prefix}-0"):
        prefix = "vpngate"
    # Reserve every usable explicit tag before allocating anything. A
    # preceding untagged node must not steal the stable tag of a later node:
    # callers use tags for pin/route identity across refreshes.
    explicit: set[str] = set()
    used: set[str] = set()
    for node in nodes:
        endpoint = node["endpoint"]
        tag = str(endpoint.get("tag") or "")
        if tag and tag not in explicit and not _tag_is_reserved(tag):
            explicit.add(tag)
    next_index = 0
    endpoints = []
    for node in nodes:
        endpoint = dict(node["endpoint"])
        tag = str(endpoint.get("tag") or "")
        if not tag or tag in used or _tag_is_reserved(tag):
            while True:
                candidate = f"{prefix}-{next_index}"
                next_index += 1
                if (candidate not in used and candidate not in explicit
                        and not _tag_is_reserved(candidate)):
                    tag = candidate
                    break
            endpoint["tag"] = tag
        used.add(tag)
        node["endpoint"] = endpoint
        endpoints.append(endpoint)
    assert len({ep["tag"] for ep in endpoints}) == len(endpoints)
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
    persistent_tags: list[str] | None = None,
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

    ``persistent_tags`` names endpoints that must hold their OpenVPN session
    while idle (the pinned/backup part of the chain): those endpoints are
    emitted with ``on_demand=False``. Every other endpoint keeps its existing
    value (default ``True`` when absent), so an unknown tag changes nothing and
    the session is still released as before. None/empty leaves the endpoints
    untouched. Persistence is keyed by the same endpoint tag and therefore
    duplicate-cn-safe: it only ever reuses that tag's own session, never a
    second dial.
    """
    persistent = set(persistent_tags or ())
    if persistent:
        endpoints = [
            {**endpoint, "on_demand": False
             if endpoint["tag"] in persistent
             else endpoint.get("on_demand", True)}
            for endpoint in endpoints
        ]
    tags = [ep["tag"] for ep in endpoints]
    if len(tags) != len(set(tags)):
        raise ValueError("duplicate endpoint tags in sing-box config")
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


def _write_output(path: str, text: str) -> None:
    """Write the generated config and force owner-only permissions."""
    Path(path).write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


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
        _write_output(
            args.output,
            json.dumps(build_singbox_config(endpoints, mixed_listen, mixed_port), indent=2) + "\n",
        )
        _safe_print(f"wrote {args.output} with {len(endpoints)} endpoints")
        return 0

    config_text = Path(args.input).read_text(encoding="utf-8")
    endpoint = ovpn_to_endpoint(config_text, tag=args.tag, username=args.username, password=args.password)
    _write_output(
        args.output,
        json.dumps(build_singbox_config([endpoint], mixed_listen, mixed_port), indent=2) + "\n",
    )
    host, port = primary_server(endpoint)
    _safe_print(f"wrote {args.output} with 1 endpoint ({host}:{port})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
