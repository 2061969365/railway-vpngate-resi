#!/usr/bin/env python3
"""End-to-end check of the published image: real VPNGate + Go edge + a
temporary Cloudflare quick tunnel + a real VLESS client.

This intentionally uses no account/token for Cloudflare: `cloudflared tunnel
--url` creates a throwaway trycloudflare.com hostname.  The public hostname is
only used for this run and is never stored.

Chain of evidence:
  server container (real VPNGate snapshot -> sing-box) -> vpngate-edge :3000
  -> cloudflared quick tunnel -> public HTTPS/WSS -> sing-box client -> SOCKS
  -> exit IP.  /ws-chain must exit through a VPNGate node, while the direct
  host IP is the GitHub runner's own egress.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMAGE = sys.argv[1] if len(sys.argv) > 1 else ""
if not IMAGE:
    raise SystemExit("usage: e2e_tunnel_image.py IMAGE_REF")

TOKEN = "e2e-admin-token-0123456789abcdef"
PROXY_PASS = "e2e-proxy-pass-0123456789abcdef"
UUID = "11111111-2222-4333-8444-555555555555"
PORT = 3000
SERVER = "vpngate-e2e-server"
CLIENT_LOCAL = "vpngate-e2e-client-local"
CLIENT_CHAIN = "vpngate-e2e-client-chain"
CLIENT_NODE = "vpngate-e2e-client-node"
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], text=True, capture_output=True, check=check, timeout=180
    )


def docker_out(*args: str) -> str:
    return docker(*args).stdout.strip()


def http(url: str, token: str | None = None, socks: str | None = None,
         timeout: int = 15) -> tuple[str, str]:
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-w", "\n%{http_code}"]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if socks:
        cmd += ["--socks5-hostname", socks]
    cmd.append(url)
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout + 5)
    raw = proc.stdout
    body, _, code = raw.rpartition("\n")
    return code.strip() or "000", body


def fetch_ip(socks: str | None = None) -> str | None:
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com",
                "https://ifconfig.me/ip"):
        code, body = http(url, socks=socks, timeout=20)
        value = body.strip()
        if code == "200" and IPV4.match(value):
            return value
    return None


def container_running(name: str) -> bool:
    proc = docker("inspect", "-f", "{{.State.Running}}", name, check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def dump_logs() -> None:
    for name in (SERVER, CLIENT_LOCAL, CLIENT_CHAIN, CLIENT_NODE):
        print(f"== docker logs {name} (tail) ==", flush=True)
        proc = docker("logs", name, check=False)
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-120:])
        print(tail or "(no logs)", flush=True)
    print("== quick tunnel log (tail) ==", flush=True)
    proc = docker("exec", SERVER, "cat", "/tmp/quick.log", check=False)
    print("\n".join(proc.stdout.splitlines()[-80:]) or "(no quick log)", flush=True)


def wait_ready() -> dict:
    """Wait for a real snapshot/pin.  The cold start is the slow part."""
    deadline = time.time() + 900
    last = 0.0
    while time.time() < deadline:
        if not container_running(SERVER):
            dump_logs()
            raise SystemExit("server container exited during cold start")
        code, body = http(f"http://127.0.0.1:{PORT}/api/status", token=TOKEN, timeout=5)
        if code == "200":
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {}
            endpoints = data.get("endpoints") or []
            if endpoints and data.get("preferred_tag"):
                print(
                    "status ready: preferred=%s endpoints=%d resi=%s"
                    % (data.get("preferred_tag"), len(endpoints),
                       (data.get("resi") or {}).get("mode")),
                    flush=True,
                )
                return data
            if time.time() - last >= 15:
                last = time.time()
                print(
                    "waiting for VPNGate: http=%s endpoints=%d preferred=%s last_error=%s"
                    % (code, len(endpoints), data.get("preferred_tag"),
                       str(data.get("last_error"))[:160]),
                    flush=True,
                )
        elif time.time() - last >= 15:
            last = time.time()
            print(f"waiting for manager: /api/status http={code}", flush=True)
        time.sleep(5)
    dump_logs()
    raise SystemExit("VPNGate cold start did not produce a pinned endpoint in 900s")


def quick_tunnel() -> str:
    docker(
        "exec", "-d", SERVER, "sh", "-c",
        "cloudflared tunnel --no-autoupdate --protocol http2 --url "
        "http://127.0.0.1:3000 >/tmp/quick.log 2>&1",
    )
    deadline = time.time() + 150
    while time.time() < deadline:
        log = docker("exec", SERVER, "cat", "/tmp/quick.log", check=False).stdout
        match = re.search(r"https://[A-Za-z0-9-]+\.trycloudflare\.com", log)
        if match:
            url = match.group(0)
            print(f"quick tunnel: {url}", flush=True)
            return url
        if time.time() > deadline - 120:
            time.sleep(3)
        else:
            time.sleep(2)
    dump_logs()
    raise SystemExit("cloudflared quick tunnel did not print a trycloudflare URL")


def wait_public(url: str) -> None:
    deadline = time.time() + 120
    while time.time() < deadline:
        code, _ = http(url + "/ui", timeout=10)
        if code == "200":
            print("public /ui is reachable", flush=True)
            return
        time.sleep(3)
    dump_logs()
    raise SystemExit(f"public /ui did not become reachable: last http={code}")


def start_client(name: str, host: str, port: int, path: str, tls: bool,
                 socks_port: int, cfg_dir: Path) -> None:
    outbound: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": UUID,
        "transport": {
            "type": "ws",
            "path": path,
            "headers": {"Host": host},
        },
    }
    if tls:
        outbound["tls"] = {"enabled": True, "server_name": host}
    cfg = {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "mixed", "tag": "in", "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }
    path_file = cfg_dir / f"{name}.json"
    path_file.write_text(json.dumps(cfg), encoding="utf-8")
    docker(
        "run", "-d", "--name", name, "--network", "host",
        "-v", f"{path_file}:/tmp/e2e-client.json:ro",
        "--entrypoint", "/usr/local/bin/sing-box", IMAGE,
        "run", "-c", "/tmp/e2e-client.json",
    )


def proxy_ip(name: str, socks_port: int, timeout: float = 120.0) -> str:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if not container_running(name):
            dump_logs()
            raise SystemExit(f"client {name} exited")
        last = fetch_ip(socks=f"127.0.0.1:{socks_port}")
        if last:
            print(f"{name}: exit IP {last}", flush=True)
            return last
        time.sleep(5)
    dump_logs()
    raise SystemExit(f"{name}: no exit IP through SOCKS after {timeout:.0f}s (last={last})")


def main() -> None:
    docker("image", "inspect", IMAGE)
    docker("rm", "-f", SERVER, CLIENT_LOCAL, CLIENT_CHAIN, CLIENT_NODE, check=False)
    print(f"== starting {IMAGE} ==", flush=True)
    docker(
        "run", "-d", "--name", SERVER, "--cap-add=NET_ADMIN",
        "--publish", f"127.0.0.1:{PORT}:{PORT}",
        "-e", f"PORT={PORT}",
        "-e", f"ADMIN_TOKEN={TOKEN}",
        "-e", f"PROXY_PASS={PROXY_PASS}",
        "-e", f"VLESS_UUID={UUID}",
        "-e", "LIMIT=16",
        "-e", "REAL_TOPK=10",
        "-e", "DIAL_WORKERS=5",
        "-e", "FULL_PROBE_WORKERS=5",
        "-e", "PROBE_WORKERS=30",
        "-e", "DIAL_TIMEOUT=8",
        "-e", "PROBE_SERVICE=0",
        "-e", "EDGE_PROXY=1",
        IMAGE,
    )
    wait_ready()

    public_base = quick_tunnel()
    wait_public(public_base)

    checks = [
        ("/ui", "200"),
        ("/healthz", None),
        ("/", "200"),
        ("/api/status", "200"),
        ("/ws-node", "400"),
        ("/ws-chain", "400"),
    ]
    for path, want in checks:
        code, _ = http(public_base + path, token=TOKEN if path == "/api/status" else None,
                       timeout=15)
        if path == "/healthz":
            if code not in ("200", "503"):
                dump_logs()
                raise SystemExit(f"public /healthz returned {code}")
            print(f"public /healthz -> {code} (503 is expected while no node is ready)", flush=True)
            continue
        if code != want:
            dump_logs()
            raise SystemExit(f"public {path} returned {code}, want {want}")
        print(f"public {path} -> {code}", flush=True)

    code, _ = http(public_base + "/api/status", timeout=15)
    if code not in ("401", "403"):
        dump_logs()
        raise SystemExit(f"unauthenticated public /api/status returned {code}")
    print(f"public unauthenticated /api/status -> {code}", flush=True)

    direct_ip = fetch_ip()
    if not direct_ip:
        raise SystemExit("could not determine the runner's direct IPv4")
    print(f"runner direct IP: {direct_ip}", flush=True)

    with tempfile.TemporaryDirectory(prefix="vpngate-e2e-") as tmp:
        cfg_dir = Path(tmp)
        host = public_base.split("://", 1)[1]

        # First prove the VLESS client + local edge + serving sing-box chain.
        # If this fails the public tunnel is not the suspect.
        start_client(CLIENT_LOCAL, "127.0.0.1", PORT, "/ws-chain", False, 1082, cfg_dir)
        local_ip = proxy_ip(CLIENT_LOCAL, 1082, timeout=150)
        if local_ip == direct_ip:
            dump_logs()
            raise SystemExit(f"local /ws-chain exited with the runner IP {direct_ip}")
        print(f"local /ws-chain: {direct_ip} -> {local_ip} (VPNGate exit)", flush=True)

        start_client(CLIENT_CHAIN, host, 443, "/ws-chain", True, 1080, cfg_dir)
        chain_ip = proxy_ip(CLIENT_CHAIN, 1080, timeout=180)
        if chain_ip == direct_ip:
            dump_logs()
            raise SystemExit(f"public /ws-chain exited with the runner IP {direct_ip}: VPNGate path did not switch")
        print(f"public /ws-chain: {direct_ip} -> {chain_ip} (VPNGate exit)", flush=True)

        start_client(CLIENT_NODE, host, 443, "/ws-node", True, 1081, cfg_dir)
        node_ip = proxy_ip(CLIENT_NODE, 1081, timeout=120)
        if node_ip == chain_ip:
            dump_logs()
            raise SystemExit(f"public /ws-node and /ws-chain both exit via {chain_ip}; direct path is wrong")
        print(f"public /ws-node: exit {node_ip} (direct path)", flush=True)

    print(
        "E2E_OK public=%s direct=%s local_chain=%s chain=%s node=%s"
        % (public_base, direct_ip, local_ip, chain_ip, node_ip),
        flush=True,
    )


if __name__ == "__main__":
    started = time.time()
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - report diagnostics before failing
        print(f"E2E-ERROR {type(exc).__name__}: {exc}", flush=True)
        dump_logs()
        raise
    finally:
        for name in (CLIENT_NODE, CLIENT_CHAIN, CLIENT_LOCAL, SERVER):
            docker("rm", "-f", name, check=False)
        print(f"elapsed {time.time() - started:.0f}s", flush=True)
