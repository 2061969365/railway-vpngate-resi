#!/usr/bin/env python3
"""Generate Python golden fixtures for the Go manager port (F6).

The fixtures freeze the *current Python output* for the pure functions ported
to internal/singbox.  F3 may still be changing vpngate_to_singbox.py; if its
semantics change, F7 must re-run this script:

    python scripts/gen_golden.py

Only stdlib is used and no network/sing-box process is started.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import vpngate_to_singbox as v  # noqa: E402
from railway_manager import assign_stable_tags  # noqa: E402

GOLDEN_DIR = ROOT / "tests" / "contract" / "golden"
UUID = "a29738e5-bee1-c0fc-b484-ae7c49cbc828"
CA = "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----"
CERT = "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----"
KEY = "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----"


def ovpn(remotes: list[str], *, cipher: str = "AES-128-CBC",
         auth: str = "SHA1", extra: str = "", tls_auth: str = "",
         tls_crypt: str = "", key_direction: int | None = None) -> str:
    lines = ["client", "dev tun", "proto tcp-client"]
    for remote in remotes:
        lines.append(f"remote {remote}")
    lines += [f"cipher {cipher}", f"auth {auth}", "auth-user-pass"]
    if extra:
        lines.append(extra)
    lines += ["<ca>", CA, "</ca>", "<cert>", CERT, "</cert>", "<key>", KEY, "</key>"]
    if tls_auth:
        lines += ["<tls-auth>", tls_auth, "</tls-auth>"]
        if key_direction is not None:
            lines.append(f"key-direction {key_direction}")
    if tls_crypt:
        lines += ["<tls-crypt>", tls_crypt, "</tls-crypt>"]
    return "\n".join(lines) + "\n"


def endpoint(host: str, port: int, tag: str, **kwargs) -> dict:
    return v.ovpn_to_endpoint(ovpn([f"{host} {port} tcp"], **kwargs), tag=tag)


def write_case(name: str, payload: dict) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    path = GOLDEN_DIR / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


def ovpn_case(name: str, text: str, tag: str = "vpngate-0",
              on_demand: bool = True) -> None:
    expected = v.ovpn_to_endpoint(text, tag=tag, on_demand=on_demand)
    write_case(name, {
        "name": name,
        "kind": "ovpn",
        "ovpn": text,
        "parse": {
            "tag": tag,
            "username": "vpn",
            "password": "vpn",
            "on_demand": on_demand,
            "allow_private_remotes": True,
        },
        "expected": expected,
    })


def config_case(name: str, endpoints: list[dict], mixed_listen: str,
                mixed_port: int, **options) -> None:
    config = v.build_singbox_config(
        endpoints, mixed_listen, mixed_port, **options)
    recorded = {"mixed_listen": mixed_listen, "mixed_port": mixed_port}
    recorded.update(options)
    write_case(name, {
        "name": name,
        "kind": "config",
        "endpoints": endpoints,
        "options": recorded,
        "expected": config,
    })


def node(host: str, tag: str) -> dict:
    return {
        "server": host,
        "server_port": 443,
        "country": "",
        "country_short": "",
        "speed": 0,
        "latency_ms": None,
        "real_latency_ms": None,
        "endpoint": endpoint(host, 443, tag),
    }


def snapshot_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "HostName", "IP", "Score", "Ping", "Speed", "CountryLong",
        "CountryShort", "NumVpnSessions", "Uptime", "TotalUsers",
        "TotalTraffic", "LogType", "Operator", "Message",
        "OpenVPN_ConfigData_Base64",
    ])
    for row in rows:
        import base64
        writer.writerow([
            row["host"], "203.0.113.1", "0", "0", str(row["speed"]),
            row["country"], row["short"], "0", "0", "0", "0", "",
            "", "", base64.b64encode(row["config"].encode("utf-8")).decode("ascii"),
        ])
    return "#" + buffer.getvalue()


def main() -> int:
    basic_text = ovpn(["203.0.113.1 443 tcp"])
    ovpn_case("ovpn-basic", basic_text)
    ovpn_case("ovpn-tls-auth", ovpn(
        ["203.0.113.2 8443 tcp"], tls_auth="VE9LRU4=", key_direction=1))
    ovpn_case("ovpn-multi-remote", ovpn(
        ["203.0.113.3 443 tcp", "203.0.113.4 8443 tcp"]))

    basic_endpoints = [endpoint("203.0.113.1", 443, "vpngate-0")]
    config_case(
        "singbox-basic", basic_endpoints,
        mixed_listen="127.0.0.1", mixed_port=40000,
        mixed_users=[("u", "p")],
    )

    gateway_endpoints = [
        endpoint("203.0.113.1", 443, "vpngate-0"),
        endpoint("203.0.113.2", 8443, "vpngate-1", tls_auth="VE9LRU4=", key_direction=1),
        endpoint("203.0.113.3", 443, "vpngate-2", tls_crypt="Q1JZUFQ=", extra="reneg-sec 0"),
    ]
    config_case(
        "singbox-gateway", gateway_endpoints,
        mixed_listen="127.0.0.1", mixed_port=40000,
        mixed_users=[("u", "p")],
        final="auto", preferred="vpngate-1", backup="vpngate-2",
        vless_uuid=UUID, vless_direct_port=8080, vless_direct_path="/ws-node",
        vless_chain_port=8082, vless_chain_path="/ws-chain",
        resi={"server": "198.51.100.10", "server_port": 1080,
              "username": "ru", "password": "rp"},
        resi_port=8084, resi_path="/ws-resi", resi_in_port=40001,
        resi_rotate=False, resi_rotate_tags=None, chain_candidates=None,
        clash_api={"external_controller": "127.0.0.1:9090", "secret": "secret"},
        persistent_tags=["vpngate-1", "vpngate-2"],
    )
    config_case(
        "singbox-rotate", gateway_endpoints,
        mixed_listen="127.0.0.1", mixed_port=40000,
        mixed_users=[("u", "p")],
        final="auto", preferred="vpngate-1", backup="vpngate-2",
        vless_uuid=UUID, vless_direct_port=8080, vless_direct_path="/ws-node",
        vless_chain_port=8082, vless_chain_path="/ws-chain",
        resi=None, resi_port=8084, resi_path="/ws-resi", resi_in_port=40001,
        resi_rotate=True, resi_rotate_tags=["vpngate-2", "vpngate-0"],
        chain_candidates=["vpngate-0", "vpngate-1", "vpngate-2"],
        clash_api={"external_controller": "127.0.0.1:9090", "secret": "secret"},
        persistent_tags=["vpngate-1", "vpngate-2"],
    )

    old_nodes = [
        node("203.0.113.10", "vpngate-0"),
        node("203.0.113.11", "vpngate-1"),
    ]
    new_nodes = [
        node("198.51.100.20", ""),
        node("203.0.113.11", "vpngate-1"),
        node("203.0.113.10", "vpngate-0"),
        node("198.51.100.21", ""),
    ]
    assign_stable_tags(new_nodes, old_nodes, "vpngate")
    write_case("tags-two-pass", {
        "name": "tags-two-pass",
        "kind": "tags",
        "old": old_nodes,
        "new": new_nodes,
        "prefix": "vpngate",
        "expected": new_nodes,
    })

    rows = [
        {"host": "198.51.100.1", "speed": 1000, "country": "Japan", "short": "jp",
         "config": ovpn(["198.51.100.1 443 tcp"])},
        {"host": "198.51.100.2", "speed": 3000, "country": "Korea", "short": "kr",
         "config": ovpn(["198.51.100.2 443 tcp", "198.51.100.22 8443 tcp"])},
        {"host": "198.51.100.3", "speed": 2000, "country": "United States", "short": "us",
         "config": ovpn(["198.51.100.3 443 tcp"])},
    ]
    csv_text = snapshot_csv(rows)
    nodes = v.snapshot_to_nodes(csv_text, limit=0, probe=False,
                                username="vpn", password="vpn")
    assign_stable_tags(nodes, [], "vpngate")
    write_case("snapshot-basic", {
        "name": "snapshot-basic",
        "kind": "snapshot",
        "csv": csv_text,
        "limit": 0,
        "prefix": "vpngate",
        "expected": nodes,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
