"""Tests for minimal VPNGate .ovpn -> sing-box openvpn-client converter."""
import base64
import json
import os
import socket
import ssl
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from vpngate_to_singbox import (
    EXIT_IP_TARGETS,
    MAX_BLOCK_BYTES,
    MAX_CONFIG_BYTES,
    MAX_CONFIG_LINE_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_ROWS,
    _all_tcp_remotes,
    _check_snapshot_limits,
    _endpoint_remotes_allowed,
    _fetch_exit_ip,
    _iter_tcp_candidates,
    _local_service_ports,
    _parse_exit_ip,
    _recv_exact,
    _resolve_with_timeout,
    _server_fields,
    _socks5_get_text,
    _validate_remote,
    build_singbox_config,
    main,
    measure_exit_ip,
    measure_mixed_exit_ip,
    measure_real_latency,
    endpoint_remotes,
    nodes_to_endpoints,
    ovpn_to_endpoint,
    probe_endpoint_latency,
    probe_tcp_latency,
    render_resi_username,
    snapshot_to_endpoints,
    snapshot_to_nodes,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
TLS_CERT = str(FIXTURE_DIR / "tls-localhost.crt")
TLS_KEY = str(FIXTURE_DIR / "tls-localhost.key")


TCP_OVPN = """\
client
dev tun
proto tcp-client
remote 203.0.113.1 443 tcp
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
Q0E=
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
Q0VSVA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
S0VZ
-----END PRIVATE KEY-----
</key>
"""

UDP_ONLY_OVPN = """\
client
dev tun
proto udp
remote 198.51.100.7 1194 udp
<ca>
Q0E=
</ca>
"""


class ConvertTcpTests(unittest.TestCase):
    def test_tcp_config_converts_to_openvpn_client_endpoint(self) -> None:
        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")

        self.assertEqual("openvpn-client", ep["type"])
        self.assertEqual("vpngate-0", ep["tag"])
        self.assertEqual("203.0.113.1", ep["server"])
        self.assertEqual(443, ep["server_port"])
        self.assertEqual("tcp", ep["network"])
        self.assertFalse(ep["system"])
        self.assertEqual("vpn", ep["username"])
        self.assertEqual("vpn", ep["password"])
        self.assertIn("BF-CBC", ep["data_ciphers"])
        self.assertIn("AES-128-CBC", ep["data_ciphers"])
        self.assertEqual("SHA1", ep["auth"])
        self.assertIn("BEGIN CERTIFICATE", ep["tls"]["certificate"])
        # VPNGate gives one OpenVPN session per node, so a second login for
        # the same node (the manager's own refresh probe) gets the serving
        # session rejected. With the default "none" that rejection is final
        # and the serving endpoint stays dead; the endpoint must retry the
        # authentication instead.
        self.assertEqual("nointeract", ep["auth_retry"])
        # An idle endpoint has to be disconnectable, otherwise it keeps the
        # node's single VPNGate session and the node cannot be taken over
        # (the pool goes stale). Needs sing-box >= 1.15.
        self.assertTrue(ep["on_demand"])
        # The keepalive comes from the .ovpn (10s/60s here), not from us.
        self.assertEqual("10s", ep["ping_interval"])
        self.assertEqual("60s", ep["ping_restart"])

    def test_pinned_endpoint_can_hold_its_session(self) -> None:
        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-pin", on_demand=False)

        self.assertFalse(ep["on_demand"])
        self.assertEqual("vpngate-pin", ep["tag"])

    def test_the_probe_does_not_retry_a_rejected_login(self) -> None:
        """The serving endpoint retries a rejected login; the throwaway probe
        must not.

        A probe that cannot get the node's single VPNGate session (the
        serving endpoint holds it) has to fail fast, so the caller can skip
        that node. With the retry the probe would sit in the login until its
        own timeout - slower, and exactly backwards.
        """
        from vpngate_to_singbox import _dial_probe_config
        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        config = _dial_probe_config(ep, 40000)

        probe = next(e for e in config["endpoints"] if e["tag"] == "dial-probe")
        self.assertEqual("none", probe["auth_retry"])
        # the probe must not wait for a keepalive or a reconnect - and the
        # keys must be absent, not empty: sing-box rejects an empty
        # duration and the probe client would not start.
        self.assertNotIn("ping_interval", probe)
        self.assertNotIn("ping_restart", probe)
        self.assertTrue(probe["ping_restart_disabled"])
        # the serving endpoint keeps the retry
        self.assertEqual("nointeract", ep["auth_retry"])

    def test_udp_only_config_raises(self) -> None:
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(UDP_ONLY_OVPN, tag="vpngate-x")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _snapshot_row(host: str, ip: str, speed: int, config_b64: str) -> str:
    return f"{host},{ip},100,20,{speed},Japan,JP,1,{config_b64}"


def _snapshot_row_country(host: str, ip: str, speed: int, config_b64: str,
                          country_long: str, country_short: str) -> str:
    return f"{host},{ip},100,20,{speed},{country_long},{country_short},1,{config_b64}"


CSV_HEADER = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"


class ProbeTcpLatencyTests(unittest.TestCase):
    def test_closed_port_returns_zero(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()

        self.assertEqual(0, probe_tcp_latency("127.0.0.1", free_port, timeout=2))

    def test_listening_port_returns_positive_ms(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def _accept() -> None:
            listener.settimeout(5)
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                        conn.close()
                    except socket.timeout:
                        continue
            except OSError:
                pass

        worker = threading.Thread(target=_accept, daemon=True)
        worker.start()
        try:
            with mock.patch.dict(os.environ, {"ALLOW_PRIVATE_REMOTES": "1"}):
                latency = probe_tcp_latency("127.0.0.1", port, timeout=5)
        finally:
            stop.set()
            listener.close()

        self.assertGreater(latency, 0)

    def test_manager_supplied_loopback_port_needs_no_environment(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def _accept() -> None:
            listener.settimeout(5)
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                pass

        threading.Thread(target=_accept, daemon=True).start()
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(0, probe_tcp_latency("127.0.0.1", port,
                                                      timeout=2))
                latency = probe_tcp_latency(
                    "127.0.0.1", port, timeout=5,
                    allow_loopback_ports={port})
        finally:
            stop.set()
            listener.close()

        self.assertGreater(latency, 0)
        self.assertIn(port, _local_service_ports({port}))


class SnapshotToNodesTests(unittest.TestCase):
    def _csv(self) -> str:
        return "\n".join([
            CSV_HEADER,
            _snapshot_row_country("vpn-jp-slow", "203.0.113.11", 1000,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.11")),
                                  "Japan", "JP"),
            _snapshot_row_country("vpn-us-fast", "203.0.113.12", 500,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.12")),
                                  "United States", "US"),
            # UDP-only row must be skipped even though its Speed is highest.
            _snapshot_row_country("vpn-udp", "198.51.100.99", 999999,
                                  _b64(UDP_ONLY_OVPN), "Japan", "JP"),
            _snapshot_row_country("vpn-broken", "203.0.113.13", 8000,
                                  "!!!not-base64!!!", "Japan", "JP"),
            "*vpn_servers",
            "# 123",
        ]) + "\n"

    def test_nodes_carry_country_and_latency_sorted_by_latency(self) -> None:
        latencies = {"203.0.113.11": 900, "203.0.113.12": 100}

        nodes = snapshot_to_nodes(
            self._csv(), probe_fn=lambda host, port: latencies[host])

        self.assertEqual(2, len(nodes))
        # sorted by measured latency, not by Speed
        self.assertEqual("203.0.113.12", nodes[0]["server"])
        self.assertEqual("US", nodes[0]["country_short"])
        self.assertEqual("United States", nodes[0]["country"])
        self.assertEqual(100, nodes[0]["latency_ms"])
        self.assertEqual(500, nodes[0]["speed"])
        self.assertEqual("JP", nodes[1]["country_short"])

    def test_unreachable_probe_result_is_filtered_out(self) -> None:
        nodes = snapshot_to_nodes(self._csv(), probe_fn=lambda host, port: 0)

        self.assertEqual([], nodes)

    def test_probe_disabled_falls_back_to_speed_rank(self) -> None:
        nodes = snapshot_to_nodes(self._csv(), probe=False)

        self.assertEqual(2, len(nodes))
        self.assertEqual("203.0.113.11", nodes[0]["server"])
        self.assertIsNone(nodes[0]["latency_ms"])

    def test_probe_fn_none_treated_as_dead(self) -> None:
        nodes = snapshot_to_nodes(self._csv(), probe_fn=lambda host, port: None)

        self.assertEqual([], nodes)

    def test_negative_probe_pool_raises(self) -> None:
        with self.assertRaises(ValueError):
            snapshot_to_nodes(self._csv(), probe_pool=-5,
                              probe_fn=lambda host, port: 100)

    def test_negative_limit_raises(self) -> None:
        with self.assertRaises(ValueError):
            snapshot_to_nodes(self._csv(), limit=-1,
                              probe_fn=lambda host, port: 100)


class NodesToEndpointsTests(unittest.TestCase):
    def test_endpoint_dict_has_no_extra_metadata_keys(self) -> None:
        nodes = snapshot_to_nodes(
            "\n".join([
                CSV_HEADER,
                _snapshot_row_country("vpn-jp", "203.0.113.11", 1000,
                                      _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.11")),
                                      "Japan", "JP"),
            ]) + "\n",
            probe_fn=lambda host, port: 50,
        )

        endpoints = nodes_to_endpoints(nodes, tag_prefix="vpngate")

        self.assertEqual(1, len(endpoints))
        self.assertEqual("vpngate-0", endpoints[0]["tag"])
        self.assertNotIn("country", endpoints[0])
        self.assertNotIn("country_short", endpoints[0])
        self.assertNotIn("latency_ms", endpoints[0])
        self.assertNotIn("speed", endpoints[0])


class FailoverConfigTests(unittest.TestCase):
    def test_urltest_is_vpn_only_and_tuned_params(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], final="auto")

        self.assertEqual("auto", cfg["route"]["final"])
        urltest = next(o for o in cfg["outbounds"] if o["type"] == "urltest")
        # direct must NOT be in the auto urltest group: it always wins on
        # speed and would silently route all serving traffic around the VPN.
        self.assertNotIn("direct", urltest["outbounds"])
        self.assertIn("vpngate-0", urltest["outbounds"])
        self.assertEqual("15s", urltest["interval"])
        self.assertEqual(150, urltest["tolerance"])

    def test_chain_selector_fallback_routes_preferred_then_auto(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], final="auto",
                                   preferred="vpngate-0")

        self.assertEqual("chain", cfg["route"]["final"])
        chain = next(o for o in cfg["outbounds"] if o["tag"] == "chain")
        self.assertEqual("selector", chain["type"])
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])

    def test_no_chain_selector_without_preferred(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], final="auto")

        self.assertEqual("auto", cfg["route"]["final"])
        self.assertNotIn("chain", [o["tag"] for o in cfg["outbounds"]])

    def test_direct_remains_in_manual_selector_as_explicit_fallback(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], final="auto")

        selector = next(o for o in cfg["outbounds"] if o["type"] == "selector")
        self.assertEqual(["vpngate-0", "direct"], selector["outbounds"])

    def test_default_final_is_auto(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint])

        self.assertEqual("auto", cfg["route"]["final"])


class SnapshotToEndpointsTests(unittest.TestCase):
    def test_tcp_rows_convert_udp_and_broken_skipped_ranked_by_speed(self) -> None:
        slow_tcp = TCP_OVPN.replace("203.0.113.1", "203.0.113.11")
        fast_tcp = TCP_OVPN.replace("203.0.113.1", "203.0.113.12")
        csv_text = "\n".join(
            [
                "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64",
                # UDP row is fastest but must be skipped (no TCP remote)
                _snapshot_row("vpn-udp", "198.51.100.99", 999999, _b64(UDP_ONLY_OVPN)),
                _snapshot_row("vpn-slow", "203.0.113.11", 1000, _b64(slow_tcp)),
                _snapshot_row("vpn-fast", "203.0.113.12", 5000, _b64(fast_tcp)),
                _snapshot_row("vpn-broken", "203.0.113.13", 8000, "!!!not-base64!!!"),
                "*vpn_servers",
                "# 123",
            ]
        ) + "\n"

        endpoints = snapshot_to_endpoints(csv_text, limit=8, tag_prefix="vpngate",
                                            probe=False)

        self.assertEqual(2, len(endpoints))
        # ranked by Speed desc
        self.assertEqual("203.0.113.12", endpoints[0]["server"])
        self.assertEqual("203.0.113.11", endpoints[1]["server"])
        self.assertEqual(["vpngate-0", "vpngate-1"], [ep["tag"] for ep in endpoints])
        self.assertTrue(all(ep["network"] == "tcp" for ep in endpoints))

    def test_limit_is_respected(self) -> None:
        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n" + "\n".join(rows) + "\n"

        endpoints = snapshot_to_endpoints(csv_text, limit=2, probe=False)

        self.assertEqual(2, len(endpoints))

    def test_snapshot_without_usable_tcp_raises(self) -> None:
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            + _snapshot_row("vpn-udp", "198.51.100.99", 999999, _b64(UDP_ONLY_OVPN))
            + "\n"
        )

        with self.assertRaises(ValueError):
            snapshot_to_endpoints(csv_text, probe=False)


class FakeSocks5Server:
    """SOCKS5 server: no-auth + CONNECT, then TLS (like a real 443 target)."""

    def __init__(self, status_code: int = 204) -> None:
        self.status_code = status_code
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.load_cert_chain(TLS_CERT, TLS_KEY)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def _recvn(self, conn: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise OSError("eof")
            data += chunk
        return data

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                nmethods = self._recvn(conn, 2)[1]
                self._recvn(conn, nmethods)
                conn.sendall(b"\x05\x00")
                header = self._recvn(conn, 4)
                atyp = header[3]
                if atyp == 1:
                    self._recvn(conn, 6)
                elif atyp == 3:
                    self._recvn(conn, self._recvn(conn, 1)[0] + 2)
                elif atyp == 4:
                    self._recvn(conn, 18)
                else:
                    conn.close()
                    continue
                conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                try:
                    conn = self._tls_context.wrap_socket(conn, server_side=True)
                except OSError:
                    conn.close()
                    continue
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                conn.sendall(
                    f"HTTP/1.1 {self.status_code} Test\r\nContent-Length: 0\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


class Socks5LatencyTests(unittest.TestCase):
    def test_204_returns_positive_ms(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        server = FakeSocks5Server(status_code=204)
        server.start()
        try:
            latency = _socks5_get_latency_ms(
                "127.0.0.1", server.port, target_host="127.0.0.1",
                target_port=server.port, timeout=5, cafile=TLS_CERT)
        finally:
            server.stop()

        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 1)

    def test_non_204_returns_none(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        server = FakeSocks5Server(status_code=500)
        server.start()
        try:
            latency = _socks5_get_latency_ms(
                "127.0.0.1", server.port, target_host="127.0.0.1",
                target_port=server.port, timeout=5, cafile=TLS_CERT)
        finally:
            server.stop()

        self.assertIsNone(latency)

    def test_refused_connection_returns_none(self) -> None:
        from vpngate_to_singbox import _socks5_get_latency_ms

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()

        self.assertIsNone(_socks5_get_latency_ms("127.0.0.1", free_port, timeout=2))


def _real_csv() -> str:
    return "\n".join([
        CSV_HEADER,
        _snapshot_row_country("vpn-a", "203.0.113.21", 3000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.21")),
                              "Japan", "JP"),
        _snapshot_row_country("vpn-b", "203.0.113.22", 2000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.22")),
                              "Japan", "JP"),
        _snapshot_row_country("vpn-c", "203.0.113.23", 1000,
                              _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.23")),
                              "Japan", "JP"),
    ]) + "\n"


class RealTopKTests(unittest.TestCase):
    def test_measured_first_then_unmeasured_by_handshake(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        handshakes = {"203.0.113.21": 300, "203.0.113.22": 100, "203.0.113.23": 200}
        real = {"203.0.113.22": 500, "203.0.113.23": 50}

        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: handshakes[host],
            real_topk=2,
            dial_fn=lambda node: real.get(node["server"]),
        )

        self.assertEqual(["203.0.113.23", "203.0.113.22", "203.0.113.21"],
                         [n["server"] for n in nodes])
        self.assertEqual([50, 500, None],
                         [n["real_latency_ms"] for n in nodes])

    def test_real_topk_zero_never_dials(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        calls: list = []
        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=0,
            dial_fn=lambda node: calls.append(node["server"]) or 1,
        )

        self.assertEqual([], calls)
        self.assertTrue(all(n["real_latency_ms"] is None for n in nodes))

    def test_dial_exception_treated_as_unmeasured(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        def bad_dial(node):
            if node["server"] == "203.0.113.22":
                raise RuntimeError("tunnel down")
            return 70

        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=3,
            dial_fn=bad_dial,
        )

        by_server = {n["server"]: n for n in nodes}
        self.assertIsNone(by_server["203.0.113.22"]["real_latency_ms"])
        self.assertEqual(70, by_server["203.0.113.21"]["real_latency_ms"])
        # measured nodes rank before the failed one
        self.assertLess(
            [n["server"] for n in nodes].index("203.0.113.21"),
            [n["server"] for n in nodes].index("203.0.113.22"),
        )

    def test_skip_dial_keys_never_dials_a_live_node(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        calls: list = []
        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=2,
            dial_fn=lambda node: calls.append(node["server"]) or 42,
            skip_dial_keys={("203.0.113.21", 443)},
        )

        # Dialing a node the caller already serves would kick its session.
        self.assertNotIn("203.0.113.21", calls)
        by_server = {n["server"]: n for n in nodes}
        self.assertIsNone(by_server["203.0.113.21"]["real_latency_ms"])
        # A skipped node must not eat a slot: two others are dialed instead.
        self.assertEqual(2, len(calls))
        self.assertEqual({"203.0.113.22", "203.0.113.23"}, set(calls))
        self.assertEqual(42, by_server["203.0.113.22"]["real_latency_ms"])

    def test_skip_dial_keys_that_covers_everything_dials_nothing(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        calls: list = []
        nodes = snapshot_to_nodes(
            _real_csv(),
            probe_fn=lambda host, port: 100,
            real_topk=3,
            dial_fn=lambda node: calls.append(node["server"]) or 42,
            skip_dial_keys={("203.0.113.21", 443), ("203.0.113.22", 443),
                            ("203.0.113.23", 443)},
        )

        self.assertEqual([], calls)
        self.assertTrue(all(n["real_latency_ms"] is None for n in nodes))

    def test_limit_zero_returns_all_nodes(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        self.assertEqual(5, len(snapshot_to_nodes(csv_text, limit=0, probe=False)))

    def test_default_limit_returns_all_nodes(self) -> None:
        from vpngate_to_singbox import snapshot_to_nodes

        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1", f"203.0.113.{100 + i}")))
            for i in range(5)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        self.assertEqual(5, len(snapshot_to_nodes(csv_text, probe=False)))


class MixedInboundTests(unittest.TestCase):
    def test_mixed_inbound_included_when_requested(self) -> None:
        from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], mixed_listen="127.0.0.1", mixed_port=18080)

        inbounds = cfg.get("inbounds", [])
        self.assertEqual(1, len(inbounds))
        self.assertEqual("mixed", inbounds[0]["type"])
        self.assertEqual("127.0.0.1", inbounds[0]["listen"])
        self.assertEqual(18080, inbounds[0]["listen_port"])

    def test_no_inbound_by_default(self) -> None:
        from vpngate_to_singbox import build_singbox_config, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint])

        self.assertNotIn("inbounds", cfg)


class MeasureDiagnosticsTests(unittest.TestCase):
    def test_dead_binary_returns_none_without_waiting_full_timeout(self) -> None:
        import sys
        import time
        from vpngate_to_singbox import measure_real_latency, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="probe-0")
        started = time.monotonic()
        # python exits immediately on a bad script name: process dies fast,
        # so measure must give up early instead of polling until deadline.
        result = measure_real_latency(endpoint, singbox_bin=sys.executable,
                                      timeout=30, poll_interval=1)
        elapsed = time.monotonic() - started

        self.assertIsNone(result)
        self.assertLess(elapsed, 15)


class MeasureReturnFirstTests(unittest.TestCase):
    def test_first_successful_get_is_returned_without_second_call(self) -> None:
        from unittest import mock
        from vpngate_to_singbox import measure_real_latency, ovpn_to_endpoint

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="probe-0")
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        with mock.patch("vpngate_to_singbox.subprocess.Popen",
                        return_value=fake_proc), \
             mock.patch("vpngate_to_singbox._socks5_get_latency_ms",
                        side_effect=[118, None]) as probe:
            result = measure_real_latency(endpoint, timeout=60, poll_interval=1)

        # The readiness probe already completed a full HTTPS GET through the
        # tunnel; a second timed GET only adds failure surface (e.g. a 2s
        # budget when readiness arrives at 118s of a 120s deadline).
        self.assertEqual(118, result)
        self.assertEqual(1, probe.call_count)


class DialProbeConfigTests(unittest.TestCase):
    def test_final_pinned_to_probe_tag(self) -> None:
        from vpngate_to_singbox import _dial_probe_config

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-3")
        config = _dial_probe_config(endpoint, 41234)

        self.assertEqual("dial-probe", config["route"]["final"])
        self.assertEqual(["dial-probe"], [ep["tag"] for ep in config["endpoints"]])
        self.assertEqual(41234, config["inbounds"][0]["listen_port"])

    def test_serving_default_stays_on_auto(self) -> None:
        from vpngate_to_singbox import build_singbox_config

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-3")
        config = build_singbox_config([endpoint])

        self.assertEqual("auto", config["route"]["final"])


class ControlWrapTests(unittest.TestCase):
    TLS_AUTH_OVPN = TCP_OVPN + """\
key-direction 1
<tls-auth>
VE9LRU4=
</tls-auth>
"""

    TLS_CRYPT_OVPN = TCP_OVPN + """\
<tls-crypt>
Q1JZUFRfS0VZ
</tls-crypt>
"""

    def test_tls_auth_block_maps_to_control_wrap(self) -> None:
        ep = ovpn_to_endpoint(self.TLS_AUTH_OVPN, tag="vpngate-ta")

        self.assertEqual(
            {"type": "tls_auth", "key": "VE9LRU4=", "direction": "client"},
            ep["tls"]["control_wrap"],
        )

    def test_crlf_config_parses(self) -> None:
        endpoint = ovpn_to_endpoint(
            TCP_OVPN.replace("\n", "\r\n"), tag="crlf")

        self.assertEqual("203.0.113.1", endpoint["server"])
        self.assertEqual(443, endpoint["server_port"])

    def test_tls_auth_direction_zero_maps_to_server(self) -> None:
        ovpn = self.TLS_AUTH_OVPN.replace("key-direction 1", "key-direction 0")
        ep = ovpn_to_endpoint(ovpn, tag="vpngate-ta0")

        self.assertEqual(
            {"type": "tls_auth", "key": "VE9LRU4=", "direction": "server"},
            ep["tls"]["control_wrap"],
        )

    def test_tls_auth_without_key_direction_omits_it(self) -> None:
        ovpn = self.TLS_AUTH_OVPN.replace("key-direction 1\n", "")
        ep = ovpn_to_endpoint(ovpn, tag="vpngate-tanodir")

        self.assertEqual(
            {"type": "tls_auth", "key": "VE9LRU4="},
            ep["tls"]["control_wrap"],
        )

    def test_tls_crypt_block_maps_to_control_wrap(self) -> None:
        ep = ovpn_to_endpoint(self.TLS_CRYPT_OVPN, tag="vpngate-tc")

        self.assertEqual(
            {"type": "tls_crypt", "key": "Q1JZUFRfS0VZ"},
            ep["tls"]["control_wrap"],
        )

    def test_tls_crypt_ignores_key_direction(self) -> None:
        ovpn = self.TLS_CRYPT_OVPN + "key-direction 1\n"
        ep = ovpn_to_endpoint(ovpn, tag="vpngate-tcdir")

        self.assertEqual(
            {"type": "tls_crypt", "key": "Q1JZUFRfS0VZ"},
            ep["tls"]["control_wrap"],
        )

    def test_cert_without_key_raises(self) -> None:
        import re

        ovpn = re.sub(r"<key>.*?</key>\n?", "", TCP_OVPN, flags=re.S)
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(ovpn, tag="vpngate-halfcert")

    def test_key_without_cert_raises(self) -> None:
        import re

        ovpn = re.sub(r"<cert>.*?</cert>\n?", "", TCP_OVPN, flags=re.S)
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(ovpn, tag="vpngate-halfkey")


class MultiRemoteTests(unittest.TestCase):
    MULTI_TCP_OVPN = TCP_OVPN.replace(
        "remote 203.0.113.1 443 tcp",
        "remote 203.0.113.1 443 tcp\nremote 203.0.113.2 1194 tcp",
    )

    def test_multiple_tcp_remotes_become_servers_list(self) -> None:
        from vpngate_to_singbox import primary_server

        ep = ovpn_to_endpoint(self.MULTI_TCP_OVPN, tag="vpngate-multi")

        self.assertNotIn("server", ep)
        self.assertNotIn("server_port", ep)
        self.assertEqual(
            [
                {"server": "203.0.113.1", "server_port": 443, "network": "tcp"},
                {"server": "203.0.113.2", "server_port": 1194, "network": "tcp"},
            ],
            ep["servers"],
        )
        self.assertEqual(("203.0.113.1", 443), primary_server(ep))

    def test_single_remote_keeps_singular_server_fields(self) -> None:
        from vpngate_to_singbox import primary_server

        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")

        self.assertEqual("203.0.113.1", ep["server"])
        self.assertEqual(443, ep["server_port"])
        self.assertNotIn("servers", ep)
        self.assertEqual(("203.0.113.1", 443), primary_server(ep))

    def test_remote_random_directive_is_preserved(self) -> None:
        ep = ovpn_to_endpoint(self.MULTI_TCP_OVPN + "remote-random\n", tag="vpngate-rr")

        self.assertTrue(ep["remote_random"])


class ProbeFallbackTests(unittest.TestCase):
    def _csv(self) -> str:
        rows = [
            _snapshot_row_country("vpn-a", "203.0.113.11", 3000,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.11")),
                                  "Japan", "JP"),
            _snapshot_row_country("vpn-b", "203.0.113.12", 2000,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.12")),
                                  "Japan", "JP"),
            _snapshot_row_country("vpn-c", "203.0.113.13", 1000,
                                  _b64(TCP_OVPN.replace("203.0.113.1", "203.0.113.13")),
                                  "Japan", "JP"),
        ]
        return "\n".join([CSV_HEADER] + rows) + "\n"

    def test_probe_falls_through_to_next_speed_chunk(self) -> None:
        latencies = {"203.0.113.11": 0, "203.0.113.12": 0, "203.0.113.13": 50}

        nodes = snapshot_to_nodes(
            self._csv(), probe_pool=2,
            probe_fn=lambda host, port: latencies[host])

        self.assertEqual(["203.0.113.13"], [n["server"] for n in nodes])
        self.assertEqual(50, nodes[0]["latency_ms"])

    def test_probe_all_dead_still_returns_empty(self) -> None:
        nodes = snapshot_to_nodes(
            self._csv(), probe_pool=2, probe_fn=lambda host, port: 0)

        self.assertEqual([], nodes)


UUID = "a29738e5-bee1-c0fc-b484-ae7c49cbc828"


def _vless_cfg(**kwargs):
    endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
    params = dict(mixed_listen="127.0.0.1", mixed_port=18080,
                  mixed_users=[("u", "0123456789abcdef")],
                  vless_uuid=UUID)
    params.update(kwargs)
    return build_singbox_config([endpoint], **params)


class VlessDualInboundTests(unittest.TestCase):
    def test_dual_vless_inbounds_present_with_ws_paths(self) -> None:
        inbounds = {i["tag"]: i for i in _vless_cfg()["inbounds"]}
        direct = inbounds["vless-direct"]
        self.assertEqual("vless", direct["type"])
        self.assertEqual(8080, direct["listen_port"])
        self.assertEqual(UUID, direct["users"][0]["uuid"])
        self.assertEqual("ws", direct["transport"]["type"])
        self.assertEqual("/ws-node", direct["transport"]["path"])
        chain = inbounds["vless-chain"]
        self.assertEqual("vless", chain["type"])
        self.assertEqual(8082, chain["listen_port"])
        self.assertEqual("/ws-chain", chain["transport"]["path"])

    def test_chain_path_needs_no_loopback_outbound(self) -> None:
        outbounds = {o["tag"]: o for o in _vless_cfg()["outbounds"]}
        self.assertNotIn("chain-socks", outbounds)

    def test_route_rules_split_traffic_by_inbound(self) -> None:
        cfg = _vless_cfg()
        rules = {(r.get("inbound"), r.get("outbound")) for r in cfg["route"]["rules"]}
        self.assertIn(("vless-direct", "direct"), rules)
        self.assertIn(("vless-chain", "auto"), rules)
        self.assertEqual("auto", cfg["route"]["final"])

    def test_pinned_chain_path_follows_chain_selector(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config(
            [endpoint], "127.0.0.1", 18080,
            mixed_users=[("u", "0123456789abcdef")],
            final="auto", preferred="vpngate-0",
            vless_uuid=UUID)
        rules = {(r.get("inbound"), r.get("outbound")) for r in cfg["route"]["rules"]}
        self.assertIn(("vless-chain", "chain"), rules)
        self.assertEqual("chain", cfg["route"]["final"])

    def test_no_vless_by_default(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config([endpoint], mixed_listen="127.0.0.1",
                                   mixed_port=18080)
        tags = [i["tag"] for i in cfg.get("inbounds", [])]
        self.assertNotIn("vless-direct", tags)
        self.assertNotIn("chain-socks", [o["tag"] for o in cfg["outbounds"]])
        self.assertNotIn("rules", cfg["route"])

    def test_vless_without_mixed_raises(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        with self.assertRaises(ValueError):
            build_singbox_config([endpoint], vless_uuid=UUID)


class DialGateTests(unittest.TestCase):
    """P1: concurrent throwaway dials are capped so a 1GB box survives."""

    def test_gate_cap_is_ten(self) -> None:
        from vpngate_to_singbox import MAX_CONCURRENT_DIALS, _DIAL_GATE

        self.assertEqual(10, MAX_CONCURRENT_DIALS)
        self.assertIsInstance(_DIAL_GATE, threading.BoundedSemaphore)

    def test_measure_acquires_and_releases_gate(self) -> None:
        import vpngate_to_singbox as mod

        ep = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-gate")
        with mock.patch.object(mod, "_DIAL_GATE") as gate, \
             mock.patch("subprocess.Popen", side_effect=OSError("noexec")):
            self.assertIsNone(mod.measure_real_latency(ep, timeout=5))
            self.assertEqual((None, None), mod.measure_exit_ip(ep, timeout=5))
        self.assertTrue(gate.acquire.called)
        self.assertTrue(gate.release.called)


class DualPinConfigTests(unittest.TestCase):
    """chain selector with a backup: [best, second, auto]."""

    def _two(self):
        first = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        second = ovpn_to_endpoint(
            TCP_OVPN.replace("203.0.113.1", "203.0.113.2"), tag="vpngate-1")
        return [first, second]

    def test_chain_with_backup_routes_best_second_auto(self) -> None:
        cfg = build_singbox_config(self._two(), preferred="vpngate-0",
                                   backup="vpngate-1")

        self.assertEqual("chain", cfg["route"]["final"])
        chain = next(o for o in cfg["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "vpngate-1", "auto"], chain["outbounds"])

    def test_unknown_backup_falls_back(self) -> None:
        cfg = build_singbox_config(self._two(), preferred="vpngate-0",
                                   backup="vpngate-9")

        chain = next(o for o in cfg["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])

    def test_backup_equal_to_preferred_falls_back(self) -> None:
        cfg = build_singbox_config(self._two(), preferred="vpngate-0",
                                   backup="vpngate-0")

        chain = next(o for o in cfg["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])

    def test_no_backup_keeps_old_shape(self) -> None:
        cfg = build_singbox_config(self._two(), preferred="vpngate-0")

        chain = next(o for o in cfg["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])


class PersistentEndpointTests(unittest.TestCase):
    """Pinned/backup tags hold their session; every other endpoint releases."""

    def _two(self):
        return [
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0"),
            ovpn_to_endpoint(
                TCP_OVPN.replace("203.0.113.1", "203.0.113.2"),
                tag="vpngate-1"),
        ]

    @staticmethod
    def _by_tag(config):
        return {ep["tag"]: ep for ep in config["endpoints"]}

    def test_default_and_empty_keep_every_endpoint_on_demand(self) -> None:
        for persistent in (None, []):
            config = build_singbox_config(
                self._two(), persistent_tags=persistent)
            self.assertEqual(
                {"vpngate-0": True, "vpngate-1": True},
                {tag: ep["on_demand"]
                 for tag, ep in self._by_tag(config).items()})

    def test_persistent_tag_holds_its_session_only(self) -> None:
        config = build_singbox_config(self._two(),
                                      persistent_tags=["vpngate-1"])
        by_tag = self._by_tag(config)

        self.assertFalse(by_tag["vpngate-1"]["on_demand"])
        self.assertTrue(by_tag["vpngate-0"]["on_demand"])

    def test_unknown_persistent_tag_has_no_effect(self) -> None:
        config = build_singbox_config(self._two(),
                                      persistent_tags=["vpngate-9"])

        self.assertTrue(all(ep["on_demand"] for ep in config["endpoints"]))

    def test_non_persistent_endpoint_keeps_its_on_demand_false(self) -> None:
        endpoints = [
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0", on_demand=False),
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-1"),
        ]
        config = build_singbox_config(endpoints,
                                      persistent_tags=["vpngate-1"])
        by_tag = self._by_tag(config)

        self.assertFalse(by_tag["vpngate-0"]["on_demand"])
        self.assertFalse(by_tag["vpngate-1"]["on_demand"])

    def test_unknown_only_list_preserves_mixed_existing_values(self) -> None:
        endpoints = [
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0", on_demand=False),
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-1"),
        ]
        config = build_singbox_config(endpoints,
                                      persistent_tags=["vpngate-9"])

        self.assertEqual(
            {"vpngate-0": False, "vpngate-1": True},
            {tag: ep["on_demand"]
             for tag, ep in self._by_tag(config).items()})

    def test_none_and_empty_preserve_mixed_existing_values(self) -> None:
        endpoints = [
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0", on_demand=False),
            ovpn_to_endpoint(TCP_OVPN, tag="vpngate-1"),
        ]
        for persistent in (None, []):
            config = build_singbox_config(endpoints,
                                          persistent_tags=persistent)
            self.assertEqual(
                {"vpngate-0": False, "vpngate-1": True},
                {tag: ep["on_demand"]
                 for tag, ep in self._by_tag(config).items()})

    def test_absent_on_demand_defaults_true(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        del endpoint["on_demand"]
        config = build_singbox_config([endpoint],
                                      persistent_tags=["vpngate-9"])

        self.assertTrue(config["endpoints"][0]["on_demand"])

    def test_config_is_json_serializable_and_shape_is_unchanged(self) -> None:
        endpoints = self._two()
        before_keys = [set(ep) for ep in endpoints]
        config = build_singbox_config(endpoints,
                                      persistent_tags=["vpngate-1"])

        json.dumps(config)
        self.assertEqual(before_keys,
                         [set(ep) for ep in config["endpoints"]])
        by_tag = self._by_tag(config)
        self.assertIsInstance(by_tag["vpngate-1"]["on_demand"], bool)
        self.assertEqual(["proxy", "auto", "direct"],
                         [outbound["tag"] for outbound in config["outbounds"]])
        self.assertEqual("auto", config["route"]["final"])


class ExitIpFallbackTests(unittest.TestCase):
    """One unreachable IP-echo service must not condemn a node.

    A node that serves gstatic can still hang on api.ipify.org; treating that
    as "no exit ip" dropped usable nodes from the rotation pool and left the
    chain pinned to a node nothing could verify.
    """

    def test_plain_body_is_an_exit_ip(self) -> None:
        self.assertEqual("203.0.113.7", _parse_exit_ip(b"203.0.113.7\n"))

    def test_keyed_body_is_parsed(self) -> None:
        body = b"fl=abc\nh=cloudflare.com\nip=203.0.113.7\nts=1\n"
        self.assertEqual("203.0.113.7", _parse_exit_ip(body))

    def test_html_or_error_body_is_rejected(self) -> None:
        self.assertIsNone(_parse_exit_ip(b"<html>blocked</html>"))
        self.assertIsNone(_parse_exit_ip(b"ip=not-an-ip"))

    def test_first_unreachable_service_falls_through_to_the_next(self) -> None:
        replies = [None, (200, b"203.0.113.7\n", 42)]

        with mock.patch("vpngate_to_singbox._socks5_get_text",
                        side_effect=replies) as fetch:
            got = _fetch_exit_ip("127.0.0.1", 40000, timeout=5)

        self.assertEqual((200, b"203.0.113.7", 42), got)
        self.assertEqual(2, fetch.call_count)
        # The retry used a different service, not the same one twice.
        hosts = [call.args[2] for call in fetch.call_args_list]
        self.assertEqual(len(set(hosts)), 2)

    def test_all_services_unreachable_returns_none(self) -> None:
        with mock.patch("vpngate_to_singbox._socks5_get_text", return_value=None) as fetch:
            got = _fetch_exit_ip("127.0.0.1", 40000, timeout=3)

        self.assertIsNone(got)
        self.assertGreater(fetch.call_count, 1)


def _test_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=TLS_CERT)
    context.check_hostname = False
    return context


class FakeConnectProxy:
    """HTTP CONNECT proxy that then terminates TLS like an echo service."""

    def __init__(self, body: bytes = b"203.0.113.7\n",
                 bodies: dict[str, bytes] | None = None,
                 statuses: list[int] | None = None,
                 hang: bool = False) -> None:
        self.body = body
        self.bodies = bodies or {}
        self.statuses = list(statuses or [])
        self.hang = hang
        self.connects: list[str] = []
        self.requests: list[dict] = []
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.load_cert_chain(TLS_CERT, TLS_KEY)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    @staticmethod
    def _read_head(conn: socket.socket) -> bytes:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                raise OSError("eof")
            head += chunk
            if len(head) > 16384:
                raise OSError("head too large")
        return head

    @staticmethod
    def _parse_head(head: bytes) -> tuple[list[str], dict[str, str]]:
        lines = head.split(b"\r\n")
        start = lines[0].decode("ascii", errors="replace").split(" ")
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if sep:
                key = name.decode("ascii", errors="replace").strip().lower()
                headers[key] = value.decode("ascii", errors="replace").strip()
        return start, headers

    def _record(self, head: bytes) -> tuple[list[str], dict[str, str]]:
        start, headers = self._parse_head(head)
        authority = start[1] if len(start) > 1 else ""
        self.connects.append(authority)
        self.requests.append(
            {"method": start[0], "authority": authority, "headers": headers})
        return start, headers

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            target = self._hold if self.hang else self._handle
            threading.Thread(target=target, args=(conn,), daemon=True).start()

    def _hold(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            self._record(self._read_head(conn))
            while not self._stop.is_set():
                if not conn.recv(4096):
                    break
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            _start, headers = self._record(self._read_head(conn))
            status = self.statuses.pop(0) if self.statuses else 200
            if status != 200:
                conn.sendall(
                    f"HTTP/1.1 {status} Denied\r\nContent-Length: 0\r\n"
                    f"Connection: close\r\n\r\n".encode())
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                conn = self._tls_context.wrap_socket(conn, server_side=True)
            except OSError:
                return
            _get_start, get_headers = self._parse_head(self._read_head(conn))
            body = self.bodies.get(get_headers.get("host", ""), self.body)
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n".encode() + body)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class MixedExitIpTests(unittest.TestCase):
    """measure_mixed_exit_ip: CONNECT + TLS exit verification, no subprocess."""

    def _patch_tls(self):
        return mock.patch("vpngate_to_singbox._exit_ip_tls_context",
                          side_effect=_test_tls_context)

    def test_basic_auth_and_exit_ip(self) -> None:
        server = FakeConnectProxy()
        server.start()
        try:
            with self._patch_tls():
                ip, ms = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=5)
        finally:
            server.stop()

        self.assertEqual("203.0.113.7", ip)
        self.assertIsNotNone(ms)
        self.assertGreaterEqual(ms, 1)
        request = server.requests[0]
        expected_auth = "Basic " + base64.b64encode(b"u:p").decode("ascii")
        self.assertEqual("CONNECT", request["method"])
        self.assertEqual(expected_auth,
                         request["headers"]["proxy-authorization"])
        host, port, _path = EXIT_IP_TARGETS[0]
        self.assertEqual(f"{host}:{port}", request["authority"])

    def test_targets_tried_in_order_and_trace_ip_parsed(self) -> None:
        last_host = EXIT_IP_TARGETS[-1][0]
        trace = b"fl=abc\nh=cloudflare.com\nip=203.0.113.9\nts=1\n"
        server = FakeConnectProxy(body=b"<html>blocked</html>",
                                  bodies={last_host: trace})
        server.start()
        try:
            with self._patch_tls():
                ip, _ms = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=5)
        finally:
            server.stop()

        self.assertEqual("203.0.113.9", ip)
        expected = [f"{host}:{port}" for host, port, _path in EXIT_IP_TARGETS]
        self.assertEqual(expected, server.connects)

    def test_non_200_connect_falls_through_to_the_next_target(self) -> None:
        server = FakeConnectProxy(statuses=[407], body=b"198.51.100.4\n")
        server.start()
        try:
            with self._patch_tls():
                ip, _ms = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=5)
        finally:
            server.stop()

        self.assertEqual("198.51.100.4", ip)
        self.assertEqual(2, len(server.connects))

    def test_all_non_200_connects_return_none(self) -> None:
        server = FakeConnectProxy(statuses=[403] * len(EXIT_IP_TARGETS))
        server.start()
        try:
            with self._patch_tls():
                got = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=5)
        finally:
            server.stop()

        self.assertEqual((None, None), got)
        self.assertEqual(len(EXIT_IP_TARGETS), len(server.connects))

    def test_no_exit_ip_in_bodies_returns_none(self) -> None:
        server = FakeConnectProxy(body=b"<html>no ip here</html>")
        server.start()
        try:
            with self._patch_tls():
                got = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=5)
        finally:
            server.stop()

        self.assertEqual((None, None), got)
        self.assertEqual(len(EXIT_IP_TARGETS), len(server.connects))

    def test_one_timeout_budget_is_shared_by_all_targets(self) -> None:
        server = FakeConnectProxy(hang=True)
        server.start()
        started = time.monotonic()
        try:
            with self._patch_tls():
                got = measure_mixed_exit_ip(
                    "127.0.0.1", server.port, "u", "p", timeout=0.5)
        finally:
            server.stop()
        elapsed = time.monotonic() - started

        self.assertEqual((None, None), got)
        self.assertLess(elapsed, 2.0)
        self.assertEqual(1, len(server.connects))


class MultiRemoteProbeTests(unittest.TestCase):
    """A VPNGate node can carry several TCP remotes; one dead address is not
    a dead node (sing-box fails over inside the endpoint)."""

    MULTI = TCP_OVPN.replace(
        "remote 203.0.113.1 443 tcp\n",
        "remote 203.0.113.1 443 tcp\nremote 203.0.113.99 1194 tcp\n",
    )

    def test_endpoint_remotes_lists_server_then_servers_in_order(self) -> None:
        single = {"server": "203.0.113.1", "server_port": 443}
        multi = ovpn_to_endpoint(self.MULTI, tag="", username="u", password="p")

        self.assertEqual([("203.0.113.1", 443)], endpoint_remotes(single))
        self.assertEqual(
            [("203.0.113.1", 443), ("203.0.113.99", 1194)],
            endpoint_remotes(multi),
        )

    def test_probe_endpoint_latency_falls_over_to_a_live_remote(self) -> None:
        endpoint = ovpn_to_endpoint(self.MULTI, tag="", username="u", password="p")
        seen: list[str] = []

        def probe(host, port):
            seen.append(host)
            return 0 if host == "203.0.113.1" else 77

        self.assertEqual(77, probe_endpoint_latency(endpoint, probe_fn=probe))
        self.assertEqual(["203.0.113.1", "203.0.113.99"], seen)
        # A dead everything endpoint is 0, and a raising probe is not fatal.
        self.assertEqual(0, probe_endpoint_latency(
            endpoint, probe_fn=lambda host, port: 0))
        self.assertEqual(0, probe_endpoint_latency(
            endpoint, probe_fn=mock.Mock(side_effect=OSError("nope"))))

    def test_snapshot_keeps_a_node_when_only_the_failover_remote_answers(self) -> None:
        csv_text = "\n".join([
            CSV_HEADER,
            _snapshot_row_country(
                "vpn-failover", "203.0.113.1", 100,
                _b64(self.MULTI), "Japan", "JP"),
        ]) + "\n"

        nodes = snapshot_to_nodes(
            csv_text,
            probe_fn=lambda host, port: 0 if host == "203.0.113.1" else 55,
        )

        self.assertEqual(1, len(nodes))
        self.assertEqual(55, nodes[0]["latency_ms"])
        self.assertEqual("203.0.113.1", nodes[0]["server"])

    def test_snapshot_still_drops_a_node_when_every_remote_is_dead(self) -> None:
        csv_text = "\n".join([
            CSV_HEADER,
            _snapshot_row_country(
                "vpn-dead", "203.0.113.1", 100,
                _b64(self.MULTI), "Japan", "JP"),
        ]) + "\n"

        self.assertEqual([], snapshot_to_nodes(csv_text,
                                               probe_fn=lambda host, port: 0))


class BlockParserHardeningTests(unittest.TestCase):
    """P1-3: the inline-block parser must be linear and bounded."""

    def _cfg(self, extra: str = "") -> str:
        return ("client\nproto tcp-client\nremote 203.0.113.1 443 tcp\n"
                + extra)

    def test_repeated_unterminated_ca_is_linear_and_raises(self) -> None:
        text = self._cfg("<ca>\n" * 1000)
        started = time.monotonic()
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_sixty_four_kib_blank_lines_parse_quickly(self) -> None:
        text = ("\n" * (64 * 1024)
                + "client\nproto tcp-client\nremote 203.0.113.1 443 tcp\n"
                + "<ca>\nQ0E=\n</ca>\n")
        started = time.monotonic()
        endpoint = ovpn_to_endpoint(text, tag="blank-lines")
        elapsed = time.monotonic() - started

        self.assertEqual("203.0.113.1", endpoint["server"])
        # Deliberately loose: the bug was ~110 seconds, not a few ms.
        self.assertLess(elapsed, 1.0)

    def test_overlong_config_line_is_rejected_and_counted(self) -> None:
        import vpngate_to_singbox as mod

        before = mod._OVERSIZED_CONFIG_LINE_COUNT
        text = "client\n" + "A" * (MAX_CONFIG_LINE_BYTES + 1) + "\n"
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")
        self.assertEqual(before + 1, mod._OVERSIZED_CONFIG_LINE_COUNT)

    def test_unterminated_block_raises(self) -> None:
        text = TCP_OVPN.replace("</ca>\n", "")
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")

    def test_oversized_block_is_rejected(self) -> None:
        text = self._cfg("<ca>\n" + "A" * (MAX_BLOCK_BYTES + 1) + "\n</ca>\n")
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")

    def test_oversized_config_is_rejected(self) -> None:
        text = TCP_OVPN + "A" * MAX_CONFIG_BYTES
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")

    def test_non_pem_block_content_is_rejected(self) -> None:
        text = self._cfg("<ca>\n<script>alert(1)</script>\n</ca>\n")
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(text, tag="x")

    def test_single_line_block_still_parses(self) -> None:
        text = self._cfg("<ca>Q0E=</ca>\n")
        endpoint = ovpn_to_endpoint(text, tag="x")
        self.assertEqual("Q0E=", endpoint["tls"]["certificate"])


class RemoteLimitTests(unittest.TestCase):
    """P1-4 / R3-07: bounded, deduped and correctly merged remotes."""

    @staticmethod
    def _cfg(remotes: list[tuple[str, int]], proto: str = "tcp-client") -> str:
        lines = ["client", f"proto {proto}"]
        lines.extend(f"remote {host} {port} tcp" for host, port in remotes)
        lines.extend(["<ca>", "Q0E=", "</ca>"])
        return "\n".join(lines) + "\n"

    def test_more_than_eight_remotes_raises(self) -> None:
        remotes = [(f"203.0.113.{i + 1}", 443) for i in range(9)]
        with self.assertRaises(ValueError):
            _all_tcp_remotes(self._cfg(remotes))

    def test_duplicate_remotes_are_deduped_in_order(self) -> None:
        remotes = [("203.0.113.1", 443), ("203.0.113.2", 1194),
                   ("203.0.113.1", 443)]
        self.assertEqual(
            [("203.0.113.1", 443), ("203.0.113.2", 1194)],
            _all_tcp_remotes(self._cfg(remotes)))

    def test_inherited_global_tcp_remote_is_not_dropped(self) -> None:
        text = ("client\nproto tcp-client\n"
                "remote 203.0.113.1 443\n"
                "remote 203.0.113.2 443 tcp\n"
                "<ca>\nQ0E=\n</ca>\n")
        self.assertEqual(
            [("203.0.113.1", 443), ("203.0.113.2", 443)],
            _all_tcp_remotes(text))

    def test_explicit_udp_remote_is_excluded(self) -> None:
        text = ("client\nproto tcp-client\n"
                "remote 203.0.113.1 443\n"
                "remote 203.0.113.2 1194 udp\n"
                "remote 203.0.113.3 443 tcp\n"
                "<ca>\nQ0E=\n</ca>\n")
        self.assertEqual(
            [("203.0.113.1", 443), ("203.0.113.3", 443)],
            _all_tcp_remotes(text))

    def test_server_fields_rejects_more_than_eight(self) -> None:
        with self.assertRaises(ValueError):
            _server_fields([(f"203.0.113.{i + 1}", 443) for i in range(9)])

    def test_probe_endpoint_latency_has_a_total_budget(self) -> None:
        endpoint = {"servers": [
            {"server": f"203.0.113.{i + 1}", "server_port": 443}
            for i in range(20)
        ]}
        calls: list[str] = []

        def slow_probe(host: str, port: int) -> int:
            calls.append(host)
            time.sleep(0.2)
            return 0

        started = time.monotonic()
        result = probe_endpoint_latency(endpoint, timeout=0.3, probe_fn=slow_probe)
        elapsed = time.monotonic() - started

        self.assertEqual(0, result)
        self.assertLess(len(calls), 20)
        self.assertLess(elapsed, 1.5)


class PrivateRemoteTests(unittest.TestCase):
    """P1-6: private/loopback/metadata remotes are rejected by default."""

    @staticmethod
    def _cfg(host: str, port: int = 443) -> str:
        return TCP_OVPN.replace("remote 203.0.113.1 443 tcp",
                                f"remote {host} {port} tcp")

    def test_forbidden_literals_are_rejected(self) -> None:
        for host in ("127.0.0.1", "169.254.169.254", "10.1.2.3",
                     "192.168.1.5", "0.0.0.0", "[::1]"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    ovpn_to_endpoint(self._cfg(host), tag="x")

    def test_out_of_range_port_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(self._cfg("203.0.113.1", 70000), tag="x")

    def test_allow_private_remotes_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"ALLOW_PRIVATE_REMOTES": "1"}):
            endpoint = ovpn_to_endpoint(self._cfg("127.0.0.1", 22), tag="x")
        self.assertEqual("127.0.0.1", endpoint["server"])
        self.assertEqual(22, endpoint["server_port"])

    def test_domain_is_rejected_without_dns(self) -> None:
        with mock.patch("vpngate_to_singbox.socket.getaddrinfo") as resolver:
            with self.assertRaises(ValueError):
                _validate_remote("evil.example", 443)
        resolver.assert_not_called()

    def test_domain_config_is_rejected_at_parse_time(self) -> None:
        with self.assertRaises(ValueError):
            ovpn_to_endpoint(self._cfg("evil.example"), tag="x")

    def test_six_to_four_and_teredo_are_rejected(self) -> None:
        for host in (
            "2002:a9fe:a9fe::1",  # 6to4 embedding 169.254.169.254
            "2002:7f00:1::",      # 6to4 embedding 127.0.0.1
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
            "2001::1",
            "2001:db8::1",
            "64:ff9b::a9fe:a9fe",  # NAT64 embedding 169.254.169.254
            "192.88.99.1",         # 6to4 relay anycast
        ):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    _validate_remote(host, 443)
                with self.assertRaises(ValueError):
                    ovpn_to_endpoint(self._cfg(host), tag="x")

    def test_public_literal_is_pinned_and_allowed(self) -> None:
        self.assertEqual(("8.8.8.8", 443), _validate_remote("8.8.8.8", 443))
        self.assertEqual(("203.0.113.1", 443),
                         _validate_remote("203.0.113.1", 443))


class _TrickleSocks5Server:
    """SOCKS5 handshake that then sends its CONNECT reply one byte at a time."""

    def __init__(self, interval: float = 0.3) -> None:
        self.interval = interval
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def _serve(self) -> None:
        try:
            conn, _ = self._listener.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            head = conn.recv(2)
            if len(head) < 2:
                return
            conn.recv(head[1])
            conn.sendall(b"\x05\x00")
            conn.recv(16)
            for byte in b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00":
                if self._stop.is_set():
                    break
                conn.sendall(bytes([byte]))
                time.sleep(self.interval)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class ResolverTimeoutTests(unittest.TestCase):
    """R2-5-06: getaddrinfo has no timeout of its own."""

    def test_slow_lookup_is_abandoned_at_the_timeout(self) -> None:
        def slow(*_args, **_kwargs):
            time.sleep(1.0)
            return []

        started = time.monotonic()
        with mock.patch("vpngate_to_singbox.socket.getaddrinfo", side_effect=slow):
            with self.assertRaises(TimeoutError):
                _resolve_with_timeout("slow.example", timeout=0.15)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_deadline_shrinks_the_lookup_budget(self) -> None:
        def slow(*_args, **_kwargs):
            time.sleep(1.0)
            return []

        started = time.monotonic()
        with mock.patch("vpngate_to_singbox.socket.getaddrinfo", side_effect=slow):
            with self.assertRaises(TimeoutError):
                _resolve_with_timeout(
                    "slow.example", timeout=3.0,
                    deadline=time.monotonic() + 0.1)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_literal_host_needs_no_lookup(self) -> None:
        with mock.patch("vpngate_to_singbox.socket.getaddrinfo") as resolver:
            self.assertEqual(["8.8.8.8"], _resolve_with_timeout("8.8.8.8"))
        resolver.assert_not_called()


class EndpointPinTests(unittest.TestCase):
    def test_domain_endpoint_is_denied_at_every_layer(self) -> None:
        endpoint = {"server": "evil.example", "server_port": 443}
        self.assertFalse(_endpoint_remotes_allowed(endpoint))
        self.assertFalse(_endpoint_remotes_allowed(
            endpoint, deadline=time.monotonic() + 1))

    def test_expired_deadline_denies_before_validation(self) -> None:
        endpoint = {"server": "8.8.8.8", "server_port": 443}
        self.assertFalse(_endpoint_remotes_allowed(
            endpoint, deadline=time.monotonic() - 1))


class DeadlineTests(unittest.TestCase):
    """P1-5: one absolute deadline per read, not one per recv()."""

    def test_recv_exact_deadline_bounds_a_trickle(self) -> None:
        client, server = socket.socketpair()
        stop = threading.Event()

        def drip() -> None:
            for _ in range(10):
                if stop.is_set():
                    break
                try:
                    server.send(b"x")
                except OSError:
                    break
                time.sleep(0.3)

        threading.Thread(target=drip, daemon=True).start()
        started = time.monotonic()
        try:
            with self.assertRaises(OSError):
                _recv_exact(client, 10, deadline=time.monotonic() + 0.5)
        finally:
            stop.set()
            client.close()
            server.close()
        self.assertLess(time.monotonic() - started, 1.5)

    def test_socks5_get_text_returns_none_on_a_slow_drip(self) -> None:
        server = _TrickleSocks5Server()
        server.start()
        started = time.monotonic()
        try:
            got = _socks5_get_text("127.0.0.1", server.port, timeout=0.5)
        finally:
            server.stop()
        self.assertIsNone(got)
        self.assertLess(time.monotonic() - started, 1.5)


class MeasureGateTests(unittest.TestCase):
    def test_measure_returns_none_when_the_gate_times_out(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="gate-timeout")
        gate = mock.Mock()
        gate.acquire.return_value = False
        with mock.patch("vpngate_to_singbox._DIAL_GATE", gate), \
             mock.patch("vpngate_to_singbox.subprocess.Popen") as popen:
            self.assertIsNone(measure_real_latency(endpoint, timeout=5))
            self.assertEqual((None, None), measure_exit_ip(endpoint, timeout=5))
        popen.assert_not_called()
        gate.release.assert_not_called()

    def test_expired_deadline_returns_before_acquiring_the_gate(self) -> None:
        import vpngate_to_singbox as mod

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="deadline-expired")
        gate = mock.Mock()
        with mock.patch.object(mod, "_DIAL_GATE", gate):
            self.assertIsNone(mod.measure_real_latency(
                endpoint, deadline=time.monotonic() - 1))
            self.assertEqual((None, None), mod.measure_exit_ip(
                endpoint, deadline=time.monotonic() - 1))
            self.assertIsNone(mod.measure_resi_rotate(
                "uuid", 40000, "/ws-resi",
                deadline=time.monotonic() - 1))
        gate.acquire.assert_not_called()

    def test_resi_rotate_gate_uses_the_remaining_deadline(self) -> None:
        import vpngate_to_singbox as mod

        gate = mock.Mock()
        gate.acquire.return_value = False
        tmpdir = mock.Mock()
        with mock.patch.object(mod, "_DIAL_GATE", gate), \
             mock.patch.object(mod.tempfile, "TemporaryDirectory",
                               return_value=tmpdir), \
             mock.patch.object(mod, "_free_port", return_value=40123):
            deadline = time.monotonic() + 4.0
            self.assertIsNone(mod.measure_resi_rotate(
                "uuid", 40000, "/ws-resi", timeout=20, deadline=deadline))
        timeout = gate.acquire.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 3.0)
        self.assertLessEqual(timeout, 4.0)
        tmpdir.cleanup.assert_called_once()

    def test_temporary_directory_failure_releases_the_gate(self) -> None:
        import vpngate_to_singbox as mod

        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="tmp-failure")
        before = mod._DIAL_GATE._value
        with mock.patch.object(mod.tempfile, "TemporaryDirectory",
                               side_effect=OSError("no tmp")):
            with self.assertRaises(OSError):
                mod.measure_real_latency(endpoint, timeout=1)
            with self.assertRaises(OSError):
                mod.measure_exit_ip(endpoint, timeout=1)
        self.assertEqual(before, mod._DIAL_GATE._value)


class TemplateErrorTests(unittest.TestCase):
    def test_attribute_error_becomes_value_error(self) -> None:
        with self.assertRaises(ValueError):
            render_resi_username("u", "{session}{user.name}", 60, "s")

    def test_allowed_placeholders_render(self) -> None:
        self.assertEqual("u-s-60",
                         render_resi_username("u", "{user}-{session}-{ttl}",
                                              60, "s"))

    def test_non_string_inputs_do_not_leak_attribute_error(self) -> None:
        self.assertEqual("123", render_resi_username(123, None, 0))
        self.assertEqual("u", render_resi_username("u", 123, 60))
        self.assertEqual("u-s-60",
                         render_resi_username("u", "{user}-{session}-{ttl}",
                                              "60", "s"))

    def test_invalid_ttl_becomes_value_error(self) -> None:
        with self.assertRaises(ValueError):
            render_resi_username("u", "{session}", "not-a-number")
        with self.assertRaises(ValueError):
            render_resi_username("u", "{session}", True)

    def test_unstringable_template_becomes_value_error(self) -> None:
        class Bad:
            def __str__(self):
                raise RuntimeError("nope")

        with self.assertRaises(ValueError):
            render_resi_username("u", Bad(), 60)


class TagUniquenessTests(unittest.TestCase):
    @staticmethod
    def _node(tag: str, host: str) -> dict:
        return {"endpoint": ovpn_to_endpoint(
            TCP_OVPN.replace("203.0.113.1", host), tag=tag)}

    def test_duplicate_tags_are_renamed(self) -> None:
        nodes = [self._node("x", "203.0.113.1"),
                 self._node("x", "203.0.113.2")]
        endpoints = nodes_to_endpoints(nodes)
        tags = [ep["tag"] for ep in endpoints]
        self.assertEqual(len(tags), len(set(tags)))
        self.assertEqual("x", tags[0])

    def test_explicit_tags_are_reserved_before_untagged_allocation(self) -> None:
        nodes = [self._node("", "203.0.113.1"),
                 self._node("vpngate-0", "203.0.113.2")]
        tags = [ep["tag"] for ep in nodes_to_endpoints(nodes)]

        # The untagged first node must not steal the later stable tag.
        self.assertEqual(["vpngate-1", "vpngate-0"], tags)

    def test_reserved_tags_are_renamed(self) -> None:
        nodes = [self._node("auto", "203.0.113.1"),
                 self._node("direct", "203.0.113.2"),
                 self._node("vless-chain", "203.0.113.3"),
                 self._node("proxy", "203.0.113.4")]
        tags = [ep["tag"] for ep in nodes_to_endpoints(nodes)]
        self.assertEqual(len(tags), len(set(tags)))
        for tag in tags:
            self.assertNotIn(tag, {"auto", "direct", "proxy"})
            self.assertFalse(tag.startswith("vless-"))

    def test_reserved_prefix_falls_back(self) -> None:
        node = self._node("", "203.0.113.1")
        tags = [ep["tag"] for ep in nodes_to_endpoints([node],
                                                       tag_prefix="vless")]
        self.assertEqual(["vpngate-0"], tags)


class SnapshotLimitTests(unittest.TestCase):
    def test_oversized_snapshot_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            snapshot_to_nodes("x" * (MAX_SNAPSHOT_BYTES + 1), probe=False)

    def test_too_many_rows_are_rejected_before_splitlines(self) -> None:
        with self.assertRaises(ValueError):
            snapshot_to_nodes("x\n" * 5001, probe=False)

    def test_limit_is_an_output_cap_not_a_parse_window(self) -> None:
        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 + i,
                          _b64(TCP_OVPN.replace("203.0.113.1",
                                                f"203.0.113.{100 + i}")))
            for i in range(10)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        with mock.patch("vpngate_to_singbox.ovpn_to_endpoint",
                        wraps=ovpn_to_endpoint) as parser:
            nodes = snapshot_to_nodes(csv_text, limit=2, probe=False)

        self.assertEqual(2, len(nodes))
        # Every row is decoded; limit only trims the ranked output.
        self.assertEqual(10, parser.call_count)
        self.assertEqual(["203.0.113.109", "203.0.113.108"],
                         [n["server"] for n in nodes])

    def test_limit_two_returns_speed_top_two(self) -> None:
        speeds = [1, 2, 900, 800]
        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", speed,
                          _b64(TCP_OVPN.replace("203.0.113.1",
                                                f"203.0.113.{100 + i}")))
            for i, speed in enumerate(speeds)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        nodes = snapshot_to_nodes(csv_text, limit=2, probe=False)

        self.assertEqual([900, 800], [n["speed"] for n in nodes])

    def test_probe_searches_the_full_ranked_pool(self) -> None:
        rows = [
            _snapshot_row(f"vpn-{i}", f"203.0.113.{100 + i}", 1000 - i,
                          _b64(TCP_OVPN.replace("203.0.113.1",
                                                f"203.0.113.{100 + i}")))
            for i in range(20)
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        def probe(host: str, port: int) -> int:
            return 0 if int(host.rsplit(".", 1)[1]) < 108 else 55

        nodes = snapshot_to_nodes(
            csv_text, limit=1, probe=True, probe_pool=0, probe_fn=probe)

        self.assertEqual(1, len(nodes))
        self.assertGreaterEqual(int(nodes[0]["server"].rsplit(".", 1)[1]), 108)

    def test_eight_mib_snapshot_is_rejected_quickly(self) -> None:
        # 4999 non-empty rows just under the 8 MiB byte cap: line count passes,
        # so this exercises the full split/CSV path rather than the byte gate.
        csv_text = ("x" * 1600 + "\n") * 4999
        self.assertLessEqual(len(csv_text.encode("utf-8")), MAX_SNAPSHOT_BYTES)
        started = time.monotonic()
        with self.assertRaises(ValueError):
            snapshot_to_nodes(csv_text, probe=False)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_splitlines_separators_cannot_bypass_the_row_cap(self) -> None:
        for separator in ("\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d",
                          "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                with self.assertRaises(ValueError):
                    _check_snapshot_limits("x" + separator * (MAX_SNAPSHOT_ROWS + 1))
        _check_snapshot_limits("x\u2028" * MAX_SNAPSHOT_ROWS)

    def test_failed_rows_consume_the_row_budget(self) -> None:
        domain_config = TCP_OVPN.replace(
            "remote 203.0.113.1 443 tcp", "remote evil.example 443 tcp")
        good = TCP_OVPN.replace("203.0.113.1", "203.0.113.200")
        rows = [
            _snapshot_row("vpn-bad1", "203.0.113.201", 100, _b64(domain_config)),
            _snapshot_row("vpn-bad2", "203.0.113.202", 100, _b64(domain_config)),
            _snapshot_row("vpn-good", "203.0.113.200", 900, _b64(good)),
        ]
        csv_text = CSV_HEADER + "\n" + "\n".join(rows) + "\n"

        # Two failed rows consume limit=2, so the good third row is never seen.
        with self.assertRaises(ValueError):
            list(_iter_tcp_candidates(csv_text, limit=2))
        self.assertEqual(1, len(list(_iter_tcp_candidates(csv_text, limit=3))))


class CliOutputTests(unittest.TestCase):
    def test_cli_output_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "out.json")
            rc = main(["--input", str(FIXTURE_DIR / "vpngate_tcp_sample.ovpn"),
                       "--output", output])
            self.assertEqual(0, rc)
            self.assertTrue(os.path.exists(output))
            if os.name != "nt":
                self.assertEqual(0o600, stat.S_IMODE(os.stat(output).st_mode))


if __name__ == "__main__":
    unittest.main()
