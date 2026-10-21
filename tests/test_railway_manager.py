"""Tests for railway_manager ($PORT multiplexer + sing-box supervisor)."""
import base64
import contextlib
import inspect
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from railway_manager import (UI_HTML, RailwayManager, _cpu_model, _cpu_pct,
                               _cpu_times, _mem_pct, build_config_from_env,
                               classify_first_bytes, default_fetch)
from vpngate_to_singbox import (build_singbox_config, measure_exit_ip,
                                measure_real_latency, nodes_to_endpoints,
                                ovpn_to_endpoint, snapshot_to_endpoints,
                                snapshot_to_nodes)


@contextlib.contextmanager
def _fake_singbox():
    """Stub out process launch + config check (no sing-box binary in unit tests)."""
    with mock.patch("railway_manager.subprocess.Popen"), \
         mock.patch.object(RailwayManager, "_check_config", return_value=True):
        yield


def _settle_probes(manager) -> None:
    """Wait for the background probe passes to finish.

    `refresh_once` starts a background full probe, and that probe writes its
    dial results back into the node dicts: a failed dial clears
    `real_latency_ms` (railway_manager.py:3517). A test that seeds
    measurements by hand must let the probe finish first, otherwise both
    write the same dicts and the verdict depends on who wins the race - which
    is how a Windows run passed while a Linux CI run failed.
    """
    for attr in ("_full_probe_thread", "_single_probe_thread"):
        thread = getattr(manager, attr, None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=30)


def get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _read_json(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


TCP_OVPN = """\
client
dev tun
proto tcp-client
remote 203.0.113.1 443 tcp
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
Q0E=
-----END CERTIFICATE-----
</ca>
"""


def _snapshot_csv(*ips: str) -> str:
    header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
    rows = []
    for i, ip in enumerate(ips):
        config = base64.b64encode(TCP_OVPN.replace("203.0.113.1", ip).encode()).decode()
        rows.append(f"vpn-{i},{ip},100,20,{1000 + i},Japan,JP,1,{config}")
    return header + "\n" + "\n".join(rows) + "\n"


# Per-test config/state files live in the platform temp dir: drive-root
# /tmp does not exist/writable on Windows, and POSIX still gets /tmp.
_TMP = tempfile.gettempdir()

class ClassifyTests(unittest.TestCase):
    def test_socks5_greeting(self) -> None:
        self.assertEqual("socks5", classify_first_bytes(b"\x05\x01\x00"))

    def test_http_connect(self) -> None:
        self.assertEqual("http-connect", classify_first_bytes(b"CONNECT example.com:443 HTTP/1.1\r\n"))

    def test_http_get(self) -> None:
        self.assertEqual("http", classify_first_bytes(b"GET /healthz HTTP/1.1\r\n"))

    def test_empty_is_unknown(self) -> None:
        self.assertEqual("unknown", classify_first_bytes(b""))

    def test_tls_is_unknown(self) -> None:
        self.assertEqual("unknown", classify_first_bytes(b"\x16\x03\x01\x00\x80"))


class MixedUsersTests(unittest.TestCase):
    def test_users_injected_into_mixed_inbound(self) -> None:
        endpoint = ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")
        cfg = build_singbox_config(
            [endpoint], mixed_listen="127.0.0.1", mixed_port=40000,
            mixed_users=[("u", "p")],
        )

        users = cfg["inbounds"][0]["users"]
        self.assertEqual([{"username": "u", "password": "p"}], users)


class MultiplexerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
        )
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _request(self, method: str, path: str, body: bytes | None = None,
                 token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def _get(self, path: str) -> bytes:
        return self._request("GET", path)

    def test_healthz_returns_ok_when_healthy(self) -> None:
        self.manager.status["endpoints"] = [
            {"tag": "vpngate-0", "server": "203.0.113.11", "server_port": 443}]
        response = self._get("/healthz")

        self.assertIn(b"200 OK", response)
        self.assertTrue(response.rstrip().endswith(b"ok"))

    def test_healthz_returns_503_without_endpoints(self) -> None:
        response = self._get("/healthz")

        self.assertIn(b"503", response)

    def test_status_returns_json(self) -> None:
        response = self._get("/api/status")
        body = response.split(b"\r\n\r\n", 1)[1]

        status = json.loads(body.decode())
        self.assertIn("endpoints", status)
        self.assertIn("last_refresh", status)

    def test_ui_returns_html(self) -> None:
        response = self._get("/ui")

        self.assertIn(b"200 OK", response)
        self.assertIn(b"text/html", response)
        self.assertIn(b"/api/status", response)

    def test_unknown_path_returns_404(self) -> None:
        response = self._get("/nope")

        self.assertIn(b"404", response)

    def test_socks5_dispatch_closes_when_backend_down(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            sock.sendall(b"\x05\x01\x00")
            sock.settimeout(5)
            data = sock.recv(16)

        self.assertEqual(b"", data)


class DisguiseRootTests(unittest.TestCase):
    MARKER = "<!-- disguise-page-marker -->"

    def _manager(self, disguise_path: str) -> RailwayManager:
        return RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            disguise_path=disguise_path,
        )

    def _get_root(self, manager: RailwayManager, port: int) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_root_serves_disguise_file(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(f"<html><body>{self.MARKER}</body></html>")
            path = handle.name
        manager = self._manager(path)
        port = manager.start()
        try:
            response = self._get_root(manager, port)
        finally:
            manager.stop()
            os.unlink(path)

        self.assertIn(b"200 OK", response)
        self.assertIn(self.MARKER.encode(), response)
        self.assertNotIn(b"/api/status", response)

    def test_root_falls_back_to_console_without_disguise_file(self) -> None:
        manager = self._manager("/nonexistent/disguise.html")
        port = manager.start()
        try:
            response = self._get_root(manager, port)
        finally:
            manager.stop()

        self.assertIn(b"200 OK", response)
        self.assertIn(b"/api/status", response)

    def test_ui_still_serves_console_when_disguise_set(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(f"<html><body>{self.MARKER}</body></html>")
            path = handle.name
        manager = self._manager(path)
        port = manager.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with sock:
                sock.sendall(b"GET /ui HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        finally:
            manager.stop()
            os.unlink(path)

        self.assertIn(b"200 OK", response)
        self.assertIn(b"/api/status", response)


class RefreshTests(unittest.TestCase):
    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        config_path=f"{_TMP}/railway-test-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-test-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-test-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_refresh_once_updates_status_and_restarts_singbox(self) -> None:
        manager = self._manager(start_singbox=True)
        try:
            with mock.patch("railway_manager.subprocess.Popen") as popen, \
                 mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100), \
                 mock.patch.object(manager, "verify_fn",
                                   side_effect=lambda ep: ("9.9.9.9", 11)):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11", "203.0.113.12"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual(["vpngate-0", "vpngate-1"],
                         [ep["tag"] for ep in manager.status["endpoints"]])
        self.assertIsNotNone(manager.status["last_refresh"])
        self.assertIsNone(manager.status["last_error"])
        # One serving restart; the gated full probe may additionally dial
        # (throwaway processes) but must never restart serving twice.
        serving = [c for c in popen.call_args_list
                   if "dial.json" not in str(c)]
        self.assertEqual(1, len(serving))

    def test_refresh_failure_keeps_old_endpoints(self) -> None:
        manager = self._manager(retry_delays=(0, 0))
        manager.status["endpoints"] = [{"tag": "old"}]
        try:
            def boom(url, timeout):
                raise TimeoutError("network down")

            ok = manager.refresh_once(fetcher=boom)
        finally:
            manager.stop()

        self.assertFalse(ok)
        self.assertEqual([{"tag": "old"}], manager.status["endpoints"])
        self.assertIn("network down", manager.status["last_error"])

    def test_refresh_passes_real_topk_and_reports_real_latency(self) -> None:
        dialed: list[str] = []
        real_by_server = {"203.0.113.12": 50}

        def fake_dial(node):
            dialed.append(node["server"])
            return real_by_server.get(node["server"])

        manager = self._manager(real_topk=2, dial_fn=fake_dial)
        try:
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100), \
                 mock.patch.object(manager, "verify_fn",
                                   side_effect=lambda ep: ("9.9.9.9", 11)):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv(
                        "203.0.113.11", "203.0.113.12", "203.0.113.13"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        servers = [ep["server"] for ep in manager.status["endpoints"]]
        reals = [ep["real_latency_ms"] for ep in manager.status["endpoints"]]
        # handshake ties break by speed desc, so .13/.12 are dialed at
        # refresh stage; the gated full probe then dials every node.
        # measured .12 sorts first and tags follow final order
        self.assertEqual({"203.0.113.13", "203.0.113.12", "203.0.113.11"},
                         set(dialed))
        self.assertEqual(["203.0.113.12", "203.0.113.13", "203.0.113.11"], servers)
        self.assertEqual([50, None, None], reals)

    def test_first_seen_pruned_to_current_nodes(self) -> None:
        manager = self._manager()
        manager._first_seen = {
            "203.0.113.11:443": "2020-01-01T00:00:00Z",  # still present: keep stamp
            "198.51.100.99:443": "2020-01-01T00:00:00Z",  # vanished: prune
        }
        try:
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency", return_value=100):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11", "203.0.113.12"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual("2020-01-01T00:00:00Z",
                         manager._first_seen.get("203.0.113.11:443"))
        self.assertNotIn("198.51.100.99:443", manager._first_seen)
        self.assertIn("203.0.113.12:443", manager._first_seen)

    def test_refresh_full_scans_every_candidate(self) -> None:
        manager = self._manager()
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            return_value=[]) as snapshot_mock:
                manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11"))
        finally:
            manager.stop()

        _, kwargs = snapshot_mock.call_args
        self.assertEqual(0, kwargs.get("probe_pool"))

    def test_refresh_once_accepts_probe_pool_override(self) -> None:
        manager = self._manager()
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            return_value=[]) as snapshot_mock:
                manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11"),
                    probe_pool=30)
        finally:
            manager.stop()

        _, kwargs = snapshot_mock.call_args
        self.assertEqual(30, kwargs.get("probe_pool"))

    def test_initial_refresh_discovers_all_nodes(self) -> None:
        manager = self._manager()
        try:
            with mock.patch.object(RailwayManager, "_boot_from_last_good",
                                   return_value=False), \
                 mock.patch.object(RailwayManager, "refresh_once",
                                   return_value=True) as refresh_mock:
                manager._initial_refresh()
                if manager._refresh_thread is not None:
                    manager._refresh_thread.join(timeout=60)
        finally:
            manager.stop()

        _, kwargs = refresh_mock.call_args
        self.assertEqual(0, kwargs.get("probe_pool", 0))

    def test_initial_refresh_loads_beyond_first_pool_chunk(self) -> None:
        ips = [f"198.51.100.{i}" for i in range(1, 41)]
        manager = self._manager(
            fetcher=lambda url, timeout: _snapshot_csv(*ips))
        try:
            with mock.patch.object(RailwayManager, "_boot_from_last_good",
                                   return_value=False), \
                 mock.patch.object(RailwayManager, "_check_config",
                                   return_value=True), \
                 mock.patch("railway_manager.probe_tcp_latency",
                            return_value=100):
                manager._initial_refresh()
                if manager._refresh_thread is not None:
                    manager._refresh_thread.join(timeout=60)
            count = len(manager._nodes)
            endpoint_count = len(manager.status["endpoints"])
        finally:
            manager.stop()

        self.assertEqual(40, count)
        self.assertEqual(40, endpoint_count)


class FullProbeTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-probe-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-probe-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-probe-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000} for ip in ips]

    def test_full_probe_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post(manager, "/api/full_probe", token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_full_probe_busy_when_already_running(self) -> None:
        manager = self._manager(dial_fn=lambda node: time.sleep(0.5) or 50)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, body = self._post(manager, "/api/full_probe", token=True)
            self.assertIn("202", status_line)
            status2, body2 = self._post(manager, "/api/full_probe", token=True)
            manager._full_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIn("409", status2)
        self.assertFalse(json.loads(body2.decode()).get("accepted", True))

    def test_full_probe_accepts_and_runs_in_background(self) -> None:
        manager = self._manager(dial_fn=lambda node: 50)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            status_line, body = self._post(manager, "/api/full_probe", token=True)
            accepted_state = manager.status["full_probe"]["state"]
            manager._full_probe_thread.join(timeout=30)
            final_state = manager.status["full_probe"]["state"]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual("running", accepted_state)
        self.assertEqual("done", final_state)
        self.assertEqual(2, manager.status["full_probe"]["done"])
        self.assertEqual(2, manager.status["full_probe"]["total"])

    def test_full_probe_fills_real_latency_for_every_node(self) -> None:
        manager = self._manager(dial_fn=lambda node: 77)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            self._post(manager, "/api/full_probe", token=True)
            manager._full_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual([77, 77],
                         [n["real_latency_ms"] for n in manager._nodes])
        self.assertEqual([77, 77],
                         [ep["real_latency_ms"]
                          for ep in manager.status["endpoints"]])

    def test_default_dial_fn_measures_real(self) -> None:
        manager = self._manager()
        try:
            dial_fn = manager.dial_fn
        finally:
            manager.stop()

        self.assertIsNotNone(dial_fn)


class FullProbeWorkersTests(unittest.TestCase):
    """Full probe dials concurrently (default 3, FULL_PROBE_WORKERS)."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-fpw-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-fpw-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-fpw-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000} for ip in ips]

    def test_full_probe_dials_concurrently(self) -> None:
        state = {"cur": 0, "max": 0, "lock": threading.Lock(),
                 "go": threading.Event()}

        def dial(node):
            with state["lock"]:
                state["cur"] += 1
                state["max"] = max(state["max"], state["cur"])
                if state["cur"] >= 5:
                    state["go"].set()
            state["go"].wait(timeout=10)
            with state["lock"]:
                state["cur"] -= 1
            return 50

        manager = self._manager(dial_fn=dial, full_probe_workers=5)
        try:
            self._seed_nodes(manager,
                             *[f"198.51.100.{i}" for i in range(1, 11)])
            self._post(manager, "/api/full_probe")
            manager._full_probe_thread.join(timeout=30)
            results = [n["real_latency_ms"] for n in manager._nodes]
            done = manager.status["full_probe"]["done"]
            final = manager.status["full_probe"]["state"]
        finally:
            manager.stop()

        self.assertEqual(5, state["max"])
        self.assertEqual([50] * 10, results)
        self.assertEqual(10, done)
        self.assertEqual("done", final)

    def test_full_probe_workers_default_and_env(self) -> None:
        base = {"PORT": "3000", "PROXY_USER": "u",
                "PROXY_PASS": "0123456789abcdef"}
        self.assertEqual(3, build_config_from_env(dict(base))["full_probe_workers"])
        override = dict(base, FULL_PROBE_WORKERS="2")
        self.assertEqual(2, build_config_from_env(override)["full_probe_workers"])

    def test_full_probe_workers_clamped_to_one(self) -> None:
        manager = self._manager(full_probe_workers=0)
        try:
            workers = manager.full_probe_workers
        finally:
            manager.stop()

        self.assertEqual(1, workers)


class SingleProbeTests(unittest.TestCase):
    """POST /api/probe dials one untried node; success auto-marks it usable."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-single-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-single-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-single-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post_json(self, manager, path, payload, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = json.dumps(payload).encode()
        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: {len(raw)}\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1") + raw)
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}"}}
                          for i, ip in enumerate(ips)]

    def test_probe_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post_json(manager, "/api/probe",
                                             {"tag": "vpngate-0"}, token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_probe_unknown_tag_returns_404(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, body = self._post_json(manager, "/api/probe",
                                                {"tag": "vpngate-9"})
        finally:
            manager.stop()

        self.assertIn("404", status_line)
        self.assertFalse(json.loads(body.decode())["ok"])

    def test_probe_missing_tag_returns_400(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, _ = self._post_json(manager, "/api/probe", {})
        finally:
            manager.stop()

        self.assertIn("400", status_line)

    def test_probe_dials_only_the_requested_node(self) -> None:
        calls = []
        manager = self._manager(
            dial_fn=lambda node: calls.append(node["server"]) or 123)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            status_line, body = self._post_json(manager, "/api/probe",
                                                {"tag": "vpngate-1"})
            manager._single_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual(["203.0.113.12"], calls)
        self.assertIsNone(manager._nodes[0]["real_latency_ms"])
        self.assertEqual(123, manager._nodes[1]["real_latency_ms"])
        probe = manager.status["probe"]
        self.assertEqual("done", probe["state"])
        self.assertEqual("vpngate-1", probe["tag"])
        self.assertEqual(123, probe["ms"])

    def test_probe_failure_keeps_none_and_records_error(self) -> None:
        def _boom(node):
            raise RuntimeError("tunnel down")

        manager = self._manager(dial_fn=_boom)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, _ = self._post_json(manager, "/api/probe",
                                             {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
            history = [h["event"] for h in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertIsNone(manager._nodes[0]["real_latency_ms"])
        self.assertEqual("done", manager.status["probe"]["state"])
        self.assertTrue(manager.status["probe"]["error"])
        self.assertIn("single-probe", history)


class AuthTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
        )
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _request(self, method: str, path: str, body: bytes | None = None,
                 token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_status_without_token_is_401(self) -> None:
        self.assertIn(b"401", self._request("GET", "/api/status"))

    def test_status_with_wrong_token_is_401(self) -> None:
        self.assertIn(b"401", self._request("GET", "/api/status", token="nope"))

    def test_status_with_token_is_200(self) -> None:
        self.assertIn(b"200 OK", self._request("GET", "/api/status", token=self.TOKEN))

    def test_healthz_needs_no_token(self) -> None:
        self.manager.status["endpoints"] = [{"tag": "vpngate-0"}]
        self.assertIn(b"200 OK", self._request("GET", "/healthz"))

    def test_refresh_requires_post_and_token(self) -> None:
        self.assertIn(b"401", self._request("POST", "/api/refresh"))
        self.assertIn(b"405", self._request("GET", "/api/refresh", token=self.TOKEN))

    def test_ui_page_mentions_token_auth(self) -> None:
        response = self._request("GET", "/ui", token=self.TOKEN)

        self.assertIn(b"200 OK", response)
        self.assertIn(b"Authorization", response)


class AstraUiTests(unittest.TestCase):
    """Astra-style /ui: hero kicker, pills, bench table, verify CTA."""

    def test_hero_kicker_and_verify_cta_present(self) -> None:
        self.assertIn('id="hero-kicker"', UI_HTML)
        self.assertIn('id="btn-verify"', UI_HTML)
        self.assertIn('id="btn-refresh"', UI_HTML)

    def test_scope_select_and_bench_table_present(self) -> None:
        # pills retired in favour of the single search+scope entry (Apple HIG:
        # one searchable location + scope control).
        self.assertNotIn('id="pills"', UI_HTML)
        self.assertIn('id="scope"', UI_HTML)
        self.assertIn('id="bench-body"', UI_HTML)
        self.assertIn('id="history-line"', UI_HTML)

    def test_api_contract_preserved(self) -> None:
        self.assertIn("/api/status", UI_HTML)
        self.assertIn("/api/switch", UI_HTML)
        self.assertIn("/api/refresh", UI_HTML)
        self.assertIn("Authorization", UI_HTML)

    def test_dark_theme_and_nav_present(self) -> None:
        self.assertIn('id="topnav"', UI_HTML)
        self.assertIn("background:#000", UI_HTML)

    def test_full_probe_button_present(self) -> None:
        self.assertIn('id="btn-fullprobe"', UI_HTML)
        self.assertIn("fullProbeNow", UI_HTML)
        self.assertIn("/api/full_probe", UI_HTML)

    def test_single_probe_button_calls_api_probe(self) -> None:
        start = UI_HTML.index("async function probeOne")
        block = UI_HTML[start:start + 600]
        self.assertIn("/api/probe", block)


class EnvValidationTests(unittest.TestCase):
    def _env(self, **overrides):
        env = {"PORT": "3000", "PROXY_USER": "u", "PROXY_PASS": "0123456789abcdef"}
        env.update(overrides)
        return env

    def test_weak_proxy_pass_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            build_config_from_env(self._env(PROXY_PASS="short"))

        self.assertNotEqual(0, ctx.exception.code)

    def test_default_proxy_pass_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(PROXY_PASS="p"))

    def test_missing_proxy_pass_is_generated(self) -> None:
        env = {"PORT": "3000", "PROXY_USER": "u"}
        config = build_config_from_env(env)

        self.assertGreaterEqual(len(config["password"]), 16)

    def test_missing_proxy_pass_generates_unique_values(self) -> None:
        env = {"PORT": "3000", "PROXY_USER": "u"}
        first = build_config_from_env(dict(env))["password"]
        second = build_config_from_env(dict(env))["password"]

        self.assertNotEqual(first, second)

    def test_non_https_snapshot_url_exits_nonzero(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(SNAPSHOT_URL="http://example.com/x.csv"))

    def test_valid_env_builds_config(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(3000, config["port"])
        self.assertEqual("0123456789abcdef", config["password"])

    def test_port_defaults_to_3000(self) -> None:
        env = {"PROXY_USER": "u", "PROXY_PASS": "0123456789abcdef"}

        self.assertEqual(3000, build_config_from_env(env)["port"])

    def test_colliding_port_refused(self) -> None:
        for bad in ("8080", "8081", "8082", "4096", "40000"):
            with self.assertRaises(SystemExit, msg="PORT=" + bad):
                build_config_from_env(self._env(PORT=bad))

    def test_colliding_custom_mixed_port_refused(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env(self._env(PORT="4001", MIXED_PORT="4001"))

    def test_non_3000_port_warns_but_starts(self) -> None:
        with mock.patch("builtins.print") as printed:
            config = build_config_from_env(self._env(PORT="5000"))

        self.assertEqual(5000, config["port"])
        self.assertTrue(any("warning" in str(call.args)
                            for call in printed.call_args_list))

    def test_data_dir_defaults_to_cwd(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(".", config["data_dir"])

    def test_data_dir_passthrough(self) -> None:
        config = build_config_from_env(self._env(DATA_DIR="/data"))

        self.assertEqual("/data", config["data_dir"])

    def test_limit_defaults_to_hundred(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(100, config["limit"])

    def test_real_topk_defaults_to_thirty(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(30, config["real_topk"])

    def test_missing_admin_token_defaults_to_vpn(self) -> None:
        env = {"PORT": "3000", "PROXY_USER": "u", "PROXY_PASS": "0123456789abcdef"}
        config = build_config_from_env(env)

        self.assertEqual("vpn", config["admin_token"])
        self.assertFalse(config["admin_token_generated"])

    def test_explicit_admin_token_is_kept(self) -> None:
        config = build_config_from_env(self._env(ADMIN_TOKEN="my-own-admin-token-0123456789"))

        self.assertEqual("my-own-admin-token-0123456789", config["admin_token"])

    def test_disguise_path_defaults_to_empty(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual("", config["disguise_path"])

    def test_disguise_path_passthrough(self) -> None:
        config = build_config_from_env(self._env(DISGUISE_PATH="/app/www/index.html"))

        self.assertEqual("/app/www/index.html", config["disguise_path"])

    def test_default_fetch_rejects_plain_http(self) -> None:
        with self.assertRaises(ValueError):
            default_fetch("http://example.com/x.csv", timeout=1)

    def test_dial_workers_defaults_to_two(self) -> None:
        config = build_config_from_env(self._env())

        self.assertEqual(2, config["dial_workers"])

    def test_dial_workers_env_override(self) -> None:
        config = build_config_from_env(self._env(DIAL_WORKERS="4"))

        self.assertEqual(4, config["dial_workers"])

    def test_data_dir_prefers_railway_volume(self) -> None:
        config = build_config_from_env(
            self._env(RAILWAY_VOLUME_MOUNT_PATH="/data"))

        self.assertEqual("/data", config["data_dir"])

    def test_explicit_data_dir_beats_railway_volume(self) -> None:
        config = build_config_from_env(self._env(
            DATA_DIR="/custom", RAILWAY_VOLUME_MOUNT_PATH="/data"))

        self.assertEqual("/custom", config["data_dir"])


class DialWorkersPlumbingTests(unittest.TestCase):
    """refresh_once must forward the configured dial concurrency."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def test_refresh_once_forwards_dial_workers(self) -> None:
        seen = {}
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(), start_singbox=False,
            auto_refresh=False, fetch_on_start=False,
            admin_token=self.TOKEN, dial_workers=10,
            config_path=f"{_TMP}/railway-dw-{id(self)}.json",
            nodes_path=f"{_TMP}/railway-dw-{id(self)}-nodes.json",
            state_path=f"{_TMP}/railway-dw-{id(self)}-state.json")
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            side_effect=lambda *a, **k: seen.update(k) or []):
                manager.refresh_once(fetcher=lambda url, timeout: "x")
        finally:
            manager.stop()

        self.assertEqual(10, seen.get("dial_workers"))


class SwitchTests(unittest.TestCase):
    TOKEN = "test-admin-token-0123456789abcdef"

    def _csv_two_countries(self) -> str:
        def row(host, ip, speed, country_long, country_short):
            config = base64.b64encode(
                TCP_OVPN.replace("203.0.113.1", ip).encode()).decode()
            return f"{host},{ip},100,20,{speed},{country_long},{country_short},1,{config}"

        header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
        return "\n".join([
            header,
            row("vpn-jp", "203.0.113.11", 5000, "Japan", "JP"),
            row("vpn-us", "203.0.113.12", 1000, "United States", "US"),
        ]) + "\n"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: self._csv_two_countries())
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _request(self, port: int, method: str, path: str,
                 body: bytes | None = None, token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_switch_by_country_picks_lowest_latency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch(
                            "railway_manager.probe_tcp_latency",
                            side_effect=lambda h, p, timeout=5: (
                                900 if h == "203.0.113.11" else 100)):
                        self.assertTrue(manager.refresh_once())
                    body = json.dumps({"country": "US"}).encode()
                    response = self._request(port, "POST", "/api/switch", body, self.TOKEN)

                self.assertIn(b"200 OK", response)
                self.assertEqual("vpngate-0", manager.preferred_tag)
                written = _read_json(f"{tmpdir}/singbox.json")
                self.assertEqual("chain", written["route"]["final"])
                chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
                self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])
            finally:
                manager.stop()

    def test_switch_unknown_country_is_400(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                body = json.dumps({"country": "XX"}).encode()
                response = self._request(port, "POST", "/api/switch", body, self.TOKEN)

                self.assertIn(b"400", response)
                self.assertIsNone(manager.preferred_tag)
            finally:
                manager.stop()

    def test_switch_by_tag_and_back_to_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                    ok, tag = manager.switch(tag="vpngate-0")
                    self.assertTrue(ok)
                    self.assertEqual("chain", tag)
                    written = _read_json(f"{tmpdir}/singbox.json")
                    self.assertEqual("chain", written["route"]["final"])
                    chain = next(o for o in written["outbounds"]
                                 if o["tag"] == "chain")
                    self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])

                    ok, tag = manager.switch(tag="auto")
                    self.assertTrue(ok)
                    self.assertIsNone(manager.preferred_tag)
                    written = _read_json(f"{tmpdir}/singbox.json")
                    self.assertEqual("auto", written["route"]["final"])
            finally:
                manager.stop()

    def test_status_lists_countries_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                self.assertIn({"code": "JP", "name": "Japan"},
                              manager.status_snapshot()["countries"])
                self.assertIn({"code": "US", "name": "United States"},
                              manager.status_snapshot()["countries"])
                self.assertTrue(any(e["event"] == "refresh-ok"
                                    for e in manager.status_snapshot()["refresh_history"]))
            finally:
                manager.stop()

    def test_nodes_and_state_persist_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    manager.switch(tag="vpngate-1")
            finally:
                manager.stop()

            reloaded = self._manager(tmpdir)
            nodes, preferred = reloaded.load_persisted()
            try:
                self.assertEqual(2, len(nodes))
                self.assertEqual("vpngate-1", preferred)
            finally:
                reloaded.stop()

    def test_config_file_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())

                if os.name != "nt":
                    mode = stat.S_IMODE(os.stat(f"{tmpdir}/singbox.json").st_mode)
                    self.assertEqual(0o600, mode)
            finally:
                manager.stop()


class PinnedHealthTests(unittest.TestCase):
    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: self._csv())
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _csv(self) -> str:
        config = base64.b64encode(TCP_OVPN.encode()).decode()
        header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
        return f"{header}\nvpn-jp,203.0.113.11,100,20,5000,Japan,JP,1,{config}\n"

    def test_three_consecutive_failures_unpins_to_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")
                    # The pin has been in place for a while: no warm-up grace.
                    manager._chain_pin_at = time.monotonic() - 3600.0

                    failing = lambda host, port, timeout=5: 0
                    with mock.patch.object(manager, "dial_fn",
                                           return_value=None):
                        self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                        self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                        self.assertEqual("unpinned", manager.check_pinned_health(probe_fn=failing))

                self.assertIsNone(manager.preferred_tag)
                written = _read_json(f"{tmpdir}/singbox.json")
                self.assertEqual("auto", written["route"]["final"])
            finally:
                manager.stop()

    def test_manual_pin_rescued_without_mid_round_switch(self) -> None:
        """A manual pin with NO mid-round switch is rescued when its
        tunnel is dead (round-scoped guard only yields to a switch that
        lands after the round started; the next test covers that)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once(
                            fetcher=lambda url, timeout: _snapshot_csv(
                                "203.0.113.11", "203.0.113.12",
                                "203.0.113.13")))
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")
                    # A pin from an earlier round, not a warm-up pin:
                    # otherwise CHAIN_SETTLE_GRACE suppresses the rescue.
                    manager._chain_pin_at = time.monotonic() - 3600.0
                    by_server = {n["server"]: n for n in manager._nodes}
                    by_server["203.0.113.11"]["real_latency_ms"] = 70
                    by_server["203.0.113.12"]["real_latency_ms"] = 30
                    by_server["203.0.113.13"]["real_latency_ms"] = 50

                    failing = lambda host, port, timeout=5: 0
                    # Dead tunnel: the first failed dial fast-rescues
                    # immediately (no 3-strike wait). The rescue path
                    # commits under the round-scoped guard, so a manual
                    # pin with no mid-round switch is rescued (operator
                    # can see auto-rescue in history and switch back);
                    # only a switch AFTER the round started wins.
                    with mock.patch.object(manager, "dial_fn",
                                           return_value=None):
                        self.assertEqual("rescued", manager.check_pinned_health(probe_fn=failing))

                self.assertEqual("vpngate-1", manager.preferred_tag)
                self.assertTrue(manager._auto_pinned)
                events = [e["event"] for e in manager.status["refresh_history"]]
                # No candidate had a fresh proof, so the rescue is
                # recorded as auto-rescue-stale: still a rescue.
                self.assertTrue(any(e.startswith("auto-rescue")
                                    for e in events))
            finally:
                manager.stop()

    def test_auto_pin_death_fast_rescues_to_best(self) -> None:
        """Same dead-tunnel setup, but the pin is auto (as after an
        auto-pin): fast-rescue must take the measured best."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once(
                            fetcher=lambda url, timeout: _snapshot_csv(
                                "203.0.113.11", "203.0.113.12",
                                "203.0.113.13")))
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")
                    # A pin from an earlier round, not a warm-up pin: the
                    # grace must not depend on how long the machine is up.
                    manager._chain_pin_at = time.monotonic() - 3600.0
                    # Simulate an auto pin (not operator-held).
                    manager._auto_pinned = True
                    by_server = {n["server"]: n for n in manager._nodes}
                    by_server["203.0.113.11"]["real_latency_ms"] = 70
                    by_server["203.0.113.12"]["real_latency_ms"] = 30
                    by_server["203.0.113.13"]["real_latency_ms"] = 50

                    failing = lambda host, port, timeout=5: 0
                    with mock.patch.object(manager, "dial_fn",
                                           return_value=None):
                        self.assertEqual("rescued", manager.check_pinned_health(probe_fn=failing))

                self.assertEqual("vpngate-1", manager.preferred_tag)
                # One reserved node: the chain fails over through a Clash API
                # hot switch, so no standby is taken from the rotation.
                self.assertIsNone(manager.backup_tag)
                self.assertTrue(manager._auto_pinned)
                written = _read_json(f"{tmpdir}/singbox.json")
                chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
                self.assertEqual(["vpngate-1", "auto"], chain["outbounds"])
                events = [e["event"] for e in manager.status["refresh_history"]]
                # "auto-rescue-stale" when no candidate had a fresh verify:
                # the rescue still happens, it is just based on stale data.
                self.assertTrue([e for e in events if e.startswith("auto-rescue")])
            finally:
                manager.stop()

    def test_healthy_pinned_node_stays_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox():
                    with mock.patch("railway_manager.probe_tcp_latency",
                                     return_value=100):
                        self.assertTrue(manager.refresh_once())
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")

                    # Health is dial-only now: a live tunnel dial keeps
                    # the pin (the probe_fn arg is ignored).
                    with mock.patch.object(manager, "dial_fn",
                                           return_value=120):
                        self.assertEqual("pinned", manager.check_pinned_health())

                self.assertEqual("vpngate-0", manager.preferred_tag)
            finally:
                manager.stop()


class StartOrderTests(unittest.TestCase):
    TOKEN = "0123456789abcdef-start-order"

    def _get(self, port: int, path: str) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_listener_up_while_initial_refresh_blocked(self) -> None:
        gate = threading.Event()
        with tempfile.TemporaryDirectory() as tmpdir:
            def blocking_fetch(url, timeout):
                gate.wait(30)
                return _snapshot_csv("203.0.113.11")

            manager = RailwayManager(
                port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                start_singbox=False, auto_refresh=False, fetch_on_start=True,
                config_path=f"{tmpdir}/singbox.json",
                nodes_path=f"{tmpdir}/nodes.json",
                state_path=f"{tmpdir}/state.json",
                fetcher=blocking_fetch)
            started = time.monotonic()
            port = manager.start()
            try:
                # start() must return while the first refresh is still blocked
                self.assertLess(time.monotonic() - started, 5)
                with mock.patch.object(RailwayManager, "_check_config",
                                       return_value=True):
                    with mock.patch("railway_manager.probe_tcp_latency",
                                      return_value=100):
                        # listener already accepts: 503, no endpoints yet
                        self.assertIn(b"503", self._get(port, "/healthz"))
                        gate.set()
                        deadline = time.monotonic() + 15
                        while (manager.status["last_refresh"] is None
                               and time.monotonic() < deadline):
                            time.sleep(0.2)
                        self.assertIsNotNone(manager.status["last_refresh"])
            finally:
                gate.set()
                manager.stop()


class SwitchRealLatencyTests(unittest.TestCase):
    TOKEN = "0123456789abcdef-switch-real"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11",
                                                                   "203.0.113.12"))
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, port: int, path: str, body: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            headers = (f"POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                       f"Authorization: Bearer {self.TOKEN}\r\n"
                       f"Content-Length: {len(body)}\r\n")
            sock.sendall(headers.encode() + b"\r\n" + body)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_switch_by_country_prefers_real_latency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # handshake winner is .11, but real tunnel latency winner is .12
            dial = lambda node: {"203.0.113.11": 800, "203.0.113.12": 50}[node["server"]]
            manager = self._manager(tmpdir, real_topk=2, dial_fn=dial)
            port = manager.start()
            try:
                with _fake_singbox():
                    with mock.patch(
                            "railway_manager.probe_tcp_latency",
                            side_effect=lambda h, p, timeout=5: (
                                100 if h == "203.0.113.11" else 900)):
                        self.assertTrue(manager.refresh_once())
                    tag12 = next(e["tag"] for e in manager.status["endpoints"]
                                 if e["server"] == "203.0.113.12")
                    body = json.dumps({"country": "JP"}).encode()
                    response = self._post(port, "/api/switch", body)

                self.assertIn(b"200 OK", response)
                self.assertEqual(tag12, manager.preferred_tag)
            finally:
                manager.stop()


class ColdStartTests(unittest.TestCase):
    def _paths(self, tmpdir: str) -> dict:
        return dict(config_path=f"{tmpdir}/singbox.json",
                    nodes_path=f"{tmpdir}/nodes.json",
                    state_path=f"{tmpdir}/state.json")

    def _seed_last_good(self, tmpdir: str) -> None:
        seed = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            **self._paths(tmpdir))
        nodes = snapshot_to_nodes(
            _snapshot_csv("203.0.113.21", "203.0.113.22"), probe=False)
        seed._nodes = nodes
        seed._persist_nodes()
        endpoints = nodes_to_endpoints(nodes)
        with open(seed.last_good_path, "w", encoding="utf-8") as handle:
            json.dump(build_singbox_config(endpoints, "127.0.0.1",
                                          seed.mixed_port), handle)

    def test_boot_attempted_before_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            calls = []
            with mock.patch.object(
                    RailwayManager, "_boot_from_last_good",
                    side_effect=lambda: calls.append("boot") or True), \
                 mock.patch.object(
                    RailwayManager, "refresh_once",
                    side_effect=lambda: calls.append("refresh") or True):
                manager._initial_refresh()
            self.assertEqual(["boot", "refresh"], calls)

    def test_serves_last_good_while_refresh_in_flight(self) -> None:
        """Last-good is served as soon as boot succeeds; the refresh runs on a
        background thread, so serving is never gated by a slow fetch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self._seed_last_good(tmpdir)
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            gate = threading.Event()
            entered = threading.Event()

            def slow_refresh():
                entered.set()
                gate.wait(30)
                return True

            try:
                with mock.patch.object(RailwayManager, "refresh_once",
                                       side_effect=slow_refresh):
                    thread = threading.Thread(target=manager._initial_refresh,
                                               daemon=True)
                    thread.start()
                    thread.join(timeout=10)
                    self.assertFalse(thread.is_alive(),
                                     "boot must not block on the fetch")
                    self.assertTrue(entered.wait(10))
                    deadline = time.monotonic() + 10
                    while not manager.status["endpoints"] \
                            and time.monotonic() < deadline:
                        time.sleep(0.1)
                    self.assertTrue(manager.status["endpoints"],
                                    "last-good not served while refresh in flight")
                    self.assertTrue(manager._serving_ok())
                    bg = manager._refresh_thread
                    self.assertIsNotNone(bg, "refresh must run in the background")
                    self.assertTrue(bg.is_alive(),
                                    "refresh should still be gated on the fetch")
            finally:
                gate.set()

    def test_no_last_good_no_endpoints_stays_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = RailwayManager(
                port=0, mixed_port=get_free_port(),
                start_singbox=False, auto_refresh=False, fetch_on_start=False,
                **self._paths(tmpdir))
            with mock.patch.object(RailwayManager, "refresh_once",
                                   return_value=False):
                manager._initial_refresh()
            self.assertFalse(manager._serving_ok())
            self.assertEqual([], manager.status["endpoints"])


class TunnelTests(unittest.TestCase):
    def _paths(self, tmpdir: str) -> dict:
        return {"config_path": os.path.join(tmpdir, "singbox.json"),
                "nodes_path": os.path.join(tmpdir, "nodes.json"),
                "state_path": os.path.join(tmpdir, "state.json")}

    def _manager(self, tmpdir: str, **kwargs) -> RailwayManager:
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=False, auto_refresh=False,
                        fetch_on_start=False)
        defaults.update(kwargs)
        return RailwayManager(**defaults, **self._paths(tmpdir))

    def test_env_defaults_leave_tunnel_off(self) -> None:
        cfg = build_config_from_env({"PROXY_PASS": "0123456789abcdef"})
        self.assertEqual("", cfg["vless_uuid"])
        self.assertEqual("", cfg["tunnel_token"])

    def test_env_picks_up_uuid_and_token(self) -> None:
        cfg = build_config_from_env({"PROXY_PASS": "0123456789abcdef",
                                     "VLESS_UUID": "u-u-i-d",
                                     "TUNNEL_TOKEN": "t-o-k-e-n"})
        self.assertEqual("u-u-i-d", cfg["vless_uuid"])
        self.assertEqual("t-o-k-e-n", cfg["tunnel_token"])

    def test_apply_config_includes_vless_when_uuid_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, vless_uuid="u-u-i-d")
            node = {"server": "203.0.113.1", "server_port": 443,
                    "endpoint": ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")}
            manager._nodes = [node]
            with _fake_singbox(), \
                 mock.patch.object(RailwayManager, "_restart_singbox"):
                self.assertTrue(manager._apply_config(final="auto"))
            written = _read_json(manager.config_path)
            tags = [i["tag"] for i in written["inbounds"]]
            self.assertIn("vless-direct", tags)
            self.assertIn("vless-chain", tags)

    def test_apply_config_skips_vless_without_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            node = {"server": "203.0.113.1", "server_port": 443,
                    "endpoint": ovpn_to_endpoint(TCP_OVPN, tag="vpngate-0")}
            manager._nodes = [node]
            with _fake_singbox(), \
                 mock.patch.object(RailwayManager, "_restart_singbox"):
                self.assertTrue(manager._apply_config(final="auto"))
            written = _read_json(manager.config_path)
            tags = [i["tag"] for i in written.get("inbounds", [])]
            self.assertNotIn("vless-direct", tags)

    def test_start_cloudflared_without_token_skips_softly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="")
            with mock.patch("railway_manager.subprocess.Popen") as popen:
                self.assertFalse(manager._start_cloudflared())
                popen.assert_not_called()
            self.assertIsNone(manager._cloudflared_proc)
            self.assertEqual("no-token", manager.status["tunnel"]["state"])

    def test_start_cloudflared_missing_binary_skips_softly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="t-o-k-e-n",
                                    cloudflared_bin="/nonexistent/cloudflared")
            with mock.patch("railway_manager.subprocess.Popen") as popen:
                self.assertFalse(manager._start_cloudflared())
                popen.assert_not_called()
            self.assertEqual("no-binary", manager.status["tunnel"]["state"])

    def test_start_cloudflared_spawns_process_with_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, tunnel_token="t-o-k-e-n")
            with mock.patch("railway_manager.subprocess.Popen") as popen, \
                 mock.patch("railway_manager.shutil.which",
                            return_value="/usr/local/bin/cloudflared"):
                self.assertTrue(manager._start_cloudflared())
                args = popen.call_args[0][0]
                self.assertIn("t-o-k-e-n", args)
            self.assertEqual("running", manager.status["tunnel"]["state"])


class OnclickQuoteTests(unittest.TestCase):
    """Row actions pass the tag via data attributes + delegation (never
    inline onclick with Python-eaten backslash quotes)."""

    def test_probe_action_uses_data_attribute(self) -> None:
        self.assertIn("data-probe='", UI_HTML)

    def test_switch_action_uses_data_attribute(self) -> None:
        self.assertIn("data-switch='", UI_HTML)

    def test_delegation_handler_reads_data_attributes(self) -> None:
        self.assertIn('getAttribute("data-probe")', UI_HTML)
        self.assertIn('getAttribute("data-switch")', UI_HTML)


class GlassUiTests(unittest.TestCase):
    """Glassmorphism console structure + feedback affordances."""

    def test_glass_cards_present(self) -> None:
        self.assertIn("glass-card", UI_HTML)

    def test_exit_card_present(self) -> None:
        self.assertIn('id="exit-card"', UI_HTML)

    def test_verify_button_present(self) -> None:
        self.assertIn('id="btn-verify"', UI_HTML)
        self.assertIn("verifyExit(", UI_HTML)

    def test_toast_container_present(self) -> None:
        self.assertIn('id="toast"', UI_HTML)

    def test_history_list_present(self) -> None:
        self.assertIn('id="history-list"', UI_HTML)

    def test_node_search_present(self) -> None:
        self.assertIn('id="node-search"', UI_HTML)

    def test_probe_progress_present(self) -> None:
        self.assertIn('id="probe-progress"', UI_HTML)

    def test_toast_helper_present(self) -> None:
        self.assertIn("function toast(", UI_HTML)

    def test_busy_helper_present(self) -> None:
        self.assertIn("function setBusy(", UI_HTML)

    def test_verify_exit_fn_present(self) -> None:
        self.assertIn("verifyExit(", UI_HTML)

    def test_poll_token_present(self) -> None:
        self.assertIn("probeSeq", UI_HTML)
        self.assertIn("verifySeq", UI_HTML)
        self.assertIn("fullSeq", UI_HTML)

    def test_served_js_parses(self) -> None:
        """Extract every <script> from the RUNTIME UI_HTML (post-Python-unescape)
        and run node --check on each: catches backslash-quote breakage that a
        source-level check would miss."""
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        blocks = re.findall(r"<script>(.*?)</script>", UI_HTML, re.S)
        self.assertTrue(blocks)
        for block in blocks:
            with tempfile.NamedTemporaryFile("w", suffix=".js",
                                             delete=False,
                                             encoding="utf-8") as handle:
                handle.write(block)
                path = handle.name
            # The child writes into files instead of pipes: a confined test
            # process cannot hand a pipe to a child process, and the
            # assertion reads the very same output.
            log_path = path + ".log"
            try:
                with open(log_path, "w", encoding="utf-8") as log:
                    result = subprocess.run([node, "--check", path],
                                            stdout=log, stderr=log,
                                            text=True, timeout=60)
                message = ""
                if os.path.exists(log_path):
                    with open(log_path, encoding="utf-8",
                              errors="replace") as log:
                        message = log.read()
            finally:
                for tmp_path in (path, log_path):
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            self.assertEqual(0, result.returncode, message)

class UiPolishTests(unittest.TestCase):
    """T1-T5 interaction polish: debounce, abortable polls, bench guards,
    toast cap, empty state, mobile."""

    def test_search_debounced(self) -> None:
        self.assertIn("debouncedRefresh", UI_HTML)
        self.assertIn("oninput=\"debouncedRefresh()\"", UI_HTML)

    def test_local_filter_without_fetch(self) -> None:
        self.assertIn("renderFiltered", UI_HTML)

    def test_fullprobe_409_toast(self) -> None:
        self.assertIn("已有全量任务进行中", UI_HTML)

    def test_polls_abortable(self) -> None:
        self.assertIn("AbortController", UI_HTML)

    def test_interval_skips_hidden(self) -> None:
        self.assertIn("document.hidden", UI_HTML)

    def test_switch_guarded_when_unmeasured(self) -> None:
        self.assertIn("aria-disabled", UI_HTML)
        self.assertIn("先测速", UI_HTML)

    def test_esc_covers_quotes(self) -> None:
        self.assertIn("&quot;", UI_HTML)

    def test_toast_capped(self) -> None:
        self.assertIn("children.length", UI_HTML)

    def test_empty_filter_row(self) -> None:
        self.assertIn("无匹配", UI_HTML)

    def test_mobile_breakpoint(self) -> None:
        self.assertIn("@media(max-width:640px)", UI_HTML)
        self.assertIn("bench-wrap", UI_HTML)
        self.assertIn("safe-area-inset", UI_HTML)

    def test_login_input_accessible(self) -> None:
        self.assertIn('autocomplete="off"', UI_HTML)


class LoginGateTests(unittest.TestCase):
    """Token login gate: enter token first, console hidden until verified."""

    def test_login_gate_present(self) -> None:
        self.assertIn('id="login-gate"', UI_HTML)

    def test_login_input_and_button_present(self) -> None:
        self.assertIn('id="login-token"', UI_HTML)
        self.assertIn('id="btn-login"', UI_HTML)
        self.assertIn("loginEnter(", UI_HTML)

    def test_lock_button_present(self) -> None:
        self.assertIn('id="btn-lock"', UI_HTML)

    def test_silent_login_present(self) -> None:
        self.assertIn("silentLogin(", UI_HTML)

    def test_topnav_token_input_removed(self) -> None:
        self.assertNotIn('id="token"', UI_HTML)


class VerifyApiTests(unittest.TestCase):
    """POST /api/verify measures the real exit IP through the live chain."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-verify-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-verify-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-verify-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   + (f"Authorization: Bearer {self.TOKEN}\r\n" if token else ""))
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}"}}
                          for i, ip in enumerate(ips)]

    def test_verify_rejects_missing_token(self) -> None:
        manager = self._manager()
        try:
            status_line, _ = self._post(manager, "/api/verify", token=False)
        finally:
            manager.stop()

        self.assertIn("401", status_line)

    def test_verify_accepts_and_reports_exit_ip(self) -> None:
        manager = self._manager(
            verify_fn=lambda endpoint: ("203.0.113.99", 321))
        try:
            self._seed_nodes(manager, "203.0.113.11")
            status_line, body = self._post(manager, "/api/verify", token=True)
            accepted_state = manager.status["verify"]["state"]
            manager._verify_thread.join(timeout=30)
            final = manager.status["verify"]
        finally:
            manager.stop()

        self.assertIn("202", status_line)
        self.assertTrue(json.loads(body.decode())["accepted"])
        self.assertEqual("running", accepted_state)
        self.assertEqual("done", final["state"])
        self.assertEqual("203.0.113.99", final["exit_ip"])
        self.assertEqual(321, final["ms"])
        self.assertEqual("vpngate-0", final["via_tag"])

    def test_verify_without_nodes_returns_503(self) -> None:
        manager = self._manager(
            verify_fn=lambda endpoint: ("203.0.113.99", 321))
        try:
            status_line, _ = self._post(manager, "/api/verify", token=True)
        finally:
            manager.stop()

        self.assertIn("503", status_line)


class ProcessHygieneTests(unittest.TestCase):
    """P0: no blocking under lock, no silent supervise death, no zombies."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-hyg-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-hyg-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-hyg-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_restart_survives_popen_failure(self) -> None:
        manager = self._manager()
        try:
            with mock.patch("railway_manager.subprocess.Popen",
                            side_effect=OSError("noexec")):
                manager._restart_singbox()  # must not raise
            self.assertIsNone(manager._singbox_proc)
        finally:
            manager.stop()

    def test_terminate_waits_after_kill(self) -> None:
        calls = []

        class FakeProc:
            def terminate(self):
                calls.append("terminate")

            def wait(self, timeout=None):
                calls.append(("wait", timeout))
                if len([c for c in calls if isinstance(c, tuple)]) == 1:
                    raise subprocess.TimeoutExpired("fake", timeout)
                return 0

            def kill(self):
                calls.append("kill")

            def poll(self):
                return None

        manager = self._manager()
        try:
            manager._singbox_proc = FakeProc()
            manager._terminate_singbox()
        finally:
            manager.stop()

        self.assertEqual(["terminate", ("wait", 5), "kill", ("wait", 5)],
                         calls)

    def test_check_runs_without_holding_lock(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "endpoint": {"tag": "vpngate-0"}}]
            verdict = {}

            def _check(path):
                # RLock is reentrant on THIS thread, so probe from another
                # thread: if _apply_config still holds the lock, this fails.
                # Acquire AND release on the probe thread: a leaked hold
                # by a dead thread would wedge every later acquire.

                def _probe():
                    acquired = manager._lock.acquire(blocking=False)
                    verdict["free"] = acquired
                    if acquired:
                        manager._lock.release()

                probe = threading.Thread(target=_probe)
                probe.start()
                probe.join(timeout=10)
                return True

            with mock.patch("railway_manager.build_singbox_config",
                            return_value={}), \
                 mock.patch.object(manager, "_check_config",
                                   side_effect=_check) as checked, \
                 mock.patch.object(manager, "_restart_singbox"):
                ok = manager._apply_config("auto")
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertTrue(checked.called)
        self.assertTrue(verdict.get("free"), "lock held during check")

    def test_cloudflared_restart_reaps_old_proc(self) -> None:
        manager = self._manager(tunnel_token="t-o-k-e-n")
        reaped = []

        class OldProc:
            def terminate(self):
                reaped.append("terminate")

            def wait(self, timeout=None):
                reaped.append(("wait", timeout))
                return 0

            def kill(self):
                reaped.append("kill")

            def poll(self):
                return 0

        manager._cloudflared_proc = OldProc()
        try:
            with mock.patch("railway_manager.shutil.which",
                            return_value="/usr/local/bin/cloudflared"), \
                 mock.patch("railway_manager.subprocess.Popen") as popen:
                started = manager._start_cloudflared()
                current = manager._cloudflared_proc
                child = popen.return_value
        finally:
            with mock.patch("railway_manager.subprocess.Popen"):
                manager.stop()

        self.assertTrue(started)
        self.assertIs(child, current)
        self.assertIn("terminate", reaped)


class HalfPacketTests(unittest.TestCase):
    """P0: TCP-fragmented request heads must wait for more bytes."""

    class FakeClient:
        def __init__(self, chunks):
            self._chunks = list(chunks)
            self.sent = b""

        def settimeout(self, timeout):
            pass

        def recv(self, size):
            if not self._chunks:
                return b""
            return self._chunks.pop(0)

        def sendall(self, data):
            self.sent += data

        def close(self):
            pass

    def _manager(self):
        return RailwayManager(
            port=0, mixed_port=get_free_port(), start_singbox=False,
            auto_refresh=False, fetch_on_start=False,
            admin_token="test-admin-token-0123456789abcdef",
            config_path=f"{_TMP}/railway-half-{id(self)}.json",
            nodes_path=f"{_TMP}/railway-half-{id(self)}-nodes.json",
            state_path=f"{_TMP}/railway-half-{id(self)}-state.json")

    def test_split_get_reaches_http(self) -> None:
        manager = self._manager()
        try:
            client = self.FakeClient([
                b"GE",
                b"T /api/status HTTP/1.1\r\nHost: x\r\n\r\n",
            ])
            manager._handle_client(client)
        finally:
            manager.stop()

        self.assertIn(b"401", client.sent)

    def test_garbage_still_closes_silently(self) -> None:
        manager = self._manager()
        try:
            client = self.FakeClient([b"XYZ"])
            manager._handle_client(client)
        finally:
            manager.stop()

        self.assertEqual(b"", client.sent)


class PipeIdleTests(unittest.TestCase):
    """P0: forwarding ends on EOF or idle timeout instead of hanging."""

    def test_forward_returns_on_timeout(self) -> None:
        a, b = socket.socketpair()
        try:
            a.settimeout(0.2)
            from railway_manager import _forward
            self.assertEqual(0, _forward(a, b))
        finally:
            a.close()
            b.close()

    def test_forward_copies_then_eof(self) -> None:
        from railway_manager import _forward
        # NOTE: feeder must be CLOSED after sending. Leaving both ends
        # open turns the pair into an echo chamber: _forward(a->b) writes
        # into b whose output feeds back into a, ping-ponging forever.
        # close() delivers queued bytes before FIN, so EOF is deterministic.
        src, feeder = socket.socketpair()
        dst, _sink = socket.socketpair()
        try:
            feeder.sendall(b"hello")
            feeder.close()
            self.assertEqual(5, _forward(src, dst))
        finally:
            for sock in (src, feeder, dst, _sink):
                try:
                    sock.close()
                except OSError:
                    pass


class RefreshMutexTests(unittest.TestCase):
    """P1: concurrent refresh_once calls must not interleave; second skips."""
    def test_concurrent_refresh_skips_second(self) -> None:
        started = threading.Event()
        release = threading.Event()
        calls = []

        def _blocking_fetch(url, timeout):
            calls.append("fetch")
            started.set()
            release.wait(timeout=30)
            raise RuntimeError("fetch failed")

        manager = RailwayManager(
            port=0, mixed_port=get_free_port(), start_singbox=False,
            auto_refresh=False, fetch_on_start=False,
            admin_token="test-admin-token-0123456789abcdef",
            config_path=f"{_TMP}/railway-mtx-{id(self)}.json",
            nodes_path=f"{_TMP}/railway-mtx-{id(self)}-nodes.json",
            state_path=f"{_TMP}/railway-mtx-{id(self)}-state.json")
        manager.retry_delays = ()
        try:
            worker = threading.Thread(
                target=manager.refresh_once,
                kwargs={"fetcher": _blocking_fetch}, daemon=True)
            worker.start()
            self.assertTrue(started.wait(timeout=10))

            def _must_not_run(url, timeout):
                calls.append("second-fetch")
                raise AssertionError("second refresh fetched concurrently")

            ok = manager.refresh_once(fetcher=_must_not_run)
            release.set()
            worker.join(timeout=30)
        finally:
            release.set()
            manager.stop()

        self.assertFalse(ok)
        self.assertNotIn("second-fetch", calls)
        events = [h["event"] for h in manager.status["refresh_history"]]
        self.assertIn("refresh-busy", events)


class LoopSurvivalTests(unittest.TestCase):
    """P1: background loops must survive one worker error, not die silent."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-loop-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-loop-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-loop-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_refresh_loop_survives_worker_error(self) -> None:
        manager = self._manager()
        manager.refresh_seconds = 0
        calls = []

        # NOTE: side_effect must be a FUNCTION here: members of a
        # side_effect *list* that are functions get returned, not called,
        # so the stop event would never be set and the loop spins forever.
        def _flaky():
            calls.append("refresh")
            if len(calls) == 1:
                raise RuntimeError("boom")
            manager._stop_event.set()
            return True

        try:
            with mock.patch.object(manager, "refresh_once",
                                   side_effect=_flaky), \
                 mock.patch("railway_manager.random.uniform",
                            return_value=-30):
                manager._refresh_loop()
        finally:
            manager.stop()

        self.assertEqual(["refresh", "refresh"], calls)

    def test_supervise_loop_survives_worker_error(self) -> None:
        manager = self._manager()
        manager.want_singbox = True
        open(manager.config_path, "w").close()

        class DeadProc:
            def poll(self):
                return 1

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        manager._singbox_proc = DeadProc()
        calls = []

        def _flaky_restart():
            calls.append("restart")
            if len(calls) == 1:
                raise RuntimeError("boom")
            manager._stop_event.set()

        try:
            with mock.patch.object(manager, "_restart_singbox",
                                   side_effect=_flaky_restart), \
                 mock.patch("railway_manager.SUPERVISE_INTERVAL", 0), \
                 mock.patch("railway_manager.CRASH_BACKOFFS", (0,)):
                manager._supervise_loop()
        finally:
            manager.stop()

        self.assertEqual(["restart", "restart"], calls)


class StableTagTests(unittest.TestCase):
    """A refresh that reorders nodes must not reshuffle tags or drop pin."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _csv(self, speeds: dict) -> str:
        header = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
        rows = []
        for ip, speed in speeds.items():
            config = base64.b64encode(
                TCP_OVPN.replace("203.0.113.1", ip).encode()).decode()
            rows.append(f"vpn-{ip},{ip},100,20,{speed},Japan,JP,1,{config}")
        return header + "\n" + "\n".join(rows) + "\n"

    def _manager(self, tmpdir: str, csv_text: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        fetcher=lambda url, timeout: csv_text)
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_assign_stable_tags_reuses_tag_per_server(self) -> None:
        from railway_manager import assign_stable_tags

        def node(server, tag=""):
            return {"server": server, "server_port": 443,
                    "endpoint": {"tag": tag, "server": server,
                                 "server_port": 443}}

        old = [node("203.0.113.11", "vpngate-0"),
               node("203.0.113.12", "vpngate-1")]
        new = [node("203.0.113.12"), node("203.0.113.11"),
               node("203.0.113.13")]
        assign_stable_tags(new, old)
        by_server = {n["server"]: n["endpoint"]["tag"] for n in new}
        self.assertEqual("vpngate-0", by_server["203.0.113.11"])
        self.assertEqual("vpngate-1", by_server["203.0.113.12"])
        self.assertTrue(by_server["203.0.113.13"].startswith("vpngate-"))
        self.assertEqual(3, len(set(by_server.values())))

    def test_same_server_keeps_tag_across_reordered_refresh(self) -> None:
        first = self._csv({"203.0.113.11": 5000, "203.0.113.12": 1000})
        second = self._csv({"203.0.113.12": 5000, "203.0.113.11": 1000})
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, first)
            try:
                # Everything that touches sing-box (check + spawn) stays
                # inside _fake_singbox: outside it _check_config would run
                # the real binary (absent on CI) and switch would fail.
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=100):
                    self.assertTrue(manager.refresh_once())
                    tags_first = {n["server"]: n["endpoint"]["tag"]
                                  for n in manager._nodes}
                    pinned = tags_first["203.0.113.11"]
                    ok, _ = manager.switch(tag=pinned)
                    self.assertTrue(ok)

                    manager.fetcher = lambda url, timeout: second
                    self.assertTrue(manager.refresh_once())
                tags_second = {n["server"]: n["endpoint"]["tag"]
                               for n in manager._nodes}
                self.assertEqual(tags_first, tags_second)
                self.assertEqual(pinned, manager.preferred_tag)
                written = _read_json(f"{tmpdir}/singbox.json")
                self.assertEqual("chain", written["route"]["final"])
            finally:
                manager.stop()


class SuperviseBackoffTests(unittest.TestCase):
    def _manager(self, **kwargs):
        # No tempfile here: DeadProc skips every filesystem branch, so these
        # tests also run inside a file sandbox. Dummy paths are never touched.
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=True, auto_refresh=False, fetch_on_start=False,
                        config_path="noop-supervise-singbox.json",
                        nodes_path="noop-supervise-nodes.json",
                        state_path="noop-supervise-state.json",
                        fetcher=lambda url, timeout: "")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _dead_proc(self):
        class DeadProc:
            def poll(self):
                return 1

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        return DeadProc()

    def test_supervise_retries_beyond_max_streak(self) -> None:
        import railway_manager as manager_mod
        manager = self._manager()
        # DeadProc (poll()=exited) skips the config-file branch without
        # touching the filesystem, so this also runs in a file sandbox.
        manager._singbox_proc = self._dead_proc()
        # The crash ladder is a clamp now: its last entry is the cap.
        manager._crash_streak = len(manager_mod.CRASH_BACKOFFS) - 1
        manager._retry_after = 0.0
        try:
            with mock.patch.object(manager, "_restart_singbox") as restart:
                manager._supervise_once()
        finally:
            manager.stop()
        restart.assert_called_once()

    def test_supervise_skips_restart_inside_backoff_window(self) -> None:
        manager = self._manager()
        manager._singbox_proc = self._dead_proc()
        manager._retry_after = time.monotonic() + 1000.0
        try:
            with mock.patch.object(manager, "_restart_singbox") as restart:
                manager._supervise_once()
        finally:
            manager.stop()
        restart.assert_not_called()


class MuxLimitTests(unittest.TestCase):
    def test_excess_mux_connections_are_dropped(self) -> None:
        # No tempfile: the constructor and the dropped path never touch
        # the filesystem, so this runs inside a file sandbox too.
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            max_mux_connections=1,
            config_path="noop-mux-singbox.json",
            nodes_path="noop-mux-nodes.json",
            state_path="noop-mux-state.json")
        try:
            self.assertTrue(manager._mux_slots.acquire(blocking=False))
            client, peer = socket.socketpair()
            try:
                client.sendall(b"\x05\x01\x00")
                before = manager.status["traffic"]["connections"]
                manager._handle_client(peer)
                self.assertEqual(before,
                                 manager.status["traffic"]["connections"])
            finally:
                client.close()
        finally:
            manager.stop()


class LogApiTests(unittest.TestCase):
    """GET /api/logs streams the sing-box stderr tail (authed)."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            config_path="noop-logs-singbox.json",
        )
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _request(self, path: str, token: str | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            sock.sendall(headers.encode() + b"\r\n")
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def _body(self, response: bytes) -> dict:
        _, _, body = response.partition(b"\r\n\r\n")
        return json.loads(body.decode("utf-8"))

    def test_logs_without_token_is_401(self) -> None:
        self.assertIn(b"401", self._request("/api/logs"))

    def test_logs_missing_file_returns_empty_list(self) -> None:
        response = self._request("/api/logs", token=self.TOKEN)
        self.assertIn(b"200 OK", response)
        payload = self._body(response)
        self.assertEqual([], payload["lines"])

    def test_logs_limit_is_clamped(self) -> None:
        payload = self._body(self._request("/api/logs?lines=5000", token=self.TOKEN))
        self.assertEqual(200, payload["limit"])
        payload = self._body(self._request("/api/logs?lines=0", token=self.TOKEN))
        self.assertEqual(1, payload["limit"])


class VlessStatusTests(unittest.TestCase):
    """status carries subscription material when VLESS is enabled."""

    def test_status_has_vless_when_uuid_set(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            vless_uuid="u-u-i-d", vless_direct_port=8080, vless_chain_port=8082)
        try:
            vless = manager.status_snapshot()["vless"]
        finally:
            manager.stop()
        self.assertEqual({"uuid": "u-u-i-d", "direct_path": "/ws-node",
                          "chain_path": "/ws-chain"}, vless)

    def test_status_vless_is_none_without_uuid(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False)
        try:
            vless = manager.status_snapshot()["vless"]
        finally:
            manager.stop()
        self.assertIsNone(vless)


class ConsoleV2Tests(unittest.TestCase):
    """v2 console: old skin, new IA, light theme, read-only additions."""

    def test_statusbar_and_theme_toggle_present(self) -> None:
        self.assertIn('id="statusbar"', UI_HTML)
        self.assertIn('id="sb-exit"', UI_HTML)
        self.assertIn('id="btn-theme"', UI_HTML)
        self.assertIn("toggleTheme(", UI_HTML)
        self.assertIn('data-theme="light"', UI_HTML)
        self.assertIn("prefers-color-scheme", UI_HTML)

    def test_sections_have_stable_anchors(self) -> None:
        for section in ("sec-overview", "sec-nodes", "sec-logs",
                        "sec-sub", "sec-hist"):
            self.assertIn('id="%s"' % section, UI_HTML)

    def test_nodes_sorting_and_latency_helpers_present(self) -> None:
        self.assertIn('id="sortsel"', UI_HTML)
        self.assertIn('data-k="real"', UI_HTML)
        self.assertIn("function latBar(", UI_HTML)
        self.assertIn("function sortVal(", UI_HTML)
        self.assertIn('id="node-count"', UI_HTML)

    def test_rate_and_routes_rendered(self) -> None:
        self.assertIn('id="spark"', UI_HTML)
        self.assertIn('id="rate-card"', UI_HTML)
        self.assertIn('id="route-strip"', UI_HTML)
        self.assertIn('id="stat-down"', UI_HTML)

    def test_logs_and_subscription_wired(self) -> None:
        self.assertIn('id="logbox"', UI_HTML)
        self.assertIn("function refreshLogs(", UI_HTML)
        self.assertIn("/api/logs", UI_HTML)
        self.assertIn('id="sub-direct"', UI_HTML)
        self.assertIn("function copySub(", UI_HTML)

    def test_switch_closure_and_skeleton_present(self) -> None:
        self.assertIn("pendingTag", UI_HTML)
        self.assertIn("function skeletonRows(", UI_HTML)
        self.assertIn("正在验证新出口", UI_HTML)

    def test_probe_verify_409_branches_present(self) -> None:
        self.assertIn("已有单测进行中，稍后再试", UI_HTML)
        self.assertIn("已有验证进行中，稍后再试", UI_HTML)

    def test_reduced_motion_respected(self) -> None:
        self.assertIn("prefers-reduced-motion", UI_HTML)


class ProbeGuardTests(unittest.TestCase):
    """Single-flight single-probe: second POST gets 409, never a phantom poll."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path="noop-guard-singbox.json",
                        nodes_path="noop-guard-nodes.json",
                        state_path="noop-guard-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post_json(self, manager, path, payload):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = json.dumps(payload).encode()
        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: {len(raw)}\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1") + raw)
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], json.loads(body.decode())

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}"}}
                          for i, ip in enumerate(ips)]

    def test_same_tag_double_post_gets_409_then_202_after_done(self) -> None:
        gate = threading.Event()
        manager = self._manager(dial_fn=lambda node: gate.wait(timeout=30) or 77)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            line1, body1 = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            line2, body2 = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            gate.set()
            manager._single_probe_thread.join(timeout=30)
            line3, body3 = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
        finally:
            gate.set()
            manager.stop()

        self.assertIn("202", line1)
        self.assertTrue(body1["accepted"])
        self.assertIn("409", line2)
        self.assertFalse(body2["accepted"])
        self.assertIn("vpngate-0", body2.get("tag", ""))
        self.assertIn("202", line3)
        self.assertTrue(body3["accepted"])

    def test_cross_tag_post_while_running_gets_409(self) -> None:
        gate = threading.Event()
        manager = self._manager(dial_fn=lambda node: gate.wait(timeout=30) or 77)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            line1, _ = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            line2, body2 = self._post_json(manager, "/api/probe", {"tag": "vpngate-1"})
        finally:
            gate.set()
            manager.stop()

        self.assertIn("202", line1)
        self.assertIn("409", line2)
        self.assertIn("vpngate-0", body2.get("tag", ""))

    def test_stale_running_guard_allows_supersede(self) -> None:
        manager = self._manager(dial_fn=lambda node: 5)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            with manager._lock:
                manager.status["probe"] = {"state": "running", "tag": "vpngate-0",
                                           "ms": None, "error": None,
                                           "started_at": time.monotonic() - 200.0}
                manager._single_probe_thread = None
            line, body = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIn("202", line)
        self.assertTrue(body["accepted"])

    def test_probe_exception_releases_guard(self) -> None:
        def _boom(node):
            raise RuntimeError("tunnel down")

        manager = self._manager(dial_fn=_boom)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
            line, body = self._post_json(manager, "/api/probe", {"tag": "vpngate-0"})
            manager._single_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIn("202", line)
        self.assertTrue(body["accepted"])


class VerifyGuardTests(unittest.TestCase):
    """Single-flight verify: same 202/409 contract as single-probe."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path="noop-vguard-singbox.json",
                        nodes_path="noop-vguard-nodes.json",
                        state_path="noop-vguard-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], json.loads(body.decode())

    def test_verify_double_post_gets_409_then_202_after_done(self) -> None:
        gate = threading.Event()
        manager = self._manager(
            verify_fn=lambda endpoint: gate.wait(timeout=30) or ("9.9.9.9", 1))
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "endpoint": {"tag": "vpngate-0"}}]
            line1, body1 = self._post(manager, "/api/verify")
            line2, body2 = self._post(manager, "/api/verify")
            gate.set()
            manager._verify_thread.join(timeout=30)
            line3, body3 = self._post(manager, "/api/verify")
            manager._verify_thread.join(timeout=30)
        finally:
            gate.set()
            manager.stop()

        self.assertIn("202", line1)
        self.assertTrue(body1["accepted"])
        self.assertIn("409", line2)
        self.assertFalse(body2["accepted"])
        self.assertIn("202", line3)
        self.assertTrue(body3["accepted"])


class HttpPostCapTests(unittest.TestCase):
    """POSTs are capped; cheap GETs (healthz/status) never starve."""
    TOKEN = "test-admin-token-0123456789abcdef"

    def setUp(self) -> None:
        self.manager = RailwayManager(
            port=0, mixed_port=get_free_port(), admin_token=self.TOKEN,
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            config_path="noop-cap-singbox.json",
            nodes_path="noop-cap-nodes.json",
            state_path="noop-cap-state.json")
        self.port = self.manager.start()

    def tearDown(self) -> None:
        for _ in range(64):
            try:
                self.manager._post_slots.release()
            except ValueError:
                break
        self.manager.stop()

    def _request(self, method, path, body=None, token=None):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            if token is not None:
                headers += f"Authorization: Bearer {token}\r\n"
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def _fill_post_slots(self):
        for _ in range(64):
            if not self.manager._post_slots.acquire(blocking=False):
                break

    def test_healthz_bypasses_full_post_cap(self) -> None:
        self.manager.status["endpoints"] = [{"tag": "vpngate-0"}]
        self._fill_post_slots()
        try:
            response = self._request("GET", "/healthz")
        finally:
            pass

        self.assertIn(b"200 OK", response)

    def test_post_over_cap_returns_503_without_running(self) -> None:
        self._fill_post_slots()
        before = self.manager.status["refresh_ok"]
        response = self._request("POST", "/api/refresh", body=b"{}",
                                 token=self.TOKEN)

        self.assertIn(b"503", response)
        self.assertEqual(before, self.manager.status["refresh_ok"])

    def test_get_status_unaffected_by_full_post_cap(self) -> None:
        self._fill_post_slots()
        response = self._request("GET", "/api/status", token=self.TOKEN)

        self.assertIn(b"200 OK", response)


class SyncProbeTagTests(unittest.TestCase):
    """_sync_probe_results must not collide with stable tags."""

    def _manager(self):
        return RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            config_path="noop-sync-singbox.json",
            nodes_path="noop-sync-nodes.json",
            state_path="noop-sync-state.json")

    def test_new_server_takes_next_free_tag(self) -> None:
        manager = self._manager()
        try:
            manager.status["endpoints"] = [
                {"tag": "vpngate-0", "server": "1.1.1.1", "server_port": 443,
                 "country": "X", "country_short": "X", "latency_ms": 1,
                 "real_latency_ms": 1, "speed": 1}]
            nodes = [{"server": "2.2.2.2", "server_port": 443,
                      "country": "Y", "country_short": "Y",
                      "latency_ms": 2, "real_latency_ms": 22, "speed": 2},
                     {"server": "3.3.3.3", "server_port": 443,
                      "country": "Z", "country_short": "Z",
                      "latency_ms": 3, "real_latency_ms": None, "speed": 3}]
            manager._sync_probe_results(nodes)
            tags = [ep["tag"] for ep in manager.status["endpoints"]]
        finally:
            manager.stop()

        self.assertEqual(3, len(tags))
        self.assertEqual(3, len(set(tags)))
        self.assertIn("vpngate-0", tags)
        self.assertTrue(all(t.startswith("vpngate-") for t in tags))


class SnapshotFallbackTests(unittest.TestCase):
    """SNAPSHOT_URLS: try mirrors in order, all must be https."""

    def test_fetch_falls_through_to_second_mirror(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            snapshot_url="https://primary.example/x",
            snapshot_urls=["https://primary.example/x",
                           "https://mirror.example/x"],
            config_path="noop-fb-singbox.json",
            nodes_path="noop-fb-nodes.json",
            state_path="noop-fb-state.json")
        try:
            def fetch(url, timeout):
                if "primary" in url:
                    raise TimeoutError("primary down")
                return "mirror-csv"
            result = manager._fetch_with_retry(fetch)
        finally:
            manager.stop()

        self.assertEqual("mirror-csv", result)

    def test_all_mirrors_down_raises_last_error(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            snapshot_urls=["https://a.example/x", "https://b.example/x"],
            config_path="noop-fb2-singbox.json",
            nodes_path="noop-fb2-nodes.json",
            state_path="noop-fb2-state.json")
        try:
            with self.assertRaises(ConnectionError):
                manager._fetch_with_retry(
                    lambda url, timeout: (_ for _ in ()).throw(
                        ConnectionError("down: " + url)))
        finally:
            manager.stop()

    def test_plain_http_mirror_refused(self) -> None:
        with self.assertRaises(SystemExit):
            build_config_from_env({"PROXY_PASS": "0123456789abcdef",
                                   "SNAPSHOT_URLS": "https://a.example/x,"
                                                    "http://evil.example/x"})

    def test_mirror_list_parsed_from_env(self) -> None:
        cfg = build_config_from_env({"PROXY_PASS": "0123456789abcdef",
                                     "SNAPSHOT_URLS": "https://a.example/x ,"
                                                      "https://b.example/x"})
        self.assertEqual(["https://a.example/x", "https://b.example/x"],
                         cfg["snapshot_urls"])


class DrainTests(unittest.TestCase):
    """stop() drains data-plane mux conns instead of cutting them."""

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=False, auto_refresh=False,
                        fetch_on_start=False,
                        config_path="noop-drain-singbox.json",
                        nodes_path="noop-drain-nodes.json",
                        state_path="noop-drain-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_drain_waits_for_inflight_then_returns_true(self) -> None:
        manager = self._manager()
        try:
            manager._mux_inflight = 1
            timer = threading.Timer(0.2, lambda: setattr(manager, "_mux_inflight", 0))
            timer.start()
            try:
                self.assertTrue(manager._drain(timeout=5))
            finally:
                timer.join(timeout=5)
        finally:
            manager.stop()

    def test_drain_times_out_returns_false(self) -> None:
        manager = self._manager()
        try:
            manager._mux_inflight = 2
            self.assertFalse(manager._drain(timeout=0.1))
        finally:
            manager.stop()


class MemoryMetricTests(unittest.TestCase):
    """status_snapshot carries a memory watermark (None where unavailable)."""

    def test_snapshot_has_memory_key(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            config_path="noop-mem-singbox.json",
            nodes_path="noop-mem-nodes.json",
            state_path="noop-mem-state.json")
        try:
            memory = manager.status_snapshot()["memory"]
        finally:
            manager.stop()

        self.assertIn("rss_mb", memory)
        self.assertTrue(memory["rss_mb"] is None
                        or isinstance(memory["rss_mb"], (int, float)))


class StderrRotationTests(unittest.TestCase):
    """Full stderr logs rotate to .prev instead of being deleted."""

    def test_oversize_log_moves_to_prev(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "singbox-railway.json.stderr.log")
            with open(path, "wb") as handle:
                handle.write(b"x" * (200 * 1024 + 1))
            RailwayManager._rotate_stderr_file(path)
            self.assertFalse(os.path.exists(path))
            self.assertTrue(os.path.exists(path + ".prev"))

    def test_small_log_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "singbox-railway.json.stderr.log")
            with open(path, "wb") as handle:
                handle.write(b"x" * 100)
            RailwayManager._rotate_stderr_file(path)
            self.assertTrue(os.path.exists(path))
            self.assertFalse(os.path.exists(path + ".prev"))


class CpuMetricTests(unittest.TestCase):
    """status_snapshot carries host CPU + MEM (None where /proc unavailable)."""

    def _write(self, tmpdir: str, name: str, text: str) -> str:
        path = os.path.join(tmpdir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_cpu_times_parses_proc_stat(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, "stat",
                               "cpu  100 0 50 700 50 0 0 0 0 0\ncpu0 100 0 50 700 50 0 0 0 0 0\n")
            self.assertEqual((750, 900), _cpu_times(path))

    def test_cpu_times_missing_file_returns_none(self) -> None:
        self.assertIsNone(_cpu_times("/nonexistent-proc-stat"))

    def test_cpu_times_ignores_malformed_first_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, "stat", "garbage line\n")
            self.assertIsNone(_cpu_times(path))

    def test_cpu_pct_between_samples(self) -> None:
        # idle 750->810 (+60), total 900->1000 (+100): 40% busy.
        self.assertAlmostEqual(40.0, _cpu_pct((750, 900), (810, 1000)))

    def test_cpu_pct_zero_delta_is_none(self) -> None:
        self.assertIsNone(_cpu_pct((750, 900), (750, 900)))

    def test_cpu_model_parses_cpuinfo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, "cpuinfo",
                               "processor\t: 0\nmodel name\t: AMD EPYC 7B12\n\n")
            self.assertEqual("AMD EPYC 7B12", _cpu_model(path))

    def test_cpu_model_missing_file_returns_none(self) -> None:
        self.assertIsNone(_cpu_model("/nonexistent-proc-cpuinfo"))

    def test_mem_pct_parses_meminfo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, "meminfo",
                               "MemTotal:        4024548 kB\nMemAvailable:    2415728 kB\n")
            pct = _mem_pct(path)
            self.assertAlmostEqual(40.0, pct, places=1)

    def test_mem_pct_missing_file_returns_none(self) -> None:
        self.assertIsNone(_mem_pct("/nonexistent-proc-meminfo"))

    def test_snapshot_has_cpu_and_mem_keys(self) -> None:
        manager = RailwayManager(
            port=0, mixed_port=get_free_port(),
            start_singbox=False, auto_refresh=False, fetch_on_start=False,
            config_path="noop-cpu-singbox.json",
            nodes_path="noop-cpu-nodes.json",
            state_path="noop-cpu-state.json")
        try:
            snapshot = manager.status_snapshot()
        finally:
            manager.stop()

        self.assertIn("model", snapshot["cpu"])
        self.assertIn("cores", snapshot["cpu"])
        self.assertIn("pct", snapshot["cpu"])
        self.assertTrue(snapshot["cpu"]["pct"] is None
                        or isinstance(snapshot["cpu"]["pct"], (int, float)))
        self.assertIn("pct", snapshot["memory"])
        self.assertTrue(snapshot["memory"]["pct"] is None
                        or isinstance(snapshot["memory"]["pct"], (int, float)))


class AppleInteractionTests(unittest.TestCase):
    """Apple-HIG interaction port: live region, real buttons, undo instead of
    confirm, silent success, IP identity, Google-white light theme, footer CPU."""

    def test_toast_is_live_region(self) -> None:
        self.assertIn('id="toast" role="status" aria-live="polite"', UI_HTML)

    def test_row_actions_are_real_buttons(self) -> None:
        self.assertIn("opbtn", UI_HTML)
        self.assertIn("min-height:28px", UI_HTML)
        # data-attribute delegation contract (single quotes) is preserved.
        self.assertIn("data-probe='", UI_HTML)
        self.assertIn("data-switch='", UI_HTML)

    def test_switch_undo_replaces_confirm(self) -> None:
        self.assertIn('id="switch-undo"', UI_HTML)
        self.assertIn("onUndo(", UI_HTML)
        self.assertIn("撤销换回", UI_HTML)

    def test_success_is_silent_failures_interrupt(self) -> None:
        self.assertNotIn("已切换到 ", UI_HTML)
        self.assertNotIn("节点已刷新", UI_HTML)
        self.assertNotIn("链接已复制", UI_HTML)
        self.assertIn("已复制", UI_HTML)
        # Failure branches still interrupt.
        self.assertIn("已有单测进行中，稍后再试", UI_HTML)
        self.assertIn("已有验证进行中，稍后再试", UI_HTML)

    def test_endpoint_column_shows_server_ip(self) -> None:
        self.assertIn("出口 IP", UI_HTML)
        self.assertIn("class='ip'", UI_HTML)

    def test_google_white_light_theme(self) -> None:
        self.assertIn("#1a73e8", UI_HTML)
        self.assertIn('data-theme="light"', UI_HTML)
        self.assertIn("toggleTheme(", UI_HTML)

    def test_footer_shows_host_cpu_and_mem(self) -> None:
        self.assertIn('id="foot-cpu"', UI_HTML)
        self.assertIn('id="foot-mem"', UI_HTML)

    def test_background_refresh_keeps_old_data(self) -> None:
        self.assertIn('id="thinbar"', UI_HTML)

    def test_verify_shows_elapsed_wait(self) -> None:
        self.assertIn("已等待", UI_HTML)

    def test_login_error_reselects_input(self) -> None:
        self.assertIn("input.select()", UI_HTML)


class AuditFixAConsoleTests(unittest.TestCase):
    """A批:纯修bug,零视觉变化.每条先红后绿."""

    def test_mem_reads_memory_with_mem_fallback(self) -> None:
        self.assertIn("s.mem || s.memory", UI_HTML)

    def test_verify_abort_restores_button(self) -> None:
        start = UI_HTML.index("async function verifyExit")
        block = UI_HTML[start:start + 2200]
        self.assertRegex(block,
                         r'if \(isAbort\(e\)\) \{[^}]*setBusy\("btn-verify", false\)')

    def test_hero_uses_unfiltered_endpoints(self) -> None:
        # preferredEp(s) is the single source: unfiltered s.endpoints,
        # preferred first, first endpoint as fallback, never the
        # filtered eps list.
        start = UI_HTML.index("function preferredEp(")
        block = UI_HTML[start:start + 400]
        self.assertIn("s.preferred_tag", block)
        self.assertIn("(s && s.endpoints) || []", block)
        self.assertNotIn("eps[0]", block)

    def test_hero_labels_latency_source(self) -> None:
        self.assertIn("未真测", UI_HTML)

    def test_401_returns_to_login(self) -> None:
        self.assertIn("登录已失效", UI_HTML)

    def test_copy_reports_real_result(self) -> None:
        self.assertIn("复制失败", UI_HTML)

    def test_double_switch_blocked_while_pending(self) -> None:
        self.assertIn("正在切换中，请稍候", UI_HTML)

    def test_lock_clears_timers(self) -> None:
        self.assertIn("clearTimeout(undoTimer)", UI_HTML)

    def test_login_enter_guards_reentrancy(self) -> None:
        self.assertIn("if (btn.disabled) return;", UI_HTML)

    def test_log_truncates_before_escaping(self) -> None:
        self.assertIn("esc(l.slice(0, 300))", UI_HTML)

    def test_probe_abort_refreshes(self) -> None:
        start = UI_HTML.index("async function probeOne")
        end = UI_HTML.index("async function refreshNow")
        block = UI_HTML[start:end]
        self.assertRegex(block,
                         r'if \(isAbort\(e\)\) \{[^}]*refresh\(\)')


class AuditFixBConsoleTests(unittest.TestCase):
    """B批:无障碍+可见体验.每条先红后绿."""

    def test_headers_keyboard_sortable(self) -> None:
        self.assertIn("aria-sort", UI_HTML)

    def test_undo_is_button(self) -> None:
        self.assertIn('<button id="undo-link"', UI_HTML)

    def test_login_error_announced(self) -> None:
        self.assertIn('id="login-err" role="alert"', UI_HTML)

    def test_gradient_darkened_for_contrast(self) -> None:
        self.assertIn("#4338CA", UI_HTML)

    def test_verify_color_uses_classes(self) -> None:
        self.assertNotIn('el.style.color = "#fca5a5"', UI_HTML)
        self.assertIn("verify-err", UI_HTML)

    def test_empty_link_uses_theme_class(self) -> None:
        self.assertNotIn('style="color:#8ab4ff;cursor:pointer"', UI_HTML)
        self.assertIn("linklike", UI_HTML)

    def test_light_status_colors_pass(self) -> None:
        self.assertIn("#B06000", UI_HTML)
        self.assertIn("#174EA6", UI_HTML)

    def test_search_has_name(self) -> None:
        self.assertIn('aria-label="搜索节点', UI_HTML)

    def test_row_buttons_named(self) -> None:
        self.assertIn("aria-label='切换到 ", UI_HTML)

    def test_focus_falls_back_to_search(self) -> None:
        self.assertIn('getElementById("node-search").focus()', UI_HTML)

    def test_scope_rebuilds_on_change_only(self) -> None:
        self.assertIn("scopeSig", UI_HTML)

    def test_progress_and_verify_named_live(self) -> None:
        self.assertIn('aria-label="全量真测进度"', UI_HTML)
        self.assertIn('id="verify-result" aria-live="polite"', UI_HTML)

    def test_fullprobe_silent_cancelable(self) -> None:
        self.assertIn('id="btn-fullprobe-cancel"', UI_HTML)
        self.assertNotIn("全量真测已开始", UI_HTML)
        self.assertNotIn("全量真测完成：", UI_HTML)

    def test_empty_states_guide_next_action(self) -> None:
        self.assertIn("重试刷新", UI_HTML)
        self.assertIn("先全量真测", UI_HTML)

    def test_statusbar_tri_state(self) -> None:
        self.assertIn('id="sb-dot"', UI_HTML)

    def test_unmeasured_switch_clickable(self) -> None:
        self.assertNotIn("disabled title='先测速", UI_HTML)


class AuditP2StatsTests(unittest.TestCase):
    """P2-1:统计卡布局/单位/时长/错误外露."""

    def test_stats_grid_auto_fit(self) -> None:
        self.assertIn("auto-fit", UI_HTML)

    def test_traffic_keeps_unit(self) -> None:
        self.assertNotIn('replace(" GB"', UI_HTML)

    def test_uptime_humanized(self) -> None:
        self.assertIn("function fmtDur(", UI_HTML)

    def test_refresh_error_chip(self) -> None:
        self.assertIn('id="stat-err"', UI_HTML)

    def test_history_line_chinese(self) -> None:
        self.assertIn("刷新成功/失败", UI_HTML)
        self.assertNotIn("refresh ok/fail:", UI_HTML)

    def test_history_keeps_twenty(self) -> None:
        self.assertIn(".slice(0, 20)", UI_HTML)
        self.assertNotIn(".slice(0, 12)", UI_HTML)


class AuditP2LogsTests(unittest.TestCase):
    """P2-2:日志搜索/自动滚动/自动刷新/级别说明/深色样式."""

    def test_log_search_and_autoscroll(self) -> None:
        self.assertIn('id="log-search"', UI_HTML)
        self.assertIn('id="log-auto"', UI_HTML)

    def test_loglevel_dark_styled(self) -> None:
        self.assertIn("#sortsel,#scope,#loglevel", UI_HTML)

    def test_loglevel_documents_mapping(self) -> None:
        self.assertIn("error≈fail", UI_HTML)


class AuditP2SubTests(unittest.TestCase):
    """P2-3:订阅死链消除/行标签/host 说明/复制全部."""

    def test_sub_nav_toggleable(self) -> None:
        self.assertIn('id="nav-sub"', UI_HTML)

    def test_sub_rows_labeled(self) -> None:
        self.assertIn("直连", UI_HTML)
        self.assertIn("跟随当前出口", UI_HTML)

    def test_sub_host_note(self) -> None:
        self.assertIn('id="sub-host"', UI_HTML)

    def test_copy_all_present(self) -> None:
        self.assertIn('id="btn-copy-all"', UI_HTML)


class AuditP2MobileTests(unittest.TestCase):
    """P2-4:移动端导航保留/粘性列."""

    def test_nav_not_removed_on_mobile(self) -> None:
        self.assertNotIn("#topnav .links{display:none}", UI_HTML)

    def test_sticky_columns(self) -> None:
        self.assertIn("td:first-child", UI_HTML)
        self.assertIn("sticky", UI_HTML)


class AuditP2LoginThemeTests(unittest.TestCase):
    """P2-5:登录手感/主题入口/文案中文化."""

    def test_token_show_toggle(self) -> None:
        self.assertIn('id="btn-show-token"', UI_HTML)

    def test_gate_theme_toggle(self) -> None:
        self.assertIn('id="btn-theme-gate"', UI_HTML)

    def test_login_sub_names_variables(self) -> None:
        self.assertIn("Variables", UI_HTML)

    def test_theme_label_is_action(self) -> None:
        self.assertIn("切换到", UI_HTML)

    def test_no_english_loading(self) -> None:
        self.assertNotIn("loading…", UI_HTML)
        self.assertIn("加载中…", UI_HTML)

    def test_no_english_fetch_error(self) -> None:
        self.assertNotIn("status fetch failed:", UI_HTML)

    def test_live_named_and_titled(self) -> None:
        self.assertIn('lang="en">LIVE', UI_HTML)
        self.assertIn('title="自动刷新每15秒"', UI_HTML)


class AuditP2A11yTests(unittest.TestCase):
    """P2-6:骨架屏/ toast 分流/曲线替代/顶栏不透明."""

    def test_skeleton_hidden_from_at(self) -> None:
        self.assertIn("aria-hidden='true'", UI_HTML)
        self.assertIn('id="load-note"', UI_HTML)

    def test_vh_class_present(self) -> None:
        self.assertIn(".vh{", UI_HTML)

    def test_alerts_container(self) -> None:
        self.assertIn('id="alerts"', UI_HTML)

    def test_spark_alternative(self) -> None:
        self.assertIn('role="img"', UI_HTML)
        self.assertIn('id="spark-alt"', UI_HTML)

    def test_dark_bars_opaque(self) -> None:
        self.assertIn("rgba(10,12,24,.88)", UI_HTML)


class AuditLowTests(unittest.TestCase):
    """Low:400 detail/toast 浅色/dot 文本/冗余清理/死规则."""

    def test_api_surfaces_detail(self) -> None:
        self.assertIn(".detail ||", UI_HTML)

    def test_toast_light_card(self) -> None:
        self.assertIn('html[data-theme="light"] .toast-msg', UI_HTML)

    def test_dot_has_text(self) -> None:
        self.assertIn('id="sb-dot-txt"', UI_HTML)

    def test_no_redundant_aria_disabled(self) -> None:
        self.assertNotIn("aria-disabled='true' disabled", UI_HTML)

    def test_dead_topnav_input_rule_removed(self) -> None:
        self.assertNotIn("#topnav input{", UI_HTML)


class TimeoutDefaultsTests(unittest.TestCase):
    """Real-tunnel dials time out at 20s by default (CI-measured: alive
    nodes answer in 3-6s, dead ones burn the full budget)."""

    def test_dial_timeout_defaults_to_twenty(self) -> None:
        for fn in (measure_real_latency, measure_exit_ip):
            self.assertEqual(
                20, inspect.signature(fn).parameters["timeout"].default,
                fn.__name__)
        for fn in (snapshot_to_nodes, snapshot_to_endpoints):
            self.assertEqual(
                20, inspect.signature(fn).parameters["dial_timeout"].default,
                fn.__name__)


class RefreshIntervalTests(unittest.TestCase):
    def test_refresh_defaults_to_hourly(self) -> None:
        env = {"PORT": "3000", "PROXY_USER": "u",
               "PROXY_PASS": "0123456789abcdef"}

        self.assertEqual(3600, build_config_from_env(env)["refresh_seconds"])


class FullProbeOrderTests(unittest.TestCase):
    """Full probe dials handshake-ascending so the fastest candidates
    resolve first (progressive pin can serve traffic in seconds)."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-ord-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-ord-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-ord-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *specs):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": hand, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, (ip, hand) in enumerate(specs)]

    def test_full_probe_dials_handshake_ascending(self) -> None:
        started: list[str] = []
        lock = threading.Lock()

        def dial(node):
            with lock:
                started.append(node["server"])
            return 50

        manager = self._manager(dial_fn=dial, full_probe_workers=1)
        try:
            self._seed_nodes(manager, ("203.0.113.11", 300),
                             ("203.0.113.12", 100), ("203.0.113.13", 200))
            with _fake_singbox():
                self._post(manager, "/api/full_probe")
                manager._full_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual(["203.0.113.12", "203.0.113.13", "203.0.113.11"],
                         started)


class RefreshAutoProbeTests(unittest.TestCase):
    """Every successful refresh kicks off a background full probe."""

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        config_path=f"{_TMP}/railway-rap-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-rap-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-rap-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_successful_refresh_starts_full_probe(self) -> None:
        manager = self._manager()
        try:
            with _fake_singbox(), \
                 mock.patch("railway_manager.probe_tcp_latency",
                            return_value=100), \
                 mock.patch.object(manager, "_start_full_probe",
                                   return_value=True) as starter:
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv(
                        "203.0.113.11", "203.0.113.12"))
        finally:
            manager.stop()

        self.assertTrue(ok)
        starter.assert_called_once_with()

    def test_failed_refresh_does_not_start_full_probe(self) -> None:
        manager = self._manager()
        try:
            with mock.patch.object(manager, "_start_full_probe",
                                   return_value=True) as starter:
                def boom(url, timeout):
                    raise TimeoutError("network down")

                ok = manager.refresh_once(fetcher=boom)
        finally:
            manager.stop()

        self.assertFalse(ok)
        starter.assert_not_called()


class RefreshGateTests(unittest.TestCase):
    """The refresh stays out of the pin decision.

    The old gate ("refresh waits for this round's full probe before applying
    the pin") was removed with the simpler-manager rewrite: rotate mode never
    re-dials a serving node - a second session would kick the live one (D13) -
    so a refresh cannot re-measure the nodes it serves, and re-picking the pin
    from such a measurement would only pin a stale node. The health loop that
    rides the served chain is the only judge of the pin.
    """

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        config_path=f"{_TMP}/railway-rgate-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-rgate-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-rgate-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_refresh_never_hands_the_pin_to_a_stale_measurement(self) -> None:
        """A refresh must not re-pick the pin from this round's dials.

        Rotate mode never re-dials a serving node (a second session would kick
        the live one), so the "stale measurement" problem is solved by keeping
        the refresh out of the pin decision entirely: the health loop, which
        rides the served chain, is the judge.

        real_topk=0 so the refresh-stage dial cannot reveal the death either
        way; assertions are made the moment refresh_once returns (no join).
        """
        manager = self._manager(
            real_topk=0,
            dial_fn=lambda node: None
            if node["server"] == "203.0.113.11" else 40)
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 20, "real_latency_ms": 10,
                               "speed": 9000,
                               "endpoint": {"tag": "vpngate-0",
                                            "server": "203.0.113.11",
                                            "server_port": 443}},
                              {"server": "203.0.113.12", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 300, "real_latency_ms": None,
                               "speed": 100,
                               "endpoint": {"tag": "vpngate-1",
                                            "server": "203.0.113.12",
                                            "server_port": 443}}]
            manager.preferred_tag = "vpngate-0"
            manager.status["preferred_tag"] = "vpngate-0"
            manager._auto_pinned = True
            manager._chain_pin_at = time.monotonic() - 3600.0
            with _fake_singbox(), \
                 mock.patch("railway_manager.probe_tcp_latency",
                            return_value=100), \
                 mock.patch.object(manager, "verify_fn",
                                   side_effect=lambda ep: ("9.9.9.9", 11)):
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv(
                        "203.0.113.11", "203.0.113.12"))
                pin_at_return = manager.preferred_tag
                # The pin only moves when its chain stops carrying traffic.
                rescued = manager.check_pinned_health(
                    probe_fn=lambda host, port, timeout=5: 0)
                pin_after_health = manager.preferred_tag
            if manager._full_probe_thread is not None:
                manager._full_probe_thread.join(timeout=60)
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual("vpngate-0", pin_at_return)
        self.assertEqual("rescued", rescued)
        self.assertEqual("vpngate-1", pin_after_health)

    def test_refresh_is_not_blocked_by_a_wedged_full_probe(self) -> None:
        """The full probe runs in the background: a wedged dial must not wedge
        refresh, and the previous pin is kept (refresh never re-picks it)."""
        gate = threading.Event()
        manager = self._manager(
            real_topk=0,
            dial_fn=lambda node: gate.wait(timeout=300) or 50)
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 20, "real_latency_ms": 10,
                               "speed": 9000,
                               "endpoint": {"tag": "vpngate-0",
                                            "server": "203.0.113.11",
                                            "server_port": 443}},
                              {"server": "203.0.113.12", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 300, "real_latency_ms": None,
                               "speed": 100,
                               "endpoint": {"tag": "vpngate-1",
                                            "server": "203.0.113.12",
                                            "server_port": 443}}]
            manager.preferred_tag = "vpngate-0"
            manager.status["preferred_tag"] = "vpngate-0"
            manager._auto_pinned = True
            manager._chain_pin_at = time.monotonic() - 3600.0
            with _fake_singbox(), \
                 mock.patch("railway_manager.probe_tcp_latency",
                            return_value=100):
                t0 = time.monotonic()
                ok = manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv(
                        "203.0.113.11", "203.0.113.12"))
                dt = time.monotonic() - t0
            gate.set()
            if manager._full_probe_thread is not None:
                manager._full_probe_thread.join(timeout=60)
        finally:
            gate.set()
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual("vpngate-0", manager.preferred_tag)
        # The probe target (vpngate-1) wedges for 300s; refresh returned at
        # once because the full pass is a background thread.
        self.assertLess(dt, 30)

class AutoPinTests(unittest.TestCase):
    """Full-probe completion pins best + backup with guards."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-ap-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-ap-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-ap-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _seed_nodes(self, manager, *specs):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": hand, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, (ip, hand) in enumerate(specs)]

    def _run_probe(self, manager, dial, verify=None):
        manager.dial_fn = dial
        # Auto-pin verifies exit IPs; unit tests stub it alive unless they
        # pass their own `verify`. It has to be injected HERE: patching
        # manager.verify_fn outside would be shadowed by this patch and the
        # caller's assertion would be vacuous.
        side_effect = verify if verify is not None else (
            lambda ep: ("9.9.9.9", 11))
        with _fake_singbox(), \
             mock.patch.object(manager, "verify_fn", side_effect=side_effect):
            self._post(manager, "/api/full_probe")
            manager._full_probe_thread.join(timeout=30)

    def test_completion_pins_best_and_second(self) -> None:
        dial = lambda node: {"203.0.113.11": 70, "203.0.113.12": 30,
                             "203.0.113.13": 50}[node["server"]]
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200), ("203.0.113.13", 300))
            self._run_probe(manager, dial)
            written = _read_json(manager.config_path)
            events = [e["event"] for e in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertEqual("vpngate-2", manager.backup_tag)
        self.assertEqual("vpngate-2", manager.status["backup_tag"])
        chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-1", "vpngate-2", "auto"], chain["outbounds"])
        self.assertIn("auto-pin", events)

    def test_zero_measured_pins_nothing(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            self._run_probe(manager, lambda node: None)
        finally:
            manager.stop()

        self.assertIsNone(manager.preferred_tag)
        self.assertIsNone(manager.backup_tag)

    def test_manual_pin_is_respected(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            manager.preferred_tag = "vpngate-0"
            manager.status["preferred_tag"] = "vpngate-0"
            manager._auto_pinned = False
            self._run_probe(manager, lambda node: 10)
        finally:
            manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertIsNone(manager.backup_tag)

    def test_rotate_cold_start_never_dials_to_verify(self) -> None:
        """Rotate mode must not verify by dialing.

        `verify_fn` starts a throwaway sing-box client, i.e. a SECOND VPNGate
        session: duplicate-cn kicks the one the rotation is serving. The
        rotation already dialed these nodes (real_latency_ms is set only after
        a real dial), so the pin is taken from them directly."""
        verify_calls: list[str] = []

        def _verify(ep):
            verify_calls.append(ep["server"])
            return ("9.9.9.9", 11)

        manager = self._manager(resi_rotate=True, vless_uuid="u-u-i-d")
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            manager._nodes[0]["real_latency_ms"] = 10
            manager._nodes[1]["real_latency_ms"] = 20
            manager.verify_fn = _verify
            with mock.patch.object(RailwayManager, "_check_config",
                                   return_value=True), \
                 mock.patch.object(RailwayManager, "_restart_singbox"):
                manager._auto_pin_best(manager._nodes, None)
            events = [e["event"] for e in manager.status["refresh_history"]]
            pinned = manager.preferred_tag
            backup = manager.backup_tag
        finally:
            manager.stop()

        self.assertEqual([], verify_calls,
                         "rotate mode must never dial a node to verify it")
        self.assertEqual("vpngate-0", pinned)
        self.assertIsNone(backup, "rotate mode reserves exactly one node")
        self.assertIn("auto-pin-unverified", events)

    def test_a_repeated_full_probe_does_not_restart_singbox(self) -> None:
        """The full probe re-publishes the same config: the file is identical
        and sing-box is NOT restarted the second time (no flap, no dropped
        client connection)."""
        dial = lambda node: {"203.0.113.11": 70, "203.0.113.12": 30}[node["server"]]
        manager = self._manager(start_singbox=True)
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            manager._singbox_proc = mock.Mock(poll=mock.Mock(return_value=None))
            with mock.patch.object(RailwayManager, "_restart_singbox") as restart:
                self._run_probe(manager, dial)
                first = Path(manager.config_path).read_bytes()
                restarts_after_first = restart.call_count
                self._run_probe(manager, dial)
                second = Path(manager.config_path).read_bytes()
                restarts_after_second = restart.call_count
        finally:
            manager.stop()

        self.assertGreaterEqual(restarts_after_first, 1,
                                "the first pass has to publish the config")
        self.assertEqual(restarts_after_first, restarts_after_second,
                         "an unchanged config must not restart sing-box")
        self.assertEqual(first, second, "the config must be byte-identical")

    def test_tie_keeps_current_without_flap(self) -> None:
        """An existing pin is never re-verified and never replaced: the full
        probe publishes the SAME pin pair, so the chain selector still points
        at the pin the operator chose (no flap)."""
        verify_mock = mock.Mock(return_value=("9.9.9.9", 11))
        manager = self._manager(start_singbox=True)
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            manager.preferred_tag = "vpngate-1"
            manager.status["preferred_tag"] = "vpngate-1"
            manager.backup_tag = "vpngate-0"
            manager.status["backup_tag"] = "vpngate-0"
            manager._auto_pinned = True
            manager._singbox_proc = mock.Mock(poll=mock.Mock(return_value=None))
            with mock.patch.object(RailwayManager, "_restart_singbox") as restart:
                self._run_probe(manager, lambda node: {"203.0.113.11": 60,
                                                       "203.0.113.12": 50}[node["server"]],
                                verify=verify_mock)
                events = [e["event"]
                          for e in manager.status["refresh_history"]]
                config = _read_json(manager.config_path)
        finally:
            manager.stop()

        # The pin and the standby are untouched ...
        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertEqual("vpngate-0", manager.backup_tag)
        self.assertIn("auto-pin-skipped", events)
        # ... and the pin was never verified (a verify dials the node, which
        # would open a second VPNGate session and kill the serving one).
        verify_mock.assert_not_called()
        # ... and the published config still points the chain at that pin.
        chain = next((o for o in config["outbounds"]
                      if o.get("tag") == "chain"), None)
        self.assertIsNotNone(chain, "a pinned chain must publish a selector")
        self.assertEqual("vpngate-1", chain["outbounds"][0])
        self.assertEqual("vpngate-1", chain.get("default"))
        self.assertIn("vpngate-0", chain["outbounds"],
                      "the standby stays in the selector")
        self.assertEqual(1, restart.call_count,
                         "the probe publishes the config exactly once")

    @unittest.skip("auto-pin repin path was dropped in the simpler-manager rewrite; AUTO_REPIN is no longer wired from env")
    def test_same_best_refreshes_stale_backup(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200),
                             ("203.0.113.13", 300))
            manager.preferred_tag = "vpngate-2"
            manager.status["preferred_tag"] = "vpngate-2"
            manager.backup_tag = "vpngate-0"
            manager.status["backup_tag"] = "vpngate-0"
            manager._auto_pinned = True
            self._run_probe(manager, lambda node: {"203.0.113.11": 60,
                                                   "203.0.113.12": 50,
                                                   "203.0.113.13": 30}[node["server"]])
            written = _read_json(manager.config_path)
        finally:
            manager.stop()

        self.assertEqual("vpngate-2", manager.preferred_tag)
        self.assertEqual("vpngate-1", manager.backup_tag)
        chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-2", "vpngate-1", "auto"], chain["outbounds"])

    @unittest.skip("auto-pin repin path was dropped in the simpler-manager rewrite; AUTO_REPIN is no longer wired from env")
    def test_auto_track_repins_to_new_best(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            self._run_probe(manager, lambda node: {"203.0.113.11": 60,
                                                   "203.0.113.12": 50}[node["server"]])
            # progressive pin may land on whichever node finished first;
            # the repin below must still converge on the new best (.11).
            self.assertIn(manager.preferred_tag, ("vpngate-0", "vpngate-1"))
            self._run_probe(manager, lambda node: {"203.0.113.11": 30,
                                                   "203.0.113.12": 80}[node["server"]])
            written = _read_json(manager.config_path)
            events = [e["event"] for e in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual("vpngate-1", manager.backup_tag)
        chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "vpngate-1", "auto"], chain["outbounds"])
        self.assertIn("auto-pin", events)

    def test_single_measured_pins_best_only(self) -> None:
        dial = lambda node: 40 if node["server"] == "203.0.113.11" else None
        manager = self._manager()
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            self._run_probe(manager, dial)
            written = _read_json(manager.config_path)
        finally:
            manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertIsNone(manager.backup_tag)
        chain = next(o for o in written["outbounds"] if o["tag"] == "chain")
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])


class ProgressivePinTests(unittest.TestCase):
    """No pin before the run completes: cold boot pins only after a full
    measurement, so the first serving pin is the measured best, never a
    blind first-finisher."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-pp-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-pp-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-pp-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))

    def test_first_measured_pins_before_completion(self) -> None:
        def dial(node):
            if node["server"] == "203.0.113.13":
                time.sleep(3)
                return 10
            return {"203.0.113.11": 60, "203.0.113.12": 50}[node["server"]]

        manager = self._manager(dial_fn=dial)
        try:
            manager._nodes = [
                {"server": f"203.0.113.1{i}", "server_port": 443,
                 "country": "Japan", "country_short": "JP",
                 "latency_ms": 100 * i, "real_latency_ms": None,
                 "speed": 1000,
                 "endpoint": {"tag": f"vpngate-{i - 1}",
                              "server": f"203.0.113.1{i}",
                              "server_port": 443}}
                for i in (1, 2, 3)]
            with _fake_singbox(), \
                 mock.patch.object(manager, "verify_fn",
                                   side_effect=lambda ep: ("9.9.9.9", 11)):
                self._post(manager, "/api/full_probe")
                seen: set = set()
                deadline = time.monotonic() + 20
                while manager._full_probe_thread.is_alive():
                    # Only sample while dials are still in flight: once
                    # full_probe.state flips to done, _auto_pin_best may
                    # already have committed (thread teardown window).
                    if manager.status["full_probe"]["state"] != "done":
                        seen.add(manager.preferred_tag)
                    if time.monotonic() > deadline:
                        break
                    time.sleep(0.05)
                manager._full_probe_thread.join(timeout=30)
                events = [e["event"]
                          for e in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertIn("vpngate-2", [n["endpoint"]["tag"]
                                    for n in manager._nodes
                                    if n["real_latency_ms"] == 10])
        self.assertEqual({None}, seen,
                         f"pin happened before completion: {seen}")
        self.assertNotIn("auto-pin-first", events)
        self.assertEqual("vpngate-2", manager.preferred_tag)
        self.assertEqual("vpngate-1", manager.backup_tag)

    def test_later_cycles_only_measure(self) -> None:
        def dial(node):
            return {"203.0.113.11": 60, "203.0.113.12": 50}[node["server"]]

        manager = self._manager(dial_fn=dial)
        try:
            manager._nodes = [
                {"server": f"203.0.113.1{i}", "server_port": 443,
                 "country": "Japan", "country_short": "JP",
                 "latency_ms": 100 * i, "real_latency_ms": None,
                 "speed": 1000,
                 "endpoint": {"tag": f"vpngate-{i - 1}",
                              "server": f"203.0.113.1{i}",
                              "server_port": 443}}
                for i in (1, 2)]
            with _fake_singbox(), \
                 mock.patch.object(manager, "verify_fn",
                                   side_effect=lambda ep: ("9.9.9.9", 11)):
                self._post(manager, "/api/full_probe")
                manager._full_probe_thread.join(timeout=30)
                auto_pin_calls = manager.preferred_tag
                self._post(manager, "/api/full_probe")
                manager._full_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual("vpngate-1", auto_pin_calls)
        self.assertEqual(auto_pin_calls, manager.preferred_tag)


class PinStateTests(unittest.TestCase):
    """backup_tag + auto_pinned survive in state.json; manual switch clears."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, tmpdir, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_switch_clears_backup_and_marks_manual(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=100):
                    self.assertTrue(manager.refresh_once(
                        fetcher=lambda url, timeout: _snapshot_csv(
                            "203.0.113.11", "203.0.113.12")))
                    ok, _ = manager.switch(tag="vpngate-0")
                    self.assertTrue(ok)
                    state = _read_json(f"{tmpdir}/state.json")
            finally:
                manager.stop()

        self.assertEqual({"preferred_tag": "vpngate-0", "backup_tag": None,
                          "auto_pinned": False}, state)
        self.assertFalse(manager._auto_pinned)

    def test_state_round_trips_backup_and_auto_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: 50,
                                    verify_fn=lambda ep: ("9.9.9.9", 11))
            try:
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=100):
                    self.assertTrue(manager.refresh_once(
                        fetcher=lambda url, timeout: _snapshot_csv(
                            "203.0.113.11", "203.0.113.12")))
                    # The auto full probe triggered by refresh runs in a
                    # background thread; join it inside the fake-singbox
                    # scope so its _apply_config sees the mocked check.
                    manager._full_probe_thread.join(timeout=60)
                    probe_state = manager.status["full_probe"]["state"]
            finally:
                manager.stop()

            self.assertEqual("done", probe_state)

            reloaded = self._manager(tmpdir)
            try:
                _, preferred = reloaded.load_persisted()
            finally:
                reloaded.stop()

        events = [e["event"] for e in manager.status["refresh_history"]]
        self.assertNotIn("auto-pin-skipped", events,
                         [e for e in manager.status["refresh_history"]
                          if e["event"] == "auto-pin-skipped"])
        self.assertIsNotNone(preferred)
        self.assertEqual(manager.backup_tag, reloaded.backup_tag)
        self.assertTrue(reloaded._auto_pinned)

    def test_old_state_file_loads_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = f"{tmpdir}/state.json"
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump({"preferred_tag": "vpngate-0"}, handle)
            manager = self._manager(tmpdir)
            try:
                _, preferred = manager.load_persisted()
            finally:
                manager.stop()

        self.assertEqual("vpngate-0", preferred)
        self.assertIsNone(manager.backup_tag)
        self.assertFalse(manager._auto_pinned)


class SettingsApiTests(unittest.TestCase):
    """GET/POST /api/settings: auth, validation, apply, persistence."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, tmpdir, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json",
                        settings_path=f"{tmpdir}/settings.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _request(self, manager, method, path, body=None, token=True):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = f"{method} {path} HTTP/1.1\r\n"
        if body is not None:
            payload = json.dumps(body).encode()
            raw += f"Content-Length: {len(payload)}\r\n"
        else:
            payload = b""
            raw += "Content-Length: 0\r\n"
        if token:
            raw += f"Authorization: Bearer {self.TOKEN}\r\n"
        client = FakeClient()
        manager._handle_http(client, (raw + "\r\n").encode("latin-1") + payload)
        head, _, resp_body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], resp_body

    def test_get_requires_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, _ = self._request(manager, "GET", "/api/settings",
                                               token=False)
            finally:
                manager.stop()

        self.assertIn("401", status_line)

    def test_get_returns_values_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, body = self._request(manager, "GET", "/api/settings")
                payload = json.loads(body.decode())
            finally:
                manager.stop()

        self.assertIn("200", status_line)
        for key in ("refresh_seconds", "dial_timeout", "real_topk",
                    "dial_workers", "full_probe_workers", "probe_workers",
                    "auto_repin", "auto_rescue"):
            self.assertIn(key, payload["values"], key)
            self.assertIn(key, payload["bounds"], key)
        self.assertEqual(3600, payload["values"]["refresh_seconds"])
        self.assertEqual(15, payload["values"]["dial_timeout"])
        self.assertFalse(payload["values"]["auto_repin"])

    def test_post_rejects_unknown_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, body = self._request(
                    manager, "POST", "/api/settings", {"PORT": 3000})
            finally:
                manager.stop()

        self.assertIn("400", status_line)
        self.assertFalse(json.loads(body.decode())["ok"])

    def test_post_rejects_out_of_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, _ = self._request(
                    manager, "POST", "/api/settings",
                    {"refresh_seconds": 60})
            finally:
                manager.stop()

        self.assertIn("400", status_line)

    def test_post_rejects_wrong_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, _ = self._request(
                    manager, "POST", "/api/settings",
                    {"dial_workers": "lots"})
            finally:
                manager.stop()

        self.assertIn("400", status_line)

    def test_post_applies_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                status_line, body = self._request(
                    manager, "POST", "/api/settings",
                    {"refresh_seconds": 1800, "dial_timeout": 45,
                     "auto_repin": False})
                self.assertIn("200", status_line)
                self.assertTrue(json.loads(body.decode())["ok"])
                saved = _read_json(f"{tmpdir}/settings.json")
            finally:
                manager.stop()

            reloaded = self._manager(tmpdir)
            try:
                values = reloaded.settings_snapshot()["values"]
            finally:
                reloaded.stop()

        self.assertEqual(1800, manager.refresh_seconds)
        self.assertEqual(45, manager.dial_timeout)
        self.assertFalse(manager.auto_repin)
        self.assertEqual(1800, saved["refresh_seconds"])
        self.assertEqual(1800, values["refresh_seconds"])
        self.assertEqual(45, values["dial_timeout"])

    def test_new_env_defaults(self) -> None:
        base = {"PORT": "3000", "PROXY_USER": "u",
                "PROXY_PASS": "0123456789abcdef"}
        cfg = build_config_from_env(dict(base))
        self.assertEqual(15, cfg["dial_timeout"])
        self.assertEqual(15, cfg["probe_workers"])
        self.assertTrue(cfg["auto_rescue"])
        self.assertNotIn("auto_repin", cfg)
        override = dict(base, DIAL_TIMEOUT="45", PROBE_WORKERS="30",
                        AUTO_RESCUE="false")
        cfg = build_config_from_env(override)
        self.assertEqual(45, cfg["dial_timeout"])
        self.assertEqual(30, cfg["probe_workers"])
        self.assertFalse(cfg["auto_rescue"])


class DialTimeoutPlumbingTests(unittest.TestCase):
    """Configured dial timeout reaches all four real-tunnel paths."""

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        config_path=f"{_TMP}/railway-dtp-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-dtp-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-dtp-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def test_default_dial_fn_uses_configured_timeout(self) -> None:
        manager = self._manager()
        try:
            node = {"endpoint": {"server": "203.0.113.11", "server_port": 443}}
            with mock.patch("railway_manager.measure_real_latency",
                            return_value=100) as dial:
                manager.dial_fn(node)
                manager.update_settings({"dial_timeout": 45})
                manager.dial_fn(node)
        finally:
            manager.stop()

        timeouts = [call.kwargs.get("timeout", call.args[2]
                                    if len(call.args) > 2 else None)
                    for call in dial.call_args_list]
        self.assertEqual([15, 45], timeouts)

    def test_default_verify_fn_uses_configured_timeout(self) -> None:
        manager = self._manager()
        try:
            endpoint = {"server": "203.0.113.11", "server_port": 443}
            with mock.patch("railway_manager.measure_exit_ip",
                            return_value=("1.2.3.4", 100)) as verify:
                manager.verify_fn(endpoint)
                manager.update_settings({"dial_timeout": 45})
                manager.verify_fn(endpoint)
        finally:
            manager.stop()

        timeouts = [call.kwargs.get("timeout", call.args[2]
                                    if len(call.args) > 2 else None)
                    for call in verify.call_args_list]
        self.assertEqual([15, 45], timeouts)

    def test_refresh_forwards_probe_workers_and_timeout(self) -> None:
        manager = self._manager(probe_workers=33, dial_timeout=44)
        try:
            with mock.patch("railway_manager.snapshot_to_nodes",
                            return_value=[]) as snapshot_mock:
                manager.refresh_once(
                    fetcher=lambda url, timeout: _snapshot_csv("203.0.113.11"))
        finally:
            manager.stop()

        _, kwargs = snapshot_mock.call_args
        self.assertEqual(33, kwargs.get("probe_workers"))
        self.assertEqual(44, kwargs.get("dial_timeout"))


class AutoPinFlagTests(unittest.TestCase):
    """auto_repin=False disables hourly re-pin; auto_rescue=False keeps
    the legacy unpin-to-auto fallback."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-apf-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-apf-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-apf-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post(self, manager, path):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: 0\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1"))

    def _seed_nodes(self, manager, *specs):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": hand, "real_latency_ms": None,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, (ip, hand) in enumerate(specs)]

    def test_auto_repin_off_skips_pin(self) -> None:
        manager = self._manager(auto_repin=False)
        try:
            self._seed_nodes(manager, ("203.0.113.11", 100),
                             ("203.0.113.12", 200))
            manager.dial_fn = lambda node: 50
            with _fake_singbox():
                self._post(manager, "/api/full_probe")
                manager._full_probe_thread.join(timeout=30)
                events = [e["event"]
                          for e in manager.status["refresh_history"]]
        finally:
            manager.stop()

        self.assertIsNone(manager.preferred_tag)
        self.assertIn("auto-pin-skipped", events)

    def test_auto_rescue_off_falls_back_to_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                config_path=f"{tmpdir}/singbox.json",
                nodes_path=f"{tmpdir}/nodes.json",
                state_path=f"{tmpdir}/state.json",
                auto_rescue=False)
            try:
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=100):
                    self.assertTrue(manager.refresh_once(
                        fetcher=lambda url, timeout: _snapshot_csv(
                            "203.0.113.11", "203.0.113.12")))
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")
                    # A pin from an earlier round, not a warm-up pin: the
                    # grace must not depend on how long the machine is up.
                    manager._chain_pin_at = time.monotonic() - 3600.0
                    by_server = {n["server"]: n for n in manager._nodes}
                    by_server["203.0.113.11"]["real_latency_ms"] = 70
                    by_server["203.0.113.12"]["real_latency_ms"] = 30

                    failing = lambda host, port, timeout=5: 0
                    with mock.patch.object(manager, "dial_fn",
                                           return_value=None):
                        self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                        self.assertEqual("pinned", manager.check_pinned_health(probe_fn=failing))
                        self.assertEqual("unpinned", manager.check_pinned_health(probe_fn=failing))
                self.assertIsNone(manager.preferred_tag)
            finally:
                manager.stop()


class SettingsUITests(unittest.TestCase):
    """Console settings section is wired to /api/settings."""

    def test_settings_section_and_nav(self) -> None:
        self.assertIn('id="sec-settings"', UI_HTML)
        self.assertIn('#sec-settings', UI_HTML)
        self.assertIn("sec-settings", UI_HTML)

    def test_settings_js_wired(self) -> None:
        self.assertIn("loadSettings(", UI_HTML)
        self.assertIn("saveSettings(", UI_HTML)
        self.assertIn("/api/settings", UI_HTML)
        self.assertIn('id="btn-settings-save"', UI_HTML)


class DualPinUITests(unittest.TestCase):
    """Console surfaces the backup pin."""

    def test_backup_tag_surfaced(self) -> None:
        self.assertIn("backup_tag", UI_HTML)

    def test_backup_label(self) -> None:
        self.assertIn("备选", UI_HTML)


class VerifyAttributionTests(unittest.TestCase):
    """Batch 1 (attribution chain): verify results carry a generation and
    stale writes are discarded; pin changes invalidate the verify state."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-verifyattr-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-verifyattr-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-verifyattr-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": 50,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, ip in enumerate(ips)]

    def test_verify_generation_increments(self) -> None:
        manager = self._manager(verify_fn=lambda ep: ("9.9.9.9", 11))
        try:
            self._seed_nodes(manager, "203.0.113.11")
            node = manager._nodes[0]
            self.assertTrue(manager._start_verify(node)[0])
            gen1 = manager.status["verify"]["generation"]
            manager._verify_thread.join(timeout=30)
            self.assertTrue(manager._start_verify(node)[0])
            gen2 = manager.status["verify"]["generation"]
            manager._verify_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertIsInstance(gen1, int)
        self.assertGreater(gen2, gen1)

    def test_stale_verify_write_discarded_after_switch(self) -> None:
        gate = threading.Event()

        def _blocked_verify(endpoint):
            gate.wait(timeout=30)
            server = endpoint.get("server")
            return ({"203.0.113.11": "9.9.9.11",
                     "203.0.113.12": "9.9.9.12"}[server], 11)

        manager = self._manager(verify_fn=_blocked_verify)
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            node_a = manager._nodes[0]
            self.assertTrue(manager._start_verify(node_a)[0])
            with _fake_singbox():
                ok, _ = manager.switch(tag="vpngate-1")
            self.assertTrue(ok)
            gate.set()
            manager._verify_thread.join(timeout=30)
            snap = manager.status["verify"]
            events = [h["event"] for h in manager.status["refresh_history"]]
        finally:
            gate.set()
            manager.stop()

        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertEqual("idle", snap["state"])
        self.assertIsNone(snap["exit_ip"])
        self.assertIn("verify-discarded", events)

    def test_switch_resets_verify_to_idle(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            with manager._lock:
                manager.status["verify"] = {"state": "done",
                                            "exit_ip": "203.0.113.99",
                                            "ms": 100, "via_tag": "vpngate-0",
                                            "error": None}
            with _fake_singbox():
                ok, _ = manager.switch(tag="vpngate-1")
            snap = manager.status["verify"]
        finally:
            manager.stop()

        self.assertTrue(ok)
        self.assertEqual("idle", snap["state"])
        self.assertIsNone(snap["exit_ip"])

    def test_auto_pin_resets_verify(self) -> None:
        manager = self._manager(verify_fn=lambda ep: ("9.9.9.9", 11))
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            with manager._lock:
                manager.status["verify"] = {"state": "done",
                                            "exit_ip": "203.0.113.99",
                                            "ms": 100, "via_tag": "vpngate-0",
                                            "error": None}
            with _fake_singbox():
                manager._auto_pin_best(manager._nodes, None)
            snap = manager.status["verify"]
        finally:
            manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual("idle", snap["state"])
        self.assertIsNone(snap["exit_ip"])

    def test_rescue_resets_verify(self) -> None:
        manager = self._manager()
        try:
            self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
            with manager._lock:
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                manager.status["verify"] = {"state": "done",
                                            "exit_ip": "203.0.113.99",
                                            "ms": 100, "via_tag": "vpngate-0",
                                            "error": None}
            failing = lambda host, port, timeout=5: 0
            with _fake_singbox(), \
                 mock.patch.object(manager, "dial_fn", return_value=None):
                # Dead tunnel dial on an auto pin: first failure
                # fast-rescues.
                result = manager.check_pinned_health(probe_fn=failing)
            snap = manager.status["verify"]
        finally:
            manager.stop()

        self.assertEqual("rescued", result)
        self.assertEqual("idle", snap["state"])
        self.assertIsNone(snap["exit_ip"])


class VerifyAttributionUiTests(unittest.TestCase):
    """Batch 1 (attribution chain), console side."""

    def test_render_verify_marks_stale_via_tag(self) -> None:
        self.assertIn("via_tag", UI_HTML)
        self.assertIn("重新验证", UI_HTML)

    def test_auto_verify_trigger_present(self) -> None:
        self.assertIn("maybeAutoVerify", UI_HTML)
        self.assertIn("autoVerifiedFor", UI_HTML)


class ProbeObserveUiTests(unittest.TestCase):
    """Batch 2 (observation chain), console side."""

    def _probe_block(self) -> str:
        start = UI_HTML.index("async function probeOne")
        end = UI_HTML.index("async function refreshNow")
        return UI_HTML[start:end]

    def test_controllers_split_per_task(self) -> None:
        self.assertIn("probeCtl", UI_HTML)
        self.assertIn("verifyCtl", UI_HTML)
        self.assertIn("fullCtl", UI_HTML)
        self.assertNotIn("pollCtl", UI_HTML)

    def test_probe_poll_renders_each_round(self) -> None:
        block = self._probe_block()
        self.assertRegex(block, r"renderAll\(s\)")
        self.assertRegex(block, r"renderProbeWait\(tag")

    def test_probe_shows_elapsed_wait(self) -> None:
        self.assertIn("已等待", self._probe_block())

    def test_busy_probe_row_explains_itself(self) -> None:
        self.assertIn("该节点测速中，请稍候", UI_HTML)
        start = UI_HTML.index('document.getElementById("bench-body").onclick')
        end = UI_HTML.index("setInterval(() => {")
        delegation = UI_HTML[start:end]
        self.assertEqual(2, delegation.count("该节点测速中，请稍候"))

    def test_space_key_defers_to_click(self) -> None:
        start = UI_HTML.index('document.getElementById("bench-body").onkeydown')
        block = UI_HTML[start:start + 1400]
        self.assertIn('if (ev.key === " ") { ev.preventDefault(); return; }',
                      block)
        space_at = block.index('if (ev.key === " ") { ev.preventDefault(); return; }')
        enter_tail = block[space_at:]
        self.assertIn("probeOne(p)", enter_tail)
        self.assertIn("switchTag(sw)", enter_tail)


class VerifyAttributionUiTests(unittest.TestCase):
    """Batch 1 (attribution chain), console side."""

    def test_render_verify_marks_stale_via_tag(self) -> None:
        self.assertIn("via_tag", UI_HTML)
        self.assertIn("重新验证", UI_HTML)

    def test_auto_verify_trigger_present(self) -> None:
        self.assertIn("maybeAutoVerify", UI_HTML)
        self.assertIn("autoVerifiedFor", UI_HTML)


class VerifyAttributionHarnessTests(unittest.TestCase):
    """Purpose harness: the served console JS must show the right exit IP
    at the right time (stale hidden, auto identify once, switch verifies
    new node once, no loops). Runs scripts/verify_attribution_stub.js in
    node against the RUNTIME UI_HTML, like test_served_js_parses."""

    def test_served_attribution_flow(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        blocks = re.findall(r"<script>(.*?)</script>", UI_HTML, re.S)
        mains = [b for b in blocks if "function probeOne" in b]
        self.assertEqual(1, len(mains))
        stub = (Path(__file__).resolve().parent.parent / "scripts" /
                "verify_attribution_stub.js")
        self.assertTrue(stub.is_file())
        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                         delete=False,
                                         encoding="utf-8") as handle:
            handle.write(mains[0])
            page_path = handle.name
        # The harness output goes to a file instead of a pipe: a confined
        # test process cannot hand a pipe to a child process, and the
        # assertions need the very same PASS markers either way.
        log_path = os.path.join(tempfile.gettempdir(),
                                f"verifyattr-{os.getpid()}.log")
        try:
            with open(log_path, "w", encoding="utf-8") as log:
                result = subprocess.run([node, str(stub), page_path],
                                        stdout=log, stderr=subprocess.STDOUT,
                                        text=True, timeout=120)
            output = ""
            if os.path.exists(log_path):
                with open(log_path, encoding="utf-8",
                          errors="replace") as log:
                    output = log.read()
        finally:
            for path in (page_path, log_path):
                if os.path.exists(path):
                    os.unlink(path)
        self.assertEqual(0, result.returncode, output)
        for marker in ("PASS A1:", "PASS A2:", "PASS B:", "PASS C:",
                       "PASS D:", "ALL PASS"):
            self.assertIn(marker, output)

class VerifyAttributionHttpTests(unittest.TestCase):
    """Purpose over real HTTP: stale IP cleared on switch, races never
    show the wrong IP, and the boot path can reach identification."""

    TOKEN = "test-admin-token-0123456789abcdef"
    IP_OF = {"203.0.113.11": "9.9.9.11", "203.0.113.12": "9.9.9.12"}

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(),
                        start_singbox=False, auto_refresh=False,
                        fetch_on_start=False, admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": 50,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, ip in enumerate(ips)]

    def _raw(self, port: int, method: str, path: str,
             body: bytes | None = None) -> tuple[str, bytes]:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        with sock:
            headers = (f"{method} {path} HTTP/1.1\r\nHost: x\r\n"
                       f"Authorization: Bearer {self.TOKEN}\r\n")
            if body is not None:
                headers += f"Content-Length: {len(body)}\r\n"
            sock.sendall(headers.encode() + b"\r\n" + (body or b""))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        head, _, resp_body = response.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], resp_body

    def _get_status(self, port: int) -> dict:
        _, body = self._raw(port, "GET", "/api/status")
        return json.loads(body.decode())

    def _post(self, port: int, path: str, payload: dict) -> tuple[str, dict]:
        line, body = self._raw(port, "POST", path, json.dumps(payload).encode())
        return line, json.loads(body.decode())

    def _wait_verify_done(self, port: int, timeout: float = 20.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            snap = self._get_status(port)["verify"]
            if snap["state"] == "done":
                return snap
            time.sleep(0.2)
        raise AssertionError("verify never reached done: %r" % (snap,))

    def test_http_switch_clears_stale_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
                with manager._lock:
                    manager.status["verify"] = {
                        "state": "done", "exit_ip": "9.9.9.11", "ms": 100,
                        "via_tag": "vpngate-0", "error": None}
                port = manager.start()
                with _fake_singbox():
                    line, _ = self._post(port, "/api/switch",
                                         {"tag": "vpngate-1"})
                    self.assertIn("200", line)
                    snap = self._get_status(port)["verify"]
            finally:
                manager.stop()

        self.assertEqual("idle", snap["state"])
        self.assertIsNone(snap["exit_ip"])

    def test_http_race_never_shows_wrong_ip(self) -> None:
        gate = threading.Event()

        def _blocked_verify(endpoint):
            gate.wait(timeout=30)
            return (self.IP_OF[endpoint["server"]], 11)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, verify_fn=_blocked_verify)
            try:
                self._seed_nodes(manager, "203.0.113.11", "203.0.113.12")
                port = manager.start()
                with _fake_singbox():
                    line1, _ = self._post(port, "/api/verify", {})
                    self.assertIn("202", line1)
                    time.sleep(0.6)
                    line2, _ = self._post(port, "/api/switch",
                                          {"tag": "vpngate-1"})
                    self.assertIn("200", line2)
                    line3, _ = self._post(port, "/api/verify", {})
                    self.assertIn("202", line3)
                    gate.set()
                    seen = []
                    deadline = time.monotonic() + 20.0
                    while time.monotonic() < deadline:
                        snap = self._get_status(port)["verify"]
                        seen.append((snap["state"], snap["via_tag"],
                                     snap["exit_ip"]))
                        if snap["state"] == "done":
                            break
                        time.sleep(0.2)
            finally:
                gate.set()
                manager.stop()

        self.assertEqual("done", snap["state"])
        self.assertEqual("vpngate-1", snap["via_tag"])
        self.assertEqual("9.9.9.12", snap["exit_ip"])
        self.assertNotIn(("done", "vpngate-0", "9.9.9.11"), seen)

    def test_first_identification_end_to_end(self) -> None:
        ip_of = self.IP_OF
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                tmpdir, dial_fn=lambda node: 50,
                verify_fn=lambda ep: (ip_of[ep["server"]], 42))
            try:
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=100):
                    self.assertTrue(manager.refresh_once(
                        fetcher=lambda url, timeout: _snapshot_csv(
                            "203.0.113.11", "203.0.113.12")))
                    manager._full_probe_thread.join(timeout=60)
                port = manager.start()
                with _fake_singbox():
                    line, body = self._post(port, "/api/verify", {})
                    self.assertIn("202", line)
                    snap = self._wait_verify_done(port)
            finally:
                manager.stop()

        self.assertEqual(manager.preferred_tag, snap["via_tag"])
        pinned = next(n for n in manager._nodes
                      if n["endpoint"]["tag"] == manager.preferred_tag)
        self.assertEqual(ip_of[pinned["server"]], snap["exit_ip"])


class ConcurrentStartTests(unittest.TestCase):
    """Batch 3 (concurrency slots): concurrent double starts accept
    exactly once — check, thread publish and start are atomic."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-race-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-race-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-race-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_nodes(self, manager, *ips):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": 100, "real_latency_ms": 50,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, ip in enumerate(ips)]

    def _race_starts(self, starter):
        """Run starter() from two threads rendezvoused inside thread
        creation, so both overlap the check-then-publish window.

        The main thread joins the barrier to release the first starter
        promptly under fixed code; under racy code both starters trip it
        together and both get accepted (the failure this guards)."""
        import threading as th_mod
        entered = threading.Event()
        gate = threading.Barrier(2)

        class SlowThread(th_mod.Thread):
            def __init__(self, *args, **kwargs):
                entered.set()
                # Fail loudly on timeout: a broken rendezvous would make
                # this a timing race instead of a forced overlap.
                gate.wait(timeout=10)
                super().__init__(*args, **kwargs)

        results = []
        hitters = [th_mod.Thread(target=lambda: results.append(starter()))
                   for _ in range(2)]
        with mock.patch.object(th_mod, "Thread", SlowThread):
            hitters[0].start()
            self.assertTrue(entered.wait(timeout=30))
            hitters[1].start()
            gate.wait(timeout=10)
            for w in hitters:
                w.join(30)
        return results

    def test_concurrent_verify_starts_single_accept(self) -> None:
        manager = self._manager(verify_fn=lambda ep: ("9.9.9.9", 1))
        try:
            self._seed_nodes(manager, "203.0.113.11")
            results = self._race_starts(
                lambda: manager._start_verify(manager._nodes[0]))
            manager._verify_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual(2, len(results))
        self.assertEqual(1, sum(1 for ok, _ in results if ok))

    def test_concurrent_probe_starts_single_accept(self) -> None:
        manager = self._manager(dial_fn=lambda node: 7)
        try:
            self._seed_nodes(manager, "203.0.113.11")
            results = self._race_starts(
                lambda: manager._start_single_probe(manager._nodes[0]))
            manager._single_probe_thread.join(timeout=30)
        finally:
            manager.stop()

        self.assertEqual(2, len(results))
        self.assertEqual(1, sum(1 for ok, _ in results if ok))


class SlotFeedbackUiTests(unittest.TestCase):
    """Batch 3 (concurrency slots), console side: 409 names the running
    task, and poll windows match the backend staleness window."""

    def _probe_block(self) -> str:
        start = UI_HTML.index("async function probeOne")
        return UI_HTML[start:UI_HTML.index("async function refreshNow")]

    def _verify_block(self) -> str:
        start = UI_HTML.index("async function verifyExit")
        return UI_HTML[start:UI_HTML.index("silentLogin();")]

    def test_api_reads_error_field(self) -> None:
        self.assertIn("j.detail || j.error || raw", UI_HTML)

    def test_running_tag_helper_present(self) -> None:
        self.assertIn("function runningTagOf", UI_HTML)

    def test_probe_409_names_running_tag(self) -> None:
        block = self._probe_block()
        self.assertIn("runningTagOf(e.message)", block)
        self.assertIn("已有单测进行中，稍后再试", block)

    def test_verify_409_names_running_tag(self) -> None:
        block = self._verify_block()
        self.assertIn("runningTagOf(e.message)", block)
        self.assertIn("已有验证进行中，稍后再试", block)

    def test_poll_windows_cover_staleness(self) -> None:
        self.assertIn("for (let i = 0; i < 60; i++)", self._probe_block())
        self.assertIn("for (let i = 0; i < 60; i++)", self._verify_block())

    def test_timeout_says_background_continues(self) -> None:
        self.assertIn("仍在后台运行", self._probe_block())
        self.assertIn("仍在后台运行", self._verify_block())


class SingleProbeWritebackTests(unittest.TestCase):
    """Batch 4 (write-back chain): single-probe results land on the
    served endpoints even when the endpoint list was rebuilt mid-dial,
    and a missing dial_fn is a clean None, not a TypeError."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-spw-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-spw-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-spw-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post_json(self, manager, path, payload):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = json.dumps(payload).encode()
        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: {len(raw)}\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1") + raw)
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def test_probe_appends_missing_endpoint(self) -> None:
        manager = self._manager(dial_fn=lambda node: 77)
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 100, "real_latency_ms": None,
                               "speed": 1000,
                               "endpoint": {"tag": "vpngate-0",
                                            "server": "203.0.113.11",
                                            "server_port": 443}}]
            with manager._lock:
                manager.status["endpoints"] = [
                    {"tag": "vpngate-9", "server": "198.51.100.9",
                     "server_port": 443, "country": "Japan",
                     "country_short": "JP", "latency_ms": 100,
                     "real_latency_ms": None, "speed": 1000}]
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            manager._single_probe_thread.join(timeout=30)
            shown = [ep for ep in manager.status["endpoints"]
                     if ep.get("real_latency_ms") == 77]
        finally:
            manager.stop()

        self.assertEqual(1, len(shown))
        self.assertEqual("203.0.113.11", shown[0]["server"])
        self.assertEqual(2, len(manager.status["endpoints"]))
        self.assertNotEqual("vpngate-9", shown[0]["tag"])
        self.assertTrue(shown[0]["tag"].startswith("vpngate-"))
        self.assertEqual(77, manager._nodes[0]["real_latency_ms"])

    def test_probe_updates_matching_endpoint_in_place(self) -> None:
        manager = self._manager(dial_fn=lambda node: 55)
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 100, "real_latency_ms": None,
                               "speed": 1000,
                               "endpoint": {"tag": "vpngate-0",
                                            "server": "203.0.113.11",
                                            "server_port": 443}}]
            with manager._lock:
                manager.status["endpoints"] = [
                    {"tag": "vpngate-0", "server": "203.0.113.11",
                     "server_port": 443, "country": "Japan",
                     "country_short": "JP", "latency_ms": 100,
                     "real_latency_ms": None, "speed": 1000}]
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            manager._single_probe_thread.join(timeout=30)
            endpoints = manager.status["endpoints"]
        finally:
            manager.stop()

        self.assertEqual(1, len(endpoints))
        self.assertEqual("vpngate-0", endpoints[0]["tag"])
        self.assertEqual(55, endpoints[0]["real_latency_ms"])

    def test_probe_without_dial_fn_is_clean_none(self) -> None:
        manager = self._manager()
        # NOTE: assign directly — passing dial_fn=None to the constructor
        # selects the default real dial instead of disabling it.
        manager.dial_fn = None
        try:
            manager._nodes = [{"server": "203.0.113.11", "server_port": 443,
                               "country": "Japan", "country_short": "JP",
                               "latency_ms": 100, "real_latency_ms": None,
                               "speed": 1000,
                               "endpoint": {"tag": "vpngate-0",
                                            "server": "203.0.113.11",
                                            "server_port": 443}}]
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            manager._single_probe_thread.join(timeout=30)
            probe = manager.status["probe"]
        finally:
            manager.stop()

        self.assertEqual("done", probe["state"])
        self.assertIsNone(probe["ms"])
        self.assertIsNone(probe["error"])


class ProbeWritebackFollowupsTests(unittest.TestCase):
    """Follow-ups 1-3: appended rows seed first_seen, mid-dial refresh
    lands on the live node, duplicate keys all update."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{_TMP}/railway-pwf-{id(self)}.json",
                        nodes_path=f"{_TMP}/railway-pwf-{id(self)}-nodes.json",
                        state_path=f"{_TMP}/railway-pwf-{id(self)}-state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _post_json(self, manager, path, payload):
        class FakeClient:
            def __init__(self):
                self.sent = b""

            def recv(self, size):
                return b""

            def sendall(self, data):
                self.sent += data

        raw = json.dumps(payload).encode()
        headers = (f"POST {path} HTTP/1.1\r\nContent-Length: {len(raw)}\r\n"
                   f"Authorization: Bearer {self.TOKEN}\r\n")
        client = FakeClient()
        manager._handle_http(client, (headers + "\r\n").encode("latin-1") + raw)
        head, _, body = client.sent.partition(b"\r\n\r\n")
        return head.decode("latin-1").split("\r\n")[0], body

    def _node(self, ip, i=0, tag=None):
        return {"server": ip, "server_port": 443,
                "country": "Japan", "country_short": "JP",
                "latency_ms": 100, "real_latency_ms": None,
                "speed": 1000,
                "endpoint": {"tag": tag or f"vpngate-{i}", "server": ip,
                             "server_port": 443}}

    def test_appended_row_seeds_first_seen(self) -> None:
        manager = self._manager(dial_fn=lambda node: 77)
        try:
            manager._nodes = [self._node("203.0.113.11")]
            with manager._lock:
                manager.status["endpoints"] = []
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            manager._single_probe_thread.join(timeout=30)
            with manager._lock:
                first_seen = manager._first_seen.get("203.0.113.11:443")
                shown = [ep for ep in manager.status["endpoints"]
                         if ep.get("real_latency_ms") == 77]
        finally:
            manager.stop()

        self.assertIsNotNone(first_seen)
        self.assertEqual(1, len(shown))

    def test_mid_dial_refresh_lands_on_live_node(self) -> None:
        gate = threading.Event()

        def _blocked_dial(node):
            gate.wait(timeout=30)
            return 66

        manager = self._manager(dial_fn=_blocked_dial)
        try:
            manager._nodes = [self._node("203.0.113.11")]
            with manager._lock:
                manager.status["endpoints"] = []
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            time.sleep(0.6)
            replacement = self._node("203.0.113.11")
            with manager._lock:
                manager._nodes = [replacement]
            gate.set()
            manager._single_probe_thread.join(timeout=30)
            live_ms = replacement["real_latency_ms"]
            with manager._lock:
                shown = [ep.get("real_latency_ms")
                         for ep in manager.status["endpoints"]]
        finally:
            gate.set()
            manager.stop()

        self.assertEqual(66, live_ms)
        self.assertIn(66, shown)

    def test_duplicate_keys_all_update(self) -> None:
        manager = self._manager(dial_fn=lambda node: 44)
        try:
            manager._nodes = [self._node("203.0.113.11")]
            with manager._lock:
                manager.status["endpoints"] = [
                    {"tag": "vpngate-0", "server": "203.0.113.11",
                     "server_port": 443, "country": "Japan",
                     "country_short": "JP", "latency_ms": 100,
                     "real_latency_ms": None, "speed": 1000},
                    {"tag": "vpngate-7", "server": "203.0.113.11",
                     "server_port": 443, "country": "Japan",
                     "country_short": "JP", "latency_ms": 200,
                     "real_latency_ms": None, "speed": 500}]
            line, _ = self._post_json(manager, "/api/probe",
                                      {"tag": "vpngate-0"})
            self.assertIn("202", line)
            manager._single_probe_thread.join(timeout=30)
            with manager._lock:
                values = [ep.get("real_latency_ms")
                          for ep in manager.status["endpoints"]]
        finally:
            manager.stop()

        self.assertEqual([44, 44], values)


class PreferredEpUiTests(unittest.TestCase):
    """Follow-up 4: one preferredEp(s) helper feeds renderAll and the
    verify loop (no duplicated find-or-first, no half guard)."""

    def test_preferred_ep_helper_present(self) -> None:
        self.assertIn("function preferredEp(", UI_HTML)
        start = UI_HTML.index("function preferredEp(")
        block = UI_HTML[start:start + 400]
        self.assertIn("s.preferred_tag", block)
        self.assertIn("s.endpoints", block)
        self.assertGreaterEqual(UI_HTML.count("preferredEp(s)"), 2)


class VerifyRunningUiTests(unittest.TestCase):
    """Batch 4 (small items), console side: running verify reads as
    verifying (not unverified), and the verify loop passes context."""

    def _statusbar_block(self) -> str:
        start = UI_HTML.index("function renderStatusbar")
        return UI_HTML[start:UI_HTML.index("function renderTraffic")]

    def _verify_block(self) -> str:
        start = UI_HTML.index("async function verifyExit")
        return UI_HTML[start:UI_HTML.index("silentLogin();")]

    def test_statusbar_shows_verifying(self) -> None:
        self.assertIn("验证中…", self._statusbar_block())

    def test_verify_loop_passes_pref(self) -> None:
        self.assertIn("renderVerify(s.verify,", self._verify_block())


class DeadPinTests(unittest.TestCase):
    """A pinned node whose tunnel is dead must not stay pinned forever.

    Health is judged by real tunnel dials only — no TCP-handshake
    shortcut (a dead tunnel keeps answering 443).
    """

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_nodes(self, manager, *specs):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": hand, "real_latency_ms": real,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, (ip, hand, real) in enumerate(specs)]

    def test_a_dead_pin_is_replaced_even_with_nothing_measured(self) -> None:
        """The pin died and has no fresh latency of its own: the health loop
        still moves the chain onto another node - and records the *stale*
        fallback, because no candidate answered a fresh handshake.

        The old full-probe tie-keep used to do this; after the simpler-manager
        rewrite `_auto_pin_best` never touches an existing pin, so
        `check_pinned_health` owns the guarantee."""
        dial_calls: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                tmpdir,
                dial_fn=lambda node: dial_calls.append(node["server"]) or None)
            try:
                # The pin was never dialed (real_latency_ms=None); the only
                # replacement candidate is ranked by its stale measurement.
                self._seed_nodes(manager, ("203.0.113.11", 100, None),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                # An old pin, not a warm-up one: CHAIN_SETTLE_GRACE would
                # otherwise suppress the very death judgement under test.
                manager._chain_pin_at = time.monotonic() - 3600.0
                failing = lambda host, port, timeout=5: 0
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=0):
                    result = manager.check_pinned_health(probe_fn=failing)
                    events = [(e["event"], e.get("detail", ""))
                              for e in manager.status["refresh_history"]]
                # read the files while the temp dir still exists
                state = _read_json(manager.state_path)
                config = _read_json(manager.config_path)
            finally:
                manager.stop()

        self.assertEqual("rescued", result)
        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertEqual([], dial_calls, "a real dial would open a second session")
        # No candidate answered a fresh handshake: the stale fallback is
        # recorded, and the pin is moved all the same.
        self.assertIn("auto-rescue-stale", [ev for ev, _ in events])
        # The new pin is published and persisted, not just held in memory.
        self.assertEqual("vpngate-1", manager.status["preferred_tag"])
        self.assertEqual("vpngate-1", state.get("preferred_tag"))
        chain = next((o for o in config["outbounds"]
                      if o.get("tag") == "chain"), None)
        self.assertIsNotNone(chain, "a pinned chain must publish a selector")
        self.assertEqual("vpngate-1", chain["outbounds"][0])

    def test_a_dead_pin_is_replaced_with_fresh_handshake_evidence(self) -> None:
        """The replacement candidate answers a fresh handshake: the rescue
        records the *evidenced* event, not the stale fallback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: None)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, None),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                manager._chain_pin_at = time.monotonic() - 3600.0
                failing = lambda host, port, timeout=5: 0
                with _fake_singbox(), \
                     mock.patch("railway_manager.probe_tcp_latency",
                                return_value=50):
                    result = manager.check_pinned_health(probe_fn=failing)
                    events = [e["event"]
                              for e in manager.status["refresh_history"]]
            finally:
                manager.stop()

        self.assertEqual("rescued", result)
        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertIn("auto-rescue", events)
        self.assertNotIn("auto-rescue-stale", events)

    def test_health_failure_never_dials_and_fast_rescues(self) -> None:
        """First failed handshake rescues to the alive node immediately (no
        3-strike wait) and never real-dials the pin: a second VPNGate session
        would kick the one the chain is riding (duplicate-cn)."""
        dial_calls: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                tmpdir,
                dial_fn=lambda node: dial_calls.append(node["server"]) or None)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                manager._chain_pin_at = time.monotonic() - 3600.0
                failing = lambda host, port, timeout=5: 0
                with _fake_singbox():
                    result = manager.check_pinned_health(probe_fn=failing)
            finally:
                manager.stop()

        self.assertEqual("rescued", result)
        self.assertEqual("vpngate-1", manager.preferred_tag)
        # Health judgement is handshake + mux probe only: no real dial.
        self.assertEqual([], dial_calls)

    def test_handshake_alive_but_tunnel_dead_rescues(self) -> None:
        """TCP handshake passes but the chain still carries nothing: two
        end-to-end probes (CHAIN_FAIL_THRESHOLD) must move the pin.

        The tunnel check rides the mux (`_chain_probe_ok`); stubbing it is the
        same signal a dead tunnel produces, without opening a second VPNGate
        session."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: None)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                manager._chain_pin_at = time.monotonic() - 3600.0
                healthy = lambda host, port, timeout=5: 120
                with _fake_singbox(), \
                     mock.patch.object(manager, "_chain_probe_ok",
                                       return_value=False):
                    first = manager.check_pinned_health(probe_fn=healthy)
                    second = manager.check_pinned_health(probe_fn=healthy)
            finally:
                manager.stop()

        self.assertEqual("pinned", first, "one failed probe must not repin")
        self.assertEqual("rescued", second)
        self.assertEqual("vpngate-1", manager.preferred_tag)

    def test_tunnel_alive_stays_pinned(self) -> None:
        """A chain that still exits a real IP keeps its pin: the handshake
        probe runs once and nothing is re-dialed."""
        probe_calls: list[tuple] = []
        dial_calls: list[str] = []

        def _recording_probe(host, port, timeout=5):
            probe_calls.append((host, port))
            return 120

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                tmpdir,
                dial_fn=lambda node: dial_calls.append(node["server"]) or 66)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                manager._chain_pin_at = time.monotonic() - 3600.0
                with _fake_singbox(), \
                     mock.patch.object(manager, "_chain_probe_ok",
                                       return_value=True):
                    result = manager.check_pinned_health(
                        probe_fn=_recording_probe)
            finally:
                manager.stop()

        self.assertEqual("pinned", result)
        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual([("203.0.113.11", 443)], probe_calls)
        self.assertEqual([], dial_calls)

    def test_rescue_yields_to_manual_switch_mid_run(self) -> None:
        """A manual switch racing a slow dial+apply must win: the
        rescue commits nothing and reports the pin as kept.

        Simulates the race deterministically: _commit_rescue is hooked
        so a real switch() lands between _apply_config and the commit
        (bumping _rescue_round), making the in-flight round stale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: None)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager.backup_tag = "vpngate-1"
                manager.status["backup_tag"] = "vpngate-1"
                manager._auto_pinned = True
                failing = lambda host, port, timeout=5: 0

                # A manual switch must take the hot path here: the rescue
                # runs `_commit_rescue` under `_config_lock`, and the cold
                # switch path needs that same lock.
                manager._repin_runtime = mock.Mock(return_value=True)
                real_commit = manager._commit_rescue

                def _commit_then_manual(round_id, best, second):
                    ok, _ = manager.switch(tag="vpngate-1")
                    assert ok
                    return real_commit(round_id, best, second)

                with _fake_singbox(), \
                     mock.patch.object(manager, "_commit_rescue",
                                       side_effect=_commit_then_manual):
                    result = manager.check_pinned_health(probe_fn=failing)
            finally:
                manager.stop()

        self.assertEqual("pinned", result)
        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertFalse(manager._auto_pinned)

    def test_auto_pin_verifies_exit_ip_before_pinning(self) -> None:
        """Winner with no exit IP is skipped in favor of the next
        candidate; nothing pinnable leaves the pin untouched."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(
                tmpdir,
                verify_fn=lambda ep: (None, None)
                if ep["server"] == "203.0.113.11" else ("9.9.9.12", 11))
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 20),
                                 ("203.0.113.12", 200, 40))
                with _fake_singbox():
                    manager._auto_pin_best(manager._nodes, None)
                    events = [e["event"]
                              for e in manager.status["refresh_history"]]
            finally:
                manager.stop()

        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertIn("auto-pin", events)

    def test_an_existing_pin_is_never_re_verified(self) -> None:
        """A full probe must not verify an existing pin: verification belongs
        to the mux-riding health loop, and a throwaway client would open a
        second VPNGate session (duplicate-cn) and kill the serving one."""
        verify_calls: list[str] = []

        def _verify(ep):
            verify_calls.append(ep["server"])
            return (None, None)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, verify_fn=_verify)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 20),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                with _fake_singbox(), \
                     mock.patch.object(manager, "_apply_config",
                                       return_value=True) as apply_mock:
                    manager._auto_pin_best(manager._nodes, "vpngate-0")
                    events = [(e["event"], e.get("detail", ""))
                              for e in manager.status["refresh_history"]]
            finally:
                manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual([], verify_calls)
        apply_mock.assert_not_called()
        self.assertTrue(any(ev == "auto-pin-skipped" and "pin exists" in detail
                            for ev, detail in events))

    def test_no_exit_ip_anywhere_pins_nothing(self) -> None:
        """Cold start with no candidate yielding an exit IP: pin nothing and
        do not rebuild the serving config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, verify_fn=lambda ep: (None, None))
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 20),
                                 ("203.0.113.12", 200, 40))
                with _fake_singbox(), \
                     mock.patch.object(manager, "_apply_config",
                                       return_value=True) as apply_mock:
                    manager._auto_pin_best(manager._nodes, None)
                    events = [(e["event"], e.get("detail", ""))
                              for e in manager.status["refresh_history"]]
            finally:
                manager.stop()

        self.assertIsNone(manager.preferred_tag)
        apply_mock.assert_not_called()
        self.assertTrue(any(ev == "auto-pin-skipped" and "exit ip" in detail
                            for ev, detail in events))

    def test_full_probe_never_repins_over_an_existing_pin(self) -> None:
        """Even when the pin lost its exit IP this round, the full probe must
        not reselect: the mux-riding health loop judges the pin, because it is
        the only verifier that does not open a second VPNGate session."""
        verify_calls: list[str] = []

        def _verify(ep):
            verify_calls.append(ep["server"])
            if ep["server"] == "203.0.113.11":
                return (None, None)
            return ("9.9.9.12", 11)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, verify_fn=_verify)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 20),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                with _fake_singbox(), \
                     mock.patch.object(manager, "_apply_config",
                                       return_value=True) as apply_mock:
                    manager._auto_pin_best(manager._nodes, "vpngate-0")
            finally:
                manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual([], verify_calls)
        apply_mock.assert_not_called()

    def test_a_healthy_pin_is_left_alone_by_the_probe(self) -> None:
        """A pin whose exit still works is neither re-verified nor rewritten:
        exactly one skip is recorded and the config is not rebuilt."""
        verify_calls: list[str] = []

        def _verify(ep):
            verify_calls.append(ep["server"])
            return ("9.9.9.9", 11)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, verify_fn=_verify)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 20),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = True
                with _fake_singbox(), \
                     mock.patch.object(manager, "_apply_config",
                                       return_value=True) as apply_mock:
                    manager._auto_pin_best(manager._nodes, "vpngate-0")
                    events = [e["event"]
                              for e in manager.status["refresh_history"]]
            finally:
                manager.stop()

        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual([], verify_calls)
        apply_mock.assert_not_called()
        self.assertEqual(1, events.count("auto-pin-skipped"))

class MultiRemotePinTests(unittest.TestCase):
    """A pin with several remotes is dead only when every remote is dead.

    VPNGate ovpn configs often list several TCP remotes for one node and
    sing-box fails over inside the endpoint, so probing only the first address
    would either rescue away from a working chain or drop a usable node from
    the rotation pool.
    """

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_multi(self, manager):
        primary = {"server": "203.0.113.11", "server_port": 443,
                   "network": "tcp"}
        failover = {"server": "203.0.113.99", "server_port": 1194,
                    "network": "tcp"}
        manager._nodes = [
            {"server": "203.0.113.11", "server_port": 443,
             "country": "Japan", "country_short": "JP",
             "latency_ms": 100, "real_latency_ms": 30, "speed": 1000,
             "endpoint": {"tag": "vpngate-0", "type": "openvpn-client",
                          "servers": [primary, failover]}},
            {"server": "203.0.113.12", "server_port": 443,
             "country": "Japan", "country_short": "JP",
             "latency_ms": 200, "real_latency_ms": 40, "speed": 1000,
             "endpoint": {"tag": "vpngate-1", "server": "203.0.113.12",
                          "server_port": 443}},
        ]

    def test_dead_first_remote_keeps_the_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                self._seed_multi(manager)
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager.backup_tag = "vpngate-1"
                manager.status["backup_tag"] = "vpngate-1"
                manager._auto_pinned = True
                seen: list[str] = []

                def probe(host, port, timeout=5):
                    seen.append(host)
                    return 0 if host == "203.0.113.11" else 90

                with _fake_singbox():
                    result = manager.check_pinned_health(probe_fn=probe)
            finally:
                manager.stop()

        self.assertEqual("pinned", result)
        self.assertEqual("vpngate-0", manager.preferred_tag)
        self.assertEqual(["203.0.113.11", "203.0.113.99"], seen)

    def test_all_remote_candidates_are_tried_before_a_rescue(self) -> None:
        """Every remote of the pin is probed before the pin is given up."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                self._seed_multi(manager)
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager.backup_tag = "vpngate-1"
                manager.status["backup_tag"] = "vpngate-1"
                manager._auto_pinned = True
                seen: list[str] = []

                def probe(host, port, timeout=5):
                    seen.append(host)
                    return 0

                with _fake_singbox():
                    manager.check_pinned_health(probe_fn=probe)
            finally:
                manager.stop()

        # 203.0.113.11 (server) then 203.0.113.99 (servers[1]) both probed.
        self.assertEqual(["203.0.113.11", "203.0.113.99"], seen[:2])


class RescueRoundTests(unittest.TestCase):
    """check_pinned_health rescue commits only when no manual switch
    landed after the round started (N3: round-scoped guard, not a bare
    auto_pinned flag which would never rescue manual pins)."""

    TOKEN = "test-admin-token-0123456789abcdef"

    def _manager(self, tmpdir: str, **kwargs):
        defaults = dict(port=0, mixed_port=get_free_port(), start_singbox=False,
                        auto_refresh=False, fetch_on_start=False,
                        admin_token=self.TOKEN,
                        config_path=f"{tmpdir}/singbox.json",
                        nodes_path=f"{tmpdir}/nodes.json",
                        state_path=f"{tmpdir}/state.json")
        defaults.update(kwargs)
        return RailwayManager(**defaults)

    def _seed_nodes(self, manager, *specs):
        manager._nodes = [{"server": ip, "server_port": 443,
                           "country": "Japan", "country_short": "JP",
                           "latency_ms": hand, "real_latency_ms": real,
                           "speed": 1000,
                           "endpoint": {"tag": f"vpngate-{i}", "server": ip,
                                        "server_port": 443}}
                          for i, (ip, hand, real) in enumerate(specs)]

    def _round_id(self, manager) -> int:
        with manager._lock:
            return manager._rescue_round

    def test_rescue_round_increments_per_check(self) -> None:
        """Each health check opens a new round id (monotonic)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: 66)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30))
                first = self._round_id(manager)
                manager.check_pinned_health()
                second = self._round_id(manager)
            finally:
                manager.stop()

        self.assertEqual(first + 1, second)

    def test_rescue_after_fresh_manual_switch_yields(self) -> None:
        """Manual switch AFTER the rescue round started wins: rescue
        commits nothing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir, dial_fn=lambda node: None)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                manager.preferred_tag = "vpngate-0"
                manager.status["preferred_tag"] = "vpngate-0"
                manager._auto_pinned = False
                failing = lambda host, port, timeout=5: 0
                with _fake_singbox():
                    # Capture the round id the check will use, then
                    # switch before the commit: stale round must yield.
                    round_at_start = self._round_id(manager)
                    result = manager.check_pinned_health(probe_fn=failing)
                    self.assertEqual("rescued", result)
                    _settle_probes(manager)
                    manager.switch(tag="vpngate-0")
                    committed = manager._commit_rescue(
                        round_at_start, "vpngate-1", "vpngate-0")
            finally:
                manager.stop()

        self.assertFalse(committed)
        self.assertEqual("vpngate-0", manager.preferred_tag)

    def test_rescue_without_mid_round_switch_commits(self) -> None:
        """No mid-round switch: the same commit path applies the rescue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = self._manager(tmpdir)
            try:
                self._seed_nodes(manager, ("203.0.113.11", 100, 30),
                                 ("203.0.113.12", 200, 40))
                with manager._lock:
                    round_id = manager._rescue_round
                with _fake_singbox():
                    committed = manager._commit_rescue(
                        round_id, "vpngate-1", "vpngate-0")
            finally:
                manager.stop()

        self.assertTrue(committed)
        self.assertEqual("vpngate-1", manager.preferred_tag)
        self.assertEqual("vpngate-0", manager.backup_tag)
        self.assertTrue(manager._auto_pinned)


if __name__ == "__main__":
    unittest.main()
