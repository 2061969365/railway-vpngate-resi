"""Tests for the fail-open vpngate-probe client (stdlib fake sidecar)."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from probe_client import ProbeClient


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[dict] = []
        self.mode = "ok"
        self.delay = 0.0
        self.token = ""
        self.delay_results = None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook
        self._handle("POST")

    def log_message(self, *args) -> None:  # noqa: D401 - silence test server
        return

    def _handle(self, method: str) -> None:
        state = self.server.state
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        with state.lock:
            state.requests.append(
                {
                    "method": method,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "body": raw,
                }
            )
        if state.delay:
            time.sleep(state.delay)
        if state.token and self.headers.get("Authorization") != "Bearer " + state.token:
            self._send(401, {"ok": False, "error": "unauthorized"})
            return
        if state.mode == "malformed":
            self._send_raw(200, b"this is not json")
            return
        if state.mode == "server_error":
            self._send(500, {"ok": False, "error": "boom"})
            return
        if method == "GET" and self.path == "/v1/health":
            self._send(200, {"ok": True, "version": "dev", "clash": True})
            return
        if method == "POST" and self.path == "/v1/exit":
            if state.mode == "exit_fail":
                self._send(200, {"ok": False, "error": "no exit ip", "ms": None})
                return
            self._send(
                200,
                {"ok": True, "exit_ip": "203.0.113.7", "ms": 12, "target": "fake.example"},
            )
            return
        if method == "POST" and self.path == "/v1/delay":
            sent = json.loads(raw or b"{}")
            if state.delay_results is not None:
                results = state.delay_results
            else:
                results = []
                if sent.get("tags"):
                    results = [
                        {"tag": "a", "alive": True, "ms": 180, "error": None},
                        {"tag": "b", "alive": False, "ms": None, "error": "timeout"},
                    ]
            self._send(200, {"ok": True, "results": results})
            return
        self._send(404, {"ok": False, "error": "not found"})

    def _send(self, status: int, payload: dict) -> None:
        self._send_raw(status, json.dumps(payload).encode("utf-8"))

    def _send_raw(self, status: int, body: bytes) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class FakeProbeServer:
    def __init__(self) -> None:
        self.state = _State()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.state = self.state
        self.thread = threading.Thread(
            target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True
        )
        self.thread.start()

    @property
    def listen(self) -> str:
        host, port = self.httpd.server_address[:2]
        return "%s:%d" % (host, port)

    @property
    def url(self) -> str:
        return "http://" + self.listen

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ProbeClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = FakeProbeServer()
        self.client = ProbeClient(self.server.url, timeout=1.0)

    def tearDown(self) -> None:
        self.server.close()

    def test_from_env_disabled_returns_none(self) -> None:
        with mock.patch.dict(os.environ, {"PROBE_SERVICE": "0"}, clear=True):
            self.assertIsNone(ProbeClient.from_env())

    def test_from_env_builds_client(self) -> None:
        self.server.state.token = "tok"
        with mock.patch.dict(
            os.environ,
            {"PROBE_LISTEN": self.server.listen, "PROBE_TOKEN": "tok"},
            clear=True,
        ):
            client = ProbeClient.from_env()
        self.assertIsNotNone(client)
        assert client is not None
        self.assertEqual(client.base_url, self.server.url)
        self.assertTrue(client.health()["ok"])
        self.assertEqual(self.server.state.requests[-1]["authorization"], "Bearer tok")

    def test_health_success(self) -> None:
        body = self.client.health()
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["version"], "dev")

    def test_health_absent_service_returns_none(self) -> None:
        client = ProbeClient("http://127.0.0.1:%d" % _free_port(), timeout=0.3)
        self.assertIsNone(client.health())

    def test_exit_ip_success(self) -> None:
        body = self.client.exit_ip("127.0.0.1", 40000, "u", "p", 1234)
        self.assertIsNotNone(body)
        assert body is not None
        self.assertEqual(body["exit_ip"], "203.0.113.7")
        request = self.server.state.requests[-1]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/v1/exit")
        sent = json.loads(request["body"])
        self.assertEqual(
            sent,
            {
                "host": "127.0.0.1",
                "port": 40000,
                "username": "u",
                "password": "p",
                "timeout_ms": 1234,
            },
        )

    def test_exit_ip_not_verified_returns_none(self) -> None:
        self.server.state.mode = "exit_fail"
        self.assertIsNone(self.client.exit_ip("127.0.0.1", 40000))

    def test_delays_returns_only_alive_tags(self) -> None:
        got = self.client.delays(["a", "b"], timeout_ms=500)
        self.assertEqual(got, {"a": 180})
        sent = json.loads(self.server.state.requests[-1]["body"])
        self.assertEqual(sent["tags"], ["a", "b"])
        self.assertTrue(sent["url"].startswith("https://"))
        self.assertEqual(sent["timeout_ms"], 500)

    def test_delays_service_error_returns_none(self) -> None:
        self.server.state.mode = "server_error"
        self.assertIsNone(self.client.delays(["a"]))

    def test_delay_status_reports_alive_and_dead(self) -> None:
        got = self.client.delay_status(["a", "b"], timeout_ms=500)
        self.assertEqual(got, {"a": True, "b": False})
        sent = json.loads(self.server.state.requests[-1]["body"])
        self.assertEqual(sent["tags"], ["a", "b"])
        self.assertEqual(sent["timeout_ms"], 500)

    def test_delay_status_omits_missing_tags(self) -> None:
        self.server.state.delay_results = [{"tag": "a", "alive": True, "ms": 180}]
        got = self.client.delay_status(["a", "c"])
        self.assertEqual(got, {"a": True})
        self.assertNotIn("c", got)

    def test_delay_status_service_error_returns_none(self) -> None:
        self.server.state.mode = "server_error"
        self.assertIsNone(self.client.delay_status(["a"]))

    def test_delay_status_malformed_returns_none(self) -> None:
        self.server.state.mode = "malformed"
        self.assertIsNone(self.client.delay_status(["a"]))

    def test_unauthorized_returns_none(self) -> None:
        self.server.state.token = "secret"
        self.assertIsNone(self.client.health())
        authorized = ProbeClient(self.server.url, token="secret", timeout=1.0)
        self.assertTrue(authorized.health()["ok"])

    def test_timeout_returns_none_quickly(self) -> None:
        self.server.state.delay = 0.6
        client = ProbeClient(self.server.url, timeout=0.1)
        start = time.monotonic()
        self.assertIsNone(client.health())
        self.assertLess(time.monotonic() - start, 0.45)

    def test_malformed_json_returns_none(self) -> None:
        self.server.state.mode = "malformed"
        self.assertIsNone(self.client.health())

    def test_breaker_short_circuits_then_recovers(self) -> None:
        self.server.state.mode = "server_error"
        client = ProbeClient(
            self.server.url, timeout=1.0, breaker_threshold=2, breaker_cooldown=60.0
        )
        self.assertIsNone(client.health())
        self.assertIsNone(client.health())
        attempts = len(self.server.state.requests)
        self.assertIsNone(client.health())
        self.assertEqual(len(self.server.state.requests), attempts, "breaker did not short-circuit")
        client._breaker.success()
        self.server.state.mode = "ok"
        self.assertTrue(client.health()["ok"])
        self.assertEqual(len(self.server.state.requests), attempts + 1)

    def test_public_methods_never_raise(self) -> None:
        self.assertIsNone(self.client.exit_ip("127.0.0.1", "not-a-port"))
        self.assertEqual(self.client.delays(None), {})


class _RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        target = self.server.target_url
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args) -> None:  # noqa: D401 - silence test server
        return


class RedirectServer:
    def __init__(self, target_url: str) -> None:
        self.target_url = target_url
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        self.httpd.daemon_threads = True
        self.httpd.target_url = target_url
        self.thread = threading.Thread(
            target=lambda: self.httpd.serve_forever(poll_interval=0.02),
            daemon=True,
        )
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        return "http://%s:%d" % (host, port)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


class ProbeClientHardeningTests(unittest.TestCase):
    def test_redirect_is_not_followed_and_token_is_not_forwarded(self) -> None:
        target = FakeProbeServer()
        target.state.token = "SECRET-TOKEN"
        redirect = RedirectServer(target.url + "/v1/health")
        client = ProbeClient(redirect.url, token="SECRET-TOKEN", timeout=1.0)
        try:
            self.assertIsNone(client.health())
        finally:
            redirect.close()
            target.close()
        self.assertEqual([], target.state.requests)

    def test_non_http_scheme_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ProbeClient("ftp://127.0.0.1:21")

    def test_environment_proxy_is_ignored(self) -> None:
        server = FakeProbeServer()
        try:
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:1",
                 "HTTPS_PROXY": "http://127.0.0.1:1",
                 "http_proxy": "http://127.0.0.1:1",
                 "https_proxy": "http://127.0.0.1:1"},
                clear=False,
            ):
                client = ProbeClient(server.url, timeout=1.0)
                self.assertTrue(client.health()["ok"])
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
