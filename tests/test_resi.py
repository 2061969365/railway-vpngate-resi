"""Tests for the rotating residential SOCKS5 exit ("resi" path).

Covers the render rules (rotation vs sticky), the generated sing-box config,
env validation, and the manager surface (status / probe API / verify path).
No real gateway is contacted: the probe functions are patched.
"""
import json
import socket
import tempfile
import time
import unittest
from unittest import mock

from railway_manager import RailwayManager, build_config_from_env
from vpngate_to_singbox import (DEFAULT_RESI_PORT, RESI_IN_PORT,
                                build_singbox_config, render_resi_username)

RESI = {"server": "gw.example.com", "server_port": 1080,
        "username": "user1", "password": "pass1"}
VLESS = "a29738e5-bee1-c0fc-b484-ae7c49cbc828"


def _endpoint(tag: str = "vpngate-0") -> dict:
    return {"type": "openvpn-client", "tag": tag, "server": "203.0.113.9",
            "server_port": 443, "network": "tcp"}


def _base_env(tmpdir: str) -> dict:
    return {"PROXY_PASS": "0123456789abcdef", "ADMIN_TOKEN": "admin-token-0123456789",
            "VLESS_UUID": VLESS, "DATA_DIR": tmpdir}


class RenderUsernameTests(unittest.TestCase):
    def test_rotation_never_adds_a_session(self) -> None:
        self.assertEqual("user1", render_resi_username(
            "user1", "{user}-session-{session}-ttl-{ttl}", 0, "abc"))

    def test_sticky_renders_documented_placeholders(self) -> None:
        self.assertEqual("user1-session-abc-ttl-600", render_resi_username(
            "user1", "{user}-session-{session}-ttl-{ttl}", 600, "abc"))

    def test_template_without_session_stays_in_rotation(self) -> None:
        # We refuse to guess a provider format: no {session} means no stickiness.
        self.assertEqual("user1", render_resi_username("user1", "{user}", 600, "abc"))

    def test_unknown_placeholder_raises_without_echoing_username(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            render_resi_username("secret-user", "{user}-{session}-{country}", 600, "abc")
        self.assertNotIn("secret-user", str(ctx.exception))
        self.assertIn("{country}", str(ctx.exception))


class BuildConfigTests(unittest.TestCase):
    def _cfg(self, **kwargs) -> dict:
        params = dict(endpoints=[_endpoint()], mixed_listen="127.0.0.1",
                      mixed_port=40000, vless_uuid=VLESS, resi=dict(RESI))
        params.update(kwargs)
        return build_singbox_config(**params)

    def test_resi_outbound_is_a_tcp_socks5(self) -> None:
        cfg = self._cfg()
        out = next(o for o in cfg["outbounds"] if o["tag"] == "resi")

        self.assertEqual("socks", out["type"])
        self.assertEqual("5", out["version"])
        self.assertEqual("gw.example.com", out["server"])
        self.assertEqual(1080, out["server_port"])
        self.assertEqual("pass1", out["password"])
        # UDP ASSOCIATE is not supported by residential gateways; forcing tcp
        # makes UDP fail fast instead of hanging.
        self.assertEqual("tcp", out["network"])

    def test_resi_is_not_part_of_failover_groups(self) -> None:
        cfg = self._cfg()
        auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
        proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")

        self.assertNotIn("resi", auto["outbounds"])
        self.assertNotIn("resi", proxy["outbounds"])

    def test_third_vless_inbound_and_rules(self) -> None:
        cfg = self._cfg()
        ports = {i["listen_port"] for i in cfg["inbounds"]}
        rules = cfg["route"]["rules"]

        self.assertIn(DEFAULT_RESI_PORT, ports)
        self.assertIn(RESI_IN_PORT, ports)
        self.assertIn({"inbound": "vless-resi", "outbound": "resi"}, rules)
        self.assertIn({"inbound": "resi-in", "outbound": "resi"}, rules)
        resi_in = next(i for i in cfg["inbounds"] if i["tag"] == "resi-in")
        # Loopback only: this exists for operators/CI, never for the internet.
        self.assertEqual("127.0.0.1", resi_in["listen"])

    def test_custom_path(self) -> None:
        cfg = self._cfg(resi_path="/ws-home")
        inbound = next(i for i in cfg["inbounds"] if i["tag"] == "vless-resi")

        self.assertEqual("/ws-home", inbound["transport"]["path"])

    def test_resi_without_vless_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_singbox_config([_endpoint()], vless_uuid=None, resi=dict(RESI))

    def test_without_resi_nothing_changes(self) -> None:
        cfg = build_singbox_config([_endpoint()], "127.0.0.1", 40000, vless_uuid=VLESS)

        self.assertNotIn("resi", [o["tag"] for o in cfg["outbounds"]])
        self.assertNotIn("vless-resi", [i["tag"] for i in cfg["inbounds"]])


class EnvTests(unittest.TestCase):
    def _env(self, **kwargs) -> dict:
        tmpdir = tempfile.mkdtemp(prefix="resi-env-")
        env = _base_env(tmpdir)
        env.update(kwargs)
        return env

    def test_disabled_without_gateway(self) -> None:
        config = build_config_from_env(self._env())

        self.assertIsNone(config["resi"])
        self.assertEqual(DEFAULT_RESI_PORT, config["resi_port"])

    def test_parsed_when_gateway_and_credentials_present(self) -> None:
        config = build_config_from_env(self._env(
            RESI_GATEWAY="gw.example.com:1080", RESI_USER="user1", RESI_PASS="pass1"))

        self.assertEqual({"server": "gw.example.com", "server_port": 1080,
                          "username": "user1", "password": "pass1",
                          "template": "{user}", "session_ttl": 0,
                          "probe_interval": 300}, config["resi"])

    def test_missing_credentials_refused(self) -> None:
        for extra in ({"RESI_USER": "user1"},
                      {"RESI_PASS": "pass1"}):
            env = self._env(RESI_GATEWAY="gw.example.com:1080", **extra)
            with self.assertRaises(SystemExit) as ctx:
                build_config_from_env(env)
            self.assertEqual(2, ctx.exception.code)

    def test_bad_gateway_refused(self) -> None:
        for bad in ("gw.example.com", "gw.example.com:notaport", ":1080"):
            env = self._env(RESI_GATEWAY=bad, RESI_USER="u", RESI_PASS="p")
            with self.assertRaises(SystemExit):
                build_config_from_env(env)

    def test_gateway_without_vless_uuid_refused(self) -> None:
        env = self._env(RESI_GATEWAY="gw.example.com:1080", RESI_USER="u",
                        RESI_PASS="p")
        env.pop("VLESS_UUID")
        with self.assertRaises(SystemExit):
            build_config_from_env(env)

    def test_port_collision_refused(self) -> None:
        env = self._env(RESI_GATEWAY="gw.example.com:1080", RESI_USER="u",
                        RESI_PASS="p", RESI_PORT="8082")
        with self.assertRaises(SystemExit):
            build_config_from_env(env)

    def test_sticky_without_session_placeholder_degrades(self) -> None:
        config = build_config_from_env(self._env(
            RESI_GATEWAY="gw.example.com:1080", RESI_USER="u", RESI_PASS="p",
            RESI_SESSION_TTL="600"))

        # ttl is kept (the gateway may honour it on its own), but the username
        # is not rewritten because the template has no {session}.
        self.assertEqual(600, config["resi"]["session_ttl"])
        self.assertEqual("{user}", config["resi"]["template"])

    def test_unknown_placeholder_refused_at_boot(self) -> None:
        env = self._env(RESI_GATEWAY="gw.example.com:1080", RESI_USER="u",
                        RESI_PASS="p", RESI_SESSION_TTL="600",
                        RESI_USER_TEMPLATE="{user}-{session}-{country}")
        with self.assertRaises(SystemExit):
            build_config_from_env(env)


def _manager(**kwargs) -> RailwayManager:
    tmpdir = tempfile.mkdtemp(prefix="resi-mgr-")
    params = dict(port=0, mixed_port=0, start_singbox=False, auto_refresh=False,
                  fetch_on_start=False, admin_token="t0ken-0123456789abcdef",
                  vless_uuid=VLESS, resi=dict(RESI),
                  config_path=f"{tmpdir}/singbox.json",
                  nodes_path=f"{tmpdir}/nodes.json",
                  state_path=f"{tmpdir}/state.json",
                  settings_path=f"{tmpdir}/settings.json")
    params.update(kwargs)
    return RailwayManager(**params)


class ResiManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = _manager()
        self.port = self.manager.start()

    def tearDown(self) -> None:
        self.manager.stop()

    def _request(self, method: str, path: str, body: bytes | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        with sock:
            headers = (f"{method} {path} HTTP/1.1\r\nHost: x\r\n"
                       f"Connection: close\r\nAuthorization: Bearer t0ken-0123456789abcdef\r\n")
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

    def test_status_exposes_resi_but_never_credentials(self) -> None:
        body = self._request("GET", "/api/status").split(b"\r\n\r\n", 1)[1]
        status = json.loads(body.decode())

        self.assertTrue(status["resi"]["enabled"])
        self.assertEqual("gw.example.com", status["resi"]["host"])
        self.assertEqual(1080, status["resi"]["port"])
        self.assertEqual("rotation", status["resi"]["mode"])
        self.assertEqual("/ws-resi", status["resi"]["path"])
        blob = json.dumps(status)
        self.assertNotIn("pass1", blob)
        self.assertNotIn("user1", blob)

    def test_outbound_renders_rotation_by_default(self) -> None:
        self.assertEqual("user1", self.manager._resi_outbound()["username"])

    def test_sticky_mode_renders_session_id(self) -> None:
        self.manager.resi_session_ttl = 600
        outbound = self.manager._resi_outbound()

        self.assertIn("user1", outbound["username"])
        # default template is {user}: an unset template must NOT invent a
        # provider format, so the rendered name stays the plain username.
        self.assertEqual("user1", outbound["username"])

    def test_sticky_mode_with_template(self) -> None:
        self.manager.resi["template"] = "{user}-session-{session}-ttl-{ttl}"
        self.manager.resi_session_ttl = 600
        outbound = self.manager._resi_outbound()

        self.assertTrue(outbound["username"].startswith("user1-session-"))
        self.assertTrue(outbound["username"].endswith("-ttl-600"))

    def test_probe_503_when_disabled(self) -> None:
        other = _manager(resi=None)
        port = other.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with sock:
                sock.sendall(b"POST /api/resi_probe HTTP/1.1\r\nHost: x\r\n"
                             b"Authorization: Bearer t0ken-0123456789abcdef\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                response = sock.recv(4096)
        finally:
            other.stop()

        self.assertIn(b"503", response)

    def test_probe_202_then_409_single_flight(self) -> None:
        gate = time.monotonic()

        def fake_measure(*args, **kwargs):
            time.sleep(0.4)
            return {"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"], "ms": [10, 11, 12],
                    "count": 3, "distinct": 3, "errors": [],
                    "first_ms": 10, "last_ms": 12}

        with mock.patch("railway_manager.measure_resi_rotation", side_effect=fake_measure):
            first = self._request("POST", "/api/resi_probe", b'{"count":3}')
            second = self._request("POST", "/api/resi_probe", b'{"count":3}')
            self.assertIn(b"202", first)
            self.assertIn(b"409", second)
            for _ in range(100):
                if self.manager.status["resi"]["last_probe"]["state"] == "done":
                    break
                time.sleep(0.05)

        probe = self.manager.status["resi"]["last_probe"]
        self.assertEqual("done", probe["state"])
        self.assertEqual(3, probe["distinct"])
        self.assertTrue(probe["rotating"])
        self.assertEqual("3.3.3.3", self.manager.status["resi"]["exit_ip"])
        self.assertGreater(time.monotonic() - gate, 0.3)

    def test_probe_reports_no_rotation(self) -> None:
        def fake_measure(*args, **kwargs):
            return {"ips": ["1.1.1.1", "1.1.1.1"], "ms": [10, 10], "count": 2,
                    "distinct": 1, "errors": [], "first_ms": 10, "last_ms": 10}

        with mock.patch("railway_manager.measure_resi_rotation", side_effect=fake_measure):
            self.manager._run_resi_probe(2)

        probe = self.manager.status["resi"]["last_probe"]
        self.assertEqual(1, probe["distinct"])
        self.assertFalse(probe["rotating"])

    def test_probe_failure_marks_down_without_touching_health(self) -> None:
        self.manager.status["endpoints"] = [{"tag": "vpngate-0"}]
        with mock.patch("railway_manager.measure_resi_rotation", return_value=None):
            self.manager._run_resi_probe(1)

        self.assertEqual("down", self.manager.status["resi"]["state"])
        self.assertIsNotNone(self.manager.status["resi"]["error"])
        # A dead residential gateway must not fail the service health check.
        self.assertIn(b"200", self._request("GET", "/healthz"))

    def test_verify_path_resi(self) -> None:
        with mock.patch("railway_manager.measure_resi_exit_ip",
                        return_value=("9.9.9.9", 42)):
            response = self._request("POST", "/api/verify?path=resi")
            self.assertIn(b"202", response)
            for _ in range(100):
                if self.manager.status["resi"]["exit_ip"] == "9.9.9.9":
                    break
                time.sleep(0.05)

        self.assertEqual("up", self.manager.status["resi"]["state"])
        self.assertEqual("9.9.9.9", self.manager.status["resi"]["exit_ip"])
        self.assertEqual(42, self.manager.status["resi"]["ms"])

    def test_settings_accept_ttl_and_switch_mode(self) -> None:
        # settings_path=None keeps this test filesystem-free; persistence goes
        # through _write_private_json, covered by the existing manager tests.
        manager = _manager(settings_path=None)
        port = manager.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with sock:
                body = b'{"resi_session_ttl":600}'
                sock.sendall(b"POST /api/settings HTTP/1.1\r\nHost: x\r\n"
                             b"Authorization: Bearer t0ken-0123456789abcdef\r\n"
                             b"Content-Length: " + str(len(body)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + body)
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        finally:
            manager.stop()

        self.assertIn(b"200", response)
        self.assertEqual(600, manager.resi_session_ttl)
        self.assertEqual("sticky", manager.status["resi"]["mode"])

    def test_settings_reject_out_of_range_ttl(self) -> None:
        response = self._request("POST", "/api/settings", b'{"resi_session_ttl":999999}')

        self.assertIn(b"400", response)
        self.assertEqual(0, self.manager.resi_session_ttl)


if __name__ == "__main__":
    unittest.main()
