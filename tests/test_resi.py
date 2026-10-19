"""Tests for the rotating residential SOCKS5 exit ("resi" path).

Covers the render rules (rotation vs sticky), the generated sing-box config,
env validation, and the manager surface (status / probe API / verify path).
No real gateway is contacted: the probe functions are patched.
"""
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from railway_manager import RailwayManager, build_config_from_env
from vpngate_to_singbox import (DEFAULT_RESI_PORT, RESI_IN_PORT,
                                RESI_ROTATE_BASE, _collect_rotate_samples,
                                build_singbox_config, render_resi_username)

RESI = {"server": "gw.example.com", "server_port": 1080,
        "username": "user1", "password": "pass1"}
VLESS = "a29738e5-bee1-c0fc-b484-ae7c49cbc828"


def _endpoint(tag: str = "vpngate-0") -> dict:
    return {"type": "openvpn-client", "tag": tag, "server": "203.0.113.9",
            "server_port": 443, "network": "tcp"}


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


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

    def test_rotate_is_the_default_without_a_gateway(self) -> None:
        config = build_config_from_env(self._env())

        self.assertIsNone(config["resi"])
        self.assertTrue(config["resi_rotate"])

    def test_rotate_needs_a_vless_uuid(self) -> None:
        env = self._env()
        env.pop("VLESS_UUID")
        config = build_config_from_env(env)

        self.assertFalse(config["resi_rotate"])

    def test_gateway_configuration_disables_rotate(self) -> None:
        config = build_config_from_env(self._env(
            RESI_GATEWAY="gw.example.com:1080", RESI_USER="u", RESI_PASS="p"))

        self.assertFalse(config["resi_rotate"])

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



class RotateConfigTests(unittest.TestCase):
    """Third path in rotating mode: one loopback inbound per serving node."""

    def _cfg(self, count: int = 3, **kwargs) -> dict:
        endpoints = [_endpoint(f"vpngate-{i}") for i in range(count)]
        params = dict(endpoints=endpoints, mixed_listen="127.0.0.1",
                      mixed_port=40000, vless_uuid=VLESS, resi_rotate=True)
        params.update(kwargs)
        return build_singbox_config(**params)

    def test_one_loopback_inbound_per_endpoint(self) -> None:
        cfg = self._cfg(3)
        rots = [i for i in cfg["inbounds"] if i["tag"].startswith("resi-rot-")]

        self.assertEqual(["resi-rot-0", "resi-rot-1", "resi-rot-2"],
                         [i["tag"] for i in rots])
        self.assertEqual([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1, RESI_ROTATE_BASE + 2],
                         [i["listen_port"] for i in rots])
        self.assertTrue(all(i["type"] == "vless" for i in rots))
        self.assertTrue(all(i["listen"] == "127.0.0.1" for i in rots))

    def test_each_inbound_routes_to_its_node(self) -> None:
        rules = self._cfg(2)["route"]["rules"]

        self.assertIn({"inbound": "resi-rot-0", "outbound": "vpngate-0"}, rules)
        self.assertIn({"inbound": "resi-rot-1", "outbound": "vpngate-1"}, rules)

    def test_manager_owns_the_port_so_singbox_does_not_bind_it(self) -> None:
        cfg = self._cfg(2)
        ports = {i["listen_port"] for i in cfg["inbounds"]}

        self.assertNotIn(DEFAULT_RESI_PORT, ports)
        self.assertNotIn("resi", [o["tag"] for o in cfg["outbounds"]])

    def test_rotate_stays_out_of_failover_groups(self) -> None:
        cfg = self._cfg(2)
        auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")

        self.assertNotIn("resi-rot-0", auto["outbounds"])

    def test_rotate_path_is_configurable(self) -> None:
        cfg = self._cfg(1, resi_path="/ws-home")
        inbound = next(i for i in cfg["inbounds"] if i["tag"] == "resi-rot-0")

        self.assertEqual("/ws-home", inbound["transport"]["path"])

    def test_rotate_without_vless_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_singbox_config([_endpoint()], vless_uuid=None, resi_rotate=True)

    def test_gateway_and_rotate_are_mutually_exclusive(self) -> None:
        with self.assertRaises(ValueError):
            build_singbox_config([_endpoint()], "127.0.0.1", 40000, vless_uuid=VLESS,
                                 resi=dict(RESI), resi_rotate=True)

    def test_no_endpoints_means_no_rotate_inbounds(self) -> None:
        cfg = self._cfg(0)

        self.assertEqual([], [i for i in cfg["inbounds"]
                              if i["tag"].startswith("resi-rot-")])


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


    def test_rotate_tags_pick_and_order_the_inbounds(self) -> None:
        # The manager rotates over verified nodes only; the port order must
        # follow that tag order (port i <-> rotate order i).
        eps = [_endpoint(f"vpngate-{i}") for i in range(3)]
        cfg = build_singbox_config(eps, "127.0.0.1", 18080, vless_uuid=VLESS,
                                   resi_rotate=True,
                                   resi_rotate_tags=["vpngate-2", "vpngate-0"])
        rot = [i["tag"] for i in cfg["inbounds"] if i["tag"].startswith("resi-rot-")]
        routes = [(r["inbound"], r["outbound"]) for r in cfg["route"]["rules"]
                  if str(r.get("inbound", "")).startswith("resi-rot-")]

        self.assertEqual(["resi-rot-0", "resi-rot-1"], rot)
        self.assertEqual([("resi-rot-0", "vpngate-2"), ("resi-rot-1", "vpngate-0")],
                         routes)

    def test_unknown_rotate_tag_is_dropped(self) -> None:
        eps = [_endpoint("vpngate-0"), _endpoint("vpngate-1")]
        cfg = build_singbox_config(eps, "127.0.0.1", 18080, vless_uuid=VLESS,
                                   resi_rotate=True,
                                   resi_rotate_tags=["vpngate-1", "gone"])
        rot = [i["tag"] for i in cfg["inbounds"] if i["tag"].startswith("resi-rot-")]

        self.assertEqual(["resi-rot-0"], rot)


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



class RotateManagerTests(unittest.TestCase):
    """Balancer behaviour: per-connection round-robin over the serving nodes."""

    def _manager(self, **kwargs) -> RailwayManager:
        # Write next to the source tree: mkdtemp dirs and /tmp are not
        # writable in every sandbox, and _apply_config must really write.
        stem = os.path.join(os.getcwd(), f".resi-rot-{id(self)}")
        params = dict(port=0, mixed_port=0, start_singbox=False, auto_refresh=False,
                      fetch_on_start=False, admin_token="t0ken-0123456789abcdef",
                      vless_uuid=VLESS, resi=None, resi_rotate=True,
                      config_path=f"{stem}.json", nodes_path=f"{stem}-nodes.json",
                      state_path=f"{stem}-state.json", settings_path=None)
        params.update(kwargs)
        return RailwayManager(**params)

    def test_status_reports_rotate_mode(self) -> None:
        manager = self._manager()
        try:
            resi = dict(manager.status["resi"])
        finally:
            manager.stop()

        self.assertTrue(resi["enabled"])
        self.assertEqual("rotate", resi["mode"])
        self.assertEqual(DEFAULT_RESI_PORT, resi["port"])
        self.assertEqual(0, resi["nodes"])

    def test_cursor_cycles_and_wraps(self) -> None:
        manager = self._manager()
        try:
            manager._set_resi_ports([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1])
            seen = [manager._resi_next_port() for _ in range(3)]
            nodes = manager.status["resi"]["nodes"]
        finally:
            manager.stop()

        self.assertEqual([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1, RESI_ROTATE_BASE],
                         seen)
        self.assertEqual(2, nodes)

    def test_no_nodes_means_no_backend(self) -> None:
        manager = self._manager()
        try:
            manager._set_resi_ports([])
            port = manager._resi_next_port()
        finally:
            manager.stop()

        self.assertIsNone(port)

    def test_rebuilding_the_table_resets_the_cursor(self) -> None:
        manager = self._manager()
        try:
            manager._set_resi_ports([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1])
            manager._resi_next_port()
            manager._set_resi_ports([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1,
                                     RESI_ROTATE_BASE + 2])
            first = manager._resi_next_port()
        finally:
            manager.stop()

        self.assertEqual(RESI_ROTATE_BASE, first)

    def test_apply_config_publishes_the_port_table(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": f"198.51.100.{i + 1}", "server_port": 443,
                 "country": "Japan", "country_short": "JP", "latency_ms": 100,
                 "real_latency_ms": 10 + i, "speed": 1000,
                 "endpoint": _endpoint(f"vpngate-{i}")} for i in range(3)]
            with mock.patch.object(RailwayManager, "_check_config", return_value=True):
                manager._apply_config()
            ports = list(manager._resi_ports)
            nodes = manager.status["resi"]["nodes"]
        finally:
            manager.stop()
            for path in (manager.config_path, manager.nodes_path,
                         manager.state_path, manager.config_path + ".last-good"):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        self.assertEqual([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1, RESI_ROTATE_BASE + 2],
                         ports)
        self.assertEqual(3, nodes)

    def test_probe_goes_through_the_listener(self) -> None:
        manager = self._manager()
        sample = {"ips": ["1.1.1.1", "2.2.2.2"], "ms": [1, 2], "count": 2,
                  "distinct": 2, "errors": [], "first_ms": 1, "last_ms": 2}
        try:
            with mock.patch("railway_manager.measure_resi_rotate",
                            return_value=sample) as probe:
                manager._run_resi_probe(2)
            args = probe.call_args[0]
            probe_state = dict(manager.status["resi"]["last_probe"])
            state = manager.status["resi"]["state"]
        finally:
            manager.stop()

        self.assertEqual((VLESS, DEFAULT_RESI_PORT, "/ws-resi"), args[:3])
        self.assertTrue(probe_state["rotating"])
        self.assertEqual("up", state)

    def test_balancer_round_robins_real_connections(self) -> None:
        servers = []
        backend_ports = []
        for _ in range(2):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(4)
            servers.append(srv)
            backend_ports.append(srv.getsockname()[1])

        def serve(srv: socket.socket, tag: str) -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    conn.sendall(tag.encode("ascii"))
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        for index, srv in enumerate(servers):
            threading.Thread(target=serve, args=(srv, f"backend-{index}"),
                             daemon=True).start()

        resi_port = _free_port()
        manager = self._manager(resi_port=resi_port)
        manager._set_resi_ports(backend_ports)
        manager.start()
        try:
            seen = []
            for _ in range(4):
                sock = socket.create_connection(("127.0.0.1", resi_port), timeout=5)
                with sock:
                    seen.append(sock.recv(64).decode("ascii"))
        finally:
            manager.stop()
            for srv in servers:
                srv.close()

        self.assertEqual(["backend-0", "backend-1", "backend-0", "backend-1"], seen)
    def _http(self, port: int, method: str, path: str,
              body: bytes | None = None) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        with sock:
            headers = (f"{method} {path} HTTP/1.1\r\nHost: x\r\n"
                       f"Connection: close\r\n"
                       f"Authorization: Bearer t0ken-0123456789abcdef\r\n")
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

    @staticmethod
    def _cleanup(manager: RailwayManager) -> None:
        for path in (manager.config_path, manager.nodes_path, manager.state_path,
                     manager.config_path + ".last-good"):
            try:
                os.unlink(path)
            except OSError:
                pass

    def test_probe_api_accepts_rotate_mode(self) -> None:
        # Regression: rotate mode has no residential gateway, so self.resi is
        # None; the handler used to answer 503 "resi disabled" and the UI's
        # probe button was dead on a default (zero-config) deployment.
        sample = {"ips": ["1.1.1.1", "2.2.2.2"], "ms": [1, 2], "count": 2,
                  "distinct": 2, "errors": [], "first_ms": 1, "last_ms": 2}
        manager = self._manager(resi_port=_free_port())
        with mock.patch("railway_manager.measure_resi_rotate", return_value=sample):
            port = manager.start()
            try:
                response = self._http(port, "POST", "/api/resi_probe", b'{"count":2}')
                for _ in range(80):
                    if manager.status["resi"]["last_probe"]["state"] == "done":
                        break
                    time.sleep(0.05)
                probe = dict(manager.status["resi"]["last_probe"])
            finally:
                manager.stop()
                self._cleanup(manager)

        self.assertIn(b"202", response)
        self.assertIn(b'"accepted": true', response)
        self.assertTrue(probe["rotating"])
        self.assertEqual(2, probe["distinct"])

    def test_verify_path_resi_accepts_rotate_mode(self) -> None:
        sample = {"ips": ["9.9.9.9"], "ms": [42], "count": 1, "distinct": 1,
                  "errors": [], "first_ms": 42, "last_ms": 42}
        manager = self._manager(resi_port=_free_port())
        with mock.patch("railway_manager.measure_resi_rotate", return_value=sample):
            port = manager.start()
            try:
                response = self._http(port, "POST", "/api/verify?path=resi")
                for _ in range(80):
                    if manager.status["resi"]["exit_ip"] == "9.9.9.9":
                        break
                    time.sleep(0.05)
                exit_ip = manager.status["resi"]["exit_ip"]
                state = manager.status["resi"]["state"]
            finally:
                manager.stop()
                self._cleanup(manager)

        self.assertIn(b"202", response)
        self.assertEqual("9.9.9.9", exit_ip)
        self.assertEqual("up", state)

    def test_resi_session_is_not_offered_in_rotate_mode(self) -> None:
        # Sticky sessions are a gateway-provider feature; rotate mode must say
        # so instead of pretending the third path is disabled.
        manager = self._manager(resi_port=_free_port())
        port = manager.start()
        try:
            response = self._http(port, "POST", "/api/resi_session")
            mode = manager.status["resi"]["mode"]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertIn(b"400", response)
        self.assertIn(b"rotate mode has no session", response)
        self.assertEqual("rotate", mode)


    def test_rotate_pool_keeps_verified_nodes_only(self) -> None:
        manager = self._manager(resi_port=_free_port())
        try:
            serving = [
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": None, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-c")},
            ]
            pool = [n["endpoint"]["tag"] for n in manager._rotate_nodes(serving)]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-a", "vpngate-c"], pool)

    def test_rotate_pool_falls_back_until_two_nodes_are_verified(self) -> None:
        manager = self._manager(resi_port=_free_port())
        try:
            serving = [
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": None, "endpoint": _endpoint("vpngate-b")},
            ]
            pool = [n["endpoint"]["tag"] for n in manager._rotate_nodes(serving)]
            empty = manager._rotate_nodes([])
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-a", "vpngate-b"], pool)
        self.assertEqual([], empty)

    def test_apply_config_rotates_over_verified_nodes_only(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": "198.51.100.1", "server_port": 443, "latency_ms": 100,
                 "real_latency_ms": 20, "endpoint": _endpoint("vpngate-0")},
                {"server": "198.51.100.2", "server_port": 443, "latency_ms": 110,
                 "real_latency_ms": 30, "endpoint": _endpoint("vpngate-1")},
                {"server": "198.51.100.3", "server_port": 443, "latency_ms": 120,
                 "endpoint": _endpoint("vpngate-2")},
            ]
            with mock.patch.object(RailwayManager, "_check_config", return_value=True):
                manager._apply_config()
            ports = list(manager._resi_ports)
            nodes = manager.status["resi"]["nodes"]
            with open(manager.config_path, encoding="utf-8") as handle:
                cfg = json.load(handle)
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1], ports)
        self.assertEqual(2, nodes)
        self.assertEqual(3, len(cfg["endpoints"]))
        rot = [i["tag"] for i in cfg["inbounds"] if i["tag"].startswith("resi-rot-")]
        self.assertEqual(["resi-rot-0", "resi-rot-1"], rot)

    def test_backend_dial_failure_steps_to_the_next_node(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        dead = _free_port()
        manager = self._manager(resi_port=_free_port())
        manager._set_resi_ports([dead, srv.getsockname()[1]])

        def serve() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.sendall(b"node-1")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=serve, daemon=True).start()
        client, peer = socket.socketpair()
        worker = threading.Thread(target=manager._handle_resi_client,
                                  args=(client,), daemon=True)
        worker.start()
        try:
            peer.settimeout(5)
            received = peer.recv(64)
            peer.shutdown(socket.SHUT_WR)
            worker.join(timeout=10)
        finally:
            peer.close()
            srv.close()
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(b"node-1", received)
        self.assertFalse(worker.is_alive())


class RotateSampleTests(unittest.TestCase):
    """A dead node in the pool must never truncate the rotation measurement."""

    def _fetch_seq(self, results):
        seq = list(results)

        def fetch():
            return seq.pop(0) if seq else None

        return fetch

    def test_walks_past_dead_nodes(self) -> None:
        fetch = self._fetch_seq([None, (200, b"1.1.1.1", 5),
                                 None, (200, b"2.2.2.2", 6)])
        ips, stamps, errors = _collect_rotate_samples(fetch, 2, time.monotonic() + 30)

        self.assertEqual(["1.1.1.1", "2.2.2.2"], ips)
        self.assertEqual([5, 6], stamps)
        self.assertEqual(["no exit ip", "no exit ip"], errors)

    def test_stops_after_enough_samples(self) -> None:
        fetch = self._fetch_seq([(200, b"1.1.1.1", 1), (200, b"2.2.2.2", 2),
                                 RuntimeError("must not be called")])
        ips, _, errors = _collect_rotate_samples(fetch, 2, time.monotonic() + 30)

        self.assertEqual(["1.1.1.1", "2.2.2.2"], ips)
        self.assertEqual([], errors)

    def test_all_dead_returns_nothing_instead_of_looping(self) -> None:
        ips, stamps, errors = _collect_rotate_samples(lambda: None, 3,
                                                      time.monotonic() + 30)

        self.assertEqual([], ips)
        self.assertEqual([], stamps)
        self.assertEqual(12, len(errors))  # count * 4 attempts, then give up

    def test_ignores_non_ip_and_non_200(self) -> None:
        fetch = self._fetch_seq([(200, b"not-an-ip", 1), (502, b"1.1.1.1", 2),
                                 (200, b"3.3.3.3", 3)])
        ips, _, errors = _collect_rotate_samples(fetch, 1, time.monotonic() + 30)

        self.assertEqual(["3.3.3.3"], ips)
        self.assertEqual(2, len(errors))

    def test_deadline_stops_the_walk(self) -> None:
        fetch = lambda: (time.sleep(0.05), None)[1]  # noqa: E731
        started = time.monotonic()
        ips, _, errors = _collect_rotate_samples(fetch, 3, started + 0.12)

        self.assertEqual([], ips)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertLess(len(errors), 12)


if __name__ == "__main__":
    unittest.main()
