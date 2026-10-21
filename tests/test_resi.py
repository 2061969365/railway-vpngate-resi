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

from railway_manager import (PINNED_FAIL_THRESHOLD, RESI_NODE_STRIKES_DOWN, RailwayManager,
                             _pump_pair, build_config_from_env)
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

    def test_chain_group_fails_over_between_the_two_reserved_nodes(self) -> None:
        # A selector never fails over by itself: a dead pin left the chain dead
        # until the manager repinned it, while /ws-resi (which skips parked
        # nodes) kept working. The rotate chain is an urltest over the two
        # reserved nodes, so a pin death is absorbed within one probe cycle
        # without a config rewrite - and neither node is dialed by the rotation.
        chain = next(o for o in self._cfg(3, preferred="vpngate-0",
                                          backup="vpngate-1")["outbounds"]
                     if o["tag"] == "chain")

        self.assertEqual("urltest", chain["type"])
        self.assertEqual(["vpngate-0", "vpngate-1"], chain["outbounds"])

    def test_rotate_without_a_backup_keeps_the_selector(self) -> None:
        chain = next(o for o in self._cfg(2, preferred="vpngate-0")["outbounds"]
                     if o["tag"] == "chain")

        self.assertEqual("selector", chain["type"])
        self.assertEqual(["vpngate-0", "auto"], chain["outbounds"])

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

    def test_the_chain_nodes_stay_out_of_the_rotation(self) -> None:
        # VPNGate gives one OpenVPN session per node, so rotating onto the
        # chain's own node gets one of the two kicked: the chain looked dead
        # while /ws-resi worked ("one dead, two dead").
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1),
                                      ("vpngate-c", RESI_ROTATE_BASE + 2)])
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.backup_tag = "vpngate-c"
                pool = [tag for tag, _ in manager._resi_pool()]
                reserved = manager.status["resi"].get("reserved")
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-b"], pool)
        self.assertEqual(2, reserved)

    def test_full_probe_never_dials_a_live_rotation_node(self) -> None:
        # Dialing a node that already holds the rotation session opens a second
        # VPNGate session (duplicate-cn is off) and kicks the user's connection,
        # so the probe would report a healthy node dead - "one dead, two dead".
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": None, "latency_ms": 50,
                 "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1),
                                      ("vpngate-c", RESI_ROTATE_BASE + 2)])
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.backup_tag = "vpngate-c"
                targets = [(n.get("endpoint") or {}).get("tag")
                           for n in manager._full_probe_targets_locked()]
        finally:
            manager.stop()
            self._cleanup(manager)

        # a is the chain's pin and serving, c is its backup: only the
        # unverified node b can be dialed without stealing a live session.
        self.assertEqual(["vpngate-b"], targets)

    def test_full_probe_may_dial_a_parked_node(self) -> None:
        # A parked node is out of the rotation, so probing it is how it heals.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            with manager._lock:
                manager._resi_health["vpngate-b"] = {
                    "strikes": 3, "down_until": time.monotonic() + 600}
                targets = [(n.get("endpoint") or {}).get("tag")
                           for n in manager._full_probe_targets_locked()]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-b"], targets)

    def test_full_probe_skips_the_pin_in_gateway_mode(self) -> None:
        manager = self._manager(resi_rotate=False, resi=None, vless_uuid=None)
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.backup_tag = "vpngate-b"
                targets = [(n.get("endpoint") or {}).get("tag")
                           for n in manager._full_probe_targets_locked()]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-c"], targets)

    def test_a_refresh_never_redials_the_nodes_it_serves(self) -> None:
        # The hourly refresh used to tunnel-dial every node again, including the
        # ones already serving the rotation: a second VPNGate session (one per
        # node) kicks the live one, so the refresh killed good nodes by itself.
        import railway_manager as rm

        seen: dict = {}

        def fake_snapshot(_csv_text, **kwargs):
            seen.update(kwargs)
            return [
                {"server": "203.0.113.21", "server_port": 443, "country": "Japan",
                 "country_short": "JP", "speed": 1, "latency_ms": 12,
                 "real_latency_ms": None, "endpoint": _endpoint("vpngate-a")},
                {"server": "203.0.113.99", "server_port": 443, "country": "Japan",
                 "country_short": "JP", "speed": 2, "latency_ms": 40,
                 "real_latency_ms": None, "endpoint": _endpoint("vpngate-b")},
            ]

        manager = self._manager(dial_fn=lambda node: 33)
        original = rm.snapshot_to_nodes
        rm.snapshot_to_nodes = fake_snapshot
        try:
            manager._nodes = [
                {"server": "203.0.113.21", "server_port": 443, "country": "Japan",
                 "country_short": "JP", "speed": 1, "latency_ms": 10,
                 "real_latency_ms": 77, "endpoint": _endpoint("vpngate-a")},
            ]
            manager.refresh_once(fetcher=lambda *a, **k: "csv")
            nodes = {n["server"]: n for n in manager._nodes}
        finally:
            rm.snapshot_to_nodes = original
            manager.stop()
            self._cleanup(manager)

        skipped = seen.get("skip_dial_keys") or set()
        self.assertIn(("203.0.113.21", 443), skipped)
        self.assertNotIn(("203.0.113.99", 443), skipped)
        # The node that was not dialed keeps its previous verification instead
        # of dropping out of the rotation pool on every refresh.
        self.assertEqual(77, nodes["203.0.113.21"]["real_latency_ms"])
        self.assertIsNone(nodes["203.0.113.99"]["real_latency_ms"])

    def test_an_unpinned_node_returns_to_the_rotation(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                pinned_pool = [tag for tag, _ in manager._resi_pool()]
                manager.preferred_tag = None
                unpinned_pool = [tag for tag, _ in manager._resi_pool()]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-b"], pinned_pool)
        self.assertEqual(["vpngate-a", "vpngate-b"], unpinned_pool)

    def test_a_pool_that_only_holds_the_chain_node_is_empty(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
            route = manager._resi_next_route()
            pool_size = manager.status["resi"]["pool"]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertIsNone(route)
        self.assertEqual(0, pool_size)

    def test_rotate_mode_never_leaves_the_chain_unpinned(self) -> None:
        # Unpinned, the chain path falls back to urltest over the same endpoints
        # the rotation dials, and the two fight for VPNGate's one session per
        # node. Rotate mode therefore pins the best dial-verified node even when
        # the exit probe fails, so the rotation has one node to exclude.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            manager.verify_fn = lambda endpoint: (None, None)
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_restart_singbox"):
                manager._auto_pin_best(manager._nodes, None)
            # _apply_config rebuilds the route table from status["endpoints"],
            # which this test bypasses: publish it after the pin instead.
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1),
                                      ("vpngate-c", RESI_ROTATE_BASE + 2)])
            pinned = manager.preferred_tag
            backup = manager.backup_tag
            pool = [tag for tag, _ in manager._resi_pool()]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("vpngate-a", pinned)
        # A dial-verified node is a legitimate standby: the chain urltest pair
        # needs two reserved nodes so a dead pin fails over without a restart.
        self.assertEqual("vpngate-b", backup)
        self.assertEqual(["vpngate-c"], pool)

    def test_rotate_mode_never_unpins_a_dead_chain_node(self) -> None:
        # Dropping the pin would hand the chain to urltest, which is exactly the
        # collision this design avoids: keep the pin and let the node recover.
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": "198.51.100.1", "server_port": 443,
                 "real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager._pinned_fail_streak = PINNED_FAIL_THRESHOLD - 1
            with mock.patch("railway_manager.probe_tcp_latency", return_value=0):
                state = manager.check_pinned_health()
            pinned = manager.preferred_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("pinned", state)
        self.assertEqual("vpngate-a", pinned)

    def test_rotate_mode_rescues_a_tcp_alive_but_tunnel_dead_pin(self) -> None:
        # The node accepts the TCP handshake and still cannot carry a byte:
        # before this check the handshake looked healthy, rotate mode never
        # unpins, and /ws-chain exited nowhere for the rest of the deployment.
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": "198.51.100.1", "server_port": 443,
                 "real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"server": "198.51.100.2", "server_port": 443,
                 "real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
                {"server": "198.51.100.3", "server_port": 443,
                 "real_latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                states = [manager.check_pinned_health() for _ in range(2)]
            pinned = manager.preferred_tag
            backup = manager.backup_tag
            events = [entry["event"] for entry in manager.status["refresh_history"]]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["pinned", "rescued"], states)
        self.assertEqual("vpngate-b", pinned)
        # The rescue always reserves a standby too, otherwise the chain urltest
        # group would be back to a single node and the next pin death is a
        # multi-minute outage again.
        self.assertEqual("vpngate-c", backup)
        self.assertIn("chain-rescue", events)

    def test_chain_rescue_prefers_the_node_that_carries_rotation_traffic(self) -> None:
        # real_latency_ms is written once when a node is dialed and, in rotate
        # mode, never refreshed for serving nodes (re-dialing them steals their
        # VPNGate session). After hours every number is stale, so ranking by it
        # kept pinning long-dead nodes: /ws-resi worked, /ws-chain stayed dead,
        # and only a manual switch fixed it. Fresh payload proof wins instead.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 5, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 8, "endpoint": _endpoint("vpngate-c")},
                {"real_latency_ms": 900, "endpoint": _endpoint("vpngate-d")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
                manager._resi_payload_at["vpngate-d"] = time.monotonic()
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                manager.check_pinned_health()
                state = manager.check_pinned_health()
            pinned = manager.preferred_tag
            backup = manager.backup_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("rescued", state)
        self.assertEqual("vpngate-d", pinned)
        self.assertEqual("vpngate-b", backup)

    def test_chain_rescue_prefers_a_node_that_returned_bytes(self) -> None:
        # Weaker evidence than payload, still fresher than a latency number
        # measured hours ago: a node that answered the rotation beats one that
        # only looks fast in the stale ranking.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 5, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 8, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
                manager._resi_ok_at["vpngate-c"] = time.monotonic()
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                manager.check_pinned_health()
                manager.check_pinned_health()
            pinned = manager.preferred_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("vpngate-c", pinned)

    def test_chain_rescue_walks_the_pool_instead_of_bouncing(self) -> None:
        # Two dead nodes on top of the stale ranking made the rescue bounce
        # A -> B -> A while the cooldown doubled to five minutes: the chain
        # never came back even though live nodes existed further down.
        manager = self._manager()
        pins = []
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 5, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 8, "endpoint": _endpoint("vpngate-c")},
                {"real_latency_ms": 9, "endpoint": _endpoint("vpngate-d")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                for _ in range(3):
                    manager._chain_rescue_at -= 10 ** 6   # let the cooldown expire
                    manager.check_pinned_health()
                    manager.check_pinned_health()
                    pins.append(manager.preferred_tag)
            dead = dict(manager._chain_dead_until)
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("vpngate-b", pins[0])
        self.assertNotIn("vpngate-a", pins)          # never back to the dead pin
        self.assertEqual(3, len(set(pins)))          # every rescue is a new node
        self.assertIn("vpngate-a", dead)
        self.assertIn("vpngate-b", dead)

    def test_chain_rescue_skips_a_node_the_rotation_parked(self) -> None:
        # The rotation already has passive proof that b is dead; the chain must
        # not waste a restart pinning it just because its old latency is best.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 5, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 8, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
                manager._resi_health["vpngate-b"] = {
                    "strikes": 0, "downs": 1, "down_until": time.monotonic() + 600}
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                manager.check_pinned_health()
                manager.check_pinned_health()
            pinned = manager.preferred_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("vpngate-c", pinned)

    def test_a_pin_that_left_the_snapshot_gets_repinned(self) -> None:
        # build_singbox_config silently drops an unknown pin and routes the
        # chain through the all-nodes urltest group, which competes with the
        # rotation for VPNGate's single session per node.
        manager = self._manager()
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 20, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-gone"
                manager.status["preferred_tag"] = "vpngate-gone"
            with mock.patch.object(RailwayManager, "_apply_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_invalidate_verify"):
                state = manager.check_pinned_health()
            pinned = manager.preferred_tag
            backup = manager.backup_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual("rescued", state)
        self.assertEqual("vpngate-b", pinned)
        self.assertEqual("vpngate-c", backup)

    def test_dead_pin_handshake_does_not_repin_while_the_standby_carries_chain(self) -> None:
        # The pin's TCP handshake is gone but the chain still exits a real IP
        # (urltest already moved to the reserved standby). Repinning would
        # rewrite the config and restart sing-box, killing every rotation
        # connection, for no benefit: the pair is left alone until a real
        # failure - both nodes dead - triggers the rescue.
        manager = self._manager()
        manager.want_singbox = True
        try:
            manager._nodes = [
                {"real_latency_ms": 10, "latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": 20, "latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 30, "latency_ms": 30, "endpoint": _endpoint("vpngate-c")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.backup_tag = "vpngate-b"
                manager.status["preferred_tag"] = "vpngate-a"
            with mock.patch("railway_manager.probe_tcp_latency", return_value=0), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=True), \
                    mock.patch.object(RailwayManager, "_apply_config") as apply_cfg:
                states = [manager.check_pinned_health() for _ in range(6)]
            pinned = manager.preferred_tag
            events = [e["event"] for e in manager.status["refresh_history"]]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["pinned"] * 6, states)
        self.assertEqual("vpngate-a", pinned)
        apply_cfg.assert_not_called()
        self.assertIn("chain-on-standby", events)

    def test_rotate_mode_keeps_the_pin_while_the_chain_carries_traffic(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": "198.51.100.1", "server_port": 443,
                 "real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
                {"server": "198.51.100.2", "server_port": 443,
                 "real_latency_ms": 20, "endpoint": _endpoint("vpngate-b")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=True) as probe, \
                    mock.patch.object(RailwayManager, "_apply_config") as apply_cfg:
                states = [manager.check_pinned_health() for _ in range(3)]
            pinned = manager.preferred_tag
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["pinned", "pinned", "pinned"], states)
        self.assertEqual("vpngate-a", pinned)
        self.assertEqual(3, probe.call_count)
        apply_cfg.assert_not_called()

    def test_chain_rescue_without_an_alternative_keeps_the_pin(self) -> None:
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": "198.51.100.1", "server_port": 443,
                 "real_latency_ms": 10, "endpoint": _endpoint("vpngate-a")},
            ]
            with manager._lock:
                manager.preferred_tag = "vpngate-a"
                manager.status["preferred_tag"] = "vpngate-a"
            with mock.patch("railway_manager.probe_tcp_latency", return_value=25), \
                    mock.patch.object(RailwayManager, "_chain_probe_ok", return_value=False), \
                    mock.patch.object(RailwayManager, "_apply_config") as apply_cfg:
                states = [manager.check_pinned_health() for _ in range(2)]
            pinned = manager.preferred_tag
            events = [entry["event"] for entry in manager.status["refresh_history"]]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["pinned", "pinned"], states)
        self.assertEqual("vpngate-a", pinned)
        self.assertIn("chain-rescue-skipped", events)
        apply_cfg.assert_not_called()

    def test_rotation_cannot_starve_the_other_two_paths(self) -> None:
        # All three paths share one mux slot table; a rotation storm that fills
        # it makes /ws-node and /ws-chain connections get dropped on arrival,
        # which looks exactly like "the third path killed the other two".
        manager = self._manager(max_mux_connections=5)
        try:
            cap = manager._resi_mux_cap
            held = [manager._resi_mux_slots.acquire(blocking=False)
                    for _ in range(cap + 1)]
            node_admitted = manager._mux_slots.acquire(blocking=False)
            reported = manager.status["resi"]["mux_limit"]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(4, cap)   # one of five slots stays reserved
        self.assertEqual([True] * cap + [False], held)
        self.assertTrue(node_admitted, "a full rotation queue must not block node/chain")
        self.assertEqual(cap, reported)

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

        # Rotate mode serves /ws-resi from the mux on $PORT; RESI_PORT is only
        # the sing-box gateway listener, so probing it always failed ("no
        # serving endpoint answered") while real clients kept rotating.
        self.assertEqual((VLESS, manager.port, "/ws-resi"), args[:3])
        self.assertNotEqual(DEFAULT_RESI_PORT, args[1])
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


    def test_rotation_pool_keeps_verified_nodes_only(self) -> None:
        # A node that was never really dialed (or that failed its dial) must
        # never receive third-path traffic: that is how clients ended up stuck
        # on dead nodes.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._nodes = [
                {"real_latency_ms": 30, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": None, "endpoint": _endpoint("vpngate-b")},
                {"real_latency_ms": 10, "endpoint": _endpoint("vpngate-c")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1),
                                      ("vpngate-c", RESI_ROTATE_BASE + 2)])
            pool = [tag for tag, _ in manager._resi_pool()]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-a", "vpngate-c"], pool)

    def test_rotation_pool_is_empty_until_a_node_is_verified(self) -> None:
        # No silent fallback to the unverified snapshot (old design §2).
        manager = self._manager(resi_port=_free_port())
        try:
            manager._nodes = [
                {"real_latency_ms": None, "endpoint": _endpoint("vpngate-a")},
                {"real_latency_ms": None, "endpoint": _endpoint("vpngate-b")},
            ]
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            pool = manager._resi_pool()
            route = manager._resi_next_route()
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual([], pool)
        self.assertIsNone(route)

    def test_apply_config_creates_one_inbound_per_serving_node(self) -> None:
        # The config must not encode the *health* pool: one inbound per serving
        # node, always, so verification results never rewrite the file.
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
            pool = manager.status["resi"]["pool"]
            inbounds = manager.status["resi"]["inbounds"]
            with open(manager.config_path, encoding="utf-8") as handle:
                cfg = json.load(handle)
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual([RESI_ROTATE_BASE, RESI_ROTATE_BASE + 1, RESI_ROTATE_BASE + 2],
                         ports)
        self.assertEqual(2, pool)          # vpngate-2 was never dialed
        self.assertEqual(3, inbounds)
        self.assertEqual(3, len(cfg["endpoints"]))
        rot = [i["tag"] for i in cfg["inbounds"] if i["tag"].startswith("resi-rot-")]
        self.assertEqual(["resi-rot-0", "resi-rot-1", "resi-rot-2"], rot)

    def test_probe_results_do_not_rewrite_the_config(self) -> None:
        # Regression: any health/pool change used to rewrite the config and
        # restart sing-box, killing the direct and chain paths together with
        # the third one ("一个死两个一起死").
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": f"198.51.100.{i + 1}", "server_port": 443,
                 "latency_ms": 100 + i, "real_latency_ms": 20 + i,
                 "endpoint": _endpoint(f"vpngate-{i}")} for i in range(3)]
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_restart_singbox") as restart:
                manager._apply_config()
                restart.reset_mock()
                first = sorted(manager._resi_ports)
                with open(manager.config_path, "rb") as handle:
                    before = handle.read()
                # One node dies, another is re-verified slower: pool changes,
                # config must not.
                manager._nodes[0]["real_latency_ms"] = None
                manager._nodes[1]["real_latency_ms"] = 999
                manager._apply_config()
                with open(manager.config_path, "rb") as handle:
                    after = handle.read()
            restarts = restart.call_count
            pool = manager.status["resi"]["pool"]
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(before, after)
        self.assertEqual(0, restarts)
        self.assertEqual(2, pool)
        self.assertEqual(3, len(first))

    def test_full_probe_grows_the_pool_without_touching_the_config(self) -> None:
        # Regression: the post-refresh full pass is what verifies the nodes
        # REAL_TOPK skipped; it must grow the *runtime* pool, not the file.
        manager = self._manager()
        try:
            manager._nodes = [
                {"server": f"198.51.100.{i + 1}", "server_port": 443,
                 "latency_ms": 100 + i,
                 "real_latency_ms": (20 + i if i < 2 else None),
                 "endpoint": _endpoint(f"vpngate-{i}")} for i in range(4)]
            with mock.patch.object(RailwayManager, "_check_config", return_value=True), \
                    mock.patch.object(RailwayManager, "_restart_singbox") as restart:
                # Keep the pin fixed: an auto-pin change is a legitimate config
                # rewrite, and this test is about the pool/health path only.
                manager.preferred_tag = "vpngate-0"
                manager._apply_config(final="auto", preferred="vpngate-0")
                restart.reset_mock()
                before = manager.status["resi"]["pool"]
                with open(manager.config_path, "rb") as handle:
                    cfg_before = handle.read()
                # Every node really dials this time: the pool must grow to all 4.
                manager.dial_fn = lambda node: 30
                manager.verify_fn = lambda endpoint: ("198.51.100.9", 5)
                manager._run_full_probe_inner()
                after = manager.status["resi"]["pool"]
                inbounds = manager.status["resi"]["inbounds"]
                with open(manager.config_path, "rb") as handle:
                    cfg_after = handle.read()
            restarts = restart.call_count
        finally:
            manager.stop()
            self._cleanup(manager)

        # 2 verified, but vpngate-0 is the chain's pin and stays out of the
        # rotation, so the pool starts at 1 and grows to 4-1 after the full pass.
        self.assertEqual(1, before)
        self.assertEqual(3, after)
        self.assertEqual(4, inbounds)
        self.assertEqual(cfg_before, cfg_after)
        self.assertEqual(0, restarts)      # a probe result never restarts sing-box

    def test_a_failing_node_is_parked_then_returns(self) -> None:
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            for _ in range(RESI_NODE_STRIKES_DOWN):
                manager._resi_note_connection("vpngate-a", 200, 128, 0.4, True)
            pool = [tag for tag, _ in manager._resi_pool()]
            # Expire the window: the node is tried again (and can recover).
            manager._resi_health["vpngate-a"]["down_until"] = 0.0
            recovered = [tag for tag, _ in manager._resi_pool()]
            manager._resi_note_connection("vpngate-a", 200, 4096, 0.4, True)
            health = dict(manager._resi_health.get("vpngate-a") or {})
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-b"], pool)
        self.assertEqual(["vpngate-a", "vpngate-b"], recovered)
        self.assertEqual({}, health)

    def test_client_side_closes_never_count_as_strikes(self) -> None:
        # A client that closes first (idle keep-alive, tcping) must not park a
        # healthy node.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            for _ in range(RESI_NODE_STRIKES_DOWN * 2):
                manager._resi_note_connection("vpngate-a", 1, 128, 0.1, False)
            health = dict(manager._resi_health.get("vpngate-a") or {})
            pool = manager._resi_pool()
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(0, health.get("strikes", 0))
        self.assertEqual(["vpngate-a"], [tag for tag, _ in pool])

    def test_an_all_parked_pool_still_serves_the_least_recent_failure(self) -> None:
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            now = time.monotonic()
            manager._resi_health["vpngate-a"] = {"strikes": 0, "downs": 1, "down_until": now + 200}
            manager._resi_health["vpngate-b"] = {"strikes": 0, "downs": 1, "down_until": now + 100}
            pool = manager._resi_pool()
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(["vpngate-b"], [tag for tag, _ in pool])

    @staticmethod
    def _fake_backend(tag: str) -> tuple[socket.socket, int]:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    # Drain the forwarded request first: closing a socket with
                    # unread data sends RST, which would discard the reply we
                    # are about to write.
                    conn.recv(4096)
                    conn.sendall(tag.encode("ascii"))
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        threading.Thread(target=serve, daemon=True).start()
        return srv, srv.getsockname()[1]

    @staticmethod
    def _ws_get(port: int, path: str) -> bytes:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        with sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n"
                         f"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                         f"Sec-WebSocket-Version: 13\r\n"
                         f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                         .encode())
            return sock.recv(64)

    def test_catch_all_tunnel_can_serve_the_third_path(self) -> None:
        # Regression: a Cloudflare catch-all (/* -> $PORT) must carry the third
        # path too. It used to hit the admin gate and answer 401, which looks
        # exactly like "the third path is broken while the other two work".
        srv, backend_port = self._fake_backend("resi-node")
        manager = self._manager(resi_port=_free_port())
        manager._set_resi_ports([backend_port])
        port = manager.start()
        try:
            received = self._ws_get(port, "/ws-resi")
        finally:
            manager.stop()
            srv.close()
            self._cleanup(manager)

        self.assertEqual(b"resi-node", received)

    def test_mux_routes_node_and_chain_paths_too(self) -> None:
        srv_direct, direct_port = self._fake_backend("direct-node")
        srv_chain, chain_port = self._fake_backend("chain-node")
        manager = self._manager(resi_port=_free_port(),
                                vless_direct_port=direct_port,
                                vless_chain_port=chain_port)
        port = manager.start()
        try:
            direct = self._ws_get(port, "/ws-node")
            chain = self._ws_get(port, "/ws-chain")
        finally:
            manager.stop()
            srv_direct.close()
            srv_chain.close()
            self._cleanup(manager)

        self.assertEqual(b"direct-node", direct)
        self.assertEqual(b"chain-node", chain)

    def test_mux_still_rejects_unknown_paths(self) -> None:
        manager = self._manager(resi_port=_free_port())
        port = manager.start()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            with sock:
                sock.sendall(b"GET /ws-unknown HTTP/1.1\r\nHost: x\r\n"
                             b"Connection: close\r\n\r\n")
                received = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    received += chunk
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertIn(b"401", received)

    def test_node_close_tears_the_connection_down_at_once(self) -> None:
        # Regression: the pipe waited for client->backend to end first, so a
        # node that dropped us left the client hanging for the whole idle
        # timeout - the "stuck on a dead node" symptom.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        backend_port = srv.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                time.sleep(0.2)
                conn.close()
            except OSError:
                return

        threading.Thread(target=serve, daemon=True).start()
        manager = self._manager(resi_port=_free_port())
        manager._set_resi_ports([backend_port])
        client, peer = socket.socketpair()
        worker = threading.Thread(target=manager._handle_resi_client,
                                  args=(client,), daemon=True)
        try:
            worker.start()
            peer.sendall(b"GET /ws-resi HTTP/1.1\r\n\r\n")
            peer.settimeout(5)
            started = time.monotonic()
            received = peer.recv(64)
            elapsed = time.monotonic() - started
            worker.join(timeout=5)
            alive = worker.is_alive()
        finally:
            peer.close()
            srv.close()
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(b"", received)   # the node dropped us, so did the mux
        self.assertLess(elapsed, 4.0)
        self.assertFalse(alive)

    def test_a_fast_node_drop_is_counted_as_a_strike(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        backend_port = srv.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                conn.close()
            except OSError:
                return

        threading.Thread(target=serve, daemon=True).start()
        manager = self._manager(resi_port=_free_port())
        manager._set_resi_ports([backend_port])
        client, peer = socket.socketpair()
        worker = threading.Thread(target=manager._handle_resi_client,
                                  args=(client,), daemon=True)
        try:
            worker.start()
            peer.sendall(b"GET /ws-resi HTTP/1.1\r\n\r\n")
            peer.settimeout(5)
            try:
                peer.recv(64)
            except socket.timeout:
                pass
            worker.join(timeout=5)
            health = dict(manager._resi_health.get(f"port-{backend_port}") or {})
        finally:
            peer.close()
            srv.close()
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(1, health.get("strikes", 0))

    def test_a_slow_node_side_failure_also_counts_as_a_strike(self) -> None:
        # A blackholed node makes sing-box sit on the dial for ~10s before it
        # closes: that is still a dead node, not a healthy one.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            manager._resi_note_connection("vpngate-a", 200, 128, 12.0, True)
            strikes = (manager._resi_health.get("vpngate-a") or {}).get("strikes")
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(1, strikes)

    def test_a_long_idle_close_is_not_a_strike(self) -> None:
        # Idle NAT reaping closes a perfectly good tunnel after a minute or
        # more; that must not park the node.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            for _ in range(RESI_NODE_STRIKES_DOWN * 2):
                manager._resi_note_connection("vpngate-a", 200, 128, 45.0, True)
            health = dict(manager._resi_health.get("vpngate-a") or {})
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(0, health.get("strikes", 0))

    def test_a_silent_node_side_strikes_even_after_the_idle_window(self) -> None:
        # Nothing came back down for the full idle timeout: the node carried no
        # payload at all, so the client must not keep being sent there.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            manager._resi_note_connection("vpngate-a", 200, 128, 120.0, False,
                                          down_idle=True)
            strikes = (manager._resi_health.get("vpngate-a") or {}).get("strikes")
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(1, strikes)

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

    def test_a_node_that_swallows_the_request_is_struck(self) -> None:
        # sing-box holds the inbound while its endpoint keeps dial-probing a
        # dead IP, so the client's bytes go nowhere and nothing ever comes back.
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            manager._resi_note_connection("vpngate-a", 700, 0, 21.0, False,
                                          first_byte_stalled=True)
            strikes = (manager._resi_health.get("vpngate-a") or {}).get("strikes")
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(1, strikes)

    def test_the_pump_gives_a_silent_node_only_the_first_byte_budget(self) -> None:
        # No closure from either side: the watchdog must end the connection once
        # the client's bytes have been unanswered for the budget (20s in prod,
        # 0.4s here), instead of waiting out PIPE_IDLE_TIMEOUT.
        client, client_peer = socket.socketpair()
        backend, backend_peer = socket.socketpair()
        client.settimeout(120)
        backend.settimeout(120)
        result: dict = {}
        started = time.monotonic()

        def run() -> None:
            result.update(_pump_pair(client, backend, started))

        worker = threading.Thread(target=run, daemon=True)
        closed_after = 0.0
        try:
            with mock.patch("railway_manager.RESI_FIRST_BYTE_TIMEOUT", 0.4):
                worker.start()
                client_peer.sendall(b"GET / HTTP/1.1\r\n\r\n")
                # The client sees the connection die when the watchdog fires.
                client_peer.settimeout(6)
                self.assertEqual(b"", client_peer.recv(64))
                closed_after = time.monotonic() - started
                worker.join(timeout=12)
        finally:
            for sock in (client, client_peer, backend, backend_peer):
                try:
                    sock.close()
                except OSError:
                    pass

        self.assertFalse(worker.is_alive())
        self.assertTrue(result.get("first_byte_stalled"), result)
        self.assertEqual(18, result.get("up"))
        self.assertEqual(0, result.get("down"))
        self.assertLess(closed_after, 4.0)

    def test_a_node_that_answered_is_not_struck_for_a_stall(self) -> None:
        manager = self._manager(resi_port=_free_port())
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            # It stalled, but it did answer eventually: payload wins.
            manager._resi_note_connection("vpngate-a", 700, 4096, 25.0, False,
                                          first_byte_stalled=True)
            health = dict(manager._resi_health.get("vpngate-a") or {})
        finally:
            manager.stop()
            self._cleanup(manager)

        self.assertEqual(0, health.get("strikes", 0))

    def test_a_failed_handshake_replay_still_closes_the_backend(self) -> None:
        # The handshake replay happens before the pump. If the node has already
        # dropped the loopback connection, sendall raises - and the backend must
        # still be closed, otherwise every bad node leaks one descriptor and the
        # manager dies after a few hundred rotations.
        manager = self._manager(resi_port=_free_port())
        backend = mock.Mock()
        backend.sendall.side_effect = OSError("replay failed")
        client, peer = socket.socketpair()
        worker = threading.Thread(target=manager._handle_resi_client,
                                  args=(client, b"GET /ws-resi HTTP/1.1\r\n\r\n"),
                                  daemon=True)
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE)])
            with mock.patch("railway_manager.socket.create_connection",
                            return_value=backend):
                worker.start()
                worker.join(timeout=5)
            inflight = manager._mux_inflight
        finally:
            peer.close()
            manager.stop()
            self._cleanup(manager)

        self.assertFalse(worker.is_alive())
        self.assertTrue(backend.close.called)
        self.assertEqual(0, inflight)
        self.assertFalse(worker.is_alive())

    def test_a_refused_loopback_dial_never_strikes_the_node(self) -> None:
        # The rotate inbound is gone for a moment whenever sing-box restarts
        # (pin change/rescue). That is not the node's fault: striking it would
        # park healthy nodes exactly when the service is recovering.
        manager = self._manager(resi_port=_free_port())
        client, peer = socket.socketpair()
        worker = threading.Thread(target=manager._handle_resi_client,
                                  args=(client, b"GET /ws-resi HTTP/1.1\r\n\r\n"),
                                  daemon=True)
        try:
            manager._set_resi_routes([("vpngate-a", RESI_ROTATE_BASE),
                                      ("vpngate-b", RESI_ROTATE_BASE + 1)])
            with mock.patch("railway_manager.socket.create_connection",
                            side_effect=ConnectionRefusedError("no listener")):
                worker.start()
                worker.join(timeout=5)
            health = dict(manager._resi_health)
            pool = [tag for tag, _ in manager._resi_pool()]
            inflight = manager._mux_inflight
        finally:
            peer.close()
            manager.stop()
            self._cleanup(manager)

        self.assertFalse(worker.is_alive())
        self.assertEqual({}, {k: v for k, v in health.items() if v.get("strikes")})
        self.assertEqual(["vpngate-a", "vpngate-b"], pool)
        self.assertEqual(0, inflight)


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
