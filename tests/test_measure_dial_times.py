"""Tests for scripts/measure_dial_times.py (dial elapsed instrumentation)."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "measure_dial_times.py"


def load_module():
    spec = importlib.util.spec_from_file_location("measure_dial_times", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def node(server, handshake=100):
    return {"server": server, "server_port": 443, "country_short": "JP",
            "latency_ms": handshake, "endpoint": {"server": server}}


def row(server, elapsed, real, handshake=100):
    return {"server": server, "server_port": 443, "country_short": "JP",
            "handshake_ms": handshake, "elapsed_s": elapsed, "real_ms": real}


class PickSpreadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_spread_covers_fast_mid_slow(self) -> None:
        nodes = [node(f"10.0.0.{i}", handshake=i) for i in range(10)]

        picked = self.mod.pick_spread(nodes, count=6)

        self.assertEqual([f"10.0.0.{i}" for i in (0, 1, 2, 4, 6, 8)],
                         [n["server"] for n in picked])

    def test_short_list_returns_what_exists(self) -> None:
        nodes = [node("10.0.0.1"), node("10.0.0.2")]

        self.assertEqual(2, len(self.mod.pick_spread(nodes, count=6)))


class SummarizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_mixed_rows_summarized(self) -> None:
        rows = [row("10.0.0.1", 12.5, 1300),
                row("10.0.0.2", 25.0, 2400),
                row("10.0.0.3", 90.0, None)]

        summary = self.mod.summarize_dials(rows, timeout=90)

        self.assertEqual((3, 2), (summary["n"], summary["measured"]))
        self.assertAlmostEqual(12.5, summary["elapsed_min"])
        self.assertAlmostEqual(18.75, summary["elapsed_med"])
        self.assertAlmostEqual(25.0, summary["elapsed_max"])
        self.assertEqual(1, summary["full_timeouts"])

    def test_all_dead_still_summarizes(self) -> None:
        rows = [row("10.0.0.1", 90.0, None)]

        summary = self.mod.summarize_dials(rows, timeout=90)

        self.assertEqual((1, 0), (summary["n"], summary["measured"]))
        self.assertIsNone(summary["elapsed_med"])

    def test_render_lists_every_row(self) -> None:
        rows = [row("10.0.0.1", 12.5, 1300), row("10.0.0.2", 90.0, None)]
        summary = self.mod.summarize_dials(rows, timeout=90)

        markdown = self.mod.render_markdown(rows, summary, timeout=90)

        self.assertIn("10.0.0.1", markdown)
        self.assertIn("10.0.0.2", markdown)
        self.assertIn("1/2", markdown)


class RunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_run_dials_spread_without_network(self) -> None:
        mod = self.mod
        nodes = [node(f"10.0.0.{i}", handshake=50 + i) for i in range(10)]
        calls = []

        def fake_snapshot(csv_text, **kwargs):
            return nodes

        def fake_dial(endpoint, singbox_bin, timeout):
            calls.append(endpoint["server"])
            return 1200

        old_snapshot, old_dial = mod.snapshot_to_nodes, mod.measure_real_latency
        mod.snapshot_to_nodes, mod.measure_real_latency = fake_snapshot, fake_dial
        with tempfile.NamedTemporaryFile("w", suffix=".csv",
                                         delete=False) as handle:
            handle.write("placeholder")
            csv_path = handle.name
        try:
            code, markdown, rows = mod.run(csv_path, count=4, timeout=90,
                                           workers=2, limit=12,
                                           singbox_bin="sing-box")
        finally:
            mod.snapshot_to_nodes, mod.measure_real_latency = old_snapshot, old_dial
            os.unlink(csv_path)

        self.assertEqual(0, code)
        self.assertEqual(4, len(rows))
        self.assertEqual(4, len(calls))
        self.assertIn("4/4", markdown)

    def test_run_bad_csv_is_infra_error(self) -> None:
        code, _, _ = self.mod.run("/nonexistent-snapshot.csv", count=4,
                                  timeout=90, workers=2,
                                  limit=12, singbox_bin="sing-box")

        self.assertEqual(1, code)


class ScriptEntryTests(unittest.TestCase):
    """The script must run as `python scripts/measure_dial_times.py`
    (only scripts/ on sys.path), like the CI step invokes it."""

    def test_help_works_from_repo_root(self) -> None:
        repo = Path(__file__).resolve().parent.parent
        # File-backed output: a confined test process cannot hand a pipe to a
        # child process; the assertions read the same stdout/stderr.
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "help.out")
            err_path = os.path.join(tmpdir, "help.err")
            with open(out_path, "w", encoding="utf-8") as out, \
                    open(err_path, "w", encoding="utf-8") as err:
                proc = subprocess.run(
                    [sys.executable, "scripts/measure_dial_times.py", "--help"],
                    cwd=repo, stdout=out, stderr=err, text=True, timeout=60)
            stdout = Path(out_path).read_text(encoding="utf-8",
                                             errors="replace")
            stderr = Path(err_path).read_text(encoding="utf-8",
                                              errors="replace")

        self.assertEqual(0, proc.returncode, stderr)
        self.assertIn("--csv", stdout)

if __name__ == "__main__":
    unittest.main()
