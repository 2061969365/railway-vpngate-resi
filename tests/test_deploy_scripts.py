"""Deployment-script contracts: entrypoint, start.sh guards, Dockerfile.

No Docker daemon is required.  Shell scripts are syntax-checked and the
early-exit paths are executed; image behaviour is asserted statically.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
START = ROOT / "start.sh"
ENTRYPOINT = ROOT / "entrypoint.sh"
DOCKERFILE = ROOT / "Dockerfile"
README = ROOT / "README.md"
GO_MANAGER_DOC = ROOT / "docs" / "go-manager.md"

# On Windows, CreateProcess searches System32 before PATH and can pick the
# WSL `bash.exe` stub.  shutil.which() honours PATH, so resolve explicitly.
BASH = shutil.which("bash") or "bash"
SH = shutil.which("sh") or "sh"


def _uid() -> int | None:
    try:
        out = subprocess.check_output(
            [BASH, "-c", "id -u"],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        return int(out.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def run_start(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(overrides)
    return subprocess.run(
        [BASH, str(START)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def extract_function(name: str) -> str:
    text = START.read_text(encoding="utf-8")
    match = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}", text)
    if match is None:
        raise AssertionError(f"{name}() not found in start.sh")
    return match.group(0)


class SyntaxTests(unittest.TestCase):
    def test_start_script_parses(self) -> None:
        subprocess.run([BASH, "-n", str(START)], check=True, timeout=30)

    def test_entrypoint_parses(self) -> None:
        subprocess.run([SH, "-n", str(ENTRYPOINT)], check=True, timeout=30)


class EntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = ENTRYPOINT.read_text(encoding="utf-8")

    def test_uses_sh_and_drops_privileges(self) -> None:
        self.assertTrue(self.text.startswith("#!/bin/sh\n"))
        self.assertIn(
            'DATA_DIR="${DATA_DIR:-${RAILWAY_VOLUME_MOUNT_PATH:-/app}}"',
            self.text,
        )
        self.assertIn('mkdir -p "$DATA_DIR"', self.text)
        self.assertIn('chown -R app:app "$DATA_DIR"', self.text)
        for call in (
            "os.setgroups([])",
            "os.setgid(10001)",
            "os.setuid(10001)",
            'os.execv("/app/start.sh"',
        ):
            self.assertIn(call, self.text)

    def test_dry_run_reports_uid_after_chown(self) -> None:
        self.assertIn("ENTRYPOINT_DRY_RUN", self.text)
        self.assertLess(
            self.text.index('chown -R app:app "$DATA_DIR"'),
            self.text.index("ENTRYPOINT_DRY_RUN"),
        )
        self.assertIn('os.execvp("id", ["id", "-u"])', self.text)
        self.assertIn("exec id -u", self.text)

    def test_non_root_execs_start_directly(self) -> None:
        self.assertIn("exec /app/start.sh", self.text)

    def test_non_root_dry_run(self) -> None:
        uid = _uid()
        if uid == 0:
            self.skipTest("running as root: the chown path is covered by CI")
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update({"ENTRYPOINT_DRY_RUN": "1", "DATA_DIR": tmp})
            proc = subprocess.run(
                [SH, str(ENTRYPOINT)],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(str(uid), proc.stdout.strip())


class DockerfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DOCKERFILE.read_text(encoding="utf-8")

    def test_entrypoint_not_user_app(self) -> None:
        self.assertNotRegex(self.text, r"(?m)^USER app\s*$")
        self.assertIn('ENTRYPOINT ["/app/entrypoint.sh"]', self.text)
        self.assertIn("COPY --chown=app:app start.sh entrypoint.sh ./", self.text)
        self.assertRegex(
            self.text, r"chmod 0755 /app/start\.sh /app/entrypoint\.sh"
        )

    def test_template_is_copied_not_generated(self) -> None:
        self.assertIn("COPY --chown=app:app www ./www", self.text)
        self.assertNotIn("RUN cp /app/www/index.html", self.text)
        self.assertNotIn("chown app:app /app/www/index.template.html", self.text)
        self.assertNotIn("chmod 0644 /app/www/index.template.html", self.text)


class StartScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = START.read_text(encoding="utf-8")

    def test_port_validation(self) -> None:
        self.assertIn('PORT="${PORT:-3000}"', self.text)
        self.assertIn("is_port \"$PORT\"", self.text)
        self.assertIn("non-root image cannot bind privileged PORT", self.text)
        for reserved in ("8080", "8081", "8082", "8084", "4096", "40000"):
            self.assertIn(reserved, self.text)
        self.assertIn("conflicts with an internal/reserved port", self.text)

    def test_invalid_ports_exit_before_services(self) -> None:
        for value, expected in (
            ("abc", "PORT must be"),
            ("08080", "PORT must be"),
            ("8080", "conflicts with an internal/reserved port"),
            ("4096", "conflicts with an internal/reserved port"),
            ("40000", "conflicts with an internal/reserved port"),
        ):
            with self.subTest(PORT=value):
                proc = run_start(PORT=value)
                self.assertNotEqual(0, proc.returncode)
                self.assertIn(expected, proc.stdout + proc.stderr)

    def test_privileged_port_rejected_for_non_root(self) -> None:
        uid = _uid()
        if uid == 0:
            self.skipTest("root can bind <1024")
        proc = run_start(PORT="80")
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("privileged PORT", proc.stdout + proc.stderr)

    def test_is_port_rejects_leading_zero(self) -> None:
        function = extract_function("is_port")
        checks = {
            "3000": "ok",
            "80": "ok",
            "65535": "ok",
            "65536": "no",
            "0": "no",
            "08080": "no",
            "abc": "no",
            "": "no",
        }
        script = function + "\n"
        for value, _ in checks.items():
            script += f'if is_port "{value}"; then echo ok; else echo no; fi\n'
        proc = subprocess.run(
            [BASH, "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(list(checks.values()), proc.stdout.split())

    def test_template_missing_is_fatal(self) -> None:
        self.assertIn('TEMPLATE="$WWW_DIR/index.template.html"', self.text)
        self.assertNotIn('TEMPLATE="$WWW_DIR/index.html"', self.text)
        self.assertIn('if [ ! -f "$TEMPLATE" ]', self.text)
        self.assertIn("disguise page template missing", self.text)
        self.assertIn('export DISGUISE_PATH="$WWW_DIR/index.html"', self.text)
        self.assertTrue((ROOT / "www" / "index.template.html").is_file())

    def test_cleanup_trap_covers_all_children(self) -> None:
        self.assertIn("trap _cleanup EXIT", self.text)
        cleanup = extract_function("_cleanup")
        for pid in (
            "MANAGER_PID",
            "PROXY_PID",
            "HTTP_PID",
            "NEZHA_PID",
            "PROBE_PID",
            "EDGE_PID",
        ):
            self.assertIn(f"${pid}", cleanup)

    def test_python_interpreter_is_resolved_once(self) -> None:
        self.assertIn(
            'PYTHON="$(command -v python3 || command -v python || true)"',
            self.text,
        )
        self.assertIn('"$PYTHON" railway_manager.py', self.text)
        self.assertIn('"$PYTHON" -m http.server 8081', self.text)
        self.assertNotIn("python3 railway_manager.py", self.text)
        self.assertNotIn("python3 -m http.server", self.text)

    def test_cc_switch_runs_with_minimal_environment(self) -> None:
        self.assertIn("run_cc_switch()", self.text)
        self.assertGreaterEqual(self.text.count("run_cc_switch"), 3)
        self.assertIn("env -i", self.text)
        self.assertIn("CC_SWITCH_INHERIT_ENV", self.text)
        self.assertIn("ZEN_TABLE_URL", self.text)
        self.assertIn("HOME=/tmp TMPDIR=/tmp", self.text)
        self.assertIn("PORT=4096 HOST=0.0.0.0", self.text)

    def test_nezha_yaml_and_zip_validation(self) -> None:
        self.assertIn("safe_unzip", self.text)
        self.assertIn("zipfile", self.text)
        self.assertIn("PurePosixPath", self.text)
        self.assertNotIn("unzip -o", self.text)
        self.assertIn("invalid NEZHA_SERVER", self.text)
        self.assertIn("invalid NEZHA_KEY", self.text)
        self.assertIn("invalid NEZHA_TLS", self.text)
        self.assertIn('client_secret: "${nezha_key}"', self.text)
        self.assertIn('server: "${nezha_server}"', self.text)
        self.assertIn("'^(\\[[0-9A-Fa-f:.]+\\](:[0-9]{1,5})?|", self.text)
        self.assertIn('valid_nezha_scalar "$nezha_key"', self.text)

    def test_nezha_scalar_rejects_embedded_whitespace(self) -> None:
        # grep -E is line-oriented: a multi-line NEZHA_KEY could otherwise
        # pass the per-line regex and inject YAML keys.
        function = extract_function("valid_nezha_scalar")
        # Values use bash ANSI-C quoting so CR/LF are produced inside bash,
        # not passed through the Windows/MSYS argv conversion (which strips
        # them and would hide the regression).
        cases = [
            (r"host:8008", "ok"),
            (r"bad\nkey", "no"),
            (r"bad\rkey", "no"),
            (r"bad\tkey", "no"),
            (r"bad key", "no"),
            ("", "no"),
        ]
        script = function + "\n"
        for value, _ in cases:
            script += (
                f"if valid_nezha_scalar $'{value}'; then echo ok; "
                "else echo no; fi\n"
            )
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "check.sh"
            script_path.write_bytes(script.encode("utf-8"))
            proc = subprocess.run(
                [BASH, str(script_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual([expected for _, expected in cases], proc.stdout.split())


class DocumentationAlignmentTests(unittest.TestCase):
    def test_readme_documents_breaking_changes(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("每次容器重启", text)
        self.assertIn("从旧版本升级", text)
        self.assertIn("ADMIN_TOKEN", text)
        self.assertIn("NEZHA_AGENT_SHA256", text)
        self.assertIn("chown -R app:app", text)
        self.assertIn("不需要手动改卷属主", text)
        self.assertIn("MANAGER_IMPL", text)

    def test_go_manager_doc_matches_start_script(self) -> None:
        text = GO_MANAGER_DOC.read_text(encoding="utf-8")
        self.assertIn("default and only implemented value is `py`", text)
        self.assertIn("documented only", text)
        self.assertIn("stages 3-6", text)
        self.assertNotIn(
            "selects the implementation at the deployment layer", text
        )


if __name__ == "__main__":
    unittest.main()
