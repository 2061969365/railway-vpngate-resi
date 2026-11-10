"""Supply-chain drift checks: Dockerfile ARGs, CI env and docs must agree.

These are read-only checks.  No new dependency is used (stdlib re/hashlib),
and the cc-switch hash is computed from the checked-in binary.
"""
from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
UNIT_TESTS = ROOT / ".github" / "workflows" / "unit-tests.yml"
PUBLISH = ROOT / ".github" / "workflows" / "publish-image.yml"
SUPPLY_DOC = ROOT / "docs" / "supply-chain.md"
REQUIREMENTS = ROOT / "requirements-test.txt"
CC_SWITCH = ROOT / "cc-switch-server"

ARG_NAMES = (
    "SINGBOX_VERSION",
    "SINGBOX_SHA256",
    "CLOUDFLARED_VERSION",
    "CLOUDFLARED_SHA256",
    "CC_SWITCH_SHA256",
)


def parse_docker_args(text: str) -> dict[str, str]:
    args: dict[str, str] = {}
    for match in re.finditer(r"(?m)^ARG\s+([A-Z0-9_]+)=(\S+)\s*$", text):
        args[match.group(1)] = match.group(2)
    return args


def parse_workflow_env(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for match in re.finditer(
        r"(?m)^\s*(SINGBOX_VERSION|SINGBOX_SHA256):\s*\"?([^\"\s]+)\"?\s*$",
        text,
    ):
        env[match.group(1)] = match.group(2)
    return env


class DockerfileArgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        cls.args = parse_docker_args(cls.dockerfile)
        cls.docs = SUPPLY_DOC.read_text(encoding="utf-8")

    def test_all_expected_args_exist(self) -> None:
        for name in ARG_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, self.args)

    def test_args_match_workflow_env(self) -> None:
        env = parse_workflow_env(UNIT_TESTS.read_text(encoding="utf-8"))
        for name in ("SINGBOX_VERSION", "SINGBOX_SHA256"):
            with self.subTest(name=name):
                self.assertIn(name, env)
                self.assertEqual(self.args[name], env[name])

    def test_args_match_supply_chain_doc(self) -> None:
        for name in ARG_NAMES:
            with self.subTest(name=name):
                self.assertIn(self.args[name], self.docs)

    def test_cc_switch_file_matches_pinned_hash(self) -> None:
        self.assertTrue(CC_SWITCH.is_file())
        digest = hashlib.sha256(CC_SWITCH.read_bytes()).hexdigest()
        self.assertEqual(self.args["CC_SWITCH_SHA256"], digest)

    def test_base_images_are_digest_pinned_and_documented(self) -> None:
        digests = re.findall(
            r"(?m)^FROM\s+(\S+)@sha256:([0-9a-f]{64})", self.dockerfile
        )
        self.assertGreaterEqual(len(digests), 2)
        for image, digest in digests:
            with self.subTest(image=image):
                self.assertIn(f"sha256:{digest}", self.docs)

    def test_docs_record_cc_switch_environment_isolation(self) -> None:
        self.assertIn("env -i", self.docs)
        self.assertIn("CC_SWITCH_INHERIT_ENV", self.docs)
        self.assertIn("ZEN_TABLE_URL", self.docs)

    def test_docs_record_nezha_yaml_and_zip_validation(self) -> None:
        self.assertIn("NEZHA_TLS", self.docs)
        self.assertIn("zipfile", self.docs)
        self.assertIn("zip-slip", self.docs)

    def test_docs_record_curl_unzip_remaining_work(self) -> None:
        self.assertIn("curl", self.docs)
        self.assertIn("unzip", self.docs)
        self.assertIn("R2-4-11", self.docs)


class TestRequirementsTests(unittest.TestCase):
    def test_pytest_is_exactly_pinned(self) -> None:
        text = REQUIREMENTS.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^pytest==\d+\.\d+\.\d+$")
        self.assertNotRegex(text, r"(?m)^pytest[<>~!]")

    def test_both_workflows_use_requirements_file(self) -> None:
        for workflow in (UNIT_TESTS, PUBLISH):
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                self.assertIn(
                    "python -m pip install -r requirements-test.txt", text
                )
                self.assertNotIn("pip install --upgrade pip pytest", text)


if __name__ == "__main__":
    unittest.main()
