"""Workflow contract tests for the image publish job."""
from __future__ import annotations

import unittest
from pathlib import Path

PUBLISH_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "publish-image.yml"


class PublishImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    def test_publishes_to_ghcr(self) -> None:
        self.assertIn("ghcr.io", self.text)

    def test_builds_repo_dockerfile(self) -> None:
        self.assertIn("Dockerfile", self.text)

    def test_pushes_only_on_main(self) -> None:
        self.assertIn("main", self.text)
        self.assertIn("push", self.text)

    def test_has_packages_write_permission(self) -> None:
        self.assertIn("packages: write", self.text)


if __name__ == "__main__":
    unittest.main()
