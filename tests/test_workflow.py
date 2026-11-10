"""Workflow contract tests for the image publish job."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
PUBLISH_WORKFLOW = WORKFLOWS / "publish-image.yml"
UNIT_TESTS_WORKFLOW = WORKFLOWS / "unit-tests.yml"


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

    def test_publish_requires_test_job(self) -> None:
        self.assertRegex(self.text, r"(?m)^\s+needs:\s*test\s*$")
        self.assertRegex(self.text, r"(?m)^\s+test:\s*$")

    def test_test_job_runs_python_and_go(self) -> None:
        self.assertIn("python -m pytest tests -q", self.text)
        self.assertIn("go test ./...", self.text)

    def test_publishes_immutable_sha_tag(self) -> None:
        self.assertIn("sha-${{ github.sha }}", self.text)
        self.assertIn("type=raw,value=latest", self.text)

    def test_latest_tag_is_default_branch_only(self) -> None:
        # R2-4-01: a workflow_dispatch from a feature branch must not move
        # the production `latest` tag.
        self.assertIn(
            "type=raw,value=latest,enable={{is_default_branch}}", self.text
        )
        self.assertNotRegex(
            self.text, r"(?m)^\s*type=raw,value=latest\s*$"
        )

    def test_publish_is_serialized_per_ref(self) -> None:
        # R2-4-02: two overlapping builds must not race to push `latest`.
        self.assertRegex(self.text, r"(?m)^concurrency:\s*$")
        self.assertIn("group: publish-image-${{ github.ref }}", self.text)
        self.assertIn("cancel-in-progress: false", self.text)

    def test_builds_are_linux_amd64(self) -> None:
        # R2-4-03: every embedded binary is amd64; an arm runner would build
        # an image that dies with Exec format error.
        self.assertGreaterEqual(self.text.count("platforms: linux/amd64"), 2)

    def test_smoke_runs_before_push(self) -> None:
        # R2-4-09/R2-4-16: no push until the image imports the manager and
        # drops to UID 10001.
        smoke = self.text.index("Smoke test image entrypoint")
        push = self.text.index("push: true")
        self.assertLess(smoke, push)
        self.assertIn("ENTRYPOINT_DRY_RUN=1", self.text)
        self.assertIn('= "10001"', self.text)
        self.assertIn("bash -n /app/start.sh", self.text)
        self.assertIn("sh -n /app/entrypoint.sh", self.text)

    def test_uses_pinned_test_requirements(self) -> None:
        # R2-4-10: no floating pytest in CI.
        self.assertIn("python -m pip install -r requirements-test.txt", self.text)
        self.assertNotIn("pip install --upgrade pip pytest", self.text)

    def test_jobs_have_timeouts(self) -> None:
        self.assertGreaterEqual(self.text.count("timeout-minutes:"), 2)

    def test_top_level_permissions_are_read_only(self) -> None:
        top = self.text.split("jobs:", 1)[0]
        self.assertIn("contents: read", top)
        self.assertNotIn("packages: write", top)


class PullRequestImageBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = UNIT_TESTS_WORKFLOW.read_text(encoding="utf-8")

    def test_pr_builds_image_without_pushing(self) -> None:
        # R2-4-19: Dockerfile/start.sh regressions must fail on the PR.
        self.assertIn("pull_request", self.text)
        self.assertIn("docker build", self.text)
        self.assertNotIn("push: true", self.text)

    def test_pr_smoke_checks_entrypoint(self) -> None:
        self.assertIn("ENTRYPOINT_DRY_RUN=1", self.text)
        self.assertIn("bash -n /app/start.sh", self.text)
        self.assertIn("sh -n /app/entrypoint.sh", self.text)
        self.assertIn('= "10001"', self.text)

    def test_uses_pinned_test_requirements(self) -> None:
        self.assertIn("python -m pip install -r requirements-test.txt", self.text)
        self.assertNotIn("pip install --upgrade pip pytest", self.text)


class ActionPinningTests(unittest.TestCase):
    def test_all_actions_use_commit_sha(self) -> None:
        uses: list[str] = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for match in re.finditer(r"(?m)^\s*-?\s*uses:\s*(\S+)", path.read_text(encoding="utf-8")):
                uses.append(match.group(1))
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
