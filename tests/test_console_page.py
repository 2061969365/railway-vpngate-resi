"""Static contract tests for www/console.html after the WF1 web fixes.

These read the page as text and assert a small number of high-value
properties. They are deliberately not a DOM snapshot: the console is one
large inline-script page, and byte-level snapshots would churn on every
cosmetic edit.
"""

import re
import unittest
from pathlib import Path

HTML = (Path(__file__).resolve().parent.parent / "www" / "console.html").read_text(encoding="utf-8")


class ConsolePageContractTests(unittest.TestCase):
    def test_alerts_and_toast_share_fixed_positioning(self) -> None:
        for selector in ("#alerts", "#toast"):
            self.assertRegex(HTML, re.escape(selector) + r"\{[^}]*position:fixed")

    def test_loglevel_option_matches_log_level_return(self) -> None:
        self.assertIn('<option value="err">error</option>', HTML)
        self.assertRegex(HTML, r'function logLevel\(line\) \{[\s\S]*?return "err";')

    def test_subscription_links_include_required_parameters(self) -> None:
        start = HTML.index("function renderSub(")
        end = HTML.index("async function copySub(")
        block = HTML[start:end]
        self.assertIn("encryption=none", block)
        self.assertIn("host=", block)
        self.assertIn("encodeURIComponent(", block)

    def test_login_clears_token_only_on_401(self) -> None:
        self.assertIn("e.status === 401", HTML)
        self.assertIn("服务暂不可用", HTML)

    def test_clipboard_is_feature_detected(self) -> None:
        self.assertIn("navigator.clipboard && navigator.clipboard.writeText", HTML)

    def test_login_gate_is_a_modal_dialog(self) -> None:
        self.assertIn('role="dialog"', HTML)
        self.assertIn('aria-modal="true"', HTML)

    def test_mobile_statusbar_is_static_and_hamburger_exists(self) -> None:
        self.assertIn("#statusbar{position:static", HTML)
        self.assertIn('aria-controls="nav-links"', HTML)
        self.assertIn('aria-expanded="false"', HTML)

    def test_no_hardcoded_probe_service_or_served_exit_defaults(self) -> None:
        self.assertNotIn("probe_service", HTML)
        self.assertNotIn("served_exit", HTML)
        self.assertNotIn("单测服务就绪", HTML)

    def test_stale_banner_and_status_generation_are_present(self) -> None:
        self.assertIn('id="stale-banner"', HTML)
        self.assertIn("statusSeq", HTML)


if __name__ == "__main__":
    unittest.main()
