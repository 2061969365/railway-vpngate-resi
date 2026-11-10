"""Disguise page contract: placeholders, injector escaping, dual VLESS links."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "www" / "index.html"
TEMPLATE = ROOT / "www" / "index.template.html"
INJECTOR = ROOT / "scripts" / "inject_page.py"


def _load_injector():
    spec = importlib.util.spec_from_file_location("inject_page", INJECTOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


inject_page = _load_injector()


class DisguisePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PAGE.read_text(encoding="utf-8")

    def test_direct_path_placeholder_present(self) -> None:
        self.assertIn("VLESS_DIRECT_PATH_PLACEHOLDER", self.text)

    def test_chain_path_placeholder_present(self) -> None:
        self.assertIn("VLESS_CHAIN_PATH_PLACEHOLDER", self.text)

    def test_resi_path_placeholder_present(self) -> None:
        self.assertIn("RESI_PATH_PLACEHOLDER", self.text)

    def test_no_hardcoded_ws_paths(self) -> None:
        for path in ("/ws-node", "/ws-chain", "/ws-resi"):
            self.assertNotIn(path, self.text)

    def test_direct_link_slot_present(self) -> None:
        self.assertIn('id="nodeLink"', self.text)

    def test_chain_link_slot_present(self) -> None:
        self.assertIn('id="nodeLinkChain"', self.text)

    def test_chain_copy_button_present(self) -> None:
        self.assertIn("nodeLinkChain", self.text)
        self.assertIn("链式", self.text)

    def test_chain_remark_suffixed(self) -> None:
        self.assertIn("-chain", self.text)

    def test_subscription_joins_two_lines(self) -> None:
        # subContent must be base64 of direct-link + newline + chain-link.
        self.assertIn("subContent", self.text)
        self.assertIn(r"\n", self.text)


class DisguiseGlassTests(unittest.TestCase):
    """realPage Glass restyle + copy-both button, fakePage untouched."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PAGE.read_text(encoding="utf-8")

    def test_realpage_uses_glass_cards(self) -> None:
        self.assertIn("glass-card", self.text)

    def test_copy_both_button_present(self) -> None:
        self.assertIn('id="btn-copy-both"', self.text)
        self.assertIn("copyBoth(", self.text)

    def test_no_alert_calls(self) -> None:
        self.assertNotIn("alert(", self.text)

    def test_fakepage_untouched(self) -> None:
        self.assertIn('id="fakePage"', self.text)
        self.assertIn("三体", self.text)

    def test_copy_handles_clipboard_denied(self) -> None:
        self.assertIn(".catch(", self.text)

    def test_copy_validates_not_generating(self) -> None:
        self.assertIn("生成中", self.text)

    def test_preferred_source_bestcfip(self) -> None:
        self.assertIn("joname1/BestCFip", self.text)
        self.assertIn("ipv4.txt", self.text)

    def test_pool_parser_handles_ip_port_hash_lines(self) -> None:
        self.assertIn("parsePoolLine(", self.text)


class DisguisePolishTests(unittest.TestCase):
    """T4-T5: clipboard fallback, input validation, pool retry, single
    mirror source, realPage mobile."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PAGE.read_text(encoding="utf-8")

    def test_copy_has_exec_fallback(self) -> None:
        self.assertIn("execCommand", self.text)

    def test_copy_validates_vless_scheme(self) -> None:
        self.assertIn("startsWith('vless://')", self.text)

    def test_pool_retry_button(self) -> None:
        self.assertIn("重试", self.text)

    def test_pool_backup_source(self) -> None:
        self.assertIn("jsdelivr", self.text.lower())

    def test_ip_octet_validated(self) -> None:
        self.assertIn("isValidIPv4", self.text)

    def test_mirror_single_source(self) -> None:
        self.assertEqual(self.text.count("has('mirror')"), 1)

    def test_realpage_mobile_block(self) -> None:
        compact = self.text.replace(" ", "")
        self.assertIn("@media(max-width:640px){#realPage", compact)


class InjectorTests(unittest.TestCase):
    """The Python injector replaces the old sed pipeline."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.template = PAGE.read_text(encoding="utf-8")
        cls.uuid = "11111111-2222-4333-8444-555555555555"

    def render(self, **env: str) -> str:
        base = {
            "VLESS_UUID": self.uuid,
            "NODE_REMARK": "US_1.2.3.4",
            "RESI_PATH": "/ws-resi",
            "VLESS_DIRECT_PATH": "/ws-node",
            "VLESS_CHAIN_PATH": "/ws-chain",
        }
        base.update(env)
        return inject_page.render(self.template, base)

    def test_replaces_js_and_html_placeholders(self) -> None:
        rendered = self.render(
            VLESS_DIRECT_PATH="/direct-x",
            VLESS_CHAIN_PATH="/chain-y",
            RESI_PATH="/resi-z",
        )
        self.assertIn(f'const uuid = "{self.uuid}";', rendered)
        self.assertIn('const wsPath = "/direct-x";', rendered)
        self.assertIn('const wsChainPath = "/chain-y";', rendered)
        self.assertIn('const wsResiPath = "/resi-z";', rendered)
        self.assertIn("> /direct-x<".replace(" ", ""), rendered.replace(" ", ""))
        for stale in (
            "UUID_PLACEHOLDER",
            "NODE_REMARK_PLACEHOLDER",
            "VLESS_DIRECT_PATH_PLACEHOLDER",
            "VLESS_CHAIN_PATH_PLACEHOLDER",
            "RESI_PATH_PLACEHOLDER",
        ):
            self.assertNotIn(stale, rendered)

    def test_script_payload_in_remark_is_escaped(self) -> None:
        rendered = self.render(NODE_REMARK='</script><script>alert(1)</script>')
        self.assertNotIn("</script><script>alert(1)</script>", rendered)
        self.assertIn('const nodeRemark = "Cloud_DynamicIP";', rendered)

    def test_quote_in_remark_falls_back(self) -> None:
        rendered = self.render(NODE_REMARK='US_1.2.3.4";alert(1)//')
        self.assertIn('const nodeRemark = "Cloud_DynamicIP";', rendered)

    def test_invalid_uuid_rejected(self) -> None:
        with self.assertRaises(inject_page.InjectionError):
            self.render(VLESS_UUID='x";alert(1)//')

    def test_path_newline_and_hash_rejected(self) -> None:
        for path in ("/ws-resi#\ne echo PWNED\n#", "/ws-resi\n", "/ws-resi#x"):
            with self.assertRaises(inject_page.InjectionError):
                self.render(RESI_PATH=path)

    def test_path_quotes_and_angle_brackets_rejected(self) -> None:
        for path in ('/ws"resi', "/ws'resi", "/ws<resi", "/ws>resi"):
            with self.assertRaises(inject_page.InjectionError):
                self.render(VLESS_DIRECT_PATH=path)

    def test_allowed_special_characters_accepted(self) -> None:
        path = "/a~b!c$d&e(f)g*h+i,j;k=l:m@n%o-p.q_r"
        rendered = self.render(RESI_PATH=path)
        self.assertIn(f'const wsResiPath = "{path}";', rendered)

    def test_empty_uuid_disables_resi_link(self) -> None:
        rendered = self.render(VLESS_UUID="")
        self.assertIn('const uuid = "";', rendered)
        self.assertIn('const wsResiPath = "";', rendered)
        self.assertNotIn("RESI_PATH_PLACEHOLDER", rendered)

    def test_cli_writes_output_and_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "index.html"
            with mock.patch.dict(
                os.environ,
                {
                    "VLESS_UUID": self.uuid,
                    "NODE_REMARK": "US_1.2.3.4",
                    "RESI_PATH": "/ws-resi",
                    "VLESS_DIRECT_PATH": "/ws-node",
                    "VLESS_CHAIN_PATH": "/ws-chain",
                },
                clear=False,
            ):
                rc = inject_page.main(["--template", str(PAGE), "--output", str(output)])
            self.assertEqual(0, rc)
            self.assertTrue(output.is_file())
            self.assertIn(self.uuid, output.read_text(encoding="utf-8"))

    def test_cli_returns_nonzero_for_bad_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "index.html"
            with mock.patch.dict(
                os.environ,
                {
                    "VLESS_UUID": self.uuid,
                    "RESI_PATH": "/bad#path",
                    "VLESS_DIRECT_PATH": "/ws-node",
                    "VLESS_CHAIN_PATH": "/ws-chain",
                },
                clear=False,
            ):
                rc = inject_page.main(["--template", str(PAGE), "--output", str(output)])
            self.assertEqual(2, rc)
            self.assertFalse(output.exists())


class VlessDisabledPageTests(unittest.TestCase):
    """R2-4-18: an empty VLESS_UUID must not render vless://@host links."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.page = PAGE.read_text(encoding="utf-8")
        cls.template = TEMPLATE.read_text(encoding="utf-8")

    def render(self, **env: str) -> str:
        base = {
            "NODE_REMARK": "US_1.2.3.4",
            "RESI_PATH": "/ws-resi",
            "VLESS_DIRECT_PATH": "/ws-node",
            "VLESS_CHAIN_PATH": "/ws-chain",
        }
        base.update(env)
        return inject_page.render(self.template, base)

    def test_template_is_tracked_and_matches_page(self) -> None:
        self.assertTrue(TEMPLATE.is_file())
        self.assertEqual(PAGE.read_bytes(), TEMPLATE.read_bytes())

    def test_both_files_carry_the_enabled_placeholder(self) -> None:
        self.assertIn("VLESS_ENABLED_PLACEHOLDER", self.template)
        self.assertIn("VLESS_ENABLED_PLACEHOLDER", self.page)

    def test_empty_uuid_renders_disabled_page(self) -> None:
        rendered = self.render(VLESS_UUID="")
        self.assertIn('const vlessEnabled = ("false" === "true");', rendered)
        self.assertNotIn("VLESS_ENABLED_PLACEHOLDER", rendered)
        self.assertNotIn("_PLACEHOLDER", rendered)
        self.assertIn("VLESS 未启用", rendered)
        # The card contents are hidden and no dead link is produced.
        self.assertIn("setVlessDisabled()", rendered)
        self.assertNotIn("vless://@", rendered)

    def test_uuid_renders_enabled_page(self) -> None:
        uuid = "11111111-2222-4333-8444-555555555555"
        rendered = self.render(VLESS_UUID=uuid)
        self.assertIn('const vlessEnabled = ("true" === "true");', rendered)
        self.assertIn(f'const uuid = "{uuid}";', rendered)

    def test_guard_precedes_link_construction(self) -> None:
        rendered = self.render(VLESS_UUID="")
        guard = rendered.index("if (!vlessEnabled)")
        link = rendered.index("const vlessLink")
        self.assertLess(guard, link)
        for element_id in (
            "directCard",
            "chainCard",
            "resiCard",
            "subCard",
            "btn-copy-both",
        ):
            self.assertIn(element_id, rendered)


class WF2PageFixTests(unittest.TestCase):
    """WEB-FIX-PLAN §2: copy, hostname, a11y, motion, pool and injector fixes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PAGE.read_text(encoding="utf-8")
        cls.template = TEMPLATE.read_text(encoding="utf-8")

    def test_subscription_copy_uses_copy_raw(self) -> None:
        self.assertIn('onclick="copyRaw(\'subContent\', this)"', self.text)
        self.assertIn("function copyRaw(elementId, btn)", self.text)

    def test_copy_raw_skips_vless_scheme_check(self) -> None:
        start = self.text.index("function copyRaw(elementId, btn)")
        end = self.text.index("function copyBoth(", start)
        body = self.text[start:end]
        self.assertIn("if (!text)", body)
        self.assertNotIn("vless://", body)

    def test_copy_feature_detects_clipboard(self) -> None:
        self.assertIn("const clipboard = navigator.clipboard;", self.text)
        self.assertIn("typeof clipboard.writeText === 'function'", self.text)
        self.assertIn("Promise.resolve(fallbackCopy(text))", self.text)

    def test_template_has_string_vless_guard(self) -> None:
        self.assertIn('("VLESS_ENABLED_PLACEHOLDER" === "true")', self.template)

    def test_hostname_used_for_authority_and_sni(self) -> None:
        self.assertNotIn("sni=${currentHost}", self.text)
        self.assertNotIn("currentHost", self.text)
        self.assertIn("location.hostname", self.text)
        self.assertIn("const uriHost = hostName.indexOf(':')", self.text)
        self.assertIn("&sni=${hostName}", self.text)
        self.assertIn("&host=${hostName}", self.text)
        self.assertIn("connectAddress || uriHost", self.text)

    def test_no_google_fonts(self) -> None:
        self.assertNotIn("fonts.googleapis.com", self.text)
        self.assertNotIn("fonts.gstatic.com", self.text)
        self.assertIn('"Noto Serif SC"', self.text)

    def test_ip_pool_is_manual_with_timeout(self) -> None:
        self.assertNotIn("try { fetchOptimizedIPs(); }", self.text)
        self.assertIn('onclick="fetchOptimizedIPs()"', self.text)
        self.assertIn("new AbortController()", self.text)
        self.assertIn("controller.abort(), 6000", self.text)

    def test_reduced_motion_block(self) -> None:
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.text)
        compact = self.text.replace(" ", "")
        self.assertIn("html{scroll-behavior:auto}", compact)
        self.assertIn(".reveal{opacity:1;transform:none}", compact)

    def test_intersection_observer_guard_and_noscript(self) -> None:
        self.assertIn(
            "if(!('IntersectionObserver' in window)){ showAll(); return; }",
            self.text,
        )
        self.assertIn("<noscript>", self.text)

    def test_particle_loop_restarts_without_double_loop(self) -> None:
        self.assertIn("window.__threeBody", self.text)
        self.assertIn("if(reduced || running || pageHidden()) return;", self.text)
        self.assertNotIn("document.hidden && rafId) cancelAnimationFrame", self.text)

    def test_mobile_menu_is_keyboard_reachable(self) -> None:
        self.assertIn('class="visually-hidden"', self.text)
        self.assertIn('role="button" tabindex="0" aria-expanded="false"', self.text)
        self.assertIn("e.key === 'Enter' || e.key === ' '", self.text)
        self.assertIn("toggle.checked = false; sync();", self.text)

    def test_contrast_fixes(self) -> None:
        self.assertIn(
            "#realPage .btn-apply { background: #0ea5e9; color: #06121f;",
            self.text,
        )
        self.assertIn("linear-gradient(92deg,#075985,#0369a1)", self.text)
        self.assertIn("linear-gradient(92deg,#065f46,#047857)", self.text)
        self.assertIn("linear-gradient(92deg,#4338ca,#0369a1)", self.text)

    def test_p3_accessibility_and_markup(self) -> None:
        self.assertIn('aria-live="polite"', self.text)
        self.assertIn('<canvas id="sim" aria-hidden="true">', self.text)
        self.assertIn('<label class="label" for="cfIpInput"', self.text)
        self.assertIn("createElement('button')", self.text)
        self.assertIn("Powered by sing-box", self.text)
        self.assertIn("Math.max(0,h)", self.text)
        self.assertIn("min-height:100svh", self.text)
        self.assertIn("'localhost'", self.text)

    def test_copy_both_reports_actual_count(self) -> None:
        self.assertIn("lines.length === 3", self.text)
        self.assertIn("三个链接已复制", self.text)
        self.assertIn("两个链接已复制", self.text)

    def test_page_and_template_identical(self) -> None:
        self.assertEqual(PAGE.read_bytes(), TEMPLATE.read_bytes())


class StartScriptTests(unittest.TestCase):
    """P0-3/P0-4 deployment contract for start.sh."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (ROOT / "start.sh").read_text(encoding="utf-8")

    def test_uses_python_injector_not_sed(self) -> None:
        self.assertIn("scripts/inject_page.py", self.text)
        self.assertNotIn("sed -i", self.text)

    def test_no_hardcoded_default_uuid(self) -> None:
        self.assertNotIn("a29738e5", self.text)
        self.assertIn("uuid.uuid4()", self.text)
        self.assertIn('elif [ -z "$VLESS_UUID" ]', self.text)

    def test_ip_and_country_probes_use_https_and_fail(self) -> None:
        self.assertIn("https://ifconfig.me/ip", self.text)
        self.assertIn("https://ipinfo.io/country", self.text)
        self.assertIn("--proto '=https'", self.text)
        self.assertIn("--fail", self.text)
        self.assertIn("^[A-Z]{2}$", self.text)

    def test_nezha_requires_sha256(self) -> None:
        self.assertIn("NEZHA_AGENT_SHA256", self.text)
        self.assertIn("sha256sum -c -", self.text)
        self.assertIn("chmod 700", self.text)
        self.assertIn("chmod 600", self.text)


if __name__ == "__main__":
    unittest.main()
