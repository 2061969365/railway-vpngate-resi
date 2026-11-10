#!/usr/bin/env python3
"""Render the disguise page placeholders from deployment environment values.

This replaces the former ``sed -i`` injection in ``start.sh``.  The template is
read once, every value is validated, and the placeholders are replaced with
context-aware escaping: JavaScript string literals get ``json.dumps`` escaping,
HTML text nodes get ``html.escape``.  No shell is involved.

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Mapping

DEFAULT_TEMPLATE = "www/index.template.html"
DEFAULT_OUTPUT = "/app/www/index.html"

DEFAULT_REMARK = "Cloud_DynamicIP"
DEFAULT_DIRECT_PATH = "/ws-node"
DEFAULT_CHAIN_PATH = "/ws-chain"
DEFAULT_RESI_PATH = "/ws-resi"

PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$")
REMARK_PATTERN = re.compile(r"^[A-Za-z]{2}_[A-Za-z0-9:._-]{1,64}$")
FORBIDDEN_PATH_CHARS = frozenset("#\"'<>\r\n")

PLACEHOLDER_DIRECT = "VLESS_DIRECT_PATH_PLACEHOLDER"
PLACEHOLDER_CHAIN = "VLESS_CHAIN_PATH_PLACEHOLDER"
PLACEHOLDER_RESI = "RESI_PATH_PLACEHOLDER"
PLACEHOLDER_UUID = "UUID_PLACEHOLDER"
PLACEHOLDER_REMARK = "NODE_REMARK_PLACEHOLDER"
PLACEHOLDER_VLESS_ENABLED = "VLESS_ENABLED_PLACEHOLDER"

_SCRIPT_BLOCK = re.compile(r"(<script\b[^>]*>)(.*?)(</script\s*>)", re.DOTALL | re.IGNORECASE)


class InjectionError(ValueError):
    """A deployment value is not safe to inject into the page."""


def validate_uuid(value: str | None) -> str:
    """Return a canonical UUID, or "" when VLESS is explicitly disabled."""
    if not value:
        return ""
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InjectionError(f"VLESS_UUID is not a valid UUID: {value!r}") from exc


def validate_path(name: str, value: str | None, default: str) -> str:
    """Validate a WS path.  An unset/empty value falls back to its default."""
    if value is None or value == "":
        value = default
    if any(char in FORBIDDEN_PATH_CHARS for char in value):
        raise InjectionError(f"{name} contains a forbidden character: {value!r}")
    if not PATH_PATTERN.fullmatch(value):
        raise InjectionError(f"{name} does not match {PATH_PATTERN.pattern}: {value!r}")
    return value


def sanitize_remark(value: str | None) -> str:
    """Return a safe remark, falling back to Cloud_DynamicIP."""
    candidate = (value or "").strip()
    if REMARK_PATTERN.fullmatch(candidate):
        return candidate
    return DEFAULT_REMARK


def js_escape(value: str) -> str:
    """Escape a value for a double-quoted JavaScript string literal."""
    return json.dumps(value)[1:-1]


def html_escape(value: str) -> str:
    """Escape a value for an HTML text node."""
    return html.escape(value, quote=True)


def _replace(text: str, values: Mapping[str, str], escape) -> str:
    for placeholder, value in values.items():
        text = text.replace(placeholder, escape(value))
    return text


def render(template: str, env: Mapping[str, str]) -> str:
    """Inject validated environment values into the page template."""
    vless_uuid = validate_uuid(env.get("VLESS_UUID"))
    direct_path = validate_path("VLESS_DIRECT_PATH", env.get("VLESS_DIRECT_PATH"), DEFAULT_DIRECT_PATH)
    chain_path = validate_path("VLESS_CHAIN_PATH", env.get("VLESS_CHAIN_PATH"), DEFAULT_CHAIN_PATH)
    resi_path = validate_path("RESI_PATH", env.get("RESI_PATH"), DEFAULT_RESI_PATH)
    remark = sanitize_remark(env.get("NODE_REMARK"))

    js_values = {
        PLACEHOLDER_UUID: vless_uuid,
        PLACEHOLDER_DIRECT: direct_path,
        PLACEHOLDER_CHAIN: chain_path,
        PLACEHOLDER_REMARK: remark,
    }
    js_values[PLACEHOLDER_RESI] = resi_path if vless_uuid else ""
    html_values = {
        PLACEHOLDER_DIRECT: direct_path,
        PLACEHOLDER_CHAIN: chain_path,
        PLACEHOLDER_RESI: resi_path if vless_uuid else "",
    }

    parts: list[str] = []
    position = 0
    for match in _SCRIPT_BLOCK.finditer(template):
        parts.append(_replace(template[position:match.start()], html_values, html_escape))
        parts.append(match.group(1))
        parts.append(_replace(match.group(2), js_values, js_escape))
        parts.append(match.group(3))
        position = match.end()
    parts.append(_replace(template[position:], html_values, html_escape))
    rendered = "".join(parts)
    # The template compares the token as a string, so an unrendered page stays
    # safely disabled instead of throwing a ReferenceError.  Replace the token
    # only after every other substitution so injected values cannot feed back
    # into it.
    rendered = rendered.replace(
        PLACEHOLDER_VLESS_ENABLED, "true" if vless_uuid else "false"
    )
    residual = [
        token
        for token in (
            PLACEHOLDER_UUID,
            PLACEHOLDER_DIRECT,
            PLACEHOLDER_CHAIN,
            PLACEHOLDER_RESI,
            PLACEHOLDER_REMARK,
            PLACEHOLDER_VLESS_ENABLED,
        )
        if token in rendered
    ]
    if residual:
        raise InjectionError(
            "placeholders left after render: " + ", ".join(residual)
        )
    return rendered


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", default=DEFAULT_TEMPLATE, help="page template to read")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="rendered page to write")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        template = Path(args.template).read_text(encoding="utf-8")
        rendered = render(template, os.environ)
    except InjectionError as exc:
        print(f"[inject_page] refusing to render: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[inject_page] cannot read template {args.template}: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        print(f"[inject_page] cannot write {args.output}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
