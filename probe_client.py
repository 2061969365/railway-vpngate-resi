"""Fail-open client for the loopback vpngate-probe sidecar.

Standard library only. Every failure (transport error, timeout, 401, 503,
malformed JSON, non-ok payload) returns ``None`` and feeds a short circuit
breaker, so callers can fall back to the Python implementation without a
sidecar outage ever leaking an exception into the manager.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:39001"
DEFAULT_DELAY_URL = "https://www.gstatic.com/generate_204"

_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})


class _Breaker:
    """Tiny consecutive-failure circuit breaker."""

    def __init__(self, threshold: int = 2, cooldown: float = 5.0) -> None:
        self._threshold = max(1, int(threshold))
        self._cooldown = max(0.0, float(cooldown))
        self._failures = 0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            return time.monotonic() >= self._open_until

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_until = 0.0

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._open_until = time.monotonic() + self._cooldown
                self._failures = 0


class ProbeClient:
    """HTTP client for the vpngate-probe sidecar."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: str = "",
        *,
        timeout: float = 2.0,
        breaker_threshold: int = 2,
        breaker_cooldown: float = 5.0,
    ) -> None:
        base = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "http://" + base
        self.base_url = base
        self.token = (token or "").strip()
        self.timeout = max(0.1, float(timeout))
        self._breaker = _Breaker(breaker_threshold, breaker_cooldown)

    @classmethod
    def from_env(cls) -> "ProbeClient | None":
        """Build a client from PROBE_* env vars, or None when disabled."""
        try:
            service = os.environ.get("PROBE_SERVICE", "").strip().lower()
            if service in _DISABLED_VALUES:
                return None
            listen = os.environ.get("PROBE_LISTEN", "").strip() or "127.0.0.1:39001"
            token = os.environ.get("PROBE_TOKEN", "").strip()
            return cls(listen, token)
        except Exception:
            return None

    def health(self) -> dict | None:
        try:
            body = self._request("GET", "/v1/health", timeout=self.timeout)
            if not body or body.get("ok") is not True:
                return None
            return body
        except Exception:
            return None

    def exit_ip(
        self,
        host: str,
        port: int,
        username: str = "",
        password: str = "",
        timeout_ms: int = 8000,
    ) -> dict | None:
        try:
            payload = {
                "host": host,
                "port": int(port),
                "username": username or "",
                "password": password or "",
                "timeout_ms": int(timeout_ms),
            }
            request_timeout = max(1.0, int(timeout_ms) / 1000.0 + 2.0)
            body = self._request("POST", "/v1/exit", payload, timeout=request_timeout)
            if not body or body.get("ok") is not True:
                return None
            exit_ip = body.get("exit_ip")
            if not isinstance(exit_ip, str) or not exit_ip:
                return None
            return body
        except Exception:
            return None

    def delays(
        self,
        tags,
        url: str = DEFAULT_DELAY_URL,
        timeout_ms: int = 5000,
    ) -> dict[str, int] | None:
        try:
            tags = [str(tag) for tag in (tags or [])]
            payload = {
                "tags": tags,
                "url": url or DEFAULT_DELAY_URL,
                "timeout_ms": int(timeout_ms),
            }
            request_timeout = max(1.0, int(timeout_ms) / 1000.0 + 2.0)
            body = self._request("POST", "/v1/delay", payload, timeout=request_timeout)
            if not body or body.get("ok") is not True:
                return None
            results = body.get("results")
            if not isinstance(results, list):
                return None
            alive: dict[str, int] = {}
            for result in results:
                if not isinstance(result, dict) or result.get("alive") is not True:
                    continue
                tag = result.get("tag")
                ms = result.get("ms")
                if isinstance(tag, str) and isinstance(ms, int) and not isinstance(ms, bool):
                    alive[tag] = ms
            return alive
        except Exception:
            return None

    def _request(self, method: str, path: str, payload: dict | None = None, timeout: float | None = None):
        if not self._breaker.allow():
            return None
        data = None
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read(1 << 20)
        except Exception:
            self._breaker.failure()
            return None
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            self._breaker.failure()
            return None
        if not isinstance(body, dict):
            self._breaker.failure()
            return None
        self._breaker.success()
        return body
