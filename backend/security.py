"""Small, dependency-free hardening for a public demo API.

  * per-client rate limits (sliding 60 s window): a general bucket and a tighter one for endpoints that can
    spend model tokens;
  * a request-body size cap (checked from Content-Length before anything is parsed);
  * conservative response headers.

State is in process memory, which matches the one-worker deployment. Behind a proxy the client address is the
first X-Forwarded-For hop (Render and most hosts set it).
"""
import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

MODEL_PATHS = ("/policy/compile", "/agent/chat", "/tests/generate", "/ci/run", "/bench/compile", "/models/refresh")
EXEMPT_PATHS = ("/health", "/healthz")
WINDOW_S = 60.0


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ[name]))
    except (KeyError, ValueError):
        return default


class RateLimiter:
    def __init__(self) -> None:
        self.enabled = os.getenv("RATE_LIMIT_DISABLED", "") != "1"
        self.general = _int_env("RATE_LIMIT_PER_MIN", 300)
        self.model = _int_env("RATE_LIMIT_MODEL_PER_MIN", 60)
        self.max_body = _int_env("MAX_BODY_BYTES", 64 * 1024)
        self._hits: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client: str, method: str, path: str) -> Optional[int]:
        """Return None if the request may proceed, else the number of seconds to wait."""
        if not self.enabled or method in ("OPTIONS", "HEAD") or path.endswith(EXEMPT_PATHS):
            return None
        costly = method != "GET" and any(path.endswith(p) for p in MODEL_PATHS)
        buckets = [("general", self.general)] + ([("model", self.model)] if costly else [])
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 5000:  # forget idle clients so memory cannot grow without bound
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < WINDOW_S}
            for name, limit in buckets:
                q = self._hits.setdefault((client, name), deque())
                while q and now - q[0] >= WINDOW_S:
                    q.popleft()
                if len(q) >= limit:
                    return max(1, int(WINDOW_S - (now - q[0])) + 1)
            for name, _ in buckets:
                self._hits[(client, name)].append(now)
        return None


def client_address(headers: Dict[str, str], peer: Optional[str]) -> str:
    forwarded = headers.get("x-forwarded-for", "")
    first = forwarded.split(",")[0].strip()
    return first or peer or "unknown"


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
}
