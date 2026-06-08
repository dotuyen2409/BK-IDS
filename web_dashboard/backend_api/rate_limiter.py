"""
BK-IDS SOC: Rate Limiter — HARDENED v2.0
==========================================
In-memory rate limiter for API endpoints.
Prevents brute force and DoS attacks.
"""

import time
import threading
import logging
from collections import defaultdict
from functools import wraps
from typing import Dict, List, Tuple

logger = logging.getLogger("Bk-IDS-RateLimiter")


class RateLimiter:
    """
    Sliding window rate limiter.
    Thread-safe, in-memory (suitable for single-container deployment).
    """

    def __init__(self):
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if a request is allowed under the rate limit.

        Args:
            key: Identifier (e.g., IP + endpoint).
            max_requests: Maximum requests allowed in the window.
            window_seconds: Time window in seconds.

        Returns:
            (allowed: bool, remaining: int)
        """
        now = time.time()
        with self._lock:
            # Clean old entries
            self._requests[key] = [
                t for t in self._requests[key]
                if t > now - window_seconds
            ]

            if len(self._requests[key]) >= max_requests:
                remaining = 0
                return False, remaining

            self._requests[key].append(now)
            remaining = max_requests - len(self._requests[key])
            return True, remaining


# Global rate limiter instance
_limiter = RateLimiter()


def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Decorator: Rate limit an endpoint by client IP.

    Usage:
        @rate_limit(max_requests=5, window_seconds=60)
        def login():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import request, jsonify

            # Get client IP (respecting X-Forwarded-For from proxy)
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(",")[0].strip()

            key = "{}:{}".format(client_ip, f.__name__)
            allowed, remaining = _limiter.is_allowed(key, max_requests, window_seconds)

            if not allowed:
                logger.warning("[RATE_LIMIT] Blocked %s on %s (limit: %d/%ds)",
                               client_ip, f.__name__, max_requests, window_seconds)
                return jsonify({
                    "status": "error",
                    "message": "Rate limit exceeded. Try again later."
                }), 429

            return f(*args, **kwargs)
        return decorated
    return decorator
