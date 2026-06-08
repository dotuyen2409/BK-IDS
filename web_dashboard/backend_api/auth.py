"""
BK-IDS SOC: RBAC & JWT Authentication Middleware — HARDENED v2.0
================================================================
Zero Trust: Every request must be authenticated and authorized.
OWASP Compliant: JWT with fixed secret, constant-time comparison,
                 safe error messages, audit logging.

Roles:
- analyst: Read-only access (view alerts, dashboards)
- admin: Full access (block/unblock IPs, manage rules, SOAR actions)

Usage:
    from auth import require_jwt_auth, require_role, require_permission, sanitize_ip

    @app.route('/api/soar/unblock', methods=['POST'])
    @require_jwt_auth
    @require_role('admin')
    def soar_unblock():
        ...
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("Bk-IDS-Auth")

# ========================================================================
# CONFIGURATION — FAIL SECRET: REFUSE TO START WITHOUT JWT_SECRET_KEY
# ========================================================================
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    # CRITICAL: Do NOT auto-generate. The app MUST fail if secret is missing.
    # This prevents token invalidation on every restart and ensures
    # operators explicitly set a persistent secret.
    raise EnvironmentError(
        "FATAL: JWT_SECRET_KEY environment variable is not set. "
        "Generate one: python3 -c \"import secrets; print(secrets.token_hex(64))\" "
        "and set it in your .env file or docker-compose environment."
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "8"))
JWT_REFRESH_DAYS = int(os.environ.get("JWT_REFRESH_DAYS", "7"))

# ========================================================================
# INPUT VALIDATION HELPERS
# ========================================================================

# Strict IPv4 regex — each octet 0-255
_IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def sanitize_ip(ip_string: str) -> Optional[str]:
    """
    Validate IPv4 address strictly.
    Returns the IP string if valid, None otherwise.
    Prevents command injection via IP parameters.
    """
    if not ip_string or not isinstance(ip_string, str):
        return None
    ip_string = ip_string.strip()
    if not _IPV4_REGEX.match(ip_string):
        return None
    # Double-check with standard library
    try:
        parts = ip_string.split(".")
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return None
        return ip_string
    except (ValueError, AttributeError):
        return None


def sanitize_sid(sid: Any) -> Optional[int]:
    """Validate Snort SID — must be positive integer."""
    try:
        val = int(sid)
        if val > 0:
            return val
    except (ValueError, TypeError):
        pass
    return None


def sanitize_limit(limit: Any, default: int = 100, max_val: int = 1000) -> int:
    """Validate pagination limit."""
    try:
        val = int(limit)
        if 1 <= val <= max_val:
            return val
    except (ValueError, TypeError):
        pass
    return default


def sanitize_offset(offset: Any, default: int = 0) -> int:
    """Validate pagination offset."""
    try:
        val = int(offset)
        if val >= 0:
            return val
    except (ValueError, TypeError):
        pass
    return default


# ========================================================================
# ROLES & PERMISSIONS
# ========================================================================

class Role(Enum):
    ANALYST = "analyst"
    ADMIN = "admin"


class Permission(Enum):
    READ_ALERTS = "read:alerts"
    READ_DASHBOARD = "read:dashboard"
    READ_RULES = "read:rules"
    WRITE_RULES = "write:rules"
    BLOCK_IP = "block:ip"
    UNBLOCK_IP = "unblock:ip"
    MANAGE_USERS = "manage:users"
    MANAGE_SOAR = "manage:soar"
    DOWNLOAD_PCAP = "download:pcap"
    SYSTEM_CONFIG = "system:config"


ROLE_PERMISSIONS: Dict[Role, List[Permission]] = {
    Role.ANALYST: [
        Permission.READ_ALERTS,
        Permission.READ_DASHBOARD,
        Permission.READ_RULES,
        Permission.DOWNLOAD_PCAP,
    ],
    Role.ADMIN: [
        Permission.READ_ALERTS,
        Permission.READ_DASHBOARD,
        Permission.READ_RULES,
        Permission.WRITE_RULES,
        Permission.BLOCK_IP,
        Permission.UNBLOCK_IP,
        Permission.MANAGE_USERS,
        Permission.MANAGE_SOAR,
        Permission.DOWNLOAD_PCAP,
        Permission.SYSTEM_CONFIG,
    ],
}


# ========================================================================
# JWT IMPLEMENTATION (no external dependency)
# ========================================================================

def _base64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    import base64
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _hmac_sha256(key: str, message: str) -> str:
    return hmac.new(
        key.encode("utf-8"),  # type: ignore[arg-type]
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def create_token(user_id: str, username: str, role: Role,
                 token_type: str = "access") -> str:
    now = time.time()
    if token_type == "access":
        exp = now + (JWT_EXPIRY_HOURS * 3600)
    else:
        exp = now + (JWT_REFRESH_DAYS * 86400)

    header = json.dumps({"alg": JWT_ALGORITHM, "typ": "JWT"}, separators=(",", ":"))
    payload = json.dumps({
        "sub": user_id,
        "username": username,
        "role": role.value,
        "type": token_type,
        "iat": int(now),
        "exp": int(exp),
        "jti": secrets.token_hex(16),
    }, separators=(",", ":"))

    header_b64 = _base64url_encode(header.encode("utf-8"))
    payload_b64 = _base64url_encode(payload.encode("utf-8"))
    signature = _hmac_sha256(JWT_SECRET_KEY, "{}.{}".format(header_b64, payload_b64))

    return "{}.{}.{}".format(header_b64, payload_b64, signature)


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token. Returns None on any failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature = parts

        # Constant-time signature comparison (prevents timing attacks)
        expected_sig = _hmac_sha256(JWT_SECRET_KEY, "{}.{}".format(header_b64, payload_b64))
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning("[AUTH] Invalid token signature")
            return None

        payload = json.loads(_base64url_decode(payload_b64))

        # Check expiry
        if payload.get("exp", 0) < time.time():
            logger.info("[AUTH] Token expired for user=%s", payload.get("username"))
            return None

        return payload

    except Exception as e:
        logger.error("[AUTH] Token verification error: %s", str(e))
        return None


# ========================================================================
# USER STORE (file-persisted, PBKDF2 hashed passwords)
# ========================================================================

class UserStore:
    def __init__(self, store_file: str = "/app/storage/auth_users.json") -> None:
        self.store_file = store_file
        self._users: Dict[str, Dict[str, Any]] = {}
        self._load()
        self._ensure_admin()

    def _load(self) -> None:
        try:
            if os.path.exists(self.store_file):
                with open(self.store_file, "r") as f:
                    self._users = json.load(f)
        except Exception as e:
            logger.error("[AUTH] Load error: %s", str(e))

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.store_file), exist_ok=True)
            with open(self.store_file, "w") as f:
                json.dump(self._users, f, indent=2)
        except Exception as e:
            logger.error("[AUTH] Save error: %s", str(e))

    def _hash_password(self, password: str,
                       salt: Optional[str] = None) -> Tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        )
        return pw_hash.hex(), salt

    def _ensure_admin(self) -> None:
        if not self._users:
            # SECURITY: Create admin ONLY if INITIAL_ADMIN_PASSWORD env var is set.
            # This prevents hardcoded credentials in source code.
            initial_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
            if not initial_password:
                logger.critical(
                    "[AUTH] NO USERS EXIST and INITIAL_ADMIN_PASSWORD not set. "
                    "Set INITIAL_ADMIN_PASSWORD in .env to create the first admin, "
                    "or use POST /api/auth/users (after bootstrap)."
                )
                return

            if len(initial_password) < 12:
                logger.critical(
                    "[AUTH] INITIAL_ADMIN_PASSWORD must be at least 12 characters. "
                    "Refusing to create admin with weak password."
                )
                return

            pw_hash, salt = self._hash_password(initial_password)
            self._users["admin"] = {
                "id": "usr_admin_001",
                "username": "admin",
                "password_hash": pw_hash,
                "salt": salt,
                "role": Role.ADMIN.value,
                "created_at": datetime.now(timezone(timedelta(hours=7))).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "is_active": True,
            }
            self._save()
            logger.warning(
                "[AUTH] Initial admin created via INITIAL_ADMIN_PASSWORD. "
                "Change password after first login."
            )

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = self._users.get(username)
        if not user or not user.get("is_active", False):
            return None
        pw_hash, _ = self._hash_password(password, user["salt"])
        if hmac.compare_digest(pw_hash, user["password_hash"]):
            return {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
        return None

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        user = self._users.get(username)
        if user:
            return {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "is_active": user.get("is_active", True),
                "created_at": user.get("created_at", ""),
            }
        return None

    def list_users(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "is_active": u.get("is_active", True),
                "created_at": u.get("created_at", ""),
            }
            for u in self._users.values()
        ]

    def create_user(self, username: str, password: str,
                    role: Role) -> Optional[Dict[str, Any]]:
        if username in self._users:
            return None
        pw_hash, salt = self._hash_password(password)
        user_id = "usr_{}_{}".format(role.value, secrets.token_hex(4))
        self._users[username] = {
            "id": user_id,
            "username": username,
            "password_hash": pw_hash,
            "salt": salt,
            "role": role.value,
            "created_at": datetime.now(timezone(timedelta(hours=7))).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "is_active": True,
        }
        self._save()
        return self.get_user(username)


# ========================================================================
# SINGLETON
# ========================================================================
_user_store: Optional[UserStore] = None


def get_user_store() -> UserStore:
    global _user_store
    if _user_store is None:
        _user_store = UserStore()
    return _user_store


# ========================================================================
# FLASK DECORATORS — ZERO TRUST
# ========================================================================

def require_jwt_auth(f):
    """
    Decorator: Require valid JWT token for ALL protected endpoints.
    Adds g.current_user with decoded token payload.
    Returns 401 if no valid token.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import request, jsonify, g

        # Skip auth for explicitly public endpoints
        public_endpoints = {'auth_login', 'auth_refresh', 'health'}
        if f.__name__ in public_endpoints:
            return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("[AUTH] Missing/invalid Authorization header from %s",
                           request.remote_addr)
            return jsonify({
                "status": "error",
                "message": "Authentication required"
            }), 401

        token = auth_header[7:]
        payload = verify_token(token)

        if not payload:
            logger.warning("[AUTH] Invalid/expired token from %s",
                           request.remote_addr)
            return jsonify({
                "status": "error",
                "message": "Invalid or expired token"
            }), 401

        if payload.get("type") != "access":
            return jsonify({
                "status": "error",
                "message": "Invalid token type"
            }), 401

        g.current_user = payload
        return f(*args, **kwargs)

    return decorated


def require_role(*roles):
    """Decorator: Require specific role(s). Must be used after @require_jwt_auth."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import jsonify, g

            if not hasattr(g, "current_user"):
                return jsonify({
                    "status": "error",
                    "message": "Authentication required"
                }), 401

            user_role = g.current_user.get("role", "")
            allowed = [r if isinstance(r, str) else r.value for r in roles]
            if user_role not in allowed:
                logger.warning(
                    "[AUTH] Role '%s' denied access to %s (required: %s) from %s",
                    user_role, f.__name__, allowed, "unknown"
                )
                return jsonify({
                    "status": "error",
                    "message": "Insufficient permissions"
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission: Permission):
    """Decorator: Require specific permission. Must be used after @require_jwt_auth."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import jsonify, g

            if not hasattr(g, "current_user"):
                return jsonify({
                    "status": "error",
                    "message": "Authentication required"
                }), 401

            user_role_str = g.current_user.get("role", "analyst")
            try:
                user_role = Role(user_role_str)
            except ValueError:
                return jsonify({
                    "status": "error",
                    "message": "Invalid role"
                }), 403

            if permission not in ROLE_PERMISSIONS.get(user_role, []):
                return jsonify({
                    "status": "error",
                    "message": "Permission denied"
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator
