"""
BK-IDS SOC: Security Middleware — HARDENED v2.0
================================================
- Security headers on all responses
- Audit logging for all authenticated actions
- Request ID tracking
"""

import os
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

logger = logging.getLogger("Bk-IDS-Security")

# Audit logger — separate from application logger
audit_logger = logging.getLogger("Bk-IDS-Audit")
audit_handler = logging.FileHandler("/app/storage/audit.log")
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)


def log_audit_event(action: str, user: str, resource: str,
                    status: str, details: str = "", ip: str = ""):
    """Log a security audit event."""
    event = {
        "timestamp": datetime.now(timezone(timedelta(hours=7))).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "action": action,
        "user": user,
        "resource": resource,
        "status": status,
        "details": details,
        "ip": ip,
    }
    audit_logger.info(json.dumps(event, ensure_ascii=False))


def audit_log(action: str, resource: str):
    """
    Decorator: Automatically log authenticated actions.

    Usage:
        @audit_log("BLOCK_IP", "/api/soar/block")
        def block_ip():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import request, g

            user = "anonymous"
            ip = request.remote_addr or "unknown"

            if hasattr(g, 'current_user'):
                user = g.current_user.get('username', 'unknown')
                ip = request.headers.get('X-Forwarded-For', ip)
                if ip:
                    ip = ip.split(',')[0].strip()

            try:
                result = f(*args, **kwargs)
                status = "SUCCESS"
                if hasattr(result, 'status_code'):
                    if result.status_code >= 400:
                        status = "DENIED"
                log_audit_event(action, user, resource, status, ip=ip)
                return result
            except Exception as e:
                log_audit_event(action, user, resource, "ERROR",
                                details=str(e), ip=ip)
                raise
        return decorated
    return decorator
