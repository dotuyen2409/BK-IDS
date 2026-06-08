"""
BK-IDS SOC: SOAR (Security Orchestration, Automation & Response) Engine
=========================================================================
Sprint 2 — Phase 2: Automated Incident Response

Capabilities:
- Receive CRITICAL alerts via webhook from AI analyzer
- Auto-block attacking IPs via iptables (host-level)
- Auto-update Nginx WAF deny rules
- Push 'Auto-Blocked by SOAR' audit log to database
- Rate limiting to prevent SOAR loop attacks
- Whitelist protection (never block whitelisted IPs)

Architecture:
    AI Analyzer → SOAR Webhook → SOAR Engine → iptables / Nginx / DB
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
import ipaddress

# ========================================================================
# IP VALIDATION — prevents command injection
# ========================================================================
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def _validate_ip_safe(ip_str):
    """Validate IPv4 address — returns cleaned IP or None."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    ip_str = ip_str.strip()
    if not _IPV4_RE.match(ip_str):
        return None
    try:
        parts = ip_str.split(".")
        for p in parts:
            num = int(p)
            if num < 0 or num > 255:
                return None
        return ip_str
    except (ValueError, AttributeError):
        return None

def load_whitelist_from_local_rules():
    """
    Parse pass rules in local.rules to extract whitelisted IPs/CIDRs.
    Also include default whitelisted IPs from environment.
    """
    whitelist = {
        "127.0.0.1",
        "0.0.0.0",
        "192.168.13.1",
        "192.168.13.128",
        "192.168.13.129"
    }
    
    # Add environment whitelist
    wl_env = os.environ.get("WHITELIST_IPS", "")
    if wl_env:
        for ip in wl_env.split(','):
            ip = ip.strip()
            if ip:
                whitelist.add(ip)
                
    # Parse local.rules
    rules_path = "/app/core_engine/local.rules"
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match pattern: pass <proto> <src> <sport> <dir> <dst> <dport>
                    # Example: pass ip 192.168.13.1 any <> any any (...)
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].lower() == "pass":
                        src = parts[2]
                        if src.lower() != "any":
                            whitelist.add(src)
                        if len(parts) >= 6:
                            direction = parts[4]
                            dst = parts[5]
                            if direction == "<>" and dst.lower() != "any":
                                whitelist.add(dst)
        except Exception as e:
            logging.getLogger("Bk-IDS-Whitelist").warning(f"Error loading local.rules whitelist: {e}")
            
    return whitelist

def _is_ip_whitelisted(ip_str, whitelist_rules):
    """
    Check if ip_str belongs to any whitelisted IP or CIDR network.
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        for wl in whitelist_rules:
            wl = wl.strip()
            if not wl or wl.lower() == "any":
                continue
            try:
                if '/' in wl:
                    net = ipaddress.ip_network(wl, strict=False)
                    if ip in net:
                        return True
                else:
                    wl_ip = ipaddress.ip_address(wl)
                    if ip == wl_ip:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def _default_whitelist_ips():
    return load_whitelist_from_local_rules()


def _safe_iptables_block(ip):
    """Block IP via iptables — safe subprocess, no shell=True."""
    if not _validate_ip_safe(ip):
        return False
    if _is_ip_whitelisted(ip, _default_whitelist_ips()):
        logging.getLogger("Bk-IDS-SOAR").warning("iptables: refused to block whitelisted IP %s", ip)
        return False
    try:
        # Check if rule already exists (idempotent — prevent duplicates)
        check = subprocess.run(
            ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        if check.returncode == 0:
            logging.getLogger("Bk-IDS-SOAR").debug("iptables: rule already exists for %s, skipping", ip)
            return True

        subprocess.run(
            ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        subprocess.run(
            ['iptables', '-I', 'DOCKER-USER', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        subprocess.run(
            ['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        return True
    except Exception as e:
        logging.getLogger("Bk-IDS-SOAR").error("iptables block error: %s", str(e))
        return False


def _safe_iptables_unblock(ip):
    """Unblock IP via iptables — safe subprocess, no shell=True."""
    if not _validate_ip_safe(ip):
        return False
    try:
        removed = False
        commands = [
            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            ['iptables', '-D', 'DOCKER-USER', '-s', ip, '-j', 'DROP'],
            ['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-s', ip, '-j', 'DROP'],
        ]
        for cmd in commands:
            for _ in range(10):
                result = subprocess.run(cmd, capture_output=True, timeout=5, shell=False)
                if result.returncode != 0:
                    break
                removed = True
        return removed
    except Exception as e:
        logging.getLogger("Bk-IDS-SOAR").error("iptables unblock error: %s", str(e))
        return False
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("Bk-IDS-SOAR")

# ========================================================================
# CONFIGURATION
# ========================================================================
SOAR_ENABLED = os.environ.get("SOAR_ENABLED", "true").lower() == "true"
SOAR_AUTO_BLOCK = os.environ.get("SOAR_AUTO_BLOCK", "true").lower() == "true"
SOAR_BAN_DURATION = int(os.environ.get("SOAR_BAN_DURATION", "3600"))
SOAR_MAX_BLOCKS_PER_MINUTE = int(os.environ.get("SOAR_MAX_BLOCKS_PER_MINUTE", "10"))
SOAR_COOLDOWN_SEC = int(os.environ.get("SOAR_COOLDOWN_SEC", "300"))
SOAR_NGINX_DENY_FILE = os.environ.get("SOAR_NGINX_DENY_FILE", "/etc/nginx/conf.d/blocked_ips.conf")
SOAR_AUDIT_LOG_FILE = os.environ.get("SOAR_AUDIT_LOG_FILE", "/app/storage/soar_audit.jsonl")


class SoarAction(Enum):
    """SOAR action types for audit logging."""
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    NGINX_DENY = "NGINX_DENY"
    ALERT_ONLY = "ALERT_ONLY"
    RATE_LIMITED = "RATE_LIMITED"
    WHITELISTED = "WHITELISTED"


class SoarAuditEntry:
    """Represents a single SOAR audit log entry."""

    def __init__(
        self,
        action: SoarAction,
        ip: str,
        reason: str,
        source: str,
        success: bool,
        details: str = "",
    ) -> None:
        self.timestamp = datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")
        self.action = action.value
        self.ip = ip
        self.reason = reason
        self.source = source
        self.success = success
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "ip": self.ip,
            "reason": self.reason,
            "source": self.source,
            "success": self.success,
            "details": self.details,
        }


class SoarEngine:
    """
    SOAR Engine for automated incident response.

    Handles:
    - IP blocking via iptables
    - Nginx WAF deny rule management
    - Audit logging to file and database
    - Rate limiting and cooldown protection
    """

    def __init__(
        self,
        whitelist_ips: Optional[Set[str]] = None,
        ban_duration: int = SOAR_BAN_DURATION,
        auto_block: bool = SOAR_AUTO_BLOCK,
    ) -> None:
        self.ban_duration = ban_duration
        self.auto_block = auto_block
        self.whitelist_ips = whitelist_ips or _default_whitelist_ips()

        # Rate limiting
        self._block_timestamps: List[float] = []
        self._cooldown_cache: Dict[str, float] = {}
        self._active_blocks: Dict[str, float] = {}  # ip -> unban_timestamp
        self._lock = threading.Lock()

        # Ensure audit log directory exists
        os.makedirs(os.path.dirname(SOAR_AUDIT_LOG_FILE), exist_ok=True)

    def process_critical_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a CRITICAL alert from the AI analyzer.

        This is the main entry point called by the SOAR webhook.

        Args:
            alert: Alert dictionary containing at least:
                - src_ip: Source IP address
                - attack_type: Type of attack
                - severity: Alert severity (should be CRITICAL)
                - mitre_technique_id: MITRE technique ID
                - confidence: AI confidence score

        Returns:
            SOAR response dictionary:
            {
                "action": str,       # Action taken
                "blocked": bool,     # Whether IP was blocked
                "ip": str,           # Target IP
                "reason": str,       # Human-readable reason
            }
        """
        result = {
            "action": SoarAction.ALERT_ONLY.value,
            "blocked": False,
            "ip": "",
            "reason": "No action taken",
        }

        # Validate alert
        src_ip = alert.get("src_ip", "")
        severity = alert.get("severity", "")

        if not src_ip:
            result["reason"] = "Missing src_ip in alert"
            return result

        if severity != "CRITICAL":
            result["reason"] = "Severity is {}, not CRITICAL".format(severity)
            return result

        # Validate IP format
        if not self._is_valid_ip(src_ip):
            result["reason"] = "Invalid IP format: {}".format(src_ip)
            return result

        # Check whitelist (reload dynamically to reflect local.rules changes)
        self.whitelist_ips = load_whitelist_from_local_rules()
        if _is_ip_whitelisted(src_ip, self.whitelist_ips):
            self._audit(SoarAction.WHITELISTED, src_ip, "IP is whitelisted", "SOAR", True)
            result["action"] = SoarAction.WHITELISTED.value
            result["ip"] = src_ip
            result["reason"] = "IP is whitelisted, not blocked"
            return result

        # Check cooldown
        if self._is_in_cooldown(src_ip):
            self._audit(SoarAction.RATE_LIMITED, src_ip, "Cooldown active", "SOAR", True)
            result["action"] = SoarAction.RATE_LIMITED.value
            result["ip"] = src_ip
            result["reason"] = "IP is in cooldown period"
            return result

        # Check rate limit
        if self._is_rate_limited():
            self._audit(SoarAction.RATE_LIMITED, src_ip, "Global rate limit exceeded", "SOAR", False)
            result["action"] = SoarAction.RATE_LIMITED.value
            result["ip"] = src_ip
            result["reason"] = "SOAR rate limit exceeded"
            return result

        # Execute block
        if self.auto_block:
            block_result = self._block_ip(src_ip, alert)
            result["action"] = SoarAction.BLOCK_IP.value
            result["blocked"] = block_result
            result["ip"] = src_ip
            result["reason"] = (
                "Auto-blocked by SOAR: {} (confidence={})".format(
                    alert.get("attack_type", "Unknown"),
                    alert.get("confidence", 0),
                )
            )

            # Also update Nginx WAF
            if block_result:
                self._update_nginx_deny(src_ip, alert)
        else:
            result["action"] = SoarAction.ALERT_ONLY.value
            result["ip"] = src_ip
            result["reason"] = "Auto-block disabled, alert only"

        return result

    def _block_ip(self, ip: str, alert: Dict[str, Any]) -> bool:
        """Block an IP address using iptables — safe subprocess."""
        try:
            with self._lock:
                if ip in self._active_blocks:
                    if self._active_blocks[ip] > time.time():
                        return True
                    else:
                        del self._active_blocks[ip]

            # Use safe iptables block (no shell=True, IP validated)
            success = _safe_iptables_block(ip)
            if not success:
                return False

            # Schedule auto-unban
            with self._lock:
                self._active_blocks[ip] = time.time() + self.ban_duration
                self._cooldown_cache[ip] = time.time()
                self._block_timestamps.append(time.time())
                cutoff = time.time() - 60
                self._block_timestamps = [t for t in self._block_timestamps if t > cutoff]

            self._audit(
                SoarAction.BLOCK_IP, ip,
                "Auto-blocked: {}".format(alert.get("attack_type", "Unknown")),
                "SOAR", True,
                "duration={}s, confidence={}".format(self.ban_duration, alert.get("confidence", 0)),
            )

            timer = threading.Timer(self.ban_duration, self._unblock_ip, args=[ip])
            timer.daemon = True
            timer.start()

            logger.critical(
                "[SOAR] AUTO-BLOCKED IP %s | Attack: %s | Duration: %s | Confidence: %s",
                ip, alert.get("attack_type", "Unknown"), self.ban_duration, alert.get("confidence", 0)
            )
            return True

        except Exception as e:
            logger.error("[SOAR] Block error for %s: %s", ip, str(e))
            self._audit(SoarAction.BLOCK_IP, ip, "Block failed", "SOAR", False, str(e))
            return False

    def _unblock_ip(self, ip: str) -> None:
        """Unblock an IP address (auto-expiry) — safe subprocess."""
        try:
            _safe_iptables_unblock(ip)

            with self._lock:
                self._active_blocks.pop(ip, None)

            self._remove_nginx_deny(ip)
            self._audit(SoarAction.UNBLOCK_IP, ip, "Auto-unblocked (expired)", "SOAR", True)
            logger.info("[SOAR] AUTO-UNBLOCKED IP %s (ban expired)", ip)

        except Exception as e:
            logger.error("[SOAR] Unblock error for %s: %s", ip, str(e))

    def _update_nginx_deny(self, ip: str, alert: Dict[str, Any]) -> bool:
        """
        Add IP to Nginx WAF deny list.

        Creates/updates /etc/nginx/conf.d/blocked_ips.conf with deny directives.
        Then reloads Nginx gracefully.

        Args:
            ip: IP address to deny.
            alert: Alert context.

        Returns:
            True if successful.
        """
        try:
            deny_line = "deny {};\n".format(ip)

            # Read existing entries
            existing_lines: Set[str] = set()
            if os.path.exists(SOAR_NGINX_DENY_FILE):
                with open(SOAR_NGINX_DENY_FILE, "r") as f:
                    existing_lines = set(f.readlines())

            # Add if not already present
            if deny_line not in existing_lines:
                with open(SOAR_NGINX_DENY_FILE, "a") as f:
                    f.write(deny_line)

            # Reload Nginx gracefully
            subprocess.run(
                ["nginx", "-s", "reload"],
                capture_output=True, timeout=10,
            )

            self._audit(
                SoarAction.NGINX_DENY, ip,
                "Added to Nginx WAF deny list",
                "SOAR", True,
            )

            logger.info("[SOAR] Nginx WAF updated: deny {}".format(ip))
            return True

        except Exception as e:
            logger.error("[SOAR] Nginx deny error for {}: {}".format(ip, e))
            self._audit(SoarAction.NGINX_DENY, ip, "Nginx deny failed", "SOAR", False, str(e))
            return False

    def _remove_nginx_deny(self, ip: str) -> None:
        """Remove IP from Nginx WAF deny list."""
        try:
            if not os.path.exists(SOAR_NGINX_DENY_FILE):
                return

            with open(SOAR_NGINX_DENY_FILE, "r") as f:
                lines = f.readlines()

            deny_line = "deny {};\n".format(ip)
            new_lines = [l for l in lines if l != deny_line]

            with open(SOAR_NGINX_DENY_FILE, "w") as f:
                f.writelines(new_lines)

            subprocess.run(
                ["nginx", "-s", "reload"],
                capture_output=True, timeout=10,
            )

            logger.info("[SOAR] Nginx WAF updated: removed {}".format(ip))

        except Exception as e:
            logger.error("[SOAR] Nginx remove error for {}: {}".format(ip, e))

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))

    def _is_in_cooldown(self, ip: str) -> bool:
        """Check if IP is in cooldown period."""
        with self._lock:
            last_block = self._cooldown_cache.get(ip, 0)
            return (time.time() - last_block) < SOAR_COOLDOWN_SEC

    def _is_rate_limited(self) -> bool:
        """Check if global block rate limit is exceeded."""
        with self._lock:
            cutoff = time.time() - 60
            self._block_timestamps = [t for t in self._block_timestamps if t > cutoff]
            return len(self._block_timestamps) >= SOAR_MAX_BLOCKS_PER_MINUTE

    def _audit(self, action: SoarAction, ip: str, reason: str, source: str, success: bool, details: str = "") -> None:
        """Write audit log entry."""
        entry = SoarAuditEntry(action, ip, reason, source, success, details)

        try:
            with open(SOAR_AUDIT_LOG_FILE, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            logger.error("[SOAR] Audit log error: {}".format(e))

    def get_active_blocks(self) -> Dict[str, str]:
        """Get currently active blocks with remaining time."""
        now = time.time()
        result = {}
        with self._lock:
            for ip, unban_time in list(self._active_blocks.items()):
                remaining = int(unban_time - now)
                if remaining > 0:
                    result[ip] = str(remaining)
                else:
                    del self._active_blocks[ip]
        return result

    def manual_unblock(self, ip: str) -> bool:
        """Manually unblock an IP (called from API)."""
        self._unblock_ip(ip)
        return True


# ========================================================================
# SINGLETON INSTANCE
# ========================================================================
_soar_engine_singleton: Optional[SoarEngine] = None


def get_soar_engine() -> SoarEngine:
    """
    Get or create the singleton SOAR engine instance.

    Returns:
        SoarEngine instance.
    """
    global _soar_engine_singleton
    if _soar_engine_singleton is None:
        # Load whitelist from environment
        whitelist = _default_whitelist_ips()

        _soar_engine_singleton = SoarEngine(
            whitelist_ips=whitelist,
            auto_block=SOAR_AUTO_BLOCK,
            ban_duration=SOAR_BAN_DURATION,
        )
    return _soar_engine_singleton
