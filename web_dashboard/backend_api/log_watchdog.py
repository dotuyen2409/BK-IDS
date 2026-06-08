"""
BK-IDS SOC: LogWatchdog — Snort Alert File Ingestion Engine
=============================================================
Phase 3: Replaces Kafka/Logstash ingestion path entirely.

Responsibilities:
- Tail /var/log/snort/alert_json.txt in real-time (inode-safe)
- Parse each JSON line from Snort alert_json output
- Normalize to canonical `alerts` schema
- Deduplicate using SHA-256 hash (timestamp+src_ip+dst_ip+sid+action)
- Write to MySQL `alerts` table with retry/backoff
- Trigger SOAR policy evaluation per alert
- Track internal metrics: lines_read, parse_errors, db_writes, soar_actions
- Handle file rotation/truncation gracefully
- Never crash the host Flask process on errors

Thread model: runs as daemon thread started at Flask app init.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import pymysql
import pymysql.cursors

logger = logging.getLogger("BK-IDS.LogWatchdog")

# ============================================================
# CONFIGURATION — from environment
# ============================================================
ALERT_FILE      = os.environ.get("SNORT_ALERT_FILE",    "/var/log/snort/alert_json.txt")
POLL_INTERVAL   = float(os.environ.get("WATCHDOG_POLL_INTERVAL", "1"))
DB_HOST         = os.environ.get("MYSQL_HOST",          "mysql_db")
DB_PORT         = int(os.environ.get("MYSQL_PORT",      "3306"))
DB_NAME         = os.environ.get("MYSQL_DATABASE",      "bk_ids")
DB_USER         = os.environ.get("MYSQL_USER",          "root")
DB_PASS         = os.environ.get("MYSQL_PASSWORD",      "")

SOAR_BLOCK_MIN_SEVERITY = os.environ.get("SOAR_BLOCK_MIN_SEVERITY", "high")
SOAR_BLOCK_THRESHOLD    = int(os.environ.get("SOAR_BLOCK_THRESHOLD",    "3"))
SOAR_COOLDOWN_SEC       = int(os.environ.get("SOAR_COOLDOWN_SEC",       "300"))
SOAR_ENABLED            = os.environ.get("SOAR_ENABLED", "true").lower() == "true"

def _parse_ip_set(value: str) -> set:
    return {
        ip.strip()
        for ip in value.split(",")
        if ip.strip()
    }


WHITELIST_IPS = _parse_ip_set(
    os.environ.get("WHITELIST_IPS", "127.0.0.1,192.168.13.1")
)
SUPPRESS_WHITELISTED_ALERTS = (
    os.environ.get("SUPPRESS_WHITELISTED_ALERTS", "true").lower() == "true"
)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_BLOCK_MIN_LEVEL = _SEVERITY_ORDER.get(SOAR_BLOCK_MIN_SEVERITY, 2)

# ============================================================
# REGEX helpers
# ============================================================
_AP_RE   = re.compile(r'^(?P<ip>[\d.]+):(?P<port>\d+)$')
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
_SID_GID_RE = re.compile(r'(\d+):(\d+):(\d+)')   # gid:sid:rev


def _validate_ip(ip: str) -> Optional[str]:
    if ip and _IPV4_RE.match(ip.strip()):
        return ip.strip()
    return None


def _is_suppressed_alert(alert: Dict[str, Any]) -> bool:
    """Drop infrastructure noise before DB insert, realtime emit, and SOAR."""
    src_ip = alert.get("src_ip", "")
    action = str(alert.get("action", "")).lower()
    if action == "pass":
        return True
    if SUPPRESS_WHITELISTED_ALERTS and src_ip in WHITELIST_IPS:
        return True
    return False


def _parse_ap(ap: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse 'ip:port' string. Returns (ip, port) or (ip, None)."""
    if not ap:
        return None, None
    m = _AP_RE.match(ap.strip())
    if m:
        return m.group("ip"), int(m.group("port"))
    if _IPV4_RE.match(ap.strip()):
        return ap.strip(), None
    return None, None


def _parse_rule(rule_str: str) -> Tuple[int, int, int]:
    """Parse Snort rule field 'gid:sid:rev'. Returns (gid, sid, rev)."""
    if not rule_str:
        return 1, 0, 1
    m = _SID_GID_RE.search(rule_str)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 1, 0, 1


def _severity_from_priority(priority: Any, classtype: str = "") -> str:
    """Map Snort priority to severity label.
    Snort convention: 1=high, 2=medium, 3=low.
    Priority 0 (rarest) reserved for critical rules.
    If classtype is provided and priority is missing, use classtype heuristic.
    """
    # Classtype-based severity override (when priority is not explicitly set)
    _CLASSTYPE_SEVERITY = {
        "web-application-attack": "critical",
        "attempted-admin":       "critical",
        "trojan-activity":       "critical",
        "shellcode-detect":      "critical",
        "denial-of-service":     "critical",
        "attempted-dos":         "high",
        "attempted-recon":       "high",
    }
    try:
        p = int(priority)
    except (TypeError, ValueError):
        # No priority from Snort — use classtype heuristic
        if classtype:
            return _CLASSTYPE_SEVERITY.get(classtype.lower().strip(), "medium")
        return "medium"
    if p == 0:
        return "critical"
    if p == 1:
        return "high"
    if p == 2:
        return "medium"
    return "low"


def _category_from_classtype(classtype: str) -> str:
    if not classtype:
        return ""
    # Map common Snort classtypes to categories
    _MAP = {
        "attempted-recon":       "reconnaissance",
        "network-scan":          "port-scan",
        "port-scan":             "port-scan",
        "portscan":              "port-scan",
        "attempted-dos":         "dos",
        "denial-of-service":     "dos",
        "web-application-attack":"web-attack",
        "attempted-admin":       "brute-force",
        "attempted-user":        "brute-force",
        "shellcode-detect":      "exploit",
        "successful-recon-largescale": "reconnaissance",
        "trojan-activity":       "malware",
        "policy-violation":      "policy",
        "protocol-command-decode":"protocol-anomaly",
        "misc-attack":           "misc",
        "reputation":            "reputation",
    }
    ct = classtype.lower().strip()
    return _MAP.get(ct, ct)


def _compute_dedupe_hash(event_time: str, src_ip: str, dst_ip: str,
                         sid: int, action: str) -> str:
    """SHA-256 idempotency key per blueprint §4.2, aggregated to 10s window."""
    try:
        # event_time is a string, e.g. "2026-06-03 09:10:23.456"
        # Parse and round to the nearest 10 seconds
        dt = datetime.strptime(event_time[:19], "%Y-%m-%d %H:%M:%S")
        rounded_second = (dt.second // 10) * 10
        dt_rounded = dt.replace(second=rounded_second, microsecond=0)
        event_time_key = dt_rounded.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        event_time_key = event_time

    raw = f"{event_time_key}|{src_ip}|{dst_ip}|{sid}|{action}"
    return hashlib.sha256(raw.encode()).hexdigest()



_rule_msg_cache = {}
_cache_lock = threading.Lock()

def _get_cached_rule_msg(sid: int) -> Optional[str]:
    """Retrieve rule message from local database cache or DB."""
    if not sid:
        return None
    with _cache_lock:
        if sid in _rule_msg_cache:
            return _rule_msg_cache[sid]
            
    msg = None
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT msg FROM rules WHERE sid = %s LIMIT 1", (sid,))
            row = cur.fetchone()
            if row:
                msg = row.get("msg") or ""
        conn.close()
    except Exception as e:
        logger.debug("Error looking up rule msg for sid %s: %s", sid, e)
        
    if msg:
        with _cache_lock:
            _rule_msg_cache[sid] = msg
    return msg


def _normalize_alert(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalize a raw Snort alert_json dict into the canonical `alerts` schema.
    Tolerant of missing/changed fields per blueprint §3.1.
    Returns None if alert is fundamentally unparseable.
    """
    try:
        # --- Timestamp ---
        ts_raw = raw.get("timestamp", "")
        try:
            # Snort format: "MM/DD-HH:MM:SS.ffffff"  or ISO
            if ts_raw and "/" in ts_raw and "-" in ts_raw:
                now = datetime.now(timezone.utc)
                # "01/15-14:23:01.123456" → add current year
                ts_str = f"{now.year}/{ts_raw}"
                event_time = datetime.strptime(ts_str, "%Y/%m/%d-%H:%M:%S.%f")
            elif ts_raw:
                event_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            else:
                event_time = datetime.now(timezone.utc)
        except Exception:
            event_time = datetime.now(timezone.utc)
        event_time_str = event_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # --- Source / Destination ---
        # Priority: src_addr/dst_addr (Snort 3 direct) > src_ap/dst_ap (legacy)
        src_ip = _validate_ip(raw.get("src_addr", ""))
        dst_ip = _validate_ip(raw.get("dst_addr", ""))

        # Try src_port/dst_port direct fields first
        src_port = None
        dst_port = None
        try:
            src_port = int(raw.get("src_port", 0)) or None
        except (TypeError, ValueError):
            pass
        try:
            dst_port = int(raw.get("dst_port", 0)) or None
        except (TypeError, ValueError):
            pass

        # Fallback: parse from src_ap/dst_ap (ip:port combined field)
        if not src_ip:
            ap_src_ip, ap_src_port = _parse_ap(raw.get("src_ap", ""))
            if ap_src_ip:
                src_ip = ap_src_ip
            if not src_port and ap_src_port:
                src_port = ap_src_port
        if not dst_ip:
            ap_dst_ip, ap_dst_port = _parse_ap(raw.get("dst_ap", ""))
            if ap_dst_ip:
                dst_ip = ap_dst_ip
            if not dst_port and ap_dst_port:
                dst_port = ap_dst_port

        # Fallback: src_ip/dst_ip named fields
        if not src_ip:
            src_ip = _validate_ip(raw.get("src_ip", raw.get("SrcIP", "")))
        if not dst_ip:
            dst_ip = _validate_ip(raw.get("dst_ip", raw.get("DstIP", "")))

        if not src_ip and not dst_ip:
            return None   # Cannot store without network context

        src_ip  = src_ip  or ""
        dst_ip  = dst_ip  or ""

        # --- Protocol ---
        protocol = str(raw.get("proto", raw.get("protocol", "tcp"))).lower()

        # --- Rule fields ---
        rule_str = raw.get("rule", "")
        gid, sid, rev = _parse_rule(rule_str)

        # --- Signature message ---
        msg = str(raw.get("msg", raw.get("message", "")))[:512]
        if not msg and sid:
            db_msg = _get_cached_rule_msg(sid)
            msg = db_msg if db_msg else f"Snort Alert SID:{sid}"

        # --- Category / Classtype ---
        # Snort alert_json now includes classtype when configured in fields
        classtype = raw.get("classtype", raw.get("category", ""))
        category  = _category_from_classtype(classtype)

        # Infer category from classtype embedded in rule field
        if not category and rule_str:
            rule_lower = rule_str.lower()
            if "classtype:" in rule_lower:
                ct_match = re.search(r'classtype:([\w-]+)', rule_str)
                if ct_match:
                    classtype = ct_match.group(1)
                    category = _category_from_classtype(classtype)

        # Port-scan detection from action/msg content
        if not category and ("portscan" in msg.lower() or "port scan" in msg.lower()):
            category = "port-scan"

        # --- Severity ---
        priority   = raw.get("priority", None)
        severity   = _severity_from_priority(priority, classtype)
        # Override: portscan → medium at minimum
        if category == "port-scan" and severity == "low":
            severity = "medium"
        # Override: reputation → high
        if category == "reputation":
            severity = "high"

        # --- Action ---
        action = str(raw.get("action", "alert")).lower()
        if action not in ("alert", "drop", "block", "pass", "reject"):
            action = "alert"

        # --- App ID (OpenAppID) ---
        app_id = raw.get("appid", raw.get("app_name", raw.get("service", None)))
        if app_id:
            app_id = str(app_id)[:100]

        # --- Dedupe hash ---
        dedupe_hash = _compute_dedupe_hash(
            event_time_str, src_ip, dst_ip, sid, action
        )

        return {
            "event_time":   event_time_str,
            "src_ip":       src_ip,
            "src_port":     src_port,
            "dst_ip":       dst_ip,
            "dst_port":     dst_port,
            "protocol":     protocol,
            "sid":          sid,
            "gid":          gid,
            "rev":          rev,
            "signature":    msg,
            "category":     category,
            "severity":     severity,
            "action":       action,
            "app_id":       app_id,
            "raw_json":     json.dumps(raw, ensure_ascii=False),
            "dedupe_hash":  dedupe_hash,
        }
    except Exception as exc:
        logger.debug("Normalize error: %s | raw=%s", exc, str(raw)[:200])
        return None


# ============================================================
# DATABASE LAYER
# ============================================================

def _get_db() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT,
        db=DB_NAME, user=DB_USER, password=DB_PASS,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=5,
    )


_INSERT_ALERT_SQL = """
    INSERT IGNORE INTO alerts
        (event_time, src_ip, src_port, dst_ip, dst_port, protocol,
         sid, gid, rev, signature, category, severity, action,
         app_id, raw_json, dedupe_hash)
    VALUES
        (%(event_time)s, %(src_ip)s, %(src_port)s, %(dst_ip)s, %(dst_port)s,
         %(protocol)s, %(sid)s, %(gid)s, %(rev)s, %(signature)s, %(category)s,
         %(severity)s, %(action)s, %(app_id)s, %(raw_json)s, %(dedupe_hash)s)
"""

_MARK_SOAR_SQL = "UPDATE alerts SET soar_blocked=1 WHERE dedupe_hash=%s"

_INSERT_SOAR_BLOCK_SQL = """
    INSERT INTO soar_blocks (ip, reason, alert_id, ban_duration_sec, source, is_active, blocked_at)
    VALUES (%(ip)s, %(reason)s, %(alert_id)s, %(ban_duration_sec)s, %(source)s, 1, NOW())
"""

_INSERT_SOAR_AUDIT_SQL = """
    INSERT INTO soar_audit (action_time, action, ip, reason, source, success, details, operator)
    VALUES (%(action_time)s, %(action)s, %(ip)s, %(reason)s, %(source)s,
            %(success)s, %(details)s, %(operator)s)
"""


def _db_insert_alerts_bulk(conn: pymysql.connections.Connection,
                           alerts: list) -> int:
    """
    Bulk insert mảng alerts sử dụng executemany.
    Tự động bỏ qua các bản ghi trùng lặp nhờ INSERT IGNORE.
    Trả về số lượng row được thêm mới thành công.
    """
    if not alerts:
        return 0
    with conn.cursor() as cur:
        affected = cur.executemany(_INSERT_ALERT_SQL, alerts)
        conn.commit()
        return affected


def _db_write_soar_block(conn: pymysql.connections.Connection,
                         ip: str, reason: str,
                         alert_id: Optional[int],
                         ban_duration: int) -> None:
    with conn.cursor() as cur:
        cur.execute(_INSERT_SOAR_BLOCK_SQL, {
            "ip": ip, "reason": reason,
            "alert_id": alert_id,
            "ban_duration_sec": ban_duration,
            "source": "soar_auto",
        })
    conn.commit()


def _db_write_soar_audit(conn: pymysql.connections.Connection,
                         action: str, ip: str, reason: str,
                         success: bool, details: str = "") -> None:
    with conn.cursor() as cur:
        cur.execute(_INSERT_SOAR_AUDIT_SQL, {
            "action_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "action": action,
            "ip": ip,
            "reason": reason[:512],
            "source": "soar_watchdog",
            "success": 1 if success else 0,
            "details": details[:1000] if details else None,
            "operator": "system",
        })
    conn.commit()


# ============================================================
# SOAR POLICY ENGINE (embedded — no external Kafka dependency)
# ============================================================

class _SoarPolicy:
    """
    Lightweight in-process SOAR policy evaluator.
    Integrates with existing soar_engine.py for iptables calls.
    Tracks per-IP alert counters for threshold-based blocking.
    """

    def __init__(self) -> None:
        self._lock            = threading.Lock()
        self._ip_counts:    Dict[str, list]  = {}   # ip → [timestamps]
        self._cooldown:     Dict[str, float] = {}   # ip → last_block_ts
        self._ban_duration  = int(os.environ.get("SOAR_BAN_DURATION", "3600"))
        self._soar_engine   = None

    def _get_engine(self):
        if self._soar_engine is None:
            try:
                import sys
                sys.path.insert(0, "/app/core_engine")
                from soar_engine import get_soar_engine
                self._soar_engine = get_soar_engine()
            except Exception as e:
                logger.warning("SOAR engine not available: %s", e)
        return self._soar_engine

    def evaluate(self, alert: Dict[str, Any],
                 conn: pymysql.connections.Connection,
                 alert_db_id: Optional[int]) -> bool:
        """
        Evaluate SOAR policy for normalized alert.
        Returns True if block was executed.
        """
        if not SOAR_ENABLED:
            return False

        src_ip   = alert.get("src_ip", "")
        severity = alert.get("severity", "low")

        if not src_ip or not _validate_ip(src_ip):
            return False
        if src_ip in WHITELIST_IPS:
            return False

        sev_level = _SEVERITY_ORDER.get(severity, 0)

        # Single-alert block: critical severity always triggers immediately
        if severity == "critical":
            return self._try_block(src_ip, alert, conn, alert_db_id, "severity=critical")

        # Threshold-based block: count alerts from same IP within cooldown window
        if sev_level >= _BLOCK_MIN_LEVEL:
            count = self._increment_count(src_ip)
            if count >= SOAR_BLOCK_THRESHOLD:
                reason = f"threshold={count} alerts in {SOAR_COOLDOWN_SEC}s, severity={severity}"
                return self._try_block(src_ip, alert, conn, alert_db_id, reason)

        return False

    def _increment_count(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            timestamps = self._ip_counts.get(ip, [])
            cutoff = now - SOAR_COOLDOWN_SEC
            timestamps = [t for t in timestamps if t > cutoff]
            timestamps.append(now)
            self._ip_counts[ip] = timestamps
            return len(timestamps)

    def _try_block(self, ip: str, alert: Dict[str, Any],
                   conn: pymysql.connections.Connection,
                   alert_db_id: Optional[int], reason: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._cooldown.get(ip, 0)
            if now - last < SOAR_COOLDOWN_SEC:
                return False   # Still in cooldown
            self._cooldown[ip] = now

        engine = self._get_engine()
        blocked = False
        if engine:
            try:
                result = engine.process_critical_alert({
                    "src_ip":      ip,
                    "severity":    "CRITICAL",
                    "attack_type": alert.get("signature", "Unknown"),
                    "confidence":  0.9,
                })
                blocked = result.get("blocked", False)
            except Exception as e:
                logger.error("[SOAR] Engine error for %s: %s", ip, e)
        else:
            # Fallback: direct iptables if engine unavailable
            try:
                import subprocess
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5, shell=False
                )
                blocked = True
            except Exception as e:
                logger.error("[SOAR] Direct iptables error for %s: %s", ip, e)

        # Write to DB regardless of engine availability
        try:
            _db_write_soar_block(conn, ip, reason, alert_db_id, self._ban_duration)
            _db_write_soar_audit(conn, "BLOCK_IP", ip, reason,
                                 blocked, f"alert_id={alert_db_id}")
        except Exception as e:
            logger.error("[SOAR] DB audit write error: %s", e)

        action_word = "BLOCKED" if blocked else "BLOCK_ATTEMPTED"
        logger.warning("[SOAR] %s %s | reason=%s | sig=%s",
                       action_word, ip, reason, alert.get("signature", ""))
        return blocked


# ============================================================
# LOGWATCHDOG — MAIN CLASS
# ============================================================

class LogWatchdog:
    """
    Tails /var/log/snort/alert_json.txt in real-time.

    Design:
    - Tracks file offset (inode-safe rotation detection)
    - At-least-once ingestion with DB dedupe_hash as idempotency key
    - Per-alert SOAR policy evaluation
    - Exponential backoff on DB errors (max 30s)
    - Socket.IO emit for real-time dashboard push
    - Never propagates exceptions to caller thread
    """

    def __init__(self, socketio=None) -> None:
        self.alert_file      = ALERT_FILE
        self.poll_interval   = POLL_INTERVAL
        self._thread: Optional[threading.Thread] = None
        self._metrics_lock   = threading.Lock()
        self._stop_event     = threading.Event()
        self._soar_policy    = _SoarPolicy()
        self._socketio       = socketio   # Flask-SocketIO instance for real-time push

        # Metrics — accessible via /api/health
        self.metrics: Dict[str, Any] = {
            "lines_read":         0,
            "parse_errors":       0,
            "db_writes":          0,
            "db_duplicates":      0,
            "suppressed_alerts":   0,
            "soar_actions":       0,
            "db_errors":          0,
            "last_seen_timestamp": None,
            "started_at":         None,
            "status":             "stopped",
            "alert_file":         ALERT_FILE,
        }
        self._metrics_lock = threading.Lock()

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.warning("[Watchdog] Already running — skipping start()")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="LogWatchdog",
            daemon=True,
        )
        self._thread.start()
        logger.info("[Watchdog] Started — watching %s", self.alert_file)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("[Watchdog] Stopped")

    def get_metrics(self) -> Dict[str, Any]:
        with self._metrics_lock:
            return dict(self.metrics)

    # ----------------------------------------------------------
    # Internal loop
    # ----------------------------------------------------------
    def _run_loop(self) -> None:
        with self._metrics_lock:
            self.metrics["status"]     = "running"
            self.metrics["started_at"] = datetime.now().isoformat()

        # Maintain states (offset and inode) per file path
        file_states = {}
        db_backoff = 1   # seconds, doubles on error, max 30

        dir_name = os.path.dirname(self.alert_file)
        base_name = os.path.basename(self.alert_file)

        while not self._stop_event.is_set():
            try:
                # Find all matching files in the directory
                matched_files = []
                if os.path.exists(dir_name):
                    try:
                        for f in os.listdir(dir_name):
                            if f == base_name or (f.endswith(base_name) and f[:-len(base_name)].replace("_", "").isdigit()):
                                matched_files.append(os.path.join(dir_name, f))
                    except OSError as e:
                        logger.warning("[Watchdog] Dir scan error: %s", e)

                if not matched_files:
                    logger.debug("[Watchdog] No alert files matching %s found yet", self.alert_file)
                    time.sleep(self.poll_interval * 5)
                    continue

                new_alerts = []
                for path in matched_files:
                    if path not in file_states:
                        file_states[path] = {"file_pos": 0, "last_inode": None}

                    state = file_states[path]
                    file_pos = state["file_pos"]
                    last_inode = state["last_inode"]

                    try:
                        stat = os.stat(path)
                        current_inode = stat.st_ino
                        current_size  = stat.st_size
                    except OSError:
                        continue

                    if current_inode != last_inode:
                        logger.info("[Watchdog] File rotation/creation detected for %s — resetting offset", path)
                        file_pos = 0
                        last_inode = current_inode
                        state["last_inode"] = current_inode

                    if current_size < file_pos:
                        logger.info("[Watchdog] File truncated for %s — resetting offset", path)
                        file_pos = 0

                    if current_size == file_pos:
                        continue

                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            fh.seek(file_pos)
                            for raw_line in fh:
                                line = raw_line.strip()
                                if not line:
                                    continue
                                with self._metrics_lock:
                                    self.metrics["lines_read"] += 1
                                alert = self._parse_line(line)
                                if alert:
                                    new_alerts.append(alert)
                                    if len(new_alerts) % 1000 == 0:
                                        time.sleep(0)
                            file_pos = fh.tell()
                        state["file_pos"] = file_pos
                    except OSError as e:
                        logger.warning("[Watchdog] File read error on %s: %s", path, e)
                        continue

                if not new_alerts:
                    time.sleep(self.poll_interval)
                    continue

                # ---- Write to DB (Bulk Insert & SOAR Batch) ----
                conn = None
                try:
                    conn = _get_db()
                    db_backoff = 1   # reset on success
                    
                    # 1. Thực thi Bulk Insert vào DB
                    try:
                        affected = 0
                        for i in range(0, len(new_alerts), 2000):
                            batch = new_alerts[i:i+2000]
                            affected += _db_insert_alerts_bulk(conn, batch)
                            time.sleep(0.01)  # Giảm tải cho MySQL và nhả GIL
                            
                        with self._metrics_lock:
                            self.metrics["db_writes"] += affected
                            self.metrics["db_duplicates"] += (len(new_alerts) - affected)
                            if new_alerts:
                                self.metrics["last_seen_timestamp"] = new_alerts[-1]["event_time"]
                    except Exception as e:
                        logger.error("[Watchdog] Bulk insert error: %s", e)
                        with self._metrics_lock:
                            self.metrics["db_errors"] += 1
                        continue # Bỏ qua kích hoạt SOAR nếu chèn DB thất bại
                        
                    # 2. Đánh giá SOAR Policy trên tập cảnh báo
                    if SOAR_ENABLED:
                        for alert in new_alerts:
                            try:
                                blocked = self._soar_policy.evaluate(alert, conn, None)
                                action_taken = "Monitored"
                                if blocked:
                                    with conn.cursor() as cur:
                                        cur.execute(_MARK_SOAR_SQL, (alert["dedupe_hash"],))
                                    conn.commit()
                                    with self._metrics_lock:
                                        self.metrics["soar_actions"] += 1
                                    action_taken = "Blocked by SOAR"

                                # Emit to Vue.js Dashboard via Socket.IO
                                if self._socketio:
                                    try:
                                        self._socketio.emit('soar_alert', {
                                            'timestamp':    alert.get('event_time', ''),
                                            'severity':     alert.get('severity', 'medium'),
                                            'src_ip':       alert.get('src_ip', ''),
                                            'dst_ip':       alert.get('dst_ip', ''),
                                            'dst_port':     alert.get('dst_port'),
                                            'signature':    alert.get('signature', ''),
                                            'category':     alert.get('category', ''),
                                            'action_taken': action_taken,
                                            'sid':          alert.get('sid', 0),
                                            'protocol':     alert.get('protocol', ''),
                                        }, namespace='/')
                                    except Exception as ws_err:
                                        logger.debug("[Watchdog] Socket.IO emit error: %s", ws_err)

                            except Exception as e:
                                logger.error("[Watchdog] SOAR eval error: %s", e)
                                
                except pymysql.err.OperationalError as e:
                    logger.error("[Watchdog] DB connection error: %s — backoff %ss", e, db_backoff)
                    with self._metrics_lock:
                        self.metrics["db_errors"] += 1
                    time.sleep(min(db_backoff, 30))
                    db_backoff = min(db_backoff * 2, 30)
                except Exception as e:
                    logger.error("[Watchdog] Unexpected DB error: %s", e, exc_info=True)
                    with self._metrics_lock:
                        self.metrics["db_errors"] += 1
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass

            except Exception as e:
                # Safety net — watchdog must never die
                logger.error("[Watchdog] Unexpected loop error: %s", e, exc_info=True)
                time.sleep(self.poll_interval * 2)

        with self._metrics_lock:
            self.metrics["status"] = "stopped"

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single JSON line from alert_json. Returns normalized dict or None."""
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError("Not a JSON object")
        except (json.JSONDecodeError, ValueError) as e:
            with self._metrics_lock:
                self.metrics["parse_errors"] += 1
            logger.debug("[Watchdog] JSON parse error: %s | line=%s", e, line[:120])
            return None

        normalized = _normalize_alert(raw)
        if normalized is None:
            with self._metrics_lock:
                self.metrics["parse_errors"] += 1
            return None
        if _is_suppressed_alert(normalized):
            with self._metrics_lock:
                self.metrics["suppressed_alerts"] += 1
            logger.debug(
                "[Watchdog] Suppressed alert src=%s sid=%s action=%s",
                normalized.get("src_ip", ""),
                normalized.get("sid", 0),
                normalized.get("action", ""),
            )
            return None
        return normalized


# ============================================================
# SINGLETON
# ============================================================
_watchdog_instance: Optional[LogWatchdog] = None
_watchdog_lock = threading.Lock()


def get_watchdog(socketio=None) -> LogWatchdog:
    """Get or create the singleton LogWatchdog instance."""
    global _watchdog_instance
    with _watchdog_lock:
        if _watchdog_instance is None:
            _watchdog_instance = LogWatchdog(socketio=socketio)
        elif socketio and not _watchdog_instance._socketio:
            _watchdog_instance._socketio = socketio
    return _watchdog_instance


def start_watchdog(socketio=None) -> LogWatchdog:
    """Start the singleton watchdog. Safe to call multiple times."""
    wd = get_watchdog(socketio=socketio)
    wd.start()
    return wd
