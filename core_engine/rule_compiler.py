# /home/ids/bk_ids/core_engine/rule_compiler.py
"""
BK-IDS SOC: RULE ENGINE CORE — Single Source of Truth (SSOT)
============================================================
Tất cả logic liên quan đến Snort rules đều tập trung tại đây:
  - Validate syntax, generate rules, parse rules
  - Đọc/ghi file (local.rules, rules_db.json, rules_audit.json)
  - Database sync (MySQL)
  - Audit logging
  - Rule templates
  - Conflict detection

Public API (được import bởi controllers/rules_controller.py):
  get_all_rules(category, action, protocol, enabled)  → list[dict]
  get_rule_by_sid(sid)                                 → dict | None
  save_rules(rules_list, mode, username)               → dict
  update_rule(sid, fields, username)                   → dict
  delete_rule(sid, username)                           → dict
  toggle_rule(sid, enabled, username)                  → dict
  validate_rules_batch(rules_list)                     → dict
  import_rules(raw_text, mode, category, username)     → dict
  export_rules(fmt, enabled_only)                      → str | dict
  bulk_delete_rules(sids, username)                    → dict
  bulk_toggle_rules(sids, enabled, username)           → dict
  get_templates()                                      → dict
  get_audit_log(limit)                                 → list
"""

import os
import re
import json
import logging
import subprocess
import threading
import time
from datetime import datetime

# ========================================================================
# CONFIGURATION — HARDCODED PATHS (never from user input)
# ========================================================================
SNORT_RULES_PATH = '/app/core_engine/local.rules'
RULES_FILE_PATH  = '/app/core_engine/local.rules'
RULES_JSON_PATH  = '/app/core_engine/rules_db.json'
RULES_AUDIT_PATH = '/app/core_engine/rules_audit.json'
SNORT_RULES_DIR  = '/app/core_engine'

# DB config from environment
DB_HOST  = os.environ.get('MYSQL_HOST', 'bkids_mysql')
DB_PORT  = int(os.environ.get('MYSQL_PORT', '3306'))
DB_USER  = os.environ.get('MYSQL_USER', 'root')
DB_PASS  = os.environ.get('MYSQL_PASSWORD', '')
DB_NAME  = os.environ.get('MYSQL_DATABASE', 'bk_ids')
DB_TABLE = 'rules'

logger = logging.getLogger("Bk-IDS-Rule-Engine")

# Thread lock for file operations
_file_lock = threading.Lock()

# ========================================================================
# VALID SNORT ACTIONS & PROTOCOLS
# ========================================================================
VALID_SNORT_ACTIONS = {
    'alert', 'drop', 'log', 'pass', 'reject', 'sdrop',
    'activate', 'dynamic'
}

VALID_SNORT_PROTOCOLS = {
    'tcp', 'udp', 'icmp', 'ip', 'http', 'ftp', 'tls', 'smb',
    'dns', 'dcerpc', 'ssh', 'smtp', 'imap', 'pop3', 'modbus',
    'dnp3', 'enip', 'ntp', 'sip', 'rfb', 'rdp'
}

# Regex patterns
SNORT_RULE_REGEX = re.compile(
    r'^\s*(alert|drop|log|pass|reject|sdrop|activate|dynamic)\s+'
    r'(tcp|udp|icmp|ip|http|ftp|tls|smb|dns|dcerpc|ssh|smtp|imap|pop3|'
    r'modbus|dnp3|enip|ntp|sip|rfb|rdp)\s+',
    re.IGNORECASE
)

SID_REGEX      = re.compile(r'sid\s*:\s*(\d+)\s*;', re.IGNORECASE)
MSG_REGEX      = re.compile(r'msg\s*:\s*"([^"]*)"\s*;', re.IGNORECASE)
PROTO_REGEX    = re.compile(r'^\s*(?:alert|drop|log|pass|reject|sdrop|activate|dynamic)\s+([a-zA-Z0-9_\-]+)\s+', re.IGNORECASE)
ACTION_REGEX   = re.compile(r'^\s*(alert|drop|log|pass|reject|sdrop|activate|dynamic)\s+', re.IGNORECASE)
REV_REGEX      = re.compile(r'rev\s*:\s*(\d+)\s*;', re.IGNORECASE)
CLASSTYPE_REGEX = re.compile(r'classtype\s*:\s*([^;]+)\s*;', re.IGNORECASE)
PRIORITY_REGEX = re.compile(r'priority\s*:\s*(\d+)\s*;', re.IGNORECASE)
CONTENT_REGEX  = re.compile(r'content\s*:\s*"([^"]*)"\s*;', re.IGNORECASE)
FLOW_REGEX     = re.compile(r'flow\s*:\s*([^;]+)\s*;', re.IGNORECASE)
THRESHOLD_REGEX = re.compile(
    r'threshold\s*:\s*type\s+(limit|threshold|both)\s*,\s*'
    r'track\s+(by_src|by_dst)\s*,\s*count\s+(\d+)\s*,\s*seconds\s+(\d+)\s*;',
    re.IGNORECASE
)

UNSAFE_RULE_PATTERNS = [
    re.compile(r'\bexec\b', re.IGNORECASE),
    re.compile(r'\bsystem\b', re.IGNORECASE),
    re.compile(r';\s*\w+\s*\(', re.IGNORECASE),
]


# ========================================================================
# INTERNAL: SANITIZE
# ========================================================================
def sanitize_name(text):
    if not text:
        return "Unknown Threat"
    return re.sub(r'[^\w\s\-]', '', str(text)).strip()


def sanitize_pattern(text):
    if not text:
        return ""
    text = str(text)
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;')
    return text


# ========================================================================
# INTERNAL: SNORT RULE GENERATION
# ========================================================================
def generate_snort_rules(rules_list):
    """
    Generate Snort 3 rule file content from a list of rule dicts.
    Each dict: {name, pattern, protocol, action, dst_port}
    Returns the full file content as a string.
    """
    snort_lines = [
        "# ==================================================================",
        "# BK-IDS SOC: TEP LUAT SNORT 3 - ENTERPRISE EDITION",
        "# ==================================================================\n"
    ]
    sid_counter = 1000001

    for rule in rules_list:
        raw_action = str(rule.get('action', 'ALERT')).upper().strip()
        action_web = "DROP" if raw_action in ["DROP", "BLOCK", "CHAN"] else "ALERT"
        snort_action = "drop" if action_web == "DROP" else "alert"

        name = sanitize_name(rule.get('name'))
        pattern = sanitize_pattern(rule.get('pattern'))
        protocol = str(rule.get('protocol', 'tcp')).lower()
        dst_port = str(rule.get('dst_port', 'any')).strip() or 'any'

        if not pattern:
            continue

        flow_directive = "flow:to_server; " if protocol == 'tcp' and dst_port != 'any' else ""

        snort_rule = (
            f'{snort_action} {protocol} $EXTERNAL_NET any -> $HOME_NET {dst_port} '
            f'(msg:"[{action_web}] {name}"; {flow_directive}content:"{pattern}", nocase; '
            f'classtype:web-application-attack; sid:{sid_counter}; rev:1;)'
        )
        snort_lines.append(snort_rule)
        sid_counter += 1

    return '\n'.join(snort_lines)


# ========================================================================
# INTERNAL: VALIDATION
# ========================================================================
def _validate_rule(rule_line):
    """
    Validate a single Snort rule line.
    Returns (is_valid: bool, error_message: str or None)
    """
    if not rule_line or not isinstance(rule_line, str):
        return False, "Rule rỗng hoặc không phải chuỗi"

    line = rule_line.strip()

    if not line or line.startswith('#'):
        return True, None

    for unsafe_re in UNSAFE_RULE_PATTERNS:
        if unsafe_re.search(line):
            return False, "Luật chứa mã không an toàn (unsafe pattern detected)"

    if not SNORT_RULE_REGEX.match(line):
        first_word = line.split()[0] if line.split() else '(rỗng)'
        if first_word.lower() not in VALID_SNORT_ACTIONS:
            return False, f"Hành động Snort không hợp lệ '{first_word}'. Phải là một trong: {', '.join(sorted(VALID_SNORT_ACTIONS))}"
        return False, f"Định dạng luật Snort không hợp lệ. Nhận: '{line[:80]}...'"

    sid_match = SID_REGEX.search(line)
    if not sid_match:
        return False, "Thiếu trường bắt buộc 'sid:<số>;'"

    sid = int(sid_match.group(1))
    if sid < 1:
        return False, f"SID không hợp lệ: {sid}. Phải là số nguyên dương."
    if sid > 2147483647:
        return False, f"SID quá lớn: {sid}. Tối đa: 2147483647"

    msg_match = MSG_REGEX.search(line)
    if not msg_match:
        return False, "Thiếu trường bắt buộc 'msg:\"...\";'"

    msg = msg_match.group(1)
    if len(msg) < 3:
        return False, "Tên cảnh báo quá ngắn (tối thiểu 3 ký tự)"
    if len(msg) > 500:
        return False, "Tên cảnh báo quá dài (tối đa 500 ký tự)"

    if line.count('(') != line.count(')'):
        return False, "Dấu ngoặc không cân bằng trong luật"

    if sid < 1000000:
        logger.warning(f"[RULES] SID {sid} nằm trong dải rule chính thức Snort (<1000000)")

    return True, None


def validate_rules_batch(rules_list):
    """
    Validate a batch of rules (strings or dicts).
    Returns {"valid": [...], "errors": [{"line", "error", "content"}]}
    """
    valid = []
    errors = []

    if not isinstance(rules_list, list):
        return {"valid": [], "errors": [{"line": "N/A", "error": "Rules phải là một mảng JSON"}]}

    if len(rules_list) > 10000:
        return {"valid": [], "errors": [{"line": "N/A", "error": "Quá nhiều luật (tối đa 10000)"}]}

    seen_sids = set()

    for i, rule in enumerate(rules_list):
        try:
            if isinstance(rule, str):
                line = ' '.join(rule.replace('\r', ' ').replace('\n', ' ').split())
                is_valid, err = _validate_rule(line)
                if is_valid and line and not line.startswith('#'):
                    sid_match = SID_REGEX.search(line)
                    if sid_match:
                        sid = int(sid_match.group(1))
                        if sid in seen_sids:
                            errors.append({"line": i + 1, "error": f"SID {sid} bị trùng trong batch", "content": line[:100]})
                            continue
                        seen_sids.add(sid)
                    valid.append(line)
                elif err:
                    errors.append({"line": i + 1, "error": err, "content": line[:100]})

            elif isinstance(rule, dict):
                raw = rule.get('raw_rule', '')
                if raw:
                    raw = ' '.join(raw.replace('\r', ' ').replace('\n', ' ').split())
                action = rule.get('action', 'ALERT').upper().strip()
                protocol = rule.get('protocol', 'tcp').lower().strip()
                msg = rule.get('msg', rule.get('name', '')).strip()
                dst_port = rule.get('dst_port', 'any').strip()
                content_pattern = rule.get('content', rule.get('pattern', '')).strip()
                sid = rule.get('sid', 0)
                rev = rule.get('rev', 1)
                classtype = rule.get('classtype', 'web-application-attack').strip()
                priority = rule.get('priority', 3)
                flow_dir = rule.get('flow', 'to_server').strip()

                if action.lower() not in VALID_SNORT_ACTIONS:
                    errors.append({"line": i + 1, "error": f"Hành động không hợp lệ: {action}"})
                    continue
                if protocol not in ('tcp', 'udp', 'icmp', 'ip'):
                    errors.append({"line": i + 1, "error": f"Giao thức không hợp lệ: {protocol}"})
                    continue
                if not msg:
                    errors.append({"line": i + 1, "error": "Thiếu tên cảnh báo (msg/name)"})
                    continue
                if len(msg) < 3:
                    errors.append({"line": i + 1, "error": "Tên cảnh báo quá ngắn (tối thiểu 3 ký tự)"})
                    continue
                if len(msg) > 500:
                    errors.append({"line": i + 1, "error": "Tên cảnh báo quá dài (tối đa 500 ký tự)"})
                    continue
                if not sid or not isinstance(sid, int) or sid < 1:
                    errors.append({"line": i + 1, "error": f"SID không hợp lệ: {sid}"})
                    continue
                if sid in seen_sids:
                    errors.append({"line": i + 1, "error": f"SID {sid} bị trùng trong batch"})
                    continue
                seen_sids.add(sid)

                msg_clean = re.sub(r'[^\w\s\-/\.\[\]{}()!@#$%^&+=]', '', msg)[:500]
                pattern_clean = content_pattern.replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;') if content_pattern else ''

                flow_str = f"flow:{flow_dir}; " if protocol == 'tcp' and flow_dir else ""
                classtype_str = f"classtype:{classtype}; " if classtype else "classtype:web-application-attack; "
                content_str = f'content:"{pattern_clean}", nocase; ' if pattern_clean else ''

                if raw:
                    is_valid, err = _validate_rule(raw)
                    if is_valid:
                        valid.append(raw)
                    elif err:
                        errors.append({"line": i + 1, "error": err, "content": str(raw)[:100]})
                    continue

                built_rule = (
                    f'{action.lower()} {protocol} $EXTERNAL_NET any -> $HOME_NET {dst_port} '
                    f'(msg:"[{action}] {msg_clean}"; '
                    f'{flow_str}'
                    f'{content_str}'
                    f'{classtype_str}'
                    f'sid:{sid}; '
                    f'rev:{rev}; '
                    f'priority:{priority};)'
                )
                valid.append(built_rule)
            else:
                errors.append({"line": i + 1, "error": f"Loại luật không hợp lệ: {type(rule).__name__}"})
        except Exception as e:
            errors.append({"line": i + 1, "error": f"Lỗi xác thực: {str(e)}"})

    return {"valid": valid, "errors": errors}


def _detect_conflicts(rules_list):
    """Detect duplicate SID conflicts. Returns list of conflict dicts."""
    conflicts = []
    sid_to_line = {}
    for i, rule in enumerate(rules_list):
        if isinstance(rule, str):
            line = rule.strip()
            if not line or line.startswith('#'):
                continue
            sid_match = SID_REGEX.search(line)
            if sid_match:
                sid = int(sid_match.group(1))
                if sid in sid_to_line:
                    conflicts.append({
                        "type": "duplicate_sid",
                        "sid": sid,
                        "message": f"SID {sid} bị trùng giữa các luật",
                        "lines": [sid_to_line[sid], i + 1]
                    })
                else:
                    sid_to_line[sid] = i + 1
    return conflicts


# ========================================================================
# INTERNAL: SAFE FILE I/O
# ========================================================================
def safe_read_file(filepath, default_content=""):
    try:
        real_path = os.path.realpath(filepath)
        if not str(real_path).startswith('/app/'):
            return default_content, "Path traversal detected"
        if not os.path.exists(filepath):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(default_content)
            except PermissionError:
                logger.warning(
                    f"[RULES] Không có quyền tạo file: {filepath}. "
                    f"Vui lòng chạy 'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                )
            return default_content, None
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read(), None
    except PermissionError as pe:
        logger.error(
            f"[RULES] PermissionError đọc file ({filepath}): {pe}. "
            f"Vui lòng chạy 'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
        )
        return default_content, str(pe)
    except Exception as e:
        logger.error(f"[RULES] Lỗi đọc file ({filepath}): {e}")
        return default_content, str(e)


def safe_write_file(filepath, content):
    """
    Atomic file write with fallback for Docker overlay filesystem.
    Strategy (Docker-aware):
      0. If file already exists, open with 'r+' (in-place overwrite) — no new inode
      1. Write to temp file, then os.replace() (atomic on same filesystem)
      2. If PermissionError (file locked by Snort), retry with shutil.move
      3. If still failing, direct 'w' open with retry
    NOTE for Docker volumes: Some bind-mounts prohibit creating new files.
    Strategy 0 handles this by reusing the existing inode.
    """
    tmp_path = None
    try:
        real_path = os.path.realpath(filepath) if os.path.exists(filepath) else filepath
        if not str(real_path).startswith('/app/'):
            return False, "Path traversal detected"
        with _file_lock:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            # Strategy 0: In-place overwrite (no new file creation)
            # Critical for Docker bind-mounts that block new inodes
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r+', encoding='utf-8') as f:
                        f.seek(0)
                        f.write(content)
                        f.truncate()
                        f.flush()
                        os.fsync(f.fileno())
                    logger.info(f"[RULES] In-place overwrite OK: {filepath}")
                    return True, None
                except PermissionError as pe:
                    logger.warning(
                        f"[RULES] In-place overwrite PermissionError: {pe}. "
                        f"Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                        f"'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                    )
                    return False, (
                        "Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                        "'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                    )
                except Exception as e0:
                    logger.warning(f"[RULES] In-place overwrite failed: {e0}, trying temp file...")

            # Strategy 1: Atomic replace via temp file
            tmp_path = filepath + '.tmp.' + str(int(time.time()))
            try:
                with open(tmp_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                import shutil as _shutil
                _shutil.move(tmp_path, filepath)  # cross-device safe
                tmp_path = None
                logger.info(f"[RULES] shutil.move() OK: {filepath}")
                return True, None
            except PermissionError:
                logger.warning(
                    f"[RULES] Temp-file write PermissionError. "
                    f"Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                    f"'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                )
                return False, (
                    "Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                    "'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                )
            except Exception as e1:
                logger.warning(f"[RULES] Temp-file strategy failed: {e1}, trying direct write...")

            # Strategy 2: Direct write with retry (file doesn't exist yet)
            for attempt in range(3):
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                        f.flush()
                        os.fsync(f.fileno())
                    logger.info(f"[RULES] Direct write OK (attempt {attempt+1}): {filepath}")
                    return True, None
                except PermissionError:
                    if attempt < 2:
                        time.sleep(0.5 * (attempt + 1))
                    else:
                        logger.error(
                            f"[RULES] All strategies failed. "
                            f"Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                            f"'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                        )
                        return False, (
                            "Lỗi phân quyền Docker: Vui lòng chạy lệnh "
                            "'sudo chmod -R 777 /home/ids/bk_ids/core_engine/' trên máy Host."
                        )
                except Exception as e2:
                    logger.error(f"[RULES] Direct write error (attempt {attempt+1}): {e2}")
                    if attempt == 2:
                        return False, str(e2)

            return False, "All write strategies failed"
    except Exception as e:
        logger.error(f"[RULES] Lỗi ghi file ({filepath}): {e}")
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False, str(e)


# ========================================================================
# INTERNAL: DATABASE
# ========================================================================
def _get_db_conn():
    try:
        import pymysql
        return pymysql.connect(
            host=DB_HOST, port=DB_PORT,
            user=DB_USER, password=DB_PASS,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5
        )
    except ImportError:
        try:
            import mysql.connector
            return mysql.connector.connect(
                host=DB_HOST, port=DB_PORT,
                user=DB_USER, password=DB_PASS,
                database=DB_NAME,
                connection_timeout=5
            )
        except Exception as e:
            logger.error(f"[RULES] Lỗi driver DB: {e}")
            return None
    except Exception as e:
        logger.error(f"[RULES] Lỗi kết nối DB: {e}")
        return None


def _sync_rules_to_db(deduped_rules):
    """Sync rules list to database. Returns (success_count, errors)."""
    errors = []
    success_count = 0
    try:
        conn = _get_db_conn()
        if not conn:
            return 0, ["Không thể kết nối database"]
        cursor = conn.cursor()
        for rule in deduped_rules:
            try:
                sid_match = SID_REGEX.search(rule)
                action_match = ACTION_REGEX.match(rule)
                proto_match = PROTO_REGEX.match(rule)
                msg_match = MSG_REGEX.search(rule)
                rev_match = REV_REGEX.search(rule)
                if sid_match:
                    sid = int(sid_match.group(1))
                    action = action_match.group(1).lower() if action_match else 'alert'
                    protocol = proto_match.group(1).lower() if proto_match else 'tcp'
                    msg = msg_match.group(1) if msg_match else ''
                    rev = int(rev_match.group(1)) if rev_match else 1
                    cursor.execute(
                        "INSERT INTO rules (sid, rev, action, protocol, msg, raw_rule, source) "
                        "VALUES (%s, %s, %s, %s, %s, %s, 'local_custom') "
                        "ON DUPLICATE KEY UPDATE "
                        "action=VALUES(action), protocol=VALUES(protocol), "
                        "msg=VALUES(msg), raw_rule=VALUES(raw_rule), rev=VALUES(rev)",
                        (sid, rev, action, protocol, msg, rule)
                    )
                    success_count += 1
            except Exception as rule_e:
                errors.append(str(rule_e))
                continue
        conn.commit()
        conn.close()
        logger.info(f"[RULES] DB sync: {success_count} luật đã lưu")
    except Exception as db_e:
        logger.warning(f"[RULES] DB sync warning: {db_e}")
        errors.append(str(db_e))
    return success_count, errors


# ========================================================================
# INTERNAL: AUDIT LOG
# ========================================================================
def _add_audit_log(action, target_sid, detail="", username="unknown", ip="N/A"):
    try:
        audit_entries = []
        if os.path.exists(RULES_AUDIT_PATH):
            try:
                content, _ = safe_read_file(RULES_AUDIT_PATH, "[]")
                audit_entries = json.loads(content) if content else []
            except Exception:
                audit_entries = []

        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "sid": target_sid,
            "detail": detail[:500],
            "user": username,
            "ip": ip
        }
        audit_entries.append(entry)
        if len(audit_entries) > 1000:
            audit_entries = audit_entries[-1000:]
        safe_write_file(RULES_AUDIT_PATH, json.dumps(audit_entries, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.warning(f"[RULES] Audit log error: {e}")


# ========================================================================
# INTERNAL: PARSE RULE
# ========================================================================
def parse_snort_rule(line):
    """Parse a raw Snort rule into structured dict."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    action_match = ACTION_REGEX.match(line)
    proto_match = PROTO_REGEX.match(line)
    sid_match = SID_REGEX.search(line)
    msg_match = MSG_REGEX.search(line)
    rev_match = REV_REGEX.search(line)
    classtype_match = CLASSTYPE_REGEX.search(line)
    priority_match = PRIORITY_REGEX.search(line)
    content_match = CONTENT_REGEX.search(line)
    flow_match = FLOW_REGEX.search(line)

    header_match = re.search(r'^\s*(alert|drop|log|pass|reject|sdrop|activate|dynamic)\s+([a-zA-Z0-9_\-]+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)', line, re.IGNORECASE)

    extra_options = ''
    opts_match = re.search(r'\((.*)\)', line)
    if opts_match:
        opts_str = opts_match.group(1)
        opts_list = [o.strip() for o in opts_str.split(';') if o.strip()]
        extra_list = []
        for o in opts_list:
            lo = o.lower()
            if not (lo.startswith('msg:') or lo.startswith('sid:') or lo.startswith('rev:')):
                extra_list.append(o + ';')
        extra_options = ' '.join(extra_list)

    return {
        'sid': int(sid_match.group(1)) if sid_match else 0,
        'action': action_match.group(1).upper() if action_match else 'ALERT',
        'protocol': proto_match.group(1).lower() if proto_match else 'tcp',
        'msg': msg_match.group(1) if msg_match else '',
        'rev': int(rev_match.group(1)) if rev_match else 1,
        'classtype': classtype_match.group(1).strip() if classtype_match else '',
        'priority': int(priority_match.group(1)) if priority_match else 3,
        'content': content_match.group(1) if content_match else '',
        'flow': flow_match.group(1).strip() if flow_match else '',
        'sourceIp': header_match.group(3) if header_match else '$HOME_NET',
        'sourcePort': header_match.group(4) if header_match else 'any',
        'direction': header_match.group(5) if header_match else '->',
        'destIp': header_match.group(6) if header_match else '$EXTERNAL_NET',
        'destPort': header_match.group(7) if header_match else 'any',
        'extraOptions': extra_options,
        'raw_rule': line,
        'enabled': True,
        'source': 'local_custom'
    }


# ========================================================================
# INTERNAL: SNORT RELOAD
# ========================================================================
def _trigger_snort_reload():
    """
    Reload Snort 3 rules without downtime.
    Strategy order:
      1. Send SIGHUP to Snort via 'docker exec' (works across PID namespaces)
      2. Direct kill -SIGHUP to Snort PID (works when api_server has host PID)
      3. Fallback: pkill -HUP (works if same PID namespace)
    Snort 3 reloads rules on SIGHUP without restarting the process.
    """
    reloaded = False

    # Strategy 1: docker exec (cross-container, most reliable)
    try:
        result = subprocess.run(
            ['docker', 'exec', 'bkids_snort_engine', 'pkill', '-HUP', '-f', 'snort'],
            capture_output=True, timeout=10, shell=False
        )
        if result.returncode == 0:
            logger.info("[RULES] Snort reload: docker exec SIGHUP OK")
            reloaded = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception as e:
        logger.debug("[RULES] docker exec reload failed: %s", e)

    if reloaded:
        return

    # Strategy 2: Direct PID kill (api_server has pid: "host" in compose)
    try:
        result = subprocess.run(
            ['pgrep', '-f', 'snort'],
            capture_output=True, timeout=5, shell=False
        )
        if result.returncode == 0:
            pids = result.stdout.decode().strip().split('\n')
            for pid in pids:
                pid = pid.strip()
                if pid.isdigit():
                    subprocess.run(
                        ['kill', '-HUP', pid],
                        capture_output=True, timeout=5, shell=False
                    )
            logger.info("[RULES] Snort reload: direct SIGHUP to PIDs %s", pids)
            reloaded = True
    except Exception as e:
        logger.debug("[RULES] Direct PID reload failed: %s", e)

    if reloaded:
        return

    # Strategy 3: Fallback pkill (same PID namespace)
    try:
        subprocess.run(
            ['pkill', '-HUP', '-f', 'snort'],
            capture_output=True, timeout=5, shell=False
        )
        logger.info("[RULES] Snort reload: pkill -HUP fallback")
    except Exception:
        logger.warning("[RULES] All Snort reload strategies failed")


# ========================================================================
# RULE TEMPLATES
# ========================================================================
def _get_rule_templates():
    return {
        "SQL_Injection": [
            {"name": "SQL Injection - Union Select", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "union select", "classtype": "web-application-attack", "category": "sqli", "flow": "to_server,established", "mitre": "T1190", "description": "Phát hiện SQL Injection dùng UNION SELECT"},
            {"name": "SQL Injection - OR 1=1", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "' or '1'='1", "classtype": "web-application-attack", "category": "sqli", "flow": "to_server,established", "mitre": "T1190", "description": "Phát hiện SQL Injection bypass authentication"},
            {"name": "SQL Injection - Sleep/Benchmark", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "sleep(", "classtype": "web-application-attack", "category": "sqli", "flow": "to_server,established", "mitre": "T1190", "description": "Phát hiện blind SQL injection bằng sleep()"},
        ],
        "XSS": [
            {"name": "XSS - Script Tag", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "<script>", "classtype": "web-application-attack", "category": "xss", "flow": "to_server,established", "mitre": "T1189", "description": "Phát hiện XSS cơ bản qua thẻ <script>"},
            {"name": "XSS - OnEvent Handler", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "onerror=", "classtype": "web-application-attack", "category": "xss", "flow": "to_server,established", "mitre": "T1189", "description": "Phát hiện XSS qua event handler"},
        ],
        "Path_Traversal": [
            {"name": "Path Traversal - Double Dot", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "../../../", "classtype": "web-application-attack", "category": "lfi", "flow": "to_server,established", "mitre": "T1083", "description": "Phát hiện Directory Traversal"},
            {"name": "Path Traversal - etc/passwd", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "/etc/passwd", "classtype": "web-application-attack", "category": "lfi", "flow": "to_server,established", "mitre": "T1083", "description": "Phát hiện Local File Inclusion /etc/passwd"},
        ],
        "Command_Injection": [
            {"name": "Command Injection - Semicolon", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "; cat /etc", "classtype": "web-application-attack", "category": "cmdi", "flow": "to_server,established", "mitre": "T1059", "description": "Phát hiện OS Command Injection"},
            {"name": "Command Injection - Pipe", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "| nc ", "classtype": "web-application-attack", "category": "cmdi", "flow": "to_server,established", "mitre": "T1059", "description": "Phát hiện Reverse Shell qua pipe"},
        ],
        "Network_Recon": [
            {"name": "Network Scan - Nmap SYN", "action": "ALERT", "protocol": "tcp", "dst_port": "any", "pattern": "", "classtype": "attempted-recon", "category": "recon", "flow": "to_server", "mitre": "T1046", "description": "Phát hiện quét mạng Nmap", "note": "Dùng threshold rule để detect port scan"},
        ],
        "Brute_Force": [
            {"name": "SSH Brute Force Detection", "action": "ALERT", "protocol": "tcp", "dst_port": "22", "pattern": "", "classtype": "attempted-admin", "category": "bruteforce", "flow": "to_server,established", "mitre": "T1110", "description": "Phát hiện Brute Force SSH", "note": "Dùng threshold: type threshold, track by_src, count 5, seconds 60"},
            {"name": "FTP Brute Force Detection", "action": "ALERT", "protocol": "tcp", "dst_port": "21", "pattern": "530 Login incorrect", "classtype": "attempted-admin", "category": "bruteforce", "flow": "from_server", "mitre": "T1110", "description": "Phát hiện Brute Force FTP"},
        ],
        "Malware_C2": [
            {"name": "Suspicious DNS Query - DGA", "action": "LOG", "protocol": "udp", "dst_port": "53", "pattern": "", "classtype": "trojan-activity", "category": "c2", "flow": "to_server", "mitre": "T1568", "description": "DNS Domain Generation Algorithm detection", "note": "Cần kết hợp với rule payload inspection"},
        ],
        "DDoS": [
            {"name": "SYN Flood Detection", "action": "ALERT", "protocol": "tcp", "dst_port": "any", "pattern": "", "classtype": "attempted-dos", "category": "ddos", "flow": "to_server", "mitre": "T1498", "description": "Phát hiện SYN Flood DDoS", "note": "Dùng threshold: type both, track by_dst, count 1000, seconds 10"},
        ],
        "Data_Exfiltration": [
            {"name": "Large Outbound Transfer", "action": "LOG", "protocol": "tcp", "dst_port": "any", "pattern": "", "classtype": "policy-violation", "category": "exfil", "flow": "to_client,established", "mitre": "T1048", "description": "Phát hiện truyền dữ liệu lớn ra ngoài"},
        ],
        "Info_Disclosure": [
            {"name": "Server Version Disclosure", "action": "LOG", "protocol": "tcp", "dst_port": "80", "pattern": "Server: Apache/", "classtype": "attempted-recon", "category": "infoleak", "flow": "from_server", "mitre": "T1082", "description": "Phát hiện lộ thông tin phiên bản server"},
            {"name": "PHP Info Disclosure", "action": "ALERT", "protocol": "tcp", "dst_port": "80", "pattern": "phpinfo()", "classtype": "attempted-recon", "category": "infoleak", "flow": "to_server,established", "mitre": "T1082", "description": "Phát hiện truy cập trang phpinfo()"},
        ],
        "Custom": [
            {"name": "Custom IPS Block Rule", "action": "DROP", "protocol": "tcp", "dst_port": "any", "pattern": "", "classtype": "admin-tag", "category": "custom_ips", "flow": "to_server,established", "description": "Mẫu luật IPS chặn kết nối"},
            {"name": "Custom IDS Alert Rule", "action": "ALERT", "protocol": "tcp", "dst_port": "any", "pattern": "", "classtype": "admin-tag", "category": "custom_ids", "flow": "to_server", "description": "Mẫu luật IDS ghi nhận cảnh báo"},
        ]
    }


# ========================================================================
# PUBLIC API
# ========================================================================

def get_all_rules(category=None, action=None, protocol=None, enabled=None):
    """
    Read all rules from local.rules + database with optional filters.
    Returns {"rules": [...], "count": N, "stats": {...}}
    """
    rules = []

    # PRIMARY: Read from local.rules
    file_content, file_err = safe_read_file(RULES_FILE_PATH, "")
    if file_err:
        logger.warning(f"[RULES] File read warning: {file_err}")

    if file_content:
        for line_num, line in enumerate(file_content.split('\n'), 1):
            try:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parsed = parse_snort_rule(line)
                if parsed:
                    parsed['line'] = line_num
                    parsed['source'] = 'local.rules'
                    rules.append(parsed)
            except Exception as e:
                logger.warning(f"[RULES] Parse warning dòng {line_num}: {e}")
                continue

    # SECONDARY: Read from database
    try:
        conn = _get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sid, action, protocol, msg, raw_rule, source, enabled FROM rules ORDER BY sid ASC")
            db_rows = cursor.fetchall()
            conn.close()
            file_sids = {r['sid'] for r in rules}
            for row in db_rows:
                if row.get('sid') not in file_sids:
                    parsed = parse_snort_rule(row.get('raw_rule', ''))
                    if parsed:
                        parsed['action'] = row.get('action', 'ALERT').upper()
                        parsed['protocol'] = row.get('protocol', 'tcp')
                        parsed['msg'] = row.get('msg', '')
                        parsed['source'] = row.get('source', 'db')
                        parsed['enabled'] = bool(row.get('enabled', 1))
                    else:
                        parsed = {
                            'sid': row.get('sid', 0), 'action': row.get('action', 'ALERT').upper(),
                            'protocol': row.get('protocol', 'tcp'), 'msg': row.get('msg', ''),
                            'raw_rule': row.get('raw_rule', ''), 'enabled': bool(row.get('enabled', 1)),
                            'source': row.get('source', 'db'), 'line': 0
                        }
                    rules.append(parsed)
    except Exception as db_e:
        logger.warning(f"[RULES] DB read warning: {db_e}")

    # Apply filters
    if category:
        rules = [r for r in rules if category in r.get('source', '').lower()]
    if action:
        rules = [r for r in rules if r.get('action', '') == action.upper()]
    if protocol:
        rules = [r for r in rules if r.get('protocol', '') == protocol.lower()]
    if enabled is not None:
        if enabled:
            rules = [r for r in rules if r.get('enabled', True)]
        else:
            rules = [r for r in rules if not r.get('enabled', True)]

    rules.sort(key=lambda r: r.get('sid', 0))

    stats = {
        'total': len(rules),
        'enabled': sum(1 for r in rules if r.get('enabled', True)),
        'disabled': sum(1 for r in rules if not r.get('enabled', True)),
        'local_custom': sum(1 for r in rules if r.get('source') == 'local.rules'),
        'by_action': {}
    }
    for r in rules:
        act = r.get('action', 'UNKNOWN')
        stats['by_action'][act] = stats['by_action'].get(act, 0) + 1

    return {"rules": rules, "count": len(rules), "stats": stats}


def get_rule_by_sid(sid):
    """Get a single rule by SID. Returns dict or None."""
    all_rules = get_all_rules()
    for r in all_rules['rules']:
        if r.get('sid') == sid:
            return r
    return None


def save_rules(rules_input, mode='replace', username='unknown', ip='N/A'):
    """
    Validate + save rules to local.rules + DB + JSON backup.
    Returns {"status", "message", "rules_count", "db_synced", ...}
    """
    if not isinstance(rules_input, list) or len(rules_input) == 0:
        return {"status": "error", "message": "Mảng luật rỗng hoặc không hợp lệ"}

    if len(rules_input) > 10000:
        return {"status": "error", "message": "Quá nhiều luật (tối đa 10000)"}

    result = validate_rules_batch(rules_input)
    valid_rules = result["valid"]
    validation_errors = result["errors"]

    if validation_errors:
        return {
            "status": "error",
            "message": f"Xác thực Snort thất bại ({len(validation_errors)} lỗi)",
            "validation_errors": validation_errors[:50]
        }

    if not valid_rules:
        return {"status": "error", "message": "Không có luật hợp lệ sau khi xác thực"}

    # Build file content
    header_lines = [
        "# ==================================================================",
        "# BK-IDS SOC: SNORT 3 LOCAL RULES — Enterprise Edition",
        f"# Tạo lúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Tổng luật: {len(valid_rules)}",
        f"# Người tạo: {username}",
        "# ==================================================================\n"
    ]

    existing_rules = []
    if mode == 'append':
        existing_content, _ = safe_read_file(RULES_FILE_PATH, "")
        if existing_content:
            for line in existing_content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    existing_rules.append(line)

    all_rules = existing_rules + valid_rules
    seen_sids = set()
    deduped_rules = []
    for rule in all_rules:
        sid_match = SID_REGEX.search(rule)
        if sid_match:
            sid = int(sid_match.group(1))
            if sid not in seen_sids:
                seen_sids.add(sid)
                deduped_rules.append(rule)
        else:
            deduped_rules.append(rule)

    file_content = '\n'.join(header_lines + [''] + deduped_rules + [''])
    write_ok, write_err = safe_write_file(RULES_FILE_PATH, file_content)
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    db_success, db_sync_errors = _sync_rules_to_db(deduped_rules)

    try:
        json_data = {
            'generated': datetime.now().isoformat(),
            'count': len(deduped_rules),
            'rules': [{'raw_rule': r} for r in deduped_rules]
        }
        safe_write_file(RULES_JSON_PATH, json.dumps(json_data, indent=2, ensure_ascii=False))
    except Exception as json_e:
        logger.warning(f"[RULES] JSON backup warning: {json_e}")

    _add_audit_log("SAVE_ALL", 0, f"Lưu {len(deduped_rules)} luật (mode={mode})", username, ip)
    _trigger_snort_reload()

    response = {
        "status": "success",
        "message": f"Đã lưu thành công {len(deduped_rules)} luật",
        "rules_count": len(deduped_rules),
        "db_synced": db_success,
        "file_path": RULES_FILE_PATH
    }
    if db_sync_errors:
        response["db_warnings"] = db_sync_errors[:5]
    return response


def update_rule(sid, fields, username='unknown', ip='N/A'):
    """
    Update a single rule by SID.
    fields: dict with optional keys: action, protocol, msg, content, dst_port,
            rev, priority, classtype, flow, raw_rule
    Returns {"status", "message", "sid"} or {"status": "error", ...}
    """
    sid = int(sid)
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    lines = content.split('\n')

    updated = False
    new_lines = []
    old_rule_str = ""

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            new_lines.append(line)
            continue

        sid_match = SID_REGEX.search(line_stripped)
        if sid_match and int(sid_match.group(1)) == sid:
            old_rule_str = line_stripped
            updated = True
            new_raw = fields.get('raw_rule', '').strip()

            if new_raw:
                new_raw = ' '.join(new_raw.replace('\r', ' ').replace('\n', ' ').split())
                is_valid, err = _validate_rule(new_raw)
                if not is_valid:
                    return {"status": "error", "message": f"Luật mới không hợp lệ: {err}"}
                new_sid_match = SID_REGEX.search(new_raw)
                if not new_sid_match or int(new_sid_match.group(1)) != sid:
                    return {"status": "error", "message": "SID trong raw_rule không khớp với SID yêu cầu"}
                new_lines.append(new_raw)
            else:
                parsed = parse_snort_rule(line_stripped)
                new_action = fields.get('action', '').upper().strip()
                new_protocol = fields.get('protocol', '').lower().strip()
                new_msg = fields.get('msg', fields.get('name', '')).strip()
                new_content = fields.get('content', fields.get('pattern', '')).strip()
                new_dst_port = fields.get('dst_port', '').strip()
                new_rev = fields.get('rev')
                new_priority = fields.get('priority')
                new_classtype = fields.get('classtype', '').strip()
                new_flow = fields.get('flow', '').strip()

                action = new_action.lower() if new_action else (parsed.get('action', 'alert').lower() if parsed else 'alert')
                protocol = new_protocol if new_protocol else (parsed.get('protocol', 'tcp') if parsed else 'tcp')
                msg = re.sub(r'[^\w\s\-/\.\[\]{}()!@#$%^&+=]', '', new_msg)[:500] if new_msg else (parsed.get('msg', '') if parsed else '')
                dst_port = new_dst_port if new_dst_port else 'any'
                rev = int(new_rev) if new_rev is not None else (parsed.get('rev', 1) if parsed else 1) + 1
                priority = int(new_priority) if new_priority is not None else (parsed.get('priority', 3) if parsed else 3)
                classtype = re.sub(r'[^\w\-]', '', new_classtype)[:100] if new_classtype else (parsed.get('classtype', 'web-application-attack') if parsed else 'web-application-attack')
                flow_str = new_flow if new_flow else (parsed.get('flow', 'to_server') if parsed else 'to_server')
                content_str = new_content if new_content else (parsed.get('content', '') if parsed else '')

                if not msg:
                    msg = "No_Name"
                content_part = f'content:"{content_str}", nocase; ' if content_str else ''

                updated_rule = (
                    f'{action} {protocol} $EXTERNAL_NET any -> $HOME_NET {dst_port} '
                    f'(msg:"[{action.upper()}] {msg}"; '
                    f'flow:{flow_str}; '
                    f'{content_part}'
                    f'classtype:{classtype}; '
                    f'sid:{sid}; '
                    f'rev:{rev}; '
                    f'priority:{priority};)'
                )
                new_lines.append(updated_rule)
        else:
            new_lines.append(line)

    if not updated:
        return {"status": "error", "message": f"Không tìm thấy luật với SID {sid}"}

    file_content = '\n'.join(new_lines)
    write_ok, write_err = safe_write_file(RULES_FILE_PATH, file_content)
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    try:
        conn = _get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE rules SET raw_rule = %s, action = %s, protocol = %s, msg = %s, rev = %s WHERE sid = %s AND source = 'local_custom'",
                (new_lines[next(i for i, l in enumerate(new_lines) if SID_REGEX.search(l) and int(SID_REGEX.search(l).group(1)) == sid)],
                 fields.get('action', 'alert').lower() if fields.get('action') else 'alert',
                 fields.get('protocol', 'tcp') if fields.get('protocol') else 'tcp',
                 fields.get('msg', 'Updated rule')[:200] if fields.get('msg') else 'Updated rule',
                 int(fields.get('rev', 1)), sid)
            )
            conn.commit()
            conn.close()
    except Exception as db_e:
        logger.warning(f"[RULES] DB update warning: {db_e}")

    _add_audit_log("UPDATE", sid, f"Cập nhật luật SID {sid}", username, ip)
    _trigger_snort_reload()
    return {"status": "success", "message": f"Đã cập nhật luật SID {sid}", "sid": sid}


def delete_rule(sid, username='unknown', ip='N/A'):
    """Delete a rule by SID. Returns {"status", "message"}"""
    sid = int(sid)
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    lines = content.split('\n')

    new_lines = []
    removed = False
    for line in lines:
        sid_match = SID_REGEX.search(line)
        if sid_match and int(sid_match.group(1)) == sid:
            removed = True
            continue
        new_lines.append(line)

    if not removed:
        return {"status": "error", "message": f"Không tìm thấy luật với SID {sid}"}

    write_ok, write_err = safe_write_file(RULES_FILE_PATH, '\n'.join(new_lines))
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    try:
        conn = _get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rules WHERE sid = %s", (sid,))
            conn.commit()
            conn.close()
    except Exception as db_e:
        logger.warning(f"[RULES] DB delete warning: {db_e}")

    _add_audit_log("DELETE", sid, f"Xóa luật SID {sid}", username, ip)
    return {"status": "success", "message": f"Đã xóa luật SID {sid}"}


def toggle_rule(sid, enabled, username='unknown', ip='N/A'):
    """Toggle rule enabled/disabled. Returns {"status", "message", "sid", "enabled"}"""
    sid = int(sid)
    enabled = bool(enabled)
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    lines = content.split('\n')

    new_lines = []
    toggled = False

    for line in lines:
        sid_match = SID_REGEX.search(line)
        if sid_match and int(sid_match.group(1)) == sid:
            toggled = True
            if enabled:
                # If it starts with '# DISABLED: ' or '#DISABLED:', strip it
                if re.match(r'^#\s*DISABLED:\s*', line.strip(), re.IGNORECASE):
                    uncommented = re.sub(r'^#\s*DISABLED:\s*', '', line.strip(), flags=re.IGNORECASE)
                    new_lines.append(uncommented)
                # Or if it's commented out but otherwise starts with a valid Snort action
                elif line.strip().startswith('#'):
                    potential_rule = re.sub(r'^#\s*', '', line.strip())
                    first_word = potential_rule.split()[0] if potential_rule.split() else ''
                    if first_word.lower() in VALID_SNORT_ACTIONS:
                        new_lines.append(potential_rule)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            else:
                if not line.strip().startswith('#'):
                    new_lines.append('# DISABLED: ' + line)
                else:
                    new_lines.append(line)
        else:
            new_lines.append(line)

    if not toggled:
        return {"status": "error", "message": f"Không tìm thấy luật với SID {sid}"}

    write_ok, write_err = safe_write_file(RULES_FILE_PATH, '\n'.join(new_lines))
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    action_toggle = "ENABLE" if enabled else "DISABLE"
    _add_audit_log(action_toggle, sid, f"{'Bật' if enabled else 'Tắt'} luật SID {sid}", username, ip)
    _trigger_snort_reload()
    return {"status": "success", "message": f"Đã {'bật' if enabled else 'tắt'} luật SID {sid}", "sid": sid, "enabled": enabled}


def import_rules(raw_text, mode='append', category='imported', username='unknown', ip='N/A'):
    """Import rules from raw Snort text. Returns {"status", ...}"""
    if not raw_text or not isinstance(raw_text, str):
        return {"status": "error", "message": "Nội dung nhập rỗng"}

    if len(raw_text) > 500000:
        return {"status": "error", "message": "Nội dung quá lớn (tối đa 500KB)"}

    # Format raw_text to merge any multiline rules and normalize spaces
    formatted_lines = []
    current_rule = ""
    for line in raw_text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            if current_rule:
                formatted_lines.append(current_rule)
                current_rule = ""
            continue
        
        words = stripped.split()
        if words and words[0].lower() in ['alert', 'drop', 'log', 'pass', 'reject', 'sdrop', 'activate', 'dynamic']:
            if current_rule:
                formatted_lines.append(current_rule)
            current_rule = stripped
        else:
            if current_rule:
                current_rule = current_rule + " " + stripped
            else:
                formatted_lines.append(stripped)
                
        if current_rule and current_rule.endswith(')'):
            formatted_lines.append(current_rule)
            current_rule = ""
    if current_rule:
        formatted_lines.append(current_rule)
        
    rule_lines = []
    for line in formatted_lines:
        cleaned = " ".join(line.split())
        if cleaned:
            rule_lines.append(cleaned)

    if not rule_lines:
        return {"status": "error", "message": "Không tìm thấy luật hợp lệ trong nội dung nhập"}

    imported_rules = []
    import_errors = []
    for i, line in enumerate(rule_lines):
        is_valid, err = _validate_rule(line)
        if is_valid:
            imported_rules.append(line)
        else:
            import_errors.append({"line": i + 1, "error": err, "content": line[:100]})

    if not imported_rules:
        return {"status": "error", "message": "Không có luật hợp lệ để nhập", "errors": import_errors[:20]}

    existing_content, _ = safe_read_file(RULES_FILE_PATH, "")
    existing_rules = []
    if mode == 'append' and existing_content:
        for line in existing_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                existing_rules.append(line)

    all_rules = existing_rules + imported_rules
    seen_sids = set()
    deduped_rules = []
    duplicate_count = 0
    for rule in all_rules:
        sid_match = SID_REGEX.search(rule)
        if sid_match:
            sid = int(sid_match.group(1))
            if sid not in seen_sids:
                seen_sids.add(sid)
                deduped_rules.append(rule)
            else:
                duplicate_count += 1
        else:
            deduped_rules.append(rule)

    header_lines = [
        "# ==================================================================",
        "# BK-IDS SOC: SNORT 3 LOCAL RULES — Enterprise Edition",
        f"# Tạo lúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Tổng luật: {len(deduped_rules)}",
        f"# Nhập: {len(imported_rules)} luật mới, {duplicate_count} bị trùng bỏ qua",
        "# ==================================================================\n"
    ]
    file_content = '\n'.join(header_lines + [''] + deduped_rules + [''])
    write_ok, write_err = safe_write_file(RULES_FILE_PATH, file_content)
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    db_success, db_errors = _sync_rules_to_db(deduped_rules)
    _add_audit_log("IMPORT", 0, f"Nhập {len(imported_rules)} luật (mode={mode}, category={category})", username, ip)
    _trigger_snort_reload()

    response = {
        "status": "success",
        "message": f"Đã nhập {len(imported_rules)} luật (bỏ qua {duplicate_count} trùng)",
        "imported_count": len(imported_rules),
        "duplicate_count": duplicate_count,
        "total_rules": len(deduped_rules),
        "validation_errors": import_errors[:10],
        "db_synced": db_success
    }
    if db_errors:
        response["db_warnings"] = db_errors[:5]
    return response


def export_rules(fmt='json', enabled_only=False):
    """Export rules in json, snort, or csv format. Returns dict or (text, headers)."""
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    rules = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('# DISABLED'):
            rules.append(line)
        elif line and line.startswith('# DISABLED'):
            if not enabled_only:
                uncommented = re.sub(r'^#\s*DISABLED:\s*', '', line)
                rules.append(uncommented)
        elif line and not line.startswith('#') and not enabled_only:
            if line not in rules:
                rules.append(line)

    if fmt == 'snort':
        header = f"# BK-IDS SOC — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n# Tổng luật: {len(rules)}\n"
        return {"format": "snort", "content": header + '\n'.join(rules), "count": len(rules)}

    elif fmt == 'csv':
        csv_lines = "sid,action,protocol,msg,raw_rule"
        for rule in rules:
            parsed = parse_snort_rule(rule)
            if parsed:
                msg_escaped = parsed.get('msg', '').replace('"', '""')
                rule_escaped = rule.replace('"', '""')
                csv_lines += f"\n{parsed['sid']},{parsed['action']},{parsed['protocol']},\"{msg_escaped}\",\"{rule_escaped}\""
            else:
                rule_escaped = rule.replace('"', '""')
                csv_lines += f"\n0,UNKNOWN,unknown,,\"{rule_escaped}\""
        return {"format": "csv", "content": csv_lines, "count": len(rules)}

    else:  # json
        return {
            "format": "json",
            "exported_at": datetime.now().isoformat(),
            "count": len(rules),
            "rules": [parse_snort_rule(r) for r in rules]
        }


def bulk_delete_rules(sids, username='unknown', ip='N/A'):
    """Delete multiple rules by SID list. Returns {"status", "removed_count", ...}"""
    sids_set = set(int(s) for s in sids)
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    lines = content.split('\n')

    new_lines = []
    removed_count = 0
    for line in lines:
        sid_match = SID_REGEX.search(line)
        if sid_match and int(sid_match.group(1)) in sids_set:
            removed_count += 1
            continue
        new_lines.append(line)

    write_ok, write_err = safe_write_file(RULES_FILE_PATH, '\n'.join(new_lines))
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    db_deleted = 0
    try:
        conn = _get_db_conn()
        if conn:
            cursor = conn.cursor()
            placeholders = ','.join(['%s'] * len(sids))
            cursor.execute(f"DELETE FROM rules WHERE sid IN ({placeholders})", tuple(sids))
            db_deleted = cursor.rowcount
            conn.commit()
            conn.close()
    except Exception as db_e:
        logger.warning(f"[RULES] DB bulk delete warning: {db_e}")

    _add_audit_log("BULK_DELETE", 0, f"Xóa hàng loạt {removed_count} luật", username, ip)
    return {"status": "success", "message": f"Đã xóa {removed_count} luật", "removed_count": removed_count, "requested_count": len(sids), "db_deleted": db_deleted}


def bulk_toggle_rules(sids, enabled, username='unknown', ip='N/A'):
    """Toggle multiple rules by SID list. Returns {"status", "toggled_count", ...}"""
    sids_set = set(int(s) for s in sids)
    enabled = bool(enabled)
    content, _ = safe_read_file(RULES_FILE_PATH, "")
    lines = content.split('\n')

    new_lines = []
    toggled_count = 0
    for line in lines:
        sid_match = SID_REGEX.search(line)
        if sid_match and int(sid_match.group(1)) in sids_set:
            toggled_count += 1
            if enabled:
                uncommented = re.sub(r'^#\s*(DISABLED:\s*)?', '', line)
                new_lines.append(uncommented)
            else:
                if not line.strip().startswith('#'):
                    new_lines.append('# DISABLED: ' + line)
                else:
                    new_lines.append(line)
        else:
            new_lines.append(line)

    write_ok, write_err = safe_write_file(RULES_FILE_PATH, '\n'.join(new_lines))
    if not write_ok:
        return {"status": "error", "message": f"Lỗi ghi file: {write_err}"}

    _add_audit_log("BULK_TOGGLE", 0, f"{'Bật' if enabled else 'Tắt'} hàng loạt {toggled_count} luật", username, ip)
    _trigger_snort_reload()
    return {"status": "success", "message": f"Đã {'bật' if enabled else 'tắt'} {toggled_count} luật", "toggled_count": toggled_count, "enabled": enabled}


def get_templates():
    """Return enterprise rule templates."""
    templates = _get_rule_templates()
    return {
        "status": "success",
        "categories": list(templates.keys()),
        "templates": templates,
        "total": sum(len(v) for v in templates.values())
    }


def get_audit_log(limit=100):
    """Get audit log entries."""
    try:
        if not os.path.exists(RULES_AUDIT_PATH):
            return []
        content, _ = safe_read_file(RULES_AUDIT_PATH, "[]")
        entries = json.loads(content) if content else []
        return entries[-limit:]
    except Exception as e:
        logger.warning(f"[RULES] Audit log read error: {e}")
        return []
