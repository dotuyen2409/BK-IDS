# /home/ids/bk_ids/core_engine/sync_rules_to_db.py
"""
BK-IDS SOC: Sync Rules to Database
===================================
Standalone script to sync rules from local.rules to MySQL.
Now imports SSOT from rule_compiler — no duplicate logic.
"""

import sys
import os
import logging

sys.path.insert(0, '/app/core_engine')

from rule_compiler import (
    SNORT_RULES_PATH,
    RULES_FILE_PATH,
    _get_db_conn,
    SID_REGEX,
    ACTION_REGEX,
    PROTO_REGEX,
    MSG_REGEX,
    REV_REGEX,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [SYNC-ENGINE] %(levelname)s - %(message)s')
logger = logging.getLogger("Bk-IDS-Sync")

# Map file paths to source labels
RULE_FILES = [
    (os.path.join(os.path.dirname(SNORT_RULES_PATH), 'pulled_rules.rules'), 'talos_community'),
    (RULES_FILE_PATH, 'local_custom'),
]


def parse_snort_rule_for_sync(line, source_name):
    """Parse a Snort rule line for DB sync. Delegates to rule_compiler for regex."""
    import re as _re
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    sid_match = SID_REGEX.search(line)
    action_match = ACTION_REGEX.match(line)
    proto_match = PROTO_REGEX.match(line)
    msg_match = MSG_REGEX.search(line)
    rev_match = REV_REGEX.search(line)

    if not sid_match:
        return None

    return (
        int(sid_match.group(1)),
        int(rev_match.group(1)) if rev_match else 1,
        action_match.group(1).upper() if action_match else 'ALERT',
        proto_match.group(1).lower() if proto_match else 'tcp',
        msg_match.group(1) if msg_match else 'Unknown Threat',
        line,
        source_name
    )


def sync_to_database():
    """Read rule files and sync to MySQL."""
    valid_rules = []
    skipped_count = 0

    for file_path, source_name in RULE_FILES:
        if not os.path.exists(file_path):
            logger.warning(f"Bỏ qua: Không tìm thấy file {file_path}")
            continue

        logger.info(f"Đang phân tích file luật từ {file_path} (Nguồn: {source_name})...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_snort_rule_for_sync(line, source_name)
                    if parsed:
                        valid_rules.append(parsed)
                    elif line.strip() and not line.strip().startswith('#'):
                        skipped_count += 1
        except Exception as e:
            logger.error(f"Lỗi đọc file {file_path}: {e}")

    total_rules = len(valid_rules)
    if total_rules == 0:
        logger.warning("Không có luật hợp lệ nào để đồng bộ. Hủy bỏ quá trình.")
        return

    logger.info(f"Phân tích hoàn tất: Lấy được {total_rules} luật (Bỏ qua {skipped_count} dòng lỗi cú pháp).")
    logger.info("Bắt đầu khởi tạo Transaction ghi vào Database...")

    conn = None
    try:
        conn = _get_db_conn()
        if not conn:
            logger.error("Không thể kết nối database")
            return

        cursor = conn.cursor()
        query = """
            INSERT INTO rules (sid, rev, action, protocol, msg, raw_rule, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            rev=VALUES(rev), action=VALUES(action), protocol=VALUES(protocol),
            msg=VALUES(msg), raw_rule=VALUES(raw_rule), source=VALUES(source), updated_at=NOW()
        """

        BATCH_SIZE = 500
        for i in range(0, total_rules, BATCH_SIZE):
            batch = valid_rules[i:i + BATCH_SIZE]
            cursor.executemany(query, batch)
            conn.commit()
            logger.info(f"🚀 Đã đồng bộ {min(i + BATCH_SIZE, total_rules)} / {total_rules} luật...")

        cursor.close()
        logger.info("✅ ĐỒNG BỘ DATA PIPELINE HOÀN TẤT 100%!")
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"❌ Lỗi Transaction Database: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == '__main__':
    sync_to_database()
