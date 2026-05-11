# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/rules_controller.py

import sys
import os
import json
import logging
import subprocess
import re
import pymysql
import threading
import time
from flask import request, jsonify

sys.path.append('/app')
try:
    import threat_intel_updater
except: pass

logger = logging.getLogger(__name__)

RULE_JSON_PATH = '/app/core_engine/rules_db.json'
SNORT_RULES_PATH = '/app/core_engine/local.rules' 

DB_HOST = 'mysql_db' 
DB_USER = 'root'
DB_PASS = 'rootpassword' 
DB_NAME = 'bk_ids'
DB_TABLE = 'rules'

# 🎯 BIẾN TOÀN CỤC CHO ĐỒNG BỘ HAI CHIỀU
LAST_SYNC_MTIME = 0
WATCHER_STARTED = False

# ========================================================================
# CƠ CHẾ ĐỒNG BỘ NGƯỢC (FILE -> DATABASE)
# ========================================================================
def sync_file_to_db_core():
    global LAST_SYNC_MTIME
    try:
        if not os.path.exists(SNORT_RULES_PATH): return

        with open(SNORT_RULES_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        cursor = conn.cursor()

        for line in lines:
            line = line.strip()
            # Bỏ qua dòng trống, comment và luật whitelist tự sinh
            if not line or line.startswith('#') or line.startswith('pass ip'):
                continue

            # Bóc tách SID và Message bằng Regex
            sid_match = re.search(r'sid\s*:\s*(\d+)\s*;', line, re.IGNORECASE)
            msg_match = re.search(r'msg\s*:\s*"([^"]+)"\s*;', line, re.IGNORECASE)

            if sid_match and msg_match:
                sid = int(sid_match.group(1))
                msg = msg_match.group(1)
                
                # Chỉ đồng bộ các SID dành cho Custom Rules (>= 1000000)
                if sid < 1000000: continue

                # Bóc tách Action (alert/drop) và Protocol (tcp/udp/icmp/ip)
                parts = line.split()
                action = parts[0].upper() if len(parts) > 0 else 'ALERT'
                protocol = parts[1].lower() if len(parts) > 1 else 'tcp'

                # Ghi đè hoặc thêm mới vào Database
                sql = f"""
                    INSERT INTO {DB_TABLE} (sid, rev, action, protocol, msg, raw_rule, source) 
                    VALUES (%s, 1, %s, %s, %s, %s, 'local_custom')
                    ON DUPLICATE KEY UPDATE 
                    action=VALUES(action), protocol=VALUES(protocol), msg=VALUES(msg), raw_rule=VALUES(raw_rule)
                """
                cursor.execute(sql, (sid, action, protocol, msg, line))

        conn.commit()
        conn.close()
        logger.info("🔄 [TWO-WAY SYNC] Đã đồng bộ ngược từ File local.rules lên Website thành công!")
        
        # Cập nhật mtime để vòng lặp tiếp theo không quét lại chính nó
        LAST_SYNC_MTIME = os.stat(SNORT_RULES_PATH).st_mtime
        
    except Exception as e:
        logger.error(f"❌ Lỗi khi đồng bộ File -> Database: {e}")

def file_watcher_worker():
    global LAST_SYNC_MTIME
    while True:
        time.sleep(3) # Quét 3 giây 1 lần
        try:
            if os.path.exists(SNORT_RULES_PATH):
                current_mtime = os.stat(SNORT_RULES_PATH).st_mtime
                if LAST_SYNC_MTIME == 0:
                    LAST_SYNC_MTIME = current_mtime # Khởi tạo lần đầu
                elif current_mtime != LAST_SYNC_MTIME:
                    logger.info("👀 Phát hiện thay đổi thủ công trong local.rules. Tiến hành đồng bộ...")
                    time.sleep(1) # Đợi người dùng Save file hoàn tất
                    sync_file_to_db_core()
                    LAST_SYNC_MTIME = os.stat(SNORT_RULES_PATH).st_mtime
        except Exception: pass

# Khởi chạy tiểu trình giám sát ngầm
if not WATCHER_STARTED:
    threading.Thread(target=file_watcher_worker, daemon=True).start()
    WATCHER_STARTED = True

# ========================================================================
# CÁC HÀM XỬ LÝ LÕI (GIỮ NGUYÊN)
# ========================================================================
def get_whitelist_from_env():
    paths = ['/home/bk_ids/bk-ids/.env', '/app/.env', '.env']
    for path in paths:
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f:
                    if line.strip().startswith("WHITELIST_IPS="):
                        ips = line.split('=', 1)[1].strip().strip('"\'').split(',')
                        return [ip.strip() for ip in ips if ip.strip()]
    return ["192.168.142.1"]

def sanitize_name(text):
    if not text: return "Unknown Threat"
    return re.sub(r'[^\w\s\-]', '', str(text)).strip()

def sanitize_pattern(text):
    if not text: return ""
    text = str(text)
    if "->" in text and "msg:" in text: return text.strip()
    text = text.replace('"', '\\"')
    return text.strip()

def trigger_system_reload():
    try:
        subprocess.run(["pkill", "-TERM", "-f", "snort"], check=False)
        logger.info("🔄 Đã gửi lệnh Hot-Reload tới Lõi Snort 3.")
    except Exception as e:
        logger.warning(f"Không thể gửi tín hiệu nạp lại tới Snort: {e}")

def generate_snort_rules_from_db():
    global LAST_SYNC_MTIME
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
        cursor = conn.cursor()
        cursor.execute(f"SELECT raw_rule FROM {DB_TABLE} WHERE source='local_custom' ORDER BY id ASC")
        db_rules = cursor.fetchall()
        conn.close()

        snort_lines = [
            "# ==================================================================",
            "# BK-IDS SOC: TỆP LUẬT SNORT 3 (LOCAL RULES)",
            "# ĐÃ KÍCH HOẠT ĐỒNG BỘ 2 CHIỀU (FILE <-> DATABASE)",
            "# ==================================================================\n"
        ]
        
        whitelist_ips = get_whitelist_from_env()
        pass_sid = 100000
        snort_lines.append("# --- KIM BÀI MIỄN TỬ (WHITELIST TỪ .ENV) ---")
        for ip in whitelist_ips:
            snort_lines.append(f"pass ip {ip} any <> any any (msg:\"Bypass Whitelist IP {ip}\"; sid:{pass_sid}; rev:1;)")
            pass_sid += 1
        snort_lines.append("# -------------------------------------------\n")

        for r in db_rules:
            if r['raw_rule']:
                clean_rule = r['raw_rule'].replace('\\"', '"').replace('\\;', ';')
                snort_lines.append(clean_rule)

        os.makedirs(os.path.dirname(SNORT_RULES_PATH), exist_ok=True)
        with open(SNORT_RULES_PATH, 'w', encoding='utf-8') as f:
            f.write('\n'.join(snort_lines))
            f.flush()
            os.fsync(f.fileno()) 
            
        # 🎯 CHỐNG LOOP: Cập nhật MTIME ngay sau khi Web ghi đè để Thread không kéo ngược lại
        LAST_SYNC_MTIME = os.stat(SNORT_RULES_PATH).st_mtime
            
    except Exception as e:
        logger.error(f"Lỗi khi xuất file local.rules: {e}")

def get_rules():
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
        cursor = conn.cursor()
        cursor.execute(f"SELECT action, protocol, dst_port, msg, raw_rule, source FROM {DB_TABLE} ORDER BY id DESC")
        db_rules = cursor.fetchall()
        conn.close()

        formatted_rules = []
        for r in db_rules:
            is_local_flag = True if r.get('source') == 'local_custom' else False
            clean_pattern = r['raw_rule'].replace('\\"', '"').replace('\\;', ';') if r['raw_rule'] else ""

            formatted_rules.append({
                "action": r['action'],
                "protocol": r['protocol'],
                "dst_port": r['dst_port'] if r['dst_port'] else "any",
                "name": r['msg'],
                "pattern": clean_pattern,
                "is_local": is_local_flag
            })
        return jsonify({'status': 'success', 'data': formatted_rules}), 200
    except Exception as e:
        logger.error(f"Lỗi đọc Database MySQL: {e}")
        if os.path.exists(RULE_JSON_PATH):
            with open(RULE_JSON_PATH, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            return jsonify({'status': 'success', 'data': rules, 'warning': 'Lỗi DB, đang dùng file tĩnh'}), 200
        return jsonify({'status': 'error', 'message': f"Lỗi đọc DB: {str(e)}"}), 500

def save_rules():
    try:
        data = request.get_json()
        if not data or 'rules' not in data:
            return jsonify({'status': 'error', 'message': 'Dữ liệu luật không hợp lệ.'}), 400
            
        rules = data.get('rules', [])
        
        os.makedirs(os.path.dirname(RULE_JSON_PATH), exist_ok=True)
        with open(RULE_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=4, ensure_ascii=False)
            
        try:
            conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
            cursor = conn.cursor()

            cursor.execute(f"DELETE FROM {DB_TABLE} WHERE source='local_custom'")
            sid_counter = 1000001
            
            for r in rules:
                raw_action = str(r.get('action', 'ALERT')).upper().strip()
                action_web = "DROP" if raw_action in ["DROP", "BLOCK", "CHẶN"] else "ALERT"
                protocol = str(r.get('protocol', 'tcp')).lower()
                name = sanitize_name(r.get('name'))
                
                raw_pattern = r.get('pattern') or r.get('content') or r.get('raw_rule')
                if not raw_pattern: continue
                
                pattern_safe = sanitize_pattern(raw_pattern)
                
                if re.search(r'sid\s*:\s*(?!1000\d+)\d+', pattern_safe, re.IGNORECASE):
                    continue
                if len(pattern_safe) > 1000:
                    continue
                
                if "->" in pattern_safe and "msg:" in pattern_safe:
                    raw_rule = pattern_safe
                    raw_rule = re.sub(r'sid\s*:\s*\d+', f'sid:{sid_counter}', raw_rule, flags=re.IGNORECASE)
                else:
                    raw_rule = (
                        f'{"drop" if action_web == "DROP" else "alert"} '
                        f'{protocol} any any -> any any '
                        f'(msg:"[{action_web}] {name}"; '
                        f'content:"{pattern_safe}",nocase; ' # 🎯 ĐÃ SỬA DẤU PHẨY THÀNH CHẤM PHẨY Ở ĐÂY
                        f'classtype:web-application-attack; '
                        f'sid:{sid_counter}; rev:5;)'
                    )
                
                sql = f"""
                    INSERT INTO {DB_TABLE} (sid, rev, action, protocol, msg, raw_rule, source) 
                    VALUES (%s, 5, %s, %s, %s, %s, 'local_custom')
                    ON DUPLICATE KEY UPDATE 
                    action=VALUES(action), protocol=VALUES(protocol), msg=VALUES(msg), raw_rule=VALUES(raw_rule), source=VALUES(source)
                """
                cursor.execute(sql, (sid_counter, action_web, protocol, name, raw_rule))
                sid_counter += 1
                
            conn.commit()
            conn.close()
        except Exception as db_e:
            logger.error(f"Lỗi khi lưu Database MySQL: {db_e}")
            return jsonify({'status': 'error', 'message': f"Lỗi Database: {str(db_e)}"}), 500

        generate_snort_rules_from_db()
        trigger_system_reload()
        
        return jsonify({'status': 'success', 'message': 'Đã lưu luật và cấp Kim bài miễn tử thành công!'}), 200
    except Exception as e:
        logger.error(f"Lỗi biên dịch luật: {e}")
        return jsonify({'status': 'error', 'message': "Lỗi máy chủ khi biên dịch luật."}), 500

def update_rules_online():
    pass