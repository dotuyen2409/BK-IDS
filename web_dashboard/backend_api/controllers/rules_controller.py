# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/rules_controller.py

import sys
import os
import json
import logging
import subprocess
import re
import pymysql

from flask import request, jsonify

sys.path.append('/app')
import threat_intel_updater

logger = logging.getLogger(__name__)

RULE_JSON_PATH = '/app/core_engine/rules_db.json'
SNORT_RULES_PATH = '/app/core_engine/local.rules' 

DB_HOST = 'mysql_db' 
DB_USER = 'root'
DB_PASS = 'rootpassword' # Thay bằng mật khẩu thực tế
DB_NAME = 'bk_ids'
DB_TABLE = 'rules'

def sanitize_name(text):
    if not text: return "Unknown Threat"
    return re.sub(r'[^\w\s\-]', '', str(text)).strip()

def sanitize_pattern(text):
    if not text: return ""
    text = str(text)
    # 🎯 FIX LỖI: Nếu là luật nguyên bản (Raw Rule), tuyệt đối không chèn thêm dấu \ làm hỏng cấu trúc
    if "->" in text and "msg:" in text:
        return text
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;')
    return text

def trigger_system_reload():
    try:
        subprocess.run(["pkill", "-SIGHUP", "-f", "snort"], check=False)
        logger.info("🔄 Đã gửi lệnh Hot-Reload tới Lõi Snort 3.")
    except Exception as e:
        logger.warning(f"Không thể gửi tín hiệu nạp lại tới Snort: {e}")

def generate_snort_rules_from_db():
    """ 🎯 ĐỌC LUẬT TỪ DATABASE VÀ XUẤT RA FILE (Tránh rác từ file JSON) """
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
        cursor = conn.cursor()
        cursor.execute(f"SELECT raw_rule FROM {DB_TABLE} WHERE source='local_custom' ORDER BY id ASC")
        db_rules = cursor.fetchall()
        conn.close()

        snort_lines = [
            "# ==================================================================",
            "# BK-IDS SOC: TỆP LUẬT SNORT 3 (LOCAL RULES)",
            "# Tự động đồng bộ từ Database - Không chỉnh sửa thủ công",
            "# ==================================================================\n"
        ]
        
        for r in db_rules:
            if r['raw_rule']:
                # Dọn dẹp rác (nếu có do lưu lỗi từ trước)
                clean_rule = r['raw_rule'].replace('\\"', '"').replace('\\;', ';')
                snort_lines.append(clean_rule)

        os.makedirs(os.path.dirname(SNORT_RULES_PATH), exist_ok=True)
        with open(SNORT_RULES_PATH, 'w', encoding='utf-8') as f:
            f.write('\n'.join(snort_lines))
            # Ép hệ thống xả bộ nhớ, ghi thẳng xuống ổ đĩa vật lý
            f.flush()
            os.fsync(f.fileno()) 
            
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
            # Trả về luật sạch cho Web hiển thị
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
        
        # 1. Vẫn lưu JSON để Backup
        os.makedirs(os.path.dirname(RULE_JSON_PATH), exist_ok=True)
        with open(RULE_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=4, ensure_ascii=False)
            
        # 2. Lưu vào DB làm nguồn chân lý
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
                    # 🎯 VÁ LỖI CÚ PHÁP SNORT 3: content:"...", nocase;
                    raw_rule = f'{"drop" if action_web == "DROP" else "alert"} {protocol} any any -> any any (msg:"[{action_web}] {name}"; content:"{pattern_safe}", nocase; classtype:web-application-attack; sid:{sid_counter}; rev:5;)'
                
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

        # 3. Xuất file local.rules thẳng từ DB (Tự động cập nhật file)
        generate_snort_rules_from_db()
        
        trigger_system_reload()
        return jsonify({'status': 'success', 'message': 'Đã lưu đồng bộ vào Database và xuất file local.rules thành công! Snort 3 đang nạp lại.'}), 200
    except Exception as e:
        logger.error(f"Lỗi biên dịch luật: {e}")
        return jsonify({'status': 'error', 'message': "Lỗi máy chủ khi biên dịch luật."}), 500

def update_rules_online():
    pass