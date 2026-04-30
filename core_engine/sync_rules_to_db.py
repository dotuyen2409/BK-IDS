# /home/bk_ids/bk-ids/core_engine/sync_rules_to_db.py

import re
import pymysql
import logging
import os

# ==========================================
# CẤU HÌNH ENTERPRISE (BẢO MẬT & ĐỘNG)
# ==========================================
# 🎯 NÂNG CẤP: Không hardcode. Ưu tiên lấy từ biến môi trường (Environment Variables)
DB_HOST = os.environ.get('MYSQL_HOST', 'localhost') 
DB_USER = os.environ.get('MYSQL_USER', 'root')
DB_PASS = os.environ.get('MYSQL_PASSWORD', 'rootpassword') 
DB_NAME = os.environ.get('MYSQL_DATABASE', 'bk_ids') 
DB_TABLE = 'rules' 

RULE_FILES = [
    ('/home/bk_ids/bk-ids/core_engine/pulled_rules.rules', 'talos_community'),
    ('/home/bk_ids/bk-ids/core_engine/local.rules', 'local_custom')
]

BATCH_SIZE = 500 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [SYNC-ENGINE] %(levelname)s - %(message)s')

def parse_snort_rule(line, source_name):
    """ 
    Bóc tách các trường của 1 rule và gán nhãn nguồn gốc 
    🎯 NÂNG CẤP: Hỗ trợ Regex chuẩn Snort 3 (thêm block, rewrite, react)
    """
    line = line.strip()
    # Bỏ qua dòng trống hoặc comment
    if not line or line.startswith('#'): return None
    
    # Nhận diện Header Snort 3 (hỗ trợ nhiều khoảng trắng hơn)
    pattern = re.compile(
        r'^\s*(alert|drop|block|log|pass|rewrite|react|reject|sdrop)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)', 
        re.IGNORECASE
    )
    match = pattern.match(line)
    if not match: return None
    
    action, proto, src_ip, src_port, direction, dst_ip, dst_port, options = match.groups()
    
    # 🎯 NÂNG CẤP: Xử lý linh hoạt việc MSG có thể có hoặc không có dấu ngoặc kép
    msg_match = re.search(r'msg\s*:\s*"?([^";]+)"?', options, re.IGNORECASE)
    sid_match = re.search(r'sid\s*:\s*(\d+)', options, re.IGNORECASE)
    rev_match = re.search(r'rev\s*:\s*(\d+)', options, re.IGNORECASE)
    
    # Luật bắt buộc phải có SID
    if not sid_match: return None 
    
    return (
        int(sid_match.group(1)),
        int(rev_match.group(1)) if rev_match else 1,
        action.upper(),
        proto.upper(),
        src_ip, src_port, dst_ip, dst_port,
        msg_match.group(1).strip() if msg_match else 'Unknown Threat',
        line,
        source_name 
    )

def sync_to_database():
    valid_rules = []
    skipped_count = 0
    
    for file_path, source_name in RULE_FILES:
        if not os.path.exists(file_path):
            logging.warning(f"Bỏ qua: Không tìm thấy file {file_path}")
            continue
            
        logging.info(f"Đang phân tích file luật từ {file_path} (Nguồn: {source_name})...")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_snort_rule(line, source_name)
                    if parsed: 
                        valid_rules.append(parsed)
                    elif line.strip() and not line.strip().startswith('#'):
                        skipped_count += 1
        except Exception as e:
            logging.error(f"Lỗi đọc file {file_path}: {e}")

    total_rules = len(valid_rules)
    if total_rules == 0:
        logging.warning("Không có luật hợp lệ nào để đồng bộ. Hủy bỏ quá trình.")
        return

    logging.info(f"Phân tích hoàn tất: Lấy được {total_rules} luật (Bỏ qua {skipped_count} dòng lỗi cú pháp).")
    logging.info("Bắt đầu khởi tạo Transaction ghi vào Database...")

    query = f"""
        INSERT INTO {DB_TABLE} 
        (sid, rev, action, protocol, src_ip, src_port, dst_ip, dst_port, msg, raw_rule, source) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
        rev=VALUES(rev), action=VALUES(action), protocol=VALUES(protocol), 
        src_ip=VALUES(src_ip), src_port=VALUES(src_port), dst_ip=VALUES(dst_ip), dst_port=VALUES(dst_port),
        msg=VALUES(msg), raw_rule=VALUES(raw_rule), source=VALUES(source), updated_at=NOW()
    """

    conn = None
    try:
        conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME)
        cursor = conn.cursor()
        
        for i in range(0, total_rules, BATCH_SIZE):
            batch = valid_rules[i:i + BATCH_SIZE]
            cursor.executemany(query, batch)
            conn.commit()  # Commit theo từng block để giải phóng buffer
            logging.info(f"🚀 Đã đồng bộ {min(i + BATCH_SIZE, total_rules)} / {total_rules} luật...")
            
        cursor.close()
        logging.info("✅ ĐỒNG BỘ DATA PIPELINE HOÀN TẤT 100%!")
    except Exception as e:
        if conn: conn.rollback() # 🎯 NÂNG CẤP: Rollback nếu sập DB giữa chừng
        logging.error(f"❌ Lỗi Transaction Database: {e}")
    finally:
        if conn and conn.open:
            conn.close()

if __name__ == '__main__':
    sync_to_database()