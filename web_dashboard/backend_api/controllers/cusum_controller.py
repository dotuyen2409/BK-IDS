# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/cusum_controller.py

import sys
import os
import logging
import time
from datetime import datetime
import pymysql 

# ==========================================
# BỌC THÉP ĐƯỜNG DẪN CỤC BỘ DOCKER
# ==========================================
sys.path.append('/app')

from flask import request, jsonify
from config.database import get_db_connection 

logger = logging.getLogger("Bk-IDS-CuSUM-Engine")

def get_current_threshold() -> float:
    env_path = '/app/.env'
    threshold = 700.0 
    
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('CUSUM_THRESHOLD='):
                        try:
                            threshold = float(line.split('=', 1)[1].strip())
                        except ValueError:
                            logger.warning(f"Giá trị CUSUM_THRESHOLD không hợp lệ. Dùng mặc định: {threshold}")
                        break
        except Exception as e:
            logger.error(f"Lỗi đọc cấu hình .env: {e}")
            
    return threshold

def _is_db_connected(conn) -> bool:
    if not conn: return False
    if hasattr(conn, 'open'): return conn.open
    if hasattr(conn, 'is_connected'): return conn.is_connected()
    return False

def get_statistics():
    start_time = time.time()
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        
        if not _is_db_connected(conn):
            logger.error("Mất kết nối tới Container bkids_mysql")
            return jsonify({'status': 'error', 'message': "Mất kết nối tới Database Cảm biến."}), 500

        try:
            cursor = conn.cursor(pymysql.cursors.DictCursor)
        except Exception:
            cursor = conn.cursor()
        
        date_filter = request.args.get('date')
        limit = request.args.get('limit', default=50, type=int)
        if limit > 2000: limit = 2000 
        
        env_threshold = get_current_threshold()
        try:
            nguong_h = float(request.args.get('threshold', env_threshold))
        except (TypeError, ValueError):
            nguong_h = env_threshold

        # 🎯 ĐÃ NÂNG CẤP: Gọi thêm cột 'sample_hex' để đọc nhãn phân tích từ Cảm biến
        if date_filter:
            sql = """
                SELECT id, tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex 
                FROM ids_dulieu 
                WHERE DATE(tg_batdau) = %s 
                ORDER BY id DESC LIMIT %s
            """
            cursor.execute(sql, (date_filter, limit))
        else:
            sql = """
                SELECT id, tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex 
                FROM ids_dulieu 
                ORDER BY id DESC LIMIT %s
            """
            cursor.execute(sql, (limit,))
        
        rows = cursor.fetchall()
        
        if not rows:
            return jsonify({'status': 'success', 'data': [], 'meta': {'execution_ms': 0}}), 200

        processed_data = []
        for row in rows:
            if isinstance(row, (tuple, list)):
                r_dict = {
                    'id': row[0],
                    'tg_batdau': row[1],
                    'tg_ketthuc': row[2],
                    'soluong_tcp': row[3],
                    'soluong_udp': row[4],
                    'soluong_icmp': row[5],
                    'Gn': row[6],
                    'entropi': row[7],
                    'top_ip': row[8],
                    'sample_hex': row[9] # 🎯 Bổ sung ánh xạ
                }
            else:
                r_dict = dict(row)

            gn_val = float(r_dict.get('Gn') or 0.0)
            entropy_val = float(r_dict.get('entropi') or 0.0)
            tcp = int(r_dict.get('soluong_tcp') or 0)
            udp = int(r_dict.get('soluong_udp') or 0)
            icmp = int(r_dict.get('soluong_icmp') or 0)
            
            # 🎯 LOGIC DOANH NGHIỆP: Trích xuất nhãn tấn công từ sample_hex
            sample_raw = str(r_dict.get('sample_hex') or '')
            attack_type = "BÌNH THƯỜNG"
            top5_info = ""
            if sample_raw.startswith('['):
                end_bracket = sample_raw.find(']')
                if end_bracket > 0:
                    attack_type = sample_raw[1:end_bracket]
                # Trích xuất TOP5 IPs nếu có
                top5_idx = sample_raw.find('TOP5: ')
                if top5_idx > 0:
                    top5_end = sample_raw.find('\n', top5_idx)
                    top5_info = sample_raw[top5_idx + 6:top5_end if top5_end > 0 else len(sample_raw)]

            # 🎯 BỘ LỌC FALSE POSITIVE: Cải thiện phát hiện — bao gồm SPOOFED và FLOOD
            is_real_anomaly = False
            if gn_val >= nguong_h:
                if "HẠ NHIỆT" not in attack_type and "BÌNH THƯỜNG" not in attack_type:
                    is_real_anomaly = True

            def format_time(t):
                if not t: return 'N/A'
                if isinstance(t, datetime): return t.strftime('%Y-%m-%d %H:%M:%S')
                return str(t)

            processed_data.append({
                'tg_batdau': format_time(r_dict.get('tg_batdau')),
                'tg_ketthuc': format_time(r_dict.get('tg_ketthuc')),
                'tong_goi': tcp + udp + icmp,
                'tcp': tcp,
                'udp': udp,
                'icmp': icmp,
                'gn': round(gn_val, 2),
                'h_threshold': nguong_h,
                'entropi': round(entropy_val, 3),
                'top_ip': r_dict.get('top_ip', 'Unknown'),
                'top5_ips': top5_info,
                'attack_type': attack_type,
                'is_anomaly': is_real_anomaly # 🎯 Trả về trạng thái đã qua bộ lọc
            })

        execution_time_ms = round((time.time() - start_time) * 1000, 2)

        return jsonify({
            'status': 'success', 
            'data': processed_data[::-1],
            'meta': {
                'total_returned': len(processed_data),
                'execution_time_ms': execution_time_ms
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Lỗi tại get_statistics: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f"Lỗi nội bộ truy xuất CuSUM: {str(e)}"}), 500
        
    finally:
        if cursor: cursor.close()
        if conn and _is_db_connected(conn): conn.close()