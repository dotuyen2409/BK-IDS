# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/alert_controller.py

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

from flask import jsonify, request
from config.database import get_db_connection

# Khởi tạo Logger chuẩn SIEM Doanh nghiệp
logger = logging.getLogger("Bk-IDS-Alert-Engine")

# ==========================================
# KHỞI TẠO MODULE ĐO LƯỜNG TÀI NGUYÊN
# ==========================================
try:
    import psutil
    PSUTIL_READY = True
    psutil.cpu_percent(interval=None)
except ImportError:
    PSUTIL_READY = False
    logger.warning(" CẢNH BÁO: Chưa cài đặt thư viện 'psutil'. Thông số CPU/RAM sẽ mặc định là 0.")

def _is_db_connected(conn) -> bool:
    """ Kiểm tra trạng thái kết nối an toàn đa nền tảng """
    if not conn: return False
    if hasattr(conn, 'open'): return conn.open
    if hasattr(conn, 'is_connected'): return conn.is_connected()
    return False

def get_alerts_summary():
    """ API Endpoint: Lấy tóm tắt sức khỏe Máy chủ Lõi """
    try:
        if PSUTIL_READY:
            cpu_usage = psutil.cpu_percent(interval=None)
            ram_usage = psutil.virtual_memory().percent
        else:
            cpu_usage, ram_usage = 0.0, 0.0 

        total_alerts = 0
        db_conn = None
        cursor = None
        
        try:
            db_conn = get_db_connection()
            if _is_db_connected(db_conn):
                cursor = db_conn.cursor() 
                cursor.execute("SELECT COUNT(*) AS total FROM misuse_alerts")
                result = cursor.fetchone()
                
                if isinstance(result, dict):
                    total_alerts = result.get('total', 0)
                elif isinstance(result, (tuple, list)):
                    total_alerts = result[0]
                    
        except Exception as db_err:
            logger.error(f"Lỗi truy vấn tóm tắt Tường lửa: {db_err}")
            
        finally:
            if cursor: cursor.close()
            if db_conn and _is_db_connected(db_conn): db_conn.close()

        return jsonify({
            'status': 'success',
            'data': {
                'cpu': round(cpu_usage, 1), 
                'ram': round(ram_usage, 1)
            },
            'total': total_alerts
        }), 200
        
    except Exception as e:
        logger.error(f"Lỗi hệ thống Alert Controller (Summary): {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': "Lỗi xử lý máy chủ nội bộ."}), 500

def get_misuse_alerts():
    """
    🎯 API DOANH NGHIỆP: Truy xuất log Cảnh báo & Máy chém.
    Đã nâng cấp cơ chế Phòng thủ Chiều sâu (Defensive Programming) chống lỗi Tuple/Dict.
    """
    start_time = time.time()
    db_conn = None
    cursor = None
    
    try:
        db_conn = get_db_connection()
        
        if not _is_db_connected(db_conn):
            logger.error("Mất kết nối tới Container Database")
            return jsonify({'status': 'error', 'message': "Mất kết nối Database Cảm biến."}), 500
            
        # Cố gắng gọi DictCursor, nhưng phòng hờ driver cũ phớt lờ lệnh này
        try:
            cursor = db_conn.cursor(pymysql.cursors.DictCursor)
        except Exception:
            cursor = db_conn.cursor()
        
        limit = request.args.get('limit', default=250, type=int)
        offset = request.args.get('offset', default=0, type=int)
        
        if limit > 1000: limit = 1000

        # Thứ tự chuẩn: 0:id, 1:timestamp, 2:ip_src, 3:sig_name, 4:protocol, 5:action
        sql = """
            SELECT id, timestamp, ip_src, sig_name, protocol, action 
            FROM misuse_alerts 
            ORDER BY timestamp DESC, id DESC 
            LIMIT %s OFFSET %s
        """
        cursor.execute(sql, (limit, offset))
        alerts_raw = cursor.fetchall()
        
        if not alerts_raw:
            return jsonify({'status': 'success', 'data': [], 'meta': {'total_returned': 0}}), 200
            
        formatted_alerts = []
        
        # 🎯 BỌC THÉP TẠI ĐÂY: Xử lý an toàn cả Tuple và Dictionary
        for row in alerts_raw:
            if isinstance(row, (tuple, list)):
                # Ép kiểu dữ liệu bằng tay nếu Database ngoan cố trả về Tuple
                alert = {
                    'id': row[0],
                    'timestamp': row[1],
                    'ip_src': row[2],
                    'sig_name': row[3],
                    'protocol': row[4],
                    'action': row[5]
                }
            else:
                # Nếu đã là Dict (chuẩn) thì sao chép
                alert = dict(row)

            # Chuẩn hóa thời gian
            ts = alert.get('timestamp')
            if isinstance(ts, datetime):
                alert['timestamp'] = ts.strftime('%Y-%m-%d %H:%M:%S')
            else:
                alert['timestamp'] = str(ts) if ts else "Unknown"
                
            formatted_alerts.append(alert)

        execution_time_ms = round((time.time() - start_time) * 1000, 2)

        return jsonify({
            'status': 'success', 
            'data': formatted_alerts,
            'meta': {
                'total_returned': len(formatted_alerts),
                'limit': limit,
                'offset': offset,
                'execution_time_ms': execution_time_ms
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Lỗi truy xuất hệ thống Alerts: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': "Lỗi truy xuất hệ thống Tường lửa."}), 500
        
    finally:
        if cursor: cursor.close()
        if db_conn and _is_db_connected(db_conn): db_conn.close()

# ==========================================
# 🟢 MODULE MỚI: TRUY VẤN DANH SÁCH GÓI TIN SOC
# ==========================================
def get_recent_alerts():
    """ 
    Truy vấn 50 cảnh báo/gói tin bất thường gần nhất từ cơ sở dữ liệu BK-IDS (Bảng ids_dulieu)
    Kết hợp phân tích giao thức và thuật toán CUSUM để tạo thông điệp SOC.
    """
    db_conn = None
    cursor = None
    try:
        db_conn = get_db_connection()
        if not _is_db_connected(db_conn):
            return jsonify({'status': 'error', 'message': "Mất kết nối Database Cảm biến."}), 500

        # Cố gắng gọi DictCursor (Phòng thủ Tuple/Dict)
        try:
            cursor = db_conn.cursor(pymysql.cursors.DictCursor)
        except Exception:
            cursor = db_conn.cursor()
        
        # Truy vấn các bản ghi mới nhất từ bảng dữ liệu IDS
        sql = """
            SELECT id, tg_ketthuc as time, top_ip as src_ip, 
                   soluong_tcp as tcp, soluong_udp as udp, soluong_icmp as icmp,
                   Gn as gn
            FROM ids_dulieu 
            ORDER BY id DESC LIMIT 50
        """
        cursor.execute(sql)
        rows = cursor.fetchall()
        
        alerts_list = []
        for row_data in rows:
            # Xử lý an toàn cả Tuple và Dictionary
            if isinstance(row_data, (tuple, list)):
                row = {
                    'id': row_data[0],
                    'time': row_data[1],
                    'src_ip': row_data[2],
                    'tcp': row_data[3],
                    'udp': row_data[4],
                    'icmp': row_data[5],
                    'gn': row_data[6]
                }
            else:
                row = dict(row_data)

            # Xử lý an toàn định dạng thời gian
            time_val = row.get('time')
            time_str = time_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(time_val, datetime) else str(time_val) if time_val else "Unknown"
            
            # Phân tích giao thức chiếm ưu thế
            counts = {'TCP': int(row.get('tcp') or 0), 'UDP': int(row.get('udp') or 0), 'ICMP': int(row.get('icmp') or 0)}
            dominant_proto = max(counts, key=counts.get)
            if sum(counts.values()) == 0:
                dominant_proto = 'UNKNOWN'

            # Gắn cờ cảnh báo dựa trên chỉ số thuật toán CUSUM (Gn)
            gn_score = float(row.get('gn') or 0)
            if gn_score > 5.0:
                msg = "[CUSUM] Phát hiện Dấu hiệu tấn công DoS/DDoS"
            elif sum(counts.values()) > 1000:
                msg = "[Cảnh báo] Lưu lượng mạng gia tăng bất thường"
            else:
                msg = "[Snort] Gói tin mạng có cấu trúc không an toàn"

            # Đóng gói kết quả trả về Frontend
            alerts_list.append({
                'id': f"#{row['id']}",
                'time': time_str,
                'src_ip': row['src_ip'],
                'src_port': 'Dynamic',    
                'dst_ip': 'Hệ thống Đích',
                'dst_port': 'Dynamic',
                'protocol': dominant_proto,
                'message': msg
            })

        return jsonify({'status': 'success', 'data': alerts_list}), 200
        
    except Exception as e:
        logger.error(f"Lỗi truy xuất danh sách cảnh báo (get_recent_alerts): {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f"Lỗi CSDL: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if db_conn and _is_db_connected(db_conn): db_conn.close()