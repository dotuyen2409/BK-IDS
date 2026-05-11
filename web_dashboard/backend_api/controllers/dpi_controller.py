# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/dpi_controller.py

import sys
import os
import re
import logging
import ipaddress
from datetime import datetime
from typing import Dict, Any

sys.path.append('/app')
from flask import request, jsonify
from config.database import get_db_connection

# ========================================================================
# CẤU HÌNH OBSERVABILITY & STRUCTURED LOGGING
# ========================================================================
logger = logging.getLogger("Bk-IDS-DPI-Engine")

# ========================================================================
# CLASS: MÔ TẢ & PHÂN TÍCH GÓI TIN CHUYÊN SÂU (WIRESHARK-GRADE DISSECTOR)
# ========================================================================
class WiresharkDissector:
    """
    Engine phân tích sâu gói tin (DPI).
    Bóc tách từ byte nhị phân thô để dựng lại toàn bộ Mô hình OSI (Lớp 2 đến Lớp 7).
    """
    
    # 🔴 BẢO VỆ OOM (Out Of Memory): Giới hạn kích thước xử lý
    MAX_HEX_LENGTH = 50000  # ~50KB hexdump tối đa cho mỗi lần soi
    MAX_ASCII_LEN = 1500    # Chỉ hiển thị tối đa 1500 ký tự payload

    @classmethod
    def parse(cls, hex_str: str) -> Dict[str, Any]:
        parsed = {
            'mac_src': 'N/A', 'mac_dst': 'N/A', 'ethertype': 'N/A',
            'ip_src': 'N/A', 'ip_dst': 'N/A', 'actual_proto': 'Unknown',
            'src_port': 'N/A', 'dst_port': 'N/A', 
            'icmp_type': 'N/A', 'icmp_code': 'N/A',
            'ip_header_len': 'N/A', 'total_len': 'N/A',
            'ascii_payload': '', 'formatted_hex': ''
        }
        
        if not hex_str: 
            return parsed

        try:
            # 🔴 Bảo vệ chống OOM Crash: Cắt cụt nếu gói tin quá lớn
            if len(hex_str) > cls.MAX_HEX_LENGTH:
                hex_str = hex_str[:cls.MAX_HEX_LENGTH]
                logger.warning("Hexdump vượt quá giới hạn an toàn. Đã cắt bớt để bảo vệ RAM.")

            # BƯỚC 1: Lọc lấy byte Hex thuần túy (Sanitize)
            clean_hex = ""
            for line in hex_str.strip().split('\n'):
                # Chỉ lấy nội dung hex, bỏ qua các cột offset hoặc ascii của tcpdump
                hex_matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line[:55]) 
                clean_hex += "".join(hex_matches)

            if not clean_hex: 
                clean_hex = re.sub(r'[^0-9a-fA-F]', '', hex_str)

            raw_bytes = bytes.fromhex(clean_hex)
            
            # BƯỚC 2: Dựng lại chuẩn giao diện Terminal (Offset | Hex | ASCII)
            formatted_hex = ""
            for i in range(0, len(raw_bytes), 16):
                chunk = raw_bytes[i:i+16]
                hex_part = ' '.join(f"{b:02x}" for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                formatted_hex += f"{i:04x}   {hex_part:<48}   {ascii_part}\n"
            parsed['formatted_hex'] = formatted_hex

            # BƯỚC 3: Trích xuất Lớp 7 (Application Payload)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
            parsed['ascii_payload'] = ascii_str[:cls.MAX_ASCII_LEN]

            # BƯỚC 4: Mổ xẻ Data Link Layer (Lớp 2 - MAC Address)
            if len(clean_hex) >= 28:
                mac_d = clean_hex[0:12]
                mac_s = clean_hex[12:24]
                eth_type = clean_hex[24:28]
                
                if eth_type in ['0800', '86dd']:
                    parsed['mac_dst'] = ':'.join(mac_d[i:i+2] for i in range(0, 12, 2)).upper()
                    parsed['mac_src'] = ':'.join(mac_s[i:i+2] for i in range(0, 12, 2)).upper()
                    parsed['ethertype'] = f'IPv4 (0x{eth_type})' if eth_type == '0800' else f'IPv6 (0x{eth_type})'
                    ip_offset = 28
                elif clean_hex.startswith('45'):
                    # Capture từ Raw Socket L3 (Bỏ qua Lớp 2)
                    parsed['mac_dst'] = 'Raw Socket (Lớp 3)'
                    parsed['mac_src'] = 'Raw Socket (Lớp 3)'
                    parsed['ethertype'] = 'IPv4'
                    ip_offset = 0
                else:
                    ip_offset = -1 
                
                # BƯỚC 5: Mổ xẻ Network Layer (Lớp 3) & Transport Layer (Lớp 4)
                if ip_offset >= 0 and len(clean_hex) >= ip_offset + 40:
                    ip_hex = clean_hex[ip_offset:]
                    
                    # Tính toán thông số IP
                    ihl_words = int(ip_hex[1], 16)
                    ihl_bytes = ihl_words * 4
                    parsed['ip_header_len'] = f"{ihl_bytes} bytes"
                    parsed['total_len'] = f"{int(ip_hex[4:8], 16)} bytes"
                    
                    parsed['ip_src'] = '.'.join(str(int(ip_hex[24+i:24+i+2], 16)) for i in range(0, 8, 2))
                    parsed['ip_dst'] = '.'.join(str(int(ip_hex[32+i:32+i+2], 16)) for i in range(0, 8, 2))
                    
                    proto_byte = ip_hex[18:20]
                    
                    # Phân tích giao thức đích xác
                    if proto_byte == '01':
                        parsed['actual_proto'] = 'ICMP'
                        if len(ip_hex) >= (ihl_bytes*2) + 4:
                            icmp_hex = ip_hex[ihl_bytes*2:]
                            parsed['icmp_type'] = str(int(icmp_hex[0:2], 16))
                            parsed['icmp_code'] = str(int(icmp_hex[2:4], 16))
                    elif proto_byte == '06':
                        parsed['actual_proto'] = 'TCP'
                        if len(ip_hex) >= (ihl_bytes*2) + 8:
                            trans_hex = ip_hex[ihl_bytes*2:]
                            parsed['src_port'] = str(int(trans_hex[0:4], 16))
                            parsed['dst_port'] = str(int(trans_hex[4:8], 16))
                    elif proto_byte == '11':
                        parsed['actual_proto'] = 'UDP'
                        if len(ip_hex) >= (ihl_bytes*2) + 8:
                            trans_hex = ip_hex[ihl_bytes*2:]
                            parsed['src_port'] = str(int(trans_hex[0:4], 16))
                            parsed['dst_port'] = str(int(trans_hex[4:8], 16))
                    else:
                        parsed['actual_proto'] = f'0x{proto_byte} (Other)'

        except Exception as e:
            logger.error(f"Lỗi Dissector DPI: {e}", exc_info=True)
            parsed['formatted_hex'] = f"Lỗi phân tích Hexdump nội bộ: {str(e)}"

        return parsed


# ========================================================================
# CONTROLLER: API ENDPOINT
# ========================================================================
def get_packet_details():
    """ 
    API Endpoint: Truy xuất và dịch ngược gói tin từ CSDL 
    """
    ip = request.args.get('ip')
    time_str = request.args.get('time') 
    
    # 🔴 INPUT VALIDATION: Ngăn chặn lỗi và SQL Edge Cases
    if not ip or not time_str:
        return jsonify({'status': 'error', 'message': 'Thiếu tham số truy vết (IP hoặc Thời gian).'}), 400
        
    try:
        # Xác thực chuẩn IP hợp lệ (Bảo vệ SQLi / Crash)
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Định dạng địa chỉ IP không hợp lệ.'}), 400

    try:
        # Xác thực chuẩn thời gian (Bảo vệ SQL Edge Cases)
        datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Định dạng thời gian không hợp lệ. Chuẩn yêu cầu: YYYY-MM-DD HH:MM:SS.'}), 400

    db_conn = None
    cursor = None
    
    try:
        db_conn = get_db_connection()
        
        # Kiểm tra kết nối an toàn (Tương thích PyMySQL)
        is_connected = False
        if db_conn:
            if hasattr(db_conn, 'open'): is_connected = db_conn.open 
            elif hasattr(db_conn, 'is_connected'): is_connected = db_conn.is_connected()
            
        if not is_connected:
            return jsonify({'status': 'error', 'message': 'Mất kết nối tới Cơ sở dữ liệu Lõi.'}), 500
            
        cursor = db_conn.cursor(dictionary=True)
        
        # Câu lệnh SQL nguyên bản, sạch sẽ
        sql = """
            SELECT tg_ketthuc as time, 
                   top_ip as ip, soluong_tcp as tcp, soluong_udp as udp, soluong_icmp as icmp,
                   Gn as gn, entropi, sample_hex as hex_dump
            FROM ids_dulieu 
            WHERE top_ip = %s AND tg_ketthuc <= %s AND sample_hex != '' AND sample_hex IS NOT NULL
            ORDER BY id DESC LIMIT 1
        """
        
        cursor.execute(sql, (ip, time_str))
        row = cursor.fetchone()
        
        if row:
            # Format thời gian an toàn bằng Python
            if isinstance(row['time'], datetime):
                row['time'] = row['time'].strftime('%Y-%m-%d %H:%M:%S')
            else:
                row['time'] = str(row['time'])

            # Ép kiểu an toàn (Safe Casting)
            tcp_count = int(row.get('tcp') or 0)
            udp_count = int(row.get('udp') or 0)
            icmp_count = int(row.get('icmp') or 0)
            
            # 🟡 SỬA LỖI LOGIC: Tìm chính xác giao thức chiếm ưu thế (Dominant Protocol)
            proto_counts = {'TCP': tcp_count, 'UDP': udp_count, 'ICMP': icmp_count}
            dominant_proto = max(proto_counts, key=proto_counts.get)
            
            row['protocol'] = dominant_proto
            row['total_packets'] = sum(proto_counts.values())
            row['tcp'], row['udp'], row['icmp'] = tcp_count, udp_count, icmp_count
            
            # 🎯 Gọi Lớp Dissector phân tích hướng đối tượng
            row['parsed'] = WiresharkDissector.parse(row['hex_dump'])
            
            return jsonify({'status': 'success', 'data': row}), 200
        else:
            return jsonify({'status': 'error', 'message': f'Gói tin từ IP {ip} không chứa Hexdump hoặc đã bị hệ thống ghi đè.'}), 404
            
    except Exception as e:
        logger.error(f"Lỗi Server DPI Controller: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': "Lỗi nội bộ khi truy vấn dữ liệu thô."}), 500
        
    finally:
        # Ngăn chặn rò rỉ bộ nhớ (Memory Leak Protection)
        if cursor: 
            cursor.close()
        if db_conn:
            if hasattr(db_conn, 'open') and db_conn.open: db_conn.close()
            elif hasattr(db_conn, 'is_connected') and db_conn.is_connected(): db_conn.close()



from datetime import datetime

def get_recent_alerts():
    """ 
    API Endpoint: Lấy danh sách 50 cảnh báo/gói tin bất thường gần nhất từ CSDL
    """
    db_conn = None
    cursor = None
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor(dictionary=True)
        
        # Truy vấn 50 bản ghi mới nhất từ bảng ids_dulieu
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
        for row in rows:
            # 1. Chuẩn hóa thời gian
            time_str = row['time'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(row['time'], datetime) else str(row['time'])
            
            # 2. Phân tích giao thức chiếm ưu thế
            counts = {'TCP': int(row.get('tcp') or 0), 'UDP': int(row.get('udp') or 0), 'ICMP': int(row.get('icmp') or 0)}
            dominant_proto = max(counts, key=counts.get)
            if sum(counts.values()) == 0:
                dominant_proto = 'UNKNOWN'

            # 3. Đánh giá cảnh báo dựa trên điểm CuSUM (Gn)
            gn_score = float(row.get('gn') or 0)
            if gn_score > 5.0:
                msg = "[Phát hiện] Dấu hiệu tấn công DoS/DDoS (CuSUM cao)"
            elif sum(counts.values()) > 1000:
                msg = "[Cảnh báo] Lưu lượng gói tin tăng đột biến"
            else:
                msg = "[Bất thường] Nhận dạng mẫu mạng không hợp lệ"

            # Đóng gói dữ liệu trả về Frontend
            alerts_list.append({
                'id': f"#{row['id']}",
                'time': time_str,
                'src_ip': row['src_ip'],
                'src_port': 'Dynamic',    # Có thể nâng cấp parse từ database sau
                'dst_ip': 'Mạng nội bộ',  # Đích đến là hệ thống của bạn
                'dst_port': 'Dynamic',
                'protocol': dominant_proto,
                'message': msg
            })

        return jsonify({'status': 'success', 'data': alerts_list}), 200
        
    except Exception as e:
        logger.error(f"Lỗi truy xuất danh sách cảnh báo: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f"Lỗi CSDL: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if db_conn:
            if hasattr(db_conn, 'open') and db_conn.open: db_conn.close()
            elif hasattr(db_conn, 'is_connected') and db_conn.is_connected(): db_conn.close()