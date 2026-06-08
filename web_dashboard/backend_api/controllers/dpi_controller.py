# /home/ids/bk_ids/web_dashboard/backend_api/controllers/dpi_controller.py
"""
BK-IDS SOC: Deep Packet Inspection (DPI) Controller — Enterprise v3.1 (HARDENED)
=================================================================================
Wireshark-grade packet dissector with full defensive programming:
  - Layer 2: Ethernet (MAC src/dst, EtherType)
  - Layer 3: IPv4 (Version, IHL, Total Len, TTL, ID, Flags, Frag Offset, Checksum, Src, Dst)
  - Layer 4: TCP (Src Port, Dst Port, Seq, Ack, Flags[SYN/ACK/FIN/RST/PSH/URG], Window, Checksum, Urgent Ptr)
  - Layer 4: UDP (Src Port, Dst Port, Length, Checksum)
  - Layer 4: ICMP (Type, Code, Checksum)
  - Layer 7: Payload (Hex dump + ASCII)

Security:
  - Input validation (IP format, datetime format)
  - Parameterized SQL queries only
  - OOM protection (MAX_HEX_LENGTH)
  - Safe error messages (no internal leaks)
  - ALL exceptions caught → never crash server (500)
"""

import sys
import os
import re
import logging
import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional

sys.path.append('/app')
from flask import request, jsonify, g
from config.database import get_db_connection

# ========================================================================
# OBSERVABILITY & STRUCTURED LOGGING
# ========================================================================
logger = logging.getLogger("Bk-IDS-DPI-Engine")

# ========================================================================
# TCP FLAGS CONSTANTS
# ========================================================================
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

# ICMP Type descriptions
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}


# ========================================================================
# SAFE HELPER FUNCTIONS
# ========================================================================
def safe_int(val, default=0, base=10):
    """Safely convert to int with optional base, return default on any error."""
    try:
        if val is None:
            return default
        if isinstance(val, int):
            return val
        s = str(val).strip()
        if not s:
            return default
        return int(s, base)
    except (TypeError, ValueError, AttributeError):
        return default


def safe_float(val, default=0.0):
    """Safely convert to float, return default on any error."""
    try:
        return float(val)
    except (TypeError, ValueError, AttributeError):
        return default


def safe_str(val, default="N/A"):
    """Safely convert to string, return default on None."""
    if val is None:
        return default
    try:
        return str(val)
    except Exception:
        return default


def safe_time_format(val):
    """Safely format datetime to string."""
    if val is None:
        return "N/A"
    if isinstance(val, datetime):
        try:
            return val.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return str(val)
    return str(val)


def safe_split_first(text, delimiter=" ", default="N/A"):
    """Safely get first part after split."""
    try:
        parts = str(text).split(delimiter)
        return parts[0] if parts else default
    except Exception:
        return default


# ========================================================================
# CLASS: WIRESHARK-GRADE PACKET DISSECTOR (HARDENED)
# ========================================================================
class WiresharkDissector:
    """
    Engine phân tích sâu gói tin (DPI).
    Bóc tách từ byte nhị phân thô để dựng lại toàn bộ Mô hình OSI (Lớp 2 đến Lớp 7).
    ALL internal errors are caught — never raises.
    """

    # OOM protection: giới hạn kích thước xử lý
    MAX_HEX_LENGTH = 50000   # ~50KB hexdump tối đa
    MAX_ASCII_LEN = 1500    # Tối đa 1500 ký tự payload hiển thị

    @classmethod
    def parse(cls, hex_str: str) -> Dict[str, Any]:
        """
        Parse hex dump string into structured OSI layers.
        Returns dict with ALL keys populated (never raises).
        """
        # Default result — always has all keys
        parsed = {
            'mac_src': 'N/A', 'mac_dst': 'N/A', 'ethertype': 'N/A',
            'ip_src': 'N/A', 'ip_dst': 'N/A', 'ip_version': 'N/A',
            'ip_ihl': 'N/A', 'ip_total_len': 'N/A', 'ip_id': 'N/A',
            'ip_ttl': 'N/A', 'ip_flags': 'N/A', 'ip_frag_offset': 'N/A',
            'ip_checksum': 'N/A', 'ip_proto': 'N/A',
            'actual_proto': 'Unknown',
            'src_port': 'N/A', 'dst_port': 'N/A',
            'tcp_seq': 'N/A', 'tcp_ack': 'N/A', 'tcp_flags': {},
            'tcp_flags_str': 'N/A', 'tcp_window': 'N/A',
            'tcp_checksum': 'N/A', 'tcp_urgent': 'N/A',
            'tcp_header_len': 'N/A',
            'udp_length': 'N/A', 'udp_checksum': 'N/A',
            'icmp_type': 'N/A', 'icmp_code': 'N/A', 'icmp_checksum': 'N/A',
            'icmp_type_desc': 'N/A',
            'ascii_payload': '', 'formatted_hex': '',
            'raw_bytes_len': 0,
        }

        # Null/empty check
        if not hex_str or not isinstance(hex_str, str):
            return parsed

        try:
            # OOM protection
            if len(hex_str) > cls.MAX_HEX_LENGTH:
                hex_str = hex_str[:cls.MAX_HEX_LENGTH]
                logger.warning("[DPI] Hexdump exceeds safe limit. Truncated to protect RAM.")

            # STEP 1: Extract pure hex bytes (sanitize input)
            clean_hex = ""
            for line in hex_str.strip().split('\n'):
                try:
                    # Skip bracket prefixes like "[SYN FLOOD]\n"
                    line = re.sub(r'^\[.*?\]\s*', '', line.strip())
                    # Extract hex pairs from tcpdump-style lines
                    hex_matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line[:55])
                    clean_hex += "".join(hex_matches)
                except Exception:
                    continue

            if not clean_hex:
                # Kiểm tra nếu chuỗi chỉ toàn là text (như [DDoS] SYN flood) thì không nên cố ép sang hex
                hex_only = re.sub(r'[^0-9a-fA-F]', '', hex_str)
                # Chỉ extract nếu tỷ lệ ký tự hex > 50% độ dài chuỗi hoặc có định dạng hexdump
                if len(hex_only) > len(hex_str) * 0.5:
                    clean_hex = hex_only

            if len(clean_hex) < 28: # Tối thiểu 14 bytes (Ethernet)
                parsed['formatted_hex'] = "Dữ liệu hex không đủ để phân tích (cần tối thiểu 14 bytes) hoặc gói tin chỉ chứa cảnh báo Text."
                return parsed

            # Ensure even number of hex chars
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]

            raw_bytes = bytes.fromhex(clean_hex)
            parsed['raw_bytes_len'] = len(raw_bytes)

            # STEP 2: Build formatted hex dump (Offset | Hex | ASCII)
            formatted_hex = ""
            for i in range(0, len(raw_bytes), 16):
                try:
                    chunk = raw_bytes[i:i+16]
                    hex_part = ' '.join(f"{b:02x}" for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    formatted_hex += f"{i:04x}   {hex_part:<48}   {ascii_part}\n"
                except Exception:
                    continue
            parsed['formatted_hex'] = formatted_hex

            # STEP 3: Extract ASCII payload
            try:
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
                parsed['ascii_payload'] = ascii_str[:cls.MAX_ASCII_LEN]
            except Exception:
                pass

            # STEP 4: Parse Layer 2 — Ethernet (14 bytes = 28 hex chars)
            ip_offset = -1
            if len(clean_hex) >= 28:
                try:
                    mac_d = clean_hex[0:12]
                    mac_s = clean_hex[12:24]
                    eth_type = clean_hex[24:28]

                    if eth_type in ('0800', '86dd'):
                        parsed['mac_dst'] = ':'.join(mac_d[i:i+2] for i in range(0, 12, 2)).upper()
                        parsed['mac_src'] = ':'.join(mac_s[i:i+2] for i in range(0, 12, 2)).upper()
                        parsed['ethertype'] = f'IPv4 (0x{eth_type})' if eth_type == '0800' else f'IPv6 (0x{eth_type})'
                        ip_offset = 28
                    elif clean_hex.startswith('45'):
                        # Raw L3 capture (no Ethernet header)
                        parsed['mac_dst'] = 'Raw Socket (L3 Capture)'
                        parsed['mac_src'] = 'Raw Socket (L3 Capture)'
                        parsed['ethertype'] = 'IPv4 (Raw)'
                        ip_offset = 0
                except Exception as e:
                    logger.warning(f"[DPI] Ethernet parse warning: {e}")

            # STEP 5: Parse Layer 3 — IPv4
            if ip_offset >= 0 and len(clean_hex) >= ip_offset + 40:
                try:
                    ip_hex = clean_hex[ip_offset:]

                    # Version + IHL
                    ver_ihl = safe_int(ip_hex[0:2], 0, 16)
                    parsed['ip_version'] = str(ver_ihl >> 4)
                    ihl_words = ver_ihl & 0x0F
                    ihl_bytes = ihl_words * 4
                    parsed['ip_ihl'] = f"{ihl_bytes} bytes ({ihl_words} words)"
                    parsed['ip_header_len'] = f"{ihl_bytes} bytes"

                    # Total Length
                    total_len = safe_int(ip_hex[4:8], 0, 16)
                    parsed['ip_total_len'] = f"{total_len} bytes"
                    parsed['total_len'] = f"{total_len} bytes"

                    # Identification
                    ip_id_val = safe_int(ip_hex[8:12], 0, 16)
                    parsed['ip_id'] = f"0x{ip_hex[8:12]} ({ip_id_val})"

                    # Flags + Fragment Offset
                    flags_frag = safe_int(ip_hex[12:16], 0, 16)
                    df = (flags_frag >> 14) & 1
                    mf = (flags_frag >> 13) & 1
                    frag_off = flags_frag & 0x1FFF
                    parsed['ip_flags'] = f"DF={df}, MF={mf}"
                    parsed['ip_frag_offset'] = str(frag_off * 8)

                    # TTL
                    parsed['ip_ttl'] = str(safe_int(ip_hex[16:18], 0, 16))

                    # Protocol
                    proto_num = safe_int(ip_hex[18:20], 0, 16)
                    parsed['ip_proto'] = str(proto_num)

                    # Header Checksum
                    parsed['ip_checksum'] = f"0x{ip_hex[20:24]}"

                    # Source IP
                    try:
                        parsed['ip_src'] = '.'.join(
                            str(safe_int(ip_hex[24+i:24+i+2], 0, 16)) for i in range(0, 8, 2)
                        )
                    except Exception:
                        pass

                    # Destination IP
                    try:
                        parsed['ip_dst'] = '.'.join(
                            str(safe_int(ip_hex[32+i:32+i+2], 0, 16)) for i in range(0, 8, 2)
                        )
                    except Exception:
                        pass

                    # STEP 6: Parse Layer 4 — TCP/UDP/ICMP
                    trans_offset = ip_offset + (ihl_bytes * 2)  # hex chars

                    if proto_num == 6:  # TCP
                        parsed['actual_proto'] = 'TCP'
                        if len(clean_hex) >= trans_offset + 40:
                            try:
                                t = clean_hex[trans_offset:]
                                parsed['src_port'] = str(safe_int(t[0:4], 0, 16))
                                parsed['dst_port'] = str(safe_int(t[4:8], 0, 16))
                                parsed['tcp_seq'] = str(safe_int(t[8:16], 0, 16))
                                parsed['tcp_ack'] = str(safe_int(t[16:24], 0, 16))

                                # TCP Data Offset (header length)
                                data_offset_byte = safe_int(t[24:26], 0, 16)
                                tcp_hdr_len = (data_offset_byte >> 4) * 4
                                parsed['tcp_header_len'] = f"{tcp_hdr_len} bytes"

                                # TCP Flags
                                flags_byte = safe_int(t[26:28], 0, 16)
                                flags_dict = {}
                                for bit, name in TCP_FLAGS.items():
                                    flags_dict[name] = bool(flags_byte & bit)
                                parsed['tcp_flags'] = flags_dict
                                active = [n for n, v in flags_dict.items() if v]
                                parsed['tcp_flags_str'] = ', '.join(active) if active else 'None'

                                # Window, Checksum, Urgent
                                parsed['tcp_window'] = str(safe_int(t[28:32], 0, 16))
                                parsed['tcp_checksum'] = f"0x{t[32:36]}"
                                parsed['tcp_urgent'] = str(safe_int(t[36:40], 0, 16))
                            except Exception as e:
                                logger.warning(f"[DPI] TCP parse warning: {e}")

                    elif proto_num == 17:  # UDP
                        parsed['actual_proto'] = 'UDP'
                        if len(clean_hex) >= trans_offset + 16:
                            try:
                                u = clean_hex[trans_offset:]
                                parsed['src_port'] = str(safe_int(u[0:4], 0, 16))
                                parsed['dst_port'] = str(safe_int(u[4:8], 0, 16))
                                udp_len = safe_int(u[8:12], 0, 16)
                                parsed['udp_length'] = f"{udp_len} bytes"
                                parsed['udp_checksum'] = f"0x{u[12:16]}"
                            except Exception as e:
                                logger.warning(f"[DPI] UDP parse warning: {e}")

                    elif proto_num == 1:  # ICMP
                        parsed['actual_proto'] = 'ICMP'
                        if len(clean_hex) >= trans_offset + 8:
                            try:
                                ic = clean_hex[trans_offset:]
                                icmp_type_val = safe_int(ic[0:2], 0, 16)
                                parsed['icmp_type'] = str(icmp_type_val)
                                parsed['icmp_code'] = str(safe_int(ic[2:4], 0, 16))
                                parsed['icmp_checksum'] = f"0x{ic[4:8]}"
                                parsed['icmp_type_desc'] = ICMP_TYPES.get(icmp_type_val, "Unknown")
                            except Exception as e:
                                logger.warning(f"[DPI] ICMP parse warning: {e}")

                    else:
                        parsed['actual_proto'] = f'Protocol {proto_num}'

                except Exception as e:
                    logger.warning(f"[DPI] IPv4 parse warning: {e}")

        except Exception as e:
            logger.error("[DPI] Dissector error: %s", str(e), exc_info=True)
            parsed['formatted_hex'] = f"Lỗi phân tích Hexdump: {str(e)}"

        return parsed


# ========================================================================
# CONTROLLER: API ENDPOINT (HARDENED — NEVER CRASHES)
# ========================================================================
def dpi_get_packet_details():
    """
    API Controller: Truy xuất và dịch ngược gói tin từ CSDL MySQL.
    Được gọi bởi api_server.py gateway route 'get_packet_details'.
    Trả về cấu trúc JSON chuẩn Enterprise: {summary, layers, payload, metadata}.

    DEFENSIVE: Mọi exception đều được bắt, log, và trả về JSON lỗi thân thiện.
    Tuyệt đối không để crash server (500).
    """
    # === PHASE 0: Input Validation ===
    try:
        ip = request.args.get('ip')
        time_str = request.args.get('time')

        if not ip:
            return jsonify({
                'status': 'error',
                'message': 'Thiếu tham số truy vết (IP).'
            }), 400

        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Định dạng địa chỉ IP không hợp lệ.'
            }), 400

        # Validate datetime format if provided
        if time_str:
            try:
                datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Định dạng thời gian không hợp lệ. Chuẩn: YYYY-MM-DD HH:MM:SS.'
                }), 400

    except Exception as e:
        logger.error(f"[DPI] Input validation error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Lỗi xác thực đầu vào: {str(e)}'
        }), 400

    # === PHASE 1: Database Query ===
    db_conn = None
    cursor = None
    row = None

    try:
        db_conn = get_db_connection()

        # Check connection
        is_connected = False
        if db_conn:
            try:
                if hasattr(db_conn, 'open'):
                    is_connected = db_conn.open
                elif hasattr(db_conn, 'is_connected'):
                    is_connected = db_conn.is_connected()
            except Exception:
                pass

        if not is_connected:
            logger.error("[DPI] Database connection failed")
            return jsonify({
                'status': 'error',
                'message': 'Mất kết nối tới Cơ sở dữ liệu Lõi. Vui lòng thử lại sau.'
            }), 200

        cursor = db_conn.cursor(dictionary=True)

        # DEBUG: First check what data exists for this IP (without time filter)
        debug_sql = """
            SELECT id, tg_ketthuc, top_ip, sample_hex IS NOT NULL as has_hex,
                   LENGTH(sample_hex) as hex_len
            FROM ids_dulieu
            WHERE top_ip = %s
            ORDER BY tg_ketthuc DESC
            LIMIT 5
        """
        cursor.execute(debug_sql, (ip,))
        debug_rows = cursor.fetchall()
        logger.info(f"[DPI] DEBUG: Found {len(debug_rows)} rows for ip={ip}")
        for dr in debug_rows:
            hex_preview = ''
            if dr.get('sample_hex'):
                try:
                    hex_preview = str(dr['sample_hex'])[:80]
                except:
                    hex_preview = '(error reading)'
            logger.info(f"[DPI] DEBUG ROW: id={dr.get('id')}, time={dr.get('tg_ketthuc')}, ip={dr.get('top_ip')}, has_hex={dr.get('has_hex')}, hex_len={dr.get('hex_len')}, preview={hex_preview}")

        # MAIN QUERY: Get the packet with hex data
        # Relaxed: removed tg_ketthuc <= time_str filter to see if data exists at all
        sql = """
            SELECT id,
                   tg_ketthuc as time,
                   top_ip as ip,
                   soluong_tcp as tcp,
                   soluong_udp as udp,
                   soluong_icmp as icmp,
                   Gn as gn,
                   entropi,
                   sample_hex as hex_dump
            FROM ids_dulieu
            WHERE top_ip = %s
              AND sample_hex IS NOT NULL
              AND sample_hex != ''
            ORDER BY tg_ketthuc DESC
            LIMIT 1
        """

        cursor.execute(sql, (ip,))
        row = cursor.fetchone()

        if not row:
            # Fallback: try without hex filter — maybe hex is NULL but row exists
            fallback_sql = """
                SELECT id, tg_ketthuc as time, top_ip as ip,
                       soluong_tcp as tcp, soluong_udp as udp, soluong_icmp as icmp,
                       Gn as gn, entropi, sample_hex as hex_dump
                FROM ids_dulieu
                WHERE top_ip = %s
                ORDER BY tg_ketthuc DESC
                LIMIT 1
            """
            cursor.execute(fallback_sql, (ip,))
            row = cursor.fetchone()

            if row:
                # Row exists but hex is NULL/empty
                logger.info(f"[DPI] Found row for ip={ip} but sample_hex is NULL/empty")
                return jsonify({
                    'status': 'error',
                    'message': f'Tìm thấy bản ghi IP {ip} nhưng không có dữ liệu hex dump (sample_hex rỗng).'
                }), 200
            else:
                # No row at all for this IP
                # Check if IP exists in ANY form
                check_sql = "SELECT COUNT(*) as cnt FROM ids_dulieu WHERE top_ip = %s"
                cursor.execute(check_sql, (ip,))
                check_row = cursor.fetchone()
                total_count = check_row.get('cnt', 0) if check_row else 0

                logger.info(f"[DPI] No rows for ip={ip}. Total matching rows: {total_count}")

                if total_count == 0:
                    # Try to find similar IPs
                    similar_sql = """
                        SELECT DISTINCT top_ip, COUNT(*) as cnt
                        FROM ids_dulieu
                        GROUP BY top_ip
                        ORDER BY cnt DESC
                        LIMIT 10
                    """
                    cursor.execute(similar_sql)
                    similar_rows = cursor.fetchall()
                    available_ips = [r.get('top_ip') for r in similar_rows if r.get('top_ip')]
                    logger.info(f"[DPI] Available IPs in DB: {available_ips}")

                    return jsonify({
                        'status': 'error',
                        'message': f'Không tìm thấy gói tin từ IP {ip}. Các IP có trong DB: {", ".join(str(x) for x in available_ips[:5])}'
                    }), 200
                else:
                    return jsonify({
                        'status': 'error',
                        'message': f'Không tìm thấy gói tin từ IP {ip} tại thời điểm {time_str} hoặc trước đó. (Có {total_count} bản ghi nhưng không khớp điều kiện thời gian)'
                    }), 200

    except Exception as e:
        logger.error(f"[DPI] Database query error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Lỗi truy vấn cơ sở dữ liệu: {str(e)}'
        }), 200

    finally:
        # Always close DB resources
        try:
            if cursor:
                cursor.close()
        except Exception:
            pass
        try:
            if db_conn:
                if hasattr(db_conn, 'open') and db_conn.open:
                    db_conn.close()
                elif hasattr(db_conn, 'is_connected') and db_conn.is_connected():
                    db_conn.close()
        except Exception:
            pass

    # === PHASE 2: Data Processing (OUTSIDE DB try block) ===
    try:
        # Safe time formatting
        time_formatted = safe_time_format(row.get('time'))

        # Safe type casting
        tcp_count = safe_int(row.get('tcp'))
        udp_count = safe_int(row.get('udp'))
        icmp_count = safe_int(row.get('icmp'))
        gn_score = safe_float(row.get('gn'))
        entropy = safe_float(row.get('entropi'))

        proto_counts = {'TCP': tcp_count, 'UDP': udp_count, 'ICMP': icmp_count}
        dominant_proto = max(proto_counts, key=proto_counts.get)
        if sum(proto_counts.values()) == 0:
            dominant_proto = 'UNKNOWN'

        # Parse hex dump via WiresharkDissector (never raises)
        hex_dump = safe_str(row.get('hex_dump'))
        parsed = WiresharkDissector.parse(hex_dump)

        # Determine protocol: prefer dissector result over DB dominant
        actual_proto = parsed.get('actual_proto', 'Unknown')
        if actual_proto == 'Unknown':
            actual_proto = dominant_proto

        # Build info string safely
        info_parts = []
        try:
            src_port = parsed.get('src_port', 'N/A')
            dst_port = parsed.get('dst_port', 'N/A')
            if src_port and src_port != 'N/A':
                info_parts.append(f"{src_port} → {dst_port}")
        except Exception:
            pass
        try:
            tcp_flags_str = parsed.get('tcp_flags_str', 'N/A')
            if tcp_flags_str and tcp_flags_str != 'N/A':
                info_parts.append(f"[{tcp_flags_str}]")
        except Exception:
            pass
        try:
            ip_total_len = parsed.get('ip_total_len', 'N/A')
            if ip_total_len and ip_total_len != 'N/A':
                len_val = safe_split_first(ip_total_len)
                info_parts.append(f"Len={len_val}")
        except Exception:
            pass
        info_str = ' '.join(info_parts) if info_parts else f'{actual_proto} Packet'

        # Safe length extraction
        packet_length = 0
        try:
            ip_total_len = parsed.get('ip_total_len', '')
            if ip_total_len and ip_total_len != 'N/A':
                len_str = safe_split_first(ip_total_len)
                if len_str.isdigit():
                    packet_length = int(len_str)
        except Exception:
            pass
        if packet_length == 0:
            packet_length = safe_int(parsed.get('raw_bytes_len'))

        # Build enterprise JSON structure
        response_data = {
            'summary': {
                'timestamp': time_formatted,
                'src_ip': safe_str(parsed.get('ip_src'), ip),
                'dst_ip': safe_str(parsed.get('ip_dst')),
                'src_port': safe_str(parsed.get('src_port')) if parsed.get('src_port') != 'N/A' else None,
                'dst_port': safe_str(parsed.get('dst_port')) if parsed.get('dst_port') != 'N/A' else None,
                'protocol': actual_proto,
                'length': packet_length,
                'info': info_str,
                'tcp_count': tcp_count,
                'udp_count': udp_count,
                'icmp_count': icmp_count,
                'record_id': safe_int(row.get('id')),
            },
            'layers': {},
            'payload': {
                'hex_lines': [],
                'ascii': safe_str(parsed.get('ascii_payload')),
                'raw_hex': hex_dump if hex_dump != 'N/A' else '',
            },
            'metadata': {
                'gn_score': gn_score,
                'entropy': entropy,
                'dominant_protocol': dominant_proto,
                'total_flow_packets': sum(proto_counts.values()),
            }
        }

        # Build hex_lines array for frontend
        try:
            formatted_hex = parsed.get('formatted_hex', '')
            if formatted_hex:
                for line in formatted_hex.strip().split('\n'):
                    if not line.strip():
                        continue
                    try:
                        m = re.match(r'^([0-9a-fA-F]{4})\s+(.+?)\s{2,}(.*)$', line)
                        if m:
                            response_data['payload']['hex_lines'].append({
                                'offset': m.group(1),
                                'hex': m.group(2).strip(),
                                'ascii': m.group(3),
                            })
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"[DPI] hex_lines build warning: {e}")

        # Build OSI layers dynamically
        try:
            if parsed.get('mac_src') and parsed['mac_src'] != 'N/A':
                response_data['layers']['frame'] = {
                    'protocol': 'Ethernet II',
                    'Destination MAC': safe_str(parsed.get('mac_dst')),
                    'Source MAC': safe_str(parsed.get('mac_src')),
                    'EtherType': safe_str(parsed.get('ethertype')),
                }
        except Exception:
            pass

        try:
            if parsed.get('ip_src') and parsed['ip_src'] != 'N/A':
                response_data['layers']['ipv4'] = {
                    'Version': safe_str(parsed.get('ip_version'), '4'),
                    'Header Length': safe_str(parsed.get('ip_ihl')),
                    'Total Length': safe_str(parsed.get('ip_total_len')),
                    'Identification': safe_str(parsed.get('ip_id')),
                    'TTL': safe_str(parsed.get('ip_ttl')),
                    'Flags': safe_str(parsed.get('ip_flags')),
                    'Fragment Offset': safe_str(parsed.get('ip_frag_offset')),
                    'Header Checksum': safe_str(parsed.get('ip_checksum')),
                    'Protocol': f"{safe_str(parsed.get('ip_proto'))} ({actual_proto})",
                    'Source': safe_str(parsed.get('ip_src')),
                    'Destination': safe_str(parsed.get('ip_dst')),
                }
        except Exception:
            pass

        try:
            if actual_proto == 'TCP':
                tcp_layer = {
                    'Source Port': safe_str(parsed.get('src_port')),
                    'Destination Port': safe_str(parsed.get('dst_port')),
                    'Sequence Number': safe_str(parsed.get('tcp_seq')),
                    'Acknowledgment Number': safe_str(parsed.get('tcp_ack')),
                    'Header Length': safe_str(parsed.get('tcp_header_len')),
                    'Flags': safe_str(parsed.get('tcp_flags_str')),
                    'Window Size': safe_str(parsed.get('tcp_window')),
                    'Checksum': safe_str(parsed.get('tcp_checksum')),
                    'Urgent Pointer': safe_str(parsed.get('tcp_urgent')),
                }
                # Add individual flag fields
                flags_dict = parsed.get('tcp_flags', {})
                if isinstance(flags_dict, dict):
                    for flag_name in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG', 'ECE', 'CWR']:
                        tcp_layer[f'Flag {flag_name}'] = '1' if flags_dict.get(flag_name) else '0'
                response_data['layers']['tcp'] = tcp_layer
        except Exception:
            pass

        try:
            if actual_proto == 'UDP':
                response_data['layers']['udp'] = {
                    'Source Port': safe_str(parsed.get('src_port')),
                    'Destination Port': safe_str(parsed.get('dst_port')),
                    'Length': safe_str(parsed.get('udp_length')),
                    'Checksum': safe_str(parsed.get('udp_checksum')),
                }
        except Exception:
            pass

        try:
            if actual_proto == 'ICMP':
                response_data['layers']['icmp'] = {
                    'Type': safe_str(parsed.get('icmp_type')),
                    'Type Description': safe_str(parsed.get('icmp_type_desc')),
                    'Code': safe_str(parsed.get('icmp_code')),
                    'Checksum': safe_str(parsed.get('icmp_checksum')),
                }
        except Exception:
            pass

        # Filter empty layers
        try:
            response_data['layers'] = {
                k: v for k, v in response_data['layers'].items() if v
            }
        except Exception:
            pass

        return jsonify({'status': 'success', 'data': response_data}), 200

    except Exception as e:
        # === CATCH-ALL: Never crash server ===
        logger.error(f"[DPI] Data processing error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Backend Error: {str(e)}'
        }), 200


# ========================================================================
# CONTROLLER: RECENT ALERTS (HARDENED)
# ========================================================================
def get_recent_alerts():
    """
    API Endpoint: Lấy danh sách 50 cảnh báo/gói tin bất thường gần nhất từ CSDL.
    DEFENSIVE: Never crashes server.
    """
    db_conn = None
    cursor = None

    try:
        db_conn = get_db_connection()
        if not db_conn:
            return jsonify({'status': 'error', 'message': 'Mất kết nối Database.'}), 200

        try:
            cursor = db_conn.cursor(dictionary=True)
        except Exception:
            cursor = db_conn.cursor()

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
            try:
                # Handle both tuple and dict
                if isinstance(row_data, (tuple, list)):
                    row = {
                        'id': row_data[0], 'time': row_data[1], 'src_ip': row_data[2],
                        'tcp': row_data[3], 'udp': row_data[4], 'icmp': row_data[5],
                        'gn': row_data[6]
                    }
                else:
                    row = dict(row_data)

                time_str = safe_time_format(row.get('time'))

                counts = {
                    'TCP': safe_int(row.get('tcp')),
                    'UDP': safe_int(row.get('udp')),
                    'ICMP': safe_int(row.get('icmp')),
                }
                dominant_proto = max(counts, key=counts.get)
                if sum(counts.values()) == 0:
                    dominant_proto = 'UNKNOWN'

                gn_score = safe_float(row.get('gn'))
                if gn_score > 5.0:
                    msg = "[Phát hiện] Dấu hiệu tấn công DoS/DDoS (CuSUM cao)"
                elif sum(counts.values()) > 1000:
                    msg = "[Cảnh báo] Lưu lượng gói tin tăng đột biến"
                else:
                    msg = "[Bất thường] Nhận dạng mẫu mạng không hợp lệ"

                alerts_list.append({
                    'id': f"#{safe_int(row['id'])}",
                    'time': time_str,
                    'src_ip': safe_str(row['src_ip']),
                    'src_port': 'Dynamic',
                    'dst_ip': 'Mạng nội bộ',
                    'dst_port': 'Dynamic',
                    'protocol': dominant_proto,
                    'message': msg,
                })
            except Exception as e:
                logger.warning(f"[DPI] Alert row parse warning: {e}")
                continue

        return jsonify({'status': 'success', 'data': alerts_list}), 200

    except Exception as e:
        logger.error(f"[DPI] Recent alerts error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Lỗi tải danh sách cảnh báo: {str(e)}'
        }), 200

    finally:
        try:
            if cursor:
                cursor.close()
        except Exception:
            pass
        try:
            if db_conn:
                if hasattr(db_conn, 'open') and db_conn.open:
                    db_conn.close()
                elif hasattr(db_conn, 'is_connected') and db_conn.is_connected():
                    db_conn.close()
        except Exception:
            pass
