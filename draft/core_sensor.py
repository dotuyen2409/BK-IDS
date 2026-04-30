import socket
import struct
import threading
import time
import math
import traceback
import os
import requests
import mysql.connector
from datetime import datetime, timedelta
import sys

# ========================================================================
# CẤU HÌNH HỆ THỐNG TỐI THƯỢNG (KIẾN TRÚC INLINE IPS / NIDS)
# ========================================================================
NGUONG_H = 700.0 
ADMIN_IP = "192.168.236.1" 
BASELINE_FILE = '/tmp/bkids_baseline.txt'
MANAGEMENT_IP = "192.168.100.11" # IP máy Windows dùng để xem Web Dashboard

# [MÔ HÌNH VẬT LÝ INLINE - ĐỨNG GIỮA ROUTER VÀ SWITCH]
# Bắt buộc máy chủ Ubuntu phải có 2 Card mạng
WAN_INTERFACE = "ens33" # Cửa kết nối ra Internet (Modem nhà mạng)
LAN_INTERFACE = "ens34" # Cửa kết nối vào Mạng nội bộ (Switch/Wi-Fi Access Point)

# NIDS sẽ lắng nghe ở Cửa Nội Bộ (LAN) để giám sát IP thật của thiết bị
INTERFACE = LAN_INTERFACE 

packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
ip_sources = {}
lock = threading.Lock()

current_sample_hex = ""

def format_hexdump(data, snaplen=128):
    """Chuyển Raw Bytes thành Hex Dump chuẩn Wireshark (Chỉ lấy 128 bytes đầu)"""
    data = data[:snaplen]
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f"{i:04x}   {hex_part:<47}  {ascii_part}")
    return '\n'.join(result)

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

# =====================================================================
# HÀM KẾT NỐI DATABASE
# =====================================================================
def get_env():
    env_vars = {}
    env_path = '/home/bk_ids/bk-ids/.env'
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, val = line.strip().split('=', 1)
                    env_vars[key.strip()] = val.strip('"\'')
    return env_vars

def get_direct_db_connection():
    env = get_env()
    try:
        return mysql.connector.connect(
            host="127.0.0.1", port=3306,
            user=env.get('MYSQL_USER', 'root'),
            password=env.get('MYSQL_PASSWORD', 'rootpassword'),
            database=env.get('MYSQL_DATABASE', 'bk_ids'),
            auth_plugin='mysql_native_password',
            ssl_disabled=True, use_pure=True, connect_timeout=10
        )
    except Exception as e: return None

# =====================================================================
# HÀM SOAR: PHÒNG THỦ IPS MẠNG LƯỚI (FORWARD & INPUT)
# =====================================================================
import requests # Bắt buộc phải có dòng này ở đầu file code (hoặc đặt trong hàm)

def send_telegram_alert(message, env_vars=None):
    """Hàm gửi Telegram có tích hợp báo lỗi chi tiết"""
    # 1. Tự động tìm Token nếu env_vars không được truyền vào
    if env_vars is None:
        env_vars = {}
        paths = ['/app/.env', '.env', '/home/bk_ids/bk-ids/.env'] # Quét các thư mục có thể chứa .env
        for path in paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        if '=' in line and not line.strip().startswith('#'):
                            k, v = line.strip().split('=', 1)
                            env_vars[k.strip()] = v.strip('"\'')
                break # Đã tìm thấy thì dừng quét

    token = env_vars.get('TELEGRAM_TOKEN', '')
    chat_id = env_vars.get('TELEGRAM_CHAT_ID', '')

    # 2. Báo lỗi nếu thiếu Token
    if not token or not chat_id: 
        logger.error(" LỖI TELEGRAM: Không tìm thấy TELEGRAM_TOKEN hoặc CHAT_ID. Hãy kiểm tra file .env!")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    # 3. Gửi và bắt lỗi chi tiết từ Server Telegram
    try: 
        response = requests.post(url, data={'chat_id': chat_id, 'text': message}, timeout=5)
        
        if response.status_code == 200:
            logger.info(f"{Colors.BLUE}✈️ [TELEGRAM] Đã gửi cảnh báo thành công tới điện thoại!{Colors.ENDC}")
        else:
            logger.error(f" [TELEGRAM] API từ chối! Mã lỗi {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f" [TELEGRAM] Lỗi kết nối mạng hoặc timeout: {e}")
    except Exception as e:
        logger.error(f" [TELEGRAM] Lỗi hệ thống chưa xác định: {e}")

def trigger_defense(tong_goi_tin, gn_value, env_vars, attacker_ip, nguong_h):
    if attacker_ip == ADMIN_IP or attacker_ip == MANAGEMENT_IP:
        print(f"{Colors.YELLOW}⚠ IP {attacker_ip} thuộc Whitelist Quản trị. Bỏ qua lệnh khóa Tường lửa!{Colors.ENDC}")
        alert_message = (f"🚨 [TEST MODE] IP Quản trị đang thử tải mạng!\nNguồn: {attacker_ip}\nCường độ: {tong_goi_tin} gói tin\nCuSUM: {round(gn_value, 2)}")
        send_telegram_alert(alert_message, env_vars)
        return

    cache_file = '/tmp/bkids_last_alert.txt'
    last_alert = 0
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f: last_alert = int(f.read().strip())
        except: pass

    current_time = int(time.time())
    if current_time - last_alert > 60:
        with open(cache_file, 'w') as f: f.write(str(current_time))
        
        # [NÂNG CẤP ENTERPRISE IPS]
        # 1. INPUT: Khóa tấn công nhắm trực tiếp vào máy NIDS
        os.system(f"sudo iptables -I INPUT 1 -s {attacker_ip} -j DROP")
        # 2. FORWARD: Khóa tấn công đi XUYÊN QUA máy NIDS (bảo vệ mạng LAN)
        os.system(f"sudo iptables -I FORWARD 1 -s {attacker_ip} -j DROP")
        
        # Hẹn giờ mở khóa sau 60 giây
        os.system(f"nohup sh -c 'sleep 60; sudo iptables -D INPUT -s {attacker_ip} -j DROP; sudo iptables -D FORWARD -s {attacker_ip} -j DROP' > /dev/null 2>&1 &")
        
        alert_message = (f"🚨 PHÁT HIỆN TẤN CÔNG!\nNguồn: {attacker_ip}\nCường độ: {tong_goi_tin} gói tin\nCuSUM: {round(gn_value, 2)}\n🛡 Hệ thống IPS đã chém đứt kết nối (FORWARD Drop)!")
        send_telegram_alert(alert_message, env_vars)

# ========================================================================
# 1. LIVE TRAFFIC (SNIFFER TRÊN CỔNG LAN)
# ========================================================================
def sniff_hardware():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((INTERFACE, 0))
        print(f"{Colors.GREEN}⚡ [INLINE SENSOR] Đang cắm chốt tại cửa nội bộ: {INTERFACE}{Colors.ENDC}")
        print(f"{Colors.YELLOW}📡 BẮT ĐẦU GIÁM SÁT TOÀN BỘ LƯU LƯỢNG QUA GATEWAY...{Colors.ENDC}\n")
    except PermissionError:
        sys.exit(1)

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            eth_header = raw_data[:14]
            eth_protocol = socket.ntohs(struct.unpack('!6s6sH', eth_header)[2])

            if eth_protocol == 8: 
                iph = struct.unpack('!BBHHHBBH4s4s', raw_data[14:34])
                protocol, total_length = iph[6], iph[2] 
                src_ip, dst_ip = socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])

                # MÀNG LỌC BPF TỐI THƯỢNG
                is_noise = False
                
                # Bỏ qua lưu lượng của máy Windows cấu hình
                if src_ip == MANAGEMENT_IP or dst_ip == MANAGEMENT_IP:
                    is_noise = True
                
                # Bỏ qua API nội bộ
                if not is_noise and protocol == 6: 
                    try:
                        iph_length = (iph[0] & 0xF) * 4
                        src_port, dst_port = struct.unpack('!HH', raw_data[14 + iph_length : 14 + iph_length + 4])
                        if src_port in [3306, 5000] or dst_port in [3306, 5000]:
                            is_noise = True
                    except: pass

                if is_noise:
                    continue 

                proto_name, color = "UNK", Colors.ENDC
                if protocol == 1: proto_name, color = "ICMP", Colors.RED
                elif protocol == 6: proto_name, color = "TCP", Colors.BLUE
                elif protocol == 17: proto_name, color = "UDP", Colors.GREEN

                if protocol == 1 or total_length > 1000:
                    print(f"{color}[LIVE] {src_ip:<15} ➔ {dst_ip:<15} | {proto_name:<4} | {total_length} bytes{Colors.ENDC}")

                with lock:
                    global current_sample_hex
                    ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1
                    if protocol == 1: packet_counts['ICMP'] += 1
                    elif protocol == 6: packet_counts['TCP'] += 1
                    elif protocol == 17: packet_counts['UDP'] += 1
                    
                    if current_sample_hex == "" or total_length > 100:
                        current_sample_hex = format_hexdump(raw_data)
        except Exception: pass

# ========================================================================
# 2. TOÁN HỌC (THUẬT TOÁN LOGIC GIỮ NGUYÊN)
# ========================================================================
def load_baseline():
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, 'r') as f: return float(f.read().strip())
        except: pass
    return 30.0

def save_baseline(val):
    try:
        with open(BASELINE_FILE, 'w') as f: f.write(str(round(val, 2)))
    except: pass

def analyzer_thread():
    global packet_counts, ip_sources, current_sample_hex
    env_vars = get_env()
    db_conn = None
    try: 
        db_conn = get_direct_db_connection()
        print(f"{Colors.GREEN} [DATABASE] Đã kết nối MySQL thành công!{Colors.ENDC}")
    except Exception: return

    trung_binh_ema = load_baseline()
    print(f"{Colors.BLUE}🔄 Đã nạp Baseline từ ổ cứng: {trung_binh_ema} gói tin/chu kỳ{Colors.ENDC}")
    
    Gn_prev = 0.0
    is_warmup = True     
    warmup_cycles = 6

    while True:
        time.sleep(5) 
        now_dt = datetime.utcnow() + timedelta(hours=7) 
        start_dt = now_dt - timedelta(seconds=5)
        
        with lock:
            tcp, udp, icmp = packet_counts['TCP'], packet_counts['UDP'], packet_counts['ICMP']
            current_ips = ip_sources.copy()
            hex_to_save = current_sample_hex 
            
            packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
            ip_sources.clear()
            current_sample_hex = ""

        tong_goi = tcp + udp + icmp
        
        if is_warmup:
            warmup_cycles -= 1
            Gn = 0.0 
            Gn_prev = 0.0
            
            if tong_goi < 100:
                trung_binh_ema = max(10.0, (trung_binh_ema + float(tong_goi)) / 2.0)
            
            if warmup_cycles <= 0:
                is_warmup = False
                save_baseline(trung_binh_ema)
                print(f"{Colors.GREEN} Đã học xong. Baseline chốt ở mức an toàn: {round(trung_binh_ema, 2)}. Sẵn sàng!{Colors.ENDC}")
            else:
                print(f"{Colors.YELLOW} Đang quét mạng ({warmup_cycles * 5}s)... Baseline duy trì: {round(trung_binh_ema, 2)}{Colors.ENDC}")
            continue

        if tong_goi == 0:
            Gn = max(0.0, (Gn_prev * 0.2) - 50.0)
            Gn_prev = Gn
            top_ip = "Unknown"
            entropi = 0.0
        else:
            top_ip = max(current_ips, key=current_ips.get) if current_ips else "Unknown"
            entropi = sum([- (c/tong_goi) * math.log2(c/tong_goi) for c in current_ips.values() if c > 0])
            
            if tong_goi < (trung_binh_ema * 3):
                trung_binh_ema = max(10.0, (0.05 * tong_goi) + (0.95 * trung_binh_ema))
                save_baseline(trung_binh_ema)

            dung_sai = max(15.0, trung_binh_ema * 0.25)
            Si = tong_goi - (trung_binh_ema + dung_sai)
            
            if Si > 0:
                Gn = min(NGUONG_H * 5, Gn_prev + Si)
            else:
                Gn = max(0.0, (Gn_prev * 0.2) + Si) 
                if tong_goi <= trung_binh_ema + 15: Gn = 0.0 

            Gn_prev = Gn

            if Gn >= NGUONG_H:
                print(f"{Colors.RED}🔥 [SOAR] PHÁT HIỆN BẤT THƯỜNG TỪ: {top_ip} (CuSUM: {round(Gn,1)}){Colors.ENDC}")
                trigger_defense(tong_goi, Gn, env_vars, top_ip, NGUONG_H)

        try:
            if not db_conn.is_connected(): db_conn = get_direct_db_connection()
            sql = """INSERT INTO ids_dulieu (tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor = db_conn.cursor()
            cursor.execute(sql, (start_dt.strftime('%Y-%m-%d %H:%M:%S'), now_dt.strftime('%Y-%m-%d %H:%M:%S'), tcp, udp, icmp, round(Gn, 2), round(entropi, 3), top_ip, hex_to_save))
            cursor.execute("DELETE FROM ids_dulieu WHERE tg_batdau < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            db_conn.commit()
            if not is_warmup:
                print(f"{Colors.BLUE}💾 Đã lưu DB [{now_dt.strftime('%H:%M:%S')}] -> Gói: {tong_goi} | IP: {top_ip} | CuSUM: {round(Gn,2)}{Colors.ENDC}")
        except Exception as e: 
            pass

if __name__ == "__main__":
    print("======================================================")
    print(" Bk-IDS ENTERPRISE SENSOR (Kiến trúc Inline IPS/NIDS)")
    print(f"🔒 Whitelist Quản trị: {MANAGEMENT_IP}")
    print("======================================================")
    
    if os.path.exists(BASELINE_FILE):
        try: os.remove(BASELINE_FILE)
        except: pass

    threading.Thread(target=analyzer_thread, daemon=True).start()
    sniff_hardware()