# /home/bk_ids/bk-ids/core_engine/sensor_ids.py

import socket
import struct
import threading
import time
import os
import math
from datetime import datetime, timedelta, timezone
import sys
import ipaddress
import logging
import signal
import fcntl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import glob

# ========================================================================
# KIỂM TRA THƯ VIỆN LÕI
# ========================================================================
try:
    import pymysql
    import requests
except ImportError:
    print("\n" + "="*70)
    print(" CRITICAL ERROR: Lõi Cảm biến thiếu thư viện 'pymysql' hoặc 'requests'.")
    print("💡 CÁCH SỬA LỖI: Hãy chạy lệnh: sudo docker exec -it bkids_anomaly_sensor pip3 install pymysql requests")
    print("="*70 + "\n")
    sys.exit(1)

bk_engine_instance = None

class Colors:
    BLUE = '\033[94m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'; PURPLE = '\033[95m'; ENDC = '\033[0m'

# ========================================================================
# MICROSERVICE: API SERVER QUẢN LÝ TƯỜNG LỬA (PORT 5005)
# ========================================================================
class FirewallAPI(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass 
        
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/blocked_ips':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self._send_cors_headers()
            self.end_headers()
            blocked = [{"ip": f.replace('/tmp/ips_block_', '').replace('.txt', '')} for f in glob.glob('/tmp/ips_block_*.txt')]
            self.wfile.write(json.dumps(blocked).encode('utf-8'))

    def do_POST(self):
        if self.path.startswith('/api/unblock/'):
            ip = self.path.split('/')[-1]
            subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"sudo iptables -D DOCKER-USER -s {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
            try: os.remove(f'/tmp/ips_block_{ip}.txt')
            except: pass
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "IP Unblocked"}).encode('utf-8'))
            
            msg = f"Đã BỎ CHẶN an toàn cho IP: <code>{ip}</code> từ giao diện Web UI."
            logging.getLogger("CuSUM-Sensor").info(f"{Colors.GREEN}🔓 [WEB UI] {msg}{Colors.ENDC}")
            
            global bk_engine_instance
            if bk_engine_instance:
                bk_engine_instance.executor.submit(bk_engine_instance.send_telegram_alert, msg, "SUCCESS")

# ========================================================================
# CLASS LÕI CẢM BIẾN (OOP DESIGN)
# ========================================================================
class BkSocAnomalyEngine:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
        self.logger = logging.getLogger("CuSUM-Sensor")
        
        self.INTERFACE = os.environ.get("SNIFF_INTERFACE", "ens33") 
        self.BASELINE_FILE = '/tmp/ids_baseline.txt'
        
        self.is_running = True
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=15) 
        
        # 🎯 STATE MACHINE: Quản lý bão tin nhắn (Chống Spam Telegram)
        self.is_under_attack = False
        self.last_spoof_alert_time = 0
        
        self.packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'SYN': 0}
        self.ip_sources = {}
        self.current_sample_hex = ""
        
        self.SYS_CONFIG = {
            'SCAN_INTERVAL': 5,
            'CUSUM_THRESHOLD': 700.0,
            'ENABLE_FIREWALL': True,
            'BAN_DURATION': 3600,
            'HOME_NET': '192.168.142.0/24',
            'MONITORED_PORTS': set(), 
            'WHITELIST_IPS': set()    
        }
        
        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)

    def graceful_shutdown(self, sig, frame):
        self.logger.info(f"\n{Colors.YELLOW} Nhận lệnh ngắt. Đang đóng Cảm biến Anomaly an toàn...{Colors.ENDC}")
        self.is_running = False
        self.executor.shutdown(wait=False)
        sys.exit(0)

    def get_env_var(self, key):
        paths = ['/home/bk_ids/bk-ids/.env', '/app/.env', '.env']
        for path in paths:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    for line in f:
                        if line.strip().startswith(f"{key}="):
                            return line.split('=', 1)[1].strip().strip('"\'')
        return ""

    def send_telegram_alert(self, message, level="INFO"):
        token = self.get_env_var('TELEGRAM_BOT_TOKEN')
        chat_id = self.get_env_var('TELEGRAM_CHAT_ID')
        
        if not token or not chat_id: 
            self.logger.error("❌ Lỗi Telegram: Thiếu TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID trong file .env!")
            return

        icons = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🚨", "SUCCESS": "✅"}
        icon = icons.get(level, "💬")
        
        text = f"{icon} <b>BK-IDS SOC ALERT</b>\n"
        text += f"┣ <b>Mức độ:</b> {level}\n"
        text += f"┣ <b>Thời gian:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        text += f"┗ <b>Nội dung:</b>\n{message}"

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            response = requests.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"}, timeout=5)
            if response.status_code != 200:
                self.logger.error(f"❌ Từ chối từ Telegram: {response.text}")
        except Exception as e:
            self.logger.error(f"❌ Lỗi mạng Telegram: {e}")

    def get_ip_address(self, ifname):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(ifname[:15], 'utf-8')))[20:24])
        except: return None

    def format_hexdump(self, data, snaplen=128):
        data = data[:snaplen]
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f"{b:02x}" for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result.append(f"{i:04x}   {hex_part:<47}  {ascii_part}")
        return '\n'.join(result)

    def get_db_connection(self):
        try:
            return pymysql.connect(
                host='127.0.0.1', port=3306, 
                user=self.get_env_var('MYSQL_USER') or 'root', 
                password=self.get_env_var('MYSQL_PASSWORD') or '123456', 
                database=self.get_env_var('MYSQL_DATABASE') or 'bk_ids',
                connect_timeout=2, cursorclass=pymysql.cursors.DictCursor
            )
        except Exception: 
            try:
                return pymysql.connect(
                    host='mysql_db', port=3306, 
                    user=self.get_env_var('MYSQL_USER') or 'root', 
                    password=self.get_env_var('MYSQL_PASSWORD') or '123456', 
                    database=self.get_env_var('MYSQL_DATABASE') or 'bk_ids',
                    connect_timeout=2, cursorclass=pymysql.cursors.DictCursor
                )
            except Exception: return None

    def load_baseline(self):
        if os.path.exists(self.BASELINE_FILE):
            try:
                with open(self.BASELINE_FILE, 'r') as f: return float(f.read().strip())
            except: pass
        return 30.0

    def save_baseline(self, val):
        try:
            with open(self.BASELINE_FILE, 'w') as f: f.write(str(round(val, 2)))
        except: pass

    def is_ip_whitelisted(self, ip_str):
        if ip_str in ["127.0.0.1", "Unknown", "No_Traffic", "Spoofed_IPs_Pool"]: return True 
        if ip_str in self.SYS_CONFIG['WHITELIST_IPS']: return True
        return False

    def execute_firewall(self, attacker_ip, attack_type, tong_goi, detailed_msg=None):
        if self.is_ip_whitelisted(attacker_ip): 
            return 
            
        cache_file = f'/tmp/ips_block_{attacker_ip}.txt'
        # 🎯 CHỈ GỬI TELEGRAM & CHẶN NẾU IP ĐÓ CHƯA BỊ CHẶN TRƯỚC ĐÓ (Chống lặp tin nhắn)
        if os.path.exists(cache_file): return
        
        try:
            duration = self.SYS_CONFIG['BAN_DURATION']
            with open(cache_file, 'w') as f: f.write(str(time.time()))
            
            subprocess.run(f"sudo iptables -I INPUT 1 -s {attacker_ip} -j DROP", shell=True)
            subprocess.run(f"sudo iptables -I DOCKER-USER 1 -s {attacker_ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
            
            os.system(f"nohup sh -c 'sleep {duration}; sudo iptables -D INPUT -s {attacker_ip} -j DROP 2>/dev/null; sudo iptables -D DOCKER-USER -s {attacker_ip} -j DROP 2>/dev/null; rm {cache_file} 2>/dev/null' > /dev/null 2>&1 &")
            
            self.logger.warning(f"{Colors.RED}🛑 [SOAR-IPS] Đã tước quyền truy cập IP {attacker_ip} | Lỗi: {attack_type}{Colors.ENDC}")
            
            # 🎯 Bắn Telegram tin nhắn siêu chi tiết khi chặn thành công ngay lập tức
            if detailed_msg:
                self.executor.submit(self.send_telegram_alert, detailed_msg, "CRITICAL")
            
        except Exception as e: 
            self.logger.error(f"Lỗi iptables SOAR: {e}")

    def log_anomaly_to_db(self, start_dt, now_dt, tcp, udp, icmp, gn, entropi, top_ip, hex_to_save, attack_type):
        conn = cursor = None
        try:
            conn = self.get_db_connection()
            if conn and conn.open:
                sql = """INSERT INTO ids_dulieu (tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                enhanced_hex = f"[{attack_type}]\n{hex_to_save}" if attack_type != "BÌNH THƯỜNG" else hex_to_save
                cursor = conn.cursor()
                cursor.execute(sql, (
                    start_dt.strftime('%Y-%m-%d %H:%M:%S'), 
                    now_dt.strftime('%Y-%m-%d %H:%M:%S'), 
                    tcp, udp, icmp, round(gn, 2), str(round(entropi, 3)), top_ip, enhanced_hex
                ))
                conn.commit()
        except Exception: pass
        finally: 
            if cursor: cursor.close()
            if conn and conn.open: conn.close()

    def config_updater_worker(self):
        while self.is_running:
            try:
                self.SYS_CONFIG['SCAN_INTERVAL'] = int(self.get_env_var('SCAN_INTERVAL') or 5)
                self.SYS_CONFIG['CUSUM_THRESHOLD'] = float(self.get_env_var('CUSUM_THRESHOLD') or 700.0)
                self.SYS_CONFIG['BAN_DURATION'] = int(self.get_env_var('BAN_DURATION') or 3600)
                
                env_fw = self.get_env_var('ENABLE_FIREWALL')
                self.SYS_CONFIG['ENABLE_FIREWALL'] = str(env_fw).lower() == 'true' if env_fw != "" else True
                
                ports_str = self.get_env_var('MONITORED_PORTS')
                if ports_str:
                    self.SYS_CONFIG['MONITORED_PORTS'] = set([int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()])
                else:
                    self.SYS_CONFIG['MONITORED_PORTS'] = set()
                    
                wl_str = self.get_env_var('WHITELIST_IPS')
                if wl_str:
                    self.SYS_CONFIG['WHITELIST_IPS'] = set([ip.strip() for ip in wl_str.split(',')])
                    
            except Exception: pass
            time.sleep(5)

    def api_server_worker(self):
        try:
            server = ThreadingHTTPServer(('0.0.0.0', 5005), FirewallAPI)
            self.logger.info(f"{Colors.PURPLE} [API SERVER] Khởi chạy thành công API Đa Luồng (Cổng 5005){Colors.ENDC}")
            server.serve_forever()
        except Exception as e: pass

    def analyzer_worker(self):
        trung_binh_ema = self.load_baseline()
        Gn_prev = 0.0
        is_warmup, warmup_cycles = True, 2 

        while self.is_running:
            scan_interval = self.SYS_CONFIG['SCAN_INTERVAL']
            time.sleep(scan_interval) 
            now_dt = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=7)
            start_dt = now_dt - timedelta(seconds=scan_interval)
            
            with self.lock:
                tcp, udp, icmp, syn = self.packet_counts['TCP'], self.packet_counts['UDP'], self.packet_counts['ICMP'], self.packet_counts['SYN']
                current_ips = self.ip_sources.copy()
                hex_to_save = self.current_sample_hex 
                
                self.packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'SYN': 0}
                self.ip_sources.clear()
                self.current_sample_hex = ""

            tong_goi = tcp + udp + icmp
            unique_ips = len(current_ips)
            
            is_spoofed_attack = (unique_ips > 1000) or (tong_goi > 2000 and unique_ips > tong_goi * 0.4)

            if tong_goi == 0:
                top_ip, entropi = "No_Traffic", 0.0
            elif is_spoofed_attack:
                top_ip, entropi = "Spoofed_IPs_Pool", 5.0 
            else:
                top_ip = max(current_ips, key=current_ips.get) if current_ips else "No_Traffic"
                entropi = sum([- (c/tong_goi) * math.log2(c/tong_goi) for c in current_ips.values() if c > 0])
                
            attack_type = "BÌNH THƯỜNG"

            if is_warmup:
                warmup_cycles -= 1
                Gn = 0.0 
                if tong_goi < 100: trung_binh_ema = max(10.0, (trung_binh_ema + float(tong_goi)) / 2.0)
                if warmup_cycles <= 0: is_warmup = False; self.save_baseline(trung_binh_ema)
            else:
                if tong_goi == 0: Gn = max(0.0, (Gn_prev * 0.2) - 50.0)
                else:
                    if tong_goi < (trung_binh_ema * 3):
                        trung_binh_ema = max(10.0, (0.05 * tong_goi) + (0.95 * trung_binh_ema))
                        self.save_baseline(trung_binh_ema)
                    
                    dung_sai = max(15.0, trung_binh_ema * 0.25)
                    Si = tong_goi - (trung_binh_ema + dung_sai)
                    Gn = min(self.SYS_CONFIG['CUSUM_THRESHOLD'] * 5, Gn_prev + Si) if Si > 0 else max(0.0, (Gn_prev * 0.2) + Si)
                    if tong_goi <= trung_binh_ema + 15: Gn = 0.0 

            # 🎯 STATE MACHINE QUẢN LÝ CẢNH BÁO TẤN CÔNG
            if Gn >= self.SYS_CONFIG['CUSUM_THRESHOLD']:
                is_active_spike = (Si > 0) or (tong_goi > trung_binh_ema * 2)
                top_ip_count = current_ips.get(top_ip, 0)
                
                if is_active_spike:
                    # ✅ Cảnh báo Bắt đầu sự cố (Chỉ báo 1 lần)
                    if not self.is_under_attack:
                        self.is_under_attack = True
                        self.executor.submit(self.send_telegram_alert, f"🚨 <b>PHÁT HIỆN TẤN CÔNG MẠNG!</b>\nĐiểm Dị thường (Gn) đã vượt ngưỡng. Đang theo dõi và phân tích...", "CRITICAL")

                    attack_proto = "UNKNOWN"
                    if tcp > udp and tcp > icmp: attack_proto = "SYN FLOOD" if syn > (tcp * 0.5) else "TCP FLOOD"
                    elif udp > tcp and udp > icmp: attack_proto = "UDP FLOOD"
                    elif icmp > tcp and icmp > udp: attack_proto = "ICMP PING FLOOD"
                    
                    if is_spoofed_attack:
                        attack_type = f"SPOOFED {attack_proto} (RAND-SOURCE)"
                        
                        # Cảnh báo IP Spoofed (Giới hạn 1 tin mỗi 60 giây để tránh spam)
                        current_time = time.time()
                        if current_time - self.last_spoof_alert_time > 60:
                            msg = (f"🔥 <b>CẢNH BÁO TẤN CÔNG SPOOFING</b>\n"
                                   f"┣ <b>Phân loại:</b> {attack_type}\n"
                                   f"┣ <b>Lưu lượng:</b> {tong_goi} Pkts/{scan_interval}s\n"
                                   f"┣ <b>Số IP rác:</b> {unique_ips} IPs\n"
                                   f"┗ <b>Hành động:</b> Chỉ ghi log, không chặn để tránh tràn Tường lửa.")
                            self.executor.submit(self.send_telegram_alert, msg, "WARNING")
                            self.last_spoof_alert_time = current_time
                    else:
                        if top_ip_count > (tong_goi * 0.3) and top_ip_count > (trung_binh_ema * 1.5):
                            scale = "DDoS Botnet" if entropi >= 1.5 else "DoS"
                            attack_type = f"{scale} ({attack_proto})"
                            
                            if self.SYS_CONFIG['ENABLE_FIREWALL'] and top_ip not in ["Unknown", "No_Traffic"]:
                                alert_msg = (
                                    f"🛑 <b>PHONG TỎA IP TẤN CÔNG</b>\n"
                                    f"┣ <b>Mục tiêu:</b> <code>{top_ip}</code>\n"
                                    f"┣ <b>Phân loại:</b> {attack_type}\n"
                                    f"┣ <b>Lưu lượng IP này:</b> {top_ip_count} Pkts\n"
                                    f"┣ <b>Giao thức (T/U/I):</b> {tcp}/{udp}/{icmp}\n"
                                    f"┗ <b>Hành động:</b> Đã khóa bằng Iptables (DOCKER-USER)."
                                )
                                self.executor.submit(self.execute_firewall, top_ip, attack_type, tong_goi, alert_msg)
                        else:
                            attack_type = "BÌNH THƯỜNG (HẠ NHIỆT)"
                else:
                    attack_type = "BÌNH THƯỜNG (HẠ NHIỆT)"
                    # ✅ Cảnh báo Kết thúc sự cố (Hệ thống hạ nhiệt nhưng Gn vẫn đang giảm)
                    if self.is_under_attack:
                        self.is_under_attack = False
                        self.executor.submit(self.send_telegram_alert, f"✅ <b>HỆ THỐNG ĐÃ AN TOÀN</b>\nLưu lượng mạng đã hạ nhiệt và trở lại bình thường.", "SUCCESS")
            else:
                # Gn tụt hẳn dưới ngưỡng Threshold
                if self.is_under_attack:
                    self.is_under_attack = False
                    self.executor.submit(self.send_telegram_alert, f"✅ <b>HỆ THỐNG ĐÃ AN TOÀN</b>\nChỉ số dị thường đã ổn định hoàn toàn (Gn < Threshold).", "SUCCESS")

            Gn_prev = Gn
            self.executor.submit(self.log_anomaly_to_db, start_dt, now_dt, tcp, udp, icmp, Gn, entropi, top_ip, hex_to_save, attack_type)

    def sniff_hardware(self):
        local_ip = self.get_ip_address(self.INTERFACE)
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 20971520) 
            conn.bind((self.INTERFACE, 0))
            self.logger.info(f"{Colors.GREEN} [HỆ THỐNG CUSUM] Đã khóa mục tiêu vào Card mạng [{self.INTERFACE}]. Sẵn sàng xử lý!{Colors.ENDC}")
        except PermissionError: 
            self.logger.error(" Cần quyền Root để mở Raw Socket!"); sys.exit(1)
        except OSError:
            self.logger.error(f" Card mạng '{self.INTERFACE}' không tồn tại."); sys.exit(1)

        while self.is_running:
            try:
                raw_data, _ = conn.recvfrom(65535)
                packet_len = len(raw_data)
                
                if packet_len < 14: continue 

                eth_protocol = struct.unpack('!H', raw_data[12:14])[0]
                offset = 14

                if eth_protocol == 0x8100:
                    if packet_len < 18: continue
                    eth_protocol = struct.unpack('!H', raw_data[16:18])[0]
                    offset = 18

                if eth_protocol == 0x0800:
                    if packet_len < offset + 20: continue 
                    
                    iph = struct.unpack('!BBHHHBBH4s4s', raw_data[offset:offset+20])
                    version_ihl = iph[0]
                    iph_length = (version_ihl & 0xF) * 4
                    total_length = iph[2]
                    protocol = iph[6] 
                    src_ip = socket.inet_ntoa(iph[8])
                    
                    if local_ip and src_ip == local_ip: continue
                    
                    if protocol == 6 or protocol == 17: 
                        if packet_len < offset + iph_length + 4: continue
                        src_port, dst_port = struct.unpack('!HH', raw_data[offset + iph_length : offset + iph_length + 4])
                        
                        monitored_ports = self.SYS_CONFIG['MONITORED_PORTS']
                        if monitored_ports:
                            if src_port not in monitored_ports and dst_port not in monitored_ports:
                                continue
                        else:
                            if src_port in {5050, 3306, 22} or dst_port in {5050, 3306, 22}: 
                                continue 

                    hex_str = None
                    if total_length > 100 and not self.current_sample_hex:
                        hex_str = self.format_hexdump(raw_data[:128])

                    with self.lock:
                        if hex_str and not self.current_sample_hex: self.current_sample_hex = hex_str
                        
                        if len(self.ip_sources) < 10000:
                            self.ip_sources[src_ip] = self.ip_sources.get(src_ip, 0) + 1
                            
                        if protocol == 1: self.packet_counts['ICMP'] += 1
                        elif protocol == 6: 
                            self.packet_counts['TCP'] += 1
                            if packet_len >= offset + iph_length + 14:
                                tcp_flags = raw_data[offset + iph_length + 13]
                                if tcp_flags & 0x02: self.packet_counts['SYN'] += 1
                        elif protocol == 17: self.packet_counts['UDP'] += 1

            except Exception: pass

    def run(self):
        global bk_engine_instance
        bk_engine_instance = self
        
        if os.path.exists(self.BASELINE_FILE):
            try: os.remove(self.BASELINE_FILE)
            except: pass
            
        threading.Thread(target=self.config_updater_worker, daemon=True).start()
        threading.Thread(target=self.analyzer_worker, daemon=True).start()
        threading.Thread(target=self.api_server_worker, daemon=True).start()
        
        self.executor.submit(self.send_telegram_alert, "Hệ thống Anomaly Sensor đã khởi động và hòa mạng thành công!", "INFO")
        self.sniff_hardware()

if __name__ == "__main__":
    engine = BkSocAnomalyEngine()
    engine.run()