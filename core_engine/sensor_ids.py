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
from soar_engine import load_whitelist_from_local_rules, _is_ip_whitelisted

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

# ========================================================================
# KAFKA, MITRE, PCAP & AI IMPORTS (Sprint 1+2: Enterprise Pipeline + AI/ML)
# ========================================================================
try:
    from kafka_producer import (
        publish_anomaly_alert,
        get_kafka_producer,
        KAFKA_BOOTSTRAP_SERVERS,
    )
    KAFKA_ENABLED = True
except ImportError:
    KAFKA_ENABLED = False

try:
    from mitre_mapper import map_attack_to_mitre, enrich_alert_with_mitre
    MITRE_ENABLED = True
except ImportError:
    MITRE_ENABLED = False

try:
    from pcap_engine import trigger_anomaly_pcap
    PCAP_ENABLED = True
except ImportError:
    PCAP_ENABLED = False

try:
    from ai_analyzer import analyze_traffic
    AI_ENABLED = True
except ImportError:
    AI_ENABLED = False

bk_engine_instance = None

class Colors:
    BLUE = '\033[94m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'; PURPLE = '\033[95m'; ENDC = '\033[0m'

# ========================================================================
# MICROSERVICE: API SERVER QUẢN LÝ TƯỜNG LỬA (PORT 5005)
# ========================================================================
# ========================================================================
# IP VALIDATION HELPER (shared with auth module logic)
# ========================================================================
import re as _re
_IPV4_RE = _re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def _validate_ip_safe(ip_str):
    """Validate IPv4 address — returns cleaned IP or None."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    ip_str = ip_str.strip()
    if not _IPV4_RE.match(ip_str):
        return None
    try:
        parts = ip_str.split(".")
        for p in parts:
            num = int(p)
            if num < 0 or num > 255:
                return None
        return ip_str
    except (ValueError, AttributeError):
        return None


def _safe_iptables_unblock(ip):
    """Unblock IP safely — no shell=True, IP validated."""
    if not _validate_ip_safe(ip):
        return False
    try:
        subprocess.run(
            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        subprocess.run(
            ['iptables', '-D', 'DOCKER-USER', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5, shell=False
        )
        return True
    except Exception as e:
        logging.getLogger("CuSUM-Sensor").error("iptables unblock error: %s", str(e))
        return False


class FirewallAPI(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    
    def _send_cors_headers(self):
        # Restrict CORS to specific origins
        self.send_header('Access-Control-Allow-Origin', 'http://192.168.13.129')
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
            
            # VALIDATE IP — prevents command injection
            if not _validate_ip_safe(ip):
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": "Invalid IP"}).encode('utf-8'))
                return
            
            # Safe unblock via SOAR Engine
            try:
                from soar_engine import get_soar_engine
                get_soar_engine().manual_unblock(ip)
            except Exception as e:
                self.logger.error("Error unblocking via SOAR: %s", e)
            
            try:
                os.remove(f'/tmp/ips_block_{ip}.txt')
            except OSError:
                pass
            
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
        # Fallback: tìm interface động nếu ens33 không tồn tại
        if not os.path.exists('/sys/class/net/' + self.INTERFACE):
            import subprocess as _sp
            try:
                _result = _sp.run(['ip', '-o', 'link', 'show', 'up'], capture_output=True, text=True, timeout=5)
                for _line in _result.stdout.split('\n'):
                    _parts = _line.split(':')
                    if len(_parts) >= 2:
                        _iface = _parts[1].strip()
                        if _iface and _iface != 'lo':
                            self.INTERFACE = _iface
                            self.logger.info("Tìm thấy interface thay thế: " + self.INTERFACE)
                            break
            except Exception:
                pass
        if not os.path.exists('/sys/class/net/' + self.INTERFACE):
            self.logger.error("Card mạng '" + self.INTERFACE + "' không tồn tại. Dùng 'any' để sniff tất cả interfaces.")
            self.INTERFACE = 'any' 
        self.BASELINE_FILE = '/tmp/ids_baseline.txt'
        
        self.is_running = True
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=15) 
        
        # 🎯 STATE MACHINE: Quản lý bão tin nhắn (Chống Spam Telegram)
        self.is_under_attack = False
        self.last_spoof_alert_time = 0
        
        self.packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'SYN': 0}
        self.ip_sources = {}
        self.mac_sources = {}       # 🎯 MAC tracking: {mac_str: {'count': N, 'ips': set()}}
        self.current_sample_hex = ""
        
        self.SYS_CONFIG = {
            'SCAN_INTERVAL': 5,
            'CUSUM_THRESHOLD': 700.0,
            'ENABLE_FIREWALL': True,
            'BAN_DURATION': 3600,
            'HOME_NET': '192.168.13.0/24',
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

    def get_interface_rx_packets(self):
        """Retrieve total rx_packets from kernel stats for accurate scaling."""
        if self.INTERFACE and self.INTERFACE != 'any':
            try:
                with open(f'/sys/class/net/{self.INTERFACE}/statistics/rx_packets', 'r') as f:
                    return int(f.read().strip())
            except Exception:
                pass
        # Fallback or if 'any': read /proc/net/dev
        try:
            total = 0
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.split(':')
                        iface = parts[0].strip()
                        if iface != 'lo':
                            stats = parts[1].split()
                            total += int(stats[1]) # rx packets is index 1
            return total
        except Exception:
            return None


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
        if ip_str in ["127.0.0.1", "Unknown", "No_Traffic"]: return True 
        # Bỏ qua MAC identifiers khi kiểm tra whitelist
        if ip_str.startswith("MAC:"): return True
        
        # Load latest whitelist dynamically from local.rules
        whitelist = load_whitelist_from_local_rules()
        # Ensure whitelist from SYS_CONFIG is included
        for ip in self.SYS_CONFIG['WHITELIST_IPS']:
            whitelist.add(ip)
            
        return _is_ip_whitelisted(ip_str, whitelist)

    def _resolve_mac_to_ip(self, mac_str):
        """🎯 Resolve MAC address → IP thật qua ARP table (/proc/net/arp).
        
        Khi tấn công spoofed IP, IP header bị giả mạo nhưng MAC address
        Layer 2 giữ nguyên. Trên cùng subnet (L2), ARP table chứa ánh xạ 
        MAC → IP thật.
        
        Returns: IP string hoặc None nếu không tìm thấy.
        """
        mac_lower = mac_str.lower().strip()
        
        # 1. Đọc ARP table từ /proc/net/arp (Linux kernel)
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    # Format: IP HW_type Flags MAC Device
                    if len(parts) >= 4:
                        arp_ip = parts[0]
                        arp_mac = parts[3].lower()
                        if arp_mac == mac_lower:
                            self.logger.info(f"[ARP] Resolved {mac_str} → {arp_ip}")
                            return arp_ip
        except Exception as e:
            self.logger.debug(f"[ARP] Không đọc được /proc/net/arp: {e}")
        
        # 2. Fallback: chạy lệnh `arp -n` 
        try:
            import subprocess
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=2, shell=False)
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3 and parts[2].lower() == mac_lower:
                    self.logger.info(f"[ARP-CMD] Resolved {mac_str} → {parts[0]}")
                    return parts[0]
        except Exception as e:
            self.logger.debug(f"[ARP-CMD] Fallback failed: {e}")
        
        # 3. Fallback cuối: gửi ARP request trực tiếp để populate cache
        try:
            import subprocess
            # Ping sweep nhanh subnet để populate ARP table
            home_net = self.SYS_CONFIG.get('HOME_NET', '192.168.13.0/24')
            subnet_base = '.'.join(home_net.split('.')[:3])
            # Chỉ thử ping vài IP phổ biến
            for i in [1, 2, 128, 129, 130, 131, 254]:
                target = f"{subnet_base}.{i}"
                subprocess.run(['arping', '-c', '1', '-w', '1', '-I', self.INTERFACE, target], 
                             capture_output=True, timeout=2, shell=False)
            
            # Đọc lại ARP table
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].lower() == mac_lower:
                        self.logger.info(f"[ARP-ARPING] Resolved {mac_str} → {parts[0]}")
                        return parts[0]
        except Exception as e:
            self.logger.debug(f"[ARP-ARPING] Fallback failed: {e}")
        
        return None

    def execute_firewall(self, attacker_ip, attack_type, tong_goi, detailed_msg=None):
        if self.is_ip_whitelisted(attacker_ip):
            return
        
        # VALIDATE IP — prevents command injection
        if not _validate_ip_safe(attacker_ip):
            self.logger.warning("[SOAR-IPS] Invalid IP rejected: %s", attacker_ip)
            return

        cache_file = f'/tmp/ips_block_{attacker_ip}.txt'
        if os.path.exists(cache_file):
            return
        
        try:
            from soar_engine import get_soar_engine
            engine = get_soar_engine()
            
            alert = {
                "src_ip": attacker_ip,
                "severity": "CRITICAL",
                "attack_type": attack_type,
                "confidence": 0.95
            }
            
            # Centralized block execution via SOAR
            result = engine.process_critical_alert(alert)
            
            if result.get("blocked"):
                with open(cache_file, 'w') as f:
                    f.write(str(time.time()))
                    
                self.logger.warning(
                    f"{Colors.RED}🛑 [SOAR-IPS] Đã chặn IP {attacker_ip} qua SOAR Engine | "
                    f"Lỗi: {attack_type}{Colors.ENDC}"
                )
                
                if detailed_msg:
                    self.executor.submit(self.send_telegram_alert, detailed_msg, "CRITICAL")
        except Exception as e:
            self.logger.error("Lỗi tích hợp SOAR Engine: %s", str(e))

    def log_anomaly_to_db(self, start_dt, now_dt, tcp, udp, icmp, gn, entropi, top_ip, hex_to_save, attack_type):
        conn = cursor = None
        try:
            conn = self.get_db_connection()
            if conn and conn.open:
                sql = """INSERT INTO ids_dulieu (tg_batdau, tg_ketthuc, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, top_ip, sample_hex) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                # hex_to_save đã được gắn nhãn attack_type ở analyzer_worker
                cursor = conn.cursor()
                cursor.execute(sql, (
                    start_dt.strftime('%Y-%m-%d %H:%M:%S'), 
                    now_dt.strftime('%Y-%m-%d %H:%M:%S'), 
                    tcp, udp, icmp, round(gn, 2), str(round(entropi, 3)), top_ip, hex_to_save
                ))
                conn.commit()
                self.logger.debug(f"[DB] Ghi: IP={top_ip} Gn={round(gn,2)} Type={attack_type}")
        except Exception as e:
            self.logger.error(f"[DB] Lỗi ghi anomaly: {e}")
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
        is_warmup, warmup_cycles = True, 1 
        rx_prev = self.get_interface_rx_packets()

        while self.is_running:
            scan_interval = self.SYS_CONFIG['SCAN_INTERVAL']
            time.sleep(scan_interval) 
            now_dt = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=7)
            start_dt = now_dt - timedelta(seconds=scan_interval)
            
            rx_now = self.get_interface_rx_packets()
            actual_packets = None
            if rx_prev is not None and rx_now is not None and rx_now >= rx_prev:
                actual_packets = rx_now - rx_prev
            rx_prev = rx_now

            with self.lock:
                tcp, udp, icmp, syn = self.packet_counts['TCP'], self.packet_counts['UDP'], self.packet_counts['ICMP'], self.packet_counts['SYN']
                current_ips = self.ip_sources.copy()
                current_macs = {k: dict(v) for k, v in self.mac_sources.items()}  # Deep copy
                hex_to_save = self.current_sample_hex 
                
                self.packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'SYN': 0}
                self.ip_sources.clear()
                self.mac_sources.clear()
                self.current_sample_hex = ""

            sampled_total = tcp + udp + icmp
            if actual_packets is not None and actual_packets > sampled_total and sampled_total > 0:
                scale = actual_packets / sampled_total
                tcp = int(tcp * scale)
                udp = int(udp * scale)
                icmp = int(icmp * scale)
                syn = int(syn * scale)
                for ip_key in current_ips:
                    current_ips[ip_key] = int(current_ips[ip_key] * scale)
                for mac_key in current_macs:
                    current_macs[mac_key]['count'] = int(current_macs[mac_key]['count'] * scale)

            tong_goi = tcp + udp + icmp
            unique_ips = len(current_ips)
            
            if tong_goi == 0:
                top_ip, entropi = "No_Traffic", 0.0
            else:
                top_ip = max(current_ips, key=current_ips.get) if current_ips else "No_Traffic"
                entropi = sum([- (c/tong_goi) * math.log2(c/tong_goi) for c in current_ips.values() if c > 0])
                
            # 🎯 SPOOFED DETECTION: Nhiều IP nhưng ít MAC → chắc chắn spoofed
            is_spoofed_attack = (unique_ips > 500) or (unique_ips > 100 and len(current_macs) < max(3, unique_ips * 0.1))
            
            # Tạo danh sách Top 5 IPs cho truy vết
            top_5_ips = sorted(current_ips.items(), key=lambda x: x[1], reverse=True)[:5] if current_ips else []
            
            # 🎯 MAC-TO-IP RESOLUTION: Khi spoofed, dùng MAC để tìm IP thật
            real_attacker_ip = None
            real_attacker_mac = None
            if is_spoofed_attack and current_macs:
                # Tìm MAC gửi nhiều gói nhất
                top_mac = max(current_macs.items(), key=lambda x: x[1].get('count', 0))
                real_attacker_mac = top_mac[0]
                mac_info = top_mac[1]
                mac_pkt_count = mac_info.get('count', 0)
                
                # Thử resolve MAC → IP qua ARP table
                resolved_ip = self._resolve_mac_to_ip(real_attacker_mac)
                if resolved_ip:
                    real_attacker_ip = resolved_ip
                    top_ip = resolved_ip  # 🎯 GHI ĐÈ top_ip bằng IP thật!
                    self.logger.info(f"[SPOOF-DETECT] MAC {real_attacker_mac} → IP thật: {resolved_ip} ({mac_pkt_count} pkts)")
                else:
                    # Không resolve được → dùng MAC làm identifier
                    top_ip = f"MAC:{real_attacker_mac}"
                    self.logger.info(f"[SPOOF-DETECT] Top MAC: {real_attacker_mac} ({mac_pkt_count} pkts), không resolve được IP")

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
                    
                    # Tăng dung sai cơ bản cho web traffic (tối thiểu 200 gói tin / 5s) để tránh bắt nhầm traffic rác/bình thường
                    dung_sai = max(200.0, trung_binh_ema * 0.5)
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
                        # top_ip đã được cập nhật bởi MAC resolver ở trên
                        
                        # Cảnh báo IP Spoofed (Giới hạn 1 tin mỗi 60 giây để tránh spam)
                        current_time = time.time()
                        if current_time - self.last_spoof_alert_time > 60:
                            top5_str = ", ".join([f"{ip}({cnt})" for ip, cnt in top_5_ips]) if top_5_ips else "N/A"
                            mac_info = f"\n┣ <b>MAC nguồn:</b> {real_attacker_mac}" if real_attacker_mac else ""
                            resolved_info = f"\n┣ <b>🎯 IP THẬT (ARP):</b> <code>{real_attacker_ip}</code>" if real_attacker_ip else ""
                            msg = (f"🔥 <b>CẢNH BÁO TẤN CÔNG SPOOFING</b>\n"
                                   f"┣ <b>Phân loại:</b> {attack_type}\n"
                                   f"┣ <b>IP hiển thị:</b> {top_ip}"
                                   f"{mac_info}"
                                   f"{resolved_info}\n"
                                   f"┣ <b>Lưu lượng:</b> {tong_goi} Pkts/{scan_interval}s\n"
                                   f"┣ <b>Số IP rác:</b> {unique_ips} IPs (Entropy: {round(entropi, 2)})\n"
                                   f"┗ <b>Hành động:</b> Ghi log + Truy vết MAC Layer 2.")
                            self.executor.submit(self.send_telegram_alert, msg, "CRITICAL")
                            self.last_spoof_alert_time = current_time
                    else:
                        # 🎯 HẠ NGƯỠNG NHƯNG CHỐNG FALSE POSITIVE TỪ IP TRẮNG
                        if self.is_ip_whitelisted(top_ip) and top_ip_count > (tong_goi * 0.5):
                            # Traffic chủ yếu từ IP được tin tưởng (Gateway, Cloudflare) -> Bình thường
                            attack_type = "BÌNH THƯỜNG"
                            if self.is_under_attack:
                                self.is_under_attack = False
                                self.executor.submit(self.send_telegram_alert, f"✅ <b>HỆ THỐNG ĐÃ AN TOÀN</b>\nLưu lượng mạng cao nhưng từ IP được tin cậy ({top_ip}).", "SUCCESS")
                        elif top_ip_count > (tong_goi * 0.2) and top_ip_count > (trung_binh_ema * 1.0):
                            if tong_goi < 500 and attack_proto != "SYN FLOOD":
                                # Dưới 500 gói tin và không phải SYN flood thì có thể là spike
                                attack_type = f"TRAFFIC SPIKE ({attack_proto})"
                            else:
                                if tong_goi < 1500 and attack_proto == "SYN FLOOD":
                                    attack_type = "PORT SCAN / SYN FLOOD"
                                else:
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
                            # Vẫn là tấn công nhưng phân tán → ghi nhận flood
                            attack_type = f"FLOOD {attack_proto} (PHÂN TÁN)"
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

            # ==================================================================
            # SPRINT 1: Kafka + MITRE + PCAP Integration
            # ==================================================================
            # 1. MITRE ATT&CK Mapping
            mitre_mapping = {}
            if MITRE_ENABLED:
                try:
                    mitre_mapping = map_attack_to_mitre(attack_type)
                    self.logger.info(
                        f"[MITRE] {attack_type} → "
                        f"{mitre_mapping.get('technique_id', 'N/A')} "
                        f"({mitre_mapping.get('technique_name', 'N/A')})"
                    )
                except Exception as e:
                    self.logger.warning(f"[MITRE] Mapping error: {e}")

            # 2. Kafka Alert Publishing
            if KAFKA_ENABLED:
                try:
                    alert_id = f"ANOM-{now_dt.strftime('%Y%m%d%H%M%S')}-{top_ip}"
                    self.executor.submit(
                        publish_anomaly_alert,
                        attack_type=attack_type,
                        src_ip=top_ip,
                        tcp=tcp,
                        udp=udp,
                        icmp=icmp,
                        gn_score=Gn,
                        entropy=entropi,
                        top_ip=top_ip,
                        mitre_mapping=mitre_mapping,
                        sample_hex=hex_to_save,
                        alert_id=alert_id,
                    )
                except Exception as e:
                    self.logger.warning(f"[KAFKA] Publish error: {e}")

            # 3. PCAP Forensics Capture (triggered on significant anomalies)
            if PCAP_ENABLED and Gn >= self.SYS_CONFIG['CUSUM_THRESHOLD']:
                try:
                    alert_id = f"ANOM-{now_dt.strftime('%Y%m%d%H%M%S')}-{top_ip}"
                    self.executor.submit(
                        trigger_anomaly_pcap,
                        alert_id=alert_id,
                        attack_type=attack_type,
                        src_ip=top_ip,
                        gn_score=Gn,
                    )
                except Exception as e:
                    self.logger.warning(f"[PCAP] Capture error: {e}")

            # 4. Hybrid AI/ML Analysis (Sprint 2)
            cusum_alert = Gn >= self.SYS_CONFIG['CUSUM_THRESHOLD']
            if AI_ENABLED:
                try:
                    ai_result = analyze_traffic(
                        tcp=tcp, udp=udp, icmp=icmp, syn=syn,
                        total_packets=tong_goi, unique_ips=unique_ips,
                        entropy=entropi, cusum_gn=Gn,
                        cusum_alert=cusum_alert,
                    )
                    # Escalate severity if both CUSUM + ML agree
                    if ai_result.get("hybrid_severity") == "CRITICAL":
                        self.logger.critical(
                            f"[AI/ML] CONFIRMED ATTACK: {ai_result.get('reason')} "
                            f"| confidence={ai_result.get('confidence', 0)}"
                        )
                        # Update attack_type to reflect AI confirmation
                        attack_type = f"{attack_type} [AI-CONFIRMED]"
                    elif ai_result.get("ml_anomaly") and not cusum_alert:
                        self.logger.warning(
                            f"[AI/ML] Subtle anomaly detected: {ai_result.get('reason')}"
                        )
                except Exception as e:
                    self.logger.warning(f"[AI/ML] Analysis error: {e}")

            # 🎯 GHI DB: Luôn ghi IP thật, kèm top5 IPs trong hex nếu là tấn công
            ip_to_save = top_ip
            if attack_type != "BÌNH THƯỜNG" and top_5_ips:
                top5_summary = " | ".join([f"{ip}:{cnt}pkts" for ip, cnt in top_5_ips])
                hex_to_save = f"[{attack_type}]\nTOP5: {top5_summary}\n{hex_to_save}" if hex_to_save else f"[{attack_type}]\nTOP5: {top5_summary}"
            
            self.executor.submit(self.log_anomaly_to_db, start_dt, now_dt, tcp, udp, icmp, Gn, entropi, ip_to_save, hex_to_save, attack_type)

    def sniff_hardware(self):
        local_ip = self.get_ip_address(self.INTERFACE)
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            # Tối ưu SO_RCVBUF cho bắt gói tốc độ cao (50MB Buffer)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 52428800)
            try:
                conn.bind((self.INTERFACE, 0))
            except OSError:
                conn.bind(('eth0', 0))
            self.logger.info("[CUSUM] Đã kết nối card mạng [" + self.INTERFACE + "]. Sẵn sàng bắt gói tin (Multiprocessing Mode)!")
        except PermissionError:
            self.logger.error("Cần quyền Root để mở Raw Socket!"); sys.exit(1)
        except OSError as e:
            self.logger.error("Không thể mở Raw Socket: " + str(e) + ". Chạy chế độ Demo (dữ liệu giả lập)...")
            self.run_demo_mode()
            return

        batch = []
        BATCH_SIZE = 5000  # Gom số lượng gói tin trước khi gửi sang ThreadPool
        last_flush_time = time.time()
        
        self.logger.info("[CUSUM] Bắt đầu quá trình Sniffing (Inline Fast-Parsing Mode) siêu tốc.")
        conn.settimeout(1.0)
        
        # Biến đệm để giảm overhead lock
        local_tcp = 0; local_udp = 0; local_icmp = 0; local_syn = 0
        local_ips = {}
        local_macs = {}   # 🎯 MAC tracking: {mac_bytes: {'count': N, 'ips': set()}}
        last_flush_time = time.time()
        
        # Pre-compute local_ip bytes if available
        local_ip_bytes = socket.inet_aton(local_ip) if local_ip else b''

        # Rate limiting variables for parsing
        window_start = time.time()
        pkts_in_window = 0
        MAX_PKTS_PER_WINDOW = 500  # Max 5000 packets parsed per second (500 per 0.1s)

        while self.is_running:
            try:
                now = time.time()
                elapsed = now - window_start
                if elapsed >= 0.1:
                    window_start = now
                    pkts_in_window = 0
                elif pkts_in_window >= MAX_PKTS_PER_WINDOW:
                    # Sleep for the rest of the 0.1s window to yield CPU & GIL
                    time.sleep(0.1 - elapsed)
                    window_start = time.time()
                    pkts_in_window = 0

                raw_data, _ = conn.recvfrom(65535)
                pkts_in_window += 1
                
                
                # Fast Parsing (Không dùng struct.unpack để tiết kiệm CPU)
                if len(raw_data) >= 34 and raw_data[12:14] == b'\x08\x00': # IPv4
                    src_ip_bytes = raw_data[26:30]
                    if src_ip_bytes != local_ip_bytes:
                        proto = raw_data[23]
                        
                        # 🎯 Trích xuất Source MAC (bytes 6-12 trong Ethernet frame)
                        src_mac_bytes = raw_data[6:12]
                        if src_mac_bytes not in local_macs:
                            local_macs[src_mac_bytes] = {'count': 0, 'ips': set()}
                        local_macs[src_mac_bytes]['count'] += 1
                        if len(local_macs[src_mac_bytes]['ips']) < 100:  # Giới hạn memory
                            local_macs[src_mac_bytes]['ips'].add(src_ip_bytes)
                        
                        # Trích xuất IP
                        if len(local_ips) < 10000:
                            local_ips[src_ip_bytes] = local_ips.get(src_ip_bytes, 0) + 1
                            
                        if proto == 6: 
                            local_tcp += 1
                            # Check SYN flag (offset 14 + (IHL*4) + 13)
                            ihl = (raw_data[14] & 0x0F) * 4
                            if len(raw_data) >= 14 + ihl + 14:
                                if raw_data[14 + ihl + 13] & 0x02:
                                    local_syn += 1
                        elif proto == 17: local_udp += 1
                        elif proto == 1: local_icmp += 1
                        
                        if not self.current_sample_hex:
                            data = raw_data[:128]
                            res = []
                            for i in range(0, len(data), 16):
                                chunk = data[i:i+16]
                                hex_part = ' '.join(f"{b:02x}" for b in chunk)
                                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                                res.append(f"{i:04x}   {hex_part:<47}  {ascii_part}")
                            self.current_sample_hex = '\n'.join(res)
                            
            except socket.timeout:
                pass
            except Exception: 
                pass

            current_time = time.time()
            if current_time - last_flush_time >= 0.5:
                # Flush buffer vào biến tổng mỗi 0.5s
                with self.lock:
                    self.packet_counts['TCP'] += local_tcp
                    self.packet_counts['UDP'] += local_udp
                    self.packet_counts['ICMP'] += local_icmp
                    self.packet_counts['SYN'] += local_syn
                    for ip_b, count in local_ips.items():
                        ip_str = socket.inet_ntoa(ip_b)
                        self.ip_sources[ip_str] = self.ip_sources.get(ip_str, 0) + count
                    # 🎯 Flush MAC data
                    for mac_b, mac_data in local_macs.items():
                        mac_str = ':'.join(f'{b:02x}' for b in mac_b)
                        if mac_str not in self.mac_sources:
                            self.mac_sources[mac_str] = {'count': 0, 'ips': set()}
                        self.mac_sources[mac_str]['count'] += mac_data['count']
                        for ip_b_item in mac_data['ips']:
                            if len(self.mac_sources[mac_str]['ips']) < 200:
                                try:
                                    self.mac_sources[mac_str]['ips'].add(socket.inet_ntoa(ip_b_item))
                                except: pass
                
                local_tcp = 0; local_udp = 0; local_icmp = 0; local_syn = 0
                local_ips.clear()
                local_macs.clear()
                last_flush_time = current_time

    def _on_batch_parsed(self, future):
        """Callback khi một tiến trình phân tích xong 1 lô (batch) gói tin"""
        try:
            res = future.result()
            if not res: return
            counts, ip_srcs, hex_str = res
            
            with self.lock:
                self.packet_counts['TCP'] += counts['TCP']
                self.packet_counts['UDP'] += counts['UDP']
                self.packet_counts['ICMP'] += counts['ICMP']
                self.packet_counts['SYN'] += counts['SYN']
                
                for ip, cnt in ip_srcs.items():
                    if len(self.ip_sources) < 10000:
                        self.ip_sources[ip] = self.ip_sources.get(ip, 0) + cnt
                        
                if hex_str and not self.current_sample_hex:
                    self.current_sample_hex = hex_str
        except Exception as e:
            self.logger.error(f"Lỗi ThreadPool callback: {e}")

    def run_demo_mode(self):
        """Chế độ Demo — Tạo dữ liệu giả lập khi không có interface"""
        import random
        self.logger.info("[DEMO] Chạy chế độ Demo — Tạo dữ lưu giả lập mỗi 5 giây...")
        demo_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.1', '203.0.113.5', '198.51.100.10', '192.168.1.1', '10.0.0.1']
        while self.is_running:
            try:
                time.sleep(5)
                ip = random.choice(demo_ips)
                tcp = random.randint(10, 500)
                udp = random.randint(5, 200)
                icmp = random.randint(0, 50)
                gn = round(random.uniform(0.1, 8.0), 2)
                entropi = round(random.uniform(1.0, 5.0), 2)
                hex_dump = ' '.join(['%02x' % random.randint(0, 255) for _ in range(random.randint(20, 100))])
                conn = None
                try:
                    from config.database import get_db_connection
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("""INSERT INTO ids_dulieu (tg_ketthuc, top_ip, soluong_tcp, soluong_udp, soluong_icmp, Gn, entropi, sample_hex) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, tcp, udp, icmp, gn, entropi, hex_dump))
                        conn.commit()
                        cursor.close()
                        self.logger.info("[DEMO] Đã ghi dữ liệu giả lập: IP=" + ip + " TCP=" + str(tcp) + " UDP=" + str(udp) + " Gn=" + str(gn))
                except Exception as e:
                    self.logger.error("[DEMO] Lỗi ghi DB: " + str(e))
                finally:
                    if conn:
                        try: conn.close()
                        except: pass
            except Exception as e:
                self.logger.error("[DEMO] Lỗi: " + str(e))

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

# ========================================================================
# HÀM XỬ LÝ SONG SONG (MULTIPROCESSING) CHỐNG NGHẼN CỔ CHAI GIL
# Chú ý: Hàm này phải nằm ngoài class để Pickler có thể truyền vào ProcessPool
# ========================================================================
def _parse_packet_batch(batch, local_ip, monitored_ports):
    import struct
    import socket
    
    counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'SYN': 0}
    ip_srcs = {}
    hex_sample = None
    
    for raw_data in batch:
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
                
                if monitored_ports:
                    if src_port not in monitored_ports and dst_port not in monitored_ports:
                        continue
                else:
                    if src_port in {5050, 3306, 22} or dst_port in {5050, 3306, 22}: 
                        continue 

            # Luôn tạo hex_sample cho gói tin đầu tiên trong lô để có dữ liệu phân tích chi tiết (OSI/DPI)
            if not hex_sample:
                data = raw_data[:128]
                res = []
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_part = ' '.join(f"{b:02x}" for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    res.append(f"{i:04x}   {hex_part:<47}  {ascii_part}")
                hex_sample = '\n'.join(res)
                
            ip_srcs[src_ip] = ip_srcs.get(src_ip, 0) + 1
            
            if protocol == 1: counts['ICMP'] += 1
            elif protocol == 6: 
                counts['TCP'] += 1
                if packet_len >= offset + iph_length + 14:
                    tcp_flags = raw_data[offset + iph_length + 13]
                    if tcp_flags & 0x02: counts['SYN'] += 1
            elif protocol == 17: counts['UDP'] += 1
            
    return counts, ip_srcs, hex_sample

if __name__ == "__main__":
    engine = BkSocAnomalyEngine()
    engine.run()