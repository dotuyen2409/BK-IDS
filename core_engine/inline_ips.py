# /home/bk_ids/bk-ids/core_engine/inline_ips.py

import sys
import os
import time
import json
import logging
import signal
import ipaddress
import threading
import subprocess
import re
import queue
import pymysql
from datetime import datetime, timedelta, timezone

# ========================================================================
# IP VALIDATION HELPER — prevents command injection
# ========================================================================
_IPV4_RE = re.compile(
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

sys.path.append('/app')
from core_engine.soar_engine import load_whitelist_from_local_rules, _is_ip_whitelisted

# ========================================================================
# KAFKA, MITRE & PCAP IMPORTS (Sprint 1: Enterprise Pipeline)
# ========================================================================
try:
    from kafka_producer import (
        publish_signature_alert,
        get_kafka_producer,
    )
    KAFKA_ENABLED = True
except ImportError:
    KAFKA_ENABLED = False

try:
    from mitre_mapper import map_attack_to_mitre
    MITRE_ENABLED = True
except ImportError:
    MITRE_ENABLED = False

try:
    from pcap_engine import trigger_signature_pcap
    PCAP_ENABLED = True
except ImportError:
    PCAP_ENABLED = False

# ========================================================================
# KIỂM TRA THƯ VIỆN LÕI
# ========================================================================
try:
    import requests
except ImportError:
    print("\n" + "="*70)
    print(" CRITICAL ERROR: Lõi IPS thiếu thư viện 'requests' cho Telegram.")
    print("💡 CÁCH SỬA LỖI: sudo docker exec -it bkids_misuse_ips pip3 install requests")
    print("="*70 + "\n")
    sys.exit(1)

class Colors:
    BLUE = '\033[94m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'; PURPLE = '\033[95m'; ENDC = '\033[0m'

# ========================================================================
# BK-IDS SOC: ENTERPRISE INLINE IPS ENGINE (PRODUCTION GRADE)
# Đã vá triệt để lỗi đồng bộ dữ liệu RAM -> Ổ cứng (JSON)
# ========================================================================
class BkSocIPSEngine:
    def __init__(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
        self.logger = logging.getLogger("Bk-IPS-Core")
        
        self.SNORT_LOG_FILE = '/var/log/snort/alert_json.txt'
        self.BANS_STATE_FILE = '/app/bans_state.json'
        
        self.is_running = True
        self.snort_process = None
        self.executor = ThreadPoolExecutor(max_workers=15)
        self.ban_lock = threading.Lock()
        
        self.db_queue = queue.Queue(maxsize=10000)
        self.metrics = {'alerts_processed': 0, 'ips_dropped': 0, 'db_writes': 0}
        
        # 🎯 STATE MACHINE QUẢN LÝ TELEGRAM (Chống Spam Tin Nhắn)
        self.telegram_alert_cache = {}
        self.TELEGRAM_COOLDOWN_SEC = 60 

        self.config = {
            'ENABLE_FIREWALL': True, 
            'BAN_DURATION': 3600, 
            'PROTECTED_NET': '192.168.0.0/16'
        }
        self.active_bans = {}
        self.whitelist_ips = set(["127.0.0.1", "0.0.0.0"])
        
        self._auto_discover_whitelist()

        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)

    # ---------------------------------------------------------
    # TELEGRAM & ENV UTILS
    # ---------------------------------------------------------
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
        
        text = f"{icon} <b>BK-IDS SOC ALERT (SIGNATURE IPS)</b>\n"
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

    # ---------------------------------------------------------
    # HỆ THỐNG QUẢN LÝ TƯỜNG LỬA VÀ TRẠNG THÁI
    # ---------------------------------------------------------
    def _auto_discover_whitelist(self):
        try:
            output = subprocess.check_output(["hostname", "-I"]).decode()
            for ip in output.split():
                if ipaddress.ip_address(ip).version == 4:
                    self.whitelist_ips.add(ip)
        except Exception: pass

    def _load_ban_state(self):
        if os.path.exists(self.BANS_STATE_FILE):
            try:
                with open(self.BANS_STATE_FILE, 'r') as f:
                    saved_bans = json.load(f)
                    current_time = time.time()
                    with self.ban_lock:
                        for ip, unban_time in saved_bans.items():
                            if unban_time > current_time:
                                self.active_bans[ip] = unban_time
                                self._enforce_iptables_drop(ip)
                self.logger.info(f"🔄 Đã khôi phục {len(self.active_bans)} IP đang bị khóa.")
            except Exception: pass

    def _save_ban_state(self):
        with self.ban_lock:
            try:
                with open(self.BANS_STATE_FILE, 'w') as f:
                    json.dump(self.active_bans, f)
            except Exception: pass

    def run_host_command(self, cmd_list):
        """Execute host command safely — uses list form, no shell=True."""
        try:
            if isinstance(cmd_list, list):
                subprocess.run(
                    cmd_list, check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    shell=False
                )
        except Exception:
            pass

    def _enforce_iptables_drop(self, ip):
        """Block IP safely — no shell=True, IP validated."""
        if not _validate_ip_safe(ip):
            self.logger.warning("[IPS] Invalid IP rejected: %s", ip)
            return
        # Check then add (mangle PREROUTING)
        self.run_host_command(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-s', ip, '-j', 'DROP'])
        self.run_host_command(['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1', '-s', ip, '-j', 'DROP'])
        # Check then add (DOCKER-USER)
        self.run_host_command(['iptables', '-C', 'DOCKER-USER', '-s', ip, '-j', 'DROP'])
        self.run_host_command(['iptables', '-I', 'DOCKER-USER', '1', '-s', ip, '-j', 'DROP'])
        # Check then add (INPUT)
        self.run_host_command(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'])
        self.run_host_command(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])

    def _remove_iptables_drop(self, ip):
        """Unblock IP safely — no shell=True, IP validated."""
        if not _validate_ip_safe(ip):
            return
        self.run_host_command(['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-s', ip, '-j', 'DROP'])
        self.run_host_command(['iptables', '-D', 'DOCKER-USER', '-s', ip, '-j', 'DROP'])
        self.run_host_command(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
        self.run_host_command(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")

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

    def _get_rule_msg(self, sid):
        try:
            conn = self.get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT msg FROM rules WHERE sid = %s", (sid,))
                row = cursor.fetchone()
                conn.close()
                if row and row['msg']:
                    return row['msg']
        except Exception:
            pass
        return None

    # ---------------------------------------------------------
    # WORKERS CHẠY NGẦM
    # ---------------------------------------------------------
    def config_updater_worker(self):
        env_path = '/app/.env'
        while self.is_running:
            try:
                if os.path.exists(env_path):
                    with open(env_path, 'r') as f:
                        for line in f:
                            if line.startswith('ENABLE_FIREWALL='):
                                self.config['ENABLE_FIREWALL'] = line.split('=')[1].strip().lower() == 'true'
                            elif line.startswith('BAN_DURATION='):
                                self.config['BAN_DURATION'] = int(line.split('=')[1].strip())
            except Exception: pass
            time.sleep(10)

    def snort_watchdog_worker(self):
        spam_counter = 0  # 🎯 Thêm biến đếm chống Spam
        while self.is_running:
            time.sleep(15)
            if self.snort_process and self.snort_process.poll() is not None:
                spam_counter += 1
                self.logger.critical(f"{Colors.RED}☠️ BÁO ĐỘNG: Lõi Snort 3 đã chết đột ngột! Đang tiến hành Auto-Healing...{Colors.ENDC}")
                
                # 🎯 CHỈ GỬI TELEGRAM TỐI ĐA 3 LẦN NẾU LIÊN TỤC SẬP
                if spam_counter <= 3:
                    self.executor.submit(self.send_telegram_alert, f"Tiến trình Lõi Snort 3 IPS đã bị sập (Lần {spam_counter}). Đang tiến hành khôi phục tự động (Auto-Healing)...", "CRITICAL")
                elif spam_counter == 4:
                    self.executor.submit(self.send_telegram_alert, "⚠️ [ANTI-SPAM] Lõi Snort 3 liên tục sập (cấu hình sai hoặc lỗi hệ thống). Đã TẠM DỪNG gửi tin nhắn cảnh báo để tránh Spam. Vui lòng kiểm tra Docker Log!", "WARNING")
                
                self.start_snort_core()
            else:
                # Nếu Snort sống khỏe qua 15s, reset lại bộ đếm Spam
                spam_counter = 0

    def metrics_worker(self):
        while self.is_running:
            time.sleep(60)
            self.logger.info(f"📊 METRICS | Xử lý: {self.metrics['alerts_processed']} | Chặn: {self.metrics['ips_dropped']} | CSDL: {self.metrics['db_writes']}")

    

    def ban_manager_worker(self):
        while self.is_running:
            time.sleep(5)
            current_time = time.time()
            expired_ips = []
            
            with self.ban_lock:
                for ip, unban_time in list(self.active_bans.items()):
                    if current_time >= unban_time: 
                        expired_ips.append(ip)
                        del self.active_bans[ip] # Xóa khỏi RAM
            
            # 🎯 NẾU CÓ IP HẾT HẠN -> PHẢI LƯU XUỐNG Ổ CỨNG NGAY ĐỂ ĐỒNG BỘ WEB
            if expired_ips:
                self._save_ban_state()
                
                for ip in expired_ips:
                    self._remove_iptables_drop(ip)
                    self.logger.info(f"{Colors.GREEN}🔓 [FIREWALL] Đã tự động mở khóa IP {ip} (Hết hạn án phạt).{Colors.ENDC}")
                    
                    # Bắn Telegram thông báo mãn hạn
                    self.executor.submit(
                        self.send_telegram_alert, 
                        f"IP <code>{ip}</code> đã hết thời gian phong tỏa và được mở khóa tự động.", 
                        "SUCCESS"
                    )

    def is_noise_ip(self, ip_str):
        # Dynamically load latest whitelist rules from local.rules
        whitelist = load_whitelist_from_local_rules()
        # Ensure our autodiscovered local IPs are also checked
        for lip in self.whitelist_ips:
            whitelist.add(lip)
        if _is_ip_whitelisted(ip_str, whitelist):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback: return True
        except ValueError:
            return True
        return False

    # ---------------------------------------------------------
    # CORE LOGIC: CHÉM & XỬ LÝ CẢNH BÁO
    # ---------------------------------------------------------
    def execute_firewall(self, attacker_ip, reason):
        if not self.config['ENABLE_FIREWALL']: return
        try:
            ip_obj = ipaddress.ip_address(attacker_ip)
            if ip_obj.version != 4: return 
            clean_ip = str(ip_obj)
        except ValueError: return

        try:
            from soar_engine import get_soar_engine
            engine = get_soar_engine()
            
            soar_alert = {
                "src_ip": clean_ip,
                "severity": "CRITICAL",
                "attack_type": reason,
                "confidence": 0.99
            }
            
            result = engine.process_critical_alert(soar_alert)
            if result.get("blocked"):
                self.metrics['ips_dropped'] += 1
                self.logger.warning(f"{Colors.RED}🛑 [FIREWALL] PHONG TỎA IP {clean_ip} QUA SOAR | Vi phạm: {reason}{Colors.ENDC}")
                
                # Bắn Telegram chi tiết khi chặt đứt IP
                alert_msg = (
                    f"🛑 <b>MÁY CHẾM IPS ĐÃ KÍCH HOẠT</b>\n"
                    f"┣ <b>Mục tiêu bị chặn:</b> <code>{clean_ip}</code>\n"
                    f"┣ <b>Chữ ký Mã độc:</b> {reason}\n"
                    f"┣ <b>Thời gian cấm:</b> {self.config['BAN_DURATION']} giây\n"
                    f"┗ <b>Hành động:</b> Đã phong tỏa qua SOAR."
                )
                self.executor.submit(self.send_telegram_alert, alert_msg, "CRITICAL")
        except Exception as e:
            self.logger.error("Lỗi tích hợp SOAR Engine: %s", str(e))

    def process_alert(self, line):
        try:
            alert = json.loads(line)
            
            if not isinstance(alert, dict):
                return

            # --- 1. Lấy IP Nguồn (ip_src) ---
            src_ip = 'Unknown'
            if 'src_addr' in alert:
                src_ip = alert['src_addr']
            elif 'src_ap' in alert:
                src_ip = alert['src_ap'].split(':')[0] if ':' in alert['src_ap'] else alert['src_ap']
            
            if src_ip.startswith("::ffff:"):
                src_ip = src_ip.replace("::ffff:", "")

            # --- 2. Lấy IP Đích (ip_dst) ---
            dst_ip = 'Unknown'
            if 'dst_addr' in alert:
                dst_ip = alert['dst_addr']
            elif 'dst_ap' in alert:
                dst_ip = alert['dst_ap'].split(':')[0] if ':' in alert['dst_ap'] else alert['dst_ap']
                
            if dst_ip.startswith("::ffff:"):
                dst_ip = dst_ip.replace("::ffff:", "")

            if src_ip == 'Unknown' or dst_ip == 'Unknown':
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if len(ips) >= 1 and src_ip == 'Unknown': src_ip = ips[0]
                if len(ips) >= 2 and dst_ip == 'Unknown': dst_ip = ips[1]

            is_whitelisted = self.is_noise_ip(src_ip)
            protocol = str(alert.get('proto', 'TCP')).upper()
            
            # --- 3. 🎯 VÁ LỖI TÊN MÃ ĐỘC (Dịch mã GID:SID:REV) ---
            raw_msg = alert.get('msg')
            if not raw_msg and 'rule' in alert:
                if isinstance(alert['rule'], dict):
                    raw_msg = alert['rule'].get('msg')
                else:
                    raw_msg = str(alert['rule'])
            
            # Nếu Snort nhả ra dạng "1:1000001:5", bóc số 1000001 ra chọc vào Database lấy tên xịn
            if raw_msg and re.match(r'^\d+:(\d+):\d+$', raw_msg):
                sid = re.match(r'^\d+:(\d+):\d+$', raw_msg).group(1)
                real_msg = self._get_rule_msg(sid)
                if real_msg:
                    raw_msg = real_msg

            if not raw_msg:
                raw_msg = 'Unknown Signature'

            action_snort = str(alert.get('action', 'alert')).upper()
            action_db = "ALERT"
            
            # Làm sạch chuỗi hiển thị
            clean_msg = raw_msg.replace("[Bk-IDS]", "").replace("[DROP]", "").strip("- ")
            self.metrics['alerts_processed'] += 1

            if "[DROP]" in raw_msg or action_snort in ["BLOCK", "DROP", "REJECT"]:
                action_db = "DROP"
                if is_whitelisted:
                    self.logger.warning(f"{Colors.YELLOW}⚠️ [IDS] Tấn công từ IP Whitelist ({src_ip}): {clean_msg}{Colors.ENDC}")
                else:
                    self.logger.warning(f"{Colors.PURPLE}🪓 [IPS] Máy chém xử lý: {src_ip} | Mã độc: {clean_msg}{Colors.ENDC}")
                    self.executor.submit(self.execute_firewall, src_ip, clean_msg)
            else:
                self.logger.info(f"{Colors.BLUE}👁️ [IDS] Cảnh báo: {src_ip} | Dấu hiệu: {clean_msg}{Colors.ENDC}")
                
                if not is_whitelisted:
                    cache_key = f"{src_ip}_{clean_msg}"
                    current_time = time.time()
                    last_alert_time = self.telegram_alert_cache.get(cache_key, 0)
                    
                    if current_time - last_alert_time > self.TELEGRAM_COOLDOWN_SEC:
                        self.telegram_alert_cache[cache_key] = current_time
                        alert_msg = (
                            f"⚠️ <b>PHÁT HIỆN DẤU HIỆU XÂM NHẬP</b>\n"
                            f"┣ <b>Nguồn:</b> <code>{src_ip}</code>\n"
                            f"┣ <b>Giao thức:</b> {protocol}\n"
                            f"┣ <b>Chữ ký:</b> {clean_msg}\n"
                            f"┗ <b>Trạng thái:</b> Đã lưu lịch sử, chưa áp dụng chặn."
                        )
                        self.executor.submit(self.send_telegram_alert, alert_msg, "WARNING")

            # --- 4. 🎯 VÁ LỖI MÚI GIỜ (Ép cứng GMT+7 Việt Nam) ---
            tz_vn = timezone(timedelta(hours=7))
            local_time = datetime.now(tz_vn).strftime('%Y-%m-%d %H:%M:%S')
            
            if not self.db_queue.full():
                self.db_queue.put((local_time, src_ip, dst_ip, clean_msg, protocol, action_db))

            # ==================================================================
            # SPRINT 1: Kafka + MITRE + PCAP Integration
            # ==================================================================
            # 1. MITRE ATT&CK Mapping
            mitre_mapping = {}
            if MITRE_ENABLED:
                try:
                    mitre_mapping = map_attack_to_mitre(clean_msg)
                except Exception as e:
                    self.logger.warning(f"[MITRE] Mapping error: {e}")

            # 2. Kafka Alert Publishing
            if KAFKA_ENABLED:
                try:
                    alert_id = f"SIG-{datetime.now(tz_vn).strftime('%Y%m%d%H%M%S')}-{src_ip}"
                    self.executor.submit(
                        publish_signature_alert,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        sig_name=clean_msg,
                        protocol=protocol,
                        action=action_db,
                        mitre_mapping=mitre_mapping,
                        sid=sid if 'sid' in dir() else None,
                        alert_id=alert_id,
                    )
                except Exception as e:
                    self.logger.warning(f"[KAFKA] Publish error: {e}")

            # 3. PCAP Forensics Capture (triggered on DROP/BLOCK actions)
            if PCAP_ENABLED and action_db == "DROP":
                try:
                    alert_id = f"SIG-PCAP-{datetime.now(tz_vn).strftime('%Y%m%d%H%M%S')}-{src_ip}"
                    self.executor.submit(
                        trigger_signature_pcap,
                        alert_id=alert_id,
                        sig_name=clean_msg,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                    )
                except Exception as e:
                    self.logger.warning(f"[PCAP] Capture error: {e}")

        except Exception as e:
            self.logger.error(f"❌ Lỗi đọc Log Snort 3: {e}")

    def db_writer_worker(self):
        conn = None
        while self.is_running or not self.db_queue.empty():
            try:
                if not conn or not conn.open: 
                    conn = self.get_db_connection()
                    if not conn:
                        self.logger.error(f"{Colors.RED}❌ MẤT KẾT NỐI DATABASE! IPS không thể ghi log lên Web.{Colors.ENDC}")
                        time.sleep(5)
                        continue

                batch = []
                try:
                    while len(batch) < 100:
                        batch.append(self.db_queue.get(timeout=2))
                except queue.Empty: pass

                if batch and conn and conn.open:
                    cursor = conn.cursor()
                    # 🎯 VÁ LỖI CSDL: Bổ sung ip_dst vào câu lệnh INSERT (Thành 6 giá trị %s)
                    sql = "INSERT INTO misuse_alerts (timestamp, ip_src, ip_dst, sig_name, protocol, action) VALUES (%s, %s, %s, %s, %s, %s)"
                    cursor.executemany(sql, batch)
                    conn.commit()
                    cursor.close()
                    self.metrics['db_writes'] += len(batch)
                    self.logger.info(f"{Colors.GREEN}✅ Đã đồng bộ thành công {len(batch)} cảnh báo lên Website!{Colors.ENDC}")
            except Exception as e:
                self.logger.error(f"{Colors.RED}❌ LỖI GHI SQL VÀO CSDL: {e}{Colors.ENDC}")
                time.sleep(5)
        if conn and conn.open: conn.close()


    # ---------------------------------------------------------
    # KHỞI ĐỘNG VÀ QUẢN LÝ TIẾN TRÌNH SNORT
    # ---------------------------------------------------------
    def start_snort_core(self):
        self.logger.info(f"{Colors.YELLOW}🛠️ Đang dọn dẹp hệ thống để khởi động Snort 3...{Colors.ENDC}")
        
        # 1. Giết sạch Snort cũ để giải phóng NFQUEUE 0 (Tránh xung đột)
        subprocess.run("pkill -9 snort", shell=True, check=False)
        time.sleep(1)

        # 2. Thiết lập Iptables (Gắn luồng traffic vào hàng đợi số 0)
        self.run_host_command("iptables -D DOCKER-USER -p tcp -m multiport --dports 80,8080,5000 -j NFQUEUE --queue-num 0 2>/dev/null || true")
        self.run_host_command("iptables -D INPUT -p tcp -m multiport --dports 80,8080,5000 -j NFQUEUE --queue-num 0 2>/dev/null || true")
        self.run_host_command("iptables -I DOCKER-USER 1 -p tcp -m multiport --dports 80,8080,5000 -j NFQUEUE --queue-num 0")
        self.run_host_command("iptables -I INPUT 1 -p tcp -m multiport --dports 80,8080,5000 -j NFQUEUE --queue-num 0")

        # 3. Tự động tìm kiếm Binary và DAQ (giữ nguyên logic cũ của bạn)
        def auto_discover_snort():
            paths = ["/home/snorty/snort3/bin/snort", "/usr/local/bin/snort", "/usr/bin/snort"]
            for p in paths:
                if os.path.exists(p): return p
            return "snort"

        def auto_discover_daq_dir():
            dirs = ["/home/snorty/snort3/lib/daq", "/usr/local/lib/daq", "/usr/lib/daq"]
            for d in dirs:
                if os.path.exists(d): return d
            return "/usr/local/lib/daq"

        snort_bin = auto_discover_snort()
        daq_dir = auto_discover_daq_dir()
        
        # 🎯 LƯU Ý: Với DAQ nfq, Snort dùng tham số -i để định danh Queue ID
        # Chúng ta dùng hàng đợi số 0 (khớp với lệnh iptables --queue-num 0)
        queue_id = "0" 
        
        self.logger.info(f"🚀 Khởi chạy Snort 3 [Inline Mode] [DAQ: nfq] [Queue ID: {queue_id}]")

        snort_cmd = [
            snort_bin,
            "-c", "/app/snort.lua",
            "--daq-dir", daq_dir,
            "-Q",
            "--daq", "nfq",
            "--daq-var", f"queue={queue_id}",
            "-l", "/var/log/snort",
            "-k", "none",
            "--lua", "alert_json = { file = true }",
        ]
        
        # Thêm các tệp luật nếu tồn tại
        # if os.path.exists("/app/core_engine/pulled_rules.rules"):
        #     snort_cmd.extend(["-R", "/app/core_engine/pulled_rules.rules"])
        if os.path.exists("/app/core_engine/local.rules"):
            snort_cmd.extend(["-R", "/app/core_engine/local.rules"])

        try:
            # 🎯 NÂNG CẤP: Chuyển hướng stderr về stdout để bạn thấy lỗi trong 'docker logs'
            self.snort_process = subprocess.Popen(
                snort_cmd, 
                stdout=None, 
                stderr=subprocess.STDOUT
            )
            self.logger.info(f"{Colors.BLUE}🛡️ Engine Nội Tuyến (Inline) đã phục kích thành công!{Colors.ENDC}")
        except Exception as e:
            self.logger.error(f"❌ Lỗi khởi động Snort: {e}")

    def tail_logs(self):
        current_ino = -1
        while self.is_running:
            if not os.path.exists(self.SNORT_LOG_FILE):
                time.sleep(1)
                continue
            try:
                stat = os.stat(self.SNORT_LOG_FILE)
                current_ino = stat.st_ino
                with open(self.SNORT_LOG_FILE, 'r', encoding='utf-8') as file:
                    file.seek(0, os.SEEK_END)
                    while self.is_running:
                        line = file.readline()
                        if not line:
                            if not os.path.exists(self.SNORT_LOG_FILE) or os.stat(self.SNORT_LOG_FILE).st_ino != current_ino:
                                break 
                            time.sleep(0.1)
                            continue
                        self.process_alert(line)
            except Exception: 
                time.sleep(2)

    def graceful_shutdown(self, sig, frame):
        self.logger.info(f"\n{Colors.YELLOW}🔻 Nhận lệnh ngắt. Đang giải phóng bộ nhớ và Iptables...{Colors.ENDC}")
        self.is_running = False
        self.executor.shutdown(wait=False)
        if self.snort_process:
            try:
                self.snort_process.terminate()
                self.run_host_command("pkill -9 snort")
            except Exception: pass
        sys.exit(0)

    def run(self):
        threading.Thread(target=self.config_updater_worker, daemon=True).start()
        threading.Thread(target=self.db_writer_worker, daemon=True).start()
        threading.Thread(target=self.snort_watchdog_worker, daemon=True).start()
        threading.Thread(target=self.metrics_worker, daemon=True).start()
        
        self.start_snort_core()
        self.tail_logs()

if __name__ == "__main__":
    engine = BkSocIPSEngine()
    engine.run()