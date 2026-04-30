# /home/bk_ids/bk-ids/web_dashboard/backend_api/api_server.py

import sys
import os
import json
import subprocess
import re
import pymysql 
from datetime import datetime

sys.path.append('/app')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

# 🎯 NÂNG CẤP BẢO MẬT: Bọc Try-Except Module ngoài để API không sập nếu module Threat Intel bị lỗi
try:
    import threat_intel_updater
    THREAT_INTEL_READY = True
except ImportError as e:
    THREAT_INTEL_READY = False

# ========================================================================
#  BK-IDS SOC: ENTERPRISE API GATEWAY
# ========================================================================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Bk-IDS-Gateway")

RULE_JSON_PATH = '/app/core_engine/rules_db.json'
SNORT_RULES_PATH = '/app/core_engine/local.rules' 

# 🎯 NÂNG CẤP ENTERPRISE: Lưới bảo vệ toàn cục (Global Error Handler)
# Ép mọi lỗi hệ thống (HTTP 500) phải trả về JSON để Frontend không bị báo "Mất kết nối"
@app.errorhandler(Exception)
def handle_global_error(e):
    logger.error(f"Lỗi Hệ thống Toàn cục: {e}", exc_info=True)
    return jsonify({'status': 'error', 'message': f'Lỗi API nội bộ: {str(e)}'}), 500

# Áp dụng bộ Header Bảo mật chuyên dụng
@app.after_request
def apply_enterprise_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

# ====================================================================
# 🛣️ CENTRAL ROUTER (ĐỊNH TUYẾN TRUNG TÂM CÔ LẬP)
# ====================================================================
@app.route('/backend_api/routes/api.php', methods=['GET', 'POST', 'OPTIONS'])
def gateway():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    route = request.args.get('route')
    
    try:
        # Nhóm 1: Capture & Sensor Configuration
        if route == 'get_capture_config':
            from controllers import capture_config_controller
            return capture_config_controller.get_config()
        elif route == 'save_capture_config':
            from controllers import capture_config_controller
            return capture_config_controller.save_config()
            
        # Nhóm 2: Anomaly Detection (CUSUM)
        elif route == 'get_anomaly_data':
            from controllers import cusum_controller
            return cusum_controller.get_statistics()
            
        # Nhóm 3: Signature & IPS Rules Management
        # 🎯 FIX LỖI IMPORT CHÉO: Cô lập độc lập từng chức năng, không dùng chung else
        elif route == 'get_misuse_alerts':
            from controllers import alert_controller
            return alert_controller.get_misuse_alerts()
        elif route == 'get_rules':
            from controllers import rules_controller
            return rules_controller.get_rules()
        elif route == 'save_rules':
            from controllers import rules_controller
            return rules_controller.save_rules()
        elif route == 'update_rules_online':
            return update_rules_online()
        elif route == 'get_banned_ips':
            return get_banned_ips()
        elif route == 'unban_ip':
            return unban_ip()

        # Nhóm 4: Deep Packet Inspection (DPI)
        elif route == 'get_packet_details':
            from controllers import dpi_controller
            return dpi_controller.get_packet_details()

        else:
            logger.warning(f" Gateway từ chối kết nối: Route [{route}] không tồn tại.")
            return jsonify({'status': 'error', 'message': f'Route [{route}] không hợp lệ.'}), 404

    except ImportError as ie:
        logger.error(f" Hệ thống thiếu Module Controller tại route {route}: {ie}")
        return jsonify({'status': 'error', 'message': f'Thiếu file module: {ie}'}), 500

@app.route('/api/get_packet_details', methods=['GET', 'OPTIONS'])
def fallback_dpi_route():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        from controllers import dpi_controller
        return dpi_controller.get_packet_details()
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Lỗi hệ thống DPI: {str(e)}'}), 500

# ====================================================================
#  CORE SYSTEM FUNCTIONS (XỬ LÝ LÕI)
# ====================================================================
def sanitize_name(text):
    if not text: return "Unknown_Threat"
    return re.sub(r'[^\w\s\-]', '', str(text)).strip()

def sanitize_pattern(text):
    if not text: return ""
    return str(text).replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;')

def trigger_system_reload():
    try:
        subprocess.run(["pkill", "-SIGHUP", "-f", "snort"], check=False)
        logger.info("🔄 Đã phát tín hiệu Hot-Reload (SIGHUP) tới Lõi Snort 3.")
    except Exception as e:
        logger.warning(f"Không thể Hot-Reload Snort: {e}")

def generate_snort_rules(rules_list):
    snort_lines = [
        "# ==================================================================",
        "# BK-IDS SOC: TỆP LUẬT SNORT 3 - ENTERPRISE EDITION",
        "# ==================================================================\n"
    ]
    sid_counter = 1000001 
    for rule in rules_list:
        raw_action = str(rule.get('action', 'ALERT')).upper().strip()
        action_web = "DROP" if raw_action in ["DROP", "BLOCK", "CHẶN"] else "ALERT"
        snort_action = "drop" if action_web == "DROP" else "alert"
        
        name = sanitize_name(rule.get('name'))
        pattern = sanitize_pattern(rule.get('pattern'))
        
        protocol = str(rule.get('protocol', 'tcp')).lower()
        dst_port = str(rule.get('dst_port', 'any')).strip()
        if not dst_port: dst_port = 'any'
        
        if not pattern: continue 
        
        flow_directive = "flow:to_server; " if protocol == 'tcp' and dst_port != 'any' else ""
        
        snort_rule = f'{snort_action} {protocol} $EXTERNAL_NET any -> $HOME_NET {dst_port} (msg:"[{action_web}] {name}"; {flow_directive}content:"{pattern}", nocase; classtype:web-application-attack; sid:{sid_counter}; rev:1;)'
        snort_lines.append(snort_rule)
        sid_counter += 1
        
    os.makedirs(os.path.dirname(SNORT_RULES_PATH), exist_ok=True)
    with open(SNORT_RULES_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(snort_lines))

# ====================================================================
#  ENDPOINTS MỞ RỘNG (THREAT INTEL & FIREWALL)
# ====================================================================
@app.route('/api/update_rules_online', methods=['POST'])
def update_rules_online():
    if not THREAT_INTEL_READY:
        return jsonify({'status': 'error', 'message': 'Module Threat Intel đang bị lỗi cấu hình, không thể chạy.'}), 500
        
    try:
        logger.info(" [API] Đang khởi chạy quy trình đồng bộ Threat Intelligence...")
        success = threat_intel_updater.fetch_and_merge_et_rules()
        
        if success:
            with open(RULE_JSON_PATH, 'r', encoding='utf-8') as f:
                updated_rules = json.load(f)
            generate_snort_rules(updated_rules)
            trigger_system_reload()
            return jsonify({'status': 'success', 'message': ' Đã nạp thành công bộ lọc Threat Intel Quốc tế vào Tường lửa!'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Lỗi khi kết nối tới máy chủ Cấp phép (Emerging Threats).'}), 500
    except Exception as e:
        logger.error(f" [API] Lỗi nghiêm trọng khi đồng bộ: {e}")
        return jsonify({'status': 'error', 'message': 'Lỗi nội bộ Máy chủ SOC.'}), 500

def get_banned_ips():
    """ 🎯 NÂNG CẤP AN TOÀN I/O: Đọc Sổ đen Firewall không crash """
    try:
        state_file = '/app/bans_state.json'
        banned_data = {}
        
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    banned_data = json.load(f)
            except json.JSONDecodeError:
                # Tránh làm sập API nếu đọc file ngay khoảnh khắc Snort đang tiến hành ghi đè
                logger.warning("File bans_state.json đang bị khóa tạm thời bởi quá trình ghi I/O.")
                pass 
                
        return jsonify({'status': 'success', 'data': banned_data}), 200
    except Exception as e:
        logger.error(f"Lỗi truy xuất trạng thái Tường lửa: {e}")
        return jsonify({'status': 'error', 'message': f"Lỗi đọc Firewall State: {str(e)}"}), 500

def unban_ip():
    """ Lệnh ân xá - Can thiệp sâu vào Iptables để gỡ phong tỏa IP. """
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'status': 'error', 'message': 'Dữ liệu không hợp lệ. Thiếu IP.'}), 400
            
        ip_to_unban = str(data['ip']).strip()
        
        def run_host_command(cmd_string):
            subprocess.run(cmd_string, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        run_host_command(f"iptables -t mangle -D PREROUTING -s {ip_to_unban} -j DROP 2>/dev/null")
        run_host_command(f"iptables -D DOCKER-USER -s {ip_to_unban} -j DROP 2>/dev/null")
        run_host_command(f"iptables -D INPUT -s {ip_to_unban} -j DROP 2>/dev/null")

        state_file = '/app/bans_state.json'
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    banned_data = json.load(f)
                
                if ip_to_unban in banned_data:
                    del banned_data[ip_to_unban]
                    with open(state_file, 'w') as f:
                        json.dump(banned_data, f)
            except Exception as fe:
                logger.warning(f"Không thể cập nhật JSON sổ đen: {fe}")
                    
        logger.info(f"🔓 [FIREWALL-API] Đã nhận lệnh Ân xá: Mở khóa IP {ip_to_unban}")
        return jsonify({'status': 'success', 'message': f'Đã gỡ bỏ phong tỏa cho IP {ip_to_unban}'}), 200
        
    except Exception as e:
        logger.error(f"Lỗi khi thực thi lệnh Ân xá (Unban): {e}")
        return jsonify({'status': 'error', 'message': f'Lỗi hệ thống Firewall: {str(e)}'}), 500

if __name__ == '__main__':
    logger.info(" LÕI API SERVER ĐÃ KÍCH HOẠT VÀ ĐỊNH TUYẾN ĐỘC LẬP!")
    app.run(host='0.0.0.0', port=5000, debug=False)