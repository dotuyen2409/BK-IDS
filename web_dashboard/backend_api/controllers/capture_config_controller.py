# /home/bk_ids/bk-ids/web_dashboard/backend_api/controllers/capture_config_controller.py

import sys
import os
import re
import tempfile
import logging
import subprocess

# ==========================================
# BỌC THÉP ĐƯỜNG DẪN CỤC BỘ DOCKER
# ==========================================
sys.path.append('/app')

from flask import request, jsonify

# Khởi tạo Logger chuẩn SIEM Doanh nghiệp
logger = logging.getLogger("Bk-IDS-Config-Manager")
ENV_PATH = '/app/.env'
SNORT_LUA_PATH = '/app/snort.lua'

def validate_network_input(val: str) -> bool:
    """
    🔴 BẢO VỆ ĐẦU VÀO (INPUT VALIDATION): Ngăn chặn Lua Injection / Code Execution
    🎯 NÂNG CẤP SNORT 3: Hỗ trợ thêm dấu chấm than (!) cho cú pháp phủ định (Negation).
    Ví dụ hợp lệ: 192.168.1.0/24, [10.0.0.0/8, 172.16.0.0/12], !192.168.1.100
    """
    val = val.strip()
    if val.lower() == 'any': 
        return True
    
    # Biểu thức chính quy cho phép: số, chữ, dấu chấm, phẩy, gạch chéo, ngoặc vuông, khoảng trắng, gạch ngang, dấu $, dấu !
    if re.match(r'^[\w\.\/\,\s\[\]\$\-\!]+$', val):
        return True
    return False

def atomic_write(filepath: str, lines: list):
    """
    🔴 AN TOÀN DỮ LIỆU (ATOMIC WRITE): Chống Crash / Hỏng file cấu hình
    Ghi dữ liệu vào Temp file, sau đó tráo đổi (rename) để đảm bảo tính toàn vẹn 100%.
    """
    dir_name = os.path.dirname(filepath)
    fd, temp_path = tempfile.mkstemp(dir=dir_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        # Thiết lập quyền hạn file an toàn (Chỉ Root/Chủ sở hữu được sửa)
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, filepath)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

def get_config():
    """Tải cấu hình Hệ thống từ file .env lên Giao diện Web an toàn"""
    if not os.path.exists(ENV_PATH):
        return jsonify({'status': 'error', 'message': "Không tìm thấy tệp cấu hình cốt lõi (.env)"}), 404
    try:
        with open(ENV_PATH, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'status': 'success', 'data': content}), 200
    except Exception as e:
        logger.error(f"Lỗi đọc .env: {e}")
        return jsonify({'status': 'error', 'message': "Lỗi máy chủ khi đọc tệp cấu hình."}), 500

def trigger_system_reload():
    """
    CHỨC NĂNG DOANH NGHIỆP: ĐỒNG BỘ TOÀN HỆ THỐNG
    Gửi tín hiệu nạp lại (Hot-reload) cho Snort 3 và các Cảm biến Python
    """
    try:
        # Nhờ cấp quyền pid: "host" trong docker-compose, API có thể tác động thẳng vào Snort
        subprocess.run(["pkill", "-SIGHUP", "-f", "snort"], check=False)
        logger.info("🔄 Đã phát tín hiệu Hot-Reload (SIGHUP) tới Lõi Snort 3.")
    except Exception as e:
        logger.warning(f"Không thể gửi tín hiệu nạp lại tới Snort: {e}")

def _sync_home_net_to_snort(home_net_val: str):
    """
    🎯 TÍNH NĂNG TỰ ĐỘNG HÓA KỸ THUẬT SÂU (SNORT 3 COMPATIBLE):
    Bơm dải IP HOME_NET trực tiếp vào file cấu hình Lõi (snort.lua).
    """
    if not os.path.exists(SNORT_LUA_PATH):
        logger.warning("Không tìm thấy snort.lua để đồng bộ HOME_NET.")
        return

    # Kiểm duyệt gắt gao trước khi tiêm vào file Lõi (Lua)
    if not validate_network_input(home_net_val):
        logger.critical(f"Phát hiện dấu hiệu Injection nguy hiểm trong dải IP: {home_net_val}")
        raise ValueError("Dải mạng chứa ký tự không hợp lệ. Từ chối cấu hình!")

    try:
        with open(SNORT_LUA_PATH, 'r', encoding='utf-8') as f:
            lua_lines = f.readlines()

        updated_lua = []
        for line in lua_lines:
            # 🎯 ĐÃ VÁ LỖI REGEX SNORT 3: 
            # Tìm dòng có chữ HOME_NET = '...', bỏ qua khoảng trắng thụt lề và dấu phẩy ở cuối
            if re.search(r'HOME_NET\s*=\s*[\'"].*?[\'"]', line):
                # Escape an toàn cho thay thế Regex
                safe_val = home_net_val.replace('\\', '\\\\')
                # Chỉ thay thế phần giá trị nằm giữa 2 dấu nháy đơn/kép
                updated_line = re.sub(r'([\'"]).*?([\'"])', rf'\g<1>{safe_val}\g<2>', line, count=1)
                updated_lua.append(updated_line)
            else:
                updated_lua.append(line)

        # Ghi an toàn bằng Atomic Write
        atomic_write(SNORT_LUA_PATH, updated_lua)
        logger.info(f"⚡ Đã chích thành công dải IP HOME_NET ({home_net_val}) xuống tầng lõi Snort 3.")
        
    except Exception as e:
        logger.error(f"Lỗi khi đồng bộ snort.lua: {e}")
        raise

def save_config():
    """
    CHỨC NĂNG: CẤU HÌNH HỆ THỐNG BẮT GÓI TIN & TIỀN XỬ LÝ (ENTERPRISE EDITION)
    Lưu cấu hình (Merge thông minh), bảo mật chặt chẽ toàn bộ Input.
    """
    try:
        input_data = request.get_json()
        if not input_data or 'config' not in input_data:
            return jsonify({'status': 'error', 'message': 'Dữ liệu cấu hình gửi lên rỗng hoặc sai định dạng.'}), 400
            
        new_config_str = input_data['config']
        
        # 🔴 BẢO VỆ OOM: Ngăn chặn gửi file cấu hình khổng lồ làm tràn RAM
        if len(new_config_str) > 20000: 
            return jsonify({'status': 'error', 'message': 'Cảnh báo: Kích thước tệp cấu hình vượt giới hạn an toàn.'}), 400

        # Làm sạch và bóc tách các dòng cấu hình mới từ Web gửi lên
        new_settings = {}
        home_net_value = None
        
        for line in new_config_str.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                
                # 🟡 LÀM SẠCH BIẾN: Ép Key thành chữ In Hoa, loại bỏ ký tự rác
                k = re.sub(r'[^A-Z0-9_]', '', k.strip().upper())
                v = v.strip()
                
                if k: # Đảm bảo Key không rỗng sau khi làm sạch
                    new_settings[k] = v
                    if k == 'HOME_NET':
                        home_net_value = v

        # Đọc cấu hình cũ để trộn (Merge), giữ nguyên cấu hình Database
        existing_lines = []
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, 'r', encoding='utf-8') as f:
                existing_lines = f.readlines()

        updated_lines = []
        keys_processed = set()
        
        for line in existing_lines:
            clean_line = line.strip()
            if '=' in clean_line and not clean_line.startswith('#'):
                k = clean_line.split('=', 1)[0].strip()
                if k in new_settings:
                    # Ghi đè giá trị mới từ Web
                    updated_lines.append(f"{k}={new_settings[k]}\n")
                    keys_processed.add(k)
                else:
                    # Giữ nguyên giá trị cũ
                    updated_lines.append(line)
            else:
                updated_lines.append(line)
                
        # Bổ sung các biến môi trường mới chưa từng tồn tại
        for k, v in new_settings.items():
            if k not in keys_processed:
                updated_lines.append(f"{k}={v}\n")

        # 🎯 Bơm IP mạng xuống C++ Engine trước khi lưu cấu hình môi trường để rà lỗi sớm
        if home_net_value:
            _sync_home_net_to_snort(home_net_value)

        # Ghi an toàn bằng Atomic Write
        atomic_write(ENV_PATH, updated_lines)
        
        # Gọi lệnh đồng bộ nóng toàn hệ thống
        trigger_system_reload()
        
        logger.info(" Cấu hình Bắt gói tin (.env) đã được kiểm duyệt và đồng bộ thành công.")
        return jsonify({'status': 'success', 'message': 'Cấu hình đã lưu! Cảm biến và Tường lửa đang tự động nạp lại.'}), 200
        
    except ValueError as ve:
        # Bắt lỗi Invalid Input từ Validate Logic
        return jsonify({'status': 'error', 'message': str(ve)}), 400
    except Exception as e:
        logger.error(f" Lỗi máy chủ nội bộ xử lý file cấu hình: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Lỗi máy chủ nội bộ khi lưu tệp cấu hình.'}), 500