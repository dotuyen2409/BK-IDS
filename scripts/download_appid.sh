#!/bin/bash
# ========================================================================
# Script tải bộ OpenAppID (ODP) từ Cisco Talos cho Snort 3
# ========================================================================

APPID_DIR="/home/ids/bk_ids/snort_config/appid"
DOWNLOAD_URL="https://snort.org/downloads/openappid/31623" # Sử dụng link mặc định cho Snort 3 ODP
TAR_FILE="/tmp/odp.tar.gz"

echo "[*] Đang tạo thư mục chứa OpenAppID tại $APPID_DIR..."
mkdir -p "$APPID_DIR"

echo "[*] Bắt đầu tải gói OpenAppID (snort3-app-detectors)..."
wget -O "$TAR_FILE" "$DOWNLOAD_URL"

if [ $? -ne 0 ]; then
    echo "[!] Lỗi: Không thể tải OpenAppID. Vui lòng kiểm tra lại mạng hoặc link download."
    exit 1
fi

echo "[*] Giải nén gói OpenAppID..."
tar -xzvf "$TAR_FILE" -C "/tmp"

echo "[*] Di chuyển các file detectors vào thư mục cấu hình..."
cp -r /tmp/odp/port/ "$APPID_DIR/" 2>/dev/null || true
cp -r /tmp/odp/lua/ "$APPID_DIR/" 2>/dev/null || true
cp -r /tmp/odp/json/ "$APPID_DIR/" 2>/dev/null || true
cp -r /tmp/odp/* "$APPID_DIR/" 2>/dev/null || true

echo "[*] Dọn dẹp file tạm..."
rm -rf "/tmp/odp" "$TAR_FILE"

echo "[*] Kiểm tra file AppID đã có:"
ls -la "$APPID_DIR"

echo "[+] HOÀN TẤT! Gói OpenAppID đã được chuẩn bị sẵn sàng."
echo "[+] Vui lòng chạy lệnh: docker compose up -d để Snort 3 load bộ AppID."
