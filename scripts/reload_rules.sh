#!/bin/bash
# ========================================================================
# Script nạp lại luật (Reload Rules) cho Snort 3 không gây gián đoạn
# Yêu cầu: Snort 3 phải được khởi chạy với cờ --socket-dir
# ========================================================================

CONTAINER_NAME="bkids_snort_engine"
SOCKET_DIR="/var/log/snort"

echo "[*] Đang gửi lệnh RELOAD tới container $CONTAINER_NAME..."

# Gọi snort_control thông qua Docker exec
docker exec -it "$CONTAINER_NAME" bash -c "snort_control -q $SOCKET_DIR reload"

if [ $? -eq 0 ]; then
    echo "[+] THÀNH CÔNG: Snort 3 đã tải lại luật mới (Zero Downtime)."
else
    echo "[!] LỖI: Không thể nạp lại luật. Vui lòng kiểm tra lại:"
    echo "    1. Container $CONTAINER_NAME có đang chạy không?"
    echo "    2. Snort 3 đã có cờ --socket-dir chưa?"
fi
