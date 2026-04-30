#!/bin/bash
# BK-IDS: Professional Startup Script

echo " Đang khởi tạo hệ thống chặn đứng mã độc (IPS)..."

# 1. Thiết lập Iptables để lùa traffic vào Snort NFQ (Chừa cổng 22 SSH)
sudo iptables -F
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# 2. Khởi chạy Snort 3 ở chế độ Inline (Máy chém)
# -Q: Chế độ NFQ
# -l: Đẩy log vào thư mục logs của dự án
sudo snort -c ~/bk-ids/snort.lua \
           -R ~/bk-ids/core_engine/local.rules \
           -Q --daq nfq --daq-var queue=0 \
           -l ~/bk-ids/logs/snort \
           -k none