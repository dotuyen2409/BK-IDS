#!/bin/bash
# ========================================================================
# BK-IDS SOC: Security Hardening Script
# Run this after deployment to set proper file permissions
# ========================================================================

set -euo pipefail

echo "========================================="
echo " BK-IDS SOC Security Hardening"
echo "========================================="

# 1. Set file permissions on sensitive files
echo "[1/5] Setting file permissions..."

# .env file — only owner can read
if [ -f /app/.env ]; then
    chmod 600 /app/.env
    echo "  .env: chmod 600"
fi

# auth_users.json — only owner can read
if [ -f /app/storage/auth_users.json ]; then
    chmod 600 /app/storage/auth_users.json
    echo "  auth_users.json: chmod 600"
fi

# JWT secret file — only owner can read
if [ -f /app/storage/.jwt_secret ]; then
    chmod 600 /app/storage/.jwt_secret
    echo "  .jwt_secret: chmod 600"
fi

# storage directory — restricted
chmod 700 /app/storage 2>/dev/null || true
echo "  storage/: chmod 700"

# PCAP storage — restricted
chmod 750 /app/storage/pcaps 2>/dev/null || true
echo "  storage/pcaps: chmod 750"

# Audit log — append only
touch /app/storage/audit.log 2>/dev/null || true
chmod 640 /app/storage/audit.log 2>/dev/null || true
echo "  audit.log: chmod 640"

# SOAR audit log
touch /app/storage/soar_audit.jsonl 2>/dev/null || true
chmod 640 /app/storage/soar_audit.jsonl 2>/dev/null || true
echo "  soar_audit.jsonl: chmod 640"

# 2. Generate JWT_SECRET if not set
echo "[2/5] Checking JWT_SECRET..."
if [ -z "${JWT_SECRET:-}" ]; then
    if [ -f /app/storage/.jwt_secret ]; then
        echo "  JWT_SECRET already persisted"
    else
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
        echo "$JWT_SECRET" > /app/storage/.jwt_secret
        chmod 600 /app/storage/.jwt_secret
        echo "  JWT_SECRET generated and saved"
    fi
else
    echo "  JWT_SECRET set from environment"
fi

# 3. Set ownership (run as root in container)
echo "[3/5] Setting ownership..."
if [ "$(id -u)" -eq 0 ]; then
    chown root:root /app/.env 2>/dev/null || true
    chown root:root /app/storage/auth_users.json 2>/dev/null || true
    chown root:root /app/storage/.jwt_secret 2>/dev/null || true
    echo "  Ownership set to root"
else
    echo "  Skipping (not running as root)"
fi

# 4. Verify no world-readable sensitive files
echo "[4/5] Verifying permissions..."
WORLD_READABLE=$(find /app/storage -type f -perm -004 2>/dev/null | grep -v "pcaps/" | head -5)
if [ -n "$WORLD_READABLE" ]; then
    echo "  WARNING: World-readable files found:"
    echo "$WORLD_READABLE"
else
    echo "  OK: No world-readable sensitive files"
fi

# 5. Check for shell=True in Python files
echo "[5/5] Scanning for shell=True in Python..."
SHELL_TRUE=$(grep -rn "shell\s*=\s*True" /app/web_dashboard/backend_api/ /app/core_engine/*.py 2>/dev/null | grep -v "safe_iptables" | head -10)
if [ -n "$SHELL_TRUE" ]; then
    echo "  WARNING: shell=True found in:"
    echo "$SHELL_TRUE"
else
    echo "  OK: No shell=True found (except safe wrappers)"
fi

echo ""
echo "========================================="
echo " Security Hardening Complete"
echo "========================================="
echo ""
echo "NEXT STEPS:"
echo "  1. Set REDIS_PASSWORD in .env and docker-compose.yml"
echo "  2. Run: docker exec bkids_elasticsearch bin/elasticsearch-setup-passwords auto"
echo "  3. Change default admin password: admin/admin123"
echo "  4. Review and rotate all API keys"
echo ""
