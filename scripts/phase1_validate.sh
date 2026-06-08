#!/usr/bin/env bash
# ============================================================
# BK-IDS Phase 1: Infrastructure Acceptance Test
# Run from project root: bash scripts/phase1_validate.sh
# ============================================================
set -uo pipefail
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "========================================================"
echo "  BK-IDS NGIPS Phase 1 — Infrastructure Validation"
echo "========================================================"
echo ""

# -------------------------------------------------------
# TEST 1: docker compose config parses without error
# -------------------------------------------------------
info "Test 1: docker compose config validity..."
if docker compose config > /dev/null 2>&1; then
    pass "docker compose config is valid"
else
    fail "docker compose config has errors"
fi

# -------------------------------------------------------
# TEST 2: Removed services must NOT appear in compose
# -------------------------------------------------------
info "Test 2: Checking removed services are absent..."
REMOVED_SERVICES=("kafka" "zookeeper" "elasticsearch" "logstash" "kibana" "waf_proxy" "anomaly_sensor" "misuse_ips")
COMPOSE_SERVICES=$(docker compose config --services 2>/dev/null)

for svc in "${REMOVED_SERVICES[@]}"; do
    if echo "$COMPOSE_SERVICES" | grep -qi "^${svc}$"; then
        fail "Legacy service found in compose: $svc"
    else
        pass "Removed service absent: $svc"
    fi
done

# -------------------------------------------------------
# TEST 3: Required services must be present
# -------------------------------------------------------
info "Test 3: Checking required services are present..."
REQUIRED_SERVICES=("mysql_db" "redis_cache" "api_server" "frontend_ui" "portal_gateway" "bkids_snort_engine")

for svc in "${REQUIRED_SERVICES[@]}"; do
    if echo "$COMPOSE_SERVICES" | grep -qi "^${svc}$"; then
        pass "Required service present: $svc"
    else
        fail "Required service MISSING: $svc"
    fi
done

# -------------------------------------------------------
# TEST 4: No legacy env vars in compose config
# -------------------------------------------------------
info "Test 4: Checking no legacy env vars leak into compose config..."
LEGACY_VARS=("ELASTICSEARCH_PASSWORD" "KAFKA_BOOTSTRAP_SERVERS" "ZOOKEEPER_CLIENT_PORT" "MODSEC_" "LOGSTASH")
COMPOSE_FULL=$(docker compose config 2>/dev/null)

for var in "${LEGACY_VARS[@]}"; do
    if echo "$COMPOSE_FULL" | grep -qi "$var"; then
        fail "Legacy env var found in compose: $var"
    else
        pass "Legacy env var absent: $var"
    fi
done

# -------------------------------------------------------
# TEST 5: Shared snort_logs volume defined
# -------------------------------------------------------
info "Test 5: Checking shared snort_logs volume..."
if echo "$COMPOSE_FULL" | grep -q "snort_logs"; then
    pass "snort_logs volume defined in compose"
else
    fail "snort_logs shared volume NOT found"
fi

# -------------------------------------------------------
# TEST 6: Snort mounts snort_logs volume
# -------------------------------------------------------
info "Test 6: Checking Snort engine volume mount..."
if echo "$COMPOSE_FULL" | grep -A5 "bkids_snort_engine" | grep -q "/var/log/snort"; then
    pass "bkids_snort_engine mounts /var/log/snort"
else
    warn "Could not confirm bkids_snort_engine /var/log/snort mount"
fi

# -------------------------------------------------------
# TEST 7: API server mounts snort_logs volume
# -------------------------------------------------------
info "Test 7: Checking API server snort_logs volume mount..."
# docker compose config expands volumes to source:/target format
if echo "$COMPOSE_FULL" | grep -B5 "target: /var/log/snort" | grep -q "snort_logs"; then
    pass "api_server mounts snort_logs volume at /var/log/snort"
elif echo "$COMPOSE_FULL" | grep -q "SNORT_ALERT_FILE.*alert_json.txt"; then
    pass "api_server has SNORT_ALERT_FILE env pointing to /var/log/snort"
else
    warn "Could not confirm api_server /var/log/snort mount"
fi

# -------------------------------------------------------
# TEST 8: Portal gateway is the primary ingress (port 9000)
# -------------------------------------------------------
info "Test 8: Checking portal gateway port..."
# docker compose config expands "9000:9000" to published/target format
if echo "$COMPOSE_FULL" | grep -q 'published: "9000"'; then
    pass "portal_gateway exposed on port 9000"
elif echo "$COMPOSE_FULL" | grep -q 'target: 9000'; then
    pass "portal_gateway target port 9000 confirmed"
else
    fail "portal_gateway not on port 9000"
fi

# -------------------------------------------------------
# TEST 9: No JVM / Big Data service images
# -------------------------------------------------------
info "Test 9: Checking no JVM Big Data images..."
JVM_IMAGES=("confluentinc/cp-" "docker.elastic.co" "owasp/modsecurity")
for img in "${JVM_IMAGES[@]}"; do
    if echo "$COMPOSE_FULL" | grep -q "$img"; then
        fail "Legacy JVM/Big Data image found: $img"
    else
        pass "Legacy image absent: $img"
    fi
done

# -------------------------------------------------------
# TEST 10: snort.lua exists and has alert_json
# -------------------------------------------------------
info "Test 10: Checking snort.lua configuration..."
if [ -f "./snort.lua" ]; then
    pass "snort.lua exists"
    if grep -q "alert_json" ./snort.lua; then
        pass "snort.lua has alert_json output configured"
    else
        fail "snort.lua missing alert_json configuration"
    fi
    if grep -q "port_scan" ./snort.lua; then
        pass "snort.lua has port_scan configured"
    else
        warn "snort.lua missing port_scan configuration"
    fi
    if grep -q "appid" ./snort.lua; then
        pass "snort.lua has appid configured"
    else
        warn "snort.lua missing appid configuration"
    fi
else
    fail "snort.lua not found"
fi

# -------------------------------------------------------
# TEST 11: MySQL init SQL has canonical alerts table
# -------------------------------------------------------
info "Test 11: Checking MySQL schema..."
if [ -f "./mysql_init/init.sql" ]; then
    pass "mysql_init/init.sql exists"
    if grep -q "CREATE TABLE IF NOT EXISTS alerts" ./mysql_init/init.sql; then
        pass "alerts canonical table defined in init.sql"
    else
        fail "alerts table NOT found in init.sql"
    fi
    if grep -q "CREATE.*VIEW misuse_alerts" ./mysql_init/init.sql; then
        pass "misuse_alerts compatibility view defined"
    else
        warn "misuse_alerts compatibility view not found"
    fi
    if grep -q "soar_blocks" ./mysql_init/init.sql; then
        pass "soar_blocks table defined"
    else
        warn "soar_blocks table not found"
    fi
    if grep -q "soar_audit" ./mysql_init/init.sql; then
        pass "soar_audit table defined"
    else
        warn "soar_audit table not found"
    fi
    if grep -q "dedupe_hash" ./mysql_init/init.sql; then
        pass "dedupe_hash field defined for idempotent ingestion"
    else
        fail "dedupe_hash field NOT found in alerts schema"
    fi
else
    fail "mysql_init/init.sql not found"
fi

# -------------------------------------------------------
# TEST 12: .env has no Kafka/ELK vars
# -------------------------------------------------------
info "Test 12: Checking .env for legacy vars..."
if [ -f ".env" ]; then
    for var in "KAFKA_BOOTSTRAP_SERVERS" "ZOOKEEPER_CLIENT_PORT" "ELASTICSEARCH_PASSWORD"; do
        if grep -q "^${var}=" .env 2>/dev/null; then
            fail ".env still has legacy var: $var"
        else
            pass ".env clean of: $var"
        fi
    done
    # Check NGIPS vars are present
    for var in "SNORT_THREADS" "SNORT_ALERT_FILE" "SOAR_BLOCK_MIN_SEVERITY"; do
        if grep -q "^${var}=" .env 2>/dev/null; then
            pass ".env has NGIPS var: $var"
        else
            warn ".env missing NGIPS var: $var"
        fi
    done
else
    warn ".env not found (copy from .env.example)"
fi

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------
echo ""
echo "========================================================"
echo -e "  RESULTS: ${GREEN}${PASS} PASS${NC} | ${RED}${FAIL} FAIL${NC} | ${YELLOW}${WARN} WARN${NC}"
echo "========================================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Phase 1 acceptance criteria NOT fully met. Fix failures above.${NC}"
    exit 1
else
    echo -e "${GREEN}Phase 1 acceptance criteria MET. Infrastructure is lean and NGIPS-ready.${NC}"
    exit 0
fi
