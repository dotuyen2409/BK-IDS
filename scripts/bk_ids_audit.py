#!/usr/bin/env python3
"""
BK-IDS Comprehensive Audit Script
==================================
Kiểm tra toàn bộ hệ thống IDS/Anomaly detection:
  1. Snort 3 Engine (binary, config, rules, process)
  2. Anomaly Detection Pipeline
  3. Backend API (routes, endpoints)
  4. Nginx Proxy Configuration
  5. Docker Services (containers, networking)
  6. Frontend-Backend Sync
  7. Rule-Threshold-Output Consistency

Chạy với: python3 bk_ids_audit.py | tee audit_report.txt
"""

import subprocess
import json
import os
import sys
import socket
import re
from datetime import datetime

# Colors for terminal output
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; CY = '\033[96m'
    W = '\033[97m'; DIM = '\033[2m'; BOLD = '\033[1m'
    END = '\033[0m'

def header(title):
    w = 70
    print(f"\n{C.BOLD}{C.CY}{'='*w}")
    print(f"  {title}")
    print(f"{'='*w}{C.END}\n")

def ok(msg):    print(f"  {C.G}[OK]{C.END}    {msg}")
def warn(msg):  print(f"  {C.Y}[WARN]{C.END}  {msg}")
def fail(msg):  print(f"  {C.R}[FAIL]{C.END}  {msg}")
def info(msg):  print(f"  {C.B}[INFO]{C.END}  {msg}")
def skip(msg):  print(f"  {C.DIM}[SKIP]{C.END} {msg}")

def run(cmd, timeout=15):
    """Run shell command, return (stdout, stderr, returncode)"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def check_file(path, desc=""):
    """Check if file exists and return content"""
    if os.path.exists(f"/{path}") if path.startswith("home/") or path.startswith("etc/") else os.path.exists(path):
        p = f"/{path}" if (path.startswith("home/") or path.startswith("etc/")) else path
        try:
            with open(p) as f:
                return True, f.read()
        except PermissionError:
            return True, "<permission denied>"
        except Exception as e:
            return True, f"<error: {e}>"
    # Try absolute
    if os.path.exists(path):
        try:
            with open(path) as f:
                return True, f.read()
        except:
            return True, "<unreadable>"
    return False, ""

def port_open(host, port, timeout=3):
    try:
        socket.create_connection((host, port), timeout=timeout)
        return True
    except:
        return False

def count_lines(text):
    return len(text.strip().split('\n')) if text.strip() else 0

# ============================================================
# RESULTS TRACKING
# ============================================================
results = {
    'snort_binary': False, 'snort_process': False, 'snort_config': False,
    'snort_rules_count': 0, 'snort_home_net': False, 'snort_output': False,
    'anomaly_service': False, 'anomaly_source': False,
    'api_alerts_route': False, 'api_anomaly_route': False, 'api_running': False,
    'nginx_config_ok': False, 'nginx_proxy_pass': False,
    'docker_snort': False, 'docker_api': False, 'docker_frontend': False,
    'frontend_api_match': False, 'threshold_sync': False,
    'errors': [], 'warnings': []
}

# ============================================================
# 1. SNORT 3 ENGINE CHECK
# ============================================================
header("1. SNORT 3 ENGINE - Phát hiện xâm nhập")

# 1a. Binary exists
snort_paths = [
    "/home/snorty/snort3/bin/snort",
    "/usr/local/bin/snort",
    "/opt/snort3/bin/snort",
    "/usr/bin/snort3",
]
snort_bin = None
for p in snort_paths:
    exists, _ = check_file(p)
    if exists:
        snort_bin = p
        results['snort_binary'] = True
        ok(f"Snort binary found: {p}")
        break

if not snort_bin:
    fail("Không tìm thấy Snort binary")
    results['errors'].append("Snort binary not found in any expected path")

# 1b. Snort version
if snort_bin:
    out, err, rc = run(f"{snort_bin} --version 2>&1")
    if out:
        for line in out.split('\n')[:5]:
            info(f"Snort: {line.strip()}")
    else:
        warn("Không lấy được Snort version")

# 1c. Snort process
out, _, _ = run("ps aux | grep -i snort | grep -v grep")
if out:
    results['snort_process'] = True
    for line in out.split('\n'):
        parts = line.split()
        if len(parts) >= 11:
            pid = parts[1]
            cpu = parts[2]
            mem = parts[3]
            cmd = ' '.join(parts[10:])[:80]
            if 'grep' not in cmd:
                ok(f"Snort process running - PID:{pid} CPU:{cpu}% MEM:{mem}% CMD:...{cmd[-60:]}")
else:
    fail("Không có Snort process đang chạy!")
    results['errors'].append("Snort process not running")

# 1d. Snort configuration
snort_configs = [
    "/home/ids/bk_ids/core_engine/snort.lua",
    "/home/snorty/snort3/etc/snort/snort.lua",
    "/etc/snort3/snort.lua",
    "/etc/snort/snort.conf",
]
for cfg in snort_configs:
    exists, content = check_file(cfg)
    if exists:
        results['snort_config'] = True
        info(f"Snort config: {cfg}")
        
        # Check HOME_NET
        if 'HOME_NET' in content or 'home_net' in content:
            for line in content.split('\n'):
                if 'HOME_NET' in line or 'home_net' in line:
                    info(f"  -> {line.strip()[:100]}")
                    if '192.168.13.0/24' in line.replace(' ', '').replace('"', '').replace("'", ""):
                        results['snort_home_net'] = True
                        ok(f"  HOME_NET matches network: 192.168.13.0/24")
        
        # Check output modules
        output_keywords = ['alert_json', 'alert_fast', 'alert_full', 'unified2', 'eve', 'json', 'output']
        output_found = [kw for kw in output_keywords if kw.lower() in content.lower()]
        if output_found:
            results['snort_output'] = True
            ok(f"  Output modules found: {', '.join(output_found)}")
        else:
            warn("Không tìm thấy output module (alert_json/eve/log) trong config")
        
        # Check DAQ (Data Acquisition)
        if 'daq' in content.lower():
            ok("DAQ module configured")
        
        # Check preprocessor (anomaly detection)
        anomaly_keywords = ['anomaly', 'sfportscan', 'stream', 'http_inspect', 'normalizer']
        found_preprocs = [kw for kw in anomaly_keywords if kw.lower() in content.lower()]
        if found_preprocs:
            ok(f"Preprocessors detected: {', '.join(found_preprocs)}")
        else:
            warn("Không tìm thấy preprocessor cụ thể")
        
        break

if not results['snort_config']:
    fail("Không tìm thấy Snort config file")
    results['errors'].append("Snort configuration not found")

# 1e. Snort Rules
rule_paths = [
    "/home/ids/bk_ids/core_engine/local.rules",
    "/home/snorty/snort3/etc/snort/rules/local.rules",
    "/etc/snort3/rules/local.rules",
]
rules_content = ""
for rp in rule_paths:
    exists, content = check_file(rp)
    if exists:
        rules_content = content
        results['snort_rules_count'] = len([l for l in content.split('\n') if l.strip().startswith('alert') or l.strip().startswith('drop')])
        ok(f"Rules file: {rp}")
        info(f"  Total rules: {results['snort_rules_count']}")
        
        # Categorize rules
        categories = {}
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            # Try to detect category from msg or metadata
            if 'msg:' in line:
                msg_match = re.search(r'msg:"([^"]*)"', line)
                if msg_match:
                    msg = msg_match.group(1)
                    cat = msg.split()[0] if msg else 'unknown'
                    categories[cat] = categories.get(cat, 0) + 1
        
        if categories:
            info(f"  Rule categories ({len(categories)}):")
            for cat, cnt in sorted(categories.items(), key=lambda x: -x[1])[:10]:
                info(f"    {cat}: {cnt} rules")
        
        # Check for anomaly-specific rules
        anomaly_rules = [l for l in content.split('\n') if 'anomaly' in l.lower()]
        if anomaly_rules:
            info(f"  Anomaly-related rules: {len(anomaly_rules)}")
        
        # Check rule syntax (verify active rules have required fields)
        active_rules = [l for l in content.split('\n') 
                        if (l.strip().startswith('alert') or l.strip().startswith('drop')) 
                        and not l.strip().startswith('#')]
        required_fields = ['msg', 'sid', 'rev']
        for rf in required_fields:
            missing = [l for l in active_rules if rf+':' not in l]
            if missing:
                warn(f"  {len(missing)} rules thiếu field '{rf}'")
            else:
                ok(f"  Tất cả rules có field '{rf}'")
        
        break

if not rules_content:
    fail("Không tìm thấy local.rules")
    results['errors'].append("Snort rules file not found")

# ============================================================
# 2. ANOMALY DETECTION PIPELINE
# ============================================================
header("2. ANOMALY DETECTION - Phát hiện bất thường")

# 2a. Check for anomaly-specific service/container
docker_services = [
    "bk_ids-misuse_ips", "bkids_snort_engine", "anomaly", "anomaly_detection"
]
out, _, _ = run("docker ps --format '{{.Names}}' 2>/dev/null")
if out:
    running_containers = out.split('\n')
    anomaly_containers = [c for c in running_containers if any(kw in c.lower() for kw in ['anomaly', 'snort', 'ids', 'misuse'])]
    if anomaly_containers:
        ok(f"Related containers: {', '.join(anomaly_containers)}")
        results['anomaly_service'] = True
    else:
        info("Không tìm thấy dedicated anomaly container")
    
    snort_containers = [c for c in running_containers if 'snort' in c.lower()]
    if snort_containers:
        results['docker_snort'] = True
        ok(f"Snort container(s): {', '.join(snort_containers)}")

# 2b. Check Snort output files (where does Snort write alerts?)
alert_log_paths = [
    "/var/log/snort/alert_json.txt",
    "/var/log/snort/alert_fast",
    "/var/log/snort/snort.alert",
    "/home/ids/bk_ids/core_engine/logs/",
    "/home/snorty/snort3/log/",
]
for lp in alert_log_paths:
    exists, content = check_file(lp)
    if exists:
        if os.path.isdir(lp):
            files = os.listdir(lp) if os.access(lp, os.R_OK) else []
            ok(f"Snort log directory: {lp} ({len(files)} files)")
            for f in files[:5]:
                info(f"  -> {f}")
            results['snort_output'] = True
        else:
            ok(f"Snort alert log: {lp} ({len(content.split(chr(10)))} lines)")
            results['snort_output'] = True

if not results['snort_output']:
    warn("Không tìm thấy Snort output/alert log")

# 2c. Data pipeline: How does anomaly detection get Snort data?
info("Checking data pipeline...")
pipeline_checks = [
    ("Redis queue", "redis-cli ping 2>/dev/null"),
    ("RabbitMQ", "rabbitmqctl status 2>/dev/null | head -3"),
    ("Kafka", "kafkacat -L 2>/dev/null | head -3"),
    ("Unix socket", "ls /var/run/snort* 2>/dev/null"),
    ("Named pipe", "ls -la /tmp/snort* 2>/dev/null"),
]
found_pipeline = False
for name, cmd in pipeline_checks:
    out, _, rc = run(cmd)
    if rc == 0 and out:
        ok(f"Data pipeline found: {name}")
        info(f"  -> {out[:100]}")
        found_pipeline = True
        results['anomaly_source'] = True

if not found_pipeline:
    warn("Không tìm thấy data pipeline (Redis/Kafka/socket) giữa Snort và Backend")
    results['warnings'].append("No data pipeline found between Snort and Backend")

# ============================================================
# 3. BACKEND API
# ============================================================
header("3. BACKEND API - Endpoints")

# 3a. Find backend source code
backend_paths = [
    "/home/ids/bk_ids/backend",
    "/home/ids/bk_ids/api",
    "/home/ids/bk_ids/server",
    "/home/ids/bk_ids/src",
]
backend_src = None
for bp in backend_paths:
    if os.path.isdir(bp):
        backend_src = bp
        ok(f"Backend source directory: {bp}")
        break

# 3b. Detect framework and find route definitions
if backend_src:
    # Check for common backend files
    framework = None
    if os.path.exists(f"{backend_src}/app.py"):
        framework = "Flask/FastAPI (Python)"
    elif os.path.exists(f"{backend_src}/server.js") or os.path.exists(f"{backend_src}/index.js"):
        framework = "Node.js/Express"
    elif os.path.exists(f"{backend_src}/main.py"):
        framework = "Python"
    elif os.path.exists(f"{backend_src}/Cargo.toml"):
        framework = "Rust"
    
    info(f"Detected framework: {framework}")
    
    # Find route definitions for our target endpoints
    target_routes = ['/api/alerts/recent', '/api/anomaly/realtime', 'alerts', 'anomaly']
    
    # Search all source files for route definitions
    out, _, _ = run(f"grep -rn '{target_routes[0]}\\|{target_routes[1]}' {backend_src}/ 2>/dev/null | head -30")
    if out:
        ok("Route definitions found:")
        for line in out.split('\n')[:20]:
            if line.strip():
                info(f"  {line.strip()[:120]}")
    else:
        warn("Không tìm thấy route /api/alerts/recent trong source code")
        results['errors'].append("Route /api/alerts/recent not found in backend source")
    
    # Search more broadly
    out, _, _ = run(f"grep -rn 'api/alerts' {backend_src}/ 2>/dev/null | head -20")
    if out:
        results['api_alerts_route'] = True
        ok(f"Alert routes found:")
        for line in out.split('\n')[:10]:
            info(f"  {line.strip()[:120]}")
    else:
        fail("Không tìm thấy bất kỳ route 'api/alerts' nào!")
        results['errors'].append("No /api/alerts routes found in backend")
    
    out, _, _ = run(f"grep -rn 'api/anomaly' {backend_src}/ 2>/dev/null | head -20")
    if out:
        results['api_anomaly_route'] = True
        ok(f"Anomaly routes found:")
        for line in out.split('\n')[:10]:
            info(f"  {line.strip()[:120]}")
    else:
        fail("Không tìm thấy bất kỳ route 'api/anomaly' nào!")
        results['errors'].append("No /api/anomaly routes found in backend")

    # Check for getAnomalyData function
    out, _, _ = run(f"grep -rn 'getAnomalyData' {backend_src}/ 2>/dev/null | head -10")
    if out:
        ok("getAnomalyData function found:")
        for line in out.split('\n')[:5]:
            info(f"  {line.strip()[:120]}")
    else:
        warn("Không tìm thấy getAnomalyData function trong backend")
        results['warnings'].append("getAnomalyData not exported from backend API module")
    
    # Check requirements/dependencies for IDS-related libs
    dep_files = ["requirements.txt", "package.json", "pyproject.toml", "go.mod"]
    for df in dep_files:
        dp = f"{backend_src}/{df}"
        if os.path.exists(dp):
            info(f"Dependencies file: {dp}")

else:
    fail("Không tìm thấy backend source directory")
    results['errors'].append("Backend source directory not found")

# 3c. Backend API running check
api_ports = [8080, 3000, 5000, 8000, 8888]
for port in api_ports:
    if port_open('127.0.0.1', port):
        ok(f"API service listening on port {port}")
        results['api_running'] = True
        if port == 8080:
            # Test our endpoints
            out, _, _ = run(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port}/api/alerts/recent?limit=50 2>/dev/null")
            if out and out != '000':
                if out == '200':
                    ok(f"  GET /api/alerts/recent -> {out} OK")
                elif out == '404':
                    fail(f"  GET /api/alerts/recent -> {out} NOT FOUND")
                else:
                    warn(f"  GET /api/alerts/recent -> {out}")
            
            out2, _, _ = run(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port}/api/anomaly/realtime 2>/dev/null")
            if out2 and out2 != '000':
                if out2 == '200':
                    ok(f"  GET /api/anomaly/realtime -> {out2} OK")
                elif out2 == '404':
                    fail(f"  GET /api/anomaly/realtime -> {out2} NOT FOUND")
                else:
                    warn(f"  GET /api/anomaly/realtime -> {out2}")
                
                # Try to get actual response body
                body, _, _ = run(f"curl -s http://127.0.0.1:{port}/api/anomaly/realtime 2>/dev/null")
                if body[:200]:
                    info(f"  Response body: {body[:200]}")
        break

if not results['api_running']:
    fail("Không tìm thấy API service đang chạy!")
    results['errors'].append("Backend API not running")

# 3d. API through Nginx (port 80/443 -> 8080)
if port_open('127.0.0.1', 80) or port_open('127.0.0.1', 8080):
    ok("Web service accessible")
    
    # Test endpoints through proxy
    web_ports = [80, 8080]
    for wp in web_ports:
        if not port_open('127.0.0.1', wp):
            continue
        out, _, _ = run(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{wp}/api/alerts/recent?limit=50 2>/dev/null")
        if out and out != '000':
            if out == '404':
                fail(f"Through port {wp}: /api/alerts/recent -> {out}")
            elif out == '200':
                ok(f"Through port {wp}: /api/alerts/recent -> {out} OK")
            else:
                warn(f"Through port {wp}: /api/alerts/recent -> {out}")

# ============================================================
# 4. NGINX CONFIGURATION
# ============================================================
header("4. NGINX PROXY CONFIGURATION")

nginx_configs = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/conf.d/default.conf",
    "/home/ids/bk_ids/nginx.conf",
    "/home/ids/bk_ids/nginx/nginx.conf",
]

for nc in nginx_configs:
    exists, content = check_file(nc)
    if exists:
        info(f"Nginx config: {nc}")
        
        # Check proxy_pass directives
        proxy_pass_matches = re.findall(r'proxy_pass\s+(.*?);', content)
        if proxy_pass_matches:
            for pp in proxy_pass_matches:
                info(f"  proxy_pass -> {pp}")
                if '8080' in pp or '/api' in pp:
                    results['nginx_proxy_pass'] = True
        else:
            warn("Không tìm thấy proxy_pass directive")
        
        # Check location blocks for /api
        api_locations = re.findall(r'location\s+([^{]*api[^{]*)\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', content, re.DOTALL)
        if api_locations:
            info(f"  API location blocks: {len(api_locations)}")
            for loc_match in api_locations[:3]:
                info(f"    location: {loc_match[0].strip()[:80]}")
        else:
            # Try simpler search
            has_api_location = bool(re.search(r'location.*api', content))
            if has_api_location:
                info("  Found 'location ... api' block")
            else:
                warn("Không tìm thấy location block cho /api")
        
        # Check for rewrite rules that might strip /api
        rewrites = re.findall(r'rewrite\s+(.*?);', content)
        if rewrites:
            for rw in rewrites:
                info(f"  rewrite: {rw}")
                if 'api' in rw:
                    warn(f"  Rewrite rule affects /api: {rw}")
        
        # Check Cache-Control
        if 'Cache-Control' in content or 'no-store' in content:
            ok("Cache-Control headers configured")
        
        results['nginx_config_ok'] = True
        break

if not results['nginx_config_ok']:
    warn("Không tìm thấy Nginx config")

# ============================================================
# 5. DOCKER SERVICES
# ============================================================
header("5. DOCKER SERVICES & NETWORKING")

out, _, _ = run("docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null")
if out:
    print(f"  {'CONTAINER':<30} {'IMAGE':<30} {'STATUS':<20} {'PORTS'}")
    print(f"  {'-'*100}")
    for line in out.split('\n'):
        parts = line.split('\t')
        if len(parts) >= 3:
            name = parts[0][:28]
            image = parts[1][:28]
            status = parts[2][:18]
            ports = parts[3] if len(parts) > 3 else ''
            
            # Color based on status
            if 'Up' in status:
                print(f"  {C.G}{name:<30}{C.END} {image:<30} {status:<20} {ports}")
            else:
                print(f"  {C.R}{name:<30}{C.END} {image:<30} {status:<20} {ports}")
    
    # Check specific services
    all_names = out.lower()
    if 'snort' in all_names or 'misuse' in all_names:
        results['docker_snort'] = True
    if 'api' in all_names or 'backend' in all_names:
        results['docker_api'] = True
    if 'frontend' in all_names or 'ui' in all_names:
        results['docker_frontend'] = True
else:
    warn("Docker không chạy hoặc không có quyền truy cập")

# Docker network check
out, _, _ = run("docker network ls --format '{{.Name}}\t{{.Driver}}' 2>/dev/null")
if out:
    info("Docker networks:")
    for line in out.split('\n'):
        info(f"  {line}")

# Check docker-compose
compose_files = [
    "/home/ids/bk_ids/docker-compose.yml",
    "/home/ids/bk_ids/docker-compose.yaml",
]
for cf in compose_files:
    if os.path.exists(cf):
        ok(f"Docker Compose file: {cf}")
        with open(cf) as f:
            compose = f.read()
        
        # Check services
        services = re.findall(r'^\s{2}(\w+):\s*$', compose, re.MULTILINE)
        if services:
            info(f"  Services defined: {', '.join(services)}")
        
        # Check volume mounts for Snort
        volumes = re.findall(r'volumes:(.*?)(?=\n\w|\Z)', compose, re.DOTALL)
        if volumes:
            info(f"  Volume mounts configured")
        
        # Check network_mode: host
        if 'network_mode: host' in compose:
            ok("  network_mode: host found (Snort needs this)")
        
        # Check userns_mode
        if 'userns_mode' in compose:
            info(f"  userns_mode configured")

# ============================================================
# 6. FRONTEND-BACKEND SYNC
# ============================================================
header("6. FRONTEND-BACKEND API SYNC")

# Find frontend source
frontend_paths = [
    "/home/ids/bk_ids/frontend",
    "/home/ids/bk_ids/frontend_ui",
    "/home/ids/bk_ids/ui",
    "/home/ids/bk_ids/app.js",
    "/home/ids/bk_ids/index.html",
]
frontend_src = None
for fp in frontend_paths:
    if os.path.exists(fp):
        frontend_src = fp
        ok(f"Frontend source: {fp}")
        break

if frontend_src:
    # Check API calls in frontend
    if os.path.isdir(frontend_src):
        # Search for API endpoint references
        out, _, _ = run(f"grep -rn 'api/alerts\\|api/anomaly\\|getAnomalyData\\|getRecentAlerts' {frontend_src}/ 2>/dev/null | head -30")
    else:
        with open(frontend_src) as f:
            content = f.read()
        out = '\n'.join([f"{i+1}: {l}" for i, l in enumerate(content.split('\n')) 
                        if 'api/alerts' in l or 'api/anomaly' in l or 'getAnomalyData' in l])
    
    if out:
        info("Frontend API calls found:")
        for line in out.split('\n')[:20]:
            if line.strip():
                info(f"  {line.strip()[:120]}")
        
        # Check if getAnomalyData is defined
        if os.path.isdir(frontend_src):
            out2, _, _ = run(f"grep -rn 'getAnomalyData' {frontend_src}/ 2>/dev/null")
        else:
            with open(frontend_src) as f:
                out2 = f.read()
            out2 = '\n'.join([l for l in out2.split('\n') if 'getAnomalyData' in l])
        
        if out2:
            # Check if it's defined (function) or just called
            is_defined = bool(re.search(r'getAnomalyData\s*[=:(]', out2))
            is_called = bool(re.search(r'getAnomalyData\s*\(', out2))
            
            if is_defined:
                ok("getAnomalyData is DEFINED in frontend")
            elif is_called:
                fail("getAnomalyData is CALLED but NOT DEFINED in frontend!")
                results['errors'].append("getAnomalyData() called but not defined in frontend code")
            else:
                warn("getAnomalyData reference found but unclear if defined")
        else:
            fail("getAnomalyData not found in frontend code at all!")
            results['errors'].append("getAnomalyData completely missing from frontend")
    else:
        warn("Không tìm thấy API calls trong frontend source")
    
    # Check API base URL configuration
    if os.path.isdir(frontend_src):
        out, _, _ = run(f"grep -rn '8080\\|API_BASE\\|VITE_API\\|baseURL\\|apiUrl' {frontend_src}/ 2>/dev/null | head -10")
    else:
        with open(frontend_src) as f:
            content = f.read()
        out = '\n'.join([l for l in content.split('\n') if '8080' in l or 'API_BASE' in l or 'baseURL' in l])
    
    if out:
        info("API base URL config:")
        for line in out.split('\n')[:10]:
            if line.strip():
                info(f"  {line.strip()[:120]}")

# ============================================================
# 7. RULE-THRESHOLD-OUTPUT CONSISTENCY
# ============================================================
header("7. RULES / THRESHOLDS / OUTPUT CONSISTENCY")

# 7a. Check if Snort rules reference anomaly detection
if rules_content:
    # Check for threshold rules
    threshold_rules = [l for l in rules_content.split('\n') if 'threshold' in l.lower() or 'detection_filter' in l.lower()]
    if threshold_rules:
        ok(f"Threshold/detection_filter rules: {len(threshold_rules)}")
        for tr in threshold_rules[:5]:
            info(f"  {tr.strip()[:100]}")
    else:
        info("Không có threshold rules (dùng default)")
    
    # Check for preprocessor rules (anomaly)
    preprocessor_rules = [l for l in rules_content.split('\n') if 'preprocessor' in l.lower()]
    if preprocessor_rules:
        info(f"Preprocessor rules: {len(preprocessor_rules)}")

# 7b. Check backend threshold config
if backend_src:
    out, _, _ = run(f"grep -rn 'threshold\\|THRESHOLD\\|anomaly.*score\\|score.*threshold' {backend_src}/ 2>/dev/null | head -10")
    if out:
        info("Backend threshold config:")
        for line in out.split('\n')[:10]:
            if line.strip():
                info(f"  {line.strip()[:120]}")

# 7c. Check frontend threshold display
if frontend_src:
    if os.path.isdir(frontend_src):
        out, _, _ = run(f"grep -rn 'threshold\\|THRESHOLD\\|anomaly.*score\\|score.*threshold' {frontend_src}/ 2>/dev/null | head -10")
    else:
        with open(frontend_src) as f:
            content = f.read()
        out = '\n'.join([l for l in content.split('\n') if 'threshold' in l.lower() or 'anomaly' in l.lower()])
    
    if out:
        info("Frontend threshold display:")
        for line in out.split('\n')[:10]:
            if line.strip():
                info(f"  {line.strip()[:120]}")

# 7d. Verify Snort output format matches what backend expects
info("Checking output format consistency...")
if results['snort_config']:
    for cfg in snort_configs:
        exists, content = check_file(cfg)
        if exists:
            # Check for JSON output (most common for API integration)
            if 'json' in content.lower() or 'eve' in content.lower():
                ok("Snort configured for JSON/EVE output (compatible with API)")
            elif 'unified2' in content.lower():
                warn("Snort uses unified2 format - backend needs barnyard2 or custom parser")
            elif 'fast' in content.lower() or 'full' in content.lower():
                warn("Snort uses alert_fast/full - backend needs text parser")
            break

# ============================================================
# 8. NETWORK CONNECTIVITY
# ============================================================
header("8. NETWORK CONNECTIVITY CHECK")

# Check if services can reach each other
checks = [
    ("Frontend -> API (8080)", "127.0.0.1", 8080),
    ("Frontend -> API (3000)", "127.0.0.1", 3000),
    ("Frontend -> API (5000)", "127.0.0.1", 5000),
    ("Nginx (80)", "127.0.0.1", 80),
    ("Nginx (443)", "127.0.0.1", 443),
]

for name, host, port in checks:
    if port_open(host, port):
        ok(f"{name} - OPEN")
    else:
        info(f"{name} - CLOSED/UNREACHABLE")

# Check DNS resolution for container names
out, _, _ = run("cat /etc/hosts | head -20")
if out:
    info("Hosts file entries:")
    for line in out.split('\n')[:10]:
        if line.strip() and not line.startswith('#'):
            info(f"  {line.strip()}")

# ============================================================
# SUMMARY
# ============================================================
header("AUDIT SUMMARY")

checks = [
    ("Snort 3 binary exists", results['snort_binary']),
    ("Snort process running", results['snort_process']),
    ("Snort config found", results['snort_config']),
    ("Snort HOME_NET correct", results['snort_home_net']),
    ("Snort output configured", results['snort_output']),
    ("Snort rules loaded", results['snort_rules_count'] > 0),
    ("Anomaly service running", results['anomaly_service']),
    ("Data pipeline exists", results['anomaly_source']),
    ("API /alerts route exists", results['api_alerts_route']),
    ("API /anomaly route exists", results['api_anomaly_route']),
    ("Backend API running", results['api_running']),
    ("Nginx config OK", results['nginx_config_ok']),
    ("Nginx proxy_pass correct", results['nginx_proxy_pass']),
    ("Docker Snort container", results['docker_snort']),
    ("Docker API container", results['docker_api']),
    ("Frontend API sync", results['frontend_api_match']),
]

passed = sum(1 for _, v in checks if v)
total = len(checks)

print(f"\n  Results: {passed}/{total} checks passed\n")

for name, status in checks:
    if status:
        ok(name)
    else:
        fail(name)

print(f"\n  Rules count: {results['snort_rules_count']}")

if results['errors']:
    print(f"\n{C.R}{C.BOLD}  CRITICAL ERRORS:{C.END}")
    for e in results['errors']:
        fail(e)

if results['warnings']:
    print(f"\n{C.Y}{C.BOLD}  WARNINGS:{C.END}")
    for w in results['warnings']:
        warn(w)

# Final diagnosis
print(f"\n{C.BOLD}{C.CY}  DIAGNOSIS:{C.END}\n")

if not results['api_alerts_route'] and not results['api_anomaly_route']:
    fail("  >> Backend KHÔNG có routes /api/alerts/recent và /api/anomaly/realtime")
    info("  >> Cần tạo thêm routes trong backend hoặc kiểm tra file route bị thiếu")

if not results['api_running']:
    fail("  >> Backend API không chạy hoặc không bind đúng port")
    info("  >> Kiểm tra: docker compose up backend hoặc systemctl status api")

if not results['snort_process']:
    fail("  >> Snort 3 không chạy")
    info("  >> Khởi động: docker compose up bkids_snort_engine")

if results['snort_process'] and not results['snort_output']:
    fail("  >> Snort chạy nhưng không có output configured")
    info("  >> Thêm alert_json hoặc eve-log vào snort.lua output section")

if not results['anomaly_source']:
    warn("  >> Không có data pipeline giữa Snort và Backend")
    info("  >> Cần: Redis/Kafka/Socket để Snort gửi alerts -> Backend đọc")

if results['api_running'] and not results['api_alerts_route']:
    fail("  >> API chạy nhưng thiếu route definitions")
    info("  >> Kiểm tra file routes/alerts.py hoặc tương tự")

print(f"\n{C.DIM}  Audit completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.END}\n")
