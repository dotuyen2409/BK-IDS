# /home/ids/bk_ids/web_dashboard/backend_api/api_server.py
# BK-IDS SOC: NGIPS API GATEWAY v3.0
# Phase 2/3: Snort NGIPS + LogWatchdog + SOAR + MySQL alerts
# ============================================================
# Architecture: Blueprint §2 + §3 + §4
# - Snort 3 NGIPS: alert_json -> LogWatchdog -> MySQL
# - No Kafka / Elasticsearch / WAF dependencies
# - JWT auth with role-based access
# ============================================================

import sys
import os
import json
import re
import logging
import subprocess
from datetime import datetime

sys.path.append('/app')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS

# Socket.IO for real-time alert push to Vue.js dashboard
try:
    from flask_socketio import SocketIO
    SOCKETIO_READY = True
except ImportError:
    SOCKETIO_READY = False
    SocketIO = None

# =================================================================
# JWT AUTH IMPORT (mandatory — API refuses to start if missing)
# =================================================================
try:
    from auth import (
        require_jwt_auth,
        require_role,
        require_permission,
        create_token,
        verify_token,
        get_user_store,
        Role,
        Permission,
        sanitize_ip,
        sanitize_limit,
        sanitize_offset,
    )
except ImportError as _e:
    raise RuntimeError(
        "CRITICAL: auth.py module missing! NGIPS API requires JWT auth. "
        "Error: " + str(_e)
    )

# =================================================================
# THREAT INTEL (optional — API still works if missing)
# =================================================================
try:
    import threat_intel_updater
    THREAT_INTEL_READY = True
except ImportError:
    THREAT_INTEL_READY = False

# =================================================================
# SOAR ENGINE (optional — watchdog has direct iptables fallback)
# =================================================================
try:
    sys.path.insert(0, '/app/core_engine')
    from soar_engine import get_soar_engine, SOAR_ENABLED as SOAR_ENGINE_ENABLED
    SOAR_READY = True
except ImportError:
    SOAR_READY = False
    SOAR_ENGINE_ENABLED = False

# =================================================================
# LOG WATCHDOG (Phase 3 — critical for NGIPS alert ingestion)
# =================================================================
try:
    from log_watchdog import start_watchdog
    WATCHDOG_READY = True
except ImportError:
    WATCHDOG_READY = False

# =================================================================
# FLASK APP SETUP
# =================================================================
app = Flask(__name__)

_CORS_ORIGINS = [
    "http://192.168.13.129",
    "http://192.168.13.129:80",
    "http://192.168.13.129:8080",
    "http://192.168.13.129:9000",
    "http://192.168.13.129:5050",
    "http://localhost",
    "http://localhost:80",
    "http://localhost:8080",
    "http://localhost:9000",
    "http://localhost:5050",
]

CORS(app, resources={r"/*": {"origins": _CORS_ORIGINS}})

# Socket.IO — real-time alert push to Vue.js dashboard
if SOCKETIO_READY:
    socketio = SocketIO(
        app,
        cors_allowed_origins=_CORS_ORIGINS,
        async_mode='threading',
        logger=False,
        engineio_logger=False,
    )
    logger_ws = logging.getLogger("BK-IDS-WS")

    @socketio.on('connect')
    def ws_connect():
        logger_ws.info("[WS] Client connected: %s", request.sid)

    @socketio.on('disconnect')
    def ws_disconnect():
        logger_ws.info("[WS] Client disconnected: %s", request.sid)
else:
    socketio = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("BK-IDS-NGIPS")

RULE_JSON_PATH = '/app/core_engine/rules_db.json'
SNORT_RULES_PATH = '/app/core_engine/local.rules'

# =================================================================
# GLOBAL ERROR HANDLER — never leak internal details
# =================================================================
@app.errorhandler(Exception)
def handle_global_error(e):
    logger.error("Unhandled exception: %s", str(e), exc_info=True)
    return jsonify({'status': 'error', 'message': 'Internal Server Error'}), 500


@app.errorhandler(404)
def handle_404(e):
    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405


# =================================================================
# SECURITY HEADERS
# =================================================================
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Request-Id"] = os.urandom(8).hex()
    return response


# =================================================================
# SAFE SUBPROCESS HELPERS
# =================================================================
def safe_iptables_cmd(action: str, ip: str, chain: str = "INPUT") -> bool:
    """Execute iptables with NO shell=True. IP validated. Chain validated."""
    if not sanitize_ip(ip):
        return False
    if not re.match(r'^[A-Za-z0-9_-]+$', chain):
        return False

    if action == 'add':
        cmd = ['iptables', '-I', chain, '1', '-s', ip, '-j', 'DROP']
    elif action == 'remove':
        cmd = ['iptables', '-D', chain, '-s', ip, '-j', 'DROP']
    else:
        return False

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5, shell=False)
        if r.returncode != 0:
            logger.warning("[FW] iptables %s failed for %s on %s: %s",
                           action, ip, chain, r.stderr.decode('utf-8', errors='replace').strip())
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def safe_block_ip(ip: str) -> bool:
    """Block IP across INPUT, DOCKER-USER, and mangle PREROUTING."""
    if ip in _whitelist_ips():
        logger.warning("[FW] Refused to block whitelisted IP: %s", ip)
        return False
    results = []
    for chain in ['INPUT', 'DOCKER-USER']:
        results.append(safe_iptables_cmd('add', ip, chain))
    try:
        subprocess.run(['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1',
                        '-s', ip, '-j', 'DROP'],
                       capture_output=True, timeout=5, shell=False)
    except Exception:
        pass
    return any(results)


def safe_unblock_ip(ip: str) -> bool:
    """Unblock IP from all chains."""
    results = []
    for chain in ['INPUT', 'DOCKER-USER']:
        removed_any = False
        for _ in range(10):
            if safe_iptables_cmd('remove', ip, chain):
                removed_any = True
                continue
            break
        results.append(removed_any)
    try:
        for _ in range(10):
            r = subprocess.run(['iptables', '-t', 'mangle', '-D', 'PREROUTING',
                                '-s', ip, '-j', 'DROP'],
                               capture_output=True, timeout=5, shell=False)
            if r.returncode != 0:
                break
    except Exception:
        pass
    return any(results)


# =================================================================
# SNORT RULE GENERATION
# =================================================================
def trigger_system_reload():
    try:
        subprocess.run(['pkill', '-SIGHUP', '-f', 'snort'],
                       check=False, capture_output=True, timeout=5, shell=False)
        logger.info("[SYSTEM] SIGHUP sent to Snort")
    except Exception as e:
        logger.warning("[SYSTEM] Cannot reload Snort: %s", e)


def generate_snort_rules(rules_list):
    """Write compiled Snort rules to local.rules file."""
    from core_engine.rule_compiler import generate_snort_rules as _compile
    _compile(rules_list)
    trigger_system_reload()


# =================================================================
# MYSQL CONNECTION HELPER (for NGIPS alert API)
# =================================================================
import pymysql
import pymysql.cursors

def _get_db():
    return pymysql.connect(
        host=os.environ.get("MYSQL_HOST", "mysql_db"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        db=os.environ.get("MYSQL_DATABASE", "bk_ids"),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=5,
    )


def _whitelist_ips():
    return {
        ip.strip()
        for ip in os.environ.get("WHITELIST_IPS", "127.0.0.1,192.168.13.1").split(",")
        if sanitize_ip(ip.strip())
    }


def _append_noise_filter(conditions, params, column="src_ip"):
    if os.environ.get("SUPPRESS_WHITELISTED_ALERTS", "true").lower() != "true":
        return
    ips = sorted(_whitelist_ips())
    if not ips:
        return
    placeholders = ", ".join(["%s"] * len(ips))
    conditions.append(column + " NOT IN (" + placeholders + ")")
    params.extend(ips)


# =================================================================
# PUBLIC ENDPOINTS — NO AUTH REQUIRED
# =================================================================

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def auth_login():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    username = data.get('username', '')
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Missing credentials'}), 400

    store = get_user_store()
    user = store.authenticate(username, password)
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

    token = create_token(user['id'], user['username'], Role(user['role']))
    refresh = create_token(user['id'], user['username'], Role(user['role']), 'refresh')
    logger.info("[AUTH] Login: %s from %s", username, request.remote_addr)
    return jsonify({
        'status': 'success',
        'token': token, 'refresh_token': refresh,
        'user': {'id': user['id'], 'username': user['username'], 'role': user['role']},
    }), 200


@app.route('/api/auth/refresh', methods=['POST', 'OPTIONS'])
def auth_refresh():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    payload = verify_token(data.get('refresh_token', ''))
    if not payload or payload.get('type') != 'refresh':
        return jsonify({'status': 'error', 'message': 'Invalid refresh token'}), 401
    new_token = create_token(payload['sub'], payload['username'], Role(payload['role']))
    return jsonify({'status': 'success', 'token': new_token}), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Extended health: DB + Redis + Watchdog + NGIPS status."""
    # DB check
    db_ok = False
    try:
        conn = _get_db()
        conn.close()
        db_ok = True
    except Exception:
        pass

    # Redis check
    redis_ok = False
    try:
        import redis as _r
        rc = _r.Redis(
            host=os.environ.get("REDIS_HOST", "redis_cache"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
            password=os.environ.get("REDIS_PASSWORD", None),
            socket_timeout=3, decode_responses=True)
        rc.ping()
        redis_ok = True
    except Exception:
        pass

    watchdog_metrics = {}
    if WATCHDOG_READY:
        try:
            from log_watchdog import get_watchdog
            watchdog_metrics = get_watchdog().get_metrics()
        except Exception:
            watchdog_metrics = {'status': 'not_initialized'}

    return jsonify({
        'status': 'ok',
        'db': 'connected' if db_ok else 'disconnected',
        'redis': 'connected' if redis_ok else 'disconnected',
        'watchdog': watchdog_metrics,
        'ngips': 'active',
    }), 200


@app.route('/api/health/system', methods=['GET', 'OPTIONS'])
def health_system():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        cpu_usage = 0.0
        try:
            import psutil
            cpu_usage = psutil.cpu_percent(interval=0.1)
        except ImportError:
            try:
                import os
                load1, load5, load15 = os.getloadavg()
                cpu_usage = load1 * 100 / os.cpu_count()
            except Exception:
                pass
        
        ram_usage = 0.0
        try:
            import psutil
            ram_usage = psutil.virtual_memory().percent
        except ImportError:
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                mem_total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
                mem_avail = int(re.search(r'MemAvailable:\s+(\d+)', meminfo).group(1))
                ram_usage = round(100 - (mem_avail / mem_total * 100), 1)
            except Exception:
                pass

        snort_running = False
        try:
            import subprocess
            r = subprocess.run(['pgrep', '-x', 'snort'], capture_output=True, shell=False)
            snort_running = r.returncode == 0
        except Exception:
            pass

        return jsonify({
            'status': 'success',
            'cpu': round(cpu_usage, 1),
            'ram': round(ram_usage, 1),
            'snort_running': snort_running
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/', methods=['GET'])
def root_endpoint():
    return jsonify({
        'status': 'ok',
        'message': 'BK-IDS NGIPS API Gateway v3.0'
    }), 200


@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    id_val = request.args.get('id') or (request.form.get('id') if request.form else None)
    if not id_val and request.is_json:
        try:
            id_val = request.get_json(force=True, silent=True).get('id')
        except Exception:
            pass
    return jsonify({
        'status': 'success',
        'message': 'Test endpoint reached successfully',
        'received_id': id_val
    }), 200


# =================================================================
# NGIPS ALERT API — Blueprint §3.6.3 (direct MySQL, no ES)
# =================================================================

@app.route('/api/alerts', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def api_list_alerts():
    """Paginated alert list from MySQL `alerts` table."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    limit   = sanitize_limit(request.args.get('limit', '100'))
    offset  = sanitize_offset(request.args.get('offset', '0'))
    severity = request.args.get('severity', '')
    src_ip  = request.args.get('src_ip', '')
    category = request.args.get('category', '')

    conditions, params = [], []
    if severity:
        conditions.append('severity = %s')
        params.append(severity)
    if src_ip and sanitize_ip(src_ip):
        conditions.append('src_ip = %s')
        params.append(src_ip)
    if category:
        conditions.append('category = %s')
        params.append(category)
    _append_noise_filter(conditions, params)
    where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) AS cnt FROM alerts' + where, params)
            total = cur.fetchone()['cnt']
        with conn.cursor() as cur:
            cur.execute(
                'SELECT id, event_time, src_ip, src_port, dst_ip, dst_port, '
                'protocol, sid, signature, category, severity, action, app_id, '
                'soar_blocked, created_at '
                'FROM alerts' + where + ' ORDER BY event_time DESC LIMIT %s OFFSET %s',
                params + [limit, offset])
            rows = cur.fetchall()
    finally:
        conn.close()

    return jsonify({
        'status': 'success', 'data': rows,
        'total': total, 'limit': limit, 'offset': offset,
    }), 200


@app.route('/api/alerts/recent', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def api_recent_alerts():
    """Last N alerts (default 50, max 500)."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    limit = min(sanitize_limit(request.args.get('limit', '50')), 500)
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            conditions, params = [], []
            _append_noise_filter(conditions, params)
            where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
            cur.execute(
                'SELECT id, event_time, src_ip, src_port, dst_ip, dst_port, '
                'protocol, sid, signature, category, severity, action, app_id, soar_blocked '
                'FROM alerts' + where + ' ORDER BY event_time DESC LIMIT %s',
                params + [limit])
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({'status': 'success', 'data': rows, 'count': len(rows)}), 200


@app.route('/api/alerts/summary', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def api_alerts_summary():
    """Aggregate counts for dashboard widgets."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    conn = _get_db()
    try:
        conditions, params = [], []
        _append_noise_filter(conditions, params)
        where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
        last_hour_where = where + (' AND ' if where else ' WHERE ')
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) AS total FROM alerts' + where, params)
            total = cur.fetchone()['total']

            cur.execute('SELECT COUNT(*) AS cnt FROM alerts '
                        + last_hour_where + 'event_time >= NOW() - INTERVAL 1 HOUR',
                        params)
            last_hour = cur.fetchone()['cnt']

            cur.execute('SELECT severity, COUNT(*) AS cnt FROM alerts'
                        + where + ' GROUP BY severity', params)
            by_severity = {r['severity']: r['cnt'] for r in cur.fetchall()}

            cur.execute('SELECT category, COUNT(*) AS cnt FROM alerts '
                        + where + ' GROUP BY category ORDER BY cnt DESC LIMIT 10',
                        params)
            by_category = [{'category': r['category'], 'count': r['cnt']} for r in cur.fetchall()]

            soar_where = where + (' AND ' if where else ' WHERE ')
            cur.execute('SELECT COUNT(*) AS cnt FROM alerts '
                        + soar_where + 'soar_blocked = 1', params)
            soar_blocked = cur.fetchone()['cnt']

            cur.execute('SELECT src_ip, COUNT(*) AS cnt FROM alerts '
                        + where + ' GROUP BY src_ip ORDER BY cnt DESC LIMIT 10',
                        params)
            top_src = [{'ip': r['src_ip'], 'count': r['cnt']} for r in cur.fetchall()]
    finally:
        conn.close()

    return jsonify({
        'status': 'success', 'total': total, 'last_hour': last_hour,
        'by_severity': by_severity, 'by_category': by_category,
        'soar_blocked': soar_blocked, 'top_source_ips': top_src,
    }), 200


# =================================================================
# ANOMALY DETECTION API — CuSUM Engine
# =================================================================

@app.route('/api/anomaly/realtime', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def api_anomaly_realtime():
    """Realtime anomaly data from CuSUM engine (ids_dulieu table)."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        from controllers.cusum_controller import get_statistics
        return get_statistics()
    except ImportError as ie:
        logger.error("[ANOMALY] cusum_controller import error: %s", ie)
        return jsonify({'status': 'error', 'message': 'Anomaly engine not available'}), 503
    except Exception as e:
        logger.error("[ANOMALY] get_statistics error: %s", e, exc_info=True)
        return jsonify({'status': 'error', 'message': 'Anomaly query failed'}), 500


@app.route('/api/anomaly/config', methods=['GET', 'OPTIONS', 'POST'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def api_anomaly_config():
    """Get/update CuSUM threshold configuration."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        if request.method == 'POST':
            data = request.get_json(force=True)
            new_threshold = data.get('cusum_threshold')
            if new_threshold is not None:
                try:
                    val = float(new_threshold)
                    if val <= 0:
                        raise ValueError("Threshold must be positive")
                except (TypeError, ValueError) as ve:
                    return jsonify({'status': 'error', 'message': 'Invalid threshold: ' + str(ve)}), 400
                # Persist to system_config table
                conn = _get_db()
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO system_config (config_key, config_value) VALUES ('CUSUM_THRESHOLD', %s) "
                            "ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)",
                            (str(val),)
                        )
                finally:
                    conn.close()
                logger.info("[ANOMALY] Threshold updated to %s by %s", val, g.current_user.get('username'))
                return jsonify({'status': 'success', 'cusum_threshold': val}), 200

        # GET: return current threshold
        conn = _get_db()
        threshold = 700.0
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT config_value FROM system_config WHERE config_key = 'CUSUM_THRESHOLD'")
                row = cur.fetchone()
                if row:
                    threshold = float(row['config_value'])
        finally:
            conn.close()
        return jsonify({'status': 'success', 'cusum_threshold': threshold}), 200
    except Exception as e:
        logger.error("[ANOMALY] config error: %s", e, exc_info=True)
        return jsonify({'status': 'error', 'message': 'Config error'}), 500


# =================================================================
# SOAR API — BLOCK/UNBLOCK
# =================================================================

@app.route('/api/soar/blocks', methods=['GET', 'OPTIONS'])
@require_jwt_auth
def soar_list_blocks():
    """List active SOAR blocks."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    # Query MySQL soar_blocks directly
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            conditions, params = ['is_active = 1'], []
            _append_noise_filter(conditions, params, column="ip")
            cur.execute('SELECT id, ip, reason, blocked_at, ban_duration_sec, source '
                        'FROM soar_blocks WHERE ' + ' AND '.join(conditions)
                        + ' ORDER BY blocked_at DESC', params)
            blocks = cur.fetchall()
            for b in blocks:
                if b.get('blocked_at') and b.get('ban_duration_sec'):
                    # Convert blocked_at to timestamp (seconds) and add duration
                    b['unban_time'] = b['blocked_at'].timestamp() + b['ban_duration_sec']
        conn.close()
        return jsonify({'status': 'success', 'data': blocks, 'count': len(blocks)}), 200
    except Exception as e:
        logger.error("[SOAR] List blocks error: %s", str(e), exc_info=True)
        return jsonify({'status': 'error', 'message': 'Query failed'}), 500


@app.route('/api/soar/block', methods=['POST', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def soar_manual_block():
    """Manually block an IP — admin only."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    ip = data.get('ip', '')
    if not sanitize_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400

    if ip in _whitelist_ips():
        return jsonify({'status': 'error', 'message': 'Cannot block whitelisted IP'}), 400

    success = safe_block_ip(ip)
    if success:
        try:
            conn = _get_db()
            with conn.cursor() as cur:
                # check if active block already exists
                cur.execute('SELECT id FROM soar_blocks WHERE ip = %s AND is_active = 1', (ip,))
                if not cur.fetchone():
                    cur.execute(
                        'INSERT INTO soar_blocks (ip, reason, blocked_at, ban_duration_sec, source, is_active) '
                        'VALUES (%s, %s, NOW(), %s, %s, 1)',
                        (ip, 'Manual block from dashboard', 86400, 'dashboard')
                    )
            conn.close()
        except Exception as e:
            logger.error("[SOAR] DB insert error: %s", e)

        logger.info("[SOAR] Manual block: %s by %s", ip, g.current_user.get('username'))
        return jsonify({'status': 'success', 'message': 'IP ' + ip + ' blocked'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Failed to block IP'}), 500


@app.route('/api/soar/unblock', methods=['POST', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def soar_manual_unblock():
    """Manually unblock an IP — admin only."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    ip = data.get('ip', '')
    if not sanitize_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400

    safe_unblock_ip(ip)
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute('UPDATE soar_blocks SET is_active = 0, unblocked_at = NOW() '
                        'WHERE ip = %s AND is_active = 1', (ip,))
        conn.close()
    except Exception as e:
        logger.error("[SOAR] DB update error: %s", e)

    logger.info("[SOAR] Manual unblock: %s by %s", ip, g.current_user.get('username'))
    return jsonify({'status': 'success', 'message': 'IP ' + ip + ' unblocked'}), 200


# =================================================================
# BANNED IPS (legacy compatibility — reads soar_blocks table)
# =================================================================

@app.route('/api/banned-ips', methods=['GET', 'OPTIONS'])
@require_jwt_auth
def get_banned_ips():
    """List banned IPs from soar_blocks + legacy bans_state.json."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        blocks = []
        try:
            conn = _get_db()
            with conn.cursor() as cur:
                conditions, params = ['is_active = 1'], []
                _append_noise_filter(conditions, params, column="ip")
                cur.execute('SELECT ip, reason, blocked_at FROM soar_blocks WHERE '
                            + ' AND '.join(conditions), params)
                for r in cur.fetchall():
                    blocks.append({'ip': r['ip'], 'reason': r['reason'], 'since': str(r['blocked_at'])})
            conn.close()
        except Exception:
            pass

        return jsonify({'status': 'success', 'data': blocks}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/unban-ip', methods=['POST', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def api_unban_ip():
    """Unban IP — alias for /api/soar/unblock."""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({'status': 'error', 'message': 'Missing IP'}), 400
    ip = str(data['ip']).strip()
    if not sanitize_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400

    safe_unblock_ip(ip)
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute('UPDATE soar_blocks SET is_active=0, unblocked_at=NOW() '
                        'WHERE ip=%s AND is_active=1', (ip,))
        conn.close()
    except Exception:
        pass

    logger.info("[FW] Unban: %s", ip)
    return jsonify({'status': 'success', 'message': 'IP ' + ip + ' unblocked'}), 200


# =================================================================
# THREAT INTEL ENDPOINTS
# =================================================================

@app.route('/api/update_rules_online', methods=['POST'])
@require_jwt_auth
@require_role(Role.ADMIN)
def update_rules_online():
    if not THREAT_INTEL_READY:
        return jsonify({'status': 'error', 'message': 'Threat Intel not available'}), 503
    try:
        success = threat_intel_updater.fetch_and_merge_et_rules()
        if not success:
            return jsonify({'status': 'error', 'message': 'Threat Intel fetch failed'}), 500
        with open(RULE_JSON_PATH, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        rule_list = rules.get('rules', []) if isinstance(rules, dict) else rules
        generate_snort_rules(rule_list)
        return jsonify({'status': 'success', 'message': 'Rules synced from Threat Intel'}), 200
    except Exception as e:
        logger.error("[TI] update_rules_online error: %s", e, exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal error'}), 500


@app.route('/api/threat-intel/lookup', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def threat_intel_lookup():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    ip = request.args.get('ip', '')
    if not sanitize_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400
    try:
        from threat_intel import check_abuseipdb
        return jsonify({'status': 'success', 'data': check_abuseipdb(ip)}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/threat-intel/check-block', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_permission(Permission.READ_ALERTS)
def threat_intel_check_block():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    ip = request.args.get('ip', '')
    if not sanitize_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP'}), 400
    try:
        from threat_intel import check_abuseipdb
        result = check_abuseipdb(ip)
        score = result.get('abuse_confidence_score', 0)
        threshold = int(request.args.get('min_score', '50'))
        return jsonify({
            'status': 'success', 'data': result,
            'should_block': score >= threshold,
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# =================================================================
# PROTECTED: AUTH USERS
# =================================================================

@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
@require_jwt_auth
def auth_me():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    return jsonify({'status': 'success', 'user': g.current_user}), 200


@app.route('/api/auth/users', methods=['GET', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def auth_list_users():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    return jsonify({'status': 'success', 'users': get_user_store().list_users()}), 200


@app.route('/api/auth/users', methods=['POST', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def auth_create_user():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    username = data.get('username', '')
    password = data.get('password', '')
    role_str = data.get('role', 'analyst')
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Missing fields'}), 400
    try:
        role = Role(role_str)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid role'}), 400
    store = get_user_store()
    user = store.create_user(username, password, role)
    if not user:
        return jsonify({'status': 'error', 'message': 'Username exists'}), 409
    return jsonify({'status': 'success', 'user': user}), 201


# =================================================================
# PACKET DETAILS (backward compat)
# =================================================================

@app.route('/api/get_packet_details', methods=['GET', 'OPTIONS'])
@require_jwt_auth
def packet_details():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        from controllers import dpi_controller
        return dpi_controller.dpi_get_packet_details()
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# =================================================================
# RULES API (RESTful)
# =================================================================

@app.route('/api/rules', methods=['GET', 'OPTIONS'])
@require_jwt_auth
def rest_get_rules():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.get_rules()

@app.route('/api/rules', methods=['POST', 'OPTIONS'])
@require_jwt_auth
def rest_save_rules():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.save_rules_endpoint()

@app.route('/api/rules/single', methods=['POST', 'OPTIONS'])
@require_jwt_auth
def rest_save_single_rule():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.save_single_rule_endpoint()

@app.route('/api/rules', methods=['PUT', 'OPTIONS'])
@require_jwt_auth
def rest_update_rule():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.update_rule_endpoint()

@app.route('/api/rules', methods=['DELETE', 'OPTIONS'])
@require_jwt_auth
def rest_delete_rule():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.delete_rule_endpoint()

@app.route('/api/rules/toggle', methods=['PATCH', 'OPTIONS'])
@require_jwt_auth
def rest_toggle_rule():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    from controllers import rules_controller
    return rules_controller.toggle_rule_endpoint()

# =================================================================
# CENTRAL ROUTER (legacy PHP-style routing — kept for compat)
# =================================================================

@app.route('/backend_api/routes/api.php', methods=['GET', 'POST', 'OPTIONS'])
@require_jwt_auth
def gateway():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    route = request.args.get('route', '')
    if not re.match(r'^[a-z_]+$', route):
        return jsonify({'status': 'error', 'message': 'Invalid route'}), 400

    try:
        if route == 'get_capture_config':
            from controllers import capture_config_controller
            return capture_config_controller.get_config()
        elif route == 'save_capture_config':
            from controllers import capture_config_controller
            return capture_config_controller.save_config()
        elif route == 'get_anomaly_data':
            from controllers import cusum_controller
            return cusum_controller.get_statistics()
        elif route == 'get_misuse_alerts':
            from controllers import alert_controller
            return alert_controller.get_misuse_alerts()
        elif route == 'get_recent_alerts':
            from controllers import alert_controller
            return alert_controller.get_recent_alerts()
        elif route == 'get_rules':
            from controllers import rules_controller
            return rules_controller.get_rules()
        elif route == 'save_rules':
            from controllers import rules_controller
            return rules_controller.save_rules_endpoint()
        elif route == 'save_single_rule':
            from controllers import rules_controller
            return rules_controller.save_single_rule_endpoint()
        elif route == 'update_rule':
            from controllers import rules_controller
            return rules_controller.update_rule_endpoint()
        elif route == 'delete_rule':
            from controllers import rules_controller
            return rules_controller.delete_rule_endpoint()
        elif route == 'toggle_rule':
            from controllers import rules_controller
            return rules_controller.toggle_rule_endpoint()
        elif route == 'validate_rules':
            from controllers import rules_controller
            return rules_controller.validate_rules_endpoint()
        elif route == 'import_rules':
            from controllers import rules_controller
            return rules_controller.import_rules_endpoint()
        elif route == 'export_rules':
            from controllers import rules_controller
            return rules_controller.export_rules_endpoint()
        elif route == 'bulk_delete_rules':
            from controllers import rules_controller
            return rules_controller.bulk_delete_rules_endpoint()
        elif route == 'bulk_toggle_rules':
            from controllers import rules_controller
            return rules_controller.bulk_toggle_rules_endpoint()
        elif route == 'get_rule_templates':
            from controllers import rules_controller
            return rules_controller.get_templates_endpoint()
        elif route == 'get_rules_audit_log':
            from controllers import rules_controller
            return rules_controller.get_rules_audit_log()
        elif route == 'update_rules_online':
            return update_rules_online()
        elif route == 'alerts_summary':
            from controllers import alert_controller
            return alert_controller.get_alerts_summary()
        elif route == 'get_banned_ips':
            return get_banned_ips()
        elif route == 'unban_ip':
            return api_unban_ip()
        else:
            return jsonify({'status': 'error', 'message': 'Route not found: ' + route}), 404
    except ImportError as ie:
        logger.error("[GW] Import error at route %s: %s", route, ie, exc_info=True)
        return jsonify({'status': 'error', 'message': 'Module error'}), 500
    except Exception as e:
        logger.error("[GW] Route %s error: %s", route, str(e), exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal error'}), 500


# =================================================================
# SOAR WEBHOOK (Kafka removed — alert already in MySQL via LogWatchdog)
# =================================================================

@app.route('/api/soar/webhook', methods=['POST', 'OPTIONS'])
@require_jwt_auth
@require_role(Role.ADMIN)
def soar_webhook():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json(force=True)
    if not data:
        return jsonify({'status': 'error', 'message': 'Empty payload'}), 400
    src_ip = data.get('src_ip', '')
    if not sanitize_ip(src_ip):
        return jsonify({'status': 'error', 'message': 'Invalid src_ip'}), 400
    if data.get('severity', '') != 'CRITICAL':
        return jsonify({'status': 'ok', 'action': 'skipped'}), 200
    if src_ip in _whitelist_ips():
        return jsonify({'status': 'ok', 'action': 'whitelisted'}), 200

    if SOAR_READY:
        soar = get_soar_engine()
        result = soar.process_critical_alert(data)
    else:
        result = {'blocked': safe_block_ip(src_ip), 'action': 'DIRECT_IPTABLES'}

    # Kafka removed per blueprint — alert already in MySQL
    logger.info("[SOAR] Webhook: %s -> %s", src_ip, result)
    return jsonify({'status': 'success', 'soar_result': result}), 200


# =================================================================
# ENTRY POINT — Start LogWatchdog + Flask
# =================================================================

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("  BK-IDS NGIPS API SERVER v3.0 — STARTING")
    logger.info("  [Watchdog=%s] [SOAR=%s] [ThreatIntel=%s] [Socket.IO=%s]",
                'ready' if WATCHDOG_READY else 'OFF',
                'ready' if SOAR_READY else 'OFF',
                'ready' if THREAT_INTEL_READY else 'OFF',
                'ready' if SOCKETIO_READY else 'OFF')
    logger.info("=" * 60)

    # Start LogWatchdog (Phase 3 — critical for NGIPS alert ingestion)
    # Pass socketio instance so alerts are pushed in real-time to Vue.js
    if WATCHDOG_READY:
        watchdog = start_watchdog(socketio=socketio)
        logger.info("[NGIPS] LogWatchdog started – ingesting Snort alerts to MySQL")
        if socketio:
            logger.info("[NGIPS] Socket.IO enabled – real-time push to Vue.js dashboard")
    else:
        logger.warning("[NGIPS] LogWatchdog NOT available – Snort alerts will NOT be ingested")

    # Use socketio.run() if available (enables WebSocket transport),
    # fallback to plain Flask app.run()
    if socketio:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=False)
