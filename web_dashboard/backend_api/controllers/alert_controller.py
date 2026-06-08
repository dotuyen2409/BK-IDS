# /home/ids/bk_ids/web_dashboard/backend_api/controllers/alert_controller.py

import sys
import logging
import time
import os
from datetime import datetime
import pymysql

sys.path.append('/app')
from flask import jsonify, request
from config.database import get_db_connection

logger = logging.getLogger("Bk-IDS-Alert-Engine")

try:
    import psutil
    PSUTIL_READY = True
    psutil.cpu_percent(interval=None)
except ImportError:
    PSUTIL_READY = False
    logger.warning("PSUTIL not ready")

def _is_db_connected(conn) -> bool:
    if not conn: return False
    if hasattr(conn, 'open'): return conn.open
    if hasattr(conn, 'is_connected'): return conn.is_connected()
    return False


def _whitelist_ips():
    return {
        ip.strip()
        for ip in os.environ.get("WHITELIST_IPS", "127.0.0.1,192.168.13.1").split(",")
        if ip.strip()
    }


def _noise_where(prefix="WHERE"):
    if os.environ.get("SUPPRESS_WHITELISTED_ALERTS", "true").lower() != "true":
        return "", []
    ips = sorted(_whitelist_ips())
    if not ips:
        return "", []
    placeholders = ", ".join(["%s"] * len(ips))
    return f" {prefix} src_ip NOT IN ({placeholders})", ips

def get_alerts_summary():
    """ API Endpoint: Lấy tóm tắt alert metrics """
    try:
        if PSUTIL_READY:
            cpu_usage = psutil.cpu_percent(interval=None)
            ram_usage = psutil.virtual_memory().percent
        else:
            cpu_usage, ram_usage = 0.0, 0.0 

        total_alerts = 0
        db_conn = None
        cursor = None
        
        try:
            db_conn = get_db_connection()
            if _is_db_connected(db_conn):
                cursor = db_conn.cursor(pymysql.cursors.DictCursor)
                # Count total alerts from new canonical alerts table
                noise_where, noise_params = _noise_where()
                cursor.execute("SELECT COUNT(*) AS total FROM alerts" + noise_where, noise_params)
                total_result = cursor.fetchone()
                total_alerts = total_result.get('total', 0) if total_result else 0
                
                # Get severity counts
                cursor.execute("SELECT severity, COUNT(*) as count FROM alerts"
                               + noise_where + " GROUP BY severity", noise_params)
                severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Get SOAR blocked counts
                blocked_where = noise_where + (" AND " if noise_where else " WHERE ")
                cursor.execute("SELECT COUNT(*) as blocked FROM alerts"
                               + blocked_where + "soar_blocked = 1", noise_params)
                blocked_result = cursor.fetchone()
                soar_blocked = blocked_result.get('blocked', 0) if blocked_result else 0
                
        except Exception as db_err:
            logger.error(f"DB Error in summary: {db_err}")
            severity_counts = {}
            soar_blocked = 0
            
        finally:
            if cursor: cursor.close()
            if db_conn and _is_db_connected(db_conn): db_conn.close()

        return jsonify({
            'status': 'success',
            'data': {
                'cpu': round(cpu_usage, 1), 
                'ram': round(ram_usage, 1),
                'severity_counts': severity_counts,
                'soar_blocked': soar_blocked
            },
            'total': total_alerts
        }), 200
        
    except Exception as e:
        logger.error(f"Alert Summary Error: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': "Internal error"}), 500

def get_misuse_alerts():
    """
    API Endpoint for alerts (canonical schema).
    Compatible with existing frontend pagination.
    """
    start_time = time.time()
    db_conn = None
    cursor = None
    
    try:
        db_conn = get_db_connection()
        if not _is_db_connected(db_conn):
            return jsonify({'status': 'error', 'message': "DB disconnected"}), 500
            
        cursor = db_conn.cursor(pymysql.cursors.DictCursor)
        
        limit = request.args.get('limit', default=250, type=int)
        offset = request.args.get('offset', default=0, type=int)
        if limit > 1000: limit = 1000

        # Query new canonical `alerts` table
        noise_where, noise_params = _noise_where()
        sql = """
            SELECT id, event_time as timestamp, src_ip as ip_src, dst_ip as ip_dst,
                   signature as sig_name, protocol, action, severity, category, app_id, soar_blocked
            FROM alerts
        """ + noise_where + """
            ORDER BY event_time DESC, id DESC 
            LIMIT %s OFFSET %s
        """
        cursor.execute(sql, noise_params + [limit, offset])
        alerts_raw = cursor.fetchall()
        
        formatted_alerts = []
        for row in alerts_raw:
            alert = dict(row)
            ts = alert.get('timestamp')
            alert['timestamp'] = ts.strftime('%Y-%m-%d %H:%M:%S') if isinstance(ts, datetime) else str(ts)
            formatted_alerts.append(alert)

        execution_time_ms = round((time.time() - start_time) * 1000, 2)

        return jsonify({
            'status': 'success', 
            'data': formatted_alerts,
            'meta': {
                'total_returned': len(formatted_alerts),
                'limit': limit,
                'offset': offset,
                'execution_time_ms': execution_time_ms
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Alert retrieval error: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': "Database error"}), 500
        
    finally:
        if cursor: cursor.close()
        if db_conn and _is_db_connected(db_conn): db_conn.close()

def get_recent_alerts():
    """ 
    API Endpoint for recent high/critical alerts (SOC live feed).
    """
    db_conn = None
    cursor = None
    try:
        db_conn = get_db_connection()
        if not _is_db_connected(db_conn):
            return jsonify({'status': 'error', 'message': "DB disconnected"}), 500

        cursor = db_conn.cursor(pymysql.cursors.DictCursor)
        
        noise_where, noise_params = _noise_where()
        sql = """
            SELECT id, event_time as time, src_ip, dst_ip, src_port, dst_port,
                   protocol, severity, signature as message, category, action, soar_blocked, app_id
            FROM alerts
        """ + noise_where + """
            ORDER BY event_time DESC, id DESC 
            LIMIT 50
        """
        cursor.execute(sql, noise_params)
        rows = cursor.fetchall()
        
        alerts_list = []
        for row in rows:
            alert = dict(row)
            time_val = alert.get('time')
            alert['time'] = time_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(time_val, datetime) else str(time_val)
            alert['id'] = f"#{alert['id']}"
            alerts_list.append(alert)

        return jsonify({'status': 'success', 'data': alerts_list}), 200
        
    except Exception as e:
        logger.error(f"Recent alerts error: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f"DB error: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if db_conn and _is_db_connected(db_conn): db_conn.close()
