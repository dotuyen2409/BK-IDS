# /home/ids/bk_ids/web_dashboard/backend_api/controllers/rules_controller.py
"""
BK-IDS SOC: Rules Controller — Thin API Wrapper (Enterprise Grade)
===================================================================
Tất cả business logic đã được chuyển sang core_engine/rule_compiler.py (SSOT).
File này chỉ làm nhiệm vụ:
  1. Nhận tham số từ Flask request (body JSON hoặc query params)
  2. Gọi hàm tương ứng từ rule_compiler
  3. Trả về JSON response

Security: JWT Auth được xử lý bởi api_server.py (@require_jwt_auth decorator)
Zero Trust: Mọi endpoint đều bọc try-except + traceback logging
"""
import sys
import os
import logging
import traceback

sys.path.append('/app')

from flask import request, jsonify, g

# Import SSOT từ core engine
from core_engine.rule_compiler import (
    get_all_rules,
    save_rules,
    update_rule,
    delete_rule,
    toggle_rule,
    validate_rules_batch,
    import_rules as _import_rules,
    export_rules as _export_rules,
    bulk_delete_rules,
    bulk_toggle_rules,
    get_templates,
    get_audit_log,
)

logger = logging.getLogger("Bk-IDS-Rules-Engine")


def _get_username():
    """Safely extract username from JWT context."""
    try:
        if hasattr(g, 'current_user') and g.current_user:
            return g.current_user.get('username', 'unknown')
    except Exception:
        pass
    return 'unknown'


def _get_request_data():
    """
    Safely extract request data from JSON body OR query params.
    Hỗ trợ cả POST body JSON và GET/PUT query params.
    """
    data = {}
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    # Merge query params (query params override body for convenience)
    try:
        for key in request.args:
            val = request.args.get(key)
            if val is not None:
                data[key] = val
    except Exception:
        pass
    return data


# ========================================================================
# GET /api/rules — Read all rules
# ========================================================================
def get_rules():
    """GET /api/rules — Query params: category, action, protocol, enabled"""
    try:
        result = get_all_rules(
            category=request.args.get('category', '').strip().lower() or None,
            action=request.args.get('action', '').strip().upper() or None,
            protocol=request.args.get('protocol', '').strip().lower() or None,
            enabled=request.args.get('enabled', '').strip().lower() == 'true' if request.args.get('enabled') else None,
        )
        return jsonify({
            'status': 'success',
            'data': result['rules'],
            'count': result['count'],
            'stats': result['stats']
        }), 200
    except Exception as e:
        logger.error(f"[RULES] get_rules error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Lỗi đọc luật: {str(e)}'}), 200


# ========================================================================
# POST /api/rules — Save/Update rules (batch mode: {rules: [...], mode: replace|append})
# ========================================================================
def save_rules_endpoint():
    """POST /api/rules — Body: {rules: [...], mode: 'replace'|'append'}"""
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        result = save_rules(
            rules_input=data.get('rules', []),
            mode=data.get('mode', 'replace'),
            username=_get_username(),
            ip=request.remote_addr or 'N/A'
        )

        if result.get('status') == 'error':
            return jsonify(result), 400 if 'Xác thực' in result.get('message', '') else 200
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] save_rules error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# POST /api/rules/single — Save/Update a SINGLE rule (frontend format)
# Nhận format: {action, protocol, source, source_port, destination, dest_port, sid, rev, msg, extra_options, rule_text}
# ========================================================================
def save_single_rule_endpoint():
    """
    POST /api/rules/single
    Body: {action, protocol, source, source_port, destination, dest_port, sid, rev, msg, extra_options, rule_text}
    Hoặc query params: ?action=alert&protocol=tcp&sid=1000001&...
    """
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng — cần thông tin luật'}), 400

        # Extract fields from frontend format
        action = str(data.get('action', 'alert')).strip().lower()
        protocol = str(data.get('protocol', 'tcp')).strip().lower()
        source = str(data.get('source', '$HOME_NET')).strip() or '$HOME_NET'
        source_port = str(data.get('source_port', 'any')).strip() or 'any'
        destination = str(data.get('destination', '$EXTERNAL_NET')).strip() or '$EXTERNAL_NET'
        dest_port = str(data.get('dest_port', 'any')).strip() or 'any'
        direction = str(data.get('direction', '->')).strip() or '->'
        sid_raw = data.get('sid', 0)
        rev_raw = data.get('rev', 1)
        msg = str(data.get('msg', '')).strip()
        extra_options = str(data.get('extra_options', '')).strip()
        rule_text = str(data.get('rule_text', '')).strip()

        # Validate SID
        try:
            sid = int(sid_raw)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': f'SID không hợp lệ: {sid_raw}'}), 400
        if sid < 1:
            return jsonify({'status': 'error', 'message': 'SID phải là số nguyên dương'}), 400

        # Validate Rev
        try:
            rev = int(rev_raw) if rev_raw is not None else 1
        except (ValueError, TypeError):
            rev = 1

        # Validate msg
        if not msg:
            return jsonify({'status': 'error', 'message': 'Message (msg) là bắt buộc'}), 400
        if len(msg) < 3:
            return jsonify({'status': 'error', 'message': 'Message quá ngắn (tối thiểu 3 ký tự)'}), 400
        if len(msg) > 255:
            msg = msg[:255]

        # Build Snort 3 rule line
        if rule_text:
            # Use provided rule_text but ensure it has correct SID/Rev
            # Yêu cầu: Không cho phép xuống dòng, chuẩn 1 dòng 1 luật
            raw_rule = ' '.join(rule_text.replace('\r', ' ').replace('\n', ' ').split())
        else:
            # Build from individual fields
            # Sanitize: trim whitespace from IP and Port
            source = ' '.join(source.split())
            source_port = ' '.join(source_port.split())
            destination = ' '.join(destination.split())
            dest_port = ' '.join(dest_port.split())

            # Build options
            opts = []
            opts.append(f'msg:"{msg}"')
            if extra_options:
                # Clean extra options: ensure each ends with ;
                for opt_line in extra_options.split('\n'):
                    opt_line = opt_line.strip()
                    if opt_line:
                        if not opt_line.endswith(';'):
                            opt_line += ';'
                        opts.append(opt_line)
            opts.append(f'sid:{sid}')
            opts.append(f'rev:{rev}')

            raw_rule = f"{action} {protocol} {source} {source_port} {direction} {destination} {dest_port} ({'; '.join(opts)};)"
            # Clean up double semicolons
            raw_rule = raw_rule.replace(';;', ';')

        # Check if rule with this SID already exists → update, otherwise create new
        from core_engine.rule_compiler import get_rule_by_sid
        existing = get_rule_by_sid(sid)

        if existing:
            # Update existing rule
            result = update_rule(
                sid=sid,
                fields={
                    'action': action.upper(),
                    'protocol': protocol,
                    'msg': msg,
                    'raw_rule': raw_rule,
                    'rev': rev,
                },
                username=_get_username(),
                ip=request.remote_addr or 'N/A'
            )
        else:
            # Create new rule — use save_rules with single rule in append mode
            result = save_rules(
                rules_input=[raw_rule],
                mode='append',
                username=_get_username(),
                ip=request.remote_addr or 'N/A'
            )

        if result.get('status') == 'error':
            return jsonify(result), 400
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] save_single_rule error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# PUT /api/rules — Update a single rule
# ========================================================================
def update_rule_endpoint():
    """PUT /api/rules — Body: {sid, action, protocol, msg, ...}"""
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        sid = data.get('sid')
        if not sid:
            return jsonify({'status': 'error', 'message': 'Thiếu SID'}), 400

        try:
            sid = int(sid)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'SID không hợp lệ'}), 400

        result = update_rule(
            sid=sid,
            fields=data,
            username=_get_username(),
            ip=request.remote_addr or 'N/A'
        )

        if result.get('status') == 'error':
            return jsonify(result), 400 if 'không hợp lệ' in result.get('message', '').lower() else 200
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] update_rule error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# DELETE /api/rules — Delete a rule by SID
# ========================================================================
def delete_rule_endpoint():
    """DELETE /api/rules — Body: {sid: 1000001} OR query param: ?sid=1000001"""
    try:
        data = _get_request_data()
        sid = data.get('sid')

        if not sid:
            return jsonify({'status': 'error', 'message': 'Thiếu tham số sid'}), 400

        try:
            sid = int(sid)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'SID không hợp lệ'}), 400

        result = delete_rule(sid=sid, username=_get_username(), ip=request.remote_addr or 'N/A')

        if result.get('status') == 'error':
            return jsonify(result), 200
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] delete_rule error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# PATCH /api/rules/toggle — Enable/Disable a rule
# ========================================================================
def toggle_rule_endpoint():
    """
    PATCH /api/rules/toggle — Body: {sid: 1000001, enabled: true}
    Hoặc query params: ?sid=1000001&enabled=true
    """
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        sid = data.get('sid')
        enabled = data.get('enabled')

        if not sid:
            return jsonify({'status': 'error', 'message': 'Thiếu tham số sid'}), 400
        if enabled is None:
            return jsonify({'status': 'error', 'message': 'Thiếu tham số enabled (true/false)'}), 400

        try:
            sid = int(sid)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'SID không hợp lệ'}), 400

        # Handle enabled as string or bool
        if isinstance(enabled, str):
            enabled = enabled.lower() in ('true', '1', 'yes', 'on')
        else:
            enabled = bool(enabled)

        result = toggle_rule(sid=sid, enabled=enabled, username=_get_username(), ip=request.remote_addr or 'N/A')

        if result.get('status') == 'error':
            return jsonify(result), 200
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] toggle_rule error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# POST /api/rules/validate — Validate without saving
# ========================================================================
def validate_rules_endpoint():
    """POST /api/rules/validate — Body: {rules: [...]}"""
    try:
        data = _get_request_data()
        rules_input = data.get('rules', [])

        if not isinstance(rules_input, list):
            return jsonify({'status': 'error', 'message': 'rules phải là mảng'}), 400

        result = validate_rules_batch(rules_input)

        return jsonify({
            'status': 'success',
            'valid_count': len(result['valid']),
            'error_count': len(result['errors']),
            'errors': result['errors'][:50],
            'is_valid': len(result['errors']) == 0
        }), 200

    except Exception as e:
        logger.error(f"[RULES] validate error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# POST /api/rules/import — Import from raw Snort rules
# ========================================================================
def import_rules_endpoint():
    """POST /api/rules/import — Body: {content: "raw snort rules text", mode: "replace"|"append"}"""
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        result = _import_rules(
            raw_text=data.get('content', ''),
            mode=data.get('mode', 'append'),
            category=data.get('category', 'imported').strip()[:50],
            username=_get_username(),
            ip=request.remote_addr or 'N/A'
        )

        if result.get('status') == 'error':
            return jsonify(result), 400
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] import_rules error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# GET /api/rules/export — Export rules
# ========================================================================
def export_rules_endpoint():
    """GET /api/rules/export — Query params: format=json|snort|csv, enabled_only=true|false"""
    try:
        fmt = request.args.get('format', 'json').strip().lower()
        enabled_only = request.args.get('enabled_only', 'false').strip().lower() == 'true'

        if fmt not in ('json', 'snort', 'csv'):
            return jsonify({'status': 'error', 'message': 'Định dạng không hợp lệ. Chọn: json, snort, csv'}), 400

        result = _export_rules(fmt=fmt, enabled_only=enabled_only)

        if fmt == 'snort':
            return result['content'], 200, {
                'Content-Type': 'text/plain; charset=utf-8',
                'Content-Disposition': 'attachment; filename="bkids_rules.conf"'
            }
        elif fmt == 'csv':
            return result['content'], 200, {
                'Content-Type': 'text/csv; charset=utf-8',
                'Content-Disposition': 'attachment; filename="bkids_rules.csv"'
            }
        else:
            return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] export_rules error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# POST /api/rules/bulk-delete — Delete multiple rules
# ========================================================================
def bulk_delete_rules_endpoint():
    """POST /api/rules/bulk-delete — Body: {sids: [1000001, 1000002, ...]}"""
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        sids = data.get('sids', [])
        if not isinstance(sids, list) or len(sids) == 0:
            return jsonify({'status': 'error', 'message': 'Mảng SIDs rỗng hoặc không hợp lệ'}), 400
        if len(sids) > 1000:
            return jsonify({'status': 'error', 'message': 'Quá nhiều SID (tối đa 1000)'}), 400

        try:
            sids = [int(s) for s in sids]
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Chứa SID không hợp lệ'}), 400

        result = bulk_delete_rules(sids=sids, username=_get_username(), ip=request.remote_addr or 'N/A')
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] bulk_delete error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# POST /api/rules/bulk-toggle — Toggle multiple rules
# ========================================================================
def bulk_toggle_rules_endpoint():
    """POST /api/rules/bulk-toggle — Body: {sids: [...], enabled: true}"""
    try:
        data = _get_request_data()
        if not data:
            return jsonify({'status': 'error', 'message': 'Body rỗng'}), 400

        sids = data.get('sids', [])
        enabled = data.get('enabled')

        if not isinstance(sids, list) or len(sids) == 0:
            return jsonify({'status': 'error', 'message': 'Mảng SIDs rỗng hoặc không hợp lệ'}), 400
        if len(sids) > 1000:
            return jsonify({'status': 'error', 'message': 'Quá nhiều SID (tối đa 1000)'}), 400
        if enabled is None:
            return jsonify({'status': 'error', 'message': 'Thiếu tham số enabled'}), 400

        try:
            sids = [int(s) for s in sids]
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Chứa SID không hợp lệ'}), 400

        if isinstance(enabled, str):
            enabled = enabled.lower() in ('true', '1', 'yes', 'on')
        else:
            enabled = bool(enabled)

        result = bulk_toggle_rules(sids=sids, enabled=enabled, username=_get_username(), ip=request.remote_addr or 'N/A')
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[RULES] bulk_toggle error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# GET /api/rules/templates — Get enterprise rule templates
# ========================================================================
def get_templates_endpoint():
    """GET /api/rules/templates"""
    try:
        result = get_templates()
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"[RULES] get_templates error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400


# ========================================================================
# GET /api/rules/audit-log — Get rule change audit log
# ========================================================================
def get_rules_audit_log():
    """GET /api/rules/audit-log — Query params: limit=100"""
    try:
        limit = request.args.get('limit', 100)
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 100
        limit = min(max(limit, 1), 1000)

        entries = get_audit_log(limit)
        return jsonify({'status': 'success', 'data': entries, 'count': len(entries)}), 200
    except Exception as e:
        logger.error(f"[RULES] get_audit_log error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Backend Exception: {str(e)}'}), 400
