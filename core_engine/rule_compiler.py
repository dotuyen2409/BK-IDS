# /home/bk_ids/bk-ids/core_engine/rule_compiler.py

import os
import re

SNORT_RULES_PATH = '/app/core_engine/local.rules'

def sanitize_name(text):
    if not text: return "Unknown Threat"
    return re.sub(r'[^\w\s\-]', '', str(text)).strip()

def sanitize_pattern(text):
    if not text: return ""
    text = str(text)
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace(';', '\\;')
    return text

def generate_snort_rules(rules_list):
    snort_lines = [
        "# ==================================================================",
        "# BK-IDS SOC: TỆP LUẬT SNORT 3 - ENTERPRISE EDITION",
        "# Cấu hình: Quét DCI Đa Cổng (Bọc thép chống cảnh báo giả 100%)",
        "# ==================================================================\n"
    ]
    sid_counter = 1000001 
    PROTECTED_SERVER_IP = "any"
    
    for rule in rules_list:
        raw_action = str(rule.get('action', 'ALERT')).upper().strip()
        action_web = "DROP" if raw_action in ["DROP", "BLOCK", "CHẶN"] else "ALERT"
        snort_action = "drop" if action_web == "DROP" else "alert"
        
        name = sanitize_name(rule.get('name'))
        pattern = sanitize_pattern(rule.get('pattern'))
        
        protocol = str(rule.get('protocol', 'tcp')).lower()
        if not pattern: continue 
        
        # 🎯 ĐÃ ĐỒNG BỘ CÚ PHÁP SNORT 3: Nối nocase bằng dấu phẩy
        snort_rule = f'{snort_action} {protocol} any any -> {PROTECTED_SERVER_IP} any (msg:"[{action_web}] {name}"; content:"{pattern}", nocase; classtype:web-application-attack; sid:{sid_counter}; rev:1;)'
        
        snort_lines.append(snort_rule)
        sid_counter += 1
        
    os.makedirs(os.path.dirname(SNORT_RULES_PATH), exist_ok=True)
    with open(SNORT_RULES_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(snort_lines))