import os
import json
import requests
import re
import logging

logger = logging.getLogger(__name__)

RULE_JSON_PATH = '/app/core_engine/rules_db.json'
ET_RULES_URL = "https://rules.emergingthreats.net/open/snort3/emerging-web_specific_apps.rules"

def fetch_and_merge_et_rules():
    logger.info(" [THREAT INTEL] Đang kết nối tới máy chủ Emerging Threats...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(ET_RULES_URL, headers=headers, timeout=20)
        response.raise_for_status() 
        raw_rules = response.text
        logger.info(" [THREAT INTEL] Tải luật thành công.")
    except Exception as e:
        logger.info(" [THREAT INTEL] Dùng Fallback (Offline)...")
        raw_rules = """
        alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS Dấu hiệu XSS Reflected cơ bản"; content:"<script>alert(", nocase; sid:2000001; rev:1;)
        alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS Tấn công SQLi Boolean Based Bypass"; content:"' OR 1=1 --", nocase; sid:2000004; rev:1;)
        alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS Khai thác Lỗ hổng Log4j JNDI Injection RCE"; content:"${jndi:ldap://", nocase; sid:2000005; rev:1;)
        """
        
    pattern = re.compile(r'alert\s+(tcp|udp).*?msg\s*:\s*"([^"]+)".*?content\s*:\s*"([^"]+)"', re.IGNORECASE)
    matches = pattern.findall(raw_rules)
    
    existing_rules = []
    if os.path.exists(RULE_JSON_PATH):
        try:
            with open(RULE_JSON_PATH, 'r', encoding='utf-8') as f:
                existing_rules = json.load(f)
        except: pass
                
    existing_patterns = {r.get('pattern') for r in existing_rules}
    new_rules = []
    added_count = 0
    
    for match in matches:
        proto, msg, content = match
        if content not in existing_patterns and len(content) > 5:
            new_rule = {
                "action": "DROP", 
                "dst_port": "any", 
                "name": f"[ET-PRO] {msg[:70]}", 
                "pattern": content,
                "protocol": proto.lower()
            }
            new_rules.append(new_rule)
            existing_patterns.add(content)
            added_count += 1
            if added_count >= 100: break
                
    if new_rules:
        existing_rules.extend(new_rules)
        os.makedirs(os.path.dirname(RULE_JSON_PATH), exist_ok=True)
        with open(RULE_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(existing_rules, f, indent=4, ensure_ascii=False)
        return True
    return True