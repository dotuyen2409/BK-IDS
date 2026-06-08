"""
BK-IDS SOC: MITRE ATT&CK Mapping Module
=========================================
Maps detected attack types to MITRE ATT&CK framework techniques.
Provides structured mapping for both anomaly-based and signature-based detections.
"""

from enum import Enum
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger("Bk-IDS-MitreMapper")


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise)"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# ========================================================================
# MITRE ATT&CK TECHNIQUE MAPPING DICTIONARY
# ========================================================================
ATTACK_TYPE_TO_MITRE: Dict[str, Dict[str, str]] = {
    # --- Denial of Service ---
    "SYN FLOOD": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "TCP FLOOD": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "UDP FLOOD": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "ICMP PING FLOOD": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "SPOOFED SYN FLOOD (RAND-SOURCE)": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "SPOOFED TCP FLOOD (RAND-SOURCE)": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "SPOOFED UDP FLOOD (RAND-SOURCE)": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },
    "DoS": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "DDoS Botnet": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.001",
        "subtechnique_name": "Direct Network Flood",
    },

    # --- Network Scanning / Reconnaissance ---
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": MitreTactic.DISCOVERY.value,
        "tactic_name": "Discovery",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "NETWORK_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": MitreTactic.DISCOVERY.value,
        "tactic_name": "Discovery",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "IP_SWEEP": {
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "tactic": MitreTactic.DISCOVERY.value,
        "tactic_name": "Discovery",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },

    # --- Web Application Attacks ---
    "SQL_INJECTION": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": MitreTactic.INITIAL_ACCESS.value,
        "tactic_name": "Initial Access",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "XSS": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": MitreTactic.INITIAL_ACCESS.value,
        "tactic_name": "Initial Access",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "COMMAND_INJECTION": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": MitreTactic.EXECUTION.value,
        "tactic_name": "Execution",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
    "PATH_TRAVERSAL": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": MitreTactic.DISCOVERY.value,
        "tactic_name": "Discovery",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },

    # --- Brute Force ---
    "BRUTE_FORCE_SSH": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": MitreTactic.CREDENTIAL_ACCESS.value,
        "tactic_name": "Credential Access",
        "subtechnique_id": "T1110.001",
        "subtechnique_name": "Password Guessing",
    },
    "BRUTE_FORCE_FTP": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": MitreTactic.CREDENTIAL_ACCESS.value,
        "tactic_name": "Credential Access",
        "subtechnique_id": "T1110.001",
        "subtechnique_name": "Password Guessing",
    },
    "BRUTE_FORCE_HTTP": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": MitreTactic.CREDENTIAL_ACCESS.value,
        "tactic_name": "Credential Access",
        "subtechnique_id": "T1110.001",
        "subtechnique_name": "Password Guessing",
    },

    # --- Malware / C2 ---
    "MALWARE_COMMUNICATION": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": MitreTactic.COMMAND_AND_CONTROL.value,
        "tactic_name": "Command and Control",
        "subtechnique_id": "T1071.001",
        "subtechnique_name": "Web Protocols",
    },
    "C2_BEACON": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": MitreTactic.COMMAND_AND_CONTROL.value,
        "tactic_name": "Command and Control",
        "subtechnique_id": "T1071.001",
        "subtechnique_name": "Web Protocols",
    },
    "CRYPTOMINER": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },

    # --- DNS Attacks ---
    "DNS_TUNNELING": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": MitreTactic.COMMAND_AND_CONTROL.value,
        "tactic_name": "Command and Control",
        "subtechnique_id": "T1071.004",
        "subtechnique_name": "DNS",
    },
    "DNS_AMPLIFICATION": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT.value,
        "tactic_name": "Impact",
        "subtechnique_id": "T1498.002",
        "subtechnique_name": "Reflection Amplification",
    },

    # --- ARP / Layer 2 ---
    "ARP_SPOOFING": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": MitreTactic.CREDENTIAL_ACCESS.value,
        "tactic_name": "Credential Access",
        "subtechnique_id": "T1557.001",
        "subtechnique_name": "LLMNR/NBT-NS Poisoning and SMB Relay",
    },
    "MAN_IN_THE_MIDDLE": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": MitreTactic.CREDENTIAL_ACCESS.value,
        "tactic_name": "Credential Access",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },

    # --- Data Exfiltration ---
    "DATA_EXFILTRATION": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": MitreTactic.EXFILTRATION.value,
        "tactic_name": "Exfiltration",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },

    # --- Default / Unknown ---
    "UNKNOWN": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": MitreTactic.COMMAND_AND_CONTROL.value,
        "tactic_name": "Command and Control",
        "subtechnique_id": "",
        "subtechnique_name": "",
    },
}


def map_attack_to_mitre(attack_type: str) -> Dict[str, Any]:
    """
    Map a detected attack type string to MITRE ATT&CK technique.

    Args:
        attack_type: The attack type string (e.g., "SYN FLOOD", "SQL_INJECTION")

    Returns:
        Dictionary containing MITRE ATT&CK mapping fields.
        Falls back to UNKNOWN mapping if attack_type not found.
    """
    if not attack_type:
        return ATTACK_TYPE_TO_MITRE["UNKNOWN"].copy()

    # Normalize: uppercase, strip whitespace
    normalized = attack_type.upper().strip()

    # Direct match
    if normalized in ATTACK_TYPE_TO_MITRE:
        return ATTACK_TYPE_TO_MITRE[normalized].copy()

    # Partial/fuzzy match: check if any key is a substring of the attack type
    for key, mapping in ATTACK_TYPE_TO_MITRE.items():
        if key != "UNKNOWN" and key in normalized:
            return mapping.copy()

    # Fallback: try to infer from keywords
    if "SYN" in normalized or "FLOOD" in normalized or "DOS" in normalized or "DDOS" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("SYN FLOOD", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "SCAN" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("PORT_SCAN", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "SQL" in normalized or "INJECTION" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("SQL_INJECTION", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "BRUTE" in normalized or "FORCE" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("BRUTE_FORCE_SSH", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "MALWARE" in normalized or "C2" in normalized or "BEACON" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("MALWARE_COMMUNICATION", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "DNS" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("DNS_TUNNELING", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()
    if "ARP" in normalized or "SPOOF" in normalized:
        return ATTACK_TYPE_TO_MITRE.get("ARP_SPOOFING", ATTACK_TYPE_TO_MITRE["UNKNOWN"]).copy()

    logger.warning(f"[MITRE] No mapping found for attack_type='{attack_type}', using UNKNOWN")
    return ATTACK_TYPE_TO_MITRE["UNKNOWN"].copy()


def enrich_alert_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert dictionary with MITRE ATT&CK fields.

    Adds the following fields to the alert dict:
        - mitre_technique_id
        - mitre_technique_name
        - mitre_tactic
        - mitre_tactic_name
        - mitre_subtechnique_id (if applicable)
        - mitre_subtechnique_name (if applicable)

    Args:
        alert: Alert dictionary containing at least an 'attack_type' or 'sig_name' field.

    Returns:
        Enriched alert dictionary.
    """
    attack_type = alert.get("attack_type") or alert.get("sig_name") or "UNKNOWN"
    mitre_mapping = map_attack_to_mitre(attack_type)

    alert["mitre_technique_id"] = mitre_mapping["technique_id"]
    alert["mitre_technique_name"] = mitre_mapping["technique_name"]
    alert["mitre_tactic"] = mitre_mapping["tactic"]
    alert["mitre_tactic_name"] = mitre_mapping["tactic_name"]

    if mitre_mapping.get("subtechnique_id"):
        alert["mitre_subtechnique_id"] = mitre_mapping["subtechnique_id"]
        alert["mitre_subtechnique_name"] = mitre_mapping["subtechnique_name"]

    return alert
