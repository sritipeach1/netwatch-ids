"""Maps Suricata signature ids to a friendly attack type and a MITRE ATT&CK technique."""
from __future__ import annotations

# sid -> (attack_type, ATT&CK technique id)
SID_MAP: dict[int, tuple[str, str]] = {
    1000001: ("port_scan", "T1046"),
    1000002: ("ssh_brute_force", "T1110"),
    1000003: ("sql_injection", "T1190"),
    1000004: ("dns_tunneling", "T1071"),
    1000005: ("syn_flood", "T1498"),
}

ML_LABEL_MAP: dict[str, tuple[str, str]] = {
    "scan": ("port_scan", "T1046"),
    "bruteforce": ("ssh_brute_force", "T1110"),
    "flood": ("syn_flood", "T1498"),
}

ATTACK_LABELS = {
    "port_scan": "Port scan",
    "ssh_brute_force": "SSH brute force",
    "sql_injection": "SQL injection",
    "dns_tunneling": "DNS tunneling",
    "syn_flood": "SYN flood",
    "other": "Other",
}


def lookup_sid(sid: int) -> tuple[str, str]:
    return SID_MAP.get(sid, ("other", ""))


def lookup_ml(label: str) -> tuple[str, str]:
    return ML_LABEL_MAP.get(label, ("other", ""))
