from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

KNOWN_SUSPICIOUS_IPS = {
    "185.220.101.5": "Known Tor Exit Node / Cyber Threat Intel Feed",
    "45.142.195.12": "Identified Bulletproof Hosting Scanner",
    "194.26.29.112": "C2 Infrastructure Indicator",
    "198.51.100.99": "Blacklisted Rogue Scanner",
    "91.240.118.172": "Active Exploitation Botnet"
}

def evaluate_unusual_ip(
    recent_logs: List[Dict[str, Any]],
    threshold: int = 1,
    window_seconds: int = 3600
) -> List[Dict[str, Any]]:
    """
    Rule 2: Suspicious Login from Unusual / Malicious IP Addresses
    Detects activity originating from known adversarial infrastructure or foreign non-whitelisted IPs.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for log in recent_logs:
        src_ip = log.get("source_ip", "")
        event_type = str(log.get("event_type", "")).upper()
        # Flag if in threat intelligence blacklist or external anomaly
        is_threat_feed = src_ip in KNOWN_SUSPICIOUS_IPS
        is_external_anomaly = (
            not src_ip.startswith("10.") and 
            not src_ip.startswith("192.168.") and 
            not src_ip.startswith("172.16.") and 
            not src_ip.startswith("127.") and
            event_type in ["AUTH_SUCCESS", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION", "ADMIN_ACCESS"]
        )

        if is_threat_feed or is_external_anomaly:
            timestamp = log.get("timestamp")
            try:
                parsed_time = (
                    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    if isinstance(timestamp, str)
                    else timestamp
                )
                if parsed_time and parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                parsed_time = now
            if parsed_time and parsed_time < cutoff:
                continue

            user = log.get("username", "system")
            key = f"{src_ip}_{user}_{event_type}"
            grouped.setdefault(key, []).append(log)

    for grouped_logs in grouped.values():
        if len(grouped_logs) < threshold:
            continue
        first_log = grouped_logs[0]
        src_ip = first_log.get("source_ip", "")
        user = first_log.get("username", "system")
        event_type = str(first_log.get("event_type", "")).upper()
        srv = first_log.get("server_id", "Unknown Server")
        reason = KNOWN_SUSPICIOUS_IPS.get(
            src_ip, "Unusual External IP authenticating to internal resource"
        )
        severity = "CRITICAL" if src_ip in KNOWN_SUSPICIOUS_IPS else "HIGH"
        evidence_ids = [
            str(log.get("_id", log.get("integrity_hash", "")))
            for log in grouped_logs
        ]

        alerts.append({
            "rule_id": "RULE-002-UNUSUAL-IP",
            "rule_name": "Suspicious Login from Unusual/Malicious IP",
            "title": f"Suspicious Activity from {src_ip} ({reason})",
            "severity": severity,
            "description": (
                f"{len(grouped_logs)} event(s) from untrusted IP {src_ip} targeted "
                f"user '{user}' on server {srv}. Event type: {event_type}. Context: {reason}."
            ),
            "source_ip": src_ip,
            "target_user": user,
            "server_id": srv,
            "evidence_log_ids": evidence_ids,
            "recommended_action": (
                f"Review the session for '{user}', revoke affected credentials if compromise is confirmed, "
                f"and assess whether {src_ip} should be blocked at the network perimeter."
            ),
            "timestamp": now.isoformat()
        })

    return alerts
