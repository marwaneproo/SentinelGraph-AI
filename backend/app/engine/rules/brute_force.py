from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

def evaluate_brute_force(
    recent_logs: List[Dict[str, Any]],
    threshold: int = 5,
    window_seconds: int = 300
) -> List[Dict[str, Any]]:
    """
    Rule 1: Brute-Force Login Attempts
    Detects repeated failed authentication attempts from the same source IP or targeting the same user.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    # Group failed auth logs by (source_ip, username)
    failed_attempts: Dict[str, List[Dict[str, Any]]] = {}

    for log in recent_logs:
        log_type = str(log.get("event_type", "")).upper()
        if log_type in ["AUTH_FAILED", "LOGIN_FAILED", "FAILED_LOGIN", "SSH_FAILED"]:
            ts_str = log.get("timestamp")
            if isinstance(ts_str, str):
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    ts = now
            elif isinstance(ts_str, datetime):
                ts = ts_str if ts_str.tzinfo else ts_str.replace(tzinfo=timezone.utc)
            else:
                ts = now

            if ts >= cutoff:
                key = f"{log.get('source_ip')}_{log.get('username')}"
                failed_attempts.setdefault(key, []).append(log)

    for key, logs in failed_attempts.items():
        if len(logs) >= threshold:
            first_log = logs[0]
            ip = first_log.get("source_ip", "Unknown IP")
            user = first_log.get("username", "Unknown User")
            srv = first_log.get("server_id", "Unknown Server")
            evidence_ids = [str(l.get("_id", l.get("integrity_hash", ""))) for l in logs]

            alerts.append({
                "rule_id": "RULE-001-BRUTEFORCE",
                "rule_name": "Brute-Force Login Attempts",
                "title": f"Brute-Force Detected: {len(logs)} failed attempts from {ip} against user '{user}'",
                "severity": "HIGH",
                "description": (
                    f"Threshold breached: {len(logs)} consecutive failed login events detected "
                    f"within {window_seconds}s for target '{user}' from source IP {ip} on server {srv}."
                ),
                "source_ip": ip,
                "target_user": user,
                "server_id": srv,
                "evidence_log_ids": evidence_ids,
                "recommended_action": (
                    f"Block source IP {ip} at perimeter firewall, enforce immediate account MFA, "
                    f"and verify account '{user}' for credential stuffing exposure."
                ),
                "timestamp": now.isoformat()
            })

    return alerts
