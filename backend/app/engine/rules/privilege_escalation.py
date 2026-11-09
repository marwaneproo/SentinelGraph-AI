from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

SUSPICIOUS_COMMANDS = [
    "sudo su", "su root", "chmod 777", "chmod +s", "visudo", 
    "useradd", "usermod -aG sudo", "cat /etc/shadow", "curl | bash",
    "bash -i >& /dev/tcp"
]

def evaluate_privilege_escalation(
    recent_logs: List[Dict[str, Any]],
    threshold: int = 1,
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """
    Rule 4: Privilege Escalation
    Detects unauthorized elevation attempts, execution of administrative binaries by unprivileged users,
    or execution of risky privilege commands.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for log in recent_logs:
        event_type = str(log.get("event_type", "")).upper()
        msg = str(log.get("message", "")).lower()
        details = log.get("details") or {}
        cmd = str(details.get("command", "")).lower()

        is_priv_event = event_type in [
            "PRIVILEGE_ESCALATION", "SUDO_VIOLATION", "UNAUTHORIZED_ROOT", 
            "SUDO_ATTEMPT", "SU_ROOT"
        ]
        has_risky_cmd = any(c in msg or c in cmd for c in SUSPICIOUS_COMMANDS)

        if is_priv_event or has_risky_cmd:
            ts_val = log.get("timestamp")
            try:
                ts = (
                    datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                    if isinstance(ts_val, str)
                    else ts_val
                )
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                ts = now
            if ts and ts < cutoff:
                continue
            user = log.get("username", "unknown")
            srv = log.get("server_id", "unknown-srv")
            key = f"{user}_{srv}_{event_type}_{msg[:30]}"
            grouped.setdefault(key, []).append(log)

    for grouped_logs in grouped.values():
        if len(grouped_logs) < threshold:
            continue
        first_log = grouped_logs[0]
        user = first_log.get("username", "unknown")
        srv = first_log.get("server_id", "unknown-srv")
        event_type = str(first_log.get("event_type", "")).upper()
        evidence_ids = [
            str(log.get("_id", log.get("integrity_hash", "")))
            for log in grouped_logs
        ]
        alerts.append({
            "rule_id": "RULE-004-PRIV-ESC",
            "rule_name": "Privilege Escalation Attempt",
            "title": f"Privilege Escalation Detected: User '{user}' on {srv}",
            "severity": "CRITICAL",
            "description": (
                f"Detected {len(grouped_logs)} potential unauthorized privilege-elevation event(s) "
                f"for account '{user}' on {srv}. Event: {event_type}. "
                f"Message detail: '{first_log.get('message')}'."
            ),
            "source_ip": first_log.get("source_ip", ""),
            "target_user": user,
            "server_id": srv,
            "evidence_log_ids": evidence_ids,
            "recommended_action": (
                f"Review host {srv}, validate the user's authorization, preserve relevant evidence, "
                f"and audit privileged commands and account changes."
            ),
            "timestamp": now.isoformat()
        })

    return alerts
