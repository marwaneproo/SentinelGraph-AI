from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

def evaluate_off_hours(
    recent_logs: List[Dict[str, Any]],
    work_start_hour: int = 7,
    work_end_hour: int = 19,
    threshold: int = 1,
    window_seconds: int = 0,
) -> List[Dict[str, Any]]:
    """
    Rule 3: Login Outside Normal Working Hours
    Detects successful logins or privileged sessions occurring during night hours or weekends.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds) if window_seconds > 0 else None
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for log in recent_logs:
        event_type = str(log.get("event_type", "")).upper()
        if event_type in ["AUTH_SUCCESS", "LOGIN_SUCCESS", "SSH_LOGIN", "ADMIN_ACCESS"]:
            ts_val = log.get("timestamp")
            if isinstance(ts_val, str):
                try:
                    ts = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                except Exception:
                    ts = now
            elif isinstance(ts_val, datetime):
                ts = ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
            else:
                ts = now

            if cutoff and ts < cutoff:
                continue

            # Check if weekend (5=Saturday, 6=Sunday) or outside working hours
            is_weekend = ts.weekday() >= 5
            is_night = (ts.hour < work_start_hour or ts.hour >= work_end_hour)

            if is_weekend or is_night:
                user = log.get("username", "Unknown")
                srv = log.get("server_id", "Unknown Server")
                key = f"{user}_{srv}_{ts.hour}_{ts.weekday()}"
                grouped.setdefault(key, []).append(log)

    for grouped_logs in grouped.values():
        if len(grouped_logs) < threshold:
            continue
        first_log = grouped_logs[0]
        ts_val = first_log.get("timestamp")
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
        is_weekend = ts.weekday() >= 5
        timing_desc = "Weekend access" if is_weekend else f"Off-hours access at {ts.strftime('%H:%M:%S UTC')}"
        evidence_ids = [
            str(log.get("_id", log.get("integrity_hash", "")))
            for log in grouped_logs
        ]
        user = first_log.get("username", "Unknown")
        srv = first_log.get("server_id", "Unknown Server")

        alerts.append({
            "rule_id": "RULE-003-OFF-HOURS",
            "rule_name": "Login Outside Normal Working Hours",
            "title": f"Off-Hours Access Detected: User '{user}' on {srv}",
            "severity": "MEDIUM",
            "description": (
                f"{len(grouped_logs)} authentication event(s) for '{user}' on {srv} "
                f"occurred outside standard business hours ({timing_desc})."
            ),
            "source_ip": first_log.get("source_ip", ""),
            "target_user": user,
            "server_id": srv,
            "evidence_log_ids": evidence_ids,
            "recommended_action": (
                f"Corroborate after-hours activity with user '{user}' or ticket management system. "
                f"Verify multi-factor authentication was satisfied."
            ),
            "timestamp": now.isoformat()
        })

    return alerts
