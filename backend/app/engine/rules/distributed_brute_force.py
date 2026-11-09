from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Set

def evaluate_distributed_brute_force(
    recent_logs: List[Dict[str, Any]],
    ip_threshold: int = 3,
    window_seconds: int = 600
) -> List[Dict[str, Any]]:
    """
    Rule 5: Distributed Brute-Force Attacks (Password Spraying / Botnet Swarm)
    Detects when multiple distinct source IP addresses target the same user account or server.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    # user -> dict of {ip: [logs]}
    user_ip_map: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    for log in recent_logs:
        log_type = str(log.get("event_type", "")).upper()
        if log_type in ["AUTH_FAILED", "LOGIN_FAILED", "SSH_FAILED", "CREDENTIAL_REJECTED"]:
            user = log.get("username")
            ip = log.get("source_ip")
            if not user or not ip:
                continue

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
                user_ip_map.setdefault(user, {}).setdefault(ip, []).append(log)

    for user, ip_dict in user_ip_map.items():
        distinct_ips = list(ip_dict.keys())
        if len(distinct_ips) >= ip_threshold:
            all_logs = []
            for ip_logs in ip_dict.values():
                all_logs.extend(ip_logs)
            
            evidence_ids = [str(l.get("_id", l.get("integrity_hash", ""))) for l in all_logs]
            srv = all_logs[0].get("server_id", "Multiple Hosts")

            alerts.append({
                "rule_id": "RULE-005-DIST-BRUTEFORCE",
                "rule_name": "Distributed Brute-Force / Password Spraying",
                "title": f"Distributed Attack on user '{user}' from {len(distinct_ips)} distinct IPs",
                "severity": "CRITICAL",
                "description": (
                    f"Coordinated authentication attack detected: {len(distinct_ips)} distinct source IPs "
                    f"({', '.join(distinct_ips[:5])}...) executed password attempts against user '{user}' "
                    f"within {window_seconds}s."
                ),
                "source_ip": distinct_ips[0],
                "target_user": user,
                "server_id": srv,
                "evidence_log_ids": evidence_ids,
                "recommended_action": (
                    f"Deploy distributed botnet rate-limiting at ingress, mandate immediate password change "
                    f"and FIDO2/WebAuthn token for user '{user}', and review target access logs."
                ),
                "timestamp": now.isoformat()
            })

    return alerts
