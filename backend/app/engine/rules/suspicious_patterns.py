from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

def evaluate_suspicious_patterns(
    recent_logs: List[Dict[str, Any]],
    server_sweep_threshold: int = 3,
    probe_threshold: int = 5,
    window_seconds: int = 300
) -> List[Dict[str, Any]]:
    """
    Rule 6: Suspicious Access Patterns (Horizontal Reconnaissance & API Probing)
    Detects single IP scanning multiple backend hosts or triggering high volume of reconnaissance events.
    """
    alerts = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    # IP -> servers visited
    ip_servers: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    # IP -> probe/scan events
    ip_probes: Dict[str, List[Dict[str, Any]]] = {}

    for log in recent_logs:
        ip = log.get("source_ip")
        if not ip:
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
            srv = log.get("server_id")
            if srv:
                ip_servers.setdefault(ip, {}).setdefault(srv, []).append(log)

            event_type = str(log.get("event_type", "")).upper()
            if event_type in ["PORT_SCAN", "API_FUZZING", "DIR_SCAN", "RECON_PROBE", "ANOMALY"]:
                ip_probes.setdefault(ip, []).append(log)

    # Pattern A: Horizontal host scanning (same IP hitting multiple distinct servers rapidly)
    for ip, srv_map in ip_servers.items():
        if len(srv_map) >= server_sweep_threshold:
            all_logs = [l for sublist in srv_map.values() for l in sublist]
            evidence_ids = [str(l.get("_id", l.get("integrity_hash", ""))) for l in all_logs[:10]]
            servers_hit = list(srv_map.keys())

            alerts.append({
                "rule_id": "RULE-006-LATERAL-SCAN",
                "rule_name": "Suspicious Access Patterns (Horizontal Network Sweep)",
                "title": f"Lateral Scanning Detected from {ip} across {len(servers_hit)} servers",
                "severity": "HIGH",
                "description": (
                    f"Source IP {ip} systematically accessed or probed {len(servers_hit)} distinct "
                    f"infrastructure servers ({', '.join(servers_hit)}) within {window_seconds}s."
                ),
                "source_ip": ip,
                "target_user": all_logs[0].get("username"),
                "server_id": servers_hit[0],
                "evidence_log_ids": evidence_ids,
                "recommended_action": (
                    f"Isolate network segments between {servers_hit}, apply strict zero-trust ACLs, "
                    f"and drop all egress/ingress traffic from {ip}."
                ),
                "timestamp": now.isoformat()
            })

    # Pattern B: Explicit reconnaissance probing
    for ip, probe_logs in ip_probes.items():
        if len(probe_logs) >= probe_threshold:
            evidence_ids = [str(l.get("_id", l.get("integrity_hash", ""))) for l in probe_logs]
            srv = probe_logs[0].get("server_id", "Multiple Hosts")

            alerts.append({
                "rule_id": "RULE-006-RECON-PROBE",
                "rule_name": "Suspicious Access Patterns (Reconnaissance Probe)",
                "title": f"Active Reconnaissance / Port Scanning from {ip}",
                "severity": "HIGH",
                "description": (
                    f"Source IP {ip} triggered {len(probe_logs)} reconnaissance security events "
                    f"(port scans, API fuzzing, or directory enumeration) on {srv}."
                ),
                "source_ip": ip,
                "target_user": probe_logs[0].get("username"),
                "server_id": srv,
                "evidence_log_ids": evidence_ids,
                "recommended_action": (
                    f"Blacklist IP {ip} at edge gateway and inspect web server access logs for zero-day CVE probing."
                ),
                "timestamp": now.isoformat()
            })

    return alerts
