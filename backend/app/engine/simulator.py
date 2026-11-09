from datetime import datetime, timezone
import random
import uuid
from typing import List, Dict, Any

from backend.app.services.log_service import log_service
from backend.app.engine.detector import threat_detector
from backend.app.core.logging import siem_logger

SERVERS = [
    {"id": "SRV-PROD-AUTH-01", "name": "auth.corp.internal", "ip": "10.0.1.10"},
    {"id": "SRV-PROD-APP-02", "name": "api.corp.internal", "ip": "10.0.1.20"},
    {"id": "SRV-FINANCE-DB-03", "name": "db-fin.corp.internal", "ip": "10.0.2.15"},
    {"id": "SRV-EDGE-GATEWAY-04", "name": "gw-external.corp.internal", "ip": "10.0.0.1"},
    {"id": "SRV-PAYMENTS-05", "name": "pay-vault.corp.internal", "ip": "10.0.3.50"}
]

USERS = ["admin", "alice.security", "bob.developer", "clara.fin", "root", "devops-svc", "support"]

BENIGN_IPS = ["192.168.1.45", "192.168.1.88", "10.10.20.101", "10.10.20.105", "172.16.5.12"]
MALICIOUS_IPS = ["185.220.101.5", "45.142.195.12", "194.26.29.112", "91.240.118.172", "198.51.100.99"]

async def generate_simulated_attack(attack_type: str) -> Dict[str, Any]:
    """
    Simulates specific attack patterns or benign traffic and runs detection.
    """
    now = datetime.now(timezone.utc)
    target_server = random.choice(SERVERS)
    target_user = random.choice(USERS)
    logs_to_ingest = []

    if attack_type == "brute_force":
        attacker_ip = "198.51.100.42"
        for i in range(6):
            logs_to_ingest.append({
                "timestamp": now.isoformat(),
                "server_id": target_server["id"],
                "server_name": target_server["name"],
                "source_ip": attacker_ip,
                "event_type": "AUTH_FAILED",
                "severity": "HIGH",
                "username": target_user,
                "message": f"Failed password attempt {i+1}/6 for user '{target_user}' from {attacker_ip} via sshd[222{i}]",
                "details": {"attempt": i+1, "protocol": "SSH-2.0", "port": 22}
            })

    elif attack_type == "unusual_ip":
        attacker_ip = "185.220.101.5" # Tor exit node
        logs_to_ingest.append({
            "timestamp": now.isoformat(),
            "server_id": target_server["id"],
            "server_name": target_server["name"],
            "source_ip": attacker_ip,
            "event_type": "AUTH_SUCCESS",
            "severity": "HIGH",
            "username": "admin",
            "message": f"Administrative login accepted from Tor exit node {attacker_ip} for account 'admin'",
            "details": {"client_version": "OpenSSH_8.9", "mfa_bypassed": False}
        })

    elif attack_type == "privilege_escalation":
        attacker_ip = "192.168.1.144"
        logs_to_ingest.append({
            "timestamp": now.isoformat(),
            "server_id": "SRV-FINANCE-DB-03",
            "server_name": "db-fin.corp.internal",
            "source_ip": attacker_ip,
            "event_type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "username": "bob.developer",
            "message": "User 'bob.developer' executed unauthorized 'sudo su root' via /usr/bin/sudo; command not in sudoers",
            "details": {"command": "sudo su", "uid": 1002, "gid": 1002, "tty": "/dev/pts/3"}
        })

    elif attack_type == "distributed_brute_force":
        dist_ips = ["45.142.195.12", "194.26.29.112", "91.240.118.172", "185.220.101.88"]
        target = "admin"
        for ip in dist_ips:
            logs_to_ingest.append({
                "timestamp": now.isoformat(),
                "server_id": target_server["id"],
                "server_name": target_server["name"],
                "source_ip": ip,
                "event_type": "AUTH_FAILED",
                "severity": "HIGH",
                "username": target,
                "message": f"Coordinated password guess attempt against '{target}' from bot IP {ip}",
                "details": {"botnet_agent": "Mirai-variant", "port": 443}
            })

    elif attack_type == "suspicious_patterns":
        scanner_ip = "194.26.29.112"
        # Hit 4 distinct servers
        for srv in SERVERS[:4]:
            logs_to_ingest.append({
                "timestamp": now.isoformat(),
                "server_id": srv["id"],
                "server_name": srv["name"],
                "source_ip": scanner_ip,
                "event_type": "PORT_SCAN",
                "severity": "HIGH",
                "username": None,
                "message": f"SYN stealth probe on ports 22, 80, 443, 3306, 5432 on {srv['name']} from {scanner_ip}",
                "details": {"scanner": "Nmap NSE", "flags": "SYN", "target_ip": srv["ip"]}
            })

    elif attack_type == "off_hours":
        # Simulate log at 03:22 AM
        night_time = now.replace(hour=3, minute=22)
        logs_to_ingest.append({
            "timestamp": night_time.isoformat(),
            "server_id": "SRV-FINANCE-DB-03",
            "server_name": "db-fin.corp.internal",
            "source_ip": "192.168.1.99",
            "event_type": "AUTH_SUCCESS",
            "severity": "MEDIUM",
            "username": "clara.fin",
            "message": f"Off-hours database access session established for user 'clara.fin' at 03:22 UTC",
            "details": {"session_type": "pgAdmin_SSL", "database": "finance_prod"}
        })

    else:
        # Benign traffic
        for _ in range(3):
            benign_ip = random.choice(BENIGN_IPS)
            user = random.choice(USERS)
            srv = random.choice(SERVERS)
            logs_to_ingest.append({
                "timestamp": now.isoformat(),
                "server_id": srv["id"],
                "server_name": srv["name"],
                "source_ip": benign_ip,
                "event_type": "AUTH_SUCCESS",
                "severity": "INFO",
                "username": user,
                "message": f"User '{user}' successfully authenticated to {srv['name']} via SSO/OIDC",
                "details": {"auth_method": "SSO", "token_valid": True}
            })

    # Ingest logs
    ingested_logs = []
    for l in logs_to_ingest:
        doc = await log_service.ingest_log(l)
        ingested_logs.append(doc)

    # Run detection pipeline
    triggered_alerts = await threat_detector.run_detection_pipeline(custom_logs=ingested_logs)

    siem_logger.info(f"Simulator executed '{attack_type}': {len(ingested_logs)} logs ingested, {len(triggered_alerts)} alerts raised.")
    return {
        "attack_type": attack_type,
        "logs_generated": len(ingested_logs),
        "alerts_triggered": len(triggered_alerts),
        "alerts": triggered_alerts
    }
