import os
from datetime import datetime, timedelta, timezone
from backend.app.db.mongodb import mongo_manager
from backend.app.core.security import hash_password
from backend.app.core.logging import siem_logger
from backend.app.services.log_service import log_service
from backend.app.engine.detector import threat_detector

DEFAULT_USERS = [
    {
        "username": "admin",
        "email": "admin@sentinelgraph.io",
        "full_name": "Chief Information Security Officer (Admin)",
        "password_env": "SEED_ADMIN_PASSWORD",
        "role": "Administrator",
        "is_active": True
    },
    {
        "username": "analyst",
        "email": "analyst@sentinelgraph.io",
        "full_name": "Tier-2 SOC Security Analyst",
        "password_env": "SEED_ANALYST_PASSWORD",
        "role": "Security Analyst",
        "is_active": True
    },
    {
        "username": "viewer",
        "email": "viewer@sentinelgraph.io",
        "full_name": "Compliance & Audit Viewer",
        "password_env": "SEED_VIEWER_PASSWORD",
        "role": "Viewer",
        "is_active": True
    }
]

DEFAULT_SERVERS = [
    {
        "server_id": "SRV-PROD-AUTH-01",
        "hostname": "auth.corp.internal",
        "ip_address": "10.0.1.10",
        "os_type": "Ubuntu 24.04 LTS",
        "role": "Central Authentication & OAuth Gateway",
        "criticality": "CRITICAL",
        "status": "ACTIVE",
        "description": "Primary identity server hosting SSO and OpenID provider."
    },
    {
        "server_id": "SRV-PROD-APP-02",
        "hostname": "api.corp.internal",
        "ip_address": "10.0.1.20",
        "os_type": "Debian 12 Bookworm",
        "role": "Production REST API Cluster",
        "criticality": "HIGH",
        "status": "ACTIVE",
        "description": "Public-facing customer portal and microservices API."
    },
    {
        "server_id": "SRV-FINANCE-DB-03",
        "hostname": "db-fin.corp.internal",
        "ip_address": "10.0.2.15",
        "os_type": "RHEL 9.3",
        "role": "PostgreSQL Financial Ledger Database",
        "criticality": "CRITICAL",
        "status": "ACTIVE",
        "description": "Stores sensitive general ledger and transactional records."
    },
    {
        "server_id": "SRV-EDGE-GATEWAY-04",
        "hostname": "gw-external.corp.internal",
        "ip_address": "10.0.0.1",
        "os_type": "Alpine Linux 3.20",
        "role": "Perimeter Ingress & Reverse Proxy",
        "criticality": "HIGH",
        "status": "ACTIVE",
        "description": "Handles TLS termination and ingress traffic filtering."
    },
    {
        "server_id": "SRV-PAYMENTS-05",
        "hostname": "pay-vault.corp.internal",
        "ip_address": "10.0.3.50",
        "os_type": "Hardened Linux 6.6",
        "role": "PCI-DSS Payment Tokenization Vault",
        "criticality": "CRITICAL",
        "status": "ACTIVE",
        "description": "Cardholder data environment with strict access control."
    }
]

DEFAULT_RULES = [
    {
        "rule_id": "RULE-001-BRUTEFORCE",
        "name": "Brute-force Login Attempts",
        "description": "Detects repeated failed authentication attempts (>=5 within 5 minutes) from a single IP.",
        "severity": "HIGH",
        "enabled": True,
        "mitre_attack_id": "T1110.001",
        "threshold": 5,
        "window_seconds": 300,
        "recommended_action": "Temporarily block IP via perimeter firewall and enforce MFA / account lockout."
    },
    {
        "rule_id": "RULE-002-UNUSUAL-IP",
        "name": "Suspicious Login from Unusual / Malicious IP",
        "description": "Detects successful or administrative access originating from threat intel or Tor exit nodes.",
        "severity": "CRITICAL",
        "enabled": True,
        "mitre_attack_id": "T1078",
        "threshold": 1,
        "window_seconds": 3600,
        "recommended_action": "Verify user location out-of-band, terminate active sessions, and rotate user credentials."
    },
    {
        "rule_id": "RULE-003-OFF-HOURS",
        "name": "Login Outside Normal Working Hours",
        "description": "Detects privileged access occurring during off-hours (22:00-06:00 UTC or weekends).",
        "severity": "MEDIUM",
        "enabled": True,
        "mitre_attack_id": "T1078.003",
        "threshold": 1,
        "window_seconds": 3600,
        "recommended_action": "Review change management tickets and corroborate authorization with system owners."
    },
    {
        "rule_id": "RULE-004-PRIV-ESC",
        "name": "Privilege Escalation Attempt",
        "description": "Detects unauthorized sudo executions, root switching, or sudoers file tampering.",
        "severity": "CRITICAL",
        "enabled": True,
        "mitre_attack_id": "T1548.003",
        "threshold": 1,
        "window_seconds": 300,
        "recommended_action": "Isolate compromised host, freeze user session, and audit auditd execution logs."
    },
    {
        "rule_id": "RULE-005-DIST-BRUTEFORCE",
        "name": "Distributed Brute-force / Password Spraying",
        "description": "Detects coordinated credential attacks from multiple distinct IPs (>=3) against the same account.",
        "severity": "CRITICAL",
        "enabled": True,
        "mitre_attack_id": "T1110.003",
        "threshold": 3,
        "window_seconds": 600,
        "recommended_action": "Deploy WAF bot mitigation, mandate immediate password reset, and enable hardware token MFA."
    },
    {
        "rule_id": "RULE-006-LATERAL-SCAN",
        "name": "Suspicious Access Patterns (Horizontal Network Sweep)",
        "description": "Detects single source IP sweeping multiple internal servers or executing port scans.",
        "severity": "HIGH",
        "enabled": True,
        "mitre_attack_id": "T1046",
        "threshold": 3,
        "window_seconds": 300,
        "recommended_action": "Isolate source IP at internal firewall and review lateral movement telemetry."
    }
]

async def seed_all(force: bool = False):
    """Initializes collections, seeds default users, servers, detection rules, and initial logs."""
    siem_logger.info("Checking database initialization...")
    users_col = mongo_manager.get_collection("users")
    user_count = await users_col.count_documents({})
    
    if user_count == 0 or force:
        siem_logger.info("Seeding initial users...")
        for u in DEFAULT_USERS:
            doc = dict(u)
            password_env = doc.pop("password_env")
            password = os.getenv(password_env)
            if not password:
                raise RuntimeError(
                    f"{password_env} must be set before initial users can be seeded."
                )
            doc["password_hash"] = hash_password(password)
            doc["created_at"] = datetime.now(timezone.utc).isoformat()
            await users_col.insert_one(doc)
        siem_logger.info(f"Seeded {len(DEFAULT_USERS)} default users.")

    servers_col = mongo_manager.get_collection("servers")
    srv_count = await servers_col.count_documents({})
    if srv_count == 0 or force:
        siem_logger.info("Seeding default servers...")
        for s in DEFAULT_SERVERS:
            doc = dict(s)
            doc["created_at"] = datetime.now(timezone.utc).isoformat()
            doc["last_heartbeat"] = datetime.now(timezone.utc).isoformat()
            await servers_col.insert_one(doc)
        siem_logger.info(f"Seeded {len(DEFAULT_SERVERS)} monitored servers.")

    rules_col = mongo_manager.get_collection("detection_rules")
    rules_count = await rules_col.count_documents({})
    if rules_count == 0 or force:
        siem_logger.info("Seeding detection rules...")
        for r in DEFAULT_RULES:
            doc = dict(r)
            doc["created_at"] = datetime.now(timezone.utc).isoformat()
            doc["trigger_count"] = 0
            doc["last_triggered"] = None
            await rules_col.insert_one(doc)
        siem_logger.info(f"Seeded {len(DEFAULT_RULES)} threat detection rules.")

    # Seed sample security logs if empty
    logs_col = mongo_manager.get_collection("logs")
    logs_count = await logs_col.count_documents({})
    if logs_count == 0 or force:
        siem_logger.info("Generating realistic initial security telemetry logs...")
        now = datetime.now(timezone.utc)
        
        sample_logs = []
        
        # 1. Benign background logs
        for i in range(15):
            ts = (now - timedelta(minutes=45 - i*2)).isoformat()
            sample_logs.append({
                "timestamp": ts,
                "server_id": "SRV-PROD-APP-02",
                "server_name": "api.corp.internal",
                "source_ip": "192.168.1.88",
                "event_type": "AUTH_SUCCESS",
                "severity": "INFO",
                "username": "bob.developer",
                "message": f"User 'bob.developer' authenticated to REST API via JWT session id #{100+i}",
                "details": {"client": "curl/8.1", "auth_realm": "api_v1"}
            })

        # 2. Brute force scenario logs
        for i in range(6):
            ts = (now - timedelta(seconds=120 - i*10)).isoformat()
            sample_logs.append({
                "timestamp": ts,
                "server_id": "SRV-PROD-AUTH-01",
                "server_name": "auth.corp.internal",
                "source_ip": "198.51.100.42",
                "event_type": "AUTH_FAILED",
                "severity": "HIGH",
                "username": "admin",
                "message": f"sshd[442{i}]: Failed password for invalid user admin from 198.51.100.42 port 489{i} ssh2",
                "details": {"attempt": i+1, "method": "password", "port": 22}
            })

        # 3. Tor exit node login
        sample_logs.append({
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "server_id": "SRV-EDGE-GATEWAY-04",
            "server_name": "gw-external.corp.internal",
            "source_ip": "185.220.101.5",
            "event_type": "AUTH_SUCCESS",
            "severity": "HIGH",
            "username": "root",
            "message": "Accepted publickey for root from 185.220.101.5 port 55432 ssh2: RSA SHA256:7v8Yx9P...",
            "details": {"threat_intel": "Tor Exit Node", "country": "DE"}
        })

        # 4. Privilege escalation log
        sample_logs.append({
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "server_id": "SRV-FINANCE-DB-03",
            "server_name": "db-fin.corp.internal",
            "source_ip": "192.168.1.144",
            "event_type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "username": "bob.developer",
            "message": "bob.developer : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
            "details": {"command": "sudo su", "uid": 1002}
        })

        # 5. Distributed brute force logs
        dist_ips = ["45.142.195.12", "194.26.29.112", "91.240.118.172"]
        for idx, ip in enumerate(dist_ips):
            sample_logs.append({
                "timestamp": (now - timedelta(minutes=3, seconds=idx*15)).isoformat(),
                "server_id": "SRV-PROD-AUTH-01",
                "server_name": "auth.corp.internal",
                "source_ip": ip,
                "event_type": "AUTH_FAILED",
                "severity": "HIGH",
                "username": "devops-svc",
                "message": f"Password spray attempt against service account 'devops-svc' from remote bot {ip}",
                "details": {"botnet": True, "target": "devops-svc"}
            })

        # 6. Lateral scanning across servers
        for srv in DEFAULT_SERVERS[:3]:
            sample_logs.append({
                "timestamp": (now - timedelta(minutes=2)).isoformat(),
                "server_id": srv["server_id"],
                "server_name": srv["hostname"],
                "source_ip": "194.26.29.112",
                "event_type": "PORT_SCAN",
                "severity": "HIGH",
                "username": None,
                "message": f"High rate SYN probe detected on ports 22, 443, 5432 from {194.26}.29.112",
                "details": {"scanner": "masscan", "target_ip": srv["ip_address"]}
            })

        # Ingest all
        for sl in sample_logs:
            await log_service.ingest_log(sl)
            
        siem_logger.info(f"Ingested {len(sample_logs)} seed security logs.")

        # Run threat detector to generate initial alerts and graph entities
        await threat_detector.run_detection_pipeline()
        siem_logger.info("Threat Detection Pipeline executed on seed data.")
