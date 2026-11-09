import asyncio
import os
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TESTING"] = "1"
os.environ.setdefault("SEED_ADMIN_PASSWORD", "AdminSentinel@2026!")
os.environ.setdefault("SEED_ANALYST_PASSWORD", "AnalystSentinel@2026!")
os.environ.setdefault("SEED_VIEWER_PASSWORD", "ViewerSentinel@2026!")

from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.db.seed_data import seed_all
from backend.app.services.log_service import log_service
from backend.app.services.alert_service import alert_service
from backend.app.services.graph_service import graph_service
from backend.app.services.ai_service import ai_service
from backend.app.engine.detector import threat_detector
from backend.app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from backend.app.core.integrity import compute_log_hash, verify_log_integrity

async def run_diagnostics():
    print("=" * 60)
    print("SENTINELGRAPH-AI SYSTEM VERIFICATION HARNESS")
    print("=" * 60)

    # 1. DB Initialization
    print("[1/8] Initializing Database Connections (Test Mode)...")
    await mongo_manager.connect()
    await neo4j_manager.connect()
    print(" -> MongoDB in_memory:", mongo_manager._in_memory)
    print(" -> Neo4j in_memory:", neo4j_manager._in_memory)

    # 2. Security & Auth Cryptography
    print("\n[2/8] Testing Password Hashing & JWT...")
    pwd = "AdminSentinel@2026!"
    hashed = hash_password(pwd)
    assert verify_password(pwd, hashed), "Password verification failed!"
    assert not verify_password("WrongPwd", hashed), "Invalid password accepted!"
    token = create_access_token({"sub": "admin", "role": "Administrator"})
    payload = decode_access_token(token)
    assert payload["sub"] == "admin"
    assert payload["role"] == "Administrator"
    print(" -> Password hashing (bcrypt) and JWT encode/decode verified.")

    # 3. Log Integrity (SHA-256)
    print("\n[3/8] Testing SHA-256 Log Integrity & Tamper Detection...")
    log_doc = {
        "timestamp": "2026-11-08T15:00:00+00:00",
        "server_id": "SRV-PROD-APP-02",
        "source_ip": "192.168.1.100",
        "event_type": "AUTH_SUCCESS",
        "severity": "INFO",
        "username": "alice.security",
        "details": {"client": "curl/8.1"}
    }
    ingested = await log_service.ingest_log(log_doc)
    assert "integrity_hash" in ingested
    v_res = await log_service.verify_log(ingested["_id"])
    assert v_res["integrity_valid"] is True, "Original log integrity failed!"
    
    # Tamper test
    ingested["username"] = "rogue_user"
    assert not verify_log_integrity(ingested), "Tampering was NOT detected!"
    print(" -> SHA-256 integrity seal & tamper detection verified.")

    # 4. Database Seeding
    print("\n[4/8] Testing Database Seeding Engine...")
    await seed_all(force=True)
    logs_res = await log_service.get_logs(page=1, page_size=100)
    print(f" -> Total Seed Logs Ingested: {logs_res['total']}")
    alerts_res = await alert_service.get_alerts(page=1, page_size=100)
    print(f" -> Initial Generated Alerts: {alerts_res['total']}")
    assert logs_res['total'] >= 15, "Not enough seed logs!"
    assert alerts_res['total'] >= 1, "No seed alerts generated!"

    # 5. Threat Detection Engine Rules
    print("\n[5/8] Testing 6 Detection Rules...")
    from backend.app.engine.rules.brute_force import evaluate_brute_force
    from backend.app.engine.rules.unusual_ip import evaluate_unusual_ip
    from backend.app.engine.rules.off_hours import evaluate_off_hours
    from backend.app.engine.rules.privilege_escalation import evaluate_privilege_escalation
    from backend.app.engine.rules.distributed_brute_force import evaluate_distributed_brute_force
    from backend.app.engine.rules.suspicious_patterns import evaluate_suspicious_patterns
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()

    # R1: Brute Force
    r1_alerts = evaluate_brute_force(
        [{"timestamp": now_iso, "source_ip": "198.51.100.5", "username": "admin", "event_type": "AUTH_FAILED"} for _ in range(6)],
        threshold=5
    )
    assert len(r1_alerts) == 1, "R1 Brute Force failed!"
    print(" -> Rule 1 (Brute-Force Login): PASSED")

    # R2: Unusual IP
    r2_alerts = evaluate_unusual_ip([{"source_ip": "185.220.101.5", "username": "root", "event_type": "AUTH_SUCCESS"}])
    assert len(r2_alerts) == 1, "R2 Unusual IP failed!"
    print(" -> Rule 2 (Unusual / Malicious IP): PASSED")

    # R3: Off Hours
    r3_alerts = evaluate_off_hours([{"timestamp": "2026-11-08T03:30:00+00:00", "username": "clara.fin", "event_type": "AUTH_SUCCESS"}])
    assert len(r3_alerts) == 1, "R3 Off-Hours failed!"
    print(" -> Rule 3 (Off-Hours Access): PASSED")

    # R4: Privilege Escalation
    r4_alerts = evaluate_privilege_escalation([{"username": "bob", "event_type": "PRIVILEGE_ESCALATION", "message": "sudo su root"}])
    assert len(r4_alerts) == 1, "R4 Privilege Escalation failed!"
    print(" -> Rule 4 (Privilege Escalation): PASSED")

    # R5: Distributed Brute Force
    r5_alerts = evaluate_distributed_brute_force([
        {"timestamp": now_iso, "source_ip": f"100.64.0.{i}", "username": "admin", "event_type": "AUTH_FAILED"}
        for i in range(4)
    ], ip_threshold=3)
    assert len(r5_alerts) == 1, "R5 Distributed Brute Force failed!"
    print(" -> Rule 5 (Distributed Brute-Force): PASSED")

    # R6: Suspicious Patterns
    r6_alerts = evaluate_suspicious_patterns([
        {"timestamp": now_iso, "source_ip": "194.26.29.112", "server_id": f"SRV-0{i}", "event_type": "PORT_SCAN"}
        for i in range(4)
    ], server_sweep_threshold=3)
    assert len(r6_alerts) >= 1, "R6 Suspicious Patterns failed!"
    print(" -> Rule 6 (Suspicious Access Patterns): PASSED")

    # 6. Graph Relationships & Queries
    print("\n[6/8] Testing Neo4j Graph Queries...")
    topo = await graph_service.get_threat_topology(limit=50)
    print(f" -> Graph Topology: {len(topo['nodes'])} nodes, {len(topo['edges'])} edges")
    assert len(topo["nodes"]) > 0, "Graph topology empty!"
    attackers = await graph_service.get_repeated_attackers()
    print(f" -> Repeated Attackers identified: {len(attackers)}")
    blast = await graph_service.get_blast_radius("185.220.101.5")
    print(f" -> Blast Radius for 185.220.101.5: {blast['impacted_nodes']} impacted nodes")
    paths = await graph_service.get_attack_paths()
    print(f" -> Lateral Attack Paths traced: {len(paths)}")
    print(" -> Neo4j Threat Graph service verified.")

    # 7. AI Security Copilot & Fallback Engine
    print("\n[7/8] Testing AI Threat Analysis & Fallback...")
    first_alert = alerts_res['alerts'][0]
    ai_report = await ai_service.analyze_threat(first_alert["alert_id"])
    print(f" -> AI Model Used: {ai_report['model_used']} (is_fallback: {ai_report['is_fallback']})")
    print(f" -> AI Incident Summary: {ai_report['summary']}")
    print(f" -> MITRE Tactics: {', '.join(ai_report['mitre_tactics'])}")
    print(f" -> Containment Steps ({len(ai_report['recommended_mitigation'])} items): {ai_report['recommended_mitigation'][0]}")

    chat_reply = await ai_service.chat("How do I block this IP via iptables?")
    print(f" -> AI Chat Copilot Reply length: {len(chat_reply['response'])} chars")
    assert len(chat_reply['response']) > 50, "Chat response too short!"
    print(" -> AI Engine & Expert Fallback verified.")

    # 8. Alert Workflow & Lifecycle
    print("\n[8/8] Testing Alert Investigation & Lifecycle...")
    updated = await alert_service.update_alert(
        first_alert["alert_id"],
        status="INVESTIGATING",
        notes="Security Analyst assigned. Reviewing firewall ingress drop rules.",
        assigned_to="analyst"
    )
    assert updated["status"] == "INVESTIGATING"
    assert updated["assigned_to"] == "analyst"
    print(" -> Alert status transitioned to INVESTIGATING with analyst notes.")

    print("\n" + "=" * 60)
    print("ALL SENTINELGRAPH-AI CORE SYSTEMS FUNCTIONAL & VERIFIED!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_diagnostics())
