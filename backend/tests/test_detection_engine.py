import pytest
from datetime import datetime, timezone
from backend.app.db.mongodb import mongo_manager
from backend.app.engine.rules.brute_force import evaluate_brute_force
from backend.app.engine.rules.unusual_ip import evaluate_unusual_ip
from backend.app.engine.rules.off_hours import evaluate_off_hours
from backend.app.engine.rules.privilege_escalation import evaluate_privilege_escalation
from backend.app.engine.rules.distributed_brute_force import evaluate_distributed_brute_force
from backend.app.engine.rules.suspicious_patterns import evaluate_suspicious_patterns
from backend.app.engine.detector import threat_detector


def test_rule_1_brute_force():
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {"timestamp": now, "source_ip": "198.51.100.42", "username": "admin", "server_id": "SRV-01", "event_type": "AUTH_FAILED"}
        for _ in range(6)
    ]
    alerts = evaluate_brute_force(logs, threshold=5, window_seconds=300)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-001-BRUTEFORCE"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["target_user"] == "admin"
    assert "198.51.100.42" in alerts[0]["title"]

def test_rule_2_unusual_ip():
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {
            "timestamp": now,
            "source_ip": "185.220.101.5", # Known Tor exit node
            "username": "root",
            "server_id": "SRV-EDGE-01",
            "event_type": "AUTH_SUCCESS"
        }
    ]
    alerts = evaluate_unusual_ip(logs)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-002-UNUSUAL-IP"
    assert alerts[0]["severity"] == "CRITICAL"

def test_rule_3_off_hours():
    # 03:00 AM UTC
    night_time = "2026-11-08T03:15:00+00:00"
    logs = [
        {
            "timestamp": night_time,
            "source_ip": "10.0.1.25",
            "username": "clara.fin",
            "server_id": "SRV-FINANCE-DB-03",
            "event_type": "AUTH_SUCCESS"
        }
    ]
    alerts = evaluate_off_hours(logs, work_start_hour=7, work_end_hour=19)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-003-OFF-HOURS"
    assert alerts[0]["severity"] == "MEDIUM"

def test_rule_4_privilege_escalation():
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {
            "timestamp": now,
            "source_ip": "192.168.1.99",
            "username": "bob.developer",
            "server_id": "SRV-FINANCE-DB-03",
            "event_type": "PRIVILEGE_ESCALATION",
            "message": "User bob executed unauthorized sudo su",
            "details": {"command": "sudo su"}
        }
    ]
    alerts = evaluate_privilege_escalation(logs)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-004-PRIV-ESC"
    assert alerts[0]["severity"] == "CRITICAL"

def test_rule_5_distributed_brute_force():
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {"timestamp": now, "source_ip": "45.142.195.12", "username": "admin", "event_type": "AUTH_FAILED"},
        {"timestamp": now, "source_ip": "194.26.29.112", "username": "admin", "event_type": "AUTH_FAILED"},
        {"timestamp": now, "source_ip": "91.240.118.172", "username": "admin", "event_type": "AUTH_FAILED"}
    ]
    alerts = evaluate_distributed_brute_force(logs, ip_threshold=3, window_seconds=600)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE-005-DIST-BRUTEFORCE"
    assert alerts[0]["target_user"] == "admin"

def test_rule_6_suspicious_patterns():
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {"timestamp": now, "source_ip": "194.26.29.112", "server_id": f"SRV-0{i}", "event_type": "PORT_SCAN"}
        for i in range(4)
    ]
    alerts = evaluate_suspicious_patterns(logs, server_sweep_threshold=3)
    assert len(alerts) >= 1
    rule_ids = [a["rule_id"] for a in alerts]
    assert any("RULE-006" in r for r in rule_ids)

@pytest.mark.asyncio
async def test_detection_pipeline_uses_saved_rule_enabled_and_threshold(async_client):
    rules_col = mongo_manager.get_collection("detection_rules")
    rule = await rules_col.find_one({"rule_id": "RULE-001-BRUTEFORCE"})
    original_enabled = rule.get("enabled", True)
    original_threshold = rule.get("threshold", 5)
    now = datetime.now(timezone.utc).isoformat()
    logs = [
        {
            "_id": f"config-test-{i}",
            "timestamp": now,
            "source_ip": "10.253.0.4",
            "username": "config-test-user",
            "server_id": "CONFIG-TEST-SRV",
            "event_type": "AUTH_FAILED",
            "message": "failed test authentication",
        }
        for i in range(6)
    ]
    try:
        await rules_col.update_one(
            {"rule_id": "RULE-001-BRUTEFORCE"},
            {"$set": {"enabled": False}}
        )
        disabled_result = await threat_detector.run_detection_pipeline(custom_logs=logs)
        assert not any(a["rule_id"] == "RULE-001-BRUTEFORCE" for a in disabled_result)

        await rules_col.update_one(
            {"rule_id": "RULE-001-BRUTEFORCE"},
            {"$set": {"enabled": True, "threshold": 7}}
        )
        above_threshold_result = await threat_detector.run_detection_pipeline(custom_logs=logs)
        assert not any(a["rule_id"] == "RULE-001-BRUTEFORCE" for a in above_threshold_result)
    finally:
        await rules_col.update_one(
            {"rule_id": "RULE-001-BRUTEFORCE"},
            {"$set": {"enabled": original_enabled, "threshold": original_threshold}}
        )
