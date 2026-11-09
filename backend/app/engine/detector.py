from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import uuid

from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.core.logging import siem_logger
from backend.app.engine.rules.brute_force import evaluate_brute_force
from backend.app.engine.rules.unusual_ip import evaluate_unusual_ip
from backend.app.engine.rules.off_hours import evaluate_off_hours
from backend.app.engine.rules.privilege_escalation import evaluate_privilege_escalation
from backend.app.engine.rules.distributed_brute_force import evaluate_distributed_brute_force
from backend.app.engine.rules.suspicious_patterns import evaluate_suspicious_patterns

class ThreatDetector:
    async def run_detection_pipeline(self, custom_logs: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Runs all active threat detection rules across recent logs.
        Stores generated alerts in MongoDB and synchronizes with Neo4j.
        """
        # Fetch recent logs from database if not explicitly provided
        if custom_logs is not None:
            recent_logs = custom_logs
        else:
            logs_col = mongo_manager.get_collection("logs")
            cursor = logs_col.find({}).sort("timestamp", -1).limit(500)
            recent_logs = await cursor.to_list(500)

        if not recent_logs:
            siem_logger.info("Detection pipeline skipped: No logs to analyze.")
            return []

        rules_col = mongo_manager.get_collection("detection_rules")
        configured_rules = await rules_col.find({}).to_list(100)
        rules_by_id = {rule.get("rule_id"): rule for rule in configured_rules}

        def rule_config(rule_id: str) -> Dict[str, Any]:
            return rules_by_id.get(rule_id, {})

        def rule_enabled(rule_id: str) -> bool:
            return rule_config(rule_id).get("enabled", True) is not False

        generated_alerts: List[Dict[str, Any]] = []

        # 1. Brute-force
        rule = rule_config("RULE-001-BRUTEFORCE")
        if rule_enabled("RULE-001-BRUTEFORCE"):
            try:
                generated_alerts.extend(evaluate_brute_force(
                    recent_logs,
                    threshold=int(rule.get("threshold", 5)),
                    window_seconds=int(rule.get("window_seconds", 300)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 1 error: {e}")

        # 2. Unusual IP
        rule = rule_config("RULE-002-UNUSUAL-IP")
        if rule_enabled("RULE-002-UNUSUAL-IP"):
            try:
                generated_alerts.extend(evaluate_unusual_ip(
                    recent_logs,
                    threshold=int(rule.get("threshold", 1)),
                    window_seconds=int(rule.get("window_seconds", 3600)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 2 error: {e}")

        # 3. Off-hours
        rule = rule_config("RULE-003-OFF-HOURS")
        if rule_enabled("RULE-003-OFF-HOURS"):
            parameters = rule.get("parameters") or {}
            try:
                generated_alerts.extend(evaluate_off_hours(
                    recent_logs,
                    work_start_hour=int(parameters.get("work_start_hour", 7)),
                    work_end_hour=int(parameters.get("work_end_hour", 19)),
                    threshold=int(rule.get("threshold", 1)),
                    window_seconds=int(rule.get("window_seconds", 3600)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 3 error: {e}")

        # 4. Privilege escalation
        rule = rule_config("RULE-004-PRIV-ESC")
        if rule_enabled("RULE-004-PRIV-ESC"):
            try:
                generated_alerts.extend(evaluate_privilege_escalation(
                    recent_logs,
                    threshold=int(rule.get("threshold", 1)),
                    window_seconds=int(rule.get("window_seconds", 300)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 4 error: {e}")

        # 5. Distributed brute-force
        rule = rule_config("RULE-005-DIST-BRUTEFORCE")
        if rule_enabled("RULE-005-DIST-BRUTEFORCE"):
            try:
                generated_alerts.extend(evaluate_distributed_brute_force(
                    recent_logs,
                    ip_threshold=int(rule.get("threshold", 3)),
                    window_seconds=int(rule.get("window_seconds", 600)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 5 error: {e}")

        # 6. Suspicious patterns
        rule = rule_config("RULE-006-LATERAL-SCAN")
        if rule_enabled("RULE-006-LATERAL-SCAN"):
            parameters = rule.get("parameters") or {}
            try:
                generated_alerts.extend(evaluate_suspicious_patterns(
                    recent_logs,
                    server_sweep_threshold=int(rule.get("threshold", 3)),
                    probe_threshold=int(parameters.get("probe_threshold", 5)),
                    window_seconds=int(rule.get("window_seconds", 300)),
                ))
            except Exception as e:
                siem_logger.error(f"Rule 6 error: {e}")

        # Persist and deduplicate alerts
        alerts_col = mongo_manager.get_collection("alerts")
        saved_alerts = []
        now_iso = datetime.now(timezone.utc).isoformat()
        dedupe_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

        for alert in generated_alerts:
            alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
            alert["alert_id"] = alert_id
            alert["status"] = "NEW"
            alert["timestamp"] = alert.get("timestamp") or now_iso
            alert["investigation_notes"] = ""
            alert["assigned_to"] = None

            # Deduplication: check if an identical active alert exists within the last 15 minutes
            existing = await alerts_col.find_one({
                "rule_id": alert["rule_id"],
                "source_ip": alert.get("source_ip"),
                "target_user": alert.get("target_user"),
                "status": {"$in": ["NEW", "INVESTIGATING"]},
                "timestamp": {"$gte": dedupe_cutoff},
            })

            if not existing:
                res = await alerts_col.insert_one(alert)
                alert["_id"] = str(res.inserted_id) if hasattr(res, "inserted_id") else alert_id
                saved_alerts.append(alert)
                
                # Sync alert node and relations into Neo4j
                await neo4j_manager.sync_alert(alert)

                # Update rule trigger statistics
                await rules_col.update_one(
                    {"rule_id": alert["rule_id"]},
                    {"$set": {"last_triggered": now_iso}, "$inc": {"trigger_count": 1}}
                )

        if saved_alerts:
            siem_logger.info(f"Threat Detection Pipeline triggered: {len(saved_alerts)} new alerts created.")
        
        return saved_alerts

threat_detector = ThreatDetector()
