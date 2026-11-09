from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import re

from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager

class AlertService:
    async def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        target_user: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """Fetch alerts with filtering and pagination."""
        query: Dict[str, Any] = {}
        if severity:
            query["severity"] = severity
        if status:
            query["status"] = status
        if rule_id:
            query["rule_id"] = rule_id
        if source_ip:
            query["source_ip"] = source_ip
        if target_user:
            query["target_user"] = target_user

        if search:
            safe_search = re.escape(search)
            query["$or"] = [
                {"title": {"$regex": safe_search, "$options": "i"}},
                {"description": {"$regex": safe_search, "$options": "i"}},
                {"source_ip": {"$regex": safe_search, "$options": "i"}},
                {"target_user": {"$regex": safe_search, "$options": "i"}}
            ]

        alerts_col = mongo_manager.get_collection("alerts")
        total = await alerts_col.count_documents(query)
        
        skip = (page - 1) * page_size
        cursor = alerts_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size)
        items = await cursor.to_list(page_size)

        for item in items:
            if "_id" in item:
                item["_id"] = str(item["_id"])

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "alerts": items
        }

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Finds alert by MongoDB ID or alert_id string."""
        alerts_col = mongo_manager.get_collection("alerts")
        doc = await alerts_col.find_one({"alert_id": alert_id})
        if not doc:
            try:
                doc = await alerts_col.find_one({"_id": alert_id})
            except Exception:
                pass
        if doc and "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def update_alert(
        self,
        alert_id: str,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        assigned_to: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Updates alert status, analyst notes, or assignment."""
        alerts_col = mongo_manager.get_collection("alerts")
        update_fields: Dict[str, Any] = {}
        if status:
            update_fields["status"] = status
        if notes is not None:
            update_fields["investigation_notes"] = notes
        if assigned_to is not None:
            update_fields["assigned_to"] = assigned_to
        
        update_fields["updated_at"] = datetime.now(timezone.utc).isoformat()

        query = {"alert_id": alert_id}
        doc = await alerts_col.find_one(query)
        if not doc:
            query = {"_id": alert_id}

        await alerts_col.update_one(query, {"$set": update_fields})
        updated = await alerts_col.find_one(query)
        if updated and "_id" in updated:
            updated["_id"] = str(updated["_id"])
        return updated

    async def get_alert_evidence(self, alert_id: str) -> List[Dict[str, Any]]:
        """Fetches associated evidence logs for an alert."""
        alert = await self.get_alert_by_id(alert_id)
        if not alert:
            return []

        evidence_ids = alert.get("evidence_log_ids", [])
        if not evidence_ids:
            return []

        logs_col = mongo_manager.get_collection("logs")
        cursor = logs_col.find({
            "$or": [
                {"_id": {"$in": evidence_ids}},
                {"integrity_hash": {"$in": evidence_ids}}
            ]
        })
        logs = await cursor.to_list(100)
        for l in logs:
            if "_id" in l:
                l["_id"] = str(l["_id"])
        return logs

    async def get_alert_stats(self) -> Dict[str, Any]:
        """Calculates severity and status KPI aggregates."""
        alerts_col = mongo_manager.get_collection("alerts")
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_status = {"NEW": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0}

        async for a in alerts_col.find({}):
            sev = a.get("severity", "LOW").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            st = a.get("status", "NEW").upper()
            by_status[st] = by_status.get(st, 0) + 1

        total_alerts = await alerts_col.count_documents({})
        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "by_status": by_status,
            "critical_or_high": by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0)
        }

alert_service = AlertService()
