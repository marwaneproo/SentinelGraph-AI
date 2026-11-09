from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid
import re

from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.core.integrity import calculate_log_hash, compute_log_hash, verify_log_integrity
from backend.app.core.logging import siem_logger

class LogService:
    _last_hash: str = "GENESIS_SENTINEL_ROOT_00000000"

    async def ingest_log(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses, normalizes, computes SHA-256 integrity hash, stores log in MongoDB,
        and synchronizes entity relationships to Neo4j.
        """
        ts = raw_data.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).isoformat()
        elif isinstance(ts, datetime):
            ts = ts.isoformat()

        server_id = raw_data.get("server_id", "UNKNOWN-SRV")
        server_name = raw_data.get("server_name") or server_id
        source_ip = raw_data.get("source_ip", "0.0.0.0")
        event_type = str(raw_data.get("event_type", "INFO")).upper()
        severity = str(raw_data.get("severity", "INFO")).upper()
        username = raw_data.get("username")
        message = raw_data.get("message", "")
        details = raw_data.get("details") or {}

        # Compute tamper-proof SHA-256 hash linked to previous log hash
        prev_h = self._last_hash
        integrity_hash = compute_log_hash(
            timestamp=ts,
            server_id=server_id,
            source_ip=source_ip,
            event_type=event_type,
            severity=severity,
            username=username,
            details=details,
            prev_hash=prev_h,
            server_name=server_name,
            source_message=message,
            destination_ip=raw_data.get("destination_ip", "192.168.1.10"),
        )
        self._last_hash = integrity_hash

        normalized_doc = {
            "timestamp": ts,
            "server_id": server_id,
            "server_name": server_name,
            "source_ip": source_ip,
            "destination_ip": raw_data.get("destination_ip", "192.168.1.10"),
            "event_type": event_type,
            "severity": severity,
            "username": username,
            "message": message,
            "details": details,
            "integrity_version": 2,
            "integrity_hash": integrity_hash,
            "prev_hash": prev_h
        }

        # Store in MongoDB
        logs_col = mongo_manager.get_collection("logs")
        res = await logs_col.insert_one(normalized_doc)
        normalized_doc["_id"] = str(res.inserted_id) if hasattr(res, "inserted_id") else str(uuid.uuid4())

        # Sync to Neo4j graph asynchronously
        try:
            await neo4j_manager.sync_log_event(normalized_doc)
        except Exception as e:
            siem_logger.error(f"Failed to sync log to Neo4j: {e}")

        return normalized_doc

    async def get_logs(
        self,
        search: Optional[str] = None,
        server_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """Search and paginate logs with multi-field filtering."""
        query: Dict[str, Any] = {}

        if server_id:
            query["server_id"] = server_id
        if source_ip:
            query["source_ip"] = source_ip
        if username:
            query["username"] = username
        if event_type:
            query["event_type"] = event_type
        if severity:
            query["severity"] = severity
        if start_time or end_time:
            time_filter = {}
            if start_time:
                time_filter["$gte"] = start_time
            if end_time:
                time_filter["$lte"] = end_time
            query["timestamp"] = time_filter

        if search:
            # Case-insensitive substring search across message, IP, username
            safe_search = re.escape(search)
            query["$or"] = [
                {"message": {"$regex": safe_search, "$options": "i"}},
                {"source_ip": {"$regex": safe_search, "$options": "i"}},
                {"username": {"$regex": safe_search, "$options": "i"}},
                {"event_type": {"$regex": safe_search, "$options": "i"}}
            ]

        logs_col = mongo_manager.get_collection("logs")
        total = await logs_col.count_documents(query)
        
        skip = (page - 1) * page_size
        cursor = logs_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size)
        items = await cursor.to_list(page_size)

        # Convert _id to string
        for item in items:
            if "_id" in item:
                item["_id"] = str(item["_id"])

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "logs": items
        }

    async def verify_log(self, log_id: str) -> Dict[str, Any]:
        """Verifies cryptographic SHA-256 integrity of a log."""
        logs_col = mongo_manager.get_collection("logs")
        doc = await logs_col.find_one({"_id": log_id})
        if not doc:
            doc = await logs_col.find_one({"integrity_hash": log_id})
            
        if not doc:
            return {
                "log_id": log_id,
                "integrity_valid": False,
                "calculated_hash": "",
                "stored_hash": "",
                "message": "Log entry not found in database."
            }

        calculated_hash = calculate_log_hash(doc)
        stored_hash = doc.get("integrity_hash", "")
        is_valid = verify_log_integrity(doc)
        return {
            "log_id": log_id,
            "integrity_valid": is_valid,
            "calculated_hash": calculated_hash,
            "stored_hash": stored_hash,
            "message": "Cryptographic SHA-256 seal verified; log has not been tampered with." if is_valid else "ALERT: Log hash mismatch, possible forensic tampering!"
        }

log_service = LogService()
