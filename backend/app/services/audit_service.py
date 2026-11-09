from datetime import datetime, timezone
from typing import Dict, Any, Optional
from backend.app.db.mongodb import mongo_manager
from backend.app.core.logging import siem_logger

class AuditService:
    async def log_action(
        self,
        username: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ):
        """Records user and administrative activity for SIEM compliance audit trails."""
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "ip_address": ip_address or "127.0.0.1"
        }
        try:
            audit_col = mongo_manager.get_collection("audit_logs")
            await audit_col.insert_one(doc)
            siem_logger.info(f"AUDIT: [{username}] performed {action} on {resource_type}:{resource_id}")
        except Exception as e:
            siem_logger.error(f"Failed to record audit log: {e}")

audit_service = AuditService()
