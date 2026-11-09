from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.db.mongodb import mongo_manager
from backend.app.models.rule import RuleBase, RuleCreate, RuleUpdate, RuleResponse
from backend.app.core.rbac import require_any_authenticated, require_admin, require_analyst_or_admin
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/rules", tags=["Threat Detection Rules"])

@router.get("", response_model=List[RuleResponse])
async def list_rules(user_payload: dict = Depends(require_any_authenticated)):
    """Lists all threat detection rules and their real-time execution statistics."""
    rules_col = mongo_manager.get_collection("rules")
    if await rules_col.count_documents({}) == 0:
        rules_col = mongo_manager.get_collection("detection_rules")
    
    rules = await rules_col.find({}).to_list(100)
    result = []
    for r in rules:
        r["_id"] = str(r.get("_id", r.get("rule_id")))
        result.append(r)
    return result

@router.patch("/{rule_id}")
async def update_rule(
    rule_id: str,
    rule_update: RuleUpdate,
    user_payload: dict = Depends(require_analyst_or_admin)
):
    """Enables, disables, or updates parameters of a threat detection rule."""
    rules_col = mongo_manager.get_collection("detection_rules")
    fields = {k: v for k, v in rule_update.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided to update")

    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    res = await rules_col.update_one({"rule_id": rule_id}, {"$set": fields})
    if res.modified_count == 0:
        # Check if rule exists
        existing = await rules_col.find_one({"rule_id": rule_id})
        if not existing:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    await audit_service.log_action(
        username=user_payload.get("sub", "analyst"),
        action="RULE_MODIFIED",
        resource_type="DETECTION_RULE",
        resource_id=rule_id,
        details=fields
    )

    updated = await rules_col.find_one({"rule_id": rule_id})
    updated["_id"] = str(updated.get("_id", rule_id))
    return updated
