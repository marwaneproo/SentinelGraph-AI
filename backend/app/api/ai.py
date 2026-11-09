from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel

from backend.app.services.ai_service import ai_service
from backend.app.models.ai import AIAnalysisRequest, AIAnalysisResponse, AIChatRequest, AIChatResponse
from backend.app.core.rbac import require_any_authenticated, require_analyst_or_admin
from backend.app.db.mongodb import mongo_manager
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/ai", tags=["AI Threat Analysis & Assistant"])

@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_threat_alert(
    req: AIAnalysisRequest,
    user_payload: dict = Depends(require_analyst_or_admin)
):
    """Generates an AI-driven investigation summary and remediation plan for an alert."""
    analysis = await ai_service.analyze_threat(
        alert_id=req.alert_id,
        custom_query=req.custom_query
    )
    await audit_service.log_action(
        username=user_payload.get("sub", "analyst"),
        action="AI_INVESTIGATION_RUN",
        resource_type="ALERT",
        resource_id=req.alert_id,
        details={"is_fallback": analysis.get("is_fallback", False)}
    )
    return analysis

@router.post("/chat", response_model=AIChatResponse)
async def chat_security_assistant(
    req: AIChatRequest,
    user_payload: dict = Depends(require_any_authenticated)
):
    """Interactive SOC assistant providing MITRE ATT&CK guidance, containment, and query help."""
    history_dicts = [{"role": m.role, "content": m.content} for m in req.history]
    return await ai_service.chat(
        user_message=req.message,
        history=history_dicts,
        alert_id=req.alert_id
    )

@router.get("/history")
async def get_ai_history(
    limit: int = Query(20, ge=1, le=100),
    user_payload: dict = Depends(require_any_authenticated)
):
    """Retrieves previous AI threat analysis reports."""
    ai_col = mongo_manager.get_collection("ai_analyses")
    cursor = ai_col.find({}).sort("analyzed_at", -1).limit(limit)
    items = await cursor.to_list(limit)
    for it in items:
        if "_id" in it:
            it["_id"] = str(it["_id"])
    return items
