from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel

from backend.app.services.log_service import log_service
from backend.app.models.log import RawLogInput, LogListResponse, LogIntegrityCheckResponse
from backend.app.core.rbac import require_any_authenticated, require_analyst_or_admin
from backend.app.engine.simulator import generate_simulated_attack
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/logs", tags=["Log Management & Ingestion"])

class SimulationRequest(BaseModel):
    attack_type: str = "brute_force" # brute_force, unusual_ip, privilege_escalation, distributed_brute_force, suspicious_patterns, off_hours, benign

@router.get("", response_model=LogListResponse)
async def list_logs(
    search: Optional[str] = Query(None, description="Search term in message, user, or IP"),
    server_id: Optional[str] = Query(None, description="Filter by server ID"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    start_time: Optional[str] = Query(None, description="ISO start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO end timestamp"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_payload: dict = Depends(require_any_authenticated)
):
    """Searches, filters, and paginates system security logs."""
    return await log_service.get_logs(
        search=search,
        server_id=server_id,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size
    )

@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_log(
    log_input: RawLogInput,
    user_payload: dict = Depends(require_analyst_or_admin)
):
    """Ingests a new security log with automatic normalization and SHA-256 seal."""
    doc = await log_service.ingest_log(log_input.model_dump())
    return doc

@router.get("/{log_id}/verify", response_model=LogIntegrityCheckResponse)
async def verify_log_integrity_endpoint(
    log_id: str,
    user_payload: dict = Depends(require_any_authenticated)
):
    """Verifies SHA-256 cryptographic seal of a specific log."""
    return await log_service.verify_log(log_id)

@router.post("/simulate")
async def trigger_simulation(
    req: SimulationRequest,
    user_payload: dict = Depends(require_analyst_or_admin)
):
    """Generates realistic attack traffic and runs the threat detection engine."""
    result = await generate_simulated_attack(req.attack_type)
    await audit_service.log_action(
        username=user_payload.get("sub", "analyst"),
        action="SIMULATION_TRIGGERED",
        resource_type="ATTACK_SIMULATOR",
        details={"attack_type": req.attack_type, "alerts": result.get("alerts_triggered", 0)}
    )
    return result
