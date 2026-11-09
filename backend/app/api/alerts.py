from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status

from backend.app.services.alert_service import alert_service
from backend.app.models.alert import AlertListResponse, AlertUpdate
from backend.app.core.rbac import require_any_authenticated, require_analyst_or_admin
from backend.app.engine.detector import threat_detector
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/alerts", tags=["Alert Management"])

@router.get("", response_model=AlertListResponse)
async def list_alerts(
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    rule_id: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    target_user: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user_payload: dict = Depends(require_any_authenticated)
):
    """Retrieves alerts with filtering and pagination."""
    return await alert_service.get_alerts(
        severity=severity,
        status=status,
        rule_id=rule_id,
        source_ip=source_ip,
        target_user=target_user,
        search=search,
        page=page,
        page_size=page_size
    )

@router.get("/{alert_id}")
async def get_alert(alert_id: str, user_payload: dict = Depends(require_any_authenticated)):
    """Retrieves a single alert by its identifier."""
    alert = await alert_service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert

@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    update_data: AlertUpdate,
    user_payload: dict = Depends(require_analyst_or_admin)
):
    """Updates alert status, analyst notes, or assignment."""
    updated = await alert_service.update_alert(
        alert_id=alert_id,
        status=update_data.status,
        notes=update_data.investigation_notes,
        assigned_to=update_data.assigned_to or user_payload.get("sub")
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    await audit_service.log_action(
        username=user_payload.get("sub", "analyst"),
        action="ALERT_STATUS_UPDATE",
        resource_type="ALERT",
        resource_id=alert_id,
        details={"status": update_data.status, "notes": update_data.investigation_notes}
    )

    return updated

@router.get("/{alert_id}/evidence")
async def get_alert_evidence(alert_id: str, user_payload: dict = Depends(require_any_authenticated)):
    """Retrieves forensic evidence logs linked to the alert."""
    return await alert_service.get_alert_evidence(alert_id)

@router.post("/run-detection")
async def run_detection_pipeline_endpoint(user_payload: dict = Depends(require_analyst_or_admin)):
    """Executes the Threat Detection Engine on recent logs immediately."""
    new_alerts = await threat_detector.run_detection_pipeline()
    return {
        "status": "success",
        "alerts_generated": len(new_alerts),
        "alerts": new_alerts
    }
