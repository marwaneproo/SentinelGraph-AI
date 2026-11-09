from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AlertSeverity(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class AlertCreate(BaseModel):
    title: str
    description: str
    severity: str = "HIGH"
    status: str = "NEW"
    rule_id: str
    rule_name: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    server_id: Optional[str] = None
    evidence_log_ids: List[str] = Field(default_factory=list)
    recommended_action: str
    metadata: Optional[Dict[str, Any]] = None

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    investigation_notes: Optional[str] = None
    assigned_to: Optional[str] = None

class AlertResponse(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    alert_id: str
    title: str
    description: str
    severity: str
    status: str
    rule_id: str
    rule_name: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    server_id: Optional[str] = None
    timestamp: datetime
    evidence_log_ids: List[str] = Field(default_factory=list)
    recommended_action: str
    investigation_notes: Optional[str] = ""
    assigned_to: Optional[str] = None
    ai_summary: Optional[str] = None

class AlertFilterParams(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    rule_id: Optional[str] = None
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    page: int = 1
    page_size: int = 50

class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    alerts: List[Dict[str, Any]]
