from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class RawLogInput(BaseModel):
    timestamp: Optional[datetime] = None
    server_id: str
    server_name: Optional[str] = None
    source_ip: str
    destination_ip: Optional[str] = "192.168.1.10"
    event_type: str
    severity: str = "INFO"
    username: Optional[str] = None
    message: str
    details: Optional[Dict[str, Any]] = None

class NormalizedLog(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    timestamp: datetime
    server_id: str
    server_name: str
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    username: Optional[str] = None
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    integrity_hash: str
    prev_hash: Optional[str] = None

class LogFilterParams(BaseModel):
    search: Optional[str] = None
    server_id: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    page_size: int = 50

class LogListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    logs: List[Dict[str, Any]]

class LogIntegrityCheckResponse(BaseModel):
    log_id: str
    integrity_valid: bool
    calculated_hash: str
    stored_hash: str
    message: str
