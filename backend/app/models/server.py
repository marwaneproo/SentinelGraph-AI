from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class ServerBase(BaseModel):
    server_id: str = Field(..., min_length=3, max_length=50)
    hostname: str
    ip_address: str
    os_type: str = "Linux"
    role: str = "Application Server"
    criticality: str = "HIGH"
    status: str = "ACTIVE"
    description: Optional[str] = None

class ServerCreate(ServerBase):
    pass

class ServerResponse(ServerBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_heartbeat: Optional[datetime] = None
    log_count: int = 0
