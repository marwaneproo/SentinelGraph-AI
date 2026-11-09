from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class RuleBase(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str = "HIGH"
    enabled: bool = True
    mitre_attack_id: Optional[str] = None
    threshold: int = Field(5, ge=1, le=100000)
    window_seconds: int = Field(300, ge=1, le=604800)
    recommended_action: str
    parameters: Optional[Dict[str, Any]] = None

class RuleCreate(RuleBase):
    pass

class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    threshold: Optional[int] = Field(None, ge=1, le=100000)
    window_seconds: Optional[int] = Field(None, ge=1, le=604800)
    recommended_action: Optional[str] = None

class RuleResponse(RuleBase):
    id: Optional[str] = Field(None, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
