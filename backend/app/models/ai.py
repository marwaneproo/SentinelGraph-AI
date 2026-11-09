from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AIAnalysisRequest(BaseModel):
    alert_id: str
    custom_query: Optional[str] = None

class AIAnalysisResponse(BaseModel):
    alert_id: str
    summary: str
    threat_explanation: str
    mitre_tactics: List[str]
    attack_vector: str
    blast_radius_assessment: str
    recommended_mitigation: List[str]
    confidence_score: float = 0.92
    model_used: str
    is_fallback: bool
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

class AIChatMessage(BaseModel):
    role: str = Field(..., description="'user', 'assistant', or 'system'")
    content: str

class AIChatRequest(BaseModel):
    message: str
    history: List[AIChatMessage] = Field(default_factory=list)
    alert_id: Optional[str] = None

class AIChatResponse(BaseModel):
    response: str
    model_used: str
    is_fallback: bool
    suggestions: List[str] = Field(default_factory=list)
