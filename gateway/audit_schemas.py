from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditEventResponse(BaseModel):
    """Public representation of a stored security audit event."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    request_id: str
    agent_id: str
    session_id: str
    tool_name: str
    action: str
    target: str | None
    decision: str
    risk_level: str
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str]
    required_controls: list[str]
    previous_hash: str
    event_hash: str
    created_at: datetime


class AuditEventListResponse(BaseModel):
    events: list[AuditEventResponse]
    count: int = Field(ge=0)
class AuditIntegrityResponse(BaseModel):
    valid: bool
    event_count: int = Field(ge=0)
    broken_event_id: str | None = None