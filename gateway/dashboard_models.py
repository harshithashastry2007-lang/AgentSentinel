from pydantic import BaseModel, ConfigDict, Field


class DashboardSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_evaluations: int = Field(ge=0)
    allowed: int = Field(ge=0)
    denied: int = Field(ge=0)
    required_approval: int = Field(ge=0)
    pending_approvals: int = Field(ge=0)
    critical_events: int = Field(ge=0)
    average_risk_score: float = Field(ge=0, le=100)
    audit_chain_valid: bool
    active_protection: bool = True