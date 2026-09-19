from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ToolInvocationRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    request_id: UUID = Field(default_factory=uuid4)
    agent_id: str = Field(min_length=3, max_length=100)
    session_id: str = Field(min_length=3, max_length=100)
    tool_name: str = Field(min_length=1, max_length=150)
    action: str = Field(min_length=1, max_length=150)
    arguments: dict[str, Any] = Field(default_factory=dict)
    requested_scopes: list[str] = Field(default_factory=list, max_length=25)
    target: str | None = Field(default=None, max_length=500)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    decision: Decision
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    required_controls: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))