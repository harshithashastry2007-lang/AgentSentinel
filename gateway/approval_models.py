from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalAction(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    action: ApprovalAction
    approver_id: str = Field(min_length=3, max_length=100)
    comment: str | None = Field(default=None, max_length=500)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: str
    request_id: UUID
    agent_id: str
    session_id: str
    tool_name: str
    action: str
    target: str | None
    risk_level: str
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str]
    required_controls: list[str]
    status: ApprovalStatus
    approver_id: str | None
    comment: str | None
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None


class ApprovalListResponse(BaseModel):
    approvals: list[ApprovalResponse]
    count: int = Field(ge=0)