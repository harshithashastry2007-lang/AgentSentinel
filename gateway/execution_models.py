from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from gateway.models import ToolInvocationRequest


class ExecutionStatus(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"
    FAILED = "failed"


class SecureExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invocation: ToolInvocationRequest
    approval_id: str | None = None
    dry_run: bool = False


class SecureExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    status: ExecutionStatus
    tool_name: str
    action: str
    approval_id: str | None = None
    output: dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100)
    message: str
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )