from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CapabilityTokenRequest(BaseModel):
    """Request for a short-lived, least-privilege token."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    agent_id: str = Field(min_length=3, max_length=100)
    session_id: str = Field(min_length=3, max_length=100)
    requested_scopes: list[str] = Field(
        min_length=1,
        max_length=25,
    )
    audience: str = Field(
        default="agentsentinel-tools",
        min_length=3,
        max_length=100,
    )


class CapabilityTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(gt=0)
    scopes: list[str]


class CapabilityClaims(BaseModel):
    """Validated claims carried by an AgentSentinel token."""

    model_config = ConfigDict(extra="forbid")

    sub: str
    session_id: str
    scopes: list[str]
    audience: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    token_id: UUID