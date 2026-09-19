from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status

from gateway.auth_models import (
    CapabilityClaims,
    CapabilityTokenRequest,
    CapabilityTokenResponse,
)
from gateway.models import PolicyDecision, ToolInvocationRequest
from security.dependencies import (
    get_token_service,
    require_capability,
)
from security.identity import AgentAuthenticator, AuthenticationError
from security.policy_engine import PolicyEngine
from security.token_service import TokenService

app = FastAPI(
    title="AgentSentinel",
    description=(
        "Zero-Trust Runtime Security Gateway "
        "for Autonomous AI Agents and MCP Tools"
    ),
    version="0.1.0",
)


def get_authenticator() -> AgentAuthenticator:
    return AgentAuthenticator()


@app.get("/", tags=["System"])
async def root() -> dict[str, str]:
    return {
        "name": "AgentSentinel",
        "status": "operational",
        "mode": "zero-trust",
    }


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "AgentSentinel Gateway",
        "version": app.version,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.post(
    "/v1/auth/token",
    response_model=CapabilityTokenResponse,
    tags=["Authentication"],
)
async def issue_capability_token(
    request: CapabilityTokenRequest,
    agent_key: Annotated[str, Header(alias="X-Agent-Key")],
    authenticator: Annotated[
        AgentAuthenticator,
        Depends(get_authenticator),
    ],
    token_service: Annotated[
        TokenService,
        Depends(get_token_service),
    ],
) -> CapabilityTokenResponse:
    try:
        authenticator.authenticate(
            agent_id=request.agent_id,
            api_key=agent_key,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent authentication failed",
        ) from exc

    return token_service.issue(request)


@app.post(
    "/v1/evaluate",
    response_model=PolicyDecision,
    tags=["Policy"],
)
async def evaluate_tool_invocation(
    request: ToolInvocationRequest,
    claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("policy:evaluate")),
    ],
) -> PolicyDecision:
    if (
        request.agent_id != claims.sub
        or request.session_id != claims.session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token identity does not match request context",
        )

    return PolicyEngine().evaluate(request)