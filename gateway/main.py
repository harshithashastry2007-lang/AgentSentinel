from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.audit_schemas import (
    AuditEventListResponse,
    AuditIntegrityResponse,
)

from gateway.auth_models import (
    CapabilityClaims,
    CapabilityTokenRequest,
    CapabilityTokenResponse,
)
from gateway.database import (
    create_database_tables,
    get_database_session,
)
from gateway.models import PolicyDecision, ToolInvocationRequest
from security.audit_service import AuditService
from security.dependencies import (
    get_token_service,
    require_capability,
)
from security.identity import AgentAuthenticator, AuthenticationError
from security.policy_engine import PolicyEngine
from security.token_service import TokenService


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await create_database_tables()
    yield


app = FastAPI(
    title="AgentSentinel",
    description=(
        "Zero-Trust Runtime Security Gateway "
        "for Autonomous AI Agents and MCP Tools"
    ),
    version="0.1.0",
    lifespan=lifespan,
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
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
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

    decision = PolicyEngine().evaluate(request)

    await AuditService(database_session).record(
        request=request,
        decision=decision,
    )

    return decision


@app.get(
    "/v1/audit/events",
    response_model=AuditEventListResponse,
    tags=["Audit"],
)
async def list_audit_events(
    _claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("audit:read")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AuditEventListResponse:
    events = await AuditService(database_session).list_recent(
        limit=limit,
    )

    return AuditEventListResponse(
        events=events,
        count=len(events),
    )

@app.get(
    "/v1/audit/integrity",
    response_model=AuditIntegrityResponse,
    tags=["Audit"],
)
async def verify_audit_integrity(
    _claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("audit:read")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
) -> AuditIntegrityResponse:
    valid, event_count, broken_event_id = (
        await AuditService(database_session).verify_chain()
    )

    return AuditIntegrityResponse(
        valid=valid,
        event_count=event_count,
        broken_event_id=broken_event_id,
    )