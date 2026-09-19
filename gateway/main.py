from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from time import perf_counter
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval_models import (
    ApprovalDecisionRequest,
    ApprovalListResponse,
    ApprovalResponse,
)
from gateway.audit_schemas import (
    AuditEventListResponse,
    AuditIntegrityResponse,
)
from gateway.auth_models import (
    CapabilityClaims,
    CapabilityTokenRequest,
    CapabilityTokenResponse,
)
from gateway.dashboard_models import DashboardSummary
from gateway.database import (
    create_database_tables,
    get_database_session,
)
from gateway.execution_models import (
    SecureExecutionRequest,
    SecureExecutionResponse,
)
from gateway.metrics import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    POLICY_DECISIONS_TOTAL,
    THREATS_DETECTED_TOTAL,
    TOOL_EXECUTIONS_TOTAL,
)
from gateway.models import (
    Decision,
    PolicyDecision,
    ToolInvocationRequest,
)
from gateway.threat_models import (
    ThreatAnalysisRequest,
    ThreatAssessment,
)
from security.approval_service import (
    ApprovalNotFoundError,
    ApprovalService,
    ApprovalStateError,
)
from security.audit_service import AuditService
from security.dashboard_service import DashboardService
from security.dependencies import (
    get_token_service,
    require_capability,
)
from security.execution_service import SecureExecutionService
from security.identity import AgentAuthenticator, AuthenticationError
from security.policy_engine import PolicyEngine
from security.threat_detector import ThreatDetector
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

@app.middleware("http")
async def monitor_http_requests(
    request: Request,
    call_next: object,
) -> Response:
    started_at = perf_counter()
    response = await call_next(request)

    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)

    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        path=path,
        status_code=str(response.status_code),
    ).inc()

    HTTP_REQUEST_DURATION_SECONDS.labels(
        method=request.method,
        path=path,
    ).observe(perf_counter() - started_at)

    return response

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
    POLICY_DECISIONS_TOTAL.labels(
        decision=decision.decision.value,
        risk_level=decision.risk_level.value,
    ).inc()

    if decision.decision == Decision.REQUIRE_APPROVAL:
        approval = await ApprovalService(
            database_session
        ).create(
            request=request,
            decision=decision,
        )
        decision = decision.model_copy(
            update={"approval_id": approval.approval_id}
        )

    await AuditService(database_session).record(
        request=request,
        decision=decision,
    )

    return decision


@app.get(
    "/v1/approvals",
    response_model=ApprovalListResponse,
    tags=["Approvals"],
)
async def list_pending_approvals(
    _claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("approval:read")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ApprovalListResponse:
    approvals = await ApprovalService(
        database_session
    ).list_pending(limit=limit)

    return ApprovalListResponse(
        approvals=approvals,
        count=len(approvals),
    )


@app.post(
    "/v1/approvals/{approval_id}/decision",
    response_model=ApprovalResponse,
    tags=["Approvals"],
)
async def resolve_approval(
    approval_id: str,
    resolution: ApprovalDecisionRequest,
    _claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("approval:write")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
) -> ApprovalResponse:
    try:
        approval = await ApprovalService(
            database_session
        ).resolve(
            approval_id=approval_id,
            resolution=resolution,
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval request not found",
        ) from exc
    except ApprovalStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return ApprovalResponse.model_validate(approval)


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

@app.post(
    "/v1/execute",
    response_model=SecureExecutionResponse,
    tags=["Execution"],
)
async def execute_tool_action(
    execution_request: SecureExecutionRequest,
    claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("tool:execute")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
) -> SecureExecutionResponse:
    invocation = execution_request.invocation

    if (
        invocation.agent_id != claims.sub
        or invocation.session_id != claims.session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token identity does not match request context",
        )

       
    response, _decision = await SecureExecutionService(
        database_session
    ).execute(execution_request)

    TOOL_EXECUTIONS_TOTAL.labels(
        status=response.status.value,
        tool_name=response.tool_name,
    ).inc()

    if response.threat_assessment is not None:
        for finding in response.threat_assessment.findings:
            THREATS_DETECTED_TOTAL.labels(
                threat_type=finding.threat_type.value,
                severity=finding.severity.value,
            ).inc()

    return response

@app.post(
    "/v1/threats/analyze",
    response_model=ThreatAssessment,
    tags=["Threat Detection"],
)
async def analyze_runtime_threat(
    request: ThreatAnalysisRequest,
    claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("threat:analyze")),
    ],
) -> ThreatAssessment:
    invocation = request.invocation

    if (
        invocation.agent_id != claims.sub
        or invocation.session_id != claims.session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token identity does not match request context",
        )

    if (
        invocation.agent_id != claims.sub
        or invocation.session_id != claims.session_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token identity does not match request context",
        )

    assessment = ThreatDetector().analyze(invocation)

    for finding in assessment.findings:
        THREATS_DETECTED_TOTAL.labels(
            threat_type=finding.threat_type.value,
            severity=finding.severity.value,
        ).inc()

    return assessment

@app.get(
    "/v1/dashboard/summary",
    response_model=DashboardSummary,
    tags=["Dashboard"],
)
async def get_dashboard_summary(
    _claims: Annotated[
        CapabilityClaims,
        Depends(require_capability("dashboard:read")),
    ],
    database_session: Annotated[
        AsyncSession,
        Depends(get_database_session),
    ],
) -> DashboardSummary:
    return await DashboardService(
        database_session
    ).get_summary()

@app.get(
    "/metrics",
    include_in_schema=False,
)
async def prometheus_metrics() -> Response:
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )