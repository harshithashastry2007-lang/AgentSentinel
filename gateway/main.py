from datetime import UTC, datetime

from fastapi import FastAPI

from gateway.models import PolicyDecision, ToolInvocationRequest
from security.policy_engine import PolicyEngine

app = FastAPI(
    title="AgentSentinel",
    description=(
        "Zero-Trust Runtime Security Gateway "
        "for Autonomous AI Agents and MCP Tools"
    ),
    version="0.1.0",
)

policy_engine = PolicyEngine()


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
    "/v1/evaluate",
    response_model=PolicyDecision,
    tags=["Zero-Trust Policy"],
)
async def evaluate_request(
    request: ToolInvocationRequest,
) -> PolicyDecision:
    return policy_engine.evaluate(request)