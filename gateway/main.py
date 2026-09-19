from datetime import UTC, datetime

from fastapi import FastAPI

app = FastAPI(
    title="AgentSentinel",
    description=(
        "Zero-Trust Runtime Security Gateway "
        "for Autonomous AI Agents and MCP Tools"
    ),
    version="0.1.0",
)


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