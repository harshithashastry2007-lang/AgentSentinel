import pytest
from pydantic import ValidationError

from gateway.models import (
    Decision,
    PolicyDecision,
    RiskLevel,
    ToolInvocationRequest,
)


def test_valid_tool_request_is_accepted() -> None:
    request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-001",
        tool_name="filesystem",
        action="read_file",
        arguments={"path": "README.md"},
        requested_scopes=["files:read"],
        target="README.md",
    )

    assert request.agent_id == "demo-agent-01"
    assert request.tool_name == "filesystem"
    assert request.requested_scopes == ["files:read"]


def test_unexpected_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolInvocationRequest(
            agent_id="demo-agent-01",
            session_id="session-001",
            tool_name="filesystem",
            action="read_file",
            admin_override=True,
        )


def test_risk_score_above_100_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyDecision(
            request_id="35e814ab-e35e-409a-a01b-866b20969614",
            decision=Decision.DENY,
            risk_level=RiskLevel.CRITICAL,
            risk_score=101,
        )