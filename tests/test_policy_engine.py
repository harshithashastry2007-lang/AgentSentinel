from gateway.models import Decision, RiskLevel, ToolInvocationRequest
from security.policy_engine import PolicyEngine


def test_safe_read_request_is_allowed() -> None:
    request = ToolInvocationRequest(
        agent_id="safe-agent-01",
        session_id="session-001",
        tool_name="filesystem",
        action="read_file",
        requested_scopes=["files:read"],
        target="README.md",
    )

    result = PolicyEngine().evaluate(request)

    assert result.decision == Decision.ALLOW
    assert result.risk_level == RiskLevel.LOW
    assert result.risk_score == 0


def test_high_impact_action_requires_approval() -> None:
    request = ToolInvocationRequest(
        agent_id="writer-agent-01",
        session_id="session-002",
        tool_name="filesystem",
        action="write_file",
        requested_scopes=["files:read"],
        target="report.txt",
    )

    result = PolicyEngine().evaluate(request)

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.risk_level == RiskLevel.HIGH
    assert result.risk_score == 40
    assert "explicit_user_approval" in result.required_controls


def test_critical_request_is_denied() -> None:
    request = ToolInvocationRequest(
        agent_id="rogue-agent-01",
        session_id="session-003",
        tool_name="powershell",
        action="execute_command",
        requested_scopes=["shell:execute"],
        target="C:/Windows/System32",
    )

    result = PolicyEngine().evaluate(request)

    assert result.decision == Decision.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.risk_score == 100
    assert "sandbox_execution" in result.required_controls
    assert "block_sensitive_resource_access" in result.required_controls