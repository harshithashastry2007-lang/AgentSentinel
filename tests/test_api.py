from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from gateway.config import Settings
from gateway.main import (
    app,
    get_authenticator,
    get_token_service,
)
from security.identity import AgentAuthenticator
from security.token_service import TokenService


@pytest.fixture
def authenticated_client() -> Generator[TestClient]:
    settings = Settings(
        jwt_secret="test-secret-key-for-agentsentinel-tests",
        bootstrap_agent_id="demo-agent-01",
        bootstrap_agent_api_key="test-bootstrap-agent-api-key",
        capability_token_minutes=5,
    )

    app.dependency_overrides[get_authenticator] = (
        lambda: AgentAuthenticator(settings)
    )
    app.dependency_overrides[get_token_service] = (
        lambda: TokenService(settings)
    )

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def issue_test_token(
    client: TestClient,
    scopes: list[str],
) -> str:
    response = client.post(
        "/v1/auth/token",
        headers={
            "X-Agent-Key": "test-bootstrap-agent-api-key",
        },
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-201",
            "requested_scopes": scopes,
        },
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def test_root_endpoint(authenticated_client: TestClient) -> None:
    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "operational"
    assert response.json()["mode"] == "zero-trust"


def test_valid_agent_receives_capability_token(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/v1/auth/token",
        headers={
            "X-Agent-Key": "test-bootstrap-agent-api-key",
        },
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-201",
            "requested_scopes": ["files:read"],
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 300
    assert body["scopes"] == ["files:read"]
    assert bool(body["access_token"])


def test_invalid_agent_key_is_rejected(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/v1/auth/token",
        headers={
            "X-Agent-Key": "incorrect-api-key",
        },
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-202",
            "requested_scopes": ["policy:evaluate"],
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Agent authentication failed"


def test_missing_capability_token_is_rejected(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/v1/evaluate",
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-203",
            "tool_name": "filesystem",
            "action": "read_file",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Capability token required"


def test_invalid_capability_token_is_rejected(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": "Bearer invalid-token"},
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-204",
            "tool_name": "filesystem",
            "action": "read_file",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid or expired capability token"
    )


def test_insufficient_scope_is_rejected(
    authenticated_client: TestClient,
) -> None:
    token = issue_test_token(
        authenticated_client,
        ["files:read"],
    )

    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-205",
            "tool_name": "filesystem",
            "action": "read_file",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Missing required capability scopes: policy:evaluate"
    )


def test_critical_request_is_denied_by_api(
    authenticated_client: TestClient,
) -> None:
    token = issue_test_token(
        authenticated_client,
        ["policy:evaluate"],
    )

    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-201",
            "tool_name": "powershell",
            "action": "execute_command",
            "arguments": {"command": "example-command"},
            "requested_scopes": ["shell:execute"],
            "target": "C:/Windows/System32",
        },
    )

    body = response.json()

    assert response.status_code == 200
    assert body["decision"] == "deny"
    assert body["risk_level"] == "critical"
    assert body["risk_score"] == 100


def test_hidden_admin_override_is_rejected_by_api(
    authenticated_client: TestClient,
) -> None:
    token = issue_test_token(
        authenticated_client,
        ["policy:evaluate"],
    )

    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "demo-agent-01",
            "session_id": "session-207",
            "tool_name": "filesystem",
            "action": "read_file",
            "admin_override": True,
        },
    )

    assert response.status_code == 422
def test_token_cannot_be_used_by_another_agent(
    authenticated_client: TestClient,
) -> None:
    token = issue_test_token(
        authenticated_client,
        ["policy:evaluate"],
    )

    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "different-agent-01",
            "session_id": "session-201",
            "tool_name": "filesystem",
            "action": "read_file",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Token identity does not match request context"
    )


def test_token_cannot_be_reused_in_another_session(
    authenticated_client: TestClient,
) -> None:
    token = issue_test_token(
        authenticated_client,
        ["policy:evaluate"],
    )

    response = authenticated_client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "demo-agent-01",
            "session_id": "different-session-01",
            "tool_name": "filesystem",
            "action": "read_file",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Token identity does not match request context"
    )