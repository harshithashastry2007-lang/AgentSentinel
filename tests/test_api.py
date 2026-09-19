from fastapi.testclient import TestClient

from gateway.main import app

client = TestClient(app)


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "operational"
    assert response.json()["mode"] == "zero-trust"


def test_critical_request_is_denied_by_api() -> None:
    response = client.post(
        "/v1/evaluate",
        json={
            "agent_id": "rogue-agent-01",
            "session_id": "session-003",
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


def test_hidden_admin_override_is_rejected_by_api() -> None:
    response = client.post(
        "/v1/evaluate",
        json={
            "agent_id": "rogue-agent-01",
            "session_id": "session-004",
            "tool_name": "filesystem",
            "action": "read_file",
            "admin_override": True,
        },
    )

    assert response.status_code == 422