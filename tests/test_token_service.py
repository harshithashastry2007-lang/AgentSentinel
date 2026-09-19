import pytest

from gateway.auth_models import CapabilityTokenRequest
from gateway.config import Settings
from security.token_service import TokenService, TokenValidationError


@pytest.fixture
def token_service() -> TokenService:
    settings = Settings(
        jwt_secret="test-secret-key-for-agentsentinel-tests",
        bootstrap_agent_id="demo-agent-01",
        bootstrap_agent_api_key="test-bootstrap-agent-api-key",
        capability_token_minutes=5,
    )
    return TokenService(settings)


def test_token_is_issued_and_validated(
    token_service: TokenService,
) -> None:
    request = CapabilityTokenRequest(
        agent_id="research-agent-01",
        session_id="session-101",
        requested_scopes=["files:read", "files:read"],
    )

    issued = token_service.issue(request)
    claims = token_service.validate(issued.access_token)

    assert claims.sub == "research-agent-01"
    assert claims.session_id == "session-101"
    assert claims.scopes == ["files:read"]
    assert issued.expires_in == 300


def test_tampered_token_is_rejected(
    token_service: TokenService,
) -> None:
    request = CapabilityTokenRequest(
        agent_id="research-agent-01",
        session_id="session-102",
        requested_scopes=["files:read"],
    )

    issued = token_service.issue(request)
    parts = issued.access_token.split(".")
    replacement = "a" if parts[2][0] != "a" else "b"
    parts[2] = replacement + parts[2][1:]
    tampered_token = ".".join(parts)

    with pytest.raises(TokenValidationError):
        token_service.validate(tampered_token)


def test_wrong_audience_is_rejected(
    token_service: TokenService,
) -> None:
    request = CapabilityTokenRequest(
        agent_id="research-agent-01",
        session_id="session-103",
        requested_scopes=["files:read"],
    )

    issued = token_service.issue(request)

    with pytest.raises(TokenValidationError):
        token_service.validate(
            issued.access_token,
            audience="unauthorized-service",
        )