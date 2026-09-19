import pytest

from gateway.config import Settings
from security.identity import AgentAuthenticator, AuthenticationError


@pytest.fixture
def authenticator() -> AgentAuthenticator:
    settings = Settings(
        jwt_secret="test-secret-key-for-agentsentinel-tests",
        bootstrap_agent_id="demo-agent-01",
        bootstrap_agent_api_key="test-bootstrap-agent-api-key",
    )
    return AgentAuthenticator(settings)


def test_valid_agent_credentials_are_accepted(
    authenticator: AgentAuthenticator,
) -> None:
    authenticated_id = authenticator.authenticate(
        agent_id="demo-agent-01",
        api_key="test-bootstrap-agent-api-key",
    )

    assert authenticated_id == "demo-agent-01"


def test_invalid_api_key_is_rejected(
    authenticator: AgentAuthenticator,
) -> None:
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(
            agent_id="demo-agent-01",
            api_key="incorrect-api-key",
        )


def test_unknown_agent_is_rejected(
    authenticator: AgentAuthenticator,
) -> None:
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(
            agent_id="unknown-agent",
            api_key="test-bootstrap-agent-api-key",
        )