from hmac import compare_digest

from gateway.config import Settings, get_settings


class AuthenticationError(Exception):
    """Raised when an agent identity cannot be trusted."""


class AgentAuthenticator:
    """Authenticates agents without exposing credential details."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def authenticate(
        self,
        agent_id: str,
        api_key: str,
    ) -> str:
        expected_agent_id = self.settings.bootstrap_agent_id
        expected_api_key = (
            self.settings.bootstrap_agent_api_key.get_secret_value()
        )

        agent_matches = compare_digest(agent_id, expected_agent_id)
        key_matches = compare_digest(api_key, expected_api_key)

        if not agent_matches or not key_matches:
            raise AuthenticationError("Agent authentication failed")

        return expected_agent_id