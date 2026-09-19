from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-based AgentSentinel configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AGENTSENTINEL_",
        extra="ignore",
    )

    app_name: str = "AgentSentinel"
    environment: str = "development"
    database_url: str = "sqlite+aiosqlite:///./runtime_data/agentsentinel.db"

    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    capability_token_minutes: int = Field(default=5, ge=1, le=30)

    bootstrap_agent_id: str = Field(min_length=3, max_length=100)
    bootstrap_agent_api_key: SecretStr


@lru_cache
def get_settings() -> Settings:
    return Settings()