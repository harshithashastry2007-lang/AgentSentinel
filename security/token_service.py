from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError

from gateway.auth_models import (
    CapabilityClaims,
    CapabilityTokenRequest,
    CapabilityTokenResponse,
)
from gateway.config import Settings, get_settings


class TokenValidationError(Exception):
    """Raised when a capability token cannot be trusted."""


class TokenService:
    issuer = "agentsentinel"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def issue(
        self,
        request: CapabilityTokenRequest,
    ) -> CapabilityTokenResponse:
        now = datetime.now(UTC)
        expires_at = now + timedelta(
            minutes=self.settings.capability_token_minutes
        )
        token_id = uuid4()
        scopes = sorted(set(request.requested_scopes))

        payload = {
            "sub": request.agent_id,
            "sid": request.session_id,
            "scopes": scopes,
            "aud": request.audience,
            "iss": self.issuer,
            "iat": now,
            "exp": expires_at,
            "jti": str(token_id),
        }

        token = jwt.encode(
            payload,
            self.settings.jwt_secret.get_secret_value(),
            algorithm=self.settings.jwt_algorithm,
        )

        return CapabilityTokenResponse(
            access_token=token,
            expires_in=int((expires_at - now).total_seconds()),
            scopes=scopes,
        )

    def validate(
        self,
        token: str,
        audience: str = "agentsentinel-tools",
    ) -> CapabilityClaims:
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret.get_secret_value(),
                algorithms=[self.settings.jwt_algorithm],
                audience=audience,
                issuer=self.issuer,
                options={
                    "require": [
                        "sub",
                        "sid",
                        "scopes",
                        "aud",
                        "iss",
                        "iat",
                        "exp",
                        "jti",
                    ]
                },
            )
        except InvalidTokenError as exc:
            raise TokenValidationError(
                "Capability token is invalid or expired"
            ) from exc

        return CapabilityClaims(
            sub=payload["sub"],
            session_id=payload["sid"],
            scopes=payload["scopes"],
            audience=payload["aud"],
            issuer=payload["iss"],
            issued_at=datetime.fromtimestamp(payload["iat"], UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            token_id=UUID(payload["jti"]),
        )