from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from gateway.auth_models import CapabilityClaims
from security.token_service import TokenService, TokenValidationError

bearer_scheme = HTTPBearer(auto_error=False)


def get_token_service() -> TokenService:
    return TokenService()


def require_capability(
    *required_scopes: str,
) -> Callable[..., CapabilityClaims]:
    required = set(required_scopes)

    async def verify_capability(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer_scheme),
        ],
        token_service: Annotated[
            TokenService,
            Depends(get_token_service),
        ],
    ) -> CapabilityClaims:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Capability token required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            claims = token_service.validate(credentials.credentials)
        except TokenValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired capability token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        token_scopes = set(claims.scopes)
        missing_scopes = required - token_scopes

        if missing_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Missing required capability scopes: "
                    + ", ".join(sorted(missing_scopes))
                ),
            )

        return claims

    return verify_capability