import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.api import db


_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer = HTTPBearer(auto_error=False)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable '{name}'. "
            "Ask the orchestrator/user to set it in the container .env."
        )
    return value


def _jwt_secret() -> str:
    # Required for security; do not default.
    return _required_env("JWT_SECRET")


def _jwt_algorithm() -> str:
    return os.getenv("JWT_ALGORITHM", "HS256")


def _jwt_exp_minutes() -> int:
    return int(os.getenv("JWT_EXPIRES_MINUTES", "10080"))  # default: 7 days


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return _pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    return _pwd_context.verify(password, password_hash)


def _create_access_token(payload: Dict[str, Any], expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, _jwt_secret(), algorithm=_jwt_algorithm())


# PUBLIC_INTERFACE
def create_user_access_token(user_id: UUID, role: str, email: str) -> str:
    """Create a JWT access token for a user."""
    return _create_access_token(
        {"sub": str(user_id), "role": role, "email": email},
        expires_delta=timedelta(minutes=_jwt_exp_minutes()),
    )


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


# PUBLIC_INTERFACE
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Dict[str, Any]:
    """Dependency that returns the current authenticated user row."""
    if credentials is None:
        raise _unauthorized()

    token = credentials.credentials
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[_jwt_algorithm()])
        sub = payload.get("sub")
        if not sub:
            raise _unauthorized("Invalid token payload")
        user_id = UUID(str(sub))
    except (JWTError, ValueError):
        raise _unauthorized("Invalid token")

    user = db.fetch_one(
        "SELECT id, email, full_name, phone, role, is_active, email_verified, created_at, updated_at "
        "FROM users WHERE id=%s",
        [str(user_id)],
    )
    if not user or not user.get("is_active"):
        raise _unauthorized("User inactive or not found")
    return user


# PUBLIC_INTERFACE
def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Dependency that ensures the current user has admin role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
