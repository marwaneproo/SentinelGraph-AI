from enum import Enum
from typing import List, Callable
from fastapi import Depends, HTTPException, status
from backend.app.core.security import oauth2_scheme, decode_access_token

class UserRole(str, Enum):
    ADMIN = "Administrator"
    ANALYST = "Security Analyst"
    VIEWER = "Viewer"

def get_current_user_payload(token: str = Depends(oauth2_scheme)) -> dict:
    """Dependency that extracts and validates the JWT payload."""
    payload = decode_access_token(token)
    return payload

def require_roles(allowed_roles: List[str]) -> Callable:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces that the current authenticated user possesses one of the allowed roles.
    """
    def role_checker(payload: dict = Depends(get_current_user_payload)) -> dict:
        user_role = payload.get("role")
        if not user_role or user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(allowed_roles)}. Your role: {user_role}",
            )
        return payload
    return role_checker

# Pre-defined convenience role requirements
require_admin = require_roles([UserRole.ADMIN.value])
require_analyst_or_admin = require_roles([UserRole.ADMIN.value, UserRole.ANALYST.value])
require_any_authenticated = require_roles([
    UserRole.ADMIN.value,
    UserRole.ANALYST.value,
    UserRole.VIEWER.value
])
