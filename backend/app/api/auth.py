from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.app.db.mongodb import mongo_manager
from backend.app.core.security import verify_password, hash_password, create_access_token
from backend.app.core.rbac import require_admin, require_any_authenticated
from backend.app.models.user import UserCreate, UserResponse, Token, LoginRequest
from backend.app.services.audit_service import audit_service
from backend.app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])

@router.post("/login", response_model=Token)
async def login(credentials: LoginRequest):
    """Authenticates user and returns a signed JWT token with user role."""
    users_col = mongo_manager.get_collection("users")
    user = await users_col.find_one({"username": credentials.username})

    if not user or not verify_password(credentials.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

    # Record last login
    await users_col.update_one(
        {"username": credentials.username},
        {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}}
    )

    token_payload = {
        "sub": user["username"],
        "role": user.get("role", "Viewer"),
        "email": user.get("email")
    }

    token = create_access_token(token_payload)

    await audit_service.log_action(
        username=user["username"],
        action="LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=user["username"]
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.get("role", "Viewer"),
        "username": user["username"],
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@router.get("/me")
async def get_current_user_profile(user_payload: dict = Depends(require_any_authenticated)):
    """Returns profile for currently authenticated user."""
    users_col = mongo_manager.get_collection("users")
    user = await users_col.find_one({"username": user_payload.get("sub")})
    if not user:
        return user_payload
    return {
        "username": user["username"],
        "email": user.get("email"),
        "full_name": user.get("full_name"),
        "role": user.get("role"),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login")
    }

@router.get("/users")
async def list_users(admin_payload: dict = Depends(require_admin)):
    """Administrator-only: list all user accounts."""
    users_col = mongo_manager.get_collection("users")
    users = await users_col.find({}).to_list(100)
    result = []
    for u in users:
        result.append({
            "id": str(u.get("_id")),
            "username": u["username"],
            "email": u.get("email"),
            "full_name": u.get("full_name"),
            "role": u.get("role"),
            "is_active": u.get("is_active", True),
            "created_at": u.get("created_at"),
            "last_login": u.get("last_login")
        })
    return result

@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(user_in: UserCreate, admin_payload: dict = Depends(require_admin)):
    """Administrator-only: create a new user account."""
    users_col = mongo_manager.get_collection("users")
    existing = await users_col.find_one({
        "$or": [{"username": user_in.username}, {"email": user_in.email}]
    })
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )

    doc = user_in.model_dump()
    raw_pwd = doc.pop("password")
    doc["password_hash"] = hash_password(raw_pwd)
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await users_col.insert_one(doc)

    await audit_service.log_action(
        username=admin_payload.get("sub", "admin"),
        action="USER_CREATED",
        resource_type="USER",
        resource_id=user_in.username
    )

    return {
        "id": str(res.inserted_id),
        "username": user_in.username,
        "email": user_in.email,
        "role": user_in.role,
        "message": "User created successfully"
    }
