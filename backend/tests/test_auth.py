import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSentinel@2026!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "Administrator"
    assert data["username"] == "admin"

@pytest.mark.asyncio
async def test_login_invalid_password(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "WrongPassword123!"}
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_me_endpoint(async_client: AsyncClient, admin_token: str):
    response = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["role"] == "Administrator"

@pytest.mark.asyncio
async def test_unauthorized_access_rejected(async_client: AsyncClient):
    response = await async_client.get("/api/v1/auth/me")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_rejects_passwords_over_bcrypt_byte_limit(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "é" * 37}
    )
    assert response.status_code == 422
