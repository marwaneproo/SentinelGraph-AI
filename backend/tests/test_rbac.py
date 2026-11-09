import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_admin_can_access_users_list(async_client: AsyncClient, admin_token: str):
    response = await async_client.get(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 3

@pytest.mark.asyncio
async def test_analyst_cannot_access_users_list(async_client: AsyncClient, analyst_token: str):
    response = await async_client.get(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]

@pytest.mark.asyncio
async def test_viewer_cannot_register_server(async_client: AsyncClient, viewer_token: str):
    response = await async_client.post(
        "/api/v1/servers",
        json={
            "server_id": "SRV-TEST-UNAUTHORIZED",
            "hostname": "unauth.corp.internal",
            "ip_address": "10.0.99.99"
        },
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_viewer_can_read_logs_and_alerts(async_client: AsyncClient, viewer_token: str):
    # Viewer can access logs
    logs_res = await async_client.get(
        "/api/v1/logs",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    
    assert logs_res.status_code == 200
    
    # Viewer can access alerts
    alerts_res = await async_client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert alerts_res.status_code == 200
