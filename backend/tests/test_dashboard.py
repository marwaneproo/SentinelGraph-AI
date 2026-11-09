import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_dashboard_analytics_uses_seeded_backend_data(
    async_client: AsyncClient,
    viewer_token: str,
):
    response = await async_client.get(
        "/api/v1/analytics/dashboard",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["kpis"]["total_logs"] > 0
    assert data["kpis"]["total_alerts"] > 0
    assert data["kpis"]["active_servers"] > 0
    assert isinstance(data["timeline"], list)


@pytest.mark.asyncio
async def test_health_reports_database_degradation_in_test_mode(
    async_client: AsyncClient,
):
    response = await async_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "DEGRADED"
