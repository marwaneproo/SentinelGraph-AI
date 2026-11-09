import pytest
from httpx import AsyncClient
from backend.app.services.ai_service import ai_service
from backend.app.services.alert_service import alert_service

@pytest.mark.asyncio
async def test_ai_investigation_graceful_fallback(async_client: AsyncClient, analyst_token: str):
    # Retrieve an existing alert from database
    alerts_data = await alert_service.get_alerts(page=1, page_size=1)
    assert len(alerts_data["alerts"]) > 0
    target_alert = alerts_data["alerts"][0]
    alert_id = target_alert["alert_id"]

    # Trigger AI analysis via endpoint
    response = await async_client.post(
        "/api/v1/ai/analyze",
        json={"alert_id": alert_id},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == alert_id
    assert "summary" in data
    assert "mitre_tactics" in data
    assert len(data["recommended_mitigation"]) > 0
    # Resilient fallback flag is properly exposed
    assert "is_fallback" in data

@pytest.mark.asyncio
async def test_ai_copilot_chat(async_client: AsyncClient, viewer_token: str):
    response = await async_client.post(
        "/api/v1/ai/chat",
        json={"message": "How do I block an attacker IP via iptables?"},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "iptables" in data["response"].lower()
    assert len(data["suggestions"]) > 0
