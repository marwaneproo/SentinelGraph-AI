import pytest
from httpx import AsyncClient
from backend.app.services.graph_service import graph_service

@pytest.mark.asyncio
async def test_threat_topology_endpoint(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/graph/topology",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0

@pytest.mark.asyncio
async def test_repeated_attackers_endpoint(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/graph/attackers",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

@pytest.mark.asyncio
async def test_blast_radius_endpoint(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/graph/blast-radius/185.220.101.5",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "focus" in data
    assert "impacted_nodes" in data

@pytest.mark.asyncio
async def test_attack_paths_endpoint(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/graph/attack-paths",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
