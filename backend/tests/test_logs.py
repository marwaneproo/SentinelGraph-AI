import pytest
from httpx import AsyncClient
from backend.app.core.integrity import compute_log_hash, verify_log_integrity

@pytest.mark.asyncio
async def test_log_ingestion_and_sha256_hash(async_client: AsyncClient, analyst_token: str):
    log_payload = {
        "server_id": "SRV-PROD-APP-02",
        "server_name": "api.corp.internal",
        "source_ip": "192.168.1.55",
        "event_type": "AUTH_SUCCESS",
        "severity": "INFO",
        "username": "alice.security",
        "message": "User alice.security logged into portal via MFA token",
        "details": {"mfa_method": "TOTP"}
    }
    response = await async_client.post(
        "/api/v1/logs",
        json=log_payload,
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert response.status_code == 201
    data = response.json()
    assert "integrity_hash" in data
    assert len(data["integrity_hash"]) == 64 # SHA-256 length

    # Verify log integrity endpoint
    log_id = data["_id"]
    verify_res = await async_client.get(
        f"/api/v1/logs/{log_id}/verify",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["integrity_valid"] is True
    assert v_data["calculated_hash"] == data["integrity_hash"]
    assert v_data["stored_hash"] == data["integrity_hash"]

def test_sha256_tamper_detection():
    # Canonical log doc
    doc = {
        "timestamp": "2026-11-08T12:00:00+00:00",
        "server_id": "SRV-FINANCE-DB-03",
        "source_ip": "10.0.1.50",
        "event_type": "SQL_QUERY",
        "severity": "INFO",
        "username": "clara.fin",
        "details": {"table": "ledger"},
        "prev_hash": "GENESIS_ROOT"
    }
    original_hash = compute_log_hash(
        timestamp=doc["timestamp"],
        server_id=doc["server_id"],
        source_ip=doc["source_ip"],
        event_type=doc["event_type"],
        severity=doc["severity"],
        username=doc["username"],
        details=doc["details"],
        prev_hash=doc["prev_hash"]
    )
    doc["integrity_hash"] = original_hash
    assert verify_log_integrity(doc) is True

    # Malicious actor tampers with username
    tampered_doc = dict(doc)
    tampered_doc["username"] = "attacker"
    assert verify_log_integrity(tampered_doc) is False

def test_v2_hash_covers_normalized_display_fields():
    doc = {
        "timestamp": "2026-11-08T12:00:00+00:00",
        "server_id": "SRV-01",
        "server_name": "app.internal",
        "source_ip": "198.51.100.10",
        "destination_ip": "10.0.0.2",
        "event_type": "AUTH_FAILED",
        "severity": "HIGH",
        "username": "analyst",
        "message": "failed login",
        "details": {"method": "ssh"},
        "prev_hash": "GENESIS_ROOT",
        "integrity_version": 2,
    }
    doc["integrity_hash"] = compute_log_hash(
        timestamp=doc["timestamp"],
        server_id=doc["server_id"],
        server_name=doc["server_name"],
        source_ip=doc["source_ip"],
        destination_ip=doc["destination_ip"],
        event_type=doc["event_type"],
        severity=doc["severity"],
        username=doc["username"],
        source_message=doc["message"],
        details=doc["details"],
        prev_hash=doc["prev_hash"],
    )
    assert verify_log_integrity(doc) is True

    tampered_doc = dict(doc, message="changed after ingestion")
    assert verify_log_integrity(tampered_doc) is False

@pytest.mark.asyncio
async def test_log_search_and_filtering(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/logs?severity=HIGH&page=1&page_size=10",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert "total" in data

@pytest.mark.asyncio
async def test_log_search_uses_literal_substring(async_client: AsyncClient, viewer_token: str):
    response = await async_client.get(
        "/api/v1/logs?search=bob.developer",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert all("bob.developer" in log["message"] for log in data["logs"])
