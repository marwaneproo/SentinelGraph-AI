import hashlib
import hmac
import json
from typing import Dict, Any, Optional

def compute_log_hash(
    timestamp: str,
    server_id: str,
    source_ip: str,
    event_type: str,
    severity: str,
    username: Optional[str],
    details: Dict[str, Any],
    prev_hash: Optional[str] = None,
    server_name: Optional[str] = None,
    source_message: Optional[str] = None,
    destination_ip: Optional[str] = None,
) -> str:
    """
    Computes a deterministic SHA-256 integrity hash for a security log.
    Includes log chaining (prev_hash) to guarantee tamper-proof audit trails.
    """
    payload = {
        "timestamp": str(timestamp),
        "server_id": str(server_id),
        "source_ip": str(source_ip),
        "event_type": str(event_type),
        "severity": str(severity),
        "username": str(username or ""),
        "details": details or {},
        "prev_hash": str(prev_hash or "GENESIS_SENTINEL_ROOT")
    }
    # Keep version-1 records verifiable while covering all normalized fields in
    # new version-2 records.
    if server_name is not None:
        payload["server_name"] = str(server_name)
    if source_message is not None:
        payload["message"] = str(source_message)
    if destination_ip is not None:
        payload["destination_ip"] = str(destination_ip)
    canonical_repr = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_repr.encode('utf-8')).hexdigest()

def calculate_log_hash(log_doc: Dict[str, Any]) -> str:
    """Recomputes the stored record's hash using its recorded hash version."""
    try:
        version = int(log_doc.get("integrity_version", 1))
    except (TypeError, ValueError):
        return ""
    if version not in {1, 2}:
        return ""
    extra_fields = {}
    if version >= 2:
        extra_fields = {
            "server_name": log_doc.get("server_name"),
            "source_message": log_doc.get("message"),
            "destination_ip": log_doc.get("destination_ip"),
        }
    return compute_log_hash(
        timestamp=log_doc.get("timestamp"),
        server_id=log_doc.get("server_id"),
        source_ip=log_doc.get("source_ip"),
        event_type=log_doc.get("event_type"),
        severity=log_doc.get("severity"),
        username=log_doc.get("username"),
        details=log_doc.get("details", {}),
        prev_hash=log_doc.get("prev_hash"),
        **extra_fields,
    )

def verify_log_integrity(log_doc: Dict[str, Any]) -> bool:
    """Verifies whether the stored integrity_hash matches the normalized record."""
    stored_hash = log_doc.get("integrity_hash")
    if not stored_hash:
        return False
    return hmac.compare_digest(str(stored_hash), calculate_log_hash(log_doc))
