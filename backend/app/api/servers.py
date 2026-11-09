from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.db.mongodb import mongo_manager
from backend.app.models.server import ServerCreate, ServerResponse
from backend.app.core.rbac import require_any_authenticated, require_admin
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/servers", tags=["Server Asset Management"])

@router.get("", response_model=List[ServerResponse])
async def list_servers(user_payload: dict = Depends(require_any_authenticated)):
    """Lists all monitored enterprise server assets and their health status."""
    servers_col = mongo_manager.get_collection("servers")
    logs_col = mongo_manager.get_collection("logs")
    
    servers = await servers_col.find({}).to_list(100)
    result = []
    for s in servers:
        s_id = s.get("server_id")
        log_cnt = await logs_col.count_documents({"server_id": s_id})
        s["_id"] = str(s.get("_id", s_id))
        s["log_count"] = log_cnt
        result.append(s)
    return result

@router.post("", status_code=status.HTTP_201_CREATED)
async def register_server(
    server_in: ServerCreate,
    admin_payload: dict = Depends(require_admin)
):
    """Administrator-only: register a new monitored server asset."""
    servers_col = mongo_manager.get_collection("servers")
    existing = await servers_col.find_one({"server_id": server_in.server_id})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Server ID '{server_in.server_id}' already registered"
        )

    doc = server_in.model_dump()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    doc["last_heartbeat"] = datetime.now(timezone.utc).isoformat()
    res = await servers_col.insert_one(doc)

    await audit_service.log_action(
        username=admin_payload.get("sub", "admin"),
        action="SERVER_REGISTERED",
        resource_type="SERVER",
        resource_id=server_in.server_id
    )

    doc["_id"] = str(res.inserted_id)
    doc["log_count"] = 0
    return doc

@router.delete("/{server_id}")
async def delete_server(server_id: str, admin_payload: dict = Depends(require_admin)):
    """Administrator-only: remove a server asset."""
    servers_col = mongo_manager.get_collection("servers")
    res = await servers_col.delete_one({"server_id": server_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found")

    await audit_service.log_action(
        username=admin_payload.get("sub", "admin"),
        action="SERVER_DELETED",
        resource_type="SERVER",
        resource_id=server_id
    )

    return {"message": f"Server {server_id} removed successfully"}
