from typing import Optional
from fastapi import APIRouter, Depends, Query

from backend.app.services.graph_service import graph_service
from backend.app.core.rbac import require_any_authenticated

router = APIRouter(prefix="/graph", tags=["Neo4j Threat Graph"])

@router.get("/topology")
async def get_graph_topology(
    limit: int = Query(150, ge=10, le=500),
    user_payload: dict = Depends(require_any_authenticated)
):
    """Retrieves nodes and edges representing IP, User, Server, Event, and Alert relationships."""
    return await graph_service.get_threat_topology(limit=limit)

@router.get("/attackers")
async def get_repeated_attackers(user_payload: dict = Depends(require_any_authenticated)):
    """Identifies attacker IPs executing operations against multiple users or servers."""
    return await graph_service.get_repeated_attackers()

@router.get("/blast-radius/{identifier}")
async def get_blast_radius(
    identifier: str,
    user_payload: dict = Depends(require_any_authenticated)
):
    """Calculates graph traversal blast radius for an IP, user, or server identifier."""
    return await graph_service.get_blast_radius(identifier)

@router.get("/attack-paths")
async def get_attack_paths(user_payload: dict = Depends(require_any_authenticated)):
    """Traces multi-hop paths from external/adversary IPs into internal protected servers."""
    return await graph_service.get_attack_paths()
