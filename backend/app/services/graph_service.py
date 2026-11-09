from typing import Dict, Any, List
from backend.app.db.neo4j import neo4j_manager

class GraphService:
    async def get_threat_topology(self, limit: int = 150) -> Dict[str, Any]:
        """Returns nodes and links formatted for the frontend force graph."""
        return await neo4j_manager.get_threat_topology(limit=limit)

    async def get_repeated_attackers(self) -> List[Dict[str, Any]]:
        """Identifies attacker IPs executing multi-target operations."""
        return await neo4j_manager.get_repeated_attackers()

    async def get_blast_radius(self, identifier: str) -> Dict[str, Any]:
        """Calculates impact blast radius around a node."""
        return await neo4j_manager.get_blast_radius(identifier)

    async def get_attack_paths(self) -> List[Dict[str, Any]]:
        """Returns attack paths derived from the current Neo4j or test graph."""
        return await neo4j_manager.get_attack_paths()

graph_service = GraphService()
