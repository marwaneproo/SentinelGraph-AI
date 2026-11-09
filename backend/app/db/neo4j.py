import ipaddress
from typing import Optional, Dict, Any, List
from neo4j import AsyncGraphDatabase, AsyncDriver
from backend.app.config import settings
from backend.app.core.logging import siem_logger

class Neo4jManager:
    driver: Optional[AsyncDriver] = None
    _in_memory: bool = False
    _mock_nodes: Dict[str, Dict[str, Any]] = {}
    _mock_edges: List[Dict[str, Any]] = []

    @staticmethod
    def _is_external_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False

    async def connect(self):
        """Initializes Neo4j async driver and verifies connectivity."""
        import os
        if os.getenv("TESTING") == "1" or settings.ENVIRONMENT == "test":
            self._in_memory = True
            siem_logger.info("Neo4j running in test in-memory mode.")
            return

        try:
            import asyncio
            self.driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_lifetime=300,
                connection_timeout=1.5
            )
            await asyncio.wait_for(self.driver.verify_connectivity(), timeout=1.5)
            self._in_memory = False
            siem_logger.info(f"Connected to Neo4j at {settings.NEO4J_URI}")
            await self.init_schema()
        except Exception as e:
            strict_environment = settings.ENVIRONMENT.lower() in {"production", "prod"}
            siem_logger.warning(f"Neo4j connection failed: {e}.")
            self._in_memory = True
            if self.driver:
                try:
                    await self.driver.close()
                except Exception:
                    pass
            self.driver = None
            if strict_environment:
                raise RuntimeError("Neo4j is required but could not be reached.") from e
            siem_logger.warning("Using the non-persistent in-memory graph adapter for development/testing.")

    async def close(self):
        if self.driver:
            await self.driver.close()
            siem_logger.info("Neo4j driver closed.")

    async def init_schema(self):
        """Initializes constraints and indexes in Neo4j."""
        if self._in_memory or not self.driver:
            return
        
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IP) REQUIRE ip.address IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Server) REQUIRE s.server_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:SecurityEvent) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
        ]
        
        async with self.driver.session() as session:
            for c in constraints:
                try:
                    await session.run(c)
                except Exception as ex:
                    siem_logger.debug(f"Constraint notice: {ex}")
        siem_logger.info("Neo4j graph constraints initialized.")

    async def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Executes a Cypher query with parameters."""
        if self._in_memory or not self.driver:
            return []
            
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def sync_log_event(self, log_doc: Dict[str, Any]):
        """Creates or updates graph entities for a normalized security log."""
        if self._in_memory or not self.driver:
            # Emulate graph storage in-memory for testing
            ip = log_doc.get("source_ip", "0.0.0.0")
            user = log_doc.get("username")
            srv = log_doc.get("server_id")
            event_id = str(log_doc.get("_id", log_doc.get("integrity_hash", "evt-1")))
            
            is_external = self._is_external_ip(ip)
            self._mock_nodes[f"ip_{ip}"] = {
                "id": f"ip_{ip}",
                "label": ip,
                "type": "IP",
                "properties": {"address": ip, "is_external": is_external},
            }
            if user:
                self._mock_nodes[f"user_{user}"] = {"id": f"user_{user}", "label": user, "type": "User", "properties": {"username": user}}
                self._mock_edges.append({"source": f"ip_{ip}", "target": f"user_{user}", "type": "ATTEMPTED_LOGIN"})
            if srv:
                server_name = log_doc.get("server_name", srv)
                self._mock_nodes[f"srv_{srv}"] = {
                    "id": f"srv_{srv}",
                    "label": server_name,
                    "type": "Server",
                    "properties": {"server_id": srv, "hostname": server_name},
                }
                if user:
                    self._mock_edges.append({"source": f"user_{user}", "target": f"srv_{srv}", "type": "TARGETED_ON"})
                self._mock_edges.append({"source": f"ip_{ip}", "target": f"srv_{srv}", "type": "COMMUNICATED_WITH"})
            self._mock_nodes[f"event_{event_id}"] = {
                "id": f"event_{event_id}",
                "label": log_doc.get("event_type", "Security Event"),
                "type": "SecurityEvent",
                "properties": {
                    "id": event_id,
                    "type": log_doc.get("event_type", "GENERIC_EVENT"),
                    "severity": log_doc.get("severity", "LOW"),
                    "timestamp": str(log_doc.get("timestamp")),
                },
            }
            self._mock_edges.append({
                "source": f"ip_{ip}",
                "target": f"event_{event_id}",
                "type": "GENERATED",
            })
            if srv:
                self._mock_edges.append({
                    "source": f"event_{event_id}",
                    "target": f"srv_{srv}",
                    "type": "OCCURRED_ON",
                })
            if user:
                self._mock_edges.append({
                    "source": f"user_{user}",
                    "target": f"event_{event_id}",
                    "type": "INVOLVED_IN",
                })
            return

        cypher = """
        MERGE (ip:IP {address: $source_ip})
        ON CREATE SET ip.first_seen = $timestamp, ip.is_external = $is_external
        ON MATCH SET ip.last_seen = $timestamp

        MERGE (s:Server {server_id: $server_id})
        ON CREATE SET s.hostname = $server_name, s.status = 'ACTIVE'

        MERGE (e:SecurityEvent {id: $event_id})
        ON CREATE SET
            e.type = $event_type,
            e.severity = $severity,
            e.timestamp = $timestamp
        
        MERGE (ip)-[:COMMUNICATED_WITH {timestamp: $timestamp}]->(s)
        MERGE (e)-[:OCCURRED_ON]->(s)
        MERGE (ip)-[:GENERATED]->(e)

        WITH ip, s, e
        WHERE $username IS NOT NULL AND $username <> ''
        MERGE (u:User {username: $username})
        MERGE (ip)-[:ATTEMPTED_LOGIN {
            status: $event_type,
            timestamp: $timestamp
        }]->(u)
        MERGE (u)-[:TARGETED_ON]->(s)
        MERGE (u)-[:INVOLVED_IN]->(e)
        """
        
        is_ext = self._is_external_ip(log_doc.get("source_ip", ""))

        params = {
            "source_ip": log_doc.get("source_ip", "0.0.0.0"),
            "server_id": log_doc.get("server_id", "unknown-srv"),
            "server_name": log_doc.get("server_name", "Unknown Server"),
            "event_id": str(log_doc.get("_id", log_doc.get("integrity_hash", ""))),
            "event_type": log_doc.get("event_type", "GENERIC_EVENT"),
            "severity": log_doc.get("severity", "LOW"),
            "timestamp": str(log_doc.get("timestamp")),
            "username": log_doc.get("username") or "",
            "is_external": is_ext
        }

        try:
            async with self.driver.session() as session:
                await session.run(cypher, params)
        except Exception as e:
            siem_logger.error(f"Failed to sync log event to Neo4j: {e}")

    async def sync_alert(self, alert_doc: Dict[str, Any]):
        """Links an alert to affected entities in the Neo4j graph."""
        if self._in_memory or not self.driver:
            alert_id = str(alert_doc.get("_id", alert_doc.get("alert_id", "alert-1")))
            self._mock_nodes[f"alert_{alert_id}"] = {
                "id": f"alert_{alert_id}",
                "label": alert_doc.get("title", "Alert"),
                "type": "Alert",
                "properties": alert_doc
            }
            if alert_doc.get("source_ip"):
                self._mock_edges.append({
                    "source": f"alert_{alert_id}",
                    "target": f"ip_{alert_doc['source_ip']}",
                    "type": "INVOLVES_IP"
                })
            if alert_doc.get("target_user"):
                self._mock_edges.append({
                    "source": f"alert_{alert_id}",
                    "target": f"user_{alert_doc['target_user']}",
                    "type": "INVOLVES_USER"
                })
            return

        cypher = """
        MERGE (a:Alert {id: $alert_id})
        ON CREATE SET 
            a.title = $title,
            a.severity = $severity,
            a.status = $status,
            a.rule_id = $rule_id,
            a.timestamp = $timestamp,
            a.description = $description

        WITH a
        WHERE $source_ip IS NOT NULL AND $source_ip <> ''
        MERGE (ip:IP {address: $source_ip})
        MERGE (a)-[:INVOLVES_IP]->(ip)

        WITH a
        WHERE $target_user IS NOT NULL AND $target_user <> ''
        MERGE (u:User {username: $target_user})
        MERGE (a)-[:INVOLVES_USER]->(u)

        WITH a
        WHERE $server_id IS NOT NULL AND $server_id <> ''
        MERGE (s:Server {server_id: $server_id})
        MERGE (a)-[:OCCURRED_ON]->(s)
        """
        
        params = {
            "alert_id": str(alert_doc.get("_id", alert_doc.get("alert_id"))),
            "title": alert_doc.get("title", "Threat Alert"),
            "severity": alert_doc.get("severity", "HIGH"),
            "status": alert_doc.get("status", "NEW"),
            "rule_id": alert_doc.get("rule_id", "RULE-CUSTOM"),
            "timestamp": str(alert_doc.get("timestamp")),
            "description": alert_doc.get("description", ""),
            "source_ip": alert_doc.get("source_ip") or "",
            "target_user": alert_doc.get("target_user") or "",
            "server_id": alert_doc.get("server_id") or ""
        }

        try:
            async with self.driver.session() as session:
                await session.run(cypher, params)
        except Exception as e:
            siem_logger.error(f"Failed to sync alert to Neo4j: {e}")

    async def get_threat_topology(self, limit: int = 100) -> Dict[str, Any]:
        """Retrieves nodes and edges for threat visualization."""
        if self._in_memory or not self.driver:
            return {
                "nodes": list(self._mock_nodes.values()),
                "edges": self._mock_edges
            }

        cypher = f"""
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN n, r, m
        LIMIT {limit}
        """
        
        nodes_dict = {}
        edges_list = []
        
        try:
            async with self.driver.session() as session:
                result = await session.run(cypher)
                async for record in result:
                    n = record.get("n")
                    m = record.get("m")
                    r = record.get("r")
                    
                    if n:
                        n_id = str(n.element_id if hasattr(n, "element_id") else n.id)
                        labels = list(n.labels) if hasattr(n, "labels") else ["Node"]
                        label_name = labels[0] if labels else "Node"
                        title = n.get("hostname") or n.get("address") or n.get("username") or n.get("title") or n_id
                        nodes_dict[n_id] = {
                            "id": n_id,
                            "label": str(title),
                            "type": label_name,
                            "properties": dict(n)
                        }
                    
                    if m:
                        m_id = str(m.element_id if hasattr(m, "element_id") else m.id)
                        labels_m = list(m.labels) if hasattr(m, "labels") else ["Node"]
                        label_m = labels_m[0] if labels_m else "Node"
                        title_m = m.get("hostname") or m.get("address") or m.get("username") or m.get("title") or m_id
                        nodes_dict[m_id] = {
                            "id": m_id,
                            "label": str(title_m),
                            "type": label_m,
                            "properties": dict(m)
                        }
                        
                    if r and n and m:
                        n_id = str(n.element_id if hasattr(n, "element_id") else n.id)
                        m_id = str(m.element_id if hasattr(m, "element_id") else m.id)
                        edges_list.append({
                            "source": n_id,
                            "target": m_id,
                            "type": r.type if hasattr(r, "type") else "RELATED_TO",
                            "properties": dict(r) if hasattr(r, "items") else {}
                        })
                        
            return {
                "nodes": list(nodes_dict.values()),
                "edges": edges_list
            }
        except Exception as e:
            siem_logger.error(f"Error fetching threat topology: {e}")
            return {"nodes": list(self._mock_nodes.values()), "edges": self._mock_edges}

    async def get_repeated_attackers(self) -> List[Dict[str, Any]]:
        """Identifies attacker IPs that targeted multiple users or servers."""
        if self._in_memory or not self.driver:
            summaries: Dict[str, Dict[str, Any]] = {}
            for edge in self._mock_edges:
                source_id = edge.get("source", "")
                target_id = edge.get("target", "")
                if not source_id.startswith("ip_") or edge.get("type") not in {
                    "ATTEMPTED_LOGIN", "COMMUNICATED_WITH"
                }:
                    continue
                ip = source_id[len("ip_"):]
                summary = summaries.setdefault(ip, {
                    "ip": ip,
                    "targets": set(),
                    "users": set(),
                    "attempts": 0,
                    "alert_count": 0,
                })
                summary["targets"].add(target_id)
                summary["attempts"] += 1
                target = self._mock_nodes.get(target_id, {})
                if target.get("type") == "User":
                    summary["users"].add(target.get("properties", {}).get("username"))

            for edge in self._mock_edges:
                if edge.get("type") == "INVOLVES_IP":
                    ip_id = edge.get("target", "")
                    ip = ip_id[len("ip_"):] if ip_id.startswith("ip_") else ""
                    if ip in summaries:
                        summaries[ip]["alert_count"] += 1

            results = []
            for summary in summaries.values():
                target_count = len(summary["targets"])
                if target_count < 2 and summary["attempts"] < 5:
                    continue
                results.append({
                    "ip": summary["ip"],
                    "target_count": target_count,
                    "users_targeted": sorted(user for user in summary["users"] if user),
                    "alert_count": summary["alert_count"],
                })
            return sorted(results, key=lambda item: item["alert_count"], reverse=True)[:10]

        cypher = """
        MATCH (ip:IP)-[r:ATTEMPTED_LOGIN|COMMUNICATED_WITH]->(target)
        WITH ip, count(DISTINCT target) AS targets, collect(DISTINCT target.username) AS users, count(r) AS attempts
        WHERE targets >= 2 OR attempts >= 5
        OPTIONAL MATCH (a:Alert)-[:INVOLVES_IP]->(ip)
        RETURN ip.address AS ip, targets AS target_count, [u IN users WHERE u IS NOT NULL] AS users_targeted, count(a) AS alert_count
        ORDER BY alert_count DESC, attempts DESC
        LIMIT 10
        """
        try:
            return await self.execute_query(cypher)
        except Exception as e:
            siem_logger.error(f"Error querying repeated attackers: {e}")
            return []

    async def get_blast_radius(self, identifier: str) -> Dict[str, Any]:
        """Calculates incident blast radius for an IP, User, or Server."""
        if self._in_memory or not self.driver:
            focus_id = None
            for node_id, node in self._mock_nodes.items():
                properties = node.get("properties", {})
                if (
                    node_id in {f"ip_{identifier}", f"user_{identifier}", f"srv_{identifier}"}
                    or identifier in properties.values()
                ):
                    focus_id = node_id
                    break
            if not focus_id:
                return {
                    "focus": identifier,
                    "impacted_nodes": 0,
                    "connected_servers": [],
                    "connected_users": [],
                    "connected_ips": [],
                    "total_alerts": 0,
                }

            adjacency: Dict[str, set] = {}
            for edge in self._mock_edges:
                source, target = edge.get("source"), edge.get("target")
                if source and target:
                    adjacency.setdefault(source, set()).add(target)
                    adjacency.setdefault(target, set()).add(source)

            impacted = set()
            frontier = {focus_id}
            for _ in range(2):
                next_frontier = set()
                for node_id in frontier:
                    next_frontier.update(adjacency.get(node_id, set()) - impacted - {focus_id})
                impacted.update(next_frontier)
                frontier = next_frontier

            nodes = [self._mock_nodes[node_id] for node_id in impacted if node_id in self._mock_nodes]
            return {
                "focus": identifier,
                "impacted_nodes": len(nodes),
                "connected_servers": sorted(
                    node.get("properties", {}).get("server_id")
                    for node in nodes
                    if node.get("type") == "Server" and node.get("properties", {}).get("server_id")
                ),
                "connected_users": sorted(
                    node.get("properties", {}).get("username")
                    for node in nodes
                    if node.get("type") == "User" and node.get("properties", {}).get("username")
                ),
                "connected_ips": sorted(
                    node.get("properties", {}).get("address")
                    for node in nodes
                    if node.get("type") == "IP" and node.get("properties", {}).get("address")
                ),
                "total_alerts": sum(1 for node in nodes if node.get("type") == "Alert"),
            }

        cypher = """
        MATCH (n)
        WHERE n.address = $id OR n.username = $id OR n.server_id = $id OR n.id = $id
        OPTIONAL MATCH (n)-[r*1..2]-(connected)
        RETURN 
            n.address AS ip,
            n.username AS user,
            n.server_id AS server,
            count(DISTINCT connected) AS impacted_nodes,
            collect(DISTINCT connected.server_id) AS servers,
            collect(DISTINCT connected.username) AS users,
            collect(DISTINCT connected.address) AS ips
        """
        try:
            results = await self.execute_query(cypher, {"id": identifier})
            if results:
                row = results[0]
                return {
                    "focus": identifier,
                    "impacted_nodes": row.get("impacted_nodes", 0),
                    "connected_servers": [s for s in row.get("servers", []) if s],
                    "connected_users": [u for u in row.get("users", []) if u],
                    "connected_ips": [i for i in row.get("ips", []) if i],
                }
        except Exception as e:
            siem_logger.error(f"Error computing blast radius: {e}")

        return {"focus": identifier, "impacted_nodes": 0, "connected_servers": [], "connected_users": [], "connected_ips": []}

    async def get_attack_paths(self) -> List[Dict[str, Any]]:
        """Returns external-IP to server paths found in the current graph."""
        if self._in_memory or not self.driver:
            adjacency: Dict[str, List[str]] = {}
            for edge in self._mock_edges:
                if edge.get("type") not in {
                    "ATTEMPTED_LOGIN", "COMMUNICATED_WITH", "TARGETED_ON"
                }:
                    continue
                adjacency.setdefault(edge.get("source", ""), []).append(edge.get("target", ""))

            paths = []
            for source_id, source_node in self._mock_nodes.items():
                properties = source_node.get("properties", {})
                if source_node.get("type") != "IP" or not properties.get("is_external"):
                    continue
                queue = [(source_id, [source_id])]
                while queue and len(paths) < 10:
                    current_id, node_path = queue.pop(0)
                    current = self._mock_nodes.get(current_id, {})
                    if current.get("type") == "Server":
                        server_props = current.get("properties", {})
                        paths.append({
                            "source_ip": properties.get("address"),
                            "destination_server": server_props.get("server_id"),
                            "hostname": server_props.get("hostname"),
                            "hop_distance": len(node_path) - 1,
                            "path_nodes": [
                                f"{self._mock_nodes[node_id].get('type', 'Node')}:"
                                f"{self._mock_nodes[node_id].get('label', node_id)}"
                                for node_id in node_path
                            ],
                        })
                        continue
                    if len(node_path) - 1 >= 3:
                        continue
                    for next_id in adjacency.get(current_id, []):
                        if next_id not in node_path and next_id in self._mock_nodes:
                            queue.append((next_id, node_path + [next_id]))
            return paths

        cypher = """
        MATCH path = (ip:IP)-[:ATTEMPTED_LOGIN|COMMUNICATED_WITH|TARGETED_ON*1..3]->(srv:Server)
        WHERE ip.is_external = true OR ip.address STARTS WITH '185.' OR ip.address STARTS WITH '45.'
        RETURN
            ip.address AS source_ip,
            srv.server_id AS destination_server,
            srv.hostname AS hostname,
            length(path) AS hop_distance,
            [n in nodes(path) | labels(n)[0] + ':' + coalesce(n.address, n.username, n.server_id, 'node')] AS path_nodes
        LIMIT 10
        """
        return await self.execute_query(cypher)

neo4j_manager = Neo4jManager()
