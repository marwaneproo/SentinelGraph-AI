import asyncio
import os
import re
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from backend.app.config import settings
from backend.app.core.logging import siem_logger

class MongoManager:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    _in_memory: bool = False
    _mock_collections: Dict[str, List[Dict[str, Any]]] = {}

    async def connect(self):
        """Connect to MongoDB or fallback gracefully to internal memory store for local testing."""
        if os.getenv("TESTING") == "1" or settings.ENVIRONMENT == "test":
            self._in_memory = True
            if not self._mock_collections:
                self._mock_collections = {
                    "users": [],
                    "servers": [],
                    "logs": [],
                    "alerts": [],
                    "detection_rules": [],
                    "ai_analyses": [],
                    "audit_logs": []
                }
            siem_logger.info("MongoDB running in test in-memory mode.")
            return

        try:
            client_options = {"serverSelectionTimeoutMS": 4000}
            if settings.MONGODB_USERNAME:
                client_options.update({
                    "username": settings.MONGODB_USERNAME,
                    "password": settings.MONGODB_PASSWORD,
                    "authSource": settings.MONGODB_AUTH_SOURCE,
                })
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                **client_options
            )
            # Ping database to check live connectivity
            await asyncio.wait_for(self.client.admin.command('ping'), timeout=6)
            self.db = self.client[settings.MONGODB_DB_NAME]
            self._in_memory = False
            siem_logger.info(f"Connected to MongoDB (db: {settings.MONGODB_DB_NAME})")
            await self.create_indexes()
        except Exception as e:
            strict_environment = settings.ENVIRONMENT.lower() in {"production", "prod"}
            siem_logger.warning(f"MongoDB connection failed: {e}.")
            self._in_memory = True
            if self.client:
                self.client.close()
            self.client = None
            self.db = None
            if strict_environment:
                raise RuntimeError("MongoDB is required but could not be reached.") from e
            siem_logger.warning("Using the non-persistent in-memory MongoDB adapter for development/testing.")
            if not self._mock_collections:
                self._mock_collections = {
                    "users": [],
                    "servers": [],
                    "logs": [],
                    "alerts": [],
                    "detection_rules": [],
                    "ai_analyses": [],
                    "audit_logs": []
                }

    async def close(self):
        if self.client:
            self.client.close()
            siem_logger.info("MongoDB connection closed.")

    async def create_indexes(self):
        """Creates SIEM performance indexes on collections."""
        if self._in_memory or self.db is None:
            return
        try:
            # Users
            await self.db.users.create_index("username", unique=True)
            await self.db.users.create_index("email", unique=True)
            
            # Servers
            await self.db.servers.create_index("server_id", unique=True)
            await self.db.servers.create_index("ip_address")
            
            # Logs
            await self.db.logs.create_index([("timestamp", -1)])
            await self.db.logs.create_index([("source_ip", 1), ("timestamp", -1)])
            await self.db.logs.create_index([("username", 1), ("timestamp", -1)])
            await self.db.logs.create_index("event_type")
            await self.db.logs.create_index("severity")
            
            # Alerts
            await self.db.alerts.create_index([("timestamp", -1)])
            await self.db.alerts.create_index("severity")
            await self.db.alerts.create_index("status")
            
            # Rules
            await self.db.detection_rules.create_index("rule_id", unique=True)
            
            siem_logger.info("MongoDB SIEM indexes verified.")
        except Exception as e:
            siem_logger.error(f"Error creating MongoDB indexes: {e}")

    def get_collection(self, collection_name: str):
        if self._in_memory or self.db is None:
            return InMemoryCollection(self._mock_collections.setdefault(collection_name, []))
        return self.db[collection_name]

class InMemoryCursor:
    """Async cursor emulation for in-memory MongoDB fallback."""
    def __init__(self, data: List[Dict[str, Any]]):
        self._data = list(data)
        self._index = 0

    def sort(self, key_or_list, direction=1):
        if isinstance(key_or_list, list):
            key, direction = key_or_list[0]
        else:
            key = key_or_list
        reverse = (direction == -1)
        self._data.sort(key=lambda x: str(x.get(key, "")), reverse=reverse)
        return self

    def skip(self, count: int):
        self._data = self._data[count:]
        return self

    def limit(self, count: int):
        self._data = self._data[:count]
        return self

    async def to_list(self, length: Optional[int] = None):
        if length is not None:
            return self._data[:length]
        return self._data

    def __aiter__(self):
        self._index = 0
        return self

    async def __anext__(self):
        if self._index < len(self._data):
            val = self._data[self._index]
            self._index += 1
            return val
        raise StopAsyncIteration

class InMemoryCollection:
    """Minimal async collection mock supporting filter, pagination, and projection."""
    def __init__(self, storage: List[Dict[str, Any]]):
        self.storage = storage

    def _matches(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for k, v in query.items():
            if k == "$or":
                if not any(self._matches(doc, subq) for subq in v):
                    return False
                continue
            if isinstance(v, dict):
                doc_val = doc.get(k)
                for op, op_val in v.items():
                    if op == "$options":
                        continue
                    if op == "$gte" and not (doc_val is not None and doc_val >= op_val):
                        return False
                    if op == "$lte" and not (doc_val is not None and doc_val <= op_val):
                        return False
                    if op == "$gt" and not (doc_val is not None and doc_val > op_val):
                        return False
                    if op == "$lt" and not (doc_val is not None and doc_val < op_val):
                        return False
                    if op == "$in" and not (doc_val in op_val):
                        return False
                    if op == "$ne" and not (doc_val != op_val):
                        return False
                    if op == "$regex":
                        flags = re.IGNORECASE if v.get("$options") == "i" else 0
                        try:
                            if not re.search(str(op_val), str(doc_val or ""), flags):
                                return False
                        except re.error:
                            return False
            else:
                if doc.get(k) != v:
                    return False
        return True

    def find(self, query: Optional[Dict[str, Any]] = None, projection: Optional[Dict[str, Any]] = None):
        query = query or {}
        matched = [dict(d) for d in self.storage if self._matches(d, query)]
        return InMemoryCursor(matched)

    async def find_one(self, query: Dict[str, Any], projection: Optional[Dict[str, Any]] = None):
        for doc in self.storage:
            if self._matches(doc, query):
                return dict(doc)
        return None

    async def insert_one(self, document: Dict[str, Any]):
        doc_copy = dict(document)
        if "_id" not in doc_copy:
            import uuid
            doc_copy["_id"] = str(uuid.uuid4())
        self.storage.append(doc_copy)
        class InsertResult:
            inserted_id = doc_copy["_id"]
        return InsertResult()

    async def insert_many(self, documents: List[Dict[str, Any]]):
        inserted_ids = []
        for doc in documents:
            doc_copy = dict(doc)
            if "_id" not in doc_copy:
                import uuid
                doc_copy["_id"] = str(uuid.uuid4())
            self.storage.append(doc_copy)
            inserted_ids.append(doc_copy["_id"])
        class InsertManyResult:
            pass
        res = InsertManyResult()
        res.inserted_ids = inserted_ids
        return res

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any]):
        count = 0
        for doc in self.storage:
            if self._matches(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                if "$inc" in update:
                    for key, amount in update["$inc"].items():
                        doc[key] = doc.get(key, 0) + amount
                count = 1
                break
        class UpdateResult:
            modified_count = count
        return UpdateResult()

    async def delete_one(self, query: Dict[str, Any]):
        deleted = 0
        for i, doc in enumerate(self.storage):
            if self._matches(doc, query):
                del self.storage[i]
                deleted = 1
                break
        class DeleteResult:
            deleted_count = deleted
        return DeleteResult()

    async def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for doc in self.storage if self._matches(doc, query))

    async def create_index(self, *args, **kwargs):
        pass

mongo_manager = MongoManager()
