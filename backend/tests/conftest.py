import pytest
import asyncio
import os
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Ensure testing mode is active
os.environ["TESTING"] = "1"
os.environ.setdefault("SEED_ADMIN_PASSWORD", "AdminSentinel@2026!")
os.environ.setdefault("SEED_ANALYST_PASSWORD", "AnalystSentinel@2026!")
os.environ.setdefault("SEED_VIEWER_PASSWORD", "ViewerSentinel@2026!")
from httpx import AsyncClient, ASGITransport

# Set root directory on python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.main import app
from backend.app.core.security import create_access_token
from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.db.seed_data import seed_all

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="session", autouse=True)
async def initialize_test_database():
    """Initializes databases before tests run."""
    await mongo_manager.connect()
    await neo4j_manager.connect()
    await seed_all(force=True)
    yield
    await mongo_manager.close()
    await neo4j_manager.close()

@pytest.fixture
def admin_token():
    return create_access_token({"sub": "admin", "role": "Administrator", "email": "admin@sentinelgraph.io"})

@pytest.fixture
def analyst_token():
    return create_access_token({"sub": "analyst", "role": "Security Analyst", "email": "analyst@sentinelgraph.io"})

@pytest.fixture
def viewer_token():
    return create_access_token({"sub": "viewer", "role": "Viewer", "email": "viewer@sentinelgraph.io"})

@pytest.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
