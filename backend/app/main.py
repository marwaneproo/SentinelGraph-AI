from contextlib import asynccontextmanager
from fastapi import FastAPI, Response, status as http_status
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import settings, validate_runtime_settings
from backend.app.core.logging import siem_logger
from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.db.seed_data import seed_all
from backend.app.api.router import api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    siem_logger.info("Initializing SentinelGraph-AI Engine...")
    try:
        validate_runtime_settings()
        await mongo_manager.connect()
        await neo4j_manager.connect()
        try:
            await seed_all()
        except Exception as e:
            siem_logger.error(f"Error during auto-seeding: {e}")
            if settings.ENVIRONMENT.lower() in {"production", "prod"}:
                raise
        yield
    finally:
        siem_logger.info("Shutting down SentinelGraph-AI...")
        await mongo_manager.close()
        await neo4j_manager.close()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Mini SIEM Platform with NoSQL (MongoDB + Neo4j) & AI Analysis",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(api_router, prefix=settings.API_V1_PREFIX)

@app.get("/")
async def root():
    databases_connected = not mongo_manager._in_memory and not neo4j_manager._in_memory
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "HEALTHY" if databases_connected else "DEGRADED",
        "databases": {
            "mongodb": "CONNECTED" if not mongo_manager._in_memory else "IN_MEMORY_NOT_PERSISTENT",
            "neo4j": "CONNECTED" if not neo4j_manager._in_memory else "IN_MEMORY_NOT_PERSISTENT"
        },
        "docs_url": "/docs"
    }

@app.get("/health")
async def health_check(response: Response):
    mongo_connected = not mongo_manager._in_memory and mongo_manager.db is not None
    neo4j_connected = not neo4j_manager._in_memory and neo4j_manager.driver is not None
    ready = mongo_connected and neo4j_connected
    if not ready and settings.ENVIRONMENT.lower() in {"production", "prod"}:
        response.status_code = http_status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "HEALTHY" if ready else "DEGRADED",
        "service": "SentinelGraph-AI Backend",
        "databases": {
            "mongodb": "CONNECTED" if mongo_connected else "UNAVAILABLE",
            "neo4j": "CONNECTED" if neo4j_connected else "UNAVAILABLE",
        },
    }
