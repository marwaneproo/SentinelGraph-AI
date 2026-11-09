import os
from typing import List
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "SentinelGraph-AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # MongoDB settings
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "sentinelgraph_db")
    MONGODB_USERNAME: str = os.getenv("MONGODB_USERNAME", "")
    MONGODB_PASSWORD: str = os.getenv("MONGODB_PASSWORD", "")
    MONGODB_AUTH_SOURCE: str = os.getenv("MONGODB_AUTH_SOURCE", "admin")
    
    # Neo4j settings
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "development-only")
    
    # JWT & Auth
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET", "development-only-secret-not-for-production-use"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
    
    # AI / Ollama
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3:latest")
    
    # CORS
    CORS_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ]
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

settings = Settings()


def validate_runtime_settings() -> None:
    """Reject missing or weak secrets before starting a production deployment."""
    if settings.ENVIRONMENT.lower() not in {"production", "prod"}:
        return

    missing_or_weak = []
    if len(settings.JWT_SECRET) < 32 or settings.JWT_SECRET.startswith("development-only-"):
        missing_or_weak.append("JWT_SECRET (at least 32 characters)")
    if len(settings.NEO4J_PASSWORD) < 12 or settings.NEO4J_PASSWORD == "development-only":
        missing_or_weak.append("NEO4J_PASSWORD (at least 12 characters)")
    if not os.getenv("SEED_ADMIN_PASSWORD") or not os.getenv("SEED_ANALYST_PASSWORD") or not os.getenv("SEED_VIEWER_PASSWORD"):
        missing_or_weak.append("SEED_*_PASSWORD values")

    if missing_or_weak:
        raise RuntimeError(
            "Production configuration is incomplete or weak: " + ", ".join(missing_or_weak)
        )
