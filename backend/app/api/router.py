from fastapi import APIRouter
from backend.app.api.auth import router as auth_router
from backend.app.api.logs import router as logs_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.graph import router as graph_router
from backend.app.api.ai import router as ai_router
from backend.app.api.analytics import router as analytics_router
from backend.app.api.servers import router as servers_router
from backend.app.api.rules import router as rules_router

api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(graph_router)
api_router.include_router(ai_router)
api_router.include_router(analytics_router)
api_router.include_router(servers_router)
api_router.include_router(rules_router)
