from routes.auth_routes import router as auth_router
from routes.repository_routes import router as repository_router
from routes.vulnerability_routes import router as vulnerability_router
from routes.scan_routes import router as scan_router
from routes.ai_pattern_routes import router as ai_pattern_router
from routes.activity_routes import router as activity_router
from routes.dashboard_routes import router as dashboard_router
from routes.github_routes import router as github_router
from routes.websocket_routes import router as websocket_router

__all__ = [
    'auth_router',
    'repository_router',
    'vulnerability_router',
    'scan_router',
    'ai_pattern_router',
    'activity_router',
    'dashboard_router',
    'github_router',
    'websocket_router'
]
