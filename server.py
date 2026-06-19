# Fixora API Server
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import asyncio

from config import get_settings, Database
from routes.scan_routes import fail_timed_out_scans
from routes import (
    auth_router,
    repository_router,
    vulnerability_router,
    scan_router,
    ai_debug_router,
    activity_router,
    dashboard_router,
    github_router,
    websocket_router
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await Database.connect_db()

    watchdog_task = None

    async def _scan_timeout_watchdog():
        while True:
            try:
                db = Database.get_db()
                modified = await fail_timed_out_scans(db, timeout_minutes=30)
                if modified:
                    logger.warning(f'Scan timeout watchdog marked {modified} stale scan(s) as failed')
                    
                    # Push WebSocket notification for timed-out scans (M1 fix)
                    try:
                        from services.websocket_manager import get_connection_manager
                        ws_manager = get_connection_manager()
                        
                        # Fetch the scans we just failed so we can notify their owners
                        timed_out_scans = await db.scans.find(
                            {"status": "failed", "phase": "timeout"},
                            {"_id": 0, "id": 1, "user_id": 1}
                        ).to_list(modified)
                        
                        for scan_doc in timed_out_scans:
                            scan_id = scan_doc.get("id")
                            user_id = scan_doc.get("user_id")
                            if scan_id:
                                await ws_manager.send_to_scan(scan_id, {
                                    "type": "scan_failed",
                                    "scan_id": scan_id,
                                    "message": "Scan timed out after 30 minutes without completing."
                                })
                            if user_id:
                                await ws_manager.send_to_user(user_id, {
                                    "type": "scan_failed",
                                    "scan_id": scan_id,
                                    "message": "Scan timed out after 30 minutes without completing."
                                })
                    except Exception as e:
                        logger.error(f'Watchdog WS notification error: {e}')

            except Exception as exc:
                logger.error(f'Scan timeout watchdog error: {exc}')
            await asyncio.sleep(60)

    watchdog_task = asyncio.create_task(_scan_timeout_watchdog())
    logger.info('Application started')
    yield
    # Shutdown
    if watchdog_task:
        watchdog_task.cancel()
        try:
            await watchdog_task
        except asyncio.CancelledError:
            pass
    await Database.close_db()
    logger.info('Application shutdown')

app = FastAPI(
    title='Fixora API',
    description='AI-powered vulnerability scanning platform',
    version='1.0.0',
    lifespan=lifespan
)

# CORS
origins = settings.cors_origins.split(',')
is_wildcard = '*' in origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=not is_wildcard,  # Cannot use credentials when origins contains '*'
    allow_methods=['*'],
    allow_headers=['*'],
)

# API Router
api_router = APIRouter(prefix='/api')

# Include all route modules
api_router.include_router(auth_router)
api_router.include_router(repository_router)
api_router.include_router(vulnerability_router)
api_router.include_router(scan_router)
api_router.include_router(ai_debug_router)
api_router.include_router(activity_router)
api_router.include_router(dashboard_router)
api_router.include_router(github_router)

# Include API router
app.include_router(api_router)

# WebSocket router (not under /api prefix)
app.include_router(websocket_router)

@app.get('/')
async def root():
    return {'message': 'Fixora API v1.0.0', 'status': 'operational'}

@app.get('/health')
async def health():
    return {'status': 'healthy'}

@app.get('/api/health')
async def api_health():
    """Health check endpoint for API (used by GitHub Actions webhook validation)"""
    return {
        'status': 'healthy',
        'service': 'fixora-api',
        'version': '1.0.0'
    }

if __name__ == "__main__":
    import uvicorn
    import os
    
    # Get port from environment variable (Render sets this)
    port = int(os.environ.get("PORT", 8000))
    
    # Bind to 0.0.0.0 so Render can detect the service
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=port,
        reload=False  # Disable reload in production
    )
