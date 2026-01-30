# WebSocket routes for real-time notifications
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from services.websocket_manager import get_connection_manager
import jwt
import logging
from config.settings import get_settings
from typing import Optional

router = APIRouter(tags=['WebSocket'])
logger = logging.getLogger(__name__)
settings = get_settings()


@router.websocket("/ws/notifications")
async def websocket_notifications(
    websocket: WebSocket,
    token: str = Query(...),
    scan_id: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time notifications.
    Connect with: ws://host/ws/notifications?token=<jwt_token>&scan_id=<optional_scan_id>
    
    If scan_id is provided, this creates a scan-specific connection that will be closed
    after the scan completes. Otherwise, it creates a general user connection.
    """
    manager = get_connection_manager()
    user_id = None
    
    try:
        # Validate JWT token
        try:
            decoded = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.algorithm]
            )
            # JWT uses 'sub' for user_id
            user_id = decoded.get("sub") or decoded.get("user_id")
            
            if not user_id:
                logger.error(f"Invalid token: no user_id or sub in token. Token contents: {decoded}")
                await websocket.close(code=4001, reason="Invalid token: no user_id")
                return
                
        except jwt.ExpiredSignatureError:
            await websocket.close(code=4001, reason="Token expired")
            return
        except jwt.InvalidTokenError as e:
            await websocket.close(code=4001, reason=f"Invalid token: {str(e)}")
            return
        
        # Accept connection (with optional scan_id for scan-specific connections)
        await manager.connect(websocket, user_id, scan_id)
        
        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "message": "WebSocket connected successfully",
            "user_id": user_id,
            "scan_id": scan_id
        })
        
        if scan_id:
            logger.info(f"Scan-specific WebSocket opened for scan {scan_id}")
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for any message (ping/pong handled automatically)
                data = await websocket.receive_json()
                
                # Handle ping from client
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket receive error: {e}")
                break
                
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if user_id:
            await manager.disconnect(websocket, user_id, scan_id)


@router.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status"""
    manager = get_connection_manager()
    return {
        "total_connections": manager.get_connection_count(),
        "scan_connections": manager.get_scan_connection_count()
    }


@router.get("/ws/status")
async def websocket_status():
    """Check WebSocket service status and connection count"""
    manager = get_connection_manager()
    return {
        "status": "active",
        "total_connections": manager.get_connection_count()
    }
