# WebSocket routes for real-time notifications
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from services.websocket_manager import get_connection_manager
import jwt
import logging
from config.settings import get_settings

router = APIRouter(tags=['WebSocket'])
logger = logging.getLogger(__name__)
settings = get_settings()


@router.websocket("/ws/notifications")
async def websocket_notifications(
    websocket: WebSocket,
    token: str = Query(...)
):
    """
    WebSocket endpoint for real-time notifications.
    Connect with: ws://host/ws/notifications?token=<jwt_token>
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
        
        # Accept connection
        await manager.connect(websocket, user_id)
        
        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "message": "WebSocket connected successfully",
            "user_id": user_id
        })
        
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
            await manager.disconnect(websocket, user_id)


@router.get("/ws/status")
async def websocket_status():
    """Check WebSocket service status and connection count"""
    manager = get_connection_manager()
    return {
        "status": "active",
        "total_connections": manager.get_connection_count()
    }
