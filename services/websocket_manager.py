# WebSocket connection manager for real-time notifications
from fastapi import WebSocket
from typing import Dict, Set, Optional
import json
import logging
import asyncio

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time notifications"""
    
    def __init__(self):
        # Map user_id -> set of WebSocket connections (for general user notifications)
        self.user_connections: Dict[str, Set[WebSocket]] = {}
        # Map scan_id -> WebSocket connection (one socket per scan)
        self.scan_connections: Dict[str, WebSocket] = {}
        # Map scan_id -> user_id (to track who owns which scan)
        self.scan_owners: Dict[str, str] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, user_id: str, scan_id: Optional[str] = None):
        """Accept a new WebSocket connection for a user or scan"""
        await websocket.accept()
        
        async with self._lock:
            if scan_id:
                # Scan-specific connection
                self.scan_connections[scan_id] = websocket
                self.scan_owners[scan_id] = user_id
                logger.info(f"WebSocket connected for scan {scan_id} (user {user_id}). Active scan sockets: {len(self.scan_connections)}")
            else:
                # General user connection
                if user_id not in self.user_connections:
                    self.user_connections[user_id] = set()
                self.user_connections[user_id].add(websocket)
                logger.info(f"WebSocket connected for user {user_id}. Total user connections: {len(self.user_connections.get(user_id, set()))}")
    
    async def disconnect(self, websocket: WebSocket, user_id: str, scan_id: Optional[str] = None):
        """Remove a WebSocket connection"""
        async with self._lock:
            if scan_id:
                # Remove scan-specific connection
                if scan_id in self.scan_connections:
                    del self.scan_connections[scan_id]
                if scan_id in self.scan_owners:
                    del self.scan_owners[scan_id]
                logger.info(f"WebSocket disconnected for scan {scan_id}. Active scan sockets: {len(self.scan_connections)}")
            else:
                # Remove general user connection
                if user_id in self.user_connections:
                    self.user_connections[user_id].discard(websocket)
                    if not self.user_connections[user_id]:
                        del self.user_connections[user_id]
                logger.info(f"WebSocket disconnected for user {user_id}")
    
    async def disconnect_scan(self, scan_id: str):
        """Close and remove a scan-specific WebSocket connection"""
        async with self._lock:
            if scan_id in self.scan_connections:
                websocket = self.scan_connections[scan_id]
                try:
                    await websocket.close(code=1000, reason="Scan completed")
                except Exception as e:
                    logger.debug(f"Error closing scan socket: {e}")
                del self.scan_connections[scan_id]
                if scan_id in self.scan_owners:
                    del self.scan_owners[scan_id]
                logger.info(f"Closed WebSocket for scan {scan_id}. Active scan sockets: {len(self.scan_connections)}")
                return True
        return False
    
    async def send_to_scan(self, scan_id: str, message: dict) -> bool:
        """Send a message to a specific scan's WebSocket connection"""
        if scan_id not in self.scan_connections:
            logger.debug(f"No active connection for scan {scan_id}")
            return False
        
        try:
            await self.scan_connections[scan_id].send_json(message)
            logger.info(f"Sent message to scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Error sending to scan socket: {e}")
            # Clean up dead connection
            async with self._lock:
                if scan_id in self.scan_connections:
                    del self.scan_connections[scan_id]
                if scan_id in self.scan_owners:
                    del self.scan_owners[scan_id]
            return False
    
    async def send_to_user(self, user_id: str, message: dict):
        """Send a message to all connections for a specific user (including scan connections)"""
        sent = False
        
        # Send to general user connections
        if user_id in self.user_connections:
            dead_connections = set()
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_json(message)
                    sent = True
                except Exception as e:
                    logger.error(f"Error sending to user websocket: {e}")
                    dead_connections.add(connection)
            
            # Clean up dead connections
            async with self._lock:
                for conn in dead_connections:
                    self.user_connections[user_id].discard(conn)
        
        # Also send to any scan connections owned by this user
        for scan_id, owner_id in list(self.scan_owners.items()):
            if owner_id == user_id:
                try:
                    if scan_id in self.scan_connections:
                        await self.scan_connections[scan_id].send_json(message)
                        sent = True
                except Exception as e:
                    logger.error(f"Error sending to scan socket {scan_id}: {e}")
        
        return sent
    
    async def broadcast(self, message: dict):
        """Broadcast a message to all connected users"""
        for user_id in list(self.user_connections.keys()):
            await self.send_to_user(user_id, message)
    
    def get_connection_count(self, user_id: str = None) -> int:
        """Get the number of active connections"""
        if user_id:
            user_count = len(self.user_connections.get(user_id, set()))
            scan_count = len([s for s, u in self.scan_owners.items() if u == user_id])
            return user_count + scan_count
        return sum(len(conns) for conns in self.user_connections.values()) + len(self.scan_connections)
    
    def get_scan_connection_count(self) -> int:
        """Get the number of active scan-specific connections"""
        return len(self.scan_connections)
    
    def has_scan_connection(self, scan_id: str) -> bool:
        """Check if a scan has an active WebSocket connection"""
        return scan_id in self.scan_connections


# Global connection manager instance
manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance"""
    return manager
