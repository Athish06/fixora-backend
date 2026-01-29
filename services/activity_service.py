# Activity logging service
from schemas.activity import ActivityLog
from typing import Optional, Dict, Any

async def log_activity(
    db, 
    user_id: str, 
    action: str, 
    entity_type: str, 
    entity_id: Optional[str] = None, 
    details: Optional[Dict[str, Any]] = None
):
    """Log user activity to the database"""
    activity = ActivityLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details
    )
    
    doc = activity.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    await db.activity_logs.insert_one(doc)
