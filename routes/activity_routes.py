# Activity Log routes
from fastapi import APIRouter, Depends
from typing import List
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.activity import ActivityLog

router = APIRouter(prefix='/activity', tags=['Activity'])

@router.get('', response_model=List[ActivityLog])
async def get_activity_log(
    limit: int = 50,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get activity log for the current user"""
    activities = await db.activity_logs.find(
        {'user_id': current_user.user_id},
        {'_id': 0}
    ).sort('timestamp', -1).limit(limit).to_list(limit)
    
    return [ActivityLog(**a) for a in activities]
