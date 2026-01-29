# AI Pattern routes
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.ai_pattern import AIPattern

router = APIRouter(prefix='/ai-patterns', tags=['AI Patterns'])

@router.get('', response_model=List[AIPattern])
async def get_ai_patterns(
    repository_id: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get AI-discovered patterns"""
    # Get user's repositories
    user_repos = await db.repositories.find({'user_id': current_user.user_id}, {'_id': 0, 'id': 1}).to_list(1000)
    repo_ids = [r['id'] for r in user_repos]
    
    query = {'repository_id': {'$in': repo_ids}}
    if repository_id:
        query['repository_id'] = repository_id
    
    patterns = await db.ai_patterns.find(query, {'_id': 0}).to_list(1000)
    return [AIPattern(**p) for p in patterns]

@router.patch('/{pattern_id}/verify')
async def verify_ai_pattern(
    pattern_id: str,
    is_correct: bool,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Verify or reject an AI-discovered pattern"""
    pattern = await db.ai_patterns.find_one({'id': pattern_id}, {'_id': 0})
    if not pattern:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Pattern not found')
    
    # Verify ownership
    repo = await db.repositories.find_one({'id': pattern['repository_id'], 'user_id': current_user.user_id})
    if not repo:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Access denied')
    
    await db.ai_patterns.update_one(
        {'id': pattern_id},
        {'$set': {'user_override': is_correct, 'is_verified': True}}
    )
    
    return {'status': 'updated'}
