# Pull Request routes
from fastapi import APIRouter, Depends
from typing import List, Optional
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.pull_request import PullRequest

router = APIRouter(prefix='/pull-requests', tags=['Pull Requests'])

@router.get('', response_model=List[PullRequest])
async def get_pull_requests(
    repository_id: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get pull requests for auto-fixes"""
    # Get user's repositories
    user_repos = await db.repositories.find({'user_id': current_user.user_id}, {'_id': 0, 'id': 1}).to_list(1000)
    repo_ids = [r['id'] for r in user_repos]
    
    query = {'repository_id': {'$in': repo_ids}}
    if repository_id:
        query['repository_id'] = repository_id
    
    prs = await db.pull_requests.find(query, {'_id': 0}).to_list(1000)
    return [PullRequest(**pr) for pr in prs]

@router.post('/{pr_id}/auto-fix')
async def trigger_auto_fix(
    pr_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Trigger auto-fix generation for a pull request"""
    # Mock auto-fix (would integrate with Hugging Face)
    return {'status': 'fix_generated', 'message': 'Auto-fix will be implemented with HuggingFace API'}
