# Repository routes
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.repository import Repository, RepositoryCreate
from services.activity_service import log_activity

router = APIRouter(prefix='/repositories', tags=['Repositories'])

@router.get('', response_model=List[Repository])
async def get_repositories(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get all repositories for the current user"""
    repos = await db.repositories.find({'user_id': current_user.user_id}, {'_id': 0}).to_list(1000)
    return [Repository(**repo) for repo in repos]

@router.post('', response_model=Repository, status_code=status.HTTP_201_CREATED)
async def create_repository(
    repo_data: RepositoryCreate,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Create a new repository"""
    # Create repository
    repo = Repository(
        **repo_data.model_dump(),
        user_id=current_user.user_id
    )
    
    doc = repo.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    if doc['last_scan']:
        doc['last_scan'] = doc['last_scan'].isoformat()
    
    await db.repositories.insert_one(doc)
    
    # Log activity
    await log_activity(db, current_user.user_id, 'repo_connected', 'repository', repo.id, {'repo_name': repo.name})
    
    return repo

@router.get('/{repo_id}', response_model=Repository)
async def get_repository(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get a specific repository by ID"""
    repo = await db.repositories.find_one({'id': repo_id, 'user_id': current_user.user_id}, {'_id': 0})
    if not repo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Repository not found')
    return Repository(**repo)

@router.delete('/{repo_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_repository(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Delete a repository and all associated data"""
    result = await db.repositories.delete_one({'id': repo_id, 'user_id': current_user.user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Repository not found')
    
    # Delete associated data
    await db.vulnerabilities.delete_many({'repository_id': repo_id})
    await db.ai_patterns.delete_many({'repository_id': repo_id})
    await db.pull_requests.delete_many({'repository_id': repo_id})
