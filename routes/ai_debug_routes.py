# AI Debug routes — serves the full pipeline debug data (Wrapper Hunter → LLM → Semgrep rules)
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData

router = APIRouter(prefix='/ai-debug', tags=['AI Debug'])


@router.get('')
async def get_ai_debug_list(
    repository_id: Optional[str] = None,
    limit: int = 50,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Return a summary list of AI debug records for all of the user's repos.
    Large payload fields (wrapper_hunter_results, llm_prompt, llm_result,
    custom_rules_yaml) are excluded from the list view — fetch a single record
    via /ai-debug/repo/{repo_id} or /ai-debug/{debug_id} for the full data.
    """
    user_repos = await db.repositories.find(
        {'user_id': current_user.user_id}, {'_id': 0, 'id': 1, 'name': 1, 'full_name': 1}
    ).to_list(1000)
    repo_ids = [r['id'] for r in user_repos]
    repo_names = {r['id']: r.get('full_name') or r.get('name', r['id']) for r in user_repos}

    query = {'repository_id': {'$in': repo_ids}}
    if repository_id:
        if repository_id not in repo_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Access denied')
        query['repository_id'] = repository_id

    # Exclude large payload fields from list view
    projection = {
        '_id': 0,
        'wrapper_hunter_results': 0,
        'llm_prompt': 0,
        'llm_result': 0,
        'custom_rules_yaml': 0,
    }
    records = await db.ai_debug.find(
        query, projection
    ).sort('created_at', -1).limit(limit).to_list(limit)

    # Annotate each record with the human-readable repo name
    for rec in records:
        rec['repository_name'] = repo_names.get(rec.get('repository_id', ''), rec.get('repository_id', ''))

    return records


@router.get('/repo/{repo_id}')
async def get_latest_ai_debug_for_repo(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Return the latest full AI debug record (all pipeline stages) for a repository."""
    repo = await db.repositories.find_one({'id': repo_id, 'user_id': current_user.user_id})
    if not repo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Repository not found')

    record = await db.ai_debug.find_one(
        {'repository_id': repo_id},
        {'_id': 0},
        sort=[('created_at', -1)]
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='No AI debug data found for this repository. Run a scan first.'
        )
    return record


@router.get('/{debug_id}')
async def get_ai_debug_by_id(
    debug_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Return a specific AI debug record by its ID."""
    record = await db.ai_debug.find_one({'id': debug_id}, {'_id': 0})
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='AI debug record not found')

    # Verify ownership
    repo = await db.repositories.find_one(
        {'id': record['repository_id'], 'user_id': current_user.user_id}
    )
    if not repo:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Access denied')

    return record
