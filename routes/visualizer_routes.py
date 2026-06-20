# Visualizer routes — serves the animated pipeline trace for a scan
from fastapi import APIRouter, Depends, HTTPException, status
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from services.pipeline_trace_service import build_trace

router = APIRouter(prefix='/visualizer', tags=['Visualizer'])


@router.get('/trace/{scan_id}')
async def get_pipeline_trace(
    scan_id: str,
    current_user: TokenData = Depends(get_current_user),
    db=Depends(get_database)
):
    """
    Return the animation-friendly pipeline trace for a specific scan.

    Reads from existing ai_debug + vulnerabilities collections —
    no new computation, no pipeline changes.  Pure read-only transform.
    """
    # Find the ai_debug doc for this scan
    ai_debug_doc = await db.ai_debug.find_one(
        {'scan_id': scan_id},
        {'_id': 0}
    )
    if not ai_debug_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='No AI debug data found for this scan. Run a scan first.'
        )

    # Verify ownership — user must own the repository
    repo_id = ai_debug_doc.get('repository_id')
    repo = await db.repositories.find_one(
        {'id': repo_id, 'user_id': current_user.user_id}
    )
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied'
        )

    # Fetch vulnerabilities for this scan (for comparison stage)
    vulnerabilities = await db.vulnerabilities.find(
        {'repository_id': repo_id, 'scan_id': scan_id},
        {
            '_id': 0,
            'rule_id': 1,
            'title': 1,
            'severity': 1,
            'file_path': 1,
            'type': 1,
            'line_number': 1,
        }
    ).to_list(5000)

    # Build the trace JSON
    trace = build_trace(ai_debug_doc, vulnerabilities)

    # Add repository name for display
    trace['repository'] = repo.get('full_name') or repo.get('name', repo_id)

    return trace
