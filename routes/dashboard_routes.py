# Dashboard routes
from fastapi import APIRouter, Depends
from datetime import datetime, timedelta, timezone
from config.database import get_database
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.dashboard import DashboardStats

router = APIRouter(prefix='/dashboard', tags=['Dashboard'])

@router.get('/stats', response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get dashboard statistics for the current user"""
    # Get user's repositories
    repos = await db.repositories.find({'user_id': current_user.user_id}, {'_id': 0}).to_list(1000)
    repo_ids = [r['id'] for r in repos]
    
    # Count vulnerabilities by severity
    critical = await db.vulnerabilities.count_documents({
        'repository_id': {'$in': repo_ids},
        'severity': 'critical',
        'status': 'open'
    })
    
    high = await db.vulnerabilities.count_documents({
        'repository_id': {'$in': repo_ids},
        'severity': 'high',
        'status': 'open'
    })
    
    total_vulns = await db.vulnerabilities.count_documents({
        'repository_id': {'$in': repo_ids},
        'status': 'open'
    })
    
    # Count pending PRs
    pending_prs = await db.pull_requests.count_documents({
        'repository_id': {'$in': repo_ids},
        'status': {'$in': ['pending', 'open']}
    })
    
    # Calculate risk score
    if critical > 0:
        risk_score = 'F'
    elif high > 5:
        risk_score = 'D'
    elif high > 0 or total_vulns > 10:
        risk_score = 'C'
    elif total_vulns > 5:
        risk_score = 'B'
    else:
        risk_score = 'A'
    
    # Count scans this week
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    scans_this_week = await db.activity_logs.count_documents({
        'user_id': current_user.user_id,
        'action': 'scan_started',
        'timestamp': {'$gte': week_ago.isoformat()}
    })
    
    return DashboardStats(
        total_repositories=len(repos),
        total_vulnerabilities=total_vulns,
        critical_vulnerabilities=critical,
        high_vulnerabilities=high,
        risk_score=risk_score,
        pending_prs=pending_prs,
        ai_false_positives_prevented=int(total_vulns * 0.85),  # Mock: AI filtered 85%
        scans_this_week=scans_this_week
    )
