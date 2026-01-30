# Scan routes
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Header, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import jwt
import logging
from datetime import datetime
from config.database import get_database
from config.settings import get_settings
from middleware.auth import get_current_user
from utils.jwt import TokenData
from schemas.scan import ScanRequest, ScanResult
from services.scan_service import run_scan
from services.activity_service import log_activity
from services.websocket_manager import get_connection_manager

router = APIRouter(prefix='/scan', tags=['Scans'])
logger = logging.getLogger(__name__)
settings = get_settings()

@router.post('', response_model=ScanResult)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Start a vulnerability scan for a repository"""
    # Verify repository ownership
    repo = await db.repositories.find_one({
        'id': scan_request.repository_id,
        'user_id': current_user.user_id
    })
    if not repo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Repository not found')
    
    # Create scan result
    scan_result = ScanResult(
        scan_id=str(uuid.uuid4()),
        repository_id=scan_request.repository_id,
        status='pending',
        phase='discovery'
    )
    
    doc = scan_result.model_dump()
    doc['started_at'] = doc['started_at'].isoformat()
    
    await db.scans.insert_one(doc)
    
    # Start background scan
    background_tasks.add_task(run_scan, scan_result.scan_id, scan_request.repository_id, db)
    
    # Log activity
    await log_activity(db, current_user.user_id, 'scan_started', 'repository', scan_request.repository_id)
    
    return scan_result

@router.get('/{scan_id}', response_model=ScanResult)
async def get_scan_status(
    scan_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get the status of a scan"""
    scan = await db.scans.find_one({'scan_id': scan_id}, {'_id': 0})
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')
    
    return ScanResult(**scan)


# ============== WEBHOOK ENDPOINTS FOR GITHUB ACTIONS ==============

class SemgrepResult(BaseModel):
    check_id: str
    path: str
    start: Dict[str, int]
    end: Dict[str, int]
    extra: Dict[str, Any]


class SemgrepPayload(BaseModel):
    results: List[Dict[str, Any]]
    errors: Optional[List[Dict[str, Any]]] = []


class ScanWebhookPayload(BaseModel):
    scan_id: str
    repository: str
    branch: str
    scan_mode: str
    commit_sha: str
    results: SemgrepPayload


@router.post('/webhook/results')
async def receive_scan_results(
    payload: ScanWebhookPayload,
    x_fixora_token: str = Header(..., alias="X-Fixora-Token"),
    db = Depends(get_database)
):
    """
    Webhook endpoint to receive scan results from GitHub Actions.
    Validates the token and processes Semgrep results.
    """
    logger.info(f"Received webhook for scan {payload.scan_id}")
    logger.info(f"Received token: {x_fixora_token}")
    logger.info(f"Using JWT secret key for verification (first 10 chars): {settings.jwt_secret_key[:10]}...")
    
    try:
        # Validate the token
        decoded = jwt.decode(
            x_fixora_token,
            settings.jwt_secret_key,
            algorithms=["HS256"]
        )
        
        logger.info(f"Token decoded successfully: type={decoded.get('type')}, repo_id={decoded.get('repo_id')}")
        
        if decoded.get("type") != "scan_webhook":
            logger.error(f"Invalid token type: {decoded.get('type')}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        repo_id = decoded.get("repo_id")
        user_id = decoded.get("user_id")
        
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    # Get the scan record
    scan = await db.scans.find_one({"id": payload.scan_id})
    
    if not scan:
        logger.warning(f"Scan not found: {payload.scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    logger.info(f"Processing scan results for {payload.scan_id} - Repository: {payload.repository}, Branch: {payload.branch}")
    
    # Process Semgrep results
    semgrep_results = payload.results.results
    vulnerabilities = []
    
    logger.info(f"Processing {len(semgrep_results)} Semgrep results")
    
    for result in semgrep_results:
        vuln_id = str(uuid.uuid4())
        
        # Extract severity from Semgrep metadata
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = metadata.get("severity", "medium").lower()
        
        # Map Semgrep severity to our format
        severity_map = {
            "error": "high",
            "warning": "medium", 
            "info": "low",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        severity = severity_map.get(severity, "medium")
        
        # Extract vulnerability type from rule_id or metadata
        rule_id = result.get("check_id", "")
        vuln_type = metadata.get("category", "security")
        
        # Try to extract a more specific type from rule_id
        # e.g., "javascript.express.security.audit.xss" -> "XSS"
        if "xss" in rule_id.lower():
            vuln_type = "XSS"
        elif "sql-injection" in rule_id.lower() or "sqli" in rule_id.lower():
            vuln_type = "SQL Injection"
        elif "command-injection" in rule_id.lower():
            vuln_type = "Command Injection"
        elif "path-traversal" in rule_id.lower():
            vuln_type = "Path Traversal"
        elif "ssrf" in rule_id.lower():
            vuln_type = "SSRF"
        elif "hardcoded" in rule_id.lower() or "secret" in rule_id.lower():
            vuln_type = "Hardcoded Secret"
        elif "csrf" in rule_id.lower():
            vuln_type = "CSRF"
        elif "open-redirect" in rule_id.lower():
            vuln_type = "Open Redirect"
        elif "insecure" in rule_id.lower():
            vuln_type = "Insecure Configuration"
        else:
            # Use the last part of the rule_id as type
            vuln_type = rule_id.split(".")[-1].replace("-", " ").title()
        
        vulnerability = {
            "id": vuln_id,
            "repository_id": repo_id,
            "scan_id": payload.scan_id,
            "user_id": user_id,
            "type": vuln_type,
            "title": result.get("check_id", "Unknown vulnerability").split(".")[-1].replace("-", " ").title(),
            "description": extra.get("message", "No description available"),
            "severity": severity,
            "file_path": result.get("path", ""),
            "line_number": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "code_snippet": extra.get("lines", ""),
            "rule_id": rule_id,
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "fix_regex": extra.get("fix_regex", None),
            "status": "open",
            "ai_verified": False,
            "ai_confidence": None,
            "ai_reasoning": None,
            "created_at": datetime.now().isoformat(),
            "branch": payload.branch,
            "commit_sha": payload.commit_sha
        }
        
        vulnerabilities.append(vulnerability)
    
    # Insert vulnerabilities
    if vulnerabilities:
        result = await db.vulnerabilities.insert_many(vulnerabilities)
        logger.info(f"Inserted {len(result.inserted_ids)} vulnerabilities into database")
    else:
        logger.info("No vulnerabilities found in scan results")
    
    # Update scan record
    vuln_count = len(vulnerabilities)
    severity_counts = {
        "critical": len([v for v in vulnerabilities if v["severity"] == "critical"]),
        "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
        "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
        "low": len([v for v in vulnerabilities if v["severity"] == "low"])
    }
    
    await db.scans.update_one(
        {"id": payload.scan_id},
        {"$set": {
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.now().isoformat(),
            "vulnerability_count": vuln_count,
            "severity_counts": severity_counts,
            "commit_sha": payload.commit_sha,
            "errors": payload.results.errors
        }}
    )
    
    logger.info(f"Updated scan record: {payload.scan_id} - Status: completed, Vulnerabilities: {vuln_count}")
    
    # Update repository stats
    await db.repositories.update_one(
        {"id": repo_id},
        {"$set": {
            "last_scan": datetime.now().isoformat(),
            "vulnerability_count": vuln_count,
            "last_scan_branch": payload.branch,
            "last_commit_sha": payload.commit_sha
        }}
    )
    
    logger.info(f"Updated repository {repo_id} stats - Total vulnerabilities: {vuln_count}")
    
    # Log activity
    await log_activity(
        db, user_id, 'scan_completed', 'repository', repo_id,
        details={"message": f"Found {vuln_count} vulnerabilities", "vulnerability_count": vuln_count, "severity_counts": severity_counts}
    )
    
    # Store notification for real-time delivery
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": "scan_complete",
        "title": "Scan Completed",
        "message": f"Security scan for {payload.repository} found {vuln_count} vulnerabilities",
        "data": {
            "scan_id": payload.scan_id,
            "repository_id": repo_id,
            "repository": payload.repository,
            "vulnerability_count": vuln_count,
            "severity_counts": severity_counts
        },
        "read": False,
        "created_at": datetime.now().isoformat()
    }
    
    # Insert into DB (this adds _id field to the dict)
    await db.notifications.insert_one(notification)
    
    # Send real-time WebSocket notification (remove _id to avoid serialization error)
    notification_copy = {k: v for k, v in notification.items() if k != '_id'}
    ws_manager = get_connection_manager()
    await ws_manager.send_to_user(user_id, {
        "type": "scan_complete",
        "notification": notification_copy
    })
    
    logger.info(f"Scan {payload.scan_id} completed with {vuln_count} vulnerabilities")
    
    return {
        "success": True,
        "processed": vuln_count,
        "scan_id": payload.scan_id
    }


@router.get('/notifications')
async def get_notifications(
    unread_only: bool = True,
    limit: int = 20,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get notifications for the current user"""
    query = {"user_id": current_user.user_id}
    if unread_only:
        query["read"] = False
    
    notifications = await db.notifications.find(
        query,
        {"_id": 0}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    return notifications


@router.post('/notifications/{notification_id}/read')
async def mark_notification_read(
    notification_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Mark a notification as read"""
    result = await db.notifications.update_one(
        {"id": notification_id, "user_id": current_user.user_id},
        {"$set": {"read": True}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    
    return {"success": True}
