# GitHub App routes
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import RedirectResponse
from config.database import get_database
from config.settings import get_settings
from middleware.auth import get_current_user
from utils.jwt import TokenData
from services.github_scan_service import GitHubScanService, generate_repo_api_token, SHADOW_BRANCH_NAME
from typing import Optional, List
from pydantic import BaseModel
import httpx
import logging
from datetime import datetime
import uuid

router = APIRouter(prefix='/github', tags=['GitHub'])
logger = logging.getLogger(__name__)
settings = get_settings()

# GitHub App OAuth URLs
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"


def get_github_headers(access_token: str) -> dict:
    """Get standard headers for GitHub API requests"""
    return {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


@router.get('/auth')
async def github_auth(current_user: TokenData = Depends(get_current_user)):
    """Redirect to GitHub App OAuth authorization page"""
    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured"
        )
    
    # Build GitHub OAuth URL for GitHub App
    # Using user_id as state to link back after callback
    state = current_user.user_id
    
    # Request all necessary scopes for GitHub App OAuth
    # Note: GitHub App permissions also need to be configured in App settings
    auth_url = (
        f"{GITHUB_AUTHORIZE_URL}"
        f"?client_id={settings.github_client_id}"
        f"&redirect_uri=http://localhost:3000/api/auth/callback/github"
        f"&scope=repo workflow read:user user:email"
        f"&state={state}"
    )
    
    return {"auth_url": auth_url}


@router.post('/callback')
async def github_callback(
    code: str,
    state: str,
    db = Depends(get_database)
):
    """Handle GitHub OAuth callback and exchange code for access token"""
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not provided"
        )
    
    user_id = state  # state contains the user_id
    
    try:
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": "http://localhost:3000/api/auth/callback/github"
                },
                headers={"Accept": "application/json"}
            )
            
            if token_response.status_code != 200:
                logger.error(f"GitHub token exchange failed: {token_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange authorization code"
                )
            
            token_data = token_response.json()
            
            if "error" in token_data:
                logger.error(f"GitHub OAuth error: {token_data}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=token_data.get("error_description", "GitHub authentication failed")
                )
            
            access_token = token_data.get("access_token")
            
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No access token received from GitHub"
                )
            
            # Get GitHub user info
            user_response = await client.get(
                f"{GITHUB_API_URL}/user",
                headers={
                    "Authorization": f"token {access_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }
            )
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to fetch GitHub user info"
                )
            
            github_user = user_response.json()
            
            # Store or update GitHub connection
            github_connection = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "github_user_id": github_user.get("id"),
                "github_username": github_user.get("login"),
                "github_avatar_url": github_user.get("avatar_url"),
                "access_token": access_token,
                "scope": token_data.get("scope", ""),
                "token_type": token_data.get("token_type", "bearer"),
                "connected_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            # Upsert: update if exists, insert if not
            await db.github_connections.update_one(
                {"user_id": user_id},
                {"$set": github_connection},
                upsert=True
            )
            
            logger.info(f"GitHub connected for user {user_id}: {github_user.get('login')}")
            
            return {
                "success": True,
                "github_username": github_user.get("login"),
                "message": "GitHub connected successfully"
            }
            
    except httpx.RequestError as e:
        logger.error(f"GitHub API request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to communicate with GitHub"
        )


@router.get('/status')
async def github_connection_status(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Check if GitHub is connected for the current user"""
    connection = await db.github_connections.find_one(
        {"user_id": current_user.user_id},
        {"_id": 0, "access_token": 0}  # Don't return access token
    )
    
    if not connection:
        return {"connected": False}
    
    return {
        "connected": True,
        "github_username": connection.get("github_username"),
        "github_avatar_url": connection.get("github_avatar_url"),
        "connected_at": connection.get("connected_at")
    }


@router.get('/verify-token')
async def verify_github_token(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Verify GitHub token permissions and scopes"""
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    access_token = connection.get("access_token")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Check token validity and get scopes
            response = await client.get(
                f"{GITHUB_API_URL}/user",
                headers=get_github_headers(access_token)
            )
            
            if response.status_code == 401:
                return {
                    "valid": False,
                    "error": "Token expired or revoked. Please reconnect GitHub."
                }
            
            # Get scopes from response headers
            scopes = response.headers.get("X-OAuth-Scopes", "")
            scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
            
            # Check for required scopes
            required_scopes = ["repo", "workflow"]
            missing_scopes = [s for s in required_scopes if s not in scope_list]
            
            # Check if we can access the installations (for GitHub Apps)
            installation_response = await client.get(
                f"{GITHUB_API_URL}/user/installations",
                headers=get_github_headers(access_token)
            )
            
            has_installations = False
            installations = []
            if installation_response.status_code == 200:
                data = installation_response.json()
                installations = data.get("installations", [])
                has_installations = len(installations) > 0
            
            return {
                "valid": True,
                "scopes": scope_list,
                "stored_scope": connection.get("scope", ""),
                "missing_scopes": missing_scopes,
                "has_required_scopes": len(missing_scopes) == 0,
                "has_github_app_installations": has_installations,
                "installation_count": len(installations),
                "message": "Token is valid" if len(missing_scopes) == 0 else f"Missing required scopes: {', '.join(missing_scopes)}. Please disconnect and reconnect GitHub."
            }
            
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return {
            "valid": False,
            "error": str(e)
        }


@router.delete('/disconnect')
async def disconnect_github(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Disconnect GitHub account"""
    result = await db.github_connections.delete_one({"user_id": current_user.user_id})
    
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No GitHub connection found"
        )
    
    # Optionally remove GitHub-sourced repositories
    # await db.repositories.delete_many({"user_id": current_user.user_id, "source": "github"})
    
    return {"message": "GitHub disconnected successfully"}


@router.get('/repos')
async def get_github_repositories(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Fetch all repositories from connected GitHub account"""
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected. Please connect your GitHub account first."
        )
    
    access_token = connection.get("access_token")
    
    try:
        async with httpx.AsyncClient() as client:
            # Fetch user's repositories
            repos = []
            page = 1
            
            while True:
                response = await client.get(
                    f"{GITHUB_API_URL}/user/repos",
                    params={
                        "per_page": 100,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc"
                    },
                    headers={
                        "Authorization": f"token {access_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"
                    }
                )
                
                if response.status_code == 401:
                    # Token expired or revoked
                    await db.github_connections.delete_one({"user_id": current_user.user_id})
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="GitHub access token expired. Please reconnect your GitHub account."
                    )
                
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to fetch repositories from GitHub"
                    )
                
                page_repos = response.json()
                
                if not page_repos:
                    break
                
                repos.extend(page_repos)
                page += 1
                
                # Safety limit
                if page > 10:
                    break
            
            # Get list of already connected repo IDs
            connected_repos = await db.repositories.find(
                {"user_id": current_user.user_id, "github_id": {"$exists": True}},
                {"github_id": 1}
            ).to_list(1000)
            connected_github_ids = {repo.get("github_id") for repo in connected_repos}
            
            # Format repositories
            formatted_repos = []
            for repo in repos:
                formatted_repos.append({
                    "github_id": repo.get("id"),
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "description": repo.get("description"),
                    "language": repo.get("language"),
                    "url": repo.get("html_url"),
                    "clone_url": repo.get("clone_url"),
                    "private": repo.get("private"),
                    "default_branch": repo.get("default_branch"),
                    "updated_at": repo.get("updated_at"),
                    "stargazers_count": repo.get("stargazers_count"),
                    "is_connected": repo.get("id") in connected_github_ids
                })
            
            return formatted_repos
            
    except httpx.RequestError as e:
        logger.error(f"GitHub API request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to communicate with GitHub"
        )


@router.post('/repos/connect')
async def connect_github_repos(
    repo_ids: list[int],
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Connect selected GitHub repositories"""
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    access_token = connection.get("access_token")
    connected_repos = []
    
    try:
        async with httpx.AsyncClient() as client:
            for github_id in repo_ids:
                # Check if already connected
                existing = await db.repositories.find_one({
                    "user_id": current_user.user_id,
                    "github_id": github_id
                })
                
                if existing:
                    continue
                
                # Fetch repo details from GitHub
                # First get all repos to find this one
                response = await client.get(
                    f"{GITHUB_API_URL}/repositories/{github_id}",
                    headers={
                        "Authorization": f"token {access_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"
                    }
                )
                
                if response.status_code != 200:
                    continue
                
                repo = response.json()
                
                # Create repository entry
                repo_doc = {
                    "id": str(uuid.uuid4()),
                    "user_id": current_user.user_id,
                    "github_id": repo.get("id"),
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "description": repo.get("description") or "",
                    "language": repo.get("language") or "Unknown",
                    "url": repo.get("html_url"),
                    "clone_url": repo.get("clone_url"),
                    "default_branch": repo.get("default_branch"),
                    "private": repo.get("private"),
                    "source": "github",
                    "risk_score": "N/A",
                    "vulnerability_count": 0,
                    "last_scan": None,
                    "created_at": datetime.now().isoformat()
                }
                
                await db.repositories.insert_one(repo_doc)
                connected_repos.append(repo_doc["name"])
        
        return {
            "success": True,
            "connected_count": len(connected_repos),
            "connected_repos": connected_repos
        }
        
    except httpx.RequestError as e:
        logger.error(f"GitHub API request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to communicate with GitHub"
        )


@router.post('/repos/disconnect')
async def disconnect_github_repos(
    repo_ids: list[int],
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Disconnect selected GitHub repositories"""
    result = await db.repositories.delete_many({
        "user_id": current_user.user_id,
        "github_id": {"$in": repo_ids}
    })
    
    return {
        "success": True,
        "disconnected_count": result.deleted_count
    }


# ============== NEW ENDPOINTS FOR SCANNING ==============

class ScanRequest(BaseModel):
    scan_mode: str = "full"  # "full" or "diff"
    branch: str = "main"
    base_commit: Optional[str] = None


@router.get('/repos/{repo_id}/branches')
async def get_repository_branches(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get all branches for a connected repository"""
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    try:
        service = GitHubScanService(connection["access_token"])
        branches = await service.get_branches(owner, repo_name)
        
        return {
            "branches": branches,
            "default_branch": repo.get("default_branch", "main")
        }
    except Exception as e:
        logger.error(f"Failed to get branches: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get('/repos/{repo_id}/tree')
async def get_repository_file_tree(
    repo_id: str,
    branch: str = Query(default="main"),
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get file tree structure for a repository branch"""
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    try:
        service = GitHubScanService(connection["access_token"])
        file_tree = await service.get_file_tree(owner, repo_name, branch)
        
        return {
            "branch": branch,
            "tree": file_tree
        }
    except Exception as e:
        logger.error(f"Failed to get file tree: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post('/repos/{repo_id}/setup')
async def setup_repository_for_scanning(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Setup a repository for Fixora scanning:
    - Creates shadow branch
    - Injects secrets
    - Pushes workflow file
    """
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Check if already setup
    if repo.get("scan_setup_complete"):
        return {
            "success": True,
            "message": "Repository already setup for scanning",
            "already_setup": True
        }
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    try:
        service = GitHubScanService(connection["access_token"])
        
        # Generate API token for this repository
        api_token = generate_repo_api_token(repo_id, current_user.user_id)
        api_url = settings.backend_url or "http://localhost:8000"
        
        # Setup the repository
        result = await service.setup_repository_for_scanning(
            owner, repo_name, api_token, api_url
        )
        
        if result["success"]:
            # Update repository as setup complete
            await db.repositories.update_one(
                {"id": repo_id},
                {"$set": {
                    "scan_setup_complete": True,
                    "scan_api_token": api_token,
                    "setup_at": datetime.now().isoformat()
                }}
            )
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to setup repository: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post('/repos/{repo_id}/scan')
async def start_repository_scan(
    repo_id: str,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Start a security scan for a repository.
    Returns immediately - scan runs in background via GitHub Actions.
    """
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    service = GitHubScanService(connection["access_token"])
    api_url = settings.backend_url or "http://localhost:8000"
    
    # Get repository info to get default branch
    repo_info = await service.get_repository_info(owner, repo_name)
    default_branch = repo_info.get("default_branch", "main")
    
    # Check if setup is complete, if not do it first
    if not repo.get("scan_setup_complete"):
        try:
            api_token = generate_repo_api_token(repo_id, current_user.user_id)
            
            setup_result = await service.setup_repository_for_scanning(
                owner, repo_name, api_token, api_url
            )
            
            if not setup_result["success"]:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to setup repository: {setup_result.get('error')}"
                )
            
            await db.repositories.update_one(
                {"id": repo_id},
                {"$set": {
                    "scan_setup_complete": True,
                    "scan_api_token": api_token,
                    "setup_at": datetime.now().isoformat()
                }}
            )
            
            # Wait for GitHub to index the workflow file
            import asyncio
            logger.info("Waiting for GitHub to index workflow file...")
            await asyncio.sleep(5)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to setup repository: {str(e)}"
            )
    else:
        # For existing setups, ensure secrets are up to date (auto-refresh)
        api_token = repo.get("scan_api_token")
        if not api_token:
            api_token = generate_repo_api_token(repo_id, current_user.user_id)
        
        # Silently refresh secrets in background to ensure URL is correct
        try:
            await service.inject_repository_secret(owner, repo_name, "FIXORA_API_TOKEN", api_token)
            await service.inject_repository_secret(owner, repo_name, "FIXORA_API_URL", api_url)
            # Also ensure workflow file is up to date
            await service.push_workflow_file(owner, repo_name, default_branch)
        except Exception as e:
            logger.warning(f"Failed to refresh secrets (non-critical): {e}")
    
    # Create scan record
    scan_id = str(uuid.uuid4())
    scan_record = {
        "id": scan_id,
        "repository_id": repo_id,
        "user_id": current_user.user_id,
        "branch": scan_request.branch,
        "scan_mode": scan_request.scan_mode,
        "base_commit": scan_request.base_commit,
        "status": "pending",
        "progress": 0,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "results": None,
        "error": None
    }
    
    await db.scans.insert_one(scan_record)
    
    # Trigger the GitHub Action workflow
    try:
        service = GitHubScanService(connection["access_token"])
        
        triggered = await service.trigger_workflow(
            owner=owner,
            repo=repo_name,
            scan_id=scan_id,
            target_branch=scan_request.branch,
            scan_mode=scan_request.scan_mode,
            base_commit=scan_request.base_commit or ""
        )
        
        if triggered:
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "running", "progress": 10}}
            )
            
            return {
                "success": True,
                "scan_id": scan_id,
                "message": "Scan started successfully",
                "status": "running"
            }
        else:
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"status": "failed", "error": "Failed to trigger workflow"}}
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to trigger scan workflow"
            )
            
    except Exception as e:
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": str(e)}}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get('/repos/{repo_id}/scans')
async def get_repository_scans(
    repo_id: str,
    limit: int = Query(default=10, le=50),
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get scan history for a repository"""
    scans = await db.scans.find(
        {"repository_id": repo_id, "user_id": current_user.user_id},
        {"_id": 0}
    ).sort("started_at", -1).limit(limit).to_list(limit)
    
    return scans


@router.get('/repos/{repo_id}/commits')
async def get_repository_commits(
    repo_id: str,
    branch: str = Query(default="main"),
    limit: int = Query(default=20, le=100),
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get recent commits for a repository branch"""
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    try:
        service = GitHubScanService(connection["access_token"])
        commits = await service.get_commits(owner, repo_name, branch, per_page=limit)
        
        return {
            "branch": branch,
            "commits": commits
        }
    except Exception as e:
        logger.error(f"Failed to get commits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post('/repos/{repo_id}/refresh-secrets')
async def refresh_repository_secrets(
    repo_id: str,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Re-inject GitHub secrets with updated backend URL"""
    # Get repository
    repo = await db.repositories.find_one({
        "id": repo_id,
        "user_id": current_user.user_id
    })
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    # Get GitHub connection
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected"
        )
    
    full_name = repo.get("full_name", "")
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid repository format"
        )
    
    owner, repo_name = full_name.split("/", 1)
    
    try:
        service = GitHubScanService(connection["access_token"])
        
        # Get current API token or generate new one
        api_token = repo.get("scan_api_token")
        if not api_token:
            api_token = generate_repo_api_token(repo_id, current_user.user_id)
        
        # Get backend URL from settings
        api_url = settings.backend_url or "http://localhost:8000"
        
        logger.info(f"Refreshing secrets for {owner}/{repo_name} with URL: {api_url}")
        
        # Get repository info to get default branch
        repo_info = await service.get_repository_info(owner, repo_name)
        default_branch = repo_info.get("default_branch", "main")
        logger.info(f"Default branch for {owner}/{repo_name}: {default_branch}")
        
        # Re-inject secrets
        token_result = await service.inject_repository_secret(
            owner, repo_name, "FIXORA_API_TOKEN", api_token
        )
        logger.info(f"Token secret injection result: {token_result}")
        
        url_result = await service.inject_repository_secret(
            owner, repo_name, "FIXORA_API_URL", api_url
        )
        logger.info(f"URL secret injection result: {url_result}")
        
        # Also push/update the workflow file to default branch
        workflow_result = await service.push_workflow_file(owner, repo_name, default_branch)
        logger.info(f"Workflow file push result: {workflow_result}")
        
        if not workflow_result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to push workflow file to default branch"
            )
        
        if not (token_result and url_result):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to inject one or more secrets"
            )
        
        # Update repository record
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {
                "scan_api_token": api_token,
                "secrets_updated_at": datetime.now().isoformat(),
                "workflow_updated_at": datetime.now().isoformat()
            }}
        )
        
        return {
            "success": True,
            "message": f"Secrets and workflow refreshed successfully with URL: {api_url}",
            "api_url": api_url,
            "workflow_updated": workflow_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to refresh secrets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )