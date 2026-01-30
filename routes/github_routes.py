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
from datetime import datetime, timedelta
import uuid
import jwt
import time

router = APIRouter(prefix='/github', tags=['GitHub'])
logger = logging.getLogger(__name__)
settings = get_settings()

# GitHub App OAuth URLs
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"


async def generate_app_jwt() -> str:
    """Generate a JWT for GitHub App authentication
    
    GitHub Apps authenticate using JWTs signed with the app's private key.
    The JWT is valid for max 10 minutes.
    """
    if not settings.github_app_id or not settings.github_private_key:
        logger.warning("GitHub App ID or Private Key not configured")
        return ""
    
    now = int(time.time())
    payload = {
        "iat": now - 60,  # Issued 60 seconds ago (clock skew buffer)
        "exp": now + (10 * 60),  # Expires in 10 minutes
        "iss": settings.github_app_id  # GitHub App ID
    }
    
    # The private key should be the full PEM content
    # Replace escaped newlines with actual newlines
    private_key = settings.github_private_key.replace("\\n", "\n")
    
    try:
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token
    except Exception as e:
        logger.error(f"Failed to generate GitHub App JWT: {e}")
        return ""


async def get_app_jwt_headers() -> dict:
    """Get headers for GitHub App API requests (app-level, not installation-level)"""
    app_jwt = await generate_app_jwt()
    return {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


async def get_installation_access_token(installation_id: int) -> Optional[str]:
    """Get an installation access token for a specific GitHub App installation
    
    Installation access tokens allow the app to act on behalf of the installation
    with the permissions granted during installation.
    """
    app_jwt = await generate_app_jwt()
    if not app_jwt:
        logger.error("Cannot get installation token: No App JWT available")
        return None
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{GITHUB_API_URL}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }
            )
            
            if response.status_code == 201:
                token_data = response.json()
                return token_data.get("token")
            else:
                logger.error(f"Failed to get installation token: {response.status_code} - {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error getting installation access token: {e}")
        return None


async def get_github_access_token(connection: dict) -> Optional[str]:
    """Get the appropriate GitHub access token from a connection.
    
    Prefers installation token (GitHub App) over OAuth access token.
    Returns None if no valid token can be obtained.
    """
    installation_id = connection.get("installation_id")
    
    if installation_id:
        # GitHub App installation - get installation access token
        token = await get_installation_access_token(installation_id)
        if token:
            return token
        logger.warning(f"Failed to get installation token for installation {installation_id}")
    
    # Fall back to OAuth access token
    access_token = connection.get("access_token")
    if access_token:
        return access_token
    
    return None


def get_github_headers(access_token: str) -> dict:
    """Get standard headers for GitHub API requests"""
    return {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


@router.get('/config/check')
async def check_backend_config(current_user: TokenData = Depends(get_current_user)):
    """Check current backend configuration (for debugging)"""
    return {
        "backend_url": settings.backend_url or "http://localhost:8000",
        "backend_url_source": "environment" if settings.backend_url else "default",
        "webhook_endpoint": f"{settings.backend_url or 'http://localhost:8000'}/api/scan/webhook/results"
    }


@router.get('/auth')
async def github_auth(current_user: TokenData = Depends(get_current_user)):
    """Redirect to GitHub App installation page
    
    When 'Request user authorization during installation' is enabled in GitHub App settings,
    GitHub will automatically prompt for OAuth after installation, sending both
    installation_id and code in one callback.
    """
    
    state = current_user.user_id
    app_slug = settings.github_app_slug or "fixora26"
    
    # Redirect to GitHub App installation page
    # After installation, GitHub will automatically prompt for OAuth authorization
    # Then redirect to callback with BOTH installation_id AND code
    install_url = f"https://github.com/apps/{app_slug}/installations/new?state={state}"
    
    return {"auth_url": install_url}


@router.get('/install')
async def github_install(current_user: TokenData = Depends(get_current_user)):
    """Get the GitHub App installation URL (for repo access permissions)"""
    
    app_slug = settings.github_app_slug or "fixora26"
    
    # This URL is for installing the app on repositories
    # User should be directed here after OAuth if they want repo write access
    install_url = f"https://github.com/apps/{app_slug}/installations/new"
    
    return {"install_url": install_url}


@router.post('/callback')
async def github_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    installation_id: Optional[str] = None,
    setup_action: Optional[str] = None,
    db = Depends(get_database)
):
    """Handle GitHub App installation + OAuth callback
    
    When "Request user authorization during installation" is enabled in GitHub App settings,
    GitHub sends BOTH installation_id AND code in the callback.
    We need to handle both to get:
    - installation_id: For repo read/write access (Installed Apps)
    - code: For user identity/OAuth token (Authorized Apps)
    """
    
    user_id = state
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User state not provided"
        )
    
    # Check for existing connection (in case user already OAuth'd and is now installing)
    existing_connection = await db.github_connections.find_one({"user_id": user_id})
    
    github_connection = {
        "id": existing_connection.get("id") if existing_connection else str(uuid.uuid4()),
        "user_id": user_id,
        "connected_at": existing_connection.get("connected_at") if existing_connection else datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    # Preserve existing OAuth data if we have it
    if existing_connection:
        if existing_connection.get("access_token"):
            github_connection["access_token"] = existing_connection["access_token"]
        if existing_connection.get("github_username"):
            github_connection["github_username"] = existing_connection["github_username"]
        if existing_connection.get("github_user_id"):
            github_connection["github_user_id"] = existing_connection["github_user_id"]
        if existing_connection.get("github_avatar_url"):
            github_connection["github_avatar_url"] = existing_connection["github_avatar_url"]
        if existing_connection.get("scope"):
            github_connection["scope"] = existing_connection["scope"]
        if existing_connection.get("token_type"):
            github_connection["token_type"] = existing_connection["token_type"]
    
    try:
        async with httpx.AsyncClient() as client:
            # Use FRONTEND_URL from environment for callback
            frontend_callback = f"{settings.frontend_url.rstrip('/')}/api/auth/callback/github"
            
            # Step 1: Handle OAuth code exchange (gets us user info and access_token)
            if code:
                token_response = await client.post(
                    GITHUB_TOKEN_URL,
                    data={
                        "client_id": settings.github_client_id,
                        "client_secret": settings.github_client_secret,
                        "code": code,
                        "redirect_uri": frontend_callback
                    },
                    headers={"Accept": "application/json"}
                )
                
                if token_response.status_code == 200:
                    token_data = token_response.json()
                    
                    if "error" not in token_data:
                        access_token = token_data.get("access_token")
                        
                        if access_token:
                            # Get GitHub user info
                            user_response = await client.get(
                                f"{GITHUB_API_URL}/user",
                                headers={
                                    "Authorization": f"token {access_token}",
                                    "Accept": "application/vnd.github+json",
                                    "X-GitHub-Api-Version": "2022-11-28"
                                }
                            )
                            
                            if user_response.status_code == 200:
                                github_user = user_response.json()
                                github_connection.update({
                                    "github_user_id": github_user.get("id"),
                                    "github_username": github_user.get("login"),
                                    "github_avatar_url": github_user.get("avatar_url"),
                                    "access_token": access_token,
                                    "scope": token_data.get("scope", ""),
                                    "token_type": token_data.get("token_type", "bearer"),
                                })
                                logger.info(f"OAuth successful for user {user_id}: {github_user.get('login')}")
                    else:
                        logger.warning(f"OAuth token exchange had error: {token_data}")
                else:
                    logger.warning(f"OAuth token exchange failed: {token_response.status_code}")
            
            # Step 2: Handle installation ID (gets us repo access)
            if installation_id:
                github_connection["installation_id"] = int(installation_id)
                github_connection["setup_action"] = setup_action or "install"
                
                # Get installation details for account info
                try:
                    install_response = await client.get(
                        f"{GITHUB_API_URL}/app/installations/{installation_id}",
                        headers=await get_app_jwt_headers()
                    )
                    
                    if install_response.status_code == 200:
                        install_data = install_response.json()
                        account = install_data.get("account", {})
                        
                        # Only update username if we don't have it from OAuth
                        if not github_connection.get("github_username"):
                            github_connection["github_username"] = account.get("login", "Unknown")
                        if not github_connection.get("github_user_id"):
                            github_connection["github_user_id"] = account.get("id")
                        if not github_connection.get("github_avatar_url"):
                            github_connection["github_avatar_url"] = account.get("avatar_url", "")
                        
                        github_connection["account_type"] = account.get("type", "User")
                        logger.info(f"Installation recorded for user {user_id}: installation_id={installation_id}")
                except Exception as e:
                    logger.warning(f"Failed to get installation details: {e}")
            
            # Make sure we have at least one of: installation_id or access_token
            if not installation_id and not github_connection.get("access_token"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Neither installation_id nor valid OAuth code provided"
                )
            
            # Save the connection
            await db.github_connections.update_one(
                {"user_id": user_id},
                {"$set": github_connection},
                upsert=True
            )
            
            username = github_connection.get("github_username", "Unknown")
            has_installation = installation_id is not None or github_connection.get("installation_id") is not None
            
            logger.info(f"GitHub connected for user {user_id}: {username} (installation: {has_installation}, oauth: {github_connection.get('access_token') is not None})")
            
            # Build install URL with state param so we can identify user after installation
            app_slug = settings.github_app_slug or "fixora26"
            install_url = f"https://github.com/apps/{app_slug}/installations/new?state={user_id}"
            
            return {
                "success": True,
                "github_username": username,
                "message": "GitHub connected successfully",
                "installation_id": installation_id,
                "has_installation": has_installation,
                "has_oauth": github_connection.get("access_token") is not None,
                "install_url": install_url if not has_installation else None
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitHub callback failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process GitHub callback: {str(e)}"
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
    
    app_slug = settings.github_app_slug or "fixora26"
    has_installation = connection.get("installation_id") is not None
    
    return {
        "connected": True,
        "github_username": connection.get("github_username"),
        "github_avatar_url": connection.get("github_avatar_url"),
        "connected_at": connection.get("connected_at"),
        "has_installation": has_installation,
        "install_url": f"https://github.com/apps/{app_slug}/installations/new" if not has_installation else None
    }


@router.post('/sync-installation')
async def sync_installation(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Find and sync the user's GitHub App installation
    
    After user installs the app on GitHub, call this to find their installation_id
    by matching their GitHub username with app installations.
    """
    connection = await db.github_connections.find_one({"user_id": current_user.user_id})
    
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub not connected. Please authorize first."
        )
    
    github_username = connection.get("github_username")
    if not github_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub username not found in connection"
        )
    
    # Already has installation
    if connection.get("installation_id"):
        return {
            "success": True,
            "installation_id": connection.get("installation_id"),
            "message": "Installation already synced"
        }
    
    try:
        async with httpx.AsyncClient() as client:
            # Get all installations for the app using App JWT
            headers = await get_app_jwt_headers()
            
            response = await client.get(
                f"{GITHUB_API_URL}/app/installations",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to list installations: {response.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to fetch app installations"
                )
            
            installations = response.json()
            
            # Find installation matching the user's GitHub username
            for install in installations:
                account = install.get("account", {})
                if account.get("login", "").lower() == github_username.lower():
                    installation_id = install.get("id")
                    
                    # Update the connection with installation_id
                    await db.github_connections.update_one(
                        {"user_id": current_user.user_id},
                        {"$set": {
                            "installation_id": installation_id,
                            "account_type": account.get("type", "User"),
                            "updated_at": datetime.now().isoformat()
                        }}
                    )
                    
                    logger.info(f"Synced installation {installation_id} for user {current_user.user_id}")
                    
                    return {
                        "success": True,
                        "installation_id": installation_id,
                        "message": "Installation synced successfully"
                    }
            
            # No installation found
            app_slug = settings.github_app_slug or "fixora26"
            return {
                "success": False,
                "message": "App not installed yet",
                "install_url": f"https://github.com/apps/{app_slug}/installations/new"
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to sync installation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync installation: {str(e)}"
        )


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
    
    # Prefer installation token if available (GitHub App installation)
    # Fall back to OAuth access_token for backward compatibility
    installation_id = connection.get("installation_id")
    access_token = connection.get("access_token")
    
    if installation_id:
        # Get installation access token
        access_token = await get_installation_access_token(installation_id)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub installation access token. Please reconnect GitHub."
            )
    elif not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No GitHub access token found. Please reconnect your GitHub account."
        )
    
    try:
        async with httpx.AsyncClient() as client:
            # Fetch repositories
            # For installation tokens, use /installation/repositories endpoint
            # For user tokens, use /user/repos endpoint
            repos = []
            page = 1
            
            api_url = f"{GITHUB_API_URL}/installation/repositories" if installation_id else f"{GITHUB_API_URL}/user/repos"
            
            while True:
                response = await client.get(
                    api_url,
                    params={
                        "per_page": 100,
                        "page": page,
                        "sort": "updated" if not installation_id else None,
                        "direction": "desc" if not installation_id else None
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
                
                response_data = response.json()
                
                # Installation endpoint returns {"total_count": N, "repositories": [...]}
                # User repos endpoint returns [...]
                if installation_id:
                    page_repos = response_data.get("repositories", [])
                else:
                    page_repos = response_data
                
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
        access_token = await get_github_access_token(connection)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub access token. Please reconnect GitHub."
            )
        
        service = GitHubScanService(access_token)
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
        access_token = await get_github_access_token(connection)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub access token. Please reconnect GitHub."
            )
        
        service = GitHubScanService(access_token)
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
        # Get access token - prefer installation token if available
        installation_id = connection.get("installation_id")
        oauth_token = connection.get("access_token")
        
        logger.info(f"Setup repository {owner}/{repo_name}: installation_id={installation_id}, has_oauth={oauth_token is not None}")
        
        if installation_id:
            access_token = await get_installation_access_token(installation_id)
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get GitHub installation access token. Please reconnect GitHub."
                )
            logger.info(f"Using installation access token for {owner}/{repo_name}")
        elif oauth_token:
            access_token = oauth_token
            logger.info(f"Using OAuth token for {owner}/{repo_name} (no installation)")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No GitHub access token found. Please reconnect your GitHub account."
            )
        
        service = GitHubScanService(access_token)
        
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
    
    # Get access token - prefer installation token if available
    installation_id = connection.get("installation_id")
    access_token = connection.get("access_token")
    
    if installation_id:
        access_token = await get_installation_access_token(installation_id)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub installation access token. Please reconnect GitHub."
            )
    elif not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No GitHub access token found. Please reconnect your GitHub account."
        )
    
    service = GitHubScanService(access_token)
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
        # Always regenerate the token to ensure it uses the current JWT secret key
        api_token = generate_repo_api_token(repo_id, current_user.user_id)
        logger.info(f"Auto-refreshing secrets for {owner}/{repo_name}")
        
        # Silently refresh secrets in background to ensure URL is correct
        try:
            await service.inject_repository_secret(owner, repo_name, "FIXORA_API_TOKEN", api_token)
            await service.inject_repository_secret(owner, repo_name, "FIXORA_API_URL", api_url)
            # Also ensure workflow file is up to date
            await service.push_workflow_file(owner, repo_name, default_branch)
            logger.info(f"Secrets refreshed successfully for {owner}/{repo_name}")
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
        service = GitHubScanService(access_token)
        
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
        access_token = await get_github_access_token(connection)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub access token. Please reconnect GitHub."
            )
        
        service = GitHubScanService(access_token)
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
        access_token = await get_github_access_token(connection)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get GitHub access token. Please reconnect GitHub."
            )
        
        service = GitHubScanService(access_token)
        
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