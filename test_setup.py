import asyncio
import httpx
import jwt
import time
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from services.github_scan_service import GitHubScanService

GITHUB_API_URL = "https://api.github.com"
INSTALLATION_ID = 106998271
TEST_REPO = "Athish06/IP"  # Change this to a repo you want to test

async def get_installation_token():
    """Get installation access token"""
    app_id = os.getenv("GITHUB_APP_ID")
    private_key = os.getenv("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
    
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }
    
    app_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GITHUB_API_URL}/app/installations/{INSTALLATION_ID}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        if response.status_code != 201:
            print(f"Failed to get installation token: {response.text}")
            return None
            
        return response.json().get("token")

async def test_setup():
    print("=" * 60)
    print("Testing Repository Setup")
    print("=" * 60)
    
    # Get installation token
    print("\n1. Getting installation access token...")
    token = await get_installation_token()
    if not token:
        print("   FAILED: Could not get installation token")
        return
    
    print(f"   SUCCESS: Got token starting with {token[:10]}...")
    
    # Create service
    print("\n2. Creating GitHubScanService...")
    owner, repo = TEST_REPO.split("/")
    service = GitHubScanService(token)
    print(f"   is_installation_token: {service.is_installation_token}")
    
    # Check permissions
    print(f"\n3. Checking permissions for {TEST_REPO}...")
    perm_result = await service.check_token_permissions(owner, repo)
    print(f"   can_read: {perm_result['can_read']}")
    print(f"   can_write: {perm_result['can_write']}")
    if perm_result.get('error'):
        print(f"   error: {perm_result['error']}")
    
    if not perm_result['can_write']:
        print("\n   FAILED: No write permission")
        return
    
    # Try to get repo info
    print(f"\n4. Getting repository info...")
    try:
        repo_info = await service.get_repository_info(owner, repo)
        print(f"   SUCCESS: {repo_info.get('full_name')}")
        print(f"   Default branch: {repo_info.get('default_branch')}")
    except Exception as e:
        print(f"   FAILED: {e}")
        return
    
    # Try to check if we can create a branch (without actually creating)
    print(f"\n5. Checking branch access...")
    try:
        default_branch = repo_info.get('default_branch', 'main')
        sha = await service.get_branch_sha(owner, repo, default_branch)
        print(f"   SUCCESS: Got SHA for {default_branch}: {sha[:12]}...")
    except Exception as e:
        print(f"   FAILED: {e}")
        return
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED - Repository setup should work!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_setup())
