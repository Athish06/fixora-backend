import asyncio
import httpx
import jwt
import time
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_API_URL = "https://api.github.com"
INSTALLATION_ID = 106998271

async def list_installation_repos():
    # Generate App JWT
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
        # Get installation access token
        response = await client.post(
            f"{GITHUB_API_URL}/app/installations/{INSTALLATION_ID}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        if response.status_code != 201:
            print(f"Error getting token: {response.text}")
            return
            
        token_data = response.json()
        access_token = token_data.get("token")
        
        # List repositories the installation can access
        repos_response = await client.get(
            f"{GITHUB_API_URL}/installation/repositories",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        print(f"List repos status: {repos_response.status_code}")
        
        if repos_response.status_code == 200:
            data = repos_response.json()
            print(f"Total repositories accessible: {data.get('total_count', 0)}")
            print("\nRepositories:")
            for repo in data.get("repositories", []):
                print(f"  - {repo.get('full_name')} (permissions: {repo.get('permissions', {})})")
        else:
            print(f"Error: {repos_response.text}")

asyncio.run(list_installation_repos())
