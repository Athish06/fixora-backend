import asyncio
import httpx
import jwt
import time
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_API_URL = "https://api.github.com"
INSTALLATION_ID = 106998271

async def test_installation_token():
    # Generate App JWT
    app_id = os.getenv("GITHUB_APP_ID")
    private_key = os.getenv("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
    
    print(f"App ID: {app_id}")
    print(f"Private key loaded: {len(private_key)} chars")
    
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }
    
    try:
        app_jwt = jwt.encode(payload, private_key, algorithm="RS256")
        print(f"App JWT generated successfully")
    except Exception as e:
        print(f"Failed to generate JWT: {e}")
        return
    
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
        
        print(f"Get installation token status: {response.status_code}")
        
        if response.status_code != 201:
            print(f"Error: {response.text}")
            return
            
        token_data = response.json()
        access_token = token_data.get("token")
        permissions = token_data.get("permissions", {})
        
        print(f"Installation token permissions: {permissions}")
        
        # Test accessing a repo
        repo_response = await client.get(
            f"{GITHUB_API_URL}/repos/Athish06/textsummarizer",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        print(f"Repo access status: {repo_response.status_code}")
        
        if repo_response.status_code == 200:
            repo_data = repo_response.json()
            print(f"Repo permissions: {repo_data.get('permissions', {})}")
        else:
            print(f"Repo error: {repo_response.text}")

asyncio.run(test_installation_token())
