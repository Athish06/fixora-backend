"""
Test script for authentication endpoints
"""
import requests
import json

# API base URL
BASE_URL = "http://localhost:8000/api"

# Test user data
test_user = {
    "email": "test@example.com",
    "password": "testpassword123",
    "full_name": "Test User"
}

def test_register():
    """Test user registration"""
    print("\n=== Testing Registration ===")
    response = requests.post(
        f"{BASE_URL}/auth/register",
        json=test_user
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code == 201:
        return response.json()['access_token']
    return None

def test_login():
    """Test user login"""
    print("\n=== Testing Login ===")
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "email": test_user["email"],
            "password": test_user["password"]
        }
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code == 200:
        return response.json()['access_token']
    return None

def test_get_me(token):
    """Test get current user"""
    print("\n=== Testing Get Current User ===")
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(
        f"{BASE_URL}/auth/me",
        headers=headers
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_invalid_login():
    """Test login with invalid credentials"""
    print("\n=== Testing Invalid Login ===")
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "email": test_user["email"],
            "password": "wrongpassword"
        }
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    print("Starting Authentication Tests...")
    print(f"Base URL: {BASE_URL}")
    
    # Test registration
    token = test_register()
    
    if token:
        # Test get current user with token from registration
        test_get_me(token)
    
    # Test login
    token = test_login()
    
    if token:
        # Test get current user with token from login
        test_get_me(token)
    
    # Test invalid login
    test_invalid_login()
    
    print("\n=== Tests Complete ===")
