# JWT token utilities
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt
from pydantic import BaseModel
from config.settings import get_settings

settings = get_settings()

class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'

class TokenData(BaseModel):
    user_id: str
    email: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get('sub')
        email: str = payload.get('email')
        
        if user_id is None or email is None:
            return None
        
        return TokenData(user_id=user_id, email=email)
    except jwt.JWTError:
        return None
