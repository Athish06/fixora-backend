# Backend configuration settings
from pydantic_settings import BaseSettings
from functools import lru_cache
import os
import secrets as _secrets
import logging as _logging

_settings_logger = _logging.getLogger(__name__)

# Ephemeral fallback: unique per process start, invalidated on restart.
# Prevents hardcoded-secret-in-source while staying usable for local dev.
_EPHEMERAL_SECRET = _secrets.token_hex(64)
_EPHEMERAL_WARNING_EMITTED = False

class Settings(BaseSettings):
    # MongoDB
    mongo_url: str = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    db_name: str = os.environ.get('DB_NAME', 'IP')
    
    # JWT — NO hardcoded fallback.  Empty string triggers ephemeral key.
    secret_key: str = os.environ.get('JWT_SECRET_KEY', '')
    algorithm: str = os.environ.get('JWT_ALGORITHM', 'HS256')
    access_token_expire_minutes: int = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 10080))  # 7 days
    
    # CORS
    cors_origins: str = os.environ.get('CORS_ORIGINS', '*')
    
    # Groq (free LLM API - get key at console.groq.com)
    groq_api_key: str = os.environ.get('GROQ_API_KEY', '')
    
    # GitHub App
    github_client_id: str = os.environ.get('GITHUB_CLIENT_ID', '')
    github_client_secret: str = os.environ.get('GITHUB_CLIENT_SECRET', '')
    github_app_id: str = os.environ.get('GITHUB_APP_ID', '')
    github_app_slug: str = os.environ.get('GITHUB_APP_SLUG', 'fixora26')
    github_private_key: str = os.environ.get('GITHUB_PRIVATE_KEY', '')
    
    # Frontend URL (for OAuth callback redirects)
    frontend_url: str = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    
    # Backend URL for webhooks
    backend_url: str = os.environ.get('BACKEND_URL', 'http://localhost:8000')
    
    # JWT Secret Key — safe accessor that falls back to ephemeral random key
    @property
    def jwt_secret_key(self) -> str:
        global _EPHEMERAL_WARNING_EMITTED
        if self.secret_key:
            return self.secret_key
        if not _EPHEMERAL_WARNING_EMITTED:
            _settings_logger.critical(
                "🚨 JWT_SECRET_KEY is NOT set! Using ephemeral random key. "
                "All tokens will be INVALIDATED on server restart. "
                "SET JWT_SECRET_KEY IN YOUR DEPLOYMENT ENVIRONMENT."
            )
            _EPHEMERAL_WARNING_EMITTED = True
        return _EPHEMERAL_SECRET
    
    class Config:
        env_file = '.env'
        case_sensitive = False
        extra = 'ignore'  # Allow extra fields from .env

@lru_cache()
def get_settings() -> Settings:
    return Settings()
