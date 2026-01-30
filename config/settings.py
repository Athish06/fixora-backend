# Backend configuration settings
from pydantic_settings import BaseSettings
from functools import lru_cache
import os

class Settings(BaseSettings):
    # MongoDB
    mongo_url: str = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    db_name: str = os.environ.get('DB_NAME', 'IP')
    
    # JWT
    secret_key: str = os.environ.get('JWT_SECRET_KEY', 'your-super-secret-key-change-in-production-min-32-chars')
    algorithm: str = os.environ.get('JWT_ALGORITHM', 'HS256')
    access_token_expire_minutes: int = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', 10080))  # 7 days
    
    # CORS
    cors_origins: str = os.environ.get('CORS_ORIGINS', '*')
    
    # Email Configuration
    sender_email: str = os.environ.get('SENDER_EMAIL', '')
    google_app_password: str = os.environ.get('GOOGLE_APP_PASSWORD', '')
    
    # Hugging Face (will be set by user later)
    hf_token: str = os.environ.get('HF_TOKEN', '')
    hf_model_detection: str = os.environ.get('HF_MODEL_DETECTION', 'meta-llama/Llama-2-7b-chat-hf')
    
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
    
    # JWT Secret Key alias
    @property
    def jwt_secret_key(self) -> str:
        return self.secret_key
    
    class Config:
        env_file = '.env'
        case_sensitive = False
        extra = 'ignore'  # Allow extra fields from .env

@lru_cache()
def get_settings() -> Settings:
    return Settings()
