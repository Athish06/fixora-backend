# Repository schemas
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
import uuid

class Repository(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str
    full_name: str  # owner/repo
    description: Optional[str] = None
    language: Optional[str] = None
    url: str
    github_id: Optional[int] = None
    status: str = 'connected'  # connected, scanning, error
    risk_score: str = 'A'  # A, B, C, D, F
    total_vulnerabilities: int = 0
    last_scan: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now())

class RepositoryCreate(BaseModel):
    name: str
    full_name: str
    description: Optional[str] = None
    language: Optional[str] = None
    url: str
    github_id: Optional[int] = None
