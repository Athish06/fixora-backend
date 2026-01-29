# Pull Request schemas
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
import uuid

class PullRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    vulnerability_id: str
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    title: str
    description: str
    status: str  # pending, open, merged, closed, failed
    created_at: datetime = Field(default_factory=lambda: datetime.now())
