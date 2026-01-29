# Activity Log schemas
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

class ActivityLog(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    action: str  # scan_started, repo_connected, pr_created, etc.
    entity_type: str  # repository, vulnerability, scan
    entity_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
