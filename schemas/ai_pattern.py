# AI Pattern schemas
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
import uuid

class AIPattern(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    pattern_type: str  # wrapper, sink, source
    pattern_name: str  # e.g., db_wrapper.execute()
    description: str
    confidence: float
    is_verified: bool = False
    user_override: Optional[bool] = None  # User can manually verify/reject
    created_at: datetime = Field(default_factory=lambda: datetime.now())

class AIPatternCreate(BaseModel):
    repository_id: str
    pattern_type: str
    pattern_name: str
    description: str
    confidence: float
