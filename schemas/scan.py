# Scan schemas
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ScanRequest(BaseModel):
    repository_id: str
    scan_type: str = 'full'  # full, differential

class ScanResult(BaseModel):
    scan_id: str
    repository_id: str
    status: str  # pending, running, completed, failed
    phase: str  # discovery, scanning, classification, auto-fix
    progress: int = 0  # 0-100
    message: Optional[str] = None
    vulnerabilities_found: int = 0
    patterns_discovered: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now())
    completed_at: Optional[datetime] = None
