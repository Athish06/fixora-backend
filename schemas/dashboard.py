# Dashboard schemas
from pydantic import BaseModel

class DashboardStats(BaseModel):
    total_repositories: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    risk_score: str
    pending_prs: int
    ai_false_positives_prevented: int
    scans_this_week: int
