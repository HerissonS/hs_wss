from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanCreateRequest(BaseModel):
    target_url: str = Field(..., description="Target web application URL to scan (must start with http:// or https://)")
    max_depth: int = Field(default=3, ge=1, le=10, description="Maximum link crawl depth")
    max_pages: int = Field(default=50, ge=1, le=500, description="Maximum total pages to visit")
    auth_enabled: bool = Field(default=False, description="Whether the scan should perform automated login")
    auth_username: Optional[str] = Field(default=None, description="Transient username/email for login (never saved)")
    auth_password: Optional[str] = Field(default=None, description="Transient password for login (never saved)")
    auth_login_url: Optional[str] = Field(default=None, description="Optional custom login page URL")

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        url_str = v.strip()
        if not (url_str.startswith("http://") or url_str.startswith("https://")):
            raise ValueError("Target URL must begin with http:// or https://")
        return url_str


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    url: str
    source_type: str
    secret_type: str
    masked_value: str
    raw_value: Optional[str] = None
    context_snippet: Optional[str] = None
    severity: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanSummaryResponse(BaseModel):
    id: int
    target_url: str
    domain: str
    status: str
    max_depth: int
    max_pages: int
    pages_scanned: int
    secrets_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    auth_status: Optional[str] = None
    auth_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanSummaryResponse):
    findings: List[FindingResponse] = []


class RuleResponse(BaseModel):
    id: str
    name: str
    severity: str
    description: str


class ActiveScanStatus(BaseModel):
    is_active: bool
    active_scan_id: Optional[int] = None
    scan: Optional[ScanSummaryResponse] = None
