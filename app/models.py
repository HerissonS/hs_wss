from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(2048), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(32), default="pending", index=True)  # pending, running, completed, failed, cancelled
    max_depth = Column(Integer, default=3)
    max_pages = Column(Integer, default=50)
    pages_scanned = Column(Integer, default=0)
    secrets_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    auth_status = Column(String(32), nullable=True)  # success, failed, skipped, None
    auth_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", order_by="Finding.id.desc()")
    visited_urls = relationship("VisitedURL", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    source_type = Column(String(64), nullable=False)  # DOM, SCRIPT, XHR_RESPONSE, REQUEST_HEADER, URL_PARAM
    secret_type = Column(String(128), nullable=False)
    masked_value = Column(String(256), nullable=False)
    raw_value = Column(String(2048), nullable=True)
    context_snippet = Column(Text, nullable=True)
    severity = Column(String(32), default="HIGH")  # CRITICAL, HIGH, MEDIUM, LOW
    created_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="findings")


class VisitedURL(Base):
    __tablename__ = "visited_urls"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    status_code = Column(Integer, nullable=True)
    depth = Column(Integer, default=0)
    content_type = Column(String(128), nullable=True)
    visited_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("Scan", back_populates="visited_urls")
