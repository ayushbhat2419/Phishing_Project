"""
SQLAlchemy Database Models (Phase 6)
====================================
Defines persistent schema for scan history, feature snapshots, explanations,
and threat intelligence records.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String(16), nullable=False, index=True)  # 'URL' or 'EMAIL'
    input_summary = Column(String(512), nullable=False)
    input_hash = Column(String(64), nullable=False, index=True)
    verdict = Column(String(32), nullable=False, index=True)   # 'PHISHING', 'SUSPICIOUS', 'LEGITIMATE'
    confidence_score = Column(Float, nullable=False)
    risk_level = Column(String(16), nullable=False)           # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    execution_time_ms = Column(Integer, nullable=False, default=0)
    threat_intel_matched = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    url_features = relationship("URLFeatureSnapshot", back_populates="scan_record", uselist=False, cascade="all, delete-orphan")
    email_features = relationship("EmailFeatureSnapshot", back_populates="scan_record", uselist=False, cascade="all, delete-orphan")
    explanation = relationship("ExplanationRecord", back_populates="scan_record", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "input_summary": self.input_summary,
            "verdict": self.verdict,
            "confidence_score": round(self.confidence_score, 4),
            "risk_level": self.risk_level,
            "execution_time_ms": self.execution_time_ms,
            "threat_intel_matched": self.threat_intel_matched,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class URLFeatureSnapshot(Base):
    __tablename__ = "url_feature_snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False)
    
    url_length = Column(Integer, default=0)
    domain_length = Column(Integer, default=0)
    dot_count = Column(Integer, default=0)
    hyphen_count = Column(Integer, default=0)
    special_char_count = Column(Integer, default=0)
    has_https = Column(Integer, default=0)
    is_ip_address = Column(Integer, default=0)
    subdomain_count = Column(Integer, default=0)
    suspicious_keyword_count = Column(Integer, default=0)
    is_shortened = Column(Integer, default=0)
    shannon_entropy = Column(Float, default=0.0)
    domain_entropy = Column(Float, default=0.0)
    is_high_risk_tld = Column(Integer, default=0)
    brand_in_subdomain = Column(Integer, default=0)

    scan_record = relationship("ScanRecord", back_populates="url_features")

    def to_dict(self):
        return {
            "url_length": self.url_length,
            "domain_length": self.domain_length,
            "dot_count": self.dot_count,
            "hyphen_count": self.hyphen_count,
            "special_char_count": self.special_char_count,
            "has_https": bool(self.has_https),
            "is_ip_address": bool(self.is_ip_address),
            "subdomain_count": self.subdomain_count,
            "suspicious_keyword_count": self.suspicious_keyword_count,
            "is_shortened": bool(self.is_shortened),
            "shannon_entropy": self.shannon_entropy,
            "domain_entropy": self.domain_entropy,
            "is_high_risk_tld": bool(self.is_high_risk_tld),
            "brand_in_subdomain": bool(self.brand_in_subdomain)
        }


class EmailFeatureSnapshot(Base):
    __tablename__ = "email_feature_snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False)
    
    sender_address = Column(String(255), default="")
    subject = Column(String(512), default="")
    urgency_score = Column(Float, default=0.0)
    has_suspicious_links = Column(Boolean, default=False)
    social_engineering_patterns = Column(JSON, default=list)
    detected_keywords = Column(JSON, default=list)

    scan_record = relationship("ScanRecord", back_populates="email_features")

    def to_dict(self):
        return {
            "sender_address": self.sender_address,
            "subject": self.subject,
            "urgency_score": self.urgency_score,
            "has_suspicious_links": self.has_suspicious_links,
            "social_engineering_patterns": self.social_engineering_patterns,
            "detected_keywords": self.detected_keywords
        }


class ExplanationRecord(Base):
    __tablename__ = "explanation_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False)
    
    top_contributing_features = Column(JSON, default=list)
    human_readable_reasons = Column(JSON, default=list)
    all_shap_values = Column(JSON, default=dict)

    scan_record = relationship("ScanRecord", back_populates="explanation")

    def to_dict(self):
        return {
            "top_contributing_features": self.top_contributing_features,
            "human_readable_reasons": self.human_readable_reasons,
            "all_shap_values": self.all_shap_values
        }
