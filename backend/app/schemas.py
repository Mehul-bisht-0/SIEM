from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, validator


class EventType(str, Enum):
    failed_login = "failed_login"
    login_success = "login_success"
    privilege_escalation = "privilege_escalation"
    port_scan = "port_scan"
    malware = "malware"
    data_exfiltration = "data_exfiltration"
    config_change = "config_change"
    normal = "normal"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogEntry(BaseModel):
    log_id: str = Field(default_factory=lambda: f"log-{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    destination_ip: str
    event_type: EventType
    severity: Severity
    message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @validator("timestamp", pre=True)
    @classmethod
    def parse_timestamp(cls, value: Any) -> datetime:
        if value is None or value == "":
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        raise ValueError("timestamp must be an ISO 8601 string or datetime")


class AlertStatus(str, Enum):
    open = "open"
    blocked = "blocked"
    resolved = "resolved"


class ThreatResult(BaseModel):
    is_anomaly: bool
    confidence_score: float
    model_score: float
    reason: str


class AlertDocument(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"alert-{uuid4().hex[:12]}")
    threat_type: str
    confidence_score: float
    status: AlertStatus = AlertStatus.open
    severity: Severity
    source_ip: str
    destination_ip: str | None = None
    attack_chain: list[str] = Field(default_factory=list)
    related_log_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    risk_level: str = "medium"
    likely_attack: str = ""
    mitre_tactic: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    llm_provider: str = "fallback"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IngestResponse(BaseModel):
    stored: bool
    log_id: str
    threat_detection: ThreatResult
    alerts: list[dict[str, Any]] = Field(default_factory=list)
