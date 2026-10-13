"""
Pydantic v2 schemas and data definitions for Pqc Certificate X509 Hybrid.
Domain: Post-Quantum Cryptography & Hardware Security
Standard: Illustrative thresholds; no cryptographic conformance evaluation
"""
import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, model_validator


class UrgencyLevel(str, Enum):
    ROUTINE = "ROUTINE"
    ELEVATED = "ELEVATED_RISK"
    CRITICAL_STAT = "CRITICAL_STAT_PANIC"


class SystemIntegrityStatus(str, Enum):
    VALIDATED = "VALIDATED_OPTIMAL"
    DISCORDANT = "DISCORDANT_ANOMALY"
    RECALIBRATION_REQUIRED = "RECALIBRATION_REQUIRED"


class SystemTaskPayload(BaseModel):
    task_id: str = Field(..., min_length=1, max_length=128, description="Unique task / case identifier")
    target_identifier: str = Field(..., min_length=1, max_length=128, description="Entity, patient key, or genomic/cryptographic target")
    primary_metric: float = Field(..., allow_inf_nan=False, description="Primary domain measurement or score")
    secondary_metric: float = Field(default=0.0, allow_inf_nan=False, description="Secondary kinetic or confidence score")
    status_descriptor: str = Field(default="NOMINAL", min_length=1, max_length=256, description="Status code or phenotype descriptor")
    is_critical_flag: bool = Field(default=False, description="Emergency escalation or high priority trigger")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Metadata key-value pairs")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    @model_validator(mode="after")
    def validate_strings(self):
        if not all(x.strip() for x in (self.task_id, self.target_identifier, self.status_descriptor)):
            raise ValueError("Task ID, target identifier and status must not be blank")
        return self


class AgentAlert(BaseModel):
    alert_id: str
    origin_worker: str
    urgency: UrgencyLevel
    summary: str
    technical_details: str
    actionable_remediation: str
    standard_reference: str = "Illustrative thresholds; no cryptographic conformance evaluation"
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ConsensusDossier(BaseModel):
    dossier_id: str
    system_slug: str = "pqc-certificate-x509-hybrid"
    domain: str = "Post-Quantum Cryptography & Hardware Security"
    task_id: str
    target_identifier: str
    overall_urgency: UrgencyLevel
    integrity_status: SystemIntegrityStatus
    total_alerts: int
    critical_alerts_count: int
    alerts: List[AgentAlert]
    standard_reference: str = "Illustrative thresholds; no cryptographic conformance evaluation"
    consensus_summary: str
    audit_hash: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
