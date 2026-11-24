"""
Data models for ShadowAPI transactions, schemas, drift findings, and reports.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DriftType(str, Enum):
    SHADOW_ENDPOINT = "SHADOW_ENDPOINT"
    ZOMBIE_ENDPOINT = "ZOMBIE_ENDPOINT"
    SCHEMA_DRIFT = "SCHEMA_DRIFT"
    AUTH_DISCREPANCY = "AUTH_DISCREPANCY"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"


@dataclass
class HTTPTransaction:
    method: str
    url: str
    path: str
    query_params: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    request_body: Any = None
    status_code: int = 200
    response_body: Any = None


@dataclass
class EndpointSignature:
    method: str
    path_template: str
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    request_schema: dict[str, Any] | None = None
    response_schemas: dict[int, dict[str, Any]] = field(default_factory=dict)
    auth_detected: bool = False
    auth_types: list[str] = field(default_factory=list)
    sample_count: int = 1


@dataclass
class DriftFinding:
    id: str
    drift_type: DriftType
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    method: str
    path: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DriftReport:
    total_transactions: int
    observed_endpoints_count: int
    declared_endpoints_count: int
    findings: list[DriftFinding] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_transactions": self.total_transactions,
            "observed_endpoints_count": self.observed_endpoints_count,
            "declared_endpoints_count": self.declared_endpoints_count,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "drift_type": f.drift_type.value,
                    "severity": f.severity,
                    "method": f.method,
                    "path": f.path,
                    "description": f.description,
                    "details": f.details,
                }
                for f in self.findings
            ],
        }
