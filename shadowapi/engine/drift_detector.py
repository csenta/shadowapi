"""
Differential Drift and Zombie Endpoint Detection Engine for ShadowAPI.
Compares declared ground-truth OpenAPI specifications against runtime observed APIs.
"""

import json
import os
import re
import uuid
from typing import Any
import yaml

from shadowapi.core.models import (
    DriftFinding,
    DriftReport,
    DriftType,
    EndpointSignature,
    HTTPTransaction,
)
from shadowapi.core.schema_inferrer import SchemaInferrer


class DriftDetector:
    """Detects shadow endpoints, zombie APIs, schema mutations, and auth discrepancies."""

    def __init__(self, declared_spec: dict[str, Any] | None = None):
        self.declared_spec = declared_spec or {}

    @classmethod
    def from_file(cls, spec_path: str) -> "DriftDetector":
        if not os.path.isfile(spec_path):
            raise FileNotFoundError(f"OpenAPI ground-truth spec not found: {spec_path}")

        with open(spec_path, "r", encoding="utf-8") as f:
            content = f.read()
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = yaml.safe_load(content)

        return cls(declared_spec=data)

    def _normalize_spec_path(self, path: str) -> str:
        """Standardizes parameter placeholders, e.g. /users/{userId} -> /users/{id}."""
        return re.sub(r"\{[a-zA-Z0-9_-]+\}", "{param}", path.rstrip("/"))

    def _extract_declared_endpoints(self) -> dict[str, dict[str, Any]]:
        """
        Builds a lookup of declared endpoints:
        key: 'METHOD /normalized/path' -> operation details
        """
        declared: dict[str, dict[str, Any]] = {}
        paths = self.declared_spec.get("paths", {})

        for path, path_item in paths.items():
            norm_path = self._normalize_spec_path(path)
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                    key = f"{method.upper()} {norm_path}"
                    declared[key] = {
                        "original_path": path,
                        "method": method.upper(),
                        "operation": op if isinstance(op, dict) else {},
                    }

        return declared

    def analyze(
        self,
        signatures: dict[str, EndpointSignature],
        transactions: list[HTTPTransaction],
    ) -> DriftReport:
        declared_lookup = self._extract_declared_endpoints()
        findings: list[DriftFinding] = []

        # 1. Inspect Observed Signatures against Declared Spec
        for sig_key, sig in signatures.items():
            norm_observed_path = self._normalize_spec_path(sig.path_template)
            lookup_key = f"{sig.method.upper()} {norm_observed_path}"

            if lookup_key not in declared_lookup:
                # SHADOW ENDPOINT: Observed in traffic but never declared in spec!
                severity = "CRITICAL" if sig.method in ("POST", "PUT", "DELETE", "PATCH") else "HIGH"
                findings.append(
                    DriftFinding(
                        id=f"drift_{uuid.uuid4().hex[:8]}",
                        drift_type=DriftType.SHADOW_ENDPOINT,
                        severity=severity,
                        method=sig.method,
                        path=sig.path_template,
                        description=f"Undocumented endpoint '{sig.method} {sig.path_template}' detected in active traffic (OWASP API9:2023).",
                        details={
                            "sample_count": sig.sample_count,
                            "detected_auth": sig.auth_detected,
                            "query_params": sig.query_params,
                        },
                    )
                )
            else:
                declared_info = declared_lookup[lookup_key]
                op = declared_info.get("operation", {})

                # Check ZOMBIE ENDPOINT (Deprecated endpoint receiving active traffic)
                is_deprecated = op.get("deprecated", False)
                if is_deprecated:
                    findings.append(
                        DriftFinding(
                            id=f"drift_{uuid.uuid4().hex[:8]}",
                            drift_type=DriftType.ZOMBIE_ENDPOINT,
                            severity="HIGH",
                            method=sig.method,
                            path=sig.path_template,
                            description=f"Zombie API detected: '{sig.method} {sig.path_template}' is marked deprecated but actively serving requests.",
                            details={
                                "declared_path": declared_info["original_path"],
                                "sample_count": sig.sample_count,
                            },
                        )
                    )

                # Check AUTH DISCREPANCY
                declared_security = op.get("security", self.declared_spec.get("security", []))
                if declared_security and not sig.auth_detected:
                    findings.append(
                        DriftFinding(
                            id=f"drift_{uuid.uuid4().hex[:8]}",
                            drift_type=DriftType.AUTH_DISCREPANCY,
                            severity="CRITICAL",
                            method=sig.method,
                            path=sig.path_template,
                            description=f"Authentication Gap: Endpoint '{sig.method} {sig.path_template}' specifies security requirements in spec, but unauthenticated traffic was observed.",
                            details={
                                "declared_security": declared_security,
                                "observed_auth": sig.auth_types,
                            },
                        )
                    )

                # Check SCHEMA DRIFT (Request body parameter mutation)
                if sig.request_schema and "requestBody" in op:
                    req_content = op.get("requestBody", {}).get("content", {})
                    json_schema = req_content.get("application/json", {}).get("schema", {})
                    declared_props = set(json_schema.get("properties", {}).keys())
                    observed_props = set(sig.request_schema.get("properties", {}).keys())

                    undocumented_props = observed_props - declared_props
                    if undocumented_props:
                        findings.append(
                            DriftFinding(
                                id=f"drift_{uuid.uuid4().hex[:8]}",
                                drift_type=DriftType.SCHEMA_DRIFT,
                                severity="MEDIUM",
                                method=sig.method,
                                path=sig.path_template,
                                description=f"Schema Drift: Request payload contains undocumented properties: {list(undocumented_props)}.",
                                details={
                                    "undocumented_properties": list(undocumented_props),
                                    "declared_properties": list(declared_props),
                                },
                            )
                        )

        # 2. Inspect Transactions for Sensitive Data Exposure (PII, Secrets, Tokens)
        already_flagged_exposure = set()
        for tx in transactions:
            if tx.response_body:
                exposures = SchemaInferrer.detect_sensitive_data(tx.response_body)
                if exposures:
                    norm_path, _ = SchemaInferrer.normalize_path(tx.path)
                    exp_key = f"{tx.method} {norm_path}"
                    if exp_key not in already_flagged_exposure:
                        already_flagged_exposure.add(exp_key)
                        reasons = [e["reason"] for e in exposures]
                        findings.append(
                            DriftFinding(
                                id=f"drift_{uuid.uuid4().hex[:8]}",
                                drift_type=DriftType.SENSITIVE_DATA_EXPOSURE,
                                severity="HIGH",
                                method=tx.method,
                                path=norm_path,
                                description=f"Sensitive Data Exposure: Response contains unmasked sensitive keys or secrets ({', '.join(reasons[:2])}).",
                                details={"exposures": exposures[:5]},
                            )
                        )

        # 3. Calculate API Risk Score (0-100)
        risk = 0
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        for f in findings:
            risk += weights.get(f.severity, 5)
        risk_score = min(100, risk)

        return DriftReport(
            total_transactions=len(transactions),
            observed_endpoints_count=len(signatures),
            declared_endpoints_count=len(declared_lookup),
            findings=findings,
            risk_score=risk_score,
        )
