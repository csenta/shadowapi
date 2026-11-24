"""
OpenAPI 3.1 Specification Builder for ShadowAPI.
Synthesizes clean OpenAPI 3.1 definitions from aggregated runtime transactions.
"""

import json
from typing import Any
import yaml

from shadowapi.core.models import EndpointSignature, HTTPTransaction
from shadowapi.core.schema_inferrer import SchemaInferrer


class SpecBuilder:
    """Builds OpenAPI 3.1 specifications from observed HTTP transactions."""

    def __init__(self, title: str = "Synthesized Runtime API", version: str = "1.0.0"):
        self.title = title
        self.version = version

    def build_signatures(self, transactions: list[HTTPTransaction]) -> dict[str, EndpointSignature]:
        """
        Groups transactions by (METHOD, normalized_path) and aggregates schemas,
        query parameters, and authentication presence.
        """
        signatures: dict[str, EndpointSignature] = {}

        for tx in transactions:
            norm_path, path_params = SchemaInferrer.normalize_path(tx.path)
            key = f"{tx.method.upper()} {norm_path}"

            auth_found = False
            auth_types: list[str] = []
            auth_header = tx.headers.get("authorization", "")
            if auth_header:
                auth_found = True
                auth_type = auth_header.split()[0] if auth_header.split() else "Bearer"
                auth_types.append(auth_type)
            if "x-api-key" in tx.headers or "apikey" in tx.headers:
                auth_found = True
                auth_types.append("ApiKey")
            if "cookie" in tx.headers and ("session" in tx.headers["cookie"] or "token" in tx.headers["cookie"]):
                auth_found = True
                auth_types.append("CookieAuth")

            if key not in signatures:
                sig = EndpointSignature(
                    method=tx.method.upper(),
                    path_template=norm_path,
                    path_params=path_params,
                    query_params=list(tx.query_params.keys()),
                    auth_detected=auth_found,
                    auth_types=list(set(auth_types)),
                    sample_count=1,
                )
                if tx.request_body is not None:
                    sig.request_schema = SchemaInferrer.infer_schema(tx.request_body)
                if tx.response_body is not None:
                    sig.response_schemas[tx.status_code] = SchemaInferrer.infer_schema(tx.response_body)
                signatures[key] = sig
            else:
                sig = signatures[key]
                sig.sample_count += 1
                for q in tx.query_params.keys():
                    if q not in sig.query_params:
                        sig.query_params.append(q)
                for a in auth_types:
                    if a not in sig.auth_types:
                        sig.auth_types.append(a)
                if auth_found:
                    sig.auth_detected = True

                if tx.request_body is not None and sig.request_schema is None:
                    sig.request_schema = SchemaInferrer.infer_schema(tx.request_body)
                if tx.response_body is not None and tx.status_code not in sig.response_schemas:
                    sig.response_schemas[tx.status_code] = SchemaInferrer.infer_schema(tx.response_body)

        return signatures

    def synthesize_openapi(self, signatures: dict[str, EndpointSignature]) -> dict[str, Any]:
        """Converts endpoint signatures into standard OpenAPI 3.1 structure."""
        paths: dict[str, Any] = {}

        for sig in signatures.values():
            if sig.path_template not in paths:
                paths[sig.path_template] = {}

            method_lower = sig.method.lower()

            parameters: list[dict[str, Any]] = []
            for p in sig.path_params:
                parameters.append({
                    "name": p,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                })

            for q in sig.query_params:
                parameters.append({
                    "name": q,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                })

            operation: dict[str, Any] = {
                "summary": f"Observed {sig.method} {sig.path_template}",
                "description": f"Synthesized from {sig.sample_count} observed runtime traffic samples.",
                "parameters": parameters,
                "responses": {},
            }

            if sig.auth_detected:
                operation["security"] = [{auth_type: []} for auth_type in sig.auth_types] or [{"bearerAuth": []}]

            if sig.request_schema:
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": sig.request_schema,
                        }
                    },
                }

            if sig.response_schemas:
                for status_code, schema in sig.response_schemas.items():
                    operation["responses"][str(status_code)] = {
                        "description": f"Observed HTTP {status_code} response",
                        "content": {
                            "application/json": {
                                "schema": schema,
                            }
                        },
                    }
            else:
                operation["responses"]["200"] = {"description": "Successful response"}

            paths[sig.path_template][method_lower] = operation

        spec = {
            "openapi": "3.1.0",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Synthesized runtime specification generated autonomously by ShadowAPI.",
            },
            "paths": paths,
        }
        return spec

    def export_json(self, spec: dict[str, Any], indent: int = 2) -> str:
        return json.dumps(spec, indent=indent)

    def export_yaml(self, spec: dict[str, Any]) -> str:
        return yaml.dump(spec, sort_keys=False)
