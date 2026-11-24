"""
Path Normalization, Sensitive Data Detection, and JSON Schema Inference Engine.
"""

import re
from typing import Any

# Regex patterns for path variable detection
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
NUMERIC_ID_RE = re.compile(r"^\d+$")
HEX_HASH_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)

# Sensitive keyword patterns
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd)", re.I),
    re.compile(r"(?:secret|api_key|apikey|private_key|privkey)", re.I),
    re.compile(r"(?:access_token|refresh_token|bearer_token|auth_token)", re.I),
    re.compile(r"(?:ssn|social_security|credit_card|cvv|card_number)", re.I),
]

# Sensitive value patterns
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
JWT_RE = re.compile(r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")


class SchemaInferrer:
    """Normalizes URL paths, infers JSON Schemas, and inspects data sensitivity."""

    @staticmethod
    def normalize_path(path: str) -> tuple[str, list[str]]:
        """
        Replaces dynamic path variables with standardized template placeholders.
        e.g. /api/v1/users/123/orders -> /api/v1/users/{user_id}/orders, ['user_id']
        """
        segments = [s for s in path.strip("/").split("/") if s]
        normalized_segments: list[str] = []
        path_params: list[str] = []

        for idx, seg in enumerate(segments):
            prev_seg = segments[idx - 1] if idx > 0 else "item"
            # Singularize prev_seg for parameter name if ends with 's'
            param_base = prev_seg[:-1] if prev_seg.endswith("s") and len(prev_seg) > 1 else prev_seg

            if UUID_RE.match(seg):
                param_name = f"{param_base}_uuid" if param_base != "item" else "id"
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(param_name)
            elif NUMERIC_ID_RE.match(seg):
                param_name = f"{param_base}_id" if param_base != "item" else "id"
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(param_name)
            elif HEX_HASH_RE.match(seg):
                param_name = f"{param_base}_hash" if param_base != "item" else "id"
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(param_name)
            else:
                normalized_segments.append(seg)

        normalized_path = "/" + "/".join(normalized_segments)
        return normalized_path, path_params

    @staticmethod
    def infer_schema(data: Any, max_depth: int = 5) -> dict[str, Any]:
        """Recursively infers JSON Schema draft-07 / OpenAPI 3.1 schema for any Python value."""
        if max_depth <= 0:
            return {"type": "object"}

        if data is None:
            return {"type": "null"}

        if isinstance(data, bool):
            return {"type": "boolean"}

        if isinstance(data, int):
            return {"type": "integer"}

        if isinstance(data, float):
            return {"type": "number"}

        if isinstance(data, str):
            schema = {"type": "string"}
            if UUID_RE.match(data):
                schema["format"] = "uuid"
            elif EMAIL_RE.match(data):
                schema["format"] = "email"
            return schema

        if isinstance(data, list):
            if not data:
                return {"type": "array", "items": {}}
            # Infer item schema from first element (or merged)
            item_schema = SchemaInferrer.infer_schema(data[0], max_depth - 1)
            return {"type": "array", "items": item_schema}

        if isinstance(data, dict):
            properties: dict[str, Any] = {}
            required: list[str] = []
            for k, v in data.items():
                str_k = str(k)
                properties[str_k] = SchemaInferrer.infer_schema(v, max_depth - 1)
                if v is not None:
                    required.append(str_k)
            return {
                "type": "object",
                "properties": properties,
                "required": required,
            }

        return {"type": "string"}

    @staticmethod
    def detect_sensitive_data(payload: Any) -> list[dict[str, str]]:
        """
        Scans a response or request payload for exposed sensitive parameters,
        such as passwords, secret keys, PII, AWS tokens, and JWTs.
        """
        exposures: list[dict[str, str]] = []

        def _traverse(val: Any, current_path: str = ""):
            if isinstance(val, dict):
                for k, v in val.items():
                    subpath = f"{current_path}.{k}" if current_path else str(k)
                    # Check key name
                    for pat in SENSITIVE_KEY_PATTERNS:
                        if pat.search(str(k)):
                            exposures.append({
                                "field": subpath,
                                "reason": f"Sensitive key detected: '{k}'",
                            })
                            break
                    _traverse(v, subpath)
            elif isinstance(val, list):
                for idx, item in enumerate(val):
                    _traverse(item, f"{current_path}[{idx}]")
            elif isinstance(val, str):
                if AWS_KEY_RE.search(val):
                    exposures.append({
                        "field": current_path,
                        "reason": "Exposed AWS Access Key pattern in value",
                    })
                elif JWT_RE.search(val) and len(val) > 40:
                    exposures.append({
                        "field": current_path,
                        "reason": "Raw JWT token exposed in payload",
                    })

        _traverse(payload)
        return exposures
