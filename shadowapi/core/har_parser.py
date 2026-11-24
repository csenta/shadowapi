"""
HAR (HTTP Archive) and Traffic Stream Parser for ShadowAPI.
Extracts normalized HTTP transactions from HAR logs, proxy dumps, or JSON entries.
"""

import json
import os
from typing import Any
from urllib.parse import parse_qs, urlparse

from shadowapi.core.models import HTTPTransaction


class HARParser:
    """Parses HTTP Archive (HAR 1.2) files and JSON transaction collections."""

    @staticmethod
    def parse_file(file_path: str) -> list[HTTPTransaction]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Traffic file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        return HARParser.parse_data(data)

    @staticmethod
    def parse_data(data: Any) -> list[HTTPTransaction]:
        transactions: list[HTTPTransaction] = []

        # Standard HAR structure: {"log": {"entries": [...]}}
        entries = []
        if isinstance(data, dict):
            if "log" in data and isinstance(data["log"], dict):
                entries = data["log"].get("entries", [])
            elif "entries" in data:
                entries = data.get("entries", [])
            elif "transactions" in data:
                entries = data.get("transactions", [])
            else:
                entries = [data]
        elif isinstance(data, list):
            entries = data

        for entry in entries:
            tx = HARParser._parse_single_entry(entry)
            if tx:
                transactions.append(tx)

        return transactions

    @staticmethod
    def _parse_single_entry(entry: dict[str, Any]) -> HTTPTransaction | None:
        try:
            req_data = entry.get("request", {})
            resp_data = entry.get("response", {})

            method = req_data.get("method", "GET").upper()
            raw_url = req_data.get("url", "")
            if not raw_url:
                return None

            parsed_url = urlparse(raw_url)
            path = parsed_url.path or "/"

            # Query params from parsed URL or HAR queryString
            query_params: dict[str, list[str]] = parse_qs(parsed_url.query)
            if "queryString" in req_data and isinstance(req_data["queryString"], list):
                for q in req_data["queryString"]:
                    name = q.get("name")
                    val = q.get("value", "")
                    if name:
                        query_params.setdefault(name, []).append(val)

            # Request Headers
            headers: dict[str, str] = {}
            if "headers" in req_data:
                for h in req_data["headers"]:
                    name = h.get("name", "").lower()
                    val = h.get("value", "")
                    if name:
                        headers[name] = val

            # Request Body
            request_body = None
            if "postData" in req_data:
                post_data = req_data["postData"]
                text = post_data.get("text", "")
                if text:
                    try:
                        request_body = json.loads(text)
                    except Exception:
                        request_body = text
            elif "body" in req_data:
                request_body = req_data["body"]

            # Response Status & Body
            status_code = resp_data.get("status", 200)
            response_body = None
            if "content" in resp_data:
                content = resp_data["content"]
                text = content.get("text", "")
                if text:
                    try:
                        response_body = json.loads(text)
                    except Exception:
                        response_body = text
            elif "body" in resp_data:
                response_body = resp_data["body"]

            return HTTPTransaction(
                method=method,
                url=raw_url,
                path=path,
                query_params=query_params,
                headers=headers,
                request_body=request_body,
                status_code=int(status_code),
                response_body=response_body,
            )
        except Exception:
            return None
