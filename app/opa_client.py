# app/opa_client.py
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional

import requests


class OPAClient:
    def __init__(self):
        self.base_url = os.getenv("OPA_URL", "http://localhost:8181").rstrip("/")
        # This must match your rego package+rule => /v1/data/genai/decision
        self.decision_path = os.getenv("OPA_DECISION_PATH", "/v1/data/genai/decision")
        self.timeout_s = float(os.getenv("OPA_TIMEOUT_S", "2.0"))

    def decide(self, opa_input: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{self.decision_path}"
        r = requests.post(url, json={"input": opa_input}, timeout=self.timeout_s)
        r.raise_for_status()
        payload = r.json()
        # OPA returns {"result": ...}
        return payload.get("result") or {}

    def bundle_status(self) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/status"
        r = requests.get(url, timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def stable_hash(obj: Any) -> str:
        b = str(obj).encode("utf-8", errors="ignore")
        return hashlib.sha256(b).hexdigest()[:12]
