# app/policy_engine.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional, List

from opa_client import OPAClient


def _env_mode_default() -> str:
    mode = os.getenv("POLICY_MODE", "enforce").lower()
    return mode if mode in ("enforce", "monitor") else "enforce"


def _float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _contains_any(text: str, needles: List[str]) -> bool:
    t = (text or "").lower()
    return any(n.lower() in t for n in needles)


def _sql_query_from_tool(tool: Optional[Any]) -> str:
    if tool is None:
        return ""
    if hasattr(tool, "args"):
        args = getattr(tool, "args") or {}
        if isinstance(args, dict):
            return str(args.get("query", "") or "")
    if isinstance(tool, dict):
        args = tool.get("args") or {}
        if isinstance(args, dict):
            return str(args.get("query", "") or "")
    return ""


class PolicyEngine:
    """
    POLICY_BACKEND=python|opa
    POLICY_MODE=enforce|monitor

    OPA_FAIL_MODE=closed|open (healthcare recommend: closed)
    """

    def __init__(self):
        self.backend = os.getenv("POLICY_BACKEND", "opa").lower()
        if self.backend not in ("python", "opa"):
            self.backend = "python"

        self._opa: Optional[OPAClient] = None

        # Python backend thresholds (kept as a fallback if you want)
        self.inj_block_threshold = _float(os.getenv("INJECTION_BLOCK_THRESHOLD", "0.85"), 0.85)
        self.inj_safe_completion_threshold = _float(os.getenv("INJECTION_SAFE_COMPLETION_THRESHOLD", "0.35"), 0.35)
        self.policy_version = os.getenv("POLICY_VERSION", "python-v1")

        self.opa_attach_bundle_status = os.getenv("OPA_ATTACH_BUNDLE_STATUS", "false").lower() == "true"
        self.opa_fail_mode = os.getenv("OPA_FAIL_MODE", "closed").lower()  # closed|open

    def _get_opa(self) -> OPAClient:
        if self._opa is None:
            self._opa = OPAClient()
        return self._opa

    def _decision(
        self,
        *,
        decision: str,
        action: str,
        reason: str,
        rule_id: str,
        mode: Optional[str] = None,
        obligations: Optional[List[str]] = None,
        policy_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "decision": decision,
            "action": action,
            "reason": reason,
            "rule_id": rule_id,
            "policy_version": policy_version or self.policy_version,
            "mode": mode or _env_mode_default(),
            "obligations": obligations or [],
        }

    def evaluate(self, message: str, signals: Dict[str, Any]) -> Dict[str, Any]:
        stage = (signals.get("stage") or "pre").lower()
        mode = _env_mode_default()

        inj_score = _float(signals.get("injection_score"), 0.0)
        hits = signals.get("injection_hits") or []
        pii_any = bool(signals.get("pii_any", False))

        if stage == "pre":
            if hits and inj_score >= self.inj_safe_completion_threshold:
                return self._decision(
                    decision="allow",
                    action="safe_completion",
                    reason="Injection signals present; safe completion",
                    rule_id="PY_INJ_SAFE_COMPLETION",
                    mode=mode,
                    obligations=["log_injection"],
                )
            if pii_any:
                return self._decision(
                    decision="allow",
                    action="redact_and_allow",
                    reason="PII detected; redact",
                    rule_id="PY_PII_REDACT",
                    mode=mode,
                    obligations=["log_pii_redaction"],
                )

        # Minimal tool rule in python fallback
        if stage == "tool" and signals.get("tool_name") == "sql_query":
            q = _sql_query_from_tool(signals.get("tool"))
            if any(k in q.lower() for k in ["drop ", "delete ", "truncate ", "alter "]):
                return self._decision(
                    decision="deny",
                    action="deny",
                    reason="Destructive SQL blocked (python fallback)",
                    rule_id="PY_SQL_BLOCK",
                    mode=mode,
                    obligations=["log_security_event"],
                )

        return self._decision(
            decision="allow",
            action="allow",
            reason="Allowed",
            rule_id="PY_DEFAULT_ALLOW",
            mode=mode,
        )

    # -------------------------
    # Stage-aware wrapper
    # -------------------------
    def evaluate_stage(
        self,
        stage: str,
        message: str,
        signals: Dict[str, Any],
        tool: Optional[Any],
        tool_result: Optional[Any],
        llm_out: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        opa_input: Dict[str, Any] = {
            "stage": stage,
            "request": {
                "message": message,
                "user_role": signals.get("user_role"),
            },
            "signals": {
                **signals,
                # helps rego reliably know current mode without env access
                "policy_mode_default": _env_mode_default(),
            },
            "tool": None if tool is None else {"name": getattr(tool, "name", None), "args": getattr(tool, "args", None)},
            "tool_result": tool_result,
            "llm_out": llm_out,
        }
        print("**169",self.backend)
        if self.backend == "opa":
            try:
                result = self._get_opa().decide(opa_input)
                print("**174")
                if self.opa_attach_bundle_status:
                    try:
                        status = self._get_opa().bundle_status()
                        result = {**result, "opa": {"status_hash": OPAClient.stable_hash(status), "status": status}}
                    except Exception:
                        result = {**result, "opa": {"status_error": True}}

                return {
                    "decision": result.get("decision", "deny"),
                    "action": result.get("action") or ("deny" if result.get("decision") == "deny" else "allow"),
                    "reason": result.get("reason", "Denied by OPA policy"),
                    "rule_id": result.get("rule_id"),
                    "policy_version": result.get("policy_version", "opa-v1"),
                    "mode": result.get("mode", _env_mode_default()),
                    "obligations": result.get("obligations", []),
                }

            except Exception as e:
                # Healthcare-safe default: fail CLOSED
                if self.opa_fail_mode == "open":
                    return self._decision(
                        decision="allow",
                        action="allow",
                        reason=f"OPA unavailable (fail-open): {type(e).__name__}",
                        rule_id="OPA_FAIL_OPEN",
                        policy_version="opa-unavailable",
                    )
                return self._decision(
                    decision="deny",
                    action="deny",
                    reason=f"OPA unavailable (fail-closed): {type(e).__name__}",
                    rule_id="OPA_FAIL_CLOSED",
                    policy_version="opa-unavailable",
                )

        # Python fallback
        stage_signals = dict(signals)
        stage_signals["stage"] = stage
        stage_signals["tool"] = None if tool is None else {"name": getattr(tool, "name", None), "args": getattr(tool, "args", None)}
        if llm_out and isinstance(llm_out, dict):
            stage_signals["llm_text"] = llm_out.get("output_text") or llm_out.get("text") or ""
        return self.evaluate(message, signals=stage_signals)
