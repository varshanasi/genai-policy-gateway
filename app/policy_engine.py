import yaml
from typing import Dict, Any, Optional, List

class PolicyEngine:
    def __init__(self, path="policy.yaml"):
        self.path = path
        with open(path) as f:
            self.policy = yaml.safe_load(f)
        print(type(self.policy), self.policy.keys())


    def evaluate(self, text: str, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        signals = signals or {}
        text_lower = text.lower()

        for rule in self.policy["rules"]:
            cond = rule.get("condition", {})

            # 1) contains_any keywords on message
            keywords = cond.get("contains_any")
            if keywords and any(k in text_lower for k in keywords):
                return self._deny(rule)

            # 2) pii_any signal
            if cond.get("pii_any") is True and signals.get("pii_any") is True:
                return self._deny(rule)

            # 3) injection_score threshold
            if "injection_score_gte" in cond:
                thr = float(cond["injection_score_gte"])
                if float(signals.get("injection_score", 0.0)) >= thr:
                    return self._deny(rule)

            # 4) tool_name match (if specified)
            if "tool_name" in cond:
                if signals.get("tool_name") != cond["tool_name"]:
                    continue

            # 5) domain allowlist check
            if "domain_not_in" in cond:
                allowed: List[str] = [d.lower() for d in cond["domain_not_in"]]
                domain = (signals.get("tool_domain") or "").lower()
                if domain and domain not in allowed:
                    return self._deny(rule)

            # 6) sql destructive flag check
            if "sql_is_destructive" in cond:
                if bool(signals.get("sql_is_destructive", False)) == bool(cond["sql_is_destructive"]):
                    # proceed to role check if any
                    pass
                else:
                    continue

            # 7) role restriction
            if "user_role_not_in" in cond:
                blocked_roles = set([r.lower() for r in cond["user_role_not_in"]])
                if (signals.get("user_role") or "").lower() in blocked_roles:
                    # role is blocked => deny (but condition says "not in", so invert)
                    continue
                # role NOT in blocked list => ok to keep evaluating other rules
                # (For this rule, other constraints already matched, so deny now)
                return self._deny(rule)

        return {
            "decision": "allow",
            "rule_id": None,
            "reason": "No policy violations",
            "policy_version": self.policy["version"],
        }

    def _deny(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "decision": "deny",
            "rule_id": rule["id"],
            "reason": rule["message"],
            "policy_version": self.policy["version"],
        }
