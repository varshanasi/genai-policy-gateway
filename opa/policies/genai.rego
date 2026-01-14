package genai

default decision = {
  "decision": "allow",
  "action": "allow",
  "rule_id": "DEFAULT_ALLOW",
  "reason": "Allowed",
  "mode": "enforce",
  "policy_version": "opa-v1",
  "obligations": []
}

# -----------------------
# Normalized input values
# -----------------------

stage = s {
  s := lower(input.stage)
} else = "pre"

inj_score = s {
  s := to_number(input.signals.injection_score)
} else = 0.0

inj_hits = hs {
  hs := input.signals.injection_hits
} else = []

pii_any = b {
  b := input.signals.pii_any
} else = false

tool_name = n {
  n := lower(input.tool.name)
} else = ""

tool_domain = d {
  d := lower(input.signals.tool_domain)
} else = ""

sql_is_destructive = b {
  b := input.signals.sql_is_destructive
} else = false

sql_is_select = b {
  b := input.signals.sql_is_select
} else = false

sql_has_limit = b {
  b := input.signals.sql_has_limit
} else = false

mode = m {
  m := lower(input.signals.policy_mode)
} else = m {
  m := lower(input.signals.mode)
} else = "enforce"

allowed_domains := {
  "cdc.gov",
  "www.cdc.gov",
  "nih.gov",
  "www.nih.gov",
}

critical_markers := {
  "system prompt",
  "developer",
  "bypass",
  "ignore",
  "jailbreak",
  "api key",
  "credentials",
  "secret",
  "reveal",
}

leak_markers := {
  "system prompt",
  "developer message",
  "api key",
  "credentials",
}

# -----------------------
# Helper predicates
# -----------------------

high_sev_injection {
  some i
  h := lower(inj_hits[i])
  some m
  m := critical_markers[_]
  contains(h, m)
}

llm_out_text = t {
  t := lower(input.llm_out.output_text)
} else = ""

has_leak_marker {
  some m
  m := leak_markers[_]
  contains(llm_out_text, m)
}

# -----------------------
# PRE stage
# -----------------------

decision = {
  "decision": "allow",
  "action": "safe_completion",
  "rule_id": "INJ_PRE_SAFE_COMPLETION",
  "reason": "Prompt-injection attempt detected; forcing safe completion",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_injection"]
} {
  stage == "pre"
  high_sev_injection
  inj_score >= 0.10
}

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "INJ_PRE_DENY",
  "reason": sprintf("Prompt-injection risk too high (score=%.2f)", [inj_score]),
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_injection"]
} {
  stage == "pre"
  inj_score >= 0.85
}

decision = {
  "decision": "allow",
  "action": "safe_completion",
  "rule_id": "INJ_PRE_SAFE_COMPLETION_SCORE",
  "reason": sprintf("Prompt-injection risk elevated (score=%.2f); forcing safe completion", [inj_score]),
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_injection"]
} {
  stage == "pre"
  inj_score >= 0.35
  inj_score < 0.85
}

decision = {
  "decision": "allow",
  "action": "redact_and_allow",
  "rule_id": "PII_PRE_REDACT",
  "reason": "PII detected; redacting before processing",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_pii_redaction"]
} {
  stage == "pre"
  pii_any
}

# -----------------------
# TOOL stage
# -----------------------

decision = {
  "decision": "allow",
  "action": "allow_no_tools",
  "rule_id": "INJ_TOOL_BLOCK_TOOLS",
  "reason": "Injection signals present; tools disabled for this request",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_injection"]
} {
  stage == "tool"
  inj_score >= 0.20
  count(inj_hits) > 0
}

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "SQL_DESTRUCTIVE_DENY",
  "reason": "Destructive SQL statements are not allowed",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_security_event"]
} {
  stage == "tool"
  tool_name == "sql_query"
  sql_is_destructive
}

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "SQL_LIMIT_REQUIRED",
  "reason": "SQL SELECT must include LIMIT",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_sensitive_access"]
} {
  stage == "tool"
  tool_name == "sql_query"
  sql_is_select
  not sql_has_limit
}

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "HTTP_DOMAIN_UNKNOWN",
  "reason": "URL domain could not be determined",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_security_event"]
} {
  stage == "tool"
  tool_name == "http_get"
  tool_domain == ""
}

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "HTTP_DOMAIN_DENY",
  "reason": sprintf("Domain not allowed: %s", [tool_domain]),
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_security_event"]
} {
  stage == "tool"
  tool_name == "http_get"
  tool_domain != ""
  not (tool_domain in allowed_domains)
}

# -----------------------
# POST stage
# -----------------------

decision = {
  "decision": "allow",
  "action": "redact_and_allow",
  "rule_id": "PII_POST_REDACT",
  "reason": "Redacting sensitive content after tool execution",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_pii_redaction"]
} {
  stage == "post"
  pii_any
}

# -----------------------
# RESPONSE stage
# -----------------------

decision = {
  "decision": "deny",
  "action": "deny",
  "rule_id": "PROMPT_LEAK_OUTPUT_DENY",
  "reason": "Potential prompt/secret leakage detected in model output",
  "mode": mode,
  "policy_version": "opa-v1",
  "obligations": ["log_security_event"]
} {
  stage == "response"
  has_leak_marker
}
