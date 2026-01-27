package genai

# ----------------------------------------------------
# DEFAULT (must be a literal)
# ----------------------------------------------------
default decision := {
  "decision": "allow",
  "action": "allow",
  "rule_id": "DEFAULT_ALLOW",
  "reason": "Allowed",
  "mode": "enforce",
  "policy_version": "opa-v1",
  "obligations": []
}

# ----------------------------------------------------
# Safe access helpers
# ----------------------------------------------------

# Prefer nested input.signals if it's an object; else fall back to the root input
signals := s if {
  x := object.get(input, "signals", {})
  is_object(x)
  s := x
} else := input

stage := s if {
  x := object.get(input, "stage", "")
  is_string(x)
  s := lower(x)
} else := "pre"

mode := m if {
  x := object.get(signals, "policy_mode", "")
  is_string(x)
  m := lower(x)
} else := m2 if {
  x2 := object.get(signals, "mode", "")
  is_string(x2)
  m2 := lower(x2)
} else := "enforce"

inj_score := s if {
  x := object.get(signals, "injection_score", 0.0)
  is_number(x)
  s := x
} else := s if {
  x := object.get(signals, "injection_score", "0")
  is_string(x)
  s := to_number(x)
} else := 0.0

inj_hits := hs if {
  x := object.get(signals, "injection_hits", [])
  is_array(x)
  hs := x
} else := []

pii_any := b if {
  x := object.get(signals, "pii_any", false)
  is_boolean(x)
  b := x
} else := false

tool_domain := d if {
  x := object.get(signals, "tool_domain", "")
  is_string(x)
  d := lower(x)
} else := ""

# tool_name: accept either input.tool.name (object) OR flat input.tool_name
tool_name := n if {
  t := object.get(input, "tool", {})
  is_object(t)
  x := object.get(t, "name", "")
  is_string(x)
  n := lower(x)
} else := n2 if {
  x2 := object.get(input, "tool_name", "")
  is_string(x2)
  n2 := lower(x2)
} else := ""

sql_is_destructive := b if {
  x := object.get(signals, "sql_is_destructive", false)
  is_boolean(x)
  b := x
} else := false

sql_is_select := b if {
  x := object.get(signals, "sql_is_select", false)
  is_boolean(x)
  b := x
} else := false

sql_has_limit := b if {
  x := object.get(signals, "sql_has_limit", false)
  is_boolean(x)
  b := x
} else := false

llm_out_text := t if {
  o := object.get(input, "llm_out", {})
  is_object(o)
  x := object.get(o, "output_text", "")
  is_string(x)
  t := lower(x)
} else := ""

# ----------------------------------------------------
# Constant sets
# ----------------------------------------------------
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

# ----------------------------------------------------
# Derived predicates
# ----------------------------------------------------
high_sev_injection if {
  some i
  h := lower(inj_hits[i])
  some m
  critical_markers[m]
  contains(h, m)
}

has_leak_marker if {
  some m
  leak_markers[m]
  contains(llm_out_text, m)
}

# ----------------------------------------------------
# Stage decisions (return object or null)
# ----------------------------------------------------
decision_pre := obj if {
  stage == "pre"
  inj_score >= 0.85
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "INJ_PRE_DENY",
    "reason": sprintf("Prompt-injection risk too high (score=%.2f)", [inj_score]),
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_injection"],
  }
} else := obj if {
  stage == "pre"
  high_sev_injection
  inj_score >= 0.10
  obj := {
    "decision": "allow",
    "action": "safe_completion",
    "rule_id": "INJ_PRE_SAFE_COMPLETION",
    "reason": "Prompt-injection attempt detected; forcing safe completion",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_injection"],
  }
} else := obj if {
  stage == "pre"
  inj_score >= 0.35
  inj_score < 0.85
  obj := {
    "decision": "allow",
    "action": "safe_completion",
    "rule_id": "INJ_PRE_SAFE_COMPLETION_SCORE",
    "reason": sprintf("Prompt-injection risk elevated (score=%.2f); forcing safe completion", [inj_score]),
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_injection"],
  }
} else := obj if {
  stage == "pre"
  pii_any
  obj := {
    "decision": "allow",
    "action": "redact_and_allow",
    "rule_id": "PII_PRE_REDACT",
    "reason": "PII detected; redacting before processing",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_pii_redaction"],
  }
} else := null

decision_tool := obj if {
  stage == "tool"
  tool_name == "sql_query"
  sql_is_destructive
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "SQL_DESTRUCTIVE_DENY",
    "reason": "Destructive SQL statements are not allowed",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_security_event"],
  }
} else := obj if {
  stage == "tool"
  tool_name == "sql_query"
  sql_is_select
  not sql_has_limit
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "SQL_LIMIT_REQUIRED",
    "reason": "SQL SELECT must include LIMIT",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_sensitive_access"],
  }
} else := obj if {
  stage == "tool"
  tool_name == "http_get"
  tool_domain == ""
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "HTTP_DOMAIN_UNKNOWN",
    "reason": "URL domain could not be determined",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_security_event"],
  }
} else := obj if {
  stage == "tool"
  tool_name == "http_get"
  tool_domain != ""
  not allowed_domains[tool_domain]
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "HTTP_DOMAIN_DENY",
    "reason": sprintf("Domain not allowed: %s", [tool_domain]),
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_security_event"],
  }
} else := obj if {
  stage == "tool"
  inj_score >= 0.20
  count(inj_hits) > 0
  obj := {
    "decision": "allow",
    "action": "allow_no_tools",
    "rule_id": "INJ_TOOL_BLOCK_TOOLS",
    "reason": "Injection signals present; tools disabled for this request",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_injection"],
  }
} else := null

decision_post := obj if {
  stage == "post"
  pii_any
  obj := {
    "decision": "allow",
    "action": "redact_and_allow",
    "rule_id": "PII_POST_REDACT",
    "reason": "Redacting sensitive content after tool execution",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_pii_redaction"],
  }
} else := null

decision_response := obj if {
  stage == "response"
  has_leak_marker
  obj := {
    "decision": "deny",
    "action": "deny",
    "rule_id": "PROMPT_LEAK_OUTPUT_DENY",
    "reason": "Potential prompt/secret leakage detected in model output",
    "mode": mode,
    "policy_version": "opa-v1",
    "obligations": ["log_security_event"],
  }
} else := null

# ----------------------------------------------------
# Final override of decision (no recursion)
# ----------------------------------------------------
decision := d if { d := decision_pre; d != null }
  else := d if { d := decision_tool; d != null }
  else := d if { d := decision_post; d != null }
  else := d if { d := decision_response; d != null }
