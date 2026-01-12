from prometheus_client import Counter,Histogram

REQUESTS_TOTAL = Counter("requests_total", "Total number of requests")

POLICY_DENIES_TOTAL = Counter(
    "policy_denies_total",
    "Total denied requests",
    ["rule_id"]
)

TOOL_CALLS_TOTAL = Counter(
    "tool_calls_total",
    "Total tool calls executed",
    ["tool"]
)

LLM_CALLS_TOTAL = Counter("llm_calls_total", "Total LLM calls")
LLM_LATENCY_MS = Histogram("llm_latency_ms", "LLM call latency in ms")
