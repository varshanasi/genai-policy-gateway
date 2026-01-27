import re
from typing import Dict, Any, Tuple, Optional
import httpx

DESTRUCTIVE_SQL = re.compile(r"\b(delete|drop|truncate|alter)\b", re.I)
DDL = re.compile(r"^\s*(drop|alter|truncate|create|rename)\b", re.IGNORECASE)
DML = re.compile(r"^\s*(insert|update|delete|merge|replace)\b", re.IGNORECASE)
SELECT = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
HAS_LIMIT = re.compile(r"\blimit\s+\d+\b", re.IGNORECASE)

def analyze_sql(query: str) -> Dict[str, Any]:
    q = (query or "").strip()
    return {
        "sql_query_len": len(q),
        "is_select": bool(SELECT.search(q)),
        "has_limit": bool(HAS_LIMIT.search(q)),
        "has_ddl": bool(DDL.search(q)),
        "has_dml": bool(DML.search(q)),
        # optional backward-compat for old keys
        "sql_is_destructive": bool(DDL.search(q) or DML.search(q)),
        "sql_is_select": bool(SELECT.search(q)),
    }

def execute_sql_query(args: Dict[str, Any]) -> Dict[str, Any]:
    # Demo tool: DO NOT connect to prod. For demo, we just echo.
    query = args.get("query", "")
    return {
        "tool": "sql_query",
        "status": "ok",
        "result_preview": f"(demo) would execute SQL: {query[:120]}"
    }

def execute_http_get(args: Dict[str, Any]) -> Dict[str, Any]:
    url = args.get("url", "")
    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
        r = client.get(url)
        text = r.text[:500]  # keep small
        return {
            "tool": "http_get",
            "status": "ok",
            "http_status": r.status_code,
            "body_preview": text
        }

def get_domain(url: str) -> Optional[str]:
    # very lightweight domain parse (good enough for demo)
    m = re.match(r"^https?://([^/]+)/?", url.strip(), re.I)
    return m.group(1).lower() if m else None

class ToolProxy:
    def __init__(self):
        self.registry = {
            "sql_query": execute_sql_query,
            "http_get": execute_http_get,
        }

    def execute(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.registry:
            return {"tool": tool_name, "status": "error", "error": "Unknown tool"}
        return self.registry[tool_name](args)
