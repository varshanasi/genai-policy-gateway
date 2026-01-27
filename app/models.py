from pydantic import BaseModel
from typing import Optional, Dict, Any

class ToolRequest(BaseModel):
    name: str
    args: Dict[str, Any] = {}

class ChatRequest(BaseModel):
    message: str
    user_role: str = "analyst"
    tool: Optional[ToolRequest] = None

class ChatResponse(BaseModel):
    audit_id: str
    decision: str
    rule_id: Optional[str]
    reason: str
    policy_version: str
    guardrails: Dict[str, Any]
    tool_result: Optional[Dict[str, Any]] = None
    llm: Optional[Dict[str, Any]] = None
