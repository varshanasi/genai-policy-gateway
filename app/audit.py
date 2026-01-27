import sqlite3
import uuid
import json
from datetime import datetime
from typing import Dict, Any

DB_PATH = os.getenv("AUDIT_DB_PATH","/tmp/genai-policy-gateway/audit.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        audit_id TEXT,
        timestamp TEXT,
        user_role TEXT,
        decision TEXT,
        rule_id TEXT,
        reason TEXT,
        policy_version TEXT,
        guardrails_json TEXT
    )
    """)
    conn.commit()
    conn.close()

def write_audit(user_role: str, decision_obj: Dict[str, Any], guardrails: Dict[str, Any]) -> str:
    audit_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    INSERT INTO audit_log (
        audit_id, timestamp, user_role, decision, rule_id, reason, policy_version, guardrails_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        audit_id,
        datetime.utcnow().isoformat(),
        user_role,
        decision_obj.get("decision"),
        decision_obj.get("rule_id"),
        decision_obj.get("reason"),
        decision_obj.get("policy_version"),
        json.dumps(guardrails, ensure_ascii=False),
    ))
    conn.commit()
    conn.close()
    return audit_id
