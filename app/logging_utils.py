import json
from datetime import datetime
from typing import Any, Dict

def log_event(level: str, event: str, payload: Dict[str, Any]) -> None:
    record = {
        "ts": datetime.utcnow().isoformat(),
        "level": level,
        "event": event,
        **payload,
    }
    print(json.dumps(record, ensure_ascii=False))
