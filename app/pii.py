import re
from typing import Dict

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
# India-ish phone: simple demo heuristic (10 digits, optional +91, spaces/dashes)
PHONE_RE = re.compile(r"(\+?91[\s-]?)?\b[6-9]\d{9}\b")
AADHAAR_LIKE_RE = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")

def detect_pii(text: str) -> Dict[str, bool]:
    return {
        "email": bool(EMAIL_RE.search(text)),
        "phone": bool(PHONE_RE.search(text)),
        "aadhaar_like": bool(AADHAAR_LIKE_RE.search(text)),
    }

def pii_any(pii: Dict[str, bool]) -> bool:
    return any(pii.values())
