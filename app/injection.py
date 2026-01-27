import re
from typing import Dict, Any

# Heuristic patterns (simple + demoable)
PATTERNS = [
    (re.compile(r"ignore (all|previous) instructions", re.I), 0.35),
    (re.compile(r"reveal (the )?system prompt", re.I), 0.45),
    (re.compile(r"you are (now )?(developer|system)", re.I), 0.25),
    (re.compile(r"bypass|jailbreak|do anything now", re.I), 0.35),
    (re.compile(r"call (the )?tool|use (the )?tool", re.I), 0.15),
    (re.compile(r"exfiltrate|leak|dump|print secrets", re.I), 0.45),
]

def injection_score(text: str) -> Dict[str, Any]:
    hits = []
    score = 0.0

    for rx, w in PATTERNS:
        if rx.search(text):
            hits.append(rx.pattern)
            score += w

    # clamp 0..1
    score = min(1.0, score)
    print( ""f"[injection] score={score} hits={hits}" )
    return {
        "injection_score": score,
        "injection_hits": hits
    }
