# from pydantic import BaseModel, Field
# from guardrails.hub import DetectPII,RegexMatch,DetectJailbreak,GroundedAIHallucination
# from guardrails import Guard


# def detect_PII(input_text: str):
#     try:
#         guard1 = Guard().use_many(DetectPII(pii_entities =["EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD_NUMBER","US_SOCIAL_SECURITY_NUMBER","PERSON","LOCATION"],on_fail="noop"))
#         result = guard1.parse(llm_output=input_text)
#         return result
#     except Exception as e:
#         return str(e)
    
# def detect_jailBreak(input_text: str):
#     try:
#         guard2 = Guard().use(DetectJailbreak(on_fail="noop"))
#         result = guard2.parse(llm_output=input_text)
#         return result
#     except Exception as e:
#         return str(e)
    
# def detect_hallucination(input_text: str):
#     try:
#         guard3 = Guard().use(GroundedAIHallucination(on_fail="noop",quant=False))
#         result = guard3.parse(llm_output=input_text)
#         return result
#     except Exception as e:
#         return str(e)

from typing import Any, Dict, List, Optional, Union
from presidio_analyzer import AnalyzerEngine
from guardrails import Guard
from guardrails.hub import DetectPII, DetectJailbreak
import regex as re

PII_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "PERSON",
    "LOCATION",
]
PATTERNS = [
    (re.compile(r"ignore (all|previous) instructions", re.I), 0.35),
    (re.compile(r"reveal (the )?system prompt", re.I), 0.45),
    (re.compile(r"you are (now )?(developer|system)", re.I), 0.25),
    (re.compile(r"bypass|jailbreak|do anything now", re.I), 0.35),
    (re.compile(r"call (the )?tool|use (the )?tool", re.I), 0.15),
    (re.compile(r"exfiltrate|leak|dump|print secrets", re.I), 0.45),
]


_pii_guard = Guard().use_many(
    DetectPII(pii_entities=PII_ENTITIES, on_fail="noop"),
)
analyzer = AnalyzerEngine()

_jb_guard = Guard().use(
    DetectJailbreak(on_fail="noop"),
)

def inj_passed(outcome: Any) -> bool | None:
    if outcome is None or isinstance(outcome, str):
        return None
    return getattr(outcome, "validation_passed", None)

def inj_error(outcome: Any) -> str:
    if outcome is None or isinstance(outcome, str):
        return ""
    err = getattr(outcome, "error", None)
    return "" if err is None else str(err)


def pii_error(outcome: Any) -> str:
    """Best-effort extraction of an error string from a ValidationOutcome-like object."""
    if outcome is None:
        return ""
    if isinstance(outcome, str):
        return outcome
    err = getattr(outcome, "error", None)
    return "" if err is None else str(err)


def pii_passed(outcome: Any) -> Optional[bool]:
    """Best-effort extraction of pass/fail from ValidationOutcome-like object."""
    if outcome is None or isinstance(outcome, str):
        return None
    vp = getattr(outcome, "validation_passed", None)
    return None if vp is None else bool(vp)


def detect_pii_guardrails(input_text: str) -> Dict[str, Any]:
    """
    Signal-only PII detection using Guardrails Hub DetectPII.
    Returns a stable dict for your OPA input.
    """
    try:
        out = _pii_guard.parse(llm_output=input_text)
        print("***82",out)
        passed = pii_passed(out)
        err = pii_error(out)
        results = analyzer.analyze(
                text=input_text,
                language="en",
                entities=PII_ENTITIES
            )

        # If validationpii_passed == False => PII detected (most common behavior)
        pii_any = (passed is False)

        # Keep it simple + stable for OPA: include raw error text as "hits"
        print(results[0])
        return {
            "provider": "guardrails",
            "validationpii_passed": passed,
            "pii_any": pii_any,
            "pii_entities": {} if passed else {results[i].entity_type:True for i in range(len(results))},
            "pii_hits": [],
            "error": err or None,
        }
    except Exception as e:
        # Fail safe: if the detector errors, do NOT block; but expose telemetry
        return {
            "provider": "guardrails",
            "validation_passed": None,
            "pii_any": False,
            "pii_entities": [],
            "pii_hits": [],
            "error": f"{type(e).__name__}: {e}",
        }


def injection_score_guardrails(input_text: str) -> Dict[str, Any]:
    """
    Signal-only jailbreak/injection detection using Guardrails Hub DetectJailbreak.
    DetectJailbreak conceptually outputs ~0.0 safe -> 1.0 jailbreak, with a threshold knob. :contentReference[oaicite:3]{index=3}
    We return:
      - injection_score: float
      - injection_hits: list[str]
    """
    try:
        out = _jb_guard.parse(llm_output=input_text)
        print("***126",out)
        passed = pii_passed(out)
        err = pii_error(out)

        score = 0.0 if passed is True else (1.0 if passed is False else 0.0)

        hits: List[str] = []
        if passed is False and err:
            hits.append(err)

        return {
            "provider": "guardrails",
            "validation_passed": passed,
            "injection_score": float(score),
            "injection_hits": hits,
            "error": err or None,
        }
    except Exception as e:
        return {
            "provider": "guardrails",
            "validation_passed": None,
            "injection_score": 0.0,
            "injection_hits": [],
            "error": f"{type(e).__name__}: {e}",
        }

def normalize_guardrails_signals(
    *,
    user_role: str,
    pii_out: dict,
    inj_out: dict,
    tool_name: str | None,
) -> dict:
    """
    Convert Guardrails outputs into legacy signal format
    """

    error_text = (pii_out.get("error") or "").upper()

    pii_map = {
        "email": "EMAIL" in error_text,
        "phone": "PHONE" in error_text,
        # Guardrails doesn't detect Aadhaar explicitly → heuristic
        "aadhaar_like": any(k in error_text for k in ["AADHAAR", "INDIA_ID", "UID"]),
    }

    pii_any = any(pii_map.values())

    return {
        "user_role": user_role,
        "pii": pii_map,
        "pii_any": pii_any,
        "injection_score": float(inj_out.get("injection_score", 0.0)),
        "injection_hits": inj_out.get("injection_hits", []),
        "tool_name": tool_name or "string",
    }

def _heuristic_injection(text: str) -> Dict[str, Any]:
    hits: List[str] = []
    score = 0.0

    for rx, weight in PATTERNS:
        if rx.search(text):
            hits.append(rx.pattern)
            score += weight

    return {
        "score": min(1.0, score),
        "hits": hits,
    }


def injection_score_combined(text: str) -> Dict[str, Any]:
    """
    Combines:
      - Guardrails DetectJailbreak (binary authority)
      - Regex heuristics (graded, explainable)

    Output is OPA-friendly and stable.
    """

    # 1) Guardrails signal
    try:
        gr_out = _jb_guard.parse(llm_output=text)
        gr_passed = inj_passed(gr_out)
        gr_error = inj_error(gr_out)
    except Exception as e:
        gr_passed = None
        gr_error = f"{type(e).__name__}: {e}"

    # 2) Heuristic signal
    heur = _heuristic_injection(text)

    # 3) Merge logic
    hits: List[str] = list(heur["hits"])
    score = heur["score"]

    if gr_passed is False:
        # Guardrails override → force high confidence
        score = max(score, 0.9)
        if gr_error:
            hits.append("guardrails_detect_jailbreak")

    # Clamp once at the end
    score = min(1.0, score)

    return {
        "provider": "guardrails+heuristics",
        "validation_passed": gr_passed,
        "injection_score": score,
        "injection_hits": hits,
    }