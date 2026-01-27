# import os
# import math
# import requests
# from typing import Dict

# NEMO_URL = os.getenv(
#     "NEMO_HEURISTICS_URL",
#     "http://nemo-heuristics:1337/heuristics",
# )

# # NeMo reference thresholds
# LPP_THRESHOLD = 89.79
# PSP_THRESHOLD = 1845.65

# def _sigmoid(x: float) -> float:
#     return 1.0 / (1.0 + math.exp(-x))

# def nemo_injection_score(llm_output: str) -> Dict:
#     """
#     Returns a deterministic injection score (0..1) from NeMo heuristics.
#     No prompts. No LLM calls.
#     """
#     r = requests.post(
#         NEMO_URL,
#         json={"text": llm_output},
#         timeout=1.0,
#     )
#     r.raise_for_status()
#     h = r.json()

#     lpp = float(h["length_per_perplexity"])
#     psp = float(h["prefix_suffix_perplexity"])

#     # Normalize vs NeMo thresholds
#     ratio_lpp = lpp / LPP_THRESHOLD
#     ratio_psp = psp / PSP_THRESHOLD

#     # Worst-case risk drives the score
#     risk_ratio = max(ratio_lpp, ratio_psp)

#     # Map to 0..1 (risk_ratio ~= 1 is the boundary)
#     score = _sigmoid((risk_ratio - 1.0) * 6.0)

#     return {
#         "injection_score": round(score, 4),
#         "injection_any": score >= 0.5,
#         "metrics": {
#             "length_per_perplexity": lpp,
#             "prefix_suffix_perplexity": psp,
#         },
#         "ratios": {
#             "length_per_perplexity": round(ratio_lpp, 3),
#             "prefix_suffix_perplexity": round(ratio_psp, 3),
#             "risk_ratio": round(risk_ratio, 3),
#         },
#         "thresholds": {
#             "length_per_perplexity": LPP_THRESHOLD,
#             "prefix_suffix_perplexity": PSP_THRESHOLD,
#         },
#     }
