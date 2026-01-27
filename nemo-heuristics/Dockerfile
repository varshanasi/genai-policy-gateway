# syntax=docker/dockerfile:1.7
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# --- System deps (cached with BuildKit) ---
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential g++ \
    && rm -rf /var/lib/apt/lists/*

# --- Python deps (cached with BuildKit) ---
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --upgrade pip setuptools wheel && \
    pip install \
      "nemoguardrails>=0.19.0" \
      torch \
      transformers \
      uvicorn

# --- FIX: make `heuristics` importable ---
# The server does: `import heuristics.checks as hc`
# That "heuristics" package lives inside nemoguardrails/library/jailbreak_detection.
# We add that folder to Python's search path via a .pth file (version-agnostic).
RUN python - <<'PY'
import site, pathlib, nemoguardrails
ng = pathlib.Path(nemoguardrails.__file__).resolve().parent
jb = ng / "library" / "jailbreak_detection"
pth_dir = pathlib.Path(site.getsitepackages()[0])
pth_file = pth_dir / "nemoguardrails_jailbreak_detection.pth"
pth_file.write_text(str(jb) + "\n")
print(f"Wrote {pth_file} -> {jb}")
PY

EXPOSE 1337
CMD ["python", "-m", "nemoguardrails.library.jailbreak_detection.server", "--port", "1337"]
