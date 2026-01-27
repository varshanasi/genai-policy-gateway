# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- System deps (cached) ----
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc g++ \
      git curl \
      libxml2-dev libxslt1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Python deps first (better layer caching) ----
COPY requirements.txt /tmp/requirements.txt

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    python -m pip install --upgrade pip setuptools wheel \
 && python -m pip install -r /tmp/requirements.txt \
 && python -m pip install "guardrails-ai[api]>=0.6.8" \
 && rm -f /tmp/requirements.txt

# ---- Configure Guardrails CLI (token via secret) ----
# Guardrails docs: install guardrails-ai then run `guardrails configure` :contentReference[oaicite:3]{index=3}
ARG GUARDRAILS_TOKEN
RUN guardrails configure --enable-metrics --enable-remote-inferencing --token $GUARDRAILS_TOKEN


# ---- Install Hub validators (NOT pip install) ----
# Hub/CLI usage :contentReference[oaicite:4]{index=4}
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    guardrails hub install hub://guardrails/guardrails_pii --quiet \
 && guardrails hub install hub://guardrails/regex_match --quiet \
 && guardrails hub install hub://guardrails/detect_jailbreak --quiet \
 && guardrails hub install hub://groundedai/grounded_ai_hallucination --quiet

# ---- Copy app code last ----
COPY . /app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
