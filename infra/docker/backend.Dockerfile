FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    PENTAFORGE_RELOAD=0 \
    PROJECTS_DB_PATH=/data/projects/projects.db \
    HF_HOME=/data/huggingface \
    SENTENCE_TRANSFORMERS_HOME=/data/huggingface

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    libgomp1 \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

COPY server /app/server

RUN mkdir -p \
    /data/projects \
    /data/huggingface \
    /app/server/cache \
    /app/server/logs

EXPOSE 8000

CMD ["uvicorn", "server.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
