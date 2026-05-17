FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=600 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    PENTAFORGE_RELOAD=0 \
    PROJECTS_DB_PATH=/data/projects/projects.db \
    KNOWLEDGE_DATA_DIR=/data/knowledge \
    KNOWLEDGE_CACHE_DIR=/data/knowledge/cache \
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
RUN pip install --prefer-binary --extra-index-url https://download.pytorch.org/whl/cpu "torch==2.3.1+cpu" && \
    pip install --prefer-binary -r /tmp/requirements.txt && \
    pip install --prefer-binary git+https://github.com/GerbenJavado/LinkFinder.git

COPY server /app/server

RUN mkdir -p \
    /data/projects \
    /data/knowledge/cache \
    /data/huggingface \
    /app/server/cache \
    /app/server/logs

EXPOSE 8000

CMD ["uvicorn", "server.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
