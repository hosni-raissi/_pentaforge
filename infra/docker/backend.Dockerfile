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
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    apktool \
    default-jdk-headless \
    libcairo2-dev \
    libgomp1 \
    nmap \
    p7zip-full \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt /tmp/requirements.txt
RUN for attempt in 1 2 3; do \
        pip install --prefer-binary --extra-index-url https://download.pytorch.org/whl/cpu "torch==2.3.1+cpu" && break; \
        if [ "$attempt" -eq 3 ]; then exit 1; fi; \
        echo "torch install failed on attempt $attempt, retrying..." >&2; \
        sleep 5; \
    done && \
    pip install --prefer-binary -r /tmp/requirements.txt && \
    pip install --prefer-binary semgrep safety mitmproxy && \
    VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d "\"" -f 4 || echo "v8.18.2") && \
    if [ -z "$VERSION" ]; then VERSION="v8.18.2"; fi && \
    VERSION_NO_V=${VERSION#v} && \
    curl -L "https://github.com/gitleaks/gitleaks/releases/download/${VERSION}/gitleaks_${VERSION_NO_V}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | bash -s -- -b /usr/local/bin && \
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
