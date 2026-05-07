FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    PENTAFORGE_SANDBOX_SERVICE=1

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

RUN mkdir -p /app/server/sandbox /app/server/cache /app/server/logs

EXPOSE 8010

CMD ["uvicorn", "server.sandbox_service.app:app", "--host", "0.0.0.0", "--port", "8010"]
