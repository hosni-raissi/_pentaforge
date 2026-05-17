FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=600 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    PENTAFORGE_SANDBOX_SERVICE=1 \
    GOPATH=/opt/go \
    GOBIN=/usr/local/bin \
    PATH=/usr/local/bin:/opt/go/bin:/opt/pentaforge-tools/bin:${PATH}

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    aapt \
    arping \
    arp-scan \
    bash \
    build-essential \
    ca-certificates \
    cloc \
    curl \
    default-jre-headless \
    dnsutils \
    docker.io \
    git \
    golang-go \
    jq \
    libgomp1 \
    libpcap-dev \
    mtr-tiny \
    nmap \
    nodejs \
    npm \
    ruby-full \
    sslscan \
    sudo \
    traceroute \
    unzip \
    wget \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY infra/docker/install-sandbox-tools.sh /usr/local/bin/install-sandbox-tools.sh
RUN chmod +x /usr/local/bin/install-sandbox-tools.sh && \
    /usr/local/bin/install-sandbox-tools.sh
