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

# Install basic system utilities, apt packages, and cloud SDKs
RUN apt-get update && apt-get install -y --no-install-recommends \
    aapt arping arp-scan bash build-essential ca-certificates cloc curl \
    default-jre-headless dnsutils docker.io git golang-go jq libgomp1 \
    libpcap-dev mtr-tiny nmap nodejs npm ruby-full sslscan sudo traceroute \
    unzip wget whois libcairo2-dev pkg-config masscan whatweb wireshark-common \
    dnsrecon fping ike-scan ldap-utils nbtscan netdiscover nfs-common \
    onesixtyone proxychains4 rpcbind smbclient snmp tcpdump tshark apktool \
    binwalk default-jdk-headless awscli kubernetes-client skopeo yq hydra \
    john openssh-client ftp hashcat netcat-traditional protobuf-compiler \
    iputils-ping gnupg \
    && echo "wireshark-common wireshark-common/install-sysusers boolean true" | debconf-set-selections \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main" > /etc/apt/sources.list.d/azure-cli.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli azure-cli google-cloud-sdk \
    && rm -rf /var/lib/apt/lists/*

# Install npm global packages
RUN npm install -g js-beautify wappalyzer-cli retire newman

# Install python dependencies (both requirements.txt and global tools)
COPY server/requirements.txt /tmp/requirements.txt
RUN for attempt in 1 2 3; do \
        pip install --prefer-binary --extra-index-url https://download.pytorch.org/whl/cpu "torch==2.3.1+cpu" && break; \
        if [ "$attempt" -eq 3 ]; then exit 1; fi; \
        echo "torch install failed on attempt $attempt, retrying..." >&2; \
        sleep 5; \
    done && \
    pip install --prefer-binary -r /tmp/requirements.txt && \
    pip install --prefer-binary wafw00f mitmproxy theHarvester bandit checkov apkid prowler safety semgrep shodan censys sshuttle s3scanner arjun param-miner pyjwt graphw00f git-dumper inql sslyze droopescan pyntcli detect-secrets knockpy ldapdomaindump bloodhound ssh-audit impacket smbmap crackmapexec netexec enum4linux-ng kube-hunter scoutsuite pacu stormspotter

COPY server /app/server

RUN mkdir -p /app/server/sandbox /app/server/sandbox/share /app/server/cache /app/server/logs \
    /usr/share/wordlists /usr/share/seclists /opt/wordlists && \
    ln -sfn /app/server/sandbox/share/wordlists /usr/share/wordlists/pentaforge && \
    ln -sfn /app/server/sandbox/share/seclists /usr/share/seclists/pentaforge && \
    ln -sfn /app/server/sandbox/share/seclists /usr/share/wordlists/SecLists && \
    ln -sfn /app/server/sandbox/share/wordlists /opt/wordlists/pentaforge && \
    ln -sfn /app/server/sandbox/share/wordlists /app/wordlists && \
    ln -sfn /app/server/sandbox/share/seclists /app/seclists

COPY infra/docker/install-sandbox-tools.sh /usr/local/bin/install-sandbox-tools.sh
RUN chmod +x /usr/local/bin/install-sandbox-tools.sh

EXPOSE 8010

CMD bash -c "/usr/local/bin/install-sandbox-tools.sh && exec uvicorn server.sandbox_service.app:app --host 0.0.0.0 --port 8010"
