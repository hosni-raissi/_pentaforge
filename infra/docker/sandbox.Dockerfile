ARG SANDBOX_BASE_IMAGE=docker-tool-sandbox-base:latest
FROM ${SANDBOX_BASE_IMAGE}

WORKDIR /app

COPY server/requirements.txt /tmp/requirements.txt
RUN pip install --prefer-binary --extra-index-url https://download.pytorch.org/whl/cpu "torch==2.3.1+cpu" && \
    pip install --prefer-binary -r /tmp/requirements.txt

COPY server /app/server

RUN mkdir -p /app/server/sandbox /app/server/sandbox/share /app/server/cache /app/server/logs \
    /usr/share/wordlists /usr/share/seclists /opt/wordlists && \
    ln -sfn /app/server/sandbox/share/wordlists /usr/share/wordlists/pentaforge && \
    ln -sfn /app/server/sandbox/share/seclists /usr/share/seclists/pentaforge && \
    ln -sfn /app/server/sandbox/share/seclists /usr/share/wordlists/SecLists && \
    ln -sfn /app/server/sandbox/share/wordlists /opt/wordlists/pentaforge && \
    ln -sfn /app/server/sandbox/share/wordlists /app/wordlists && \
    ln -sfn /app/server/sandbox/share/seclists /app/seclists

EXPOSE 8010

CMD ["uvicorn", "server.sandbox_service.app:app", "--host", "0.0.0.0", "--port", "8010"]
