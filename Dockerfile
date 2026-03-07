FROM python:3.13-slim

# System deps for git repo cloning
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer caching)
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt

# Copy application code
COPY server/ /app/server/

# Data volume mount point
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1
ENV KNOWLEDGE_DATA_DIR=/app/data

ENTRYPOINT ["python", "-m", "server.db.knowledge"]
CMD ["sources"]
