# PentaForge Knowledge DB CLI Commands

All commands run from repo root:

```bash
python -m server.db.knowledge.cli <command> [options]
```

## What the DB uses

- Vectors: Qdrant (content stored as chunks + metadata)
- Search cache: Redis
- Local caches/stores: SQLite files under `server/db/knowledge/data/`
- Repos: git clones under `server/db/knowledge/data/repos/`

## 1) Ingest Commands

### Ingest one source

```bash
python -m server.db.knowledge.cli ingest --source HackTricks
```

What it does:
- Pulls/extracts that source
- Deduplicates by document identity + content hash
- Chunks, embeds, and upserts into Qdrant

### Ingest one domain

```bash
python -m server.db.knowledge.cli ingest --domain shared
python -m server.db.knowledge.cli ingest --domain api
```

What it does:
- Ingests all configured sources for that domain
- Skips unchanged documents automatically

### Ingest all enabled sources

```bash
python -m server.db.knowledge.cli ingest --all
```

### Control source concurrency

```bash
python -m server.db.knowledge.cli ingest --domain web --concurrency 2
```

Note:
- Higher concurrency is faster but uses more CPU/RAM/VRAM.

### Fast ingest preset (recommended for very large runs)

```bash
python -m server.db.knowledge.cli ingest --domain shared --fast
```

What `--fast` changes for this run:
- Embedding batch size: `256`
- Chunk size: `900`
- Chunk overlap: `80`
- Minimum chunk words: `40`

Use this when full ingest would otherwise take hours.

### Manual ingest tuning (one-off overrides)

```bash
python -m server.db.knowledge.cli ingest --domain shared \
	--embedding-batch-size 256 \
	--chunk-size 900 \
	--chunk-overlap 80 \
	--min-chunk-words 40
```

## 2) Search Commands

### Search globally

```bash
python -m server.db.knowledge.cli search "jwt none alg bypass"
```

### Search by domain (includes `shared` by default)

```bash
python -m server.db.knowledge.cli search "rate limiting" --domain api
```

### Strict domain-only search (exclude `shared`)

```bash
python -m server.db.knowledge.cli search "rate limiting" --domain api --no-shared
```

### Search by source

```bash
python -m server.db.knowledge.cli search "xss polyglot" --source PayloadsAllTheThings
```

### Hybrid search (semantic + payload text)

```bash
python -m server.db.knowledge.cli search "jwt none algorithm bypass" --domain api --with-payloads
```

### Control payload match count in hybrid search

```bash
python -m server.db.knowledge.cli search "xss" --domain web --with-payloads --payload-results 20
```

### Number of hits

```bash
python -m server.db.knowledge.cli search "ssrf" -n 10
```

## 3) Source Listing

### List all configured sources

```bash
python -m server.db.knowledge.cli sources
```

### List sources for one domain

```bash
python -m server.db.knowledge.cli sources --domain shared
```

## 4) Stats

### Show DB stats

```bash
python -m server.db.knowledge.cli stats
```

What it shows:
- Qdrant collections and point counts
- Total chunks

## 5) Delete Source Data

### Delete one source from vector DB

```bash
python -m server.db.knowledge.cli delete --source HackTricks
```

This is the command you asked about (`delete --source <SOURCE_NAME>`).

What it does:
- Removes all chunks in Qdrant for that `source_name`
- Clears cached search entries

What it does not do:
- Does not remove the source definition from `sources.py`
- Does not delete local git repo folders

Use when:
- You no longer want that source data in RAG
- You want a clean re-ingest for one source

## 6) Reset Everything

### Full knowledge reset

```bash
python -m server.db.knowledge.cli reset --confirm
```

What it does:
- Resets all knowledge vector collections
- Effectively clears indexed chunk data

Warning:
- Destructive operation. Use only when you want to rebuild from scratch.

## 7) CVE Commands

### Lookup one CVE

```bash
python -m server.db.knowledge.cli cve lookup CVE-2024-3094
```

### Search CVEs by keyword

```bash
python -m server.db.knowledge.cli cve search "Apache Tomcat" --severity CRITICAL --days 365 -n 20
```

### Seed common CVEs

```bash
python -m server.db.knowledge.cli cve seed --severity CRITICAL --days 90
```

## 8) Payload Store Commands

### Ingest all raw payloads

```bash
python -m server.db.knowledge.cli ingest-payloads
```

### Ingest payloads for one domain

```bash
python -m server.db.knowledge.cli ingest-payloads --domain web
```

## Safe Retry Behavior

- Stopping and retrying ingestion is generally safe.
- The pipeline deduplicates unchanged docs by content hash.
- If you suspect a source was interrupted in a bad state, run:

```bash
python -m server.db.knowledge.cli delete --source <SOURCE_NAME>
python -m server.db.knowledge.cli ingest --source <SOURCE_NAME>
```

format mark down, 
NIST
profile