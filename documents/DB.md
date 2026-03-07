When you run ingest --all again after already ingesting
It skips everything that hasn't changed. The pipeline uses a content-hash dedup system:

For each document extracted, a content_hash (SHA-256 of the content) is computed
Before processing, it checks PostgreSQL: SELECT id FROM knowledge_documents WHERE source_name = $1 AND content_hash = $2
If the hash exists → skip (counted as skipped_existing)
If the hash is new → clean → chunk → embed → store
So running ingest --all a second time is fast — it clones/fetches the repos, scans files, but skips all unchanged documents.

When you ADD a new source to sources.py
Next ingest --all will:

Skip all existing sources (content hashes already in Postgres)
Ingest only the new source — extract, chunk, embed, store in the correct vector_<domain> collection
When you DELETE a source from sources.py
The old data stays in ChromaDB and PostgreSQL. Removing a source from sources.py just means it won't be re-ingested — but the already-stored vectors and metadata remain.

To actually clean up the deleted source's data, you need to explicitly run:

This removes it from both PostgreSQL and the vector collection.

When upstream content changes (e.g. PayloadsAllTheThings updates a file)
The file will have a different content hash, so:

Old hash → still in the DB (stale)
New hash → doesn't match → gets ingested as new
Old chunks remain alongside new ones (no automatic cleanup of stale versions)


# Stop containers and DELETE all volumes (vectors + postgres + cloned repos)
docker compose down -v

# Rebuild and start clean
docker compose build knowledge
docker compose up -d postgres

# Wait a few seconds for postgres to be ready, then ingest
docker compose run --rm knowledge ingest --domain shared