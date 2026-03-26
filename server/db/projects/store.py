"""SQLite-backed project store."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import projects_db_config


class ProjectsStore:
    """CRUD operations for project payloads persisted as JSON."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = Path(db_path or projects_db_config.projects_db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_records_updated_at
                ON records (updated_at DESC);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS share_links (
                    token TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    password_hash TEXT,
                    password_salt TEXT,
                    one_time INTEGER NOT NULL DEFAULT 0,
                    view_count INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_share_links_project_id
                ON share_links (project_id);
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_share_links_expires_at
                ON share_links (expires_at);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS intel_resources (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, target_type)
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_intel_resources_target_type
                ON intel_resources (target_type);
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_intel_resources_enabled
                ON intel_resources (enabled);
                """
            )
            conn.commit()

    def list_projects(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT payload
                FROM records
                ORDER BY updated_at DESC;
                """
            )
            rows = cur.fetchall()

        projects: list[dict[str, Any]] = []
        for row in rows:
            payload = row["payload"]
            try:
                parsed = json.loads(payload)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(parsed, dict):
                projects.append(parsed)
        return projects

    def upsert_project(self, project: dict[str, Any]) -> None:
        project_id = str(project.get("id", "")).strip()
        if not project_id:
            raise ValueError("project.id is required")
        payload = json.dumps(project, ensure_ascii=True)

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO records (id, payload, created_at, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT (id) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (project_id, payload),
            )
            conn.commit()

    def delete_project(self, project_id: str) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM records WHERE id = ?;", (project_id,))
            cur.execute("DELETE FROM share_links WHERE project_id = ?;", (project_id,))
            conn.commit()

    def create_share_link(
        self,
        project_id: str,
        *,
        expires_hours: int = 24,
        password: str | None = None,
        one_time: bool = False,
    ) -> dict[str, Any]:
        project = self.get_project(project_id)
        if project is None:
            raise ValueError("project not found")

        token = secrets.token_urlsafe(24)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        payload = json.dumps(self._sanitize_share_payload(project), ensure_ascii=True)

        password_hash: str | None = None
        password_salt: str | None = None
        if password:
            password_salt = secrets.token_hex(16)
            password_hash = self._hash_password(password, password_salt)

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO share_links (
                    token, project_id, payload, expires_at,
                    password_hash, password_salt, one_time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    token,
                    project_id,
                    payload,
                    expires_at.isoformat(),
                    password_hash,
                    password_salt,
                    1 if one_time else 0,
                ),
            )
            conn.commit()

        return {
            "token": token,
            "expires_at": expires_at.isoformat(),
            "one_time": one_time,
            "password_protected": bool(password_hash),
        }

    def access_share_link(self, token: str, *, password: str | None = None) -> dict[str, Any]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT token, payload, expires_at, password_hash, password_salt, one_time, view_count, revoked
                FROM share_links
                WHERE token = ?;
                """,
                (token,),
            )
            row = cur.fetchone()
            if row is None:
                raise LookupError("share link not found")

            if int(row["revoked"]) == 1:
                raise PermissionError("share link revoked")

            expires_at = self._parse_utc_iso(row["expires_at"])
            if datetime.now(timezone.utc) >= expires_at:
                raise TimeoutError("share link expired")

            password_hash = row["password_hash"] or ""
            if password_hash:
                if not password:
                    raise PermissionError("password_required")
                password_salt = row["password_salt"] or ""
                candidate = self._hash_password(password, password_salt)
                if not hmac.compare_digest(candidate, password_hash):
                    raise PermissionError("invalid_password")

            one_time = int(row["one_time"]) == 1
            view_count = int(row["view_count"] or 0)
            if one_time and view_count >= 1:
                raise TimeoutError("share link already used")

            cur.execute(
                """
                UPDATE share_links
                SET view_count = view_count + 1,
                    revoked = CASE WHEN one_time = 1 THEN 1 ELSE revoked END
                WHERE token = ?;
                """,
                (token,),
            )
            conn.commit()

        payload = row["payload"]
        try:
            project = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid shared payload") from exc

        return {
            "project": project,
            "meta": {
                "token": token,
                "expires_at": row["expires_at"],
                "one_time": one_time,
                "password_protected": bool(password_hash),
            },
        }

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT payload
                FROM records
                WHERE id = ?;
                """,
                (project_id,),
            )
            row = cur.fetchone()

        if row is None:
            return None
        try:
            payload = json.loads(row["payload"])
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def list_intel_resources(
        self,
        target_type: str | None = None,
        *,
        enabled_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_type and target_type.strip():
            clauses.append("target_type = ?")
            params.append(target_type.strip().lower())
        if enabled_only:
            clauses.append("enabled = 1")
        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT id, name, url, target_type, enabled, created_at, updated_at
                FROM intel_resources
                {where_clause}
                ORDER BY target_type ASC, name COLLATE NOCASE ASC;
                """,
                tuple(params),
            )
            rows = cur.fetchall()

        resources: list[dict[str, Any]] = []
        for row in rows:
            resources.append(
                {
                    "id": str(row["id"]),
                    "name": str(row["name"]),
                    "url": str(row["url"]),
                    "target_type": str(row["target_type"]),
                    "enabled": bool(int(row["enabled"] or 0)),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                }
            )
        return resources

    def add_intel_resource(
        self,
        *,
        name: str,
        url: str,
        target_type: str,
        enabled: bool = True,
    ) -> dict[str, Any]:
        clean_name = name.strip()
        clean_url = url.strip()
        clean_target_type = target_type.strip().lower()

        if not clean_name:
            raise ValueError("resource name is required")
        if len(clean_name) > 120:
            raise ValueError("resource name is too long (max 120)")
        if not clean_target_type:
            raise ValueError("target_type is required")
        if len(clean_target_type) > 64:
            raise ValueError("target_type is too long (max 64)")

        parsed = urlsplit(clean_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("resource URL must be a valid http(s) URL")

        resource_id = str(uuid.uuid4())
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO intel_resources (
                    id, name, url, target_type, enabled, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(name, target_type)
                DO UPDATE SET
                    url = excluded.url,
                    enabled = excluded.enabled,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (resource_id, clean_name, clean_url, clean_target_type, 1 if enabled else 0),
            )
            cur.execute(
                """
                SELECT id, name, url, target_type, enabled, created_at, updated_at
                FROM intel_resources
                WHERE name = ? AND target_type = ?
                LIMIT 1;
                """,
                (clean_name, clean_target_type),
            )
            row = cur.fetchone()
            conn.commit()

        if row is None:
            raise ValueError("failed to save intel resource")

        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "url": str(row["url"]),
            "target_type": str(row["target_type"]),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def get_intel_resource_by_name(
        self,
        name: str,
        *,
        target_type: str | None = None,
        enabled_only: bool = True,
    ) -> dict[str, Any] | None:
        clean_name = name.strip().lower()
        if not clean_name:
            return None

        clauses = ["lower(name) = ?"]
        params: list[Any] = [clean_name]
        if enabled_only:
            clauses.append("enabled = 1")
        if target_type and target_type.strip():
            clean_target_type = target_type.strip().lower()
            clauses.append("(target_type = ? OR target_type = 'all')")
            params.append(clean_target_type)

        where_clause = " AND ".join(clauses)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT id, name, url, target_type, enabled, created_at, updated_at
                FROM intel_resources
                WHERE {where_clause}
                ORDER BY
                  CASE
                    WHEN target_type = ? THEN 0
                    WHEN target_type = 'all' THEN 1
                    ELSE 2
                  END,
                  updated_at DESC
                LIMIT 1;
                """,
                tuple(params + [target_type.strip().lower() if target_type and target_type.strip() else ""]),
            )
            row = cur.fetchone()

        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "url": str(row["url"]),
            "target_type": str(row["target_type"]),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _hash_password(password: str, salt_hex: str) -> str:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            260_000,
        )
        return digest.hex()

    @staticmethod
    def _parse_utc_iso(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _sanitize_share_payload(project: dict[str, Any]) -> dict[str, Any]:
        # Exclude sensitive request details like raw targetConfig/credentials while
        # keeping scan outcomes and report data useful for clients.
        allowed_keys = (
            "id",
            "name",
            "target",
            "targetType",
            "status",
            "createdAt",
            "updatedAt",
            "description",
            "findings",
            "agents",
            "phases",
            "scanProgress",
        )
        shared = {key: project.get(key) for key in allowed_keys if key in project}
        shared["sharedAt"] = datetime.now(timezone.utc).isoformat()
        return shared
