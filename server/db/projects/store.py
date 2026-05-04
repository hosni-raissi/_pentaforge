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

_INTEL_RESOURCE_CONTENT_TYPES = {
    "strategies",
    "exploits",
    "tools",
    "standards",
    "attack_types",
    "payload",
}
_INTEL_RESOURCE_UPDATE_MODES = {
    "every_3_days",
    "static",
}


def _normalize_static_plan_target_type(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_")


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
                    tunnel_url TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            # Migration: Ensure tunnel_url column exists if table was already created
            try:
                cur.execute("ALTER TABLE share_links ADD COLUMN tunnel_url TEXT")
            except sqlite3.OperationalError:
                pass # Already exists
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
                    content_type TEXT NOT NULL DEFAULT 'strategies',
                    update_mode TEXT NOT NULL DEFAULT 'every_3_days',
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
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS intel_update_prefs (
                    target_type TEXT PRIMARY KEY,
                    refresh_days INTEGER NOT NULL DEFAULT 3,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_intel_update_prefs_refresh_days
                ON intel_update_prefs (refresh_days);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS intel_hidden_builtin_resources (
                    name TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS planner_static_recon_plans (
                    target_type TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_planner_static_recon_plans_updated_at
                ON planner_static_recon_plans (updated_at DESC);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS target_info_profiles (
                    target_type TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_target_info_profiles_updated_at
                ON target_info_profiles (updated_at DESC);
                """
            )
            cur.execute("PRAGMA table_info(intel_resources);")
            intel_columns = {str(row[1]) for row in cur.fetchall()}
            if "content_type" not in intel_columns:
                cur.execute(
                    """
                    ALTER TABLE intel_resources
                    ADD COLUMN content_type TEXT NOT NULL DEFAULT 'strategies';
                    """
                )
            if "update_mode" not in intel_columns:
                cur.execute(
                    """
                    ALTER TABLE intel_resources
                    ADD COLUMN update_mode TEXT NOT NULL DEFAULT 'every_3_days';
                    """
                )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_event_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    data TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_projects_scan_event_cache_project_id_id
                ON scan_event_cache (project_id, id DESC);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS project_reports (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    format TEXT NOT NULL DEFAULT 'markdown',
                    content TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(project_id, format)
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_project_reports_project_id
                ON project_reports (project_id);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS client_messages (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_client_messages_project_id_created_at
                ON client_messages (project_id, created_at ASC);
                """
            )
            conn.commit()

    def list_hidden_builtin_intel_resources(self) -> set[str]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT name
                FROM intel_hidden_builtin_resources;
                """
            )
            rows = cur.fetchall()
        hidden: set[str] = set()
        for row in rows:
            name = str(row["name"] or "").strip()
            if name:
                hidden.add(name.lower())
        return hidden

    def hide_builtin_intel_resource(self, name: str) -> None:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("resource name is required")
        if len(clean_name) > 160:
            raise ValueError("resource name is too long (max 160)")
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO intel_hidden_builtin_resources (name, created_at)
                VALUES (?, CURRENT_TIMESTAMP);
                """,
                (clean_name,),
            )
            conn.commit()

    def recover_interrupted_scans(self) -> int:
        """Mark stale `running` scans as interrupted after server restarts."""
        now_iso = datetime.now(timezone.utc).isoformat()
        recovered = 0

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, payload
                FROM records;
                """
            )
            rows = cur.fetchall()

            for row in rows:
                record_id = str(row["id"])
                try:
                    payload = json.loads(row["payload"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict):
                    continue

                changed = False
                status = str(payload.get("status", "")).strip().lower()
                if status == "running":
                    payload["status"] = "paused"
                    changed = True

                last_scan = payload.get("lastScan")
                if isinstance(last_scan, dict):
                    last_status = str(last_scan.get("status", "")).strip().lower()
                    if last_status == "running":
                        last_scan["status"] = "paused"
                        if not str(last_scan.get("finishedAt", "")).strip():
                            last_scan["finishedAt"] = now_iso
                        if not str(last_scan.get("error", "")).strip():
                            last_scan["error"] = "Scan interrupted because server restarted."
                        payload["lastScan"] = last_scan
                        changed = True

                if not changed:
                    continue

                payload["updatedAt"] = now_iso
                cur.execute(
                    """
                    UPDATE records
                    SET payload = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                    """,
                    (json.dumps(payload, ensure_ascii=True), record_id),
                )
                recovered += 1

            conn.commit()

        return recovered

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

    def append_scan_event_cache(
        self,
        project_id: str,
        payload: dict[str, Any],
        *,
        max_per_project: int = 1000,
    ) -> None:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return

        scan_id = str(payload.get("scan_id", "") or "")
        event = str(payload.get("event", "") or "")
        level = str(payload.get("level", "info") or "info")
        message = str(payload.get("message", "") or "")
        timestamp = str(payload.get("timestamp", "") or datetime.now(timezone.utc).isoformat())
        data = payload.get("data", {})
        if not isinstance(data, dict):
            data = {}

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scan_event_cache (
                    project_id, scan_id, event, level, message, timestamp, data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    safe_project_id,
                    scan_id,
                    event,
                    level,
                    message,
                    timestamp,
                    json.dumps(data, ensure_ascii=True),
                ),
            )
            cur.execute(
                """
                DELETE FROM scan_event_cache
                WHERE project_id = ?
                  AND id NOT IN (
                    SELECT id
                    FROM scan_event_cache
                    WHERE project_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                  );
                """,
                (safe_project_id, safe_project_id, max_per_project),
            )
            conn.commit()

    def list_scan_event_cache(
        self,
        project_id: str,
        *,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return []
        safe_limit = max(1, min(int(limit), 2000))

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT project_id, scan_id, event, level, message, timestamp, data
                FROM (
                    SELECT id, project_id, scan_id, event, level, message, timestamp, data
                    FROM scan_event_cache
                    WHERE project_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC;
                """,
                (safe_project_id, safe_limit),
            )
            rows = cur.fetchall()

        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                parsed_data = json.loads(row["data"])
            except (TypeError, json.JSONDecodeError):
                parsed_data = {}
            if not isinstance(parsed_data, dict):
                parsed_data = {}

            out.append(
                {
                    "event": str(row["event"]),
                    "project_id": str(row["project_id"]),
                    "scan_id": str(row["scan_id"]),
                    "level": str(row["level"]),
                    "message": str(row["message"]),
                    "timestamp": str(row["timestamp"]),
                    "data": parsed_data,
                }
            )
        return out

    def clear_scan_event_cache(self, project_id: str) -> int:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return 0
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM scan_event_cache
                WHERE project_id = ?;
                """,
                (safe_project_id,),
            )
            deleted = int(cur.rowcount or 0)
            conn.commit()
        return deleted

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

    def append_project_copilot_history(
        self,
        project_id: str,
        messages: list[dict[str, Any]],
        *,
        max_messages: int = 200,
        scope_key: str | None = None,
    ) -> None:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return
        if not isinstance(messages, list) or not messages:
            return

        project = self.get_project(safe_project_id)
        if not isinstance(project, dict):
            return

        active_scope = str(scope_key or "").strip()
        stored_scope = str(project.get("copilotHistoryScope", "")).strip()
        existing = project.get("copilotHistory", [])
        history: list[dict[str, Any]] = existing if isinstance(existing, list) else []
        if active_scope and stored_scope != active_scope:
            history = []
        normalized_new: list[dict[str, Any]] = []
        for item in messages:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", "")).strip().lower()
            text = str(item.get("text", "")).strip()
            if role not in {"user", "assistant"} or not text:
                continue
            entry = {
                "id": str(item.get("id", "")).strip() or str(uuid.uuid4()),
                "role": role,
                "text": text,
                "timestamp": str(item.get("timestamp", "")).strip()
                or datetime.now(timezone.utc).isoformat(),
            }
            if role == "assistant":
                route = str(item.get("route", "")).strip().lower()
                if route:
                    entry["route"] = route
                if "blocked" in item:
                    entry["blocked"] = bool(item.get("blocked"))
            normalized_new.append(entry)

        if not normalized_new:
            return

        history.extend(normalized_new)
        if len(history) > max_messages:
            history = history[-max_messages:]

        project["copilotHistory"] = history
        if active_scope:
            project["copilotHistoryScope"] = active_scope
        project["updatedAt"] = datetime.now(timezone.utc).isoformat()
        self.upsert_project(project)

    def update_project_copilot_context(
        self,
        project_id: str,
        context: str,
        *,
        max_chars: int = 4000,
        scope_key: str | None = None,
    ) -> None:
        safe_project_id = str(project_id or "").strip()
        safe_context = str(context or "").strip()
        if not safe_project_id:
            return

        project = self.get_project(safe_project_id)
        if not isinstance(project, dict):
            return

        active_scope = str(scope_key or "").strip()
        if active_scope:
            project["copilotContextScope"] = active_scope
        project["copilotContext"] = safe_context[:max_chars] if safe_context else ""
        project["updatedAt"] = datetime.now(timezone.utc).isoformat()
        self.upsert_project(project)

    def clear_project_copilot_state(
        self,
        project_id: str,
        *,
        scope_key: str | None = None,
    ) -> None:
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return

        project = self.get_project(safe_project_id)
        if not isinstance(project, dict):
            return

        active_scope = str(scope_key or "").strip()
        history_scope = str(project.get("copilotHistoryScope", "")).strip()
        context_scope = str(project.get("copilotContextScope", "")).strip()

        if not active_scope or history_scope == active_scope:
            project["copilotHistory"] = []
            if active_scope:
                project["copilotHistoryScope"] = active_scope
            else:
                project["copilotHistoryScope"] = ""

        if not active_scope or context_scope == active_scope:
            project["copilotContext"] = ""
            if active_scope:
                project["copilotContextScope"] = active_scope
            else:
                project["copilotContextScope"] = ""

        project["updatedAt"] = datetime.now(timezone.utc).isoformat()
        self.upsert_project(project)

    def delete_project(self, project_id: str) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM records WHERE id = ?;", (project_id,))
            cur.execute("DELETE FROM share_links WHERE project_id = ?;", (project_id,))
            cur.execute("DELETE FROM scan_event_cache WHERE project_id = ?;", (project_id,))
            conn.commit()

    def create_share_link(
        self,
        project_id: str,
        *,
        expires_hours: int = 24,
        password: str | None = None,
        one_time: bool = False,
        tunnel_url: str | None = None,
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
                "UPDATE share_links SET revoked = 1 WHERE project_id = ? AND token != ?",
                (project_id, token)
            )
            cur.execute(
                """
                INSERT INTO share_links (
                    token, project_id, payload, expires_at,
                    password_hash, password_salt, one_time, tunnel_url
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    token,
                    project_id,
                    payload,
                    expires_at.isoformat(),
                    password_hash,
                    password_salt,
                    1 if one_time else 0,
                    tunnel_url
                ),
            )
            conn.commit()

        return {
            "token": token,
            "expires_at": expires_at.isoformat(),
            "one_time": one_time,
            "password_protected": bool(password_hash),
        }

    def get_active_share_link(self, project_id: str) -> dict[str, Any] | None:
        """Return the most recent non-revoked, non-expired share link for a project."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT token, expires_at, one_time, password_hash, tunnel_url
                FROM share_links
                WHERE project_id = ?
                  AND revoked = 0
                  AND expires_at > ?
                ORDER BY expires_at DESC
                LIMIT 1;
                """,
                (project_id, now),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "token": row["token"],
            "expires_at": row["expires_at"],
            "one_time": bool(int(row["one_time"])),
            "password_protected": bool(row["password_hash"]),
            "tunnel_url": row["tunnel_url"],
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

    def add_client_message(self, project_id: str, sender: str, content: str) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO client_messages (id, project_id, sender, content, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (message_id, project_id, sender, content, created_at)
            )
            conn.commit()
        return {
            "id": message_id,
            "project_id": project_id,
            "sender": sender,
            "content": content,
            "created_at": created_at
        }

    def list_client_messages(self, project_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, project_id, sender, content, created_at
                FROM client_messages
                WHERE project_id = ?
                ORDER BY created_at ASC;
                """,
                (project_id,)
            )
            rows = cur.fetchall()
        return [
            {
                "id": row["id"],
                "project_id": row["project_id"],
                "sender": row["sender"],
                "content": row["content"],
                "created_at": row["created_at"]
            }
            for row in rows
        ]

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

    def list_static_recon_plans(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT target_type, payload, created_at, updated_at
                FROM planner_static_recon_plans
                ORDER BY target_type ASC;
                """
            )
            rows = cur.fetchall()

        plans: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            payload.setdefault("target_type", str(row["target_type"]))
            payload["created_at"] = str(row["created_at"])
            payload["updated_at"] = str(row["updated_at"])
            plans.append(payload)
        return plans

    def get_static_recon_plan(self, target_type: str) -> dict[str, Any] | None:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            return None
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT target_type, payload, created_at, updated_at
                FROM planner_static_recon_plans
                WHERE target_type = ?;
                """,
                (clean_target_type,),
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
        payload.setdefault("target_type", str(row["target_type"]))
        payload["created_at"] = str(row["created_at"])
        payload["updated_at"] = str(row["updated_at"])
        return payload

    def upsert_static_recon_plan(self, *, target_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            raise ValueError("target_type is required")
        if len(clean_target_type) > 64:
            raise ValueError("target_type is too long (max 64)")
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        safe_payload = dict(payload)
        safe_payload["target_type"] = clean_target_type

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO planner_static_recon_plans (
                    target_type, payload, created_at, updated_at
                )
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(target_type) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (clean_target_type, json.dumps(safe_payload, ensure_ascii=True)),
            )
            conn.commit()

        saved = self.get_static_recon_plan(clean_target_type)
        if saved is None:
            raise ValueError("failed to save static recon plan")
        return saved

    def delete_static_recon_plan(self, target_type: str) -> int:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            return 0
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM planner_static_recon_plans
                WHERE target_type = ?;
                """,
                (clean_target_type,),
            )
            deleted = int(cur.rowcount or 0)
            conn.commit()
        return deleted

    def list_target_info_profiles(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT target_type, payload, created_at, updated_at
                FROM target_info_profiles
                ORDER BY updated_at DESC;
                """
            )
            rows = cur.fetchall()

        profiles: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            payload.setdefault("target_type", str(row["target_type"]))
            payload.setdefault("created_at", str(row["created_at"]))
            payload.setdefault("updated_at", str(row["updated_at"]))
            profiles.append(payload)
        return profiles

    def get_target_info_profile(self, target_type: str) -> dict[str, Any] | None:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            return None

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT target_type, payload, created_at, updated_at
                FROM target_info_profiles
                WHERE target_type = ?;
                """,
                (clean_target_type,),
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
        payload.setdefault("target_type", str(row["target_type"]))
        payload.setdefault("created_at", str(row["created_at"]))
        payload.setdefault("updated_at", str(row["updated_at"]))
        return payload

    def upsert_target_info_profile(self, *, target_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            raise ValueError("target_type is required")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")

        now_iso = datetime.now(timezone.utc).isoformat()
        safe_payload = dict(payload)
        safe_payload["target_type"] = clean_target_type
        safe_payload.setdefault("updated_at", now_iso)
        serialized = json.dumps(safe_payload, ensure_ascii=True)

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO target_info_profiles (
                    target_type, payload, created_at, updated_at
                )
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT (target_type) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (clean_target_type, serialized),
            )
            conn.commit()

        saved = self.get_target_info_profile(clean_target_type)
        if saved is None:
            raise RuntimeError("failed to save target info profile")
        return saved

    def delete_target_info_profile(self, target_type: str) -> int:
        clean_target_type = _normalize_static_plan_target_type(target_type)
        if not clean_target_type:
            return 0

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM target_info_profiles
                WHERE target_type = ?;
                """,
                (clean_target_type,),
            )
            deleted = int(cur.rowcount or 0)
            conn.commit()
        return deleted

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
                SELECT id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
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
                    "content_type": str(row["content_type"] or "strategies"),
                    "update_mode": str(row["update_mode"] or "every_3_days"),
                    "enabled": bool(int(row["enabled"] or 0)),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                }
            )
        return resources

    def get_intel_resource(self, resource_id: str) -> dict[str, Any] | None:
        clean_id = resource_id.strip()
        if not clean_id:
            return None

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
                FROM intel_resources
                WHERE id = ?
                LIMIT 1;
                """,
                (clean_id,),
            )
            row = cur.fetchone()

        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "url": str(row["url"]),
            "target_type": str(row["target_type"]),
            "content_type": str(row["content_type"] or "strategies"),
            "update_mode": str(row["update_mode"] or "every_3_days"),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def get_intel_refresh_days(self, target_type: str) -> int | None:
        clean_target = target_type.strip().lower()
        if not clean_target:
            return None

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT refresh_days
                FROM intel_update_prefs
                WHERE target_type = ?
                LIMIT 1;
                """,
                (clean_target,),
            )
            row = cur.fetchone()
            if row is None and clean_target != "all":
                cur.execute(
                    """
                    SELECT refresh_days
                    FROM intel_update_prefs
                    WHERE target_type = 'all'
                    LIMIT 1;
                    """
                )
                row = cur.fetchone()

        if row is None:
            return None
        try:
            value = int(row["refresh_days"])
        except (TypeError, ValueError):
            return None
        if value < 1:
            return None
        return value

    def set_intel_refresh_days(self, *, target_type: str, refresh_days: int) -> dict[str, Any]:
        clean_target = target_type.strip().lower()
        if not clean_target:
            raise ValueError("target_type is required")
        if len(clean_target) > 64:
            raise ValueError("target_type is too long (max 64)")
        if refresh_days < 1 or refresh_days > 3650:
            raise ValueError("refresh_days must be between 1 and 3650")

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO intel_update_prefs (
                    target_type, refresh_days, created_at, updated_at
                )
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(target_type)
                DO UPDATE SET
                    refresh_days = excluded.refresh_days,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (clean_target, int(refresh_days)),
            )
            cur.execute(
                """
                SELECT target_type, refresh_days, created_at, updated_at
                FROM intel_update_prefs
                WHERE target_type = ?
                LIMIT 1;
                """,
                (clean_target,),
            )
            row = cur.fetchone()
            conn.commit()

        if row is None:
            raise ValueError("failed to save intel update preference")
        return {
            "target_type": str(row["target_type"]),
            "refresh_days": int(row["refresh_days"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def add_intel_resource(
        self,
        *,
        name: str,
        url: str,
        target_type: str,
        content_type: str = "strategies",
        update_mode: str = "every_3_days",
        enabled: bool = True,
    ) -> dict[str, Any]:
        clean_name = name.strip()
        clean_url = url.strip()
        clean_target_type = target_type.strip().lower()
        clean_content_type = content_type.strip().lower()
        clean_update_mode = update_mode.strip().lower()

        if not clean_name:
            raise ValueError("resource name is required")
        if len(clean_name) > 120:
            raise ValueError("resource name is too long (max 120)")
        if not clean_target_type:
            raise ValueError("target_type is required")
        if len(clean_target_type) > 64:
            raise ValueError("target_type is too long (max 64)")
        if clean_content_type not in _INTEL_RESOURCE_CONTENT_TYPES:
            raise ValueError(
                "content_type must be one of: "
                + ", ".join(sorted(_INTEL_RESOURCE_CONTENT_TYPES))
            )
        if clean_update_mode not in _INTEL_RESOURCE_UPDATE_MODES:
            raise ValueError(
                "update_mode must be one of: "
                + ", ".join(sorted(_INTEL_RESOURCE_UPDATE_MODES))
            )

        parsed = urlsplit(clean_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("resource URL must be a valid http(s) URL")

        resource_id = str(uuid.uuid4())
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO intel_resources (
                    id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(name, target_type)
                DO UPDATE SET
                    url = excluded.url,
                    content_type = excluded.content_type,
                    update_mode = excluded.update_mode,
                    enabled = excluded.enabled,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (
                    resource_id,
                    clean_name,
                    clean_url,
                    clean_target_type,
                    clean_content_type,
                    clean_update_mode,
                    1 if enabled else 0,
                ),
            )
            cur.execute(
                """
                SELECT id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
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
            "content_type": str(row["content_type"] or "strategies"),
            "update_mode": str(row["update_mode"] or "every_3_days"),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def update_intel_resource(
        self,
        resource_id: str,
        *,
        name: str | None = None,
        url: str | None = None,
        target_type: str | None = None,
        content_type: str | None = None,
        update_mode: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        clean_id = resource_id.strip()
        if not clean_id:
            raise ValueError("resource id is required")

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, name, url, target_type, content_type, update_mode, enabled
                FROM intel_resources
                WHERE id = ?
                LIMIT 1;
                """,
                (clean_id,),
            )
            existing = cur.fetchone()
            if existing is None:
                raise LookupError("resource not found")

            next_name = (name if name is not None else str(existing["name"])).strip()
            next_url = (url if url is not None else str(existing["url"])).strip()
            next_target_type = (target_type if target_type is not None else str(existing["target_type"])).strip().lower()
            next_content_type = (content_type if content_type is not None else str(existing["content_type"] or "strategies")).strip().lower()
            next_update_mode = (update_mode if update_mode is not None else str(existing["update_mode"] or "every_3_days")).strip().lower()
            next_enabled = int(1 if (enabled if enabled is not None else bool(int(existing["enabled"] or 0))) else 0)

            if not next_name:
                raise ValueError("resource name is required")
            if len(next_name) > 120:
                raise ValueError("resource name is too long (max 120)")
            if not next_target_type:
                raise ValueError("target_type is required")
            if len(next_target_type) > 64:
                raise ValueError("target_type is too long (max 64)")
            if next_content_type not in _INTEL_RESOURCE_CONTENT_TYPES:
                raise ValueError(
                    "content_type must be one of: "
                    + ", ".join(sorted(_INTEL_RESOURCE_CONTENT_TYPES))
                )
            if next_update_mode not in _INTEL_RESOURCE_UPDATE_MODES:
                raise ValueError(
                    "update_mode must be one of: "
                    + ", ".join(sorted(_INTEL_RESOURCE_UPDATE_MODES))
                )

            parsed = urlsplit(next_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("resource URL must be a valid http(s) URL")

            try:
                cur.execute(
                    """
                    UPDATE intel_resources
                    SET
                        name = ?,
                        url = ?,
                        target_type = ?,
                        content_type = ?,
                        update_mode = ?,
                        enabled = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                    """,
                    (
                        next_name,
                        next_url,
                        next_target_type,
                        next_content_type,
                        next_update_mode,
                        next_enabled,
                        clean_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("a resource with the same name and target type already exists") from exc

            cur.execute(
                """
                SELECT id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
                FROM intel_resources
                WHERE id = ?
                LIMIT 1;
                """,
                (clean_id,),
            )
            row = cur.fetchone()
            conn.commit()

        if row is None:
            raise LookupError("resource not found")

        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "url": str(row["url"]),
            "target_type": str(row["target_type"]),
            "content_type": str(row["content_type"] or "strategies"),
            "update_mode": str(row["update_mode"] or "every_3_days"),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def delete_intel_resource(self, resource_id: str) -> bool:
        clean_id = resource_id.strip()
        if not clean_id:
            return False
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM intel_resources
                WHERE id = ?;
                """,
                (clean_id,),
            )
            deleted = cur.rowcount > 0
            conn.commit()
        return deleted

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
                SELECT id, name, url, target_type, content_type, update_mode, enabled, created_at, updated_at
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
            "content_type": str(row["content_type"] or "strategies"),
            "update_mode": str(row["update_mode"] or "every_3_days"),
            "enabled": bool(int(row["enabled"] or 0)),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    # ── Report Persistence ──────────────────────────────────────

    def save_report(
        self,
        project_id: str,
        *,
        report_id: str,
        format: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Upsert a report for a project + format."""
        safe_project_id = str(project_id or "").strip()
        safe_format = str(format or "markdown").strip().lower()
        if not safe_project_id:
            raise ValueError("project_id is required")
        if safe_format not in {"markdown", "html", "pdf"}:
            raise ValueError(f"unsupported report format: {safe_format}")

        meta_json = json.dumps(metadata or {}, ensure_ascii=True)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO project_reports (id, project_id, format, content, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT (project_id, format) DO UPDATE SET
                    id = EXCLUDED.id,
                    content = EXCLUDED.content,
                    metadata = EXCLUDED.metadata,
                    updated_at = CURRENT_TIMESTAMP;
                """,
                (report_id, safe_project_id, safe_format, content, meta_json),
            )
            conn.commit()

    def get_report(
        self,
        project_id: str,
        format: str = "markdown",
    ) -> dict[str, Any] | None:
        """Retrieve a report by project and format."""
        safe_project_id = str(project_id or "").strip()
        safe_format = str(format or "markdown").strip().lower()
        if not safe_project_id:
            return None

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, project_id, format, content, metadata, created_at, updated_at
                FROM project_reports
                WHERE project_id = ? AND format = ?;
                """,
                (safe_project_id, safe_format),
            )
            row = cur.fetchone()

        if row is None:
            return None

        try:
            meta = json.loads(row["metadata"])
        except (TypeError, json.JSONDecodeError):
            meta = {}

        return {
            "id": str(row["id"]),
            "project_id": str(row["project_id"]),
            "format": str(row["format"]),
            "content": str(row["content"]),
            "metadata": meta if isinstance(meta, dict) else {},
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def delete_report(self, project_id: str, format: str = "markdown") -> bool:
        """Delete a specific report format for a project."""
        safe_project_id = str(project_id or "").strip()
        safe_format = str(format or "markdown").strip().lower()
        if not safe_project_id:
            return False

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM project_reports
                WHERE project_id = ? AND format = ?;
                """,
                (safe_project_id, safe_format),
            )
            deleted = int(cur.rowcount or 0)
            conn.commit()
        return deleted > 0

    def list_report_status(self, project_id: str) -> dict[str, Any]:
        """Return which report formats exist for a project."""
        safe_project_id = str(project_id or "").strip()
        if not safe_project_id:
            return {
                "markdown": False,
                "html": False,
                "pdf": False,
                "generated_at": None,
            }

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT format, created_at
                FROM project_reports
                WHERE project_id = ?;
                """,
                (safe_project_id,),
            )
            rows = cur.fetchall()

        formats_present = {str(row["format"]).strip().lower() for row in rows}
        latest_date: str | None = None
        for row in rows:
            ts = str(row["created_at"])
            if latest_date is None or ts > latest_date:
                latest_date = ts

        return {
            "markdown": "markdown" in formats_present,
            "html": "html" in formats_present,
            "pdf": "pdf" in formats_present,
            "generated_at": latest_date,
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
