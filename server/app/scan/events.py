from __future__ import annotations

import asyncio
import structlog
from typing import Any, Dict, Set, TYPE_CHECKING
from .utils import _utc_now_iso
from server.db.projects.scan_observability import enrich_scan_event_payload

if TYPE_CHECKING:
    from server.db.projects import ProjectsStore
    from .persistence import ScanPersistenceService

logger = structlog.get_logger(__name__)

class ScanEventService:
    """Standardized event emission for scan progress and tool status."""

    def __init__(self, persistence: ScanPersistenceService, projects_store: ProjectsStore):
        self._persistence = persistence
        self._projects_store = projects_store
        self._subscribers: Dict[str, Set[asyncio.Queue[Dict[str, Any]]]] = {}

    def emit(
        self,
        project_id: str,
        event: str,
        scan_id: str | None = None,
        level: str = "info",
        message: str = "",
        data: Dict[str, Any] | None = None
    ) -> None:
        """Emits an event to the persistent cache and all active subscribers."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return

        payload = {
            "event": event,
            "project_id": project_key,
            "scan_id": scan_id or "",
            "level": level,
            "message": message,
            "timestamp": _utc_now_iso(),
            "data": data or {},
        }
        payload = enrich_scan_event_payload(project_key, payload)
        
        # Persist to project event cache
        try:
            self._projects_store.append_scan_event_cache(project_key, payload)
        except Exception as exc:
            logger.warning(
                "scan_event_cache_append_failed",
                project_id=project_key,
                event=event,
                error=str(exc),
            )

        # Push to active subscribers
        subs = self._subscribers.get(project_key, set())
        for queue in list(subs):
            self._push_event(queue, payload)

    def subscribe(self, project_id: str) -> asyncio.Queue[Dict[str, Any]]:
        """Subscribes to events for a project and returns a queue."""
        project_key = str(project_id or "").strip()
        
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._subscribers.setdefault(project_key, set()).add(queue)

        # Replay cached events
        try:
            cached = self._projects_store.list_scan_event_cache(project_key, limit=180)
        except Exception as exc:
            logger.warning("scan_event_cache_load_failed", project_id=project_key, error=str(exc))
            cached = []
            
        for payload in cached:
            self._push_event(queue, payload)

        # Send initial status snapshot
        status_snapshot = self._persistence.get_scan_status(project_key)
        self._push_event(
            queue,
            enrich_scan_event_payload(
                project_key,
                {
                "event": "scan_status_snapshot",
                "project_id": project_key,
                "scan_id": str(status_snapshot.get("scan_id", "")),
                "level": "info",
                "message": f"Current scan status: {status_snapshot.get('status', 'idle')}.",
                "timestamp": _utc_now_iso(),
                "data": {
                    "status": status_snapshot.get("status", "idle"),
                    "scan": status_snapshot,
                },
                },
            ),
        )
        return queue

    def unsubscribe(self, project_id: str, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        """Removes a subscriber queue."""
        project_key = str(project_id or "").strip()
        subs = self._subscribers.get(project_key)
        if subs and queue in subs:
            subs.remove(queue)
            if not subs:
                self._subscribers.pop(project_key, None)

    def _push_event(self, queue: asyncio.Queue[Dict[str, Any]], payload: Dict[str, Any]) -> None:
        """Safely pushes an event to a queue, dropping the oldest event if full."""
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    def clear_cache(self, project_id: str) -> int:
        """Clears the event cache for a project."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return 0
        return self._projects_store.clear_scan_event_cache(project_key)

    def list_cache(self, project_id: str, limit: int = 200) -> list[Dict[str, Any]]:
        """Lists cached events for a project."""
        project_key = str(project_id or "").strip()
        if not project_key:
            return []
        return self._projects_store.list_scan_event_cache(project_key, limit=limit)
