"""Shared API dependencies (stores and startup hooks)."""

from __future__ import annotations

from server.app.orchestrator import ScanOrchestratorService
from server.db.knowledge.storage.intel_state_store import IntelStateStore
from server.db.projects import ProjectsStore
from server.layers.safety.rate_limiter import RateLimiter

from server.app.scan.persistence import ScanPersistenceService
from server.app.scan.events import ScanEventService
from server.app.scan.approval import ApprovalGateService
from server.app.scan.runner import PhaseRunnerService
from server.app.scan.lifecycle import ScanLifecycleService

projects_store = ProjectsStore()
intel_state_store = IntelStateStore()
rate_limiter = RateLimiter()

# Initialize new services
persistence_service = ScanPersistenceService(projects_store)
event_service = ScanEventService(persistence_service, projects_store)
approval_service = ApprovalGateService(persistence_service, event_service)
runner_service = PhaseRunnerService(persistence_service, event_service, approval_service)
lifecycle_service = ScanLifecycleService(persistence_service, event_service, runner_service, approval_service)

scan_orchestrator = ScanOrchestratorService(
    projects_store,
    persistence_service=persistence_service,
    event_service=event_service,
    approval_service=approval_service,
    runner_service=runner_service,
    lifecycle_service=lifecycle_service
)


def init_api_state() -> None:
    """Initialize database schema required by API routes."""
    projects_store.init_schema()
    projects_store.recover_interrupted_scans()
    projects_store.recover_interrupted_task_runs()
