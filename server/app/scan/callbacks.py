from __future__ import annotations

import time
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..orchestrator import ScanOrchestratorService


class PrintCallback:
    """Print step-by-step output in the same style as test_intel_agent."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        on_log: Callable[[str, str], None] | None = None,
    ) -> None:
        self._start = time.perf_counter()
        self._enabled = enabled
        self._on_log = on_log

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  -> {message} {self._ts()}", flush=True)
        if self._on_log is not None:
            self._on_log("info", message)

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  + {message}", flush=True)
        if self._on_log is not None:
            self._on_log("success", message)

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ! {message}", flush=True)
        if self._on_log is not None:
            self._on_log("warn", message)

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        if self._enabled:
            print(
                f"  ! approval required: role={role} tool={tool_name} call_id={call_id}",
                flush=True,
            )
        if self._on_log is not None:
            self._on_log(
                "warn",
                (
                    f"Tool approval required: role={role} "
                    f"tool={tool_name} call_id={call_id} args={args}"
                ),
            )
        return False


class ExecuterScanCallback:
    """Executer callback bridged to scan event bus + approval workflow."""

    def __init__(
        self,
        *,
        service: ScanOrchestratorService,
        project_id: str,
        scan_id: str,
        enabled: bool = True,
    ) -> None:
        self._service = service
        self._project_id = project_id
        self._scan_id = scan_id
        self._enabled = enabled
        self._start = time.perf_counter()

    def _ts(self) -> str:
        return f"[{time.perf_counter() - self._start:.1f}s]"

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  -> {message} {self._ts()}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_step",
            scan_id=self._scan_id,
            level="info",
            message=f"Executer [step] {message}",
            data={"stage": "executer", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  + {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"Executer [done] {message}",
            data={"stage": "executer", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ! {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="executer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"Executer [warn] {message}",
            data={"stage": "executer", "kind": "warn", "raw_message": message},
        )

    def get_approval_mode(self) -> str:
        project = self._service._projects_store.get_project(self._project_id)  # noqa: SLF001
        return str(project.get("approval_mode") or "custom").lower().strip() if project else "custom"

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return await self._service.request_executer_tool_approval(
            project_id=self._project_id,
            scan_id=self._scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    async def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        prompt_text = str(prompt or "").strip()
        reason_text = str(reason or "").strip()
        tool_name = "authentication"
        for token_source in (prompt_text, reason_text):
            first_token = token_source.split(" ", 1)[0].strip(" :").lower()
            if first_token in {"ssh", "sudo", "mysql", "psql", "sqlite3", "ftp", "sshpass"}:
                tool_name = first_token
                break

        return await self._service.request_executer_password(
            project_id=self._project_id,
            scan_id=self._scan_id,
            tool_name=tool_name,
            prompt=prompt_text,
            reason=reason_text,
            call_id=call_id,
        )

    def request_tool_approval_threadsafe(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return self._service.request_tool_approval_threadsafe(
            project_id=self._project_id,
            scan_id=self._scan_id,
            role=role,
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    def request_password_threadsafe(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return self._service.request_password_threadsafe(
            project_id=self._project_id,
            scan_id=self._scan_id,
            tool_name="authentication",  # Or better detection
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )


class AnalyzerScanCallback(ExecuterScanCallback):
    """Analyzer callback bridged to scan event bus + approval workflow."""

    def on_step(self, message: str) -> None:
        if self._enabled:
            print(f"  -> {message} {self._ts()}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_step",
            scan_id=self._scan_id,
            level="info",
            message=f"Analyzer [step] {message}",
            data={"stage": "analyzer", "kind": "step", "raw_message": message},
        )

    def on_done(self, message: str) -> None:
        if self._enabled:
            print(f"  + {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_done",
            scan_id=self._scan_id,
            level="success",
            message=f"Analyzer [done] {message}",
            data={"stage": "analyzer", "kind": "done", "raw_message": message},
        )

    def on_warn(self, message: str) -> None:
        if self._enabled:
            print(f"  ! {message}", flush=True)
        self._service._emit_event(  # noqa: SLF001
            self._project_id,
            event="analyzer_warn",
            scan_id=self._scan_id,
            level="warn",
            message=f"Analyzer [warn] {message}",
            data={"stage": "analyzer", "kind": "warn", "raw_message": message},
        )


class WorkerExecuterCallback:
    """Prefixes executer callback logs with a stable worker label."""

    def __init__(self, *, parent: ExecuterScanCallback, worker_index: int) -> None:
        self._parent = parent
        self._worker_index = worker_index
        self._prefix = f"[worker {worker_index}]"

    def _prefix_message(self, message: str) -> str:
        text = str(message or "").strip()
        if not text:
            return self._prefix
        if text.startswith(self._prefix):
            return text
        return f"{self._prefix} {text}"

    def on_step(self, message: str) -> None:
        self._parent.on_step(self._prefix_message(message))

    def on_done(self, message: str) -> None:
        self._parent.on_done(self._prefix_message(message))

    def on_warn(self, message: str) -> None:
        self._parent.on_warn(self._prefix_message(message))

    def get_approval_mode(self) -> str:
        return self._parent.get_approval_mode()

    async def request_tool_approval(
        self,
        *,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        call_id: str,
    ) -> bool:
        return await self._parent.request_tool_approval(
            role=f"{self._prefix} {role}",
            tool_name=tool_name,
            args=args,
            call_id=call_id,
        )

    async def request_password(
        self,
        *,
        prompt: str,
        reason: str,
        call_id: str,
    ) -> str | None:
        return await self._parent.request_password(
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )
