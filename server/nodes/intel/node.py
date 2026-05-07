"""Node wrapper for Intel RAG refresh and deterministic checklist compatibility."""

from __future__ import annotations

from typing import Any

from .helpers import refresh_rag as _refresh_rag
from .helpers import synthesize_checklist as _synthesize_checklist


class IntelNode:
    """Node-owned Intel behavior without the old agent package."""

    def __init__(self, *, callback: Any = None, project_id: str = "") -> None:
        self._callback = callback
        self._project_id = project_id

    async def refresh_rag(
        self,
        *,
        target_type: str,
        info: str,
        force_update: bool = False,
    ) -> Any:
        """Refresh or reuse RAG state based on the configured cooldown window."""

        _ = self._project_id
        return await _refresh_rag(
            target_type=target_type,
            info=info,
            force_update=force_update,
            callback=self._callback,
        )

    async def synthesize_checklist(
        self,
        *,
        target_type: str,
        info: str,
        custom_checklist_text: str = "",
        merge_custom_checklist: bool = False,
        max_checklist_items: int | None = None,
        skip_rag_check: bool = True,
    ) -> Any:
        """Compatibility wrapper for the old Intel checklist synthesis call site."""

        _ = (self._project_id, skip_rag_check)
        return await _synthesize_checklist(
            target_type=target_type,
            info=info,
            custom_checklist_text=custom_checklist_text,
            merge_custom_checklist=bool(merge_custom_checklist),
            max_checklist_items=max_checklist_items,
            callback=self._callback,
        )

    async def run(
        self,
        *,
        target: str,
        target_type: str,
        project_id: str,
        force_update: bool = False,
    ) -> Any:
        """Unified entry point for the Intel phase execution."""

        # 1. Refresh RAG to ensure we have latest knowledge for this target type
        rag_result = await self.refresh_rag(
            target_type=target_type,
            info=target,  # Use target as info for RAG context
            force_update=force_update,
        )

        # 2. Synthesize the deterministic checklist
        checklist_result = await self.synthesize_checklist(
            target_type=target_type,
            info=target,
        )

        # 3. Combine results
        return {
            "status": "complete",
            "summary": f"{rag_result.summary}\n{checklist_result.summary}",
            "rag": {
                "status": rag_result.status,
                "stats": rag_result.stats,
            },
            "checklist": checklist_result.checklist,
            "vulnerabilities": checklist_result.vulnerabilities,
        }
