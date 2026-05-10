"""Architect agent: synthesizes target architecture from findings and memory."""

from __future__ import annotations

import json
import re
from typing import Any

import structlog

from server.agents.rate_limiter import get_global_llm_queue
from server.core.llm import LLMClient, ChatMessage, get_public_agent_config
from .prompts import ARCHITECT_SYSTEM_PROMPT, ARCHITECT_USER_PROMPT_TEMPLATE
from .config import ARCHITECT_HISTORY_THRESHOLD

logger = structlog.get_logger(__name__)

_SPECULATIVE_MARKERS = (
    "assumed",
    "likely",
    "possible",
    "potential",
    "inferred",
    "not directly observed",
    "best-guess",
)
_FEATURE_HOST_MARKERS = (
    "console",
    "debug",
    "debugger",
    "openapi",
    "swagger",
    "yaml",
    "json",
    "idor",
    "security header",
    "headers",
    "tls",
    "certificate",
    "cipher",
    "werkzeug",
)
_WEB_HOST_MARKERS = (
    "web",
    "app",
    "application",
    "http",
    "https",
    "route",
    "endpoint",
    "header",
    "tls",
    "certificate",
)
_TITLE_REWRITE_MARKERS = (
    "vulnerable",
    "confirmed",
    "critical security flaws",
    "rce",
    "idor",
)
_ARCHITECT_SIGNAL_MARKERS = (
    "port",
    "service",
    "host",
    "route",
    "endpoint",
    "header",
    "tls",
    "certificate",
    "banner",
    "http",
    "https",
    "ssh",
    "ftp",
    "telnet",
    "smtp",
    "mysql",
    "postgres",
    "nfs",
    "smb",
    "rpc",
    "distcc",
    "ajp",
    "verified",
    "confirmed",
    "critical",
    "high",
    "finding",
    "memory",
    "tech",
)

class ArchitectAgent:
    """
    Agent responsible for drawing and updating the target architecture logical map.
    
    ### MECHANISM
    - Analyzes reconnaissance findings, service banners, and verified evidence.
    - Synthesizes a logical topology that prioritizes "Design-First" visibility.
    - Maps services to roles (Edge, Service, Internal, Data, etc.) and calculates UI coordinates.
    
    ### INFORMATION SOURCES
    1. **Primary**: Project Records Store (`projects.db`) - contains verified findings and target state.
    2. **Secondary**: Scan Event Cache - provides raw tool output and historical context for unverified but observed services.
    3. **Context**: Project Memory Block - provides grounded history from the RAG layer.
    """

    def __init__(
        self,
        *,
        project_id: str | None = None,
        project_cache_dir: str | None = None,
        on_event: Any | None = None,
    ) -> None:
        self.project_id = project_id
        self.project_cache_dir = project_cache_dir
        self.on_event = on_event
        self._config = get_public_agent_config("architect")
        self._queue = get_global_llm_queue()

    async def synthesize(
        self,
        *,
        target: str,
        target_type: str,
        scope: str,
        memory_block: str,
        vulnerabilities_block: str,
        previous_draft: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Synthesize architecture draft from current project state."""
        if self.on_event:
            self.on_event("architect_synthesizing", {"project_id": self.project_id})

        memory_block = self._compact_evidence_block(memory_block)
        vulnerabilities_block = self._compact_evidence_block(vulnerabilities_block)

        total_input_len = len(memory_block or "") + len(vulnerabilities_block or "")
        if total_input_len > ARCHITECT_HISTORY_THRESHOLD:
            logger.info(
                "architect_history_exceeded_threshold",
                length=total_input_len,
                threshold=ARCHITECT_HISTORY_THRESHOLD,
            )
            memory_block = await self._compress_blocks(
                target=target,
                memory_block=memory_block,
                vulnerabilities_block=vulnerabilities_block,
            )
            vulnerabilities_block = "Merged into compressed summary above."

        # ── 2. Build User Prompt ──────────────────────────────────────────────
        user_message = ARCHITECT_USER_PROMPT_TEMPLATE.format(
            target=target,
            target_type=target_type,
            scope=scope,
            memory_block=memory_block,
            vulnerabilities_block=vulnerabilities_block,
            previous_draft_block=json.dumps(previous_draft, indent=2) if previous_draft else "No previous draft available.",
        )

        messages = [
            ChatMessage(role="system", content=ARCHITECT_SYSTEM_PROMPT),
            ChatMessage(role="user", content=user_message),
        ]

        try:
            response = await self._chat(messages)
            return self._sanitize_draft(self._parse_json_response(response.content))
        except Exception as exc:
            logger.error("architect_synthesis_failed", error=str(exc))
            return previous_draft or {}

    async def _compress_blocks(
        self,
        *,
        target: str,
        memory_block: str,
        vulnerabilities_block: str,
    ) -> str:
        """Compact large evidence blocks deterministically to avoid a second LLM round."""
        logger.info("architect_compressing_history", target=target)
        if self.on_event:
            self.on_event("architect_compressing", {"project_id": self.project_id})
        sections = [
            f"Target: {target}",
            "### COMPACT ARCHITECT MEMORY",
            self._compact_evidence_block(memory_block, max_chars=max(4000, ARCHITECT_HISTORY_THRESHOLD // 2)),
            "",
            "### COMPACT VERIFIED VULNERABILITIES",
            self._compact_evidence_block(vulnerabilities_block, max_chars=max(2000, ARCHITECT_HISTORY_THRESHOLD // 3)),
        ]
        combined = "\n".join(part for part in sections if str(part).strip()).strip()
        return combined[:ARCHITECT_HISTORY_THRESHOLD].strip()

    async def _chat(self, messages: list[ChatMessage]):
        async with LLMClient(self._config, client_name="architect") as llm:
            return await self._queue.call_with_queue(
                "architect",
                llm.chat(messages),
            )

    def _parse_json_response(self, content: str | None) -> dict[str, Any]:
        """Extract and parse JSON from LLM response."""
        if not content:
            return {}
        
        # Strip potential markdown blocks
        clean_content = content.strip()
        if clean_content.startswith("```json"):
            clean_content = clean_content[7:]
        if clean_content.endswith("```"):
            clean_content = clean_content[:-3]
        clean_content = clean_content.strip()

        try:
            parsed = json.loads(clean_content)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            # Try finding JSON block with regex if direct parse fails
            import re
            match = re.search(r'\{.*\}', clean_content, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group())
                    if isinstance(parsed, dict):
                        return parsed
                except json.JSONDecodeError:
                    pass
        
        logger.warning("architect_failed_to_parse_json", content=content[:200])
        return {}

    @classmethod
    def _compact_evidence_block(cls, text: str, *, max_chars: int | None = None) -> str:
        raw = str(text or "").strip()
        if not raw:
            return ""
        limit = max_chars or ARCHITECT_HISTORY_THRESHOLD
        if len(raw) <= limit:
            return raw

        kept: list[str] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            clean = re.sub(r"\s+", " ", line).strip()
            if not clean:
                continue
            lowered = clean.lower()
            keep = (
                clean.startswith(("###", "-", "*"))
                or any(marker in lowered for marker in _ARCHITECT_SIGNAL_MARKERS)
            )
            if not keep:
                continue
            if clean in seen:
                continue
            kept.append(clean[:320])
            seen.add(clean)
            if sum(len(item) + 1 for item in kept) >= limit:
                break

        if not kept:
            return raw[:limit].strip()
        compact = "\n".join(kept)
        return compact[:limit].strip()

    def _sanitize_draft(self, draft: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(draft, dict):
            return {}

        raw_hosts = draft.get("hosts", [])
        hosts = [self._normalize_host(item) for item in raw_hosts if isinstance(item, dict)]
        hosts = [host for host in hosts if host]
        hosts = [host for host in hosts if not self._is_speculative_host(host)]

        if not hosts:
            return {}

        hosts = self._merge_feature_hosts(hosts)
        hosts = self._apply_layout(hosts)

        kept_ids = {str(host["id"]) for host in hosts}
        flows: list[dict[str, Any]] = []
        seen_flow_keys: set[tuple[str, str, str]] = set()
        for row in draft.get("flows", []) if isinstance(draft.get("flows"), list) else []:
            if not isinstance(row, dict):
                continue
            from_id = str(row.get("fromId", "")).strip()
            to_id = str(row.get("toId", "")).strip()
            label = self._clean_text(row.get("label"), limit=120)
            if not from_id or not to_id or from_id == to_id:
                continue
            if from_id not in kept_ids or to_id not in kept_ids:
                continue
            key = (from_id, to_id, label.lower())
            if key in seen_flow_keys:
                continue
            seen_flow_keys.add(key)
            flows.append({
                "fromId": from_id,
                "toId": to_id,
                "label": label,
            })

        title = self._clean_text(draft.get("title"), limit=120)
        if (
            not title
            or self._contains_speculative_text(title)
            or any(marker in title.lower() for marker in _TITLE_REWRITE_MARKERS)
        ):
            title = self._build_default_title(hosts)

        return {
            "title": title,
            "hosts": hosts,
            "flows": flows,
        }

    def _normalize_host(self, item: dict[str, Any]) -> dict[str, Any] | None:
        host_id = self._slug(item.get("id") or item.get("name") or "host")
        name = self._clean_text(item.get("name"), limit=80) or "Observed Host"
        role = self._clean_text(item.get("role"), limit=24) or "Service"
        ports = self._normalize_ports(item.get("ports"))
        note = self._clean_text(item.get("note"), limit=420)
        try:
            x = float(item.get("x", 50))
        except (TypeError, ValueError):
            x = 50.0
        try:
            y = float(item.get("y", 50))
        except (TypeError, ValueError):
            y = 50.0
        return {
            "id": host_id,
            "name": name,
            "role": role,
            "ports": ports,
            "note": note,
            "x": max(0.0, min(100.0, x)),
            "y": max(0.0, min(100.0, y)),
        }

    def _merge_feature_hosts(self, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(hosts) <= 1:
            return hosts

        primary = self._select_primary_host(hosts)
        if primary is None:
            return hosts

        merged: list[dict[str, Any]] = []
        primary_note_parts = [primary.get("note", "").strip()]
        primary_ports = list(primary.get("ports", []))
        primary_id = str(primary["id"])

        for host in hosts:
            host_id = str(host["id"])
            if host_id == primary_id:
                continue
            if self._should_merge_into_primary(host, primary):
                feature_note = self._clean_text(host.get("note"), limit=220)
                feature_name = self._clean_text(host.get("name"), limit=80)
                if feature_note:
                    primary_note_parts.append(feature_note)
                elif feature_name:
                    primary_note_parts.append(f"Observed feature: {feature_name}.")
                for port in host.get("ports", []):
                    if port not in primary_ports:
                        primary_ports.append(port)
                continue
            merged.append(host)

        primary["ports"] = primary_ports
        primary["note"] = self._dedupe_sentences(" ".join(part for part in primary_note_parts if part))
        merged.insert(0, primary)
        return merged

    def _select_primary_host(self, hosts: list[dict[str, Any]]) -> dict[str, Any] | None:
        best_host: dict[str, Any] | None = None
        best_score = -1
        for host in hosts:
            score = 0
            role = str(host.get("role", "")).strip().lower()
            text = f"{host.get('name', '')} {host.get('note', '')}".lower()
            if role in {"edge", "service"}:
                score += 3
            if host.get("ports"):
                score += 3
            if any(marker in text for marker in _WEB_HOST_MARKERS):
                score += 3
            if "gateway" in text or "server" in text:
                score += 1
            if score > best_score:
                best_score = score
                best_host = host
        return best_host

    def _should_merge_into_primary(self, host: dict[str, Any], primary: dict[str, Any]) -> bool:
        text = f"{host.get('name', '')} {host.get('note', '')}".lower()
        host_ports = set(host.get("ports", []))
        primary_ports = set(primary.get("ports", []))
        overlaps_ports = bool(host_ports and primary_ports and host_ports.issubset(primary_ports))
        no_ports = not host_ports

        if any(marker in text for marker in _FEATURE_HOST_MARKERS):
            return True

        if overlaps_ports:
            merge_markers = ("gateway", "edge", "web", "application", "server")
            if any(marker in text for marker in merge_markers):
                return True

        return no_ports

    def _is_speculative_host(self, host: dict[str, Any]) -> bool:
        text = f"{host.get('name', '')} {host.get('note', '')}"
        return self._contains_speculative_text(text)

    def _contains_speculative_text(self, text: Any) -> bool:
        lowered = str(text or "").strip().lower()
        return any(marker in lowered for marker in _SPECULATIVE_MARKERS)

    def _apply_layout(self, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(hosts) == 1:
            hosts[0]["x"] = 50.0
            hosts[0]["y"] = 46.0
            return hosts

        role_rank = {
            "edge": 0,
            "service": 1,
            "internal": 2,
            "auth": 2,
            "data": 3,
            "backup": 4,
        }
        ordered = sorted(
            hosts,
            key=lambda host: (
                role_rank.get(str(host.get("role", "")).strip().lower(), 5),
                str(host.get("name", "")).lower(),
            ),
        )
        x_positions = [20.0, 52.0, 80.0]
        y_positions = [28.0, 52.0, 76.0]
        for index, host in enumerate(ordered):
            host["x"] = x_positions[min(index, len(x_positions) - 1)]
            host["y"] = y_positions[index % len(y_positions)]
        return ordered

    def _build_default_title(self, hosts: list[dict[str, Any]]) -> str:
        if len(hosts) == 1:
            return f"Observed Target Surface: {hosts[0]['name']}"
        return "Observed Target Surface And Service Relationships"

    def _normalize_ports(self, value: Any) -> list[str]:
        ports: list[str] = []
        raw_ports = value if isinstance(value, list) else []
        for item in raw_ports:
            clean = self._clean_text(item, limit=24).lower()
            if not clean:
                continue
            if clean not in ports:
                ports.append(clean)
        return ports

    def _clean_text(self, value: Any, *, limit: int) -> str:
        text = re.sub(r"\s+", " ", str(value or "").strip())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 3)].rstrip() + "..."

    def _slug(self, value: Any) -> str:
        text = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
        return text or "host"

    def _dedupe_sentences(self, text: str) -> str:
        parts = re.split(r"(?<=[.!?])\s+", str(text or "").strip())
        seen: set[str] = set()
        unique: list[str] = []
        for part in parts:
            clean = part.strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(clean)
        return " ".join(unique)[:420]
