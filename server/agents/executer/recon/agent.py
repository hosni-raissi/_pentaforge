"""Recon executer agent."""

from __future__ import annotations

import json

from server.agents.executer.base import BaseExecuterAgent, ExecuterCallback, ExecuterResult
from server.agents.executer.resource_catalog import (
    format_executer_resource_catalog_for_prompt,
)
from server.agents.executer.target_tool_routing import (
    filter_tools_for_target_types,
    normalize_target_types,
)
from server.agents.executer.recon.tools.api.security_tools import API_RECON_TOOLS
from server.agents.executer.recon.tools.cloud.security_tools import CLOUD_RECON_TOOLS
from server.agents.executer.recon.tools.container.security_tools import CONTAINER_RECON_TOOLS
from server.agents.executer.recon.tools.infra.security_tools import INFRA_RECON_TOOLS
from server.agents.executer.recon.tools.iot.security_tools import IOT_RECON_TOOLS
from server.agents.executer.recon.tools.mobile.security_tools import MOBILE_APP_RECON_TOOLS
from server.agents.executer.recon.tools.network.security_tools import NETWORK_RECON_TOOLS
from server.agents.executer.recon.tools.repository.security_tools import REPOSITORY_RECON_TOOLS
from server.agents.executer.recon.tools.server.security_tools import SERVER_RECON_TOOLS
from server.agents.executer.recon.tools.web.security_tools import WEB_RECON_TOOLS
from server.config.agent import LocalLLMConfig, PublicLLMConfig

from .config import (
    LLM_CALL_TIMEOUT_SECONDS,
    MAX_TOOL_ROUNDS,
    RECON_MAX_TOOL_CALLS_PER_ROUND,
    RECON_TOOL_EXECUTION_TIMEOUT_SECONDS,
    WARMUP_RECON_MAX_TOOL_CALLS_PER_ROUND,
)
from .prompts import SYSTEM_PROMPT
from .tools import ALL_RECON_TOOLS

_RECON_RUN_CUSTOM_CATALOG_BY_SCOPE: dict[str, dict[str, dict[str, object]]] = {
    "web": WEB_RECON_TOOLS,
    "api": API_RECON_TOOLS,
    "network": NETWORK_RECON_TOOLS,
    "infra": INFRA_RECON_TOOLS,
    "server": SERVER_RECON_TOOLS,
    "mobile": MOBILE_APP_RECON_TOOLS,
    "cloud": CLOUD_RECON_TOOLS,
    "container": CONTAINER_RECON_TOOLS,
    "repository": REPOSITORY_RECON_TOOLS,
    "iot": IOT_RECON_TOOLS,
}

_RECON_TARGET_TYPE_SCOPE_MATRIX: dict[str, tuple[str, ...]] = {
    "web_app": ("web",),
    "api": ("api",),
    "network": ("network",),
    "infra": ("infra",),
    "linux_server": ("server",),
    "mobile": ("mobile",),
    "desktop": (),
    "cloud": ("cloud",),
    "container": ("container",),
    "repository": ("repository",),
    "iot": ("iot",),
}

_REPOSITORY_RUN_CUSTOM_CATALOG_EXCLUDES = {
    "github-workflow-enum",
    "github-secret-scan-read",
    "github-dependency-enum",
    "gitlab-ci-enum",
    "circleci-config-enum",
    "jenkinsfile-audit",
    "gitleaks-detect",
    "trufflehog-filesystem",
    "detect-secrets",
    "repo-supervisor",
    "trivy-repo",
    "grype-repo",
    "syft-sbom",
    "osv-scanner",
}


def _truncate_prompt_tool_description(value: object, limit: int = 140) -> str:
    text = " ".join(str(value or "").strip().split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def build_recon_callable_tool_guide_for_target_types(
    target_types: list[str] | None,
) -> list[dict[str, str]]:
    normalized = normalize_target_types(target_types)
    scoped_tools = filter_tools_for_target_types(
        role="recon",
        tools=ALL_RECON_TOOLS,
        target_types=normalized,
    )
    guide: list[dict[str, str]] = []
    for tool in scoped_tools:
        name = str(getattr(tool, "name", "")).strip()
        if not name or name in {"run_custom", "run_python"}:
            continue
        description = _truncate_prompt_tool_description(getattr(tool, "description", ""))
        guide.append({
            "name": name,
            "description": description,
        })
    guide.sort(key=lambda item: item["name"])
    return guide


def build_recon_run_custom_catalog_for_target_types(
    target_types: list[str] | None,
) -> dict[str, dict[str, object]]:
    normalized = normalize_target_types(target_types)
    if not normalized:
        return {}

    scopes: list[str] = []
    for target_type in normalized:
        for scope in _RECON_TARGET_TYPE_SCOPE_MATRIX.get(target_type, ()):
            if scope not in scopes:
                scopes.append(scope)

    merged: dict[str, dict[str, object]] = {}
    for scope in scopes:
        source = _RECON_RUN_CUSTOM_CATALOG_BY_SCOPE.get(scope)
        if not source:
            continue
        for tool_name, meta in source.items():
            merged[tool_name] = dict(meta)
    if "repository" in normalized:
        for tool_name in _REPOSITORY_RUN_CUSTOM_CATALOG_EXCLUDES:
            merged.pop(tool_name, None)
    return merged


def build_recon_scoped_prompt(target_types: list[str] | None) -> str:
    run_custom_catalog = build_recon_run_custom_catalog_for_target_types(target_types)
    callable_tool_guide = build_recon_callable_tool_guide_for_target_types(target_types)
    local_resource_catalog = format_executer_resource_catalog_for_prompt()
    scope_text = ", ".join(str(x).strip() for x in (target_types or []) if str(x).strip())
    scoped_prompt = SYSTEM_PROMPT
    if scope_text:
        scoped_prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Target surface scope for this run: {scope_text}. "
            "Only work on active surfaces unless tool evidence discovers a new surface."
        )
    if run_custom_catalog:
        scoped_prompt = (
            f"{scoped_prompt}\n\n"
            "run_custom command catalog for this target scope:\n"
            f"{json.dumps(run_custom_catalog, ensure_ascii=True, sort_keys=True, indent=2)}\n"
            "For external security CLIs from this catalog, use "
            "run_custom(command=..., args=[...], reason=...). "
            "Treat the catalog as guidance for what tools are appropriate in this scope."
        )
    if callable_tool_guide:
        scoped_prompt = (
            f"{scoped_prompt}\n\n"
            "Scoped built-in recon tools for this target type:\n"
            f"{json.dumps(callable_tool_guide[:20], ensure_ascii=True, indent=2)}\n"
            "If one of these agent-native tools directly fits the scenario, prefer it before falling back to run_custom."
        )
    if "repository" in normalize_target_types(target_types):
        scoped_prompt = (
            f"{scoped_prompt}\n\n"
            "Repository target guidance:\n"
            "- If the target is a remote repository URL, first create a local sandbox checkout before file-based inspection.\n"
            "- Prefer cloning into a relative sandbox path such as repos/<owner>/<repo>.\n"
            "- After the checkout exists, run read-only tools such as cloc, grep, find, gitleaks, semgrep, or dependency scanners against that local path.\n"
            "- Treat missing local checkout paths as setup issues, not vulnerability evidence."
        )
    if "mobile" in normalize_target_types(target_types):
        scoped_prompt = (
            f"{scoped_prompt}\n\n"
            "Mobile target guidance:\n"
            "- Mobile scans in this deployment are static-only.\n"
            "- Focus on APK/IPA decompilation, manifest and plist review, secret extraction, endpoint discovery, signing checks, and configuration analysis.\n"
            "- Do not assume a live Android or iOS runtime is available for adb, Frida, Objection, or traffic-proxy steps.\n"
            "- Treat runtime-only checks as unsupported in this environment unless the operator explicitly provides external evidence."
        )
    scoped_prompt = (
        f"{scoped_prompt}\n\n"
        "Preferred local executer resource catalog for this repository:\n"
        f"{local_resource_catalog}\n"
        "Prefer these project-local checklist, wordlist, and seclist paths over generic "
        "OS defaults such as /usr/share/... or /opt/wordlists."
    )
    return scoped_prompt


class ReconExecuterAgent(BaseExecuterAgent):
    """
    Executes reconnaissance scenarios with stealth capabilities.

    Orchestrates passive and active reconnaissance including:
    - Port scanning (Nmap, Masscan) with stealth adaptation
    - Subdomain enumeration (Amass, Subfinder)
    - OSINT collection (Shodan, certificate transparency)
    - Technology detection (WhatWeb, header analysis)
    - Secret discovery (TruffleHog, Gitleaks)

    Features a Stealth Analyzer sub-component that:
    - Detects honeypot indicators
    - Identifies tarpit behavior
    - Dynamically adapts scan cadence
    - Avoids detection patterns
    """

    def __init__(
        self,
        *,
        mode: str | None = None,
        callback: ExecuterCallback | None = None,
        config: PublicLLMConfig | None = None,
        local_config: LocalLLMConfig | None = None,
        target_types: list[str] | None = None,
        project_id: str | None = None,
        project_cache_dir: str | None = None,
        approval_mode: str = "custom",
    ) -> None:
        self._target_types = list(target_types or [])
        scoped_tools = filter_tools_for_target_types(
            role="recon",
            tools=ALL_RECON_TOOLS,
            target_types=target_types,
        )
        scoped_prompt = build_recon_scoped_prompt(target_types)
        super().__init__(
            role="recon",
            system_prompt=scoped_prompt,
            tools=scoped_tools,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            max_tool_calls_per_round=RECON_MAX_TOOL_CALLS_PER_ROUND,
            call_timeout_seconds=LLM_CALL_TIMEOUT_SECONDS,
            mode=mode,
            callback=callback,
            config=config,
            local_config=local_config,
            project_id=project_id,
            project_cache_dir=project_cache_dir,
            approval_mode=approval_mode,
        )

    async def run(
        self,
        user_message: str,
        *,
        max_tool_rounds_override: int | None = None,
    ) -> ExecuterResult:
        context_block = "Project memory system is authoritative for prior findings; no legacy context window is used."

        available_tools = sorted(self._tools.keys())
        normalized_targets = normalize_target_types(self._target_types)
        run_custom_catalog = build_recon_run_custom_catalog_for_target_types(self._target_types)
        callable_tool_guide = build_recon_callable_tool_guide_for_target_types(self._target_types)
        local_resource_catalog = format_executer_resource_catalog_for_prompt()
        max_tool_calls_for_run = _max_tool_calls_per_round_for_message(user_message)
        max_rounds_for_run = (
            min(3, max(1, int(max_tool_rounds_override)))
            if max_tool_rounds_override is not None
            else MAX_TOOL_ROUNDS
        )
        packet = build_recon_scenario_packet(
            scenario_and_target=user_message,
            context_block=context_block,
            available_tools=available_tools,
            target_types=normalized_targets,
            run_custom_catalog=run_custom_catalog,
            callable_tool_guide=callable_tool_guide,
            local_resource_catalog=local_resource_catalog,
            max_tool_calls_per_round=max_tool_calls_for_run,
            max_rounds_per_scenario=max_rounds_for_run,
        )
        previous_timeout_cap = self._execution_tool_timeout_cap_seconds
        previous_max_tool_calls = self._max_tool_calls_per_round
        self._execution_tool_timeout_cap_seconds = _tool_timeout_cap_for_message(user_message)
        self._max_tool_calls_per_round = max_tool_calls_for_run
        try:
            return await super().run(packet, max_tool_rounds_override=max_rounds_for_run)
        finally:
            self._execution_tool_timeout_cap_seconds = previous_timeout_cap
            self._max_tool_calls_per_round = previous_max_tool_calls


def _tool_timeout_cap_for_message(user_message: str) -> int | None:
    message = str(user_message or "")
    if "Warmup scenario batch" in message or "Warmup mode:" in message:
        return RECON_TOOL_EXECUTION_TIMEOUT_SECONDS
    return None


def _max_tool_calls_per_round_for_message(user_message: str) -> int:
    message = str(user_message or "")
    if "Warmup scenario batch" in message or "Warmup mode:" in message:
        return WARMUP_RECON_MAX_TOOL_CALLS_PER_ROUND
    return RECON_MAX_TOOL_CALLS_PER_ROUND

def build_recon_scenario_packet(
    *,
    scenario_and_target: str,
    context_block: str,
    available_tools: list[str],
    target_types: list[str],
    run_custom_catalog: dict[str, dict[str, object]] | list[str],
    callable_tool_guide: list[dict[str, str]] | None = None,
    local_resource_catalog: str = "",
    max_tool_calls_per_round: int,
    max_rounds_per_scenario: int,
) -> str:
    if isinstance(run_custom_catalog, dict):
        run_custom_catalog_names = sorted(run_custom_catalog.keys())
        run_custom_catalog_details = json.dumps(
            run_custom_catalog,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
    else:
        run_custom_catalog_names = [
            str(item).strip()
            for item in run_custom_catalog
            if str(item).strip()
        ] if isinstance(run_custom_catalog, list) else []
        run_custom_catalog_details = (
            ", ".join(run_custom_catalog_names)
            if run_custom_catalog_names
            else "none"
        )

    callable_tool_guide_block = (
        json.dumps(callable_tool_guide[:20], ensure_ascii=True, indent=2)
        if isinstance(callable_tool_guide, list) and callable_tool_guide
        else "none"
    )

    local_catalog_block = (
        "Preferred local executer resource catalog:\n"
        f"{local_resource_catalog}\n\n"
        if local_resource_catalog
        else ""
    )
    return (
        "Recon scenario packet:\n"
        "1) Scenario + target info from operator follows below.\n"
        "   Operator info may include prior execution history for this agent.\n"
        "2) Use scoped recon tools to maximize useful recon signal for this scenario.\n"
        f"3) Max tool executions per round: {max_tool_calls_per_round}. Max rounds per scenario: {max_rounds_per_scenario}.\n"
        "4) Every allowed round is a tool-execution round. Do not reserve a separate final JSON/reporting round.\n"
        "5) If another round remains after this one, carry forward a concise summary of what ran and what was found before choosing the next tools.\n"
        "6) After the last allowed tool round, the system will forward collected evidence and round summaries to the perceptor.\n"
        "7) Always update context window with new findings each round.\n\n"
        "8) If scenario info includes recommended product tooling or nuclei hints, prefer that selective path over broad generic scanning.\n\n"
        "Current context window:\n"
        f"{context_block}\n\n"
        f"Target surface scope for this run: {', '.join(target_types) if target_types else 'unspecified'}\n\n"
        "Available callable tools in this run:\n"
        f"{', '.join(available_tools)}\n\n"
        "run_custom catalog security tools for this scope:\n"
        f"{', '.join(run_custom_catalog_names) if run_custom_catalog_names else 'none'}\n\n"
        "Scoped run_custom catalog details:\n"
        f"{run_custom_catalog_details}\n\n"
        "Scoped built-in recon tools for this run:\n"
        f"{callable_tool_guide_block}\n\n"
        "If a scoped built-in recon tool already matches the objective, prefer that agent-native tool first.\n"
        "Use run_custom for external CLIs that are appropriate in this scoped catalog.\n\n"
        "When a suitable external security CLI appears in this scoped catalog, prefer executing it via "
        "run_custom(command=..., args=[...], reason=...) instead of inventing shell syntax or using a generic substitute.\n\n"
        f"{local_catalog_block}"
        "Scenario + target info:\n"
        f"{scenario_and_target}"
    )
