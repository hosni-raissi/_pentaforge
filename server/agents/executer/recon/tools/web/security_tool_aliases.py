"""Lightweight web recon aliases backed by curated run_custom security CLIs."""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Optional

from server.agents.tools.run_custom import run_custom

_WORKDIR = Path(__file__).resolve().parents[6]
_MAX_TIMEOUT = 300
_WEB_WORDLIST_DIR = Path("wordlists/web")


def _safe_timeout(value: int, default: int) -> tuple[int, list[str]]:
    try:
        requested = int(value)
    except (TypeError, ValueError):
        requested = default
    effective = max(5, min(requested, _MAX_TIMEOUT))
    warnings: list[str] = []
    if effective != requested:
        warnings.append(f"timeout capped at {_MAX_TIMEOUT}s by run_custom policy")
    return effective, warnings


def _wordlist_path(kind: Optional[str]) -> str:
    clean = str(kind or "folders").strip().lower()
    filename = "files.txt" if clean == "files" else "folders.txt"
    return str(_WEB_WORDLIST_DIR / filename)


def _has_flag(args: list[str], *flags: str) -> bool:
    known = {flag.lower() for flag in flags}
    for arg in args:
        lowered = str(arg or "").strip().lower()
        if lowered in known or any(lowered.startswith(flag + "=") for flag in known):
            return True
    return False


def _result(
    *,
    success: bool,
    command: str,
    tool_name: str,
    execution_time: float,
    extra: Optional[dict] = None,
    warnings: Optional[list[str]] = None,
    error: Optional[str] = None,
) -> dict:
    payload = {
        "success": success,
        "tool": tool_name,
        "command": command,
        "working_dir": str(_WORKDIR),
        "warnings": warnings or [],
        "error": error,
        "execution_time": round(execution_time, 2),
    }
    if extra:
        payload.update(extra)
    return payload


def _run_cli(command: str, args: list[str], reason: str, timeout: int) -> tuple[dict, list[str]]:
    safe_timeout, warnings = _safe_timeout(timeout, 120)
    result = run_custom(
        command=command,
        args=args,
        reason=reason,
        timeout=safe_timeout,
        cwd=str(_WORKDIR),
    )
    stderr = str(result.get("stderr") or "").strip()
    if stderr and stderr not in warnings:
        warnings.append(stderr[:500])
    return result, warnings


def _parse_json_lines(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in str(text or "").splitlines():
        clean = line.strip()
        if not clean.startswith("{"):
            continue
        try:
            parsed = json.loads(clean)
        except Exception:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _http_probe_impl(
    target: Optional[str] = None,
    targets: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
    timeout: int = 120,
) -> dict:
    start = time.time()
    target_list = [str(item).strip() for item in ([target] + list(targets or [])) if str(item).strip()]
    deduped_targets = list(dict.fromkeys(target_list))
    if not deduped_targets:
        return _result(
            success=False,
            command="",
            tool_name="http_probe",
            execution_time=time.time() - start,
            error="target or targets is required",
            extra={"hosts": [], "total_alive": 0, "total_input_targets": 0, "raw_output": ""},
        )

    final_args = [str(arg) for arg in (args or []) if str(arg).strip()]
    defaults = ["-json", "-silent", "-title", "-tech-detect", "-status-code", "-cl", "-ct"]
    for flag in defaults:
        if not _has_flag(final_args, flag):
            final_args.append(flag)
    if not _has_flag(final_args, "-u", "-target"):
        for item in deduped_targets:
            final_args.extend(["-u", item])

    result, warnings = _run_cli(
        "httpx",
        final_args,
        "Probe live HTTP endpoints and collect reachability metadata for recon",
        timeout,
    )
    raw_output = str(result.get("stdout") or "")
    parsed_rows = _parse_json_lines(raw_output)
    hosts: list[dict] = []
    for row in parsed_rows:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        hosts.append(
            {
                "url": url,
                "status_code": int(row.get("status_code") or 0),
                "title": row.get("title") or None,
                "webserver": row.get("webserver") or None,
                "tech": [str(item) for item in (row.get("technologies") or []) if str(item).strip()],
                "content_length": int(row.get("content_length") or 0),
                "content_type": row.get("content_type") or None,
                "scheme": row.get("scheme") or None,
                "host": row.get("host") or None,
                "port": int(row.get("port")) if row.get("port") is not None else None,
            }
        )

    return _result(
        success=bool(result.get("success")) or bool(hosts),
        command=str(result.get("full_command") or ""),
        tool_name="http_probe",
        execution_time=float(result.get("execution_time") or (time.time() - start)),
        warnings=warnings,
        error=result.get("error"),
        extra={
            "hosts": hosts,
            "total_alive": len(hosts),
            "total_input_targets": len(deduped_targets),
            "raw_output": raw_output,
        },
    )


def _cms_detect_and_scan_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 180,
) -> dict:
    start = time.time()
    scanner = str(tool or "").strip().lower()
    target_url = str(target or "").strip()
    if scanner not in {"cmseek", "wpscan", "joomscan", "droopescan"}:
        return _result(
            success=False,
            command="",
            tool_name="cms_detect_and_scan",
            execution_time=time.time() - start,
            error="tool must be cmseek, wpscan, joomscan, or droopescan",
            extra={"target": target_url, "cms_name": None, "cms_version": None, "findings": [], "raw_output": ""},
        )

    final_args = [str(arg) for arg in (args or []) if str(arg).strip()]
    if scanner == "cmseek":
        if not _has_flag(final_args, "--batch"):
            final_args.append("--batch")
        if not _has_flag(final_args, "--random-agent", "-r"):
            final_args.append("--random-agent")
        if not _has_flag(final_args, "-u", "--url"):
            final_args.extend(["-u", target_url])
    elif scanner == "wpscan":
        if not _has_flag(final_args, "--url"):
            final_args.extend(["--url", target_url])
        if not _has_flag(final_args, "-f", "--format"):
            final_args.extend(["-f", "json"])
        if not _has_flag(final_args, "--no-update", "--update"):
            final_args.append("--no-update")
        if not _has_flag(final_args, "-e", "--enumerate"):
            final_args.extend(["-e", "vp,vt,tt,cb,dbe,u,m"])
    elif scanner == "joomscan":
        if not _has_flag(final_args, "-u", "--url"):
            final_args.extend(["-u", target_url])
    elif scanner == "droopescan":
        if "scan" not in final_args:
            final_args.insert(0, "scan")
        if "drupal" not in final_args and "silverstripe" not in final_args:
            scan_index = final_args.index("scan")
            final_args.insert(scan_index + 1, "drupal")
        if not _has_flag(final_args, "-u", "--url"):
            final_args.extend(["-u", target_url])

    result, warnings = _run_cli(
        scanner,
        final_args,
        "Run CMS-focused security CLI for platform fingerprinting and exposure review",
        timeout,
    )
    raw_output = "\n".join(part for part in [str(result.get("stdout") or ""), str(result.get("stderr") or "")] if part).strip()
    lowered = raw_output.lower()
    cms_name = None
    if "wordpress" in lowered or scanner == "wpscan":
        cms_name = "WordPress"
    elif "joomla" in lowered or scanner == "joomscan":
        cms_name = "Joomla"
    elif "drupal" in lowered or scanner == "droopescan":
        cms_name = "Drupal"
    findings = [{"title": match, "severity": "HIGH"} for match in sorted(set(__import__("re").findall(r"\bCVE-\d{4}-\d{4,7}\b", raw_output, __import__("re").IGNORECASE)))]

    return _result(
        success=bool(result.get("success")),
        command=str(result.get("full_command") or ""),
        tool_name="cms_detect_and_scan",
        execution_time=float(result.get("execution_time") or (time.time() - start)),
        warnings=warnings,
        error=result.get("error"),
        extra={
            "target": target_url,
            "cms_name": cms_name,
            "cms_version": None,
            "findings": findings,
            "raw_output": raw_output,
        },
    )


def _directory_file_fuzzing_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
    timeout: int = 240,
) -> dict:
    start = time.time()
    fuzzer = str(tool or "").strip().lower()
    target_url = str(target or "").strip()
    if fuzzer not in {"ffuf", "feroxbuster"}:
        return _result(
            success=False,
            command="",
            tool_name="directory_file_fuzzing",
            execution_time=time.time() - start,
            error="tool must be ffuf or feroxbuster",
            extra={"target": target_url, "results": [], "total_found": 0},
        )

    wordlist = _wordlist_path(builtin_list)
    final_args = [str(arg) for arg in (args or []) if str(arg).strip()]
    if fuzzer == "ffuf":
        if not _has_flag(final_args, "-json"):
            final_args.append("-json")
        if not _has_flag(final_args, "-u"):
            final_args.extend(["-u", target_url if "FUZZ" in target_url else f"{target_url.rstrip('/')}/FUZZ"])
        if not _has_flag(final_args, "-w"):
            final_args.extend(["-w", wordlist])
        if not _has_flag(final_args, "-mc", "-fc"):
            final_args.extend(["-mc", "200,204,301,302,307,401,403"])
    else:
        if not _has_flag(final_args, "--json"):
            final_args.append("--json")
        if not _has_flag(final_args, "--silent", "--output", "--debug-log"):
            final_args.append("--silent")
        if not _has_flag(final_args, "-u", "--url"):
            final_args.extend(["-u", target_url.replace("FUZZ", "")])
        if not _has_flag(final_args, "-w", "--wordlist"):
            final_args.extend(["-w", wordlist])

    result, warnings = _run_cli(
        fuzzer,
        final_args,
        "Enumerate hidden paths and exposed web artifacts for reconnaissance",
        timeout,
    )
    raw_output = str(result.get("stdout") or "")
    parsed_rows = _parse_json_lines(raw_output)
    findings: list[dict] = []
    for row in parsed_rows:
        if fuzzer == "ffuf":
            findings.append(
                {
                    "url": row.get("url", ""),
                    "path": (row.get("input") or {}).get("FFUF", ""),
                    "status": int(row.get("status") or 0),
                    "content_length": int(row.get("length") or 0),
                }
            )
        elif row.get("type") == "response":
            findings.append(
                {
                    "url": row.get("url", ""),
                    "path": row.get("path", ""),
                    "status": int(row.get("status") or 0),
                    "content_length": int(row.get("content_length") or 0),
                }
            )

    return _result(
        success=bool(result.get("success")) or bool(findings),
        command=str(result.get("full_command") or ""),
        tool_name="directory_file_fuzzing",
        execution_time=float(result.get("execution_time") or (time.time() - start)),
        warnings=warnings,
        error=result.get("error"),
        extra={
            "target": target_url,
            "wordlist_used": wordlist,
            "results": findings,
            "total_found": len(findings),
            "raw_output": raw_output,
        },
    )


@lru_cache(maxsize=128)
def _cached_http_probe(target: Optional[str], targets: tuple[str, ...], args: tuple[str, ...], timeout: int) -> str:
    return json.dumps(_http_probe_impl(target=target, targets=list(targets), args=list(args), timeout=timeout), ensure_ascii=True)


@lru_cache(maxsize=128)
def _cached_cms_detect_and_scan(tool: str, target: str, args: tuple[str, ...], timeout: int) -> str:
    return json.dumps(_cms_detect_and_scan_impl(tool=tool, target=target, args=list(args), timeout=timeout), ensure_ascii=True)


@lru_cache(maxsize=128)
def _cached_directory_file_fuzzing(tool: str, target: str, args: tuple[str, ...], builtin_list: Optional[str], timeout: int) -> str:
    return json.dumps(
        _directory_file_fuzzing_impl(tool=tool, target=target, args=list(args), builtin_list=builtin_list, timeout=timeout),
        ensure_ascii=True,
    )


def http_probe(
    target: Optional[str] = None,
    targets: Optional[list[str]] = None,
    args: Optional[list[str]] = None,
    timeout: int = 120,
    use_cache: bool = True,
) -> dict:
    if use_cache:
        return json.loads(_cached_http_probe(target, tuple(targets or ()), tuple(args or ()), timeout))
    return _http_probe_impl(target=target, targets=targets, args=args, timeout=timeout)


def cms_detect_and_scan(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 180,
    use_cache: bool = True,
) -> dict:
    if use_cache:
        return json.loads(_cached_cms_detect_and_scan(tool, target, tuple(args or ()), timeout))
    return _cms_detect_and_scan_impl(tool=tool, target=target, args=args, timeout=timeout)


def directory_file_fuzzing(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    wordlist_mode: str = "builtin",
    inline_wordlist: Optional[list[str]] = None,
    builtin_list: Optional[str] = None,
    timeout: int = 240,
    use_cache: bool = True,
    list_type: Optional[str] = None,
) -> dict:
    if inline_wordlist or list_type == "ia" or str(wordlist_mode).strip().lower() != "builtin":
        return _result(
            success=False,
            command="",
            tool_name="directory_file_fuzzing",
            execution_time=0.0,
            error="Only builtin wordlists are supported for this alias",
            extra={"target": target, "results": [], "total_found": 0},
        )
    if use_cache:
        return json.loads(_cached_directory_file_fuzzing(tool, target, tuple(args or ()), builtin_list, timeout))
    return _directory_file_fuzzing_impl(tool=tool, target=target, args=args, builtin_list=builtin_list, timeout=timeout)


HTTP_PROBE_TOOL_DEFINITION = {
    "name": "http_probe",
    "description": "Probe HTTP endpoints using a lightweight httpx-backed recon alias.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "targets": {"type": "array", "items": {"type": "string"}},
            "args": {"type": "array", "items": {"type": "string"}},
            "timeout": {"type": "integer"},
            "use_cache": {"type": "boolean"},
        },
    },
}


CMS_SCAN_TOOL_DEFINITION = {
    "name": "cms_detect_and_scan",
    "description": "Run CMS-focused recon CLIs like cmseek or wpscan through a lightweight alias.",
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {"type": "string", "enum": ["cmseek", "wpscan", "joomscan", "droopescan"]},
            "target": {"type": "string"},
            "args": {"type": "array", "items": {"type": "string"}},
            "timeout": {"type": "integer"},
            "use_cache": {"type": "boolean"},
        },
        "required": ["tool", "target"],
    },
}


DIRECTORY_FILE_FUZZING_TOOL_DEFINITION = {
    "name": "directory_file_fuzzing",
    "description": "Enumerate hidden paths with ffuf or feroxbuster through a lightweight recon alias.",
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {"type": "string", "enum": ["ffuf", "feroxbuster"]},
            "target": {"type": "string"},
            "args": {"type": "array", "items": {"type": "string"}},
            "wordlist_mode": {"type": "string"},
            "inline_wordlist": {"type": "array", "items": {"type": "string"}},
            "builtin_list": {"type": "string", "enum": ["folders", "files"]},
            "timeout": {"type": "integer"},
            "use_cache": {"type": "boolean"},
            "list_type": {"type": "string", "enum": ["user", "ia"]},
        },
        "required": ["tool", "target"],
    },
}
