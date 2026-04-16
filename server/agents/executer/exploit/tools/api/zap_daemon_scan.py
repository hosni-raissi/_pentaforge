#/+
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from ...config import (
    ZAP_API_HOST,
    ZAP_API_KEY,
    ZAP_API_PORT,
    ZAP_DAEMON_START_COMMAND,
    ZAP_DEFAULT_MAX_ALERTS,
    ZAP_DEFAULT_SCAN_TIMEOUT,
    ZAP_POLL_INTERVAL_SECONDS,
)

try:
    from zapv2 import ZAPv2  # type: ignore[import-not-found]
except Exception:
    ZAPv2 = None


_BLOCKED_TARGETS = {"0.0.0.0", "169.254.169.254", "metadata.google.internal"}
_ALLOWED_PROFILES = {"web", "api"}
_ALLOWED_FORMATS = {"json", "xml", "html", "md"}
_RISK_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "other": 0}
_DEFAULT_NOISE_ALERTS = {"user agent fuzzer"}


class ZapAlert(BaseModel):
    alert: str = ""
    risk: str = ""
    confidence: str = ""
    url: str = ""
    param: str = ""
    attack: str = ""
    description: str = ""
    solution: str = ""
    reference: str = ""
    cweid: str = ""
    wascid: str = ""
    pluginid: str = ""


class ZapDaemonScanRequest(BaseModel):
    target: str
    profile: str = "web"
    run_spider: bool = True
    run_active_scan: bool = True
    api_definition_url: Optional[str] = None
    context_name: Optional[str] = None
    include_regex: list[str] = Field(default_factory=list)
    exclude_regex: list[str] = Field(default_factory=list)
    report_format: str = "json"
    timeout: int = Field(default=ZAP_DEFAULT_SCAN_TIMEOUT, ge=30, le=7200)
    max_alerts: int = Field(default=ZAP_DEFAULT_MAX_ALERTS, ge=1, le=2000)
    min_risk: str = "informational"
    suppress_default_noise: bool = True
    suppress_alert_names: list[str] = Field(default_factory=list)
    dedupe_alerts: bool = True
    host: str = ZAP_API_HOST
    port: int = Field(default=ZAP_API_PORT, ge=1, le=65535)
    api_key: Optional[str] = None
    poll_interval_seconds: float = Field(default=ZAP_POLL_INTERVAL_SECONDS, ge=0.5, le=30.0)
    auto_start_daemon: bool = False
    daemon_start_command: list[str] = Field(default_factory=list)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        target = value.strip()
        lowered = target.lower()
        if not target.startswith(("http://", "https://")):
            raise ValueError("target must start with http:// or https://")

        for blocked in _BLOCKED_TARGETS:
            if blocked in lowered:
                raise ValueError(f"target '{target}' is blocked")
        return target

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        profile = value.strip().lower()
        if profile not in _ALLOWED_PROFILES:
            raise ValueError(f"profile must be one of: {sorted(_ALLOWED_PROFILES)}")
        return profile

    @field_validator("report_format")
    @classmethod
    def validate_report_format(cls, value: str) -> str:
        fmt = value.strip().lower()
        if fmt not in _ALLOWED_FORMATS:
            raise ValueError(f"report_format must be one of: {sorted(_ALLOWED_FORMATS)}")
        return fmt

    @field_validator("min_risk")
    @classmethod
    def validate_min_risk(cls, value: str) -> str:
        risk = value.strip().lower()
        allowed = {"informational", "low", "medium", "high"}
        if risk not in allowed:
            raise ValueError(f"min_risk must be one of: {sorted(allowed)}")
        return risk

    @field_validator("suppress_alert_names")
    @classmethod
    def validate_suppress_alert_names(cls, value: list[str]) -> list[str]:
        return [item.strip().lower() for item in value if item.strip()]


class ZapDaemonScanResult(BaseModel):
    success: bool
    target: str
    profile: str
    daemon_endpoint: str
    zap_version: str = ""
    spider_started: bool = False
    spider_completed: bool = False
    spider_scan_id: Optional[str] = None
    spider_status: Optional[int] = None
    active_scan_started: bool = False
    active_scan_completed: bool = False
    active_scan_id: Optional[str] = None
    active_scan_status: Optional[int] = None
    report_format: str = "json"
    report: Optional[str] = None
    total_alerts: int = 0
    filtered_out_alerts: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    alerts: list[ZapAlert] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


def _is_socket_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _start_daemon_if_needed(req: ZapDaemonScanRequest, warnings: list[str]) -> None:
    if _is_socket_open(req.host, req.port):
        return
    if not req.auto_start_daemon:
        return

    cmd = req.daemon_start_command or ZAP_DAEMON_START_COMMAND
    if not cmd:
        for candidate in ("zap.sh", "zap", "zaproxy", "owasp-zap", "owasp-zap.sh"):
            resolved = shutil.which(candidate)
            if resolved:
                cmd = [
                    resolved,
                    "-daemon",
                    "-host",
                    req.host,
                    "-port",
                    str(req.port),
                    "-config",
                    "api.disablekey=true",
                ]
                break

    if not cmd:
        warnings.append(
            "ZAP daemon is not reachable and auto-start is enabled, but no daemon_start_command is configured and no ZAP binary was found on PATH."
        )
        return

    # If configured command uses a bare executable name, ensure it exists before spawn.
    cmd_exec = cmd[0].strip() if cmd and cmd[0] else ""
    if cmd_exec and "/" not in cmd_exec and shutil.which(cmd_exec) is None:
        warnings.append(
            f"ZAP daemon command executable '{cmd_exec}' was not found on PATH."
        )
        return

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception as exc:
        warnings.append(f"Failed to auto-start ZAP daemon: {exc}")
        return

    wait_seconds = max(30, min(req.timeout, 120))
    start = time.monotonic()
    while time.monotonic() - start < wait_seconds:
        if _is_socket_open(req.host, req.port):
            warnings.append("ZAP daemon auto-started successfully.")
            return

        if proc.poll() is not None:
            err = ""
            if proc.stderr is not None:
                try:
                    err = proc.stderr.read().strip()
                except Exception:
                    err = ""

            if err:
                warnings.append(f"ZAP daemon exited early: {err[:500]}")
            else:
                warnings.append(
                    f"ZAP daemon process exited early with code {proc.returncode}."
                )
            return

        time.sleep(1.0)

    warnings.append(
        f"Attempted to auto-start ZAP daemon, but it did not become reachable within {wait_seconds}s."
    )


def _wait_for_scan(
    status_fn,
    scan_id: str,
    timeout: int,
    poll_interval_seconds: float,
) -> tuple[bool, int]:
    start = time.monotonic()
    last_status = 0
    while True:
        try:
            last_status = int(str(status_fn(scan_id)).strip())
        except Exception:
            last_status = 0

        if last_status >= 100:
            return True, 100

        if (time.monotonic() - start) >= timeout:
            return False, last_status

        time.sleep(poll_interval_seconds)


def _coerce_alert(alert: dict[str, Any]) -> ZapAlert:
    return ZapAlert(
        alert=str(alert.get("alert", "")),
        risk=str(alert.get("risk", "")),
        confidence=str(alert.get("confidence", "")),
        url=str(alert.get("url", "")),
        param=str(alert.get("param", "")),
        attack=str(alert.get("attack", "")),
        description=str(alert.get("description", "")),
        solution=str(alert.get("solution", "")),
        reference=str(alert.get("reference", "")),
        cweid=str(alert.get("cweid", "")),
        wascid=str(alert.get("wascid", "")),
        pluginid=str(alert.get("pluginid", "")),
    )


def _summarize_risks(alerts: list[ZapAlert]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0, "other": 0}
    for item in alerts:
        risk = _normalize_risk(item.risk)
        if risk in counts:
            counts[risk] += 1
    return counts


def _normalize_risk(risk: str) -> str:
    value = risk.strip().lower()
    if value in {"info", "informative"}:
        return "informational"
    if value in _RISK_ORDER:
        return value
    return "other"


def _filter_and_rank_alerts(
    alerts: list[ZapAlert],
    min_risk: str,
    suppress_alert_names: list[str],
    dedupe_alerts: bool,
) -> tuple[list[ZapAlert], int]:
    min_rank = _RISK_ORDER.get(min_risk, 0)
    suppressed = {name.strip().lower() for name in suppress_alert_names if name.strip()}
    filtered_out = 0
    kept: list[ZapAlert] = []
    seen: set[tuple[str, str, str, str]] = set()

    for alert in alerts:
        alert_name = alert.alert.strip().lower()
        if alert_name in suppressed:
            filtered_out += 1
            continue

        if _RISK_ORDER.get(_normalize_risk(alert.risk), 0) < min_rank:
            filtered_out += 1
            continue

        if dedupe_alerts:
            key = (
                alert_name,
                alert.url.strip().lower(),
                alert.param.strip().lower(),
                alert.attack.strip().lower(),
            )
            if key in seen:
                filtered_out += 1
                continue
            seen.add(key)

        kept.append(alert)

    kept.sort(
        key=lambda a: (
            _RISK_ORDER.get(_normalize_risk(a.risk), 0),
            a.alert.lower(),
            a.url.lower(),
        ),
        reverse=True,
    )
    return kept, filtered_out


def _parse_host_from_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.strip().lower()


def _build_report(zap: Any, req: ZapDaemonScanRequest, warnings: list[str]) -> Optional[str]:
    if req.report_format == "json":
        return None

    try:
        if req.report_format == "html":
            return str(zap.core.htmlreport())
        if req.report_format == "xml":
            return str(zap.core.xmlreport())
        if req.report_format == "md":
            return str(zap.core.mdreport())
    except Exception as exc:
        warnings.append(f"Failed to generate {req.report_format} report: {exc}")

    return None


def zap_daemon_scan(
    target: str,
    profile: str = "web",
    run_spider: bool = True,
    run_active_scan: bool = True,
    api_definition_url: Optional[str] = None,
    context_name: Optional[str] = None,
    include_regex: Optional[list[str]] = None,
    exclude_regex: Optional[list[str]] = None,
    report_format: str = "json",
    timeout: int = ZAP_DEFAULT_SCAN_TIMEOUT,
    max_alerts: int = ZAP_DEFAULT_MAX_ALERTS,
    min_risk: str = "informational",
    suppress_default_noise: bool = True,
    suppress_alert_names: Optional[list[str]] = None,
    dedupe_alerts: bool = True,
    host: str = ZAP_API_HOST,
    port: int = ZAP_API_PORT,
    api_key: Optional[str] = None,
    poll_interval_seconds: float = ZAP_POLL_INTERVAL_SECONDS,
    auto_start_daemon: bool = False,
    daemon_start_command: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Run OWASP ZAP via API/daemon mode and return structured findings.

    This wrapper supports both web and API-centric scans:
    - profile=web: URL access + spider + active scan
    - profile=api: optional OpenAPI import + spider + active scan
    """
    started_at = time.monotonic()
    warnings: list[str] = []

    if ZAPv2 is None:
        return ZapDaemonScanResult(
            success=False,
            target=target,
            profile=profile,
            daemon_endpoint=f"http://{host}:{port}",
            error="python-owasp-zap-v2.4 is not installed. Install it in the server environment.",
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()

    try:
        req = ZapDaemonScanRequest(
            target=target,
            profile=profile,
            run_spider=run_spider,
            run_active_scan=run_active_scan,
            api_definition_url=api_definition_url,
            context_name=context_name,
            include_regex=include_regex or [],
            exclude_regex=exclude_regex or [],
            report_format=report_format,
            timeout=timeout,
            max_alerts=max_alerts,
            min_risk=min_risk,
            suppress_default_noise=suppress_default_noise,
            suppress_alert_names=suppress_alert_names or [],
            dedupe_alerts=dedupe_alerts,
            host=host,
            port=port,
            api_key=api_key,
            poll_interval_seconds=poll_interval_seconds,
            auto_start_daemon=auto_start_daemon,
            daemon_start_command=daemon_start_command or [],
        )
    except Exception as exc:
        return ZapDaemonScanResult(
            success=False,
            target=target,
            profile=profile,
            daemon_endpoint=f"http://{host}:{port}",
            error=f"Validation error: {exc}",
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()

    _start_daemon_if_needed(req, warnings)

    if not _is_socket_open(req.host, req.port):
        return ZapDaemonScanResult(
            success=False,
            target=req.target,
            profile=req.profile,
            daemon_endpoint=f"http://{req.host}:{req.port}",
            error="ZAP daemon is not reachable. Start ZAP in daemon mode or enable auto_start_daemon with a valid start command.",
            warnings=warnings,
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()

    endpoint = f"http://{req.host}:{req.port}"
    client_key = req.api_key if req.api_key is not None else ZAP_API_KEY

    zap = ZAPv2(
        apikey=client_key or None,
        proxies={
            "http": endpoint,
            "https": endpoint,
        },
    )

    spider_scan_id: Optional[str] = None
    active_scan_id: Optional[str] = None
    spider_status: Optional[int] = None
    active_scan_status: Optional[int] = None
    spider_completed = False
    active_scan_completed = False

    try:
        version = str(zap.core.version)
    except Exception as exc:
        return ZapDaemonScanResult(
            success=False,
            target=req.target,
            profile=req.profile,
            daemon_endpoint=endpoint,
            error=f"Unable to connect/authenticate to ZAP API: {exc}",
            warnings=warnings,
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()

    try:
        if req.context_name:
            ctx = getattr(zap, "context", None)
            if ctx is None:
                warnings.append("Context API not available in this ZAP instance.")
            else:
                try:
                    existing = ctx.context_list if not callable(ctx.context_list) else ctx.context_list()
                    if req.context_name not in existing:
                        ctx.new_context(req.context_name)
                except Exception:
                    try:
                        ctx.new_context(req.context_name)
                    except Exception as exc:
                        warnings.append(f"Could not create/use context '{req.context_name}': {exc}")

                for pattern in req.include_regex:
                    try:
                        ctx.include_in_context(req.context_name, pattern)
                    except Exception:
                        warnings.append(f"Could not add include regex to context: {pattern}")

                for pattern in req.exclude_regex:
                    try:
                        ctx.exclude_from_context(req.context_name, pattern)
                    except Exception:
                        warnings.append(f"Could not add exclude regex to context: {pattern}")

        try:
            zap.urlopen(req.target)
        except Exception:
            warnings.append("Initial URL open failed; continuing with scan requests.")

        if req.profile == "api" and req.api_definition_url:
            openapi = getattr(zap, "openapi", None)
            if openapi is None:
                warnings.append("OpenAPI addon not available; skipping api_definition_url import.")
            else:
                imported = False
                try:
                    openapi.import_url(req.api_definition_url)
                    imported = True
                except TypeError:
                    try:
                        openapi.import_url(req.api_definition_url, req.target)
                        imported = True
                    except Exception:
                        imported = False
                except Exception:
                    imported = False

                if not imported:
                    warnings.append("OpenAPI definition import failed; continuing with spider/active scan.")

        if req.run_spider:
            spider_scan_id = str(zap.spider.scan(req.target))
            spider_completed, spider_status = _wait_for_scan(
                status_fn=zap.spider.status,
                scan_id=spider_scan_id,
                timeout=req.timeout,
                poll_interval_seconds=req.poll_interval_seconds,
            )
            if not spider_completed:
                warnings.append("Spider did not reach 100% before timeout.")

        if req.run_active_scan:
            active_scan_id = str(zap.ascan.scan(req.target))
            active_scan_completed, active_scan_status = _wait_for_scan(
                status_fn=zap.ascan.status,
                scan_id=active_scan_id,
                timeout=req.timeout,
                poll_interval_seconds=req.poll_interval_seconds,
            )
            if not active_scan_completed:
                warnings.append("Active scan did not reach 100% before timeout.")

        raw_alerts = zap.core.alerts(baseurl=req.target, start=0, count=req.max_alerts)
        alerts = [_coerce_alert(item) for item in raw_alerts]
        suppress_names = list(req.suppress_alert_names)
        if req.suppress_default_noise:
            suppress_names.extend(sorted(_DEFAULT_NOISE_ALERTS))

        alerts, filtered_out_alerts = _filter_and_rank_alerts(
            alerts=alerts,
            min_risk=req.min_risk,
            suppress_alert_names=suppress_names,
            dedupe_alerts=req.dedupe_alerts,
        )
        severity_counts = _summarize_risks(alerts)

        if filtered_out_alerts:
            warnings.append(
                f"Filtered out {filtered_out_alerts} alert(s) using min_risk='{req.min_risk}', "
                f"suppression, and deduplication rules."
            )

        if req.profile == "api":
            target_host = _parse_host_from_url(req.target)
            external_count = 0
            for item in alerts:
                host = _parse_host_from_url(item.url)
                if host and target_host and host != target_host:
                    external_count += 1
            if external_count:
                warnings.append(
                    f"{external_count} alert(s) are on URLs outside the API host '{target_host}'."
                )

        report = _build_report(zap, req, warnings)
        success = True
        if req.run_spider and not spider_completed and req.run_active_scan and not active_scan_completed:
            success = False

        return ZapDaemonScanResult(
            success=success,
            target=req.target,
            profile=req.profile,
            daemon_endpoint=endpoint,
            zap_version=version,
            spider_started=req.run_spider,
            spider_completed=spider_completed,
            spider_scan_id=spider_scan_id,
            spider_status=spider_status,
            active_scan_started=req.run_active_scan,
            active_scan_completed=active_scan_completed,
            active_scan_id=active_scan_id,
            active_scan_status=active_scan_status,
            report_format=req.report_format,
            report=report,
            total_alerts=len(alerts),
            filtered_out_alerts=filtered_out_alerts,
            severity_counts=severity_counts,
            alerts=alerts,
            warnings=warnings,
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()

    except Exception as exc:
        return ZapDaemonScanResult(
            success=False,
            target=req.target,
            profile=req.profile,
            daemon_endpoint=endpoint,
            zap_version=version,
            spider_started=req.run_spider,
            spider_completed=spider_completed,
            spider_scan_id=spider_scan_id,
            spider_status=spider_status,
            active_scan_started=req.run_active_scan,
            active_scan_completed=active_scan_completed,
            active_scan_id=active_scan_id,
            active_scan_status=active_scan_status,
            warnings=warnings,
            error=str(exc),
            execution_time=round(time.monotonic() - started_at, 2),
        ).model_dump()


ZAP_DAEMON_SCAN_TOOL_DEFINITION = {
    "name": "zap_daemon_scan",
    "description": (
        "Run OWASP ZAP using daemon/API mode for web or API targets. Supports spider and "
        "active scan orchestration, optional OpenAPI import, and returns structured alerts "
        "for database ingestion."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL to scan"},
            "profile": {"type": "string", "enum": ["web", "api"], "default": "web"},
            "run_spider": {"type": "boolean", "default": True},
            "run_active_scan": {"type": "boolean", "default": True},
            "api_definition_url": {
                "type": "string",
                "description": "Optional OpenAPI/Swagger URL for API profile imports",
            },
            "context_name": {
                "type": "string",
                "description": "Optional ZAP context name for include/exclude scoping",
            },
            "include_regex": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Regex patterns to include in ZAP context",
            },
            "exclude_regex": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Regex patterns to exclude from ZAP context",
            },
            "report_format": {
                "type": "string",
                "enum": ["json", "xml", "html", "md"],
                "default": "json",
            },
            "timeout": {
                "type": "integer",
                "default": ZAP_DEFAULT_SCAN_TIMEOUT,
                "minimum": 30,
                "maximum": 7200,
            },
            "max_alerts": {
                "type": "integer",
                "default": ZAP_DEFAULT_MAX_ALERTS,
                "minimum": 1,
                "maximum": 2000,
            },
            "min_risk": {
                "type": "string",
                "enum": ["informational", "low", "medium", "high"],
                "default": "informational",
                "description": "Minimum risk level to include in returned alerts",
            },
            "suppress_default_noise": {
                "type": "boolean",
                "default": True,
                "description": "Suppress common low-signal ZAP passive alerts (e.g., User Agent Fuzzer)",
            },
            "suppress_alert_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alert names to suppress from output",
            },
            "dedupe_alerts": {
                "type": "boolean",
                "default": True,
                "description": "Deduplicate repeated alerts by name/url/param/attack",
            },
            "host": {
                "type": "string",
                "default": ZAP_API_HOST,
                "description": "ZAP daemon host",
            },
            "port": {
                "type": "integer",
                "default": ZAP_API_PORT,
                "minimum": 1,
                "maximum": 65535,
            },
            "api_key": {
                "type": "string",
                "description": "Optional API key override (falls back to exploit config)",
            },
            "poll_interval_seconds": {
                "type": "number",
                "default": ZAP_POLL_INTERVAL_SECONDS,
                "minimum": 0.5,
                "maximum": 30.0,
            },
            "auto_start_daemon": {
                "type": "boolean",
                "default": False,
                "description": "Try starting ZAP daemon when unreachable",
            },
            "daemon_start_command": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional command override for daemon start",
            },
        },
        "required": ["target"],
    },
}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def _env_csv(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def main() -> None:
    target = os.getenv("PENTAFORGE_ZAP_TARGET", "http://localhost:8888/api").strip()
    profile = os.getenv("PENTAFORGE_ZAP_PROFILE", "web").strip().lower() or "web"
    api_definition_url = os.getenv("PENTAFORGE_ZAP_OPENAPI_URL") or None
    context_name = os.getenv("PENTAFORGE_ZAP_CONTEXT_NAME") or None
    include_regex = _env_csv("PENTAFORGE_ZAP_INCLUDE_REGEX")
    exclude_regex = _env_csv("PENTAFORGE_ZAP_EXCLUDE_REGEX")

    run_spider = _env_bool("PENTAFORGE_ZAP_RUN_SPIDER", True)
    run_active_scan = _env_bool("PENTAFORGE_ZAP_RUN_ACTIVE_SCAN", True)
    auto_start_daemon = _env_bool("PENTAFORGE_ZAP_AUTO_START", True)
    dedupe_alerts = _env_bool("PENTAFORGE_ZAP_DEDUPE_ALERTS", True)
    suppress_default_noise = _env_bool("PENTAFORGE_ZAP_SUPPRESS_DEFAULT_NOISE", True)
    suppress_alert_names = _env_csv("PENTAFORGE_ZAP_SUPPRESS_ALERT_NAMES")

    timeout = _env_int("PENTAFORGE_ZAP_TIMEOUT", ZAP_DEFAULT_SCAN_TIMEOUT, 30, 7200)
    max_alerts = _env_int("PENTAFORGE_ZAP_MAX_ALERTS", ZAP_DEFAULT_MAX_ALERTS, 1, 2000)
    min_risk = os.getenv("PENTAFORGE_ZAP_MIN_RISK", "low").strip().lower() or "low"
    report_format = os.getenv("PENTAFORGE_ZAP_REPORT_FORMAT", "json").strip().lower() or "json"

    result = zap_daemon_scan(
        target=target,
        profile=profile,
        run_spider=run_spider,
        run_active_scan=run_active_scan,
        api_definition_url=api_definition_url,
        context_name=context_name,
        include_regex=include_regex,
        exclude_regex=exclude_regex,
        auto_start_daemon=auto_start_daemon,
        dedupe_alerts=dedupe_alerts,
        suppress_default_noise=suppress_default_noise,
        suppress_alert_names=suppress_alert_names,
        report_format=report_format,
        timeout=timeout,
        max_alerts=max_alerts,
        min_risk=min_risk,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
