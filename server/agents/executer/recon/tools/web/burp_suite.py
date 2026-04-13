from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import BURP_SUITE_CMD, BURP_SUITE_JAR

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class BurpSuiteRequest(BaseModel):
    target: str
    burp_host: str = "127.0.0.1"
    burp_port: int = Field(default=8080, ge=1, le=65535)
    timeout: int = Field(default=10, ge=2, le=120)
    send_test_request: bool = True
    capture_traffic: bool = True
    capture_paths: list[str] = Field(
        default_factory=lambda: ["/", "/api", "/openapi.json", "/swagger", "/graphql"]
    )
    max_capture_flows: int = Field(default=8, ge=1, le=50)
    response_body_limit: int = Field(default=1000, ge=100, le=20000)
    auto_start_burp: bool = False
    burp_startup_wait: int = Field(default=60, ge=3, le=180)

    @field_validator("target")
    def validate_target(cls, v):
        value = v.strip()
        if not value:
            raise ValueError("Target cannot be empty")

        parsed = urlparse(value if "://" in value else f"http://{value}")
        host = parsed.hostname or value

        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for marker in dangerous:
            if marker in value:
                raise ValueError(f"Dangerous character '{marker}' in target")

        if not host:
            raise ValueError("Invalid target/hostname")

        return value

    @field_validator("burp_host")
    def validate_burp_host(cls, v):
        host = v.strip()
        if not host:
            raise ValueError("burp_host cannot be empty")
        if any(ch in host for ch in [" ", "/", "\\", "\n", "\r", "\t"]):
            raise ValueError("Invalid burp_host")
        return host


class BurpSuiteResult(BaseModel):
    success: bool
    target: str
    burp_proxy_url: str
    burp_host: str
    burp_port: int
    burp_listening: bool = False
    burp_launch_attempted: bool = False
    burp_launch_command: Optional[str] = None
    burp_launch_error: Optional[str] = None
    test_request_sent: bool = False
    test_request_error: Optional[str] = None
    capture_traffic: bool = False
    captured_count: int = 0
    captured_flows: list[dict] = []
    capture_errors: list[str] = []
    usage_instructions: list[str] = []
    error: Optional[str] = None
    execution_time: float = 0.0


def resolve_target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target


def port_accepting_connections(port: int, host: str = "127.0.0.1", timeout: float = 0.8) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_usage_instructions(proxy_url: str, host: str) -> list[str]:
    return [
        f"Burp proxy expected at {proxy_url}",
        "Open Burp Suite Community and ensure Proxy listener is enabled.",
        f"Set your browser/client proxy to {proxy_url}",
        "Trust Burp CA certificate in your client for HTTPS interception.",
        f"Then browse or send requests to target host: {host}",
        "Optional env vars for project tools: HTTP_PROXY and HTTPS_PROXY",
    ]


def _command_ready(cmd: list[str]) -> tuple[bool, Optional[str]]:
    if not cmd:
        return False, "Empty launch command"

    exe = cmd[0]
    if "/" in exe:
        if not Path(exe).exists():
            return False, f"Executable not found: {exe}"
    elif shutil.which(exe) is None:
        return False, f"Command not found: {exe}"

    if len(cmd) >= 3 and cmd[0] == "flatpak" and cmd[1] == "run":
        app_id = cmd[2]
        try:
            check = subprocess.run(  # noqa: S603
                ["flatpak", "info", app_id],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=6,
                check=False,
            )
            if check.returncode != 0:
                return False, f"Flatpak app '{app_id}' is not installed"
        except Exception as exc:
            return False, f"Unable to verify flatpak app '{app_id}': {exc}"

    if len(cmd) >= 3 and cmd[0] == "snap" and cmd[1] == "run":
        snap_name = cmd[2]
        try:
            check = subprocess.run(  # noqa: S603
                ["snap", "list", snap_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=6,
                check=False,
            )
            if check.returncode != 0:
                return False, f"Snap package '{snap_name}' is not installed"
        except Exception as exc:
            return False, f"Unable to verify snap package '{snap_name}': {exc}"

    return True, None


def _candidate_burp_commands() -> list[list[str]]:
    commands: list[list[str]] = []

    def _append_unique(cmd: list[str]) -> None:
        if cmd and cmd not in commands:
            commands.append(cmd)

    configured_cmd = (BURP_SUITE_CMD or "").strip()
    if configured_cmd:
        try:
            _append_unique(shlex.split(configured_cmd))
        except ValueError:
            pass

    configured_jar = (BURP_SUITE_JAR or "").strip()
    if configured_jar:
        _append_unique(["java", "-jar", configured_jar])

    _append_unique(["burpsuite"])
    _append_unique(["burpsuite-community"])
    _append_unique(["flatpak", "run", "com.portswigger.BurpSuiteCommunity"])
    _append_unique(["snap", "run", "burpsuite"])

    return commands


def _launch_burp_suite() -> tuple[bool, Optional[str], Optional[str]]:
    attempted = False
    launch_error: Optional[str] = None
    skip_reasons: list[str] = []

    for cmd in _candidate_burp_commands():
        ready, reason = _command_ready(cmd)
        if not ready:
            if reason:
                skip_reasons.append(f"{' '.join(cmd)} -> {reason}")
            continue

        attempted = True
        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Catch immediate startup failures (common when GUI launch command is invalid).
            time.sleep(1.0)
            rc = proc.poll()
            if rc is not None and rc != 0:
                launch_error = f"Launch command exited immediately with code {rc}: {' '.join(cmd)}"
                continue
            return True, " ".join(cmd), None
        except Exception as exc:
            launch_error = f"Failed launching {' '.join(cmd)}: {exc}"

    if attempted:
        return False, None, launch_error or "Unable to launch Burp Suite command"

    if skip_reasons:
        details = "; ".join(skip_reasons[:3])
        return False, None, f"No runnable Burp launch command. {details}"

    return (
        False,
        None,
        (
            "No Burp launch command found. Set recon config BURP_SUITE_CMD/BURP_SUITE_JAR "
            "in server.agents.executer.recon.config."
        ),
    )


def _send_test_request_via_burp(target: str, burp_host: str, burp_port: int, timeout: int) -> Optional[str]:
    url = target if "://" in target else f"http://{target}"
    proxy_url = f"http://{burp_host}:{burp_port}"

    if REQUESTS_AVAILABLE:
        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            headers = {"User-Agent": "PentaForgeBurpSuite/1.0"}
            requests.get(url, proxies=proxies, headers=headers, timeout=timeout, verify=False)
            return None
        except requests.exceptions.RequestException:
            pass

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    req = urllib.request.Request(url, headers={"User-Agent": "PentaForgeBurpSuite/1.0"})

    try:
        with opener.open(req, timeout=timeout):
            return None
    except urllib.error.HTTPError:
        return None
    except Exception as exc:
        return f"Test request failed: {exc}"


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "... [truncated]"


def _capture_urls(target: str, paths: list[str], max_flows: int) -> list[str]:
    normalized = target if "://" in target else f"http://{target}"
    parsed = urlparse(normalized)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    urls: list[str] = [normalized]

    for path in paths:
        item = (path or "").strip()
        if not item:
            continue
        if item.startswith(("http://", "https://")):
            urls.append(item)
            continue
        if not item.startswith("/"):
            item = "/" + item
        urls.append(urljoin(base_root + "/", item.lstrip("/")))

    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            deduped.append(url)
        if len(deduped) >= max_flows:
            break
    return deduped


def _capture_flows_via_burp(
    target: str,
    burp_host: str,
    burp_port: int,
    timeout: int,
    paths: list[str],
    max_flows: int,
    response_body_limit: int,
) -> tuple[list[dict], list[str]]:
    proxy_url = f"http://{burp_host}:{burp_port}"
    urls = _capture_urls(target, paths, max_flows)
    flows: list[dict] = []
    errors: list[str] = []

    if REQUESTS_AVAILABLE:
        proxies = {"http": proxy_url, "https": proxy_url}
        headers = {"User-Agent": "PentaForgeBurpSuite/1.0"}

        for url in urls:
            start = time.time()
            request_meta = {
                "method": "GET",
                "url": url,
                "proxy": proxy_url,
                "headers": headers,
            }
            try:
                resp = requests.get(
                    url,
                    proxies=proxies,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body_text = resp.text or ""
                flows.append(
                    {
                        "request": request_meta,
                        "response": {
                            "status_code": resp.status_code,
                            "final_url": resp.url,
                            "content_type": resp.headers.get("Content-Type", ""),
                            "headers": dict(resp.headers),
                            "body_snippet": _truncate_text(body_text, response_body_limit),
                            "body_length": len(body_text),
                            "elapsed_ms": round((time.time() - start) * 1000, 2),
                        },
                    }
                )
            except requests.exceptions.RequestException as exc:
                errors.append(f"{url} -> {exc}")
                flows.append(
                    {
                        "request": request_meta,
                        "response": None,
                        "error": str(exc),
                    }
                )
        return flows, errors

    for url in urls:
        request_meta = {
            "method": "GET",
            "url": url,
            "proxy": proxy_url,
            "headers": {"User-Agent": "PentaForgeBurpSuite/1.0"},
        }
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        req = urllib.request.Request(url, headers=request_meta["headers"])
        start = time.time()
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                flow = {
                    "request": request_meta,
                    "response": {
                        "status_code": getattr(resp, "status", None),
                        "final_url": resp.geturl(),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "headers": dict(resp.headers),
                        "body_snippet": _truncate_text(body, response_body_limit),
                        "body_length": len(body),
                        "elapsed_ms": round((time.time() - start) * 1000, 2),
                    },
                }
                flows.append(flow)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            flow = {
                "request": request_meta,
                "response": {
                    "status_code": exc.code,
                    "final_url": exc.geturl(),
                    "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
                    "headers": dict(exc.headers) if exc.headers else {},
                    "body_snippet": _truncate_text(body, response_body_limit),
                    "body_length": len(body),
                    "elapsed_ms": round((time.time() - start) * 1000, 2),
                },
            }
            flows.append(flow)
        except Exception as exc:
            errors.append(f"{url} -> {exc}")
            flows.append(
                {
                    "request": request_meta,
                    "response": None,
                    "error": str(exc),
                }
            )

    return flows, errors


def burp_suite(
    target: str,
    burp_host: str = "127.0.0.1",
    burp_port: int = 8080,
    timeout: int = 10,
    send_test_request: bool = True,
    capture_traffic: bool = True,
    capture_paths: Optional[list[str]] = None,
    max_capture_flows: int = 8,
    response_body_limit: int = 1000,
    auto_start_burp: bool = False,
    burp_startup_wait: int = 60,
) -> dict:
    start = time.time()

    try:
        req = BurpSuiteRequest(
            target=target,
            burp_host=burp_host,
            burp_port=burp_port,
            timeout=timeout,
            send_test_request=send_test_request,
            capture_traffic=capture_traffic,
            capture_paths=capture_paths or ["/", "/api", "/openapi.json", "/swagger", "/graphql"],
            max_capture_flows=max_capture_flows,
            response_body_limit=response_body_limit,
            auto_start_burp=auto_start_burp,
            burp_startup_wait=burp_startup_wait,
        )
    except Exception as exc:
        return BurpSuiteResult(
            success=False,
            target=target,
            burp_proxy_url=f"http://{burp_host}:{burp_port}",
            burp_host=burp_host,
            burp_port=burp_port,
            error=f"Validation: {exc}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    target_host = resolve_target_host(req.target)
    proxy_url = f"http://{req.burp_host}:{req.burp_port}"
    listening = port_accepting_connections(req.burp_port, host=req.burp_host)

    launch_attempted = False
    launch_command = None
    launch_error = None
    if not listening and req.auto_start_burp:
        launch_attempted = True
        launched, launch_command, launch_error = _launch_burp_suite()
        if launched:
            deadline = time.time() + req.burp_startup_wait
            while time.time() < deadline:
                if port_accepting_connections(req.burp_port, host=req.burp_host):
                    listening = True
                    break
                time.sleep(0.5)
            if not listening and launch_error is None:
                launch_error = (
                    f"Burp launched using '{launch_command}' but listener did not appear at "
                    f"{proxy_url} within {req.burp_startup_wait}s"
                )

    test_error = None
    test_sent = False
    captured_flows: list[dict] = []
    capture_errors: list[str] = []
    if listening and req.send_test_request:
        test_sent = True
        test_error = _send_test_request_via_burp(
            req.target,
            req.burp_host,
            req.burp_port,
            req.timeout,
        )

    if listening and req.capture_traffic:
        captured_flows, capture_errors = _capture_flows_via_burp(
            req.target,
            req.burp_host,
            req.burp_port,
            req.timeout,
            req.capture_paths,
            req.max_capture_flows,
            req.response_body_limit,
        )

    error = None
    success = listening and (not test_sent or not test_error)
    if not listening:
        error = (
            f"Burp proxy not reachable at {proxy_url}. Start Burp Suite Community and verify Proxy listener settings."
        )
        if launch_attempted and launch_error:
            error = f"{error} Launch detail: {launch_error}"
    elif test_sent and test_error:
        error = f"Burp reachable but test request failed: {test_error}"
    elif req.capture_traffic and not captured_flows:
        error = "Burp reachable but no flows were captured from the configured target/paths."
        success = False

    return BurpSuiteResult(
        success=success,
        target=req.target,
        burp_proxy_url=proxy_url,
        burp_host=req.burp_host,
        burp_port=req.burp_port,
        burp_listening=listening,
        burp_launch_attempted=launch_attempted,
        burp_launch_command=launch_command,
        burp_launch_error=launch_error,
        test_request_sent=test_sent,
        test_request_error=test_error,
        capture_traffic=req.capture_traffic,
        captured_count=len(captured_flows),
        captured_flows=captured_flows,
        capture_errors=capture_errors,
        usage_instructions=build_usage_instructions(proxy_url, target_host),
        error=error,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


BURP_SUITE_TOOL_DEFINITION = {
    "name": "burp_suite",
    "description": (
        "Connect project traffic workflow to Burp Suite Community proxy. "
        "Validates Burp listener reachability and can send a test request through Burp."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target host or URL, e.g. 'https://example.com'",
            },
            "burp_host": {
                "type": "string",
                "description": "Burp proxy host",
                "default": "127.0.0.1",
            },
            "burp_port": {
                "type": "integer",
                "description": "Burp proxy listener port",
                "default": 8080,
            },
            "timeout": {
                "type": "integer",
                "description": "Seconds to wait for test request",
                "default": 10,
            },
            "send_test_request": {
                "type": "boolean",
                "description": "Send one test request through Burp",
                "default": True,
            },
            "capture_traffic": {
                "type": "boolean",
                "description": "Actively send API/web requests through Burp and return request/response flows",
                "default": True,
            },
            "capture_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Paths (or full URLs) to request through Burp for capture",
                "default": ["/", "/api", "/openapi.json", "/swagger", "/graphql"],
            },
            "max_capture_flows": {
                "type": "integer",
                "description": "Maximum number of capture requests to send",
                "default": 8,
            },
            "response_body_limit": {
                "type": "integer",
                "description": "Max response body characters per captured flow",
                "default": 1000,
            },
            "auto_start_burp": {
                "type": "boolean",
                "description": "Attempt to start Burp Suite automatically if listener is not reachable",
                "default": False,
            },
            "burp_startup_wait": {
                "type": "integer",
                "description": "Seconds to wait for Burp listener after auto-start",
                "default": 60,
            },
        },
        "required": ["target"],
    },
}


def main() -> None:
    # Configure local test run.
    TARGET = "http://localhost:8888"
    BURP_HOST = "127.0.0.1"
    BURP_PORT = 8080
    TIMEOUT = 10
    SEND_TEST_REQUEST = True
    CAPTURE_TRAFFIC = True
    CAPTURE_PATHS = ["/", "/api", "/openapi.json", "/swagger", "/graphql"]
    MAX_CAPTURE_FLOWS = 8
    RESPONSE_BODY_LIMIT = 1000
    AUTO_START_BURP = True
    BURP_STARTUP_WAIT = 60
    EMIT_JSON = False

    result = burp_suite(
        target=TARGET,
        burp_host=BURP_HOST,
        burp_port=BURP_PORT,
        timeout=TIMEOUT,
        send_test_request=SEND_TEST_REQUEST,
        capture_traffic=CAPTURE_TRAFFIC,
        capture_paths=CAPTURE_PATHS,
        max_capture_flows=MAX_CAPTURE_FLOWS,
        response_body_limit=RESPONSE_BODY_LIMIT,
        auto_start_burp=AUTO_START_BURP,
        burp_startup_wait=BURP_STARTUP_WAIT,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2))
        return

    status = "OK" if result.get("success") else "FAILED"
    print(f"\n[{status}] target={result.get('target')}")
    print(f"  Burp proxy       : {result.get('burp_proxy_url')}")
    print(f"  Burp listening   : {result.get('burp_listening')}")
    print(f"  Launch attempted : {result.get('burp_launch_attempted')}")
    if result.get("burp_launch_command"):
        print(f"  Launch command   : {result.get('burp_launch_command')}")
    if result.get("burp_launch_error"):
        print(f"  Launch error     : {result.get('burp_launch_error')}")
    print(f"  Test sent        : {result.get('test_request_sent')}")
    if result.get("test_request_error"):
        print(f"  Test error       : {result.get('test_request_error')}")
    print(f"  Captured flows   : {result.get('captured_count')}")
    capture_errors = result.get("capture_errors") or []
    if capture_errors:
        print(f"  Capture errors   : {len(capture_errors)}")
    if result.get("error"):
        print(f"  Error            : {result.get('error')}")

    flows = result.get("captured_flows") or []
    if flows:
        print("\n  Flow preview:")
        for idx, flow in enumerate(flows[:3], start=1):
            req_meta = flow.get("request") or {}
            resp_meta = flow.get("response") or {}
            status = resp_meta.get("status_code", "-")
            final_url = resp_meta.get("final_url") or req_meta.get("url")
            print(f"  {idx}. {req_meta.get('method', 'GET')} {final_url} -> {status}")

    instructions = result.get("usage_instructions") or []
    if instructions:
        print("\n  Usage:")
        for line in instructions:
            print(f"  - {line}")


if __name__ == "__main__":
    main()
