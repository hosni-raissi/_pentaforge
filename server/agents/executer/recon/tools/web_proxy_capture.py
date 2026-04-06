#/+
import subprocess
import json
import os
import time
import signal
import tempfile
import shutil
import socket
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
# PROJECT CONFIG
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    _project_dir: Optional[Path] = None
    TEMP_DIR = "tmp"

    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir

        current = Path(__file__).resolve().parent
        for parent in [current] + list(current.parents):
            if any((parent / m).exists() for m in ["pyproject.toml", "setup.py", ".git"]):
                cls._project_dir = parent
                return cls._project_dir

        cls._project_dir = Path.cwd()
        return cls._project_dir

    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


# ══════════════════════════════════════════════════════════════
# SCHEMAS
# ══════════════════════════════════════════════════════════════

class HttpCaptureRequest(BaseModel):
    target: str
    port: int = Field(default=8080, ge=1024, le=65535)
    timeout: int = Field(default=120, ge=10, le=3600)
    max_results: int = Field(default=200, ge=1, le=5000)
    exact_host: bool = True
    host_regex: Optional[str] = None
    capture_response_body: bool = False
    max_request_body_bytes: int = Field(default=10000, ge=0, le=500000)
    max_response_body_bytes: int = Field(default=10000, ge=0, le=500000)
    startup_timeout: int = Field(default=15, ge=3, le=120)
    auto_probe: bool = False
    auto_probe_timeout: int = Field(default=8, ge=2, le=60)

    @field_validator("target")
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        parsed = urlparse(v if "://" in v else f"http://{v}")
        host = parsed.hostname or v

        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")

        if not host:
            raise ValueError("Invalid target/hostname")

        return v

    @field_validator("host_regex")
    def validate_host_regex(cls, v):
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid host_regex: {e}")
        return v


class HttpFlow(BaseModel):
    flow_id: str
    host: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None

    request_headers: Optional[dict] = None
    request_cookies: Optional[dict] = None
    request_query: Optional[dict] = None
    request_post_data: Optional[str] = None
    request_content_type: Optional[str] = None
    request_timestamp: Optional[float] = None
    request_body_truncated: bool = False

    status: Optional[int] = None
    response_headers: Optional[dict] = None
    response_cookies: Optional[dict] = None
    response_content_type: Optional[str] = None
    response_body: Optional[str] = None
    response_timestamp: Optional[float] = None
    response_body_truncated: bool = False

    has_request: bool = False
    has_response: bool = False


class HttpCaptureResult(BaseModel):
    success: bool
    target: str
    matched_host: str
    port: int
    proxy_url: str
    usage_instructions: list[str] = []
    total_captured: int = 0
    total_requests: int = 0
    total_responses: int = 0
    truncated: bool = False
    flows: list[HttpFlow] = []
    mitmdump_return_code: Optional[int] = None
    mitmdump_stderr: Optional[str] = None
    startup_confirmed: bool = False
    auto_probe_sent: bool = False
    auto_probe_error: Optional[str] = None
    capture_response_body: bool = False
    host_regex: Optional[str] = None
    ca_files_present: bool = False
    ca_hint: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# MITM SCRIPT
# ══════════════════════════════════════════════════════════════

MITM_SCRIPT = r'''
from mitmproxy import http
import json
import time
import re
import threading
import sys

TARGET_DOMAIN = __TARGET_DOMAIN__
OUTPUT_FILE = __OUTPUT_FILE__
EXACT_HOST = __EXACT_HOST__
HOST_REGEX = __HOST_REGEX__
CAPTURE_RESPONSE_BODY = __CAPTURE_RESPONSE_BODY__
MAX_REQUEST_BODY_BYTES = __MAX_REQUEST_BODY_BYTES__
MAX_RESPONSE_BODY_BYTES = __MAX_RESPONSE_BODY_BYTES__

_host_re = re.compile(HOST_REGEX) if HOST_REGEX else None
_write_lock = threading.Lock()

def host_matches(host: str) -> bool:
    if not host:
        return False

    host = host.lower().split(":")[0]  # Remove port if present
    target = TARGET_DOMAIN.lower()

    if _host_re is not None:
        try:
            return _host_re.search(host) is not None
        except Exception:
            return False

    if EXACT_HOST:
        return host == target

    return host == target or host.endswith("." + target)

def limit_text(text: str, max_bytes: int):
    if text is None:
        return None, False
    if max_bytes <= 0:
        return "", len(text) > 0
    if len(text) > max_bytes:
        return text[:max_bytes], True
    return text, False

def append_line(obj: dict):
    try:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        with _write_lock:
            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        sys.stderr.write(f"[mitmproxy-addon] Error writing to {OUTPUT_FILE}: {e}\n")

def request(flow: http.HTTPFlow):
    try:
        host = flow.request.pretty_host
        if not host_matches(host):
            return

        body = flow.request.get_text(strict=False)
        body, body_truncated = limit_text(body, MAX_REQUEST_BODY_BYTES)

        data = {
            "event": "request",
            "flow_id": flow.id,
            "host": host,
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "cookies": dict(flow.request.cookies),
            "query": dict(flow.request.query),
            "post_data": body,
            "content_type": flow.request.headers.get("content-type"),
            "body_truncated": body_truncated,
        }
        append_line(data)
    except Exception as e:
        sys.stderr.write(f"[mitmproxy-addon] Error in request handler: {e}\n")

def response(flow: http.HTTPFlow):
    try:
        host = flow.request.pretty_host
        if not host_matches(host):
            return

        response_body = None
        body_truncated = False

        if CAPTURE_RESPONSE_BODY and flow.response is not None:
            response_body = flow.response.get_text(strict=False)
            response_body, body_truncated = limit_text(response_body, MAX_RESPONSE_BODY_BYTES)

        data = {
            "event": "response",
            "flow_id": flow.id,
            "host": host,
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status": flow.response.status_code if flow.response else None,
            "headers": dict(flow.response.headers) if flow.response else {},
            "cookies": dict(flow.response.cookies) if flow.response else {},
            "content_type": flow.response.headers.get("content-type") if flow.response else None,
            "response_body": response_body,
            "body_truncated": body_truncated,
        }
        append_line(data)
    except Exception as e:
        sys.stderr.write(f"[mitmproxy-addon] Error in response handler: {e}\n")
'''


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def resolve_target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def build_usage_instructions(port: int, host: str) -> list[str]:
    return [
        f"mitmdump is listening on 127.0.0.1:{port}",
        "This tool only captures traffic that is explicitly routed through the proxy.",
        f"Configure your browser/client proxy to http://127.0.0.1:{port}",
        "Install and trust the mitmproxy CA certificate in the client if intercepting HTTPS",
        f"Then browse or send requests to the target host: {host}",
        "Without routing traffic through the proxy, this capture will return zero flows",
    ]


def read_file_safe(path: Path, limit: int = 12000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except Exception:
        return ""


def port_available(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def port_accepting_connections(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def stop_process(proc: subprocess.Popen, graceful_timeout: int = 5) -> tuple[Optional[int], Optional[str]]:
    try:
        if proc.poll() is not None:
            return proc.returncode, None

        proc.send_signal(signal.SIGINT)

        try:
            proc.wait(timeout=graceful_timeout)
            return proc.returncode, None
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
                return proc.returncode, "Process required terminate() after SIGINT timeout"
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                return proc.returncode, "Process required kill() after terminate() timeout"
    except Exception as e:
        return None, str(e)


def parse_capture_file(capture_file: Path, max_results: int) -> tuple[list[HttpFlow], int, int, int, bool]:
    flow_map: dict[str, dict] = {}
    total_requests = 0
    total_responses = 0

    if not capture_file.exists():
        return [], 0, 0, 0, False

    with capture_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except Exception:
                continue

            flow_id = data.get("flow_id")
            if not flow_id:
                continue

            if flow_id not in flow_map:
                flow_map[flow_id] = {
                    "flow_id": flow_id,
                    "host": data.get("host"),
                    "method": None,
                    "url": None,
                    "request_headers": None,
                    "request_cookies": None,
                    "request_query": None,
                    "request_post_data": None,
                    "request_content_type": None,
                    "request_timestamp": None,
                    "request_body_truncated": False,
                    "status": None,
                    "response_headers": None,
                    "response_cookies": None,
                    "response_content_type": None,
                    "response_body": None,
                    "response_timestamp": None,
                    "response_body_truncated": False,
                    "has_request": False,
                    "has_response": False,
                }

            rec = flow_map[flow_id]
            event = data.get("event")

            if event == "request":
                total_requests += 1
                rec["host"] = data.get("host") or rec["host"]
                rec["method"] = data.get("method")
                rec["url"] = data.get("url")
                rec["request_headers"] = data.get("headers")
                rec["request_cookies"] = data.get("cookies")
                rec["request_query"] = data.get("query")
                rec["request_post_data"] = data.get("post_data")
                rec["request_content_type"] = data.get("content_type")
                rec["request_timestamp"] = data.get("timestamp")
                rec["request_body_truncated"] = bool(data.get("body_truncated", False))
                rec["has_request"] = True

            elif event == "response":
                total_responses += 1
                rec["host"] = data.get("host") or rec["host"]
                rec["method"] = data.get("method") or rec["method"]
                rec["url"] = data.get("url") or rec["url"]
                rec["status"] = data.get("status")
                rec["response_headers"] = data.get("headers")
                rec["response_cookies"] = data.get("cookies")
                rec["response_content_type"] = data.get("content_type")
                rec["response_body"] = data.get("response_body")
                rec["response_timestamp"] = data.get("timestamp")
                rec["response_body_truncated"] = bool(data.get("body_truncated", False))
                rec["has_response"] = True

    flows = [HttpFlow(**v) for v in flow_map.values()]
    flows.sort(
        key=lambda x: (
            x.request_timestamp if x.request_timestamp is not None else
            x.response_timestamp if x.response_timestamp is not None else 0
        )
    )

    total = len(flows)
    truncated = False
    if total > max_results:
        flows = flows[:max_results]
        truncated = True

    return flows, total, total_requests, total_responses, truncated


def wait_for_mitmdump_start(
    proc: subprocess.Popen,
    stderr_path: Path,
    startup_timeout: int,
    port: int,
) -> tuple[bool, str]:
    start = time.time()
    observed = ""

    ready_markers = [
        "proxy server listening",
        "http proxy listening",
        "listening at",
        "server listening",
    ]

    while time.time() - start < startup_timeout:
        if proc.poll() is not None:
            observed = read_file_safe(stderr_path, limit=12000)
            return False, observed

        # Reliable readiness signal: socket is accepting connections.
        if port_accepting_connections(port):
            observed = read_file_safe(stderr_path, limit=12000)
            if observed:
                observed = f"{observed}\n[startup] tcp-listening on 127.0.0.1:{port}"
            else:
                observed = f"[startup] tcp-listening on 127.0.0.1:{port}"
            return True, observed

        observed = read_file_safe(stderr_path, limit=12000).lower()
        if any(marker in observed for marker in ready_markers):
            return True, observed

        time.sleep(0.25)

    # Final check right at timeout boundary.
    if proc.poll() is None and port_accepting_connections(port):
        observed = read_file_safe(stderr_path, limit=12000)
        if observed:
            observed = f"{observed}\n[startup] tcp-listening on 127.0.0.1:{port}"
        else:
            observed = f"[startup] tcp-listening on 127.0.0.1:{port}"
        return True, observed

    observed = read_file_safe(stderr_path, limit=12000)
    return False, observed


def detect_mitm_ca_files() -> tuple[bool, Optional[str]]:
    mitm_dir = Path.home() / ".mitmproxy"
    expected = [
        mitm_dir / "mitmproxy-ca.pem",
        mitm_dir / "mitmproxy-ca-cert.pem",
        mitm_dir / "mitmproxy-ca-cert.cer",
        mitm_dir / "mitmproxy-ca-cert.p12",
    ]

    present = [str(p) for p in expected if p.exists()]
    if present:
        return True, f"mitmproxy CA files found: {', '.join(present[:4])}"

    return False, (
        f"No mitmproxy CA files detected in {mitm_dir}. "
        "HTTPS interception may fail unless mitmproxy initializes its CA and the client trusts it."
    )


def send_auto_probe_via_proxy(target: str, port: int, timeout: int) -> Optional[str]:
    """Send one request through the local proxy to seed capture with at least one flow."""
    url = target if "://" in target else f"http://{target}"
    proxy_url = f"http://127.0.0.1:{port}"

    # Try with requests first (more reliable), fall back to urllib
    if REQUESTS_AVAILABLE:
        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            headers = {"User-Agent": "PentaForgeProxyCapture/1.0"}
            requests.get(url, proxies=proxies, headers=headers, timeout=timeout, verify=False)
            return None
        except requests.exceptions.RequestException as e:
            # Continue to try urllib as fallback
            pass

    # Fallback to urllib
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    req = urllib.request.Request(url, headers={"User-Agent": "PentaForgeProxyCapture/1.0"})

    try:
        with opener.open(req, timeout=timeout):
            return None
    except urllib.error.HTTPError:
        # HTTP errors still generate flows, so treat as successful probe.
        return None
    except Exception as e:
        return f"Auto-probe request failed: {e}"


# ══════════════════════════════════════════════════════════════
# MAIN TOOL
# ══════════════════════════════════════════════════════════════

def http_capture(
    target: str,
    port: int = 8080,
    timeout: int = 120,
    max_results: int = 200,
    exact_host: bool = True,
    host_regex: Optional[str] = None,
    capture_response_body: bool = False,
    max_request_body_bytes: int = 10000,
    max_response_body_bytes: int = 10000,
    startup_timeout: int = 15,
    auto_probe: bool = False,
    auto_probe_timeout: int = 8,
) -> dict:
    """
    Capture HTTP/HTTPS traffic for a target host via mitmdump proxy.

    IMPORTANT:
    - This tool does NOT generate traffic by itself.
    - Traffic must actually be routed through the proxy.
    - For HTTPS interception, the client must trust the mitmproxy CA.
    - If host_regex is set, it overrides exact_host/subdomain logic.
    """

    start = time.time()

    try:
        req = HttpCaptureRequest(
            target=target,
            port=port,
            timeout=timeout,
            max_results=max_results,
            exact_host=exact_host,
            host_regex=host_regex,
            capture_response_body=capture_response_body,
            max_request_body_bytes=max_request_body_bytes,
            max_response_body_bytes=max_response_body_bytes,
            startup_timeout=startup_timeout,
            auto_probe=auto_probe,
            auto_probe_timeout=auto_probe_timeout,
        )
    except Exception as e:
        return HttpCaptureResult(
            success=False,
            target=target,
            matched_host="",
            port=port,
            proxy_url=f"http://127.0.0.1:{port}",
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2)
        ).model_dump()

    host = resolve_target_host(req.target)
    ca_files_present, ca_hint = detect_mitm_ca_files()

    if not command_exists("mitmdump"):
        return HttpCaptureResult(
            success=False,
            target=req.target,
            matched_host=host,
            port=req.port,
            proxy_url=f"http://127.0.0.1:{req.port}",
            usage_instructions=build_usage_instructions(req.port, host),
            capture_response_body=req.capture_response_body,
            host_regex=req.host_regex,
            ca_files_present=ca_files_present,
            ca_hint=ca_hint,
            error="Tool 'mitmdump' not installed or not in PATH",
            execution_time=round(time.time() - start, 2)
        ).model_dump()

    if not port_available(req.port):
        return HttpCaptureResult(
            success=False,
            target=req.target,
            matched_host=host,
            port=req.port,
            proxy_url=f"http://127.0.0.1:{req.port}",
            usage_instructions=build_usage_instructions(req.port, host),
            capture_response_body=req.capture_response_body,
            host_regex=req.host_regex,
            ca_files_present=ca_files_present,
            ca_hint=ca_hint,
            error=f"Port {req.port} is already in use on 127.0.0.1",
            execution_time=round(time.time() - start, 2)
        ).model_dump()

    tmp_dir = ProjectConfig.get_temp_dir()

    stderr_fd, stderr_path_str = tempfile.mkstemp(prefix="mitm_stderr_", suffix=".log", dir=tmp_dir)
    capture_fd, capture_path_str = tempfile.mkstemp(prefix="capture_", suffix=".jsonl", dir=tmp_dir)
    script_fd, script_path_str = tempfile.mkstemp(prefix="mitm_script_", suffix=".py", dir=tmp_dir)

    os.close(stderr_fd)
    os.close(capture_fd)
    os.close(script_fd)

    stderr_path = Path(stderr_path_str)
    capture_path = Path(capture_path_str)
    script_path = Path(script_path_str)

    script = MITM_SCRIPT
    script = script.replace("__TARGET_DOMAIN__", json.dumps(host))
    script = script.replace("__OUTPUT_FILE__", json.dumps(str(capture_path)))
    script = script.replace("__EXACT_HOST__", "True" if req.exact_host else "False")
    script = script.replace("__HOST_REGEX__", repr(req.host_regex))
    script = script.replace("__CAPTURE_RESPONSE_BODY__", "True" if req.capture_response_body else "False")
    script = script.replace("__MAX_REQUEST_BODY_BYTES__", str(req.max_request_body_bytes))
    script = script.replace("__MAX_RESPONSE_BODY_BYTES__", str(req.max_response_body_bytes))
    script_path.write_text(script, encoding="utf-8")

    cmd = [
        "mitmdump",
        "-p", str(req.port),
        "-s", str(script_path)
    ]

    proc = None
    mitmdump_rc = None
    mitmdump_stderr = None
    process_note = None
    startup_confirmed = False
    auto_probe_sent = False
    auto_probe_error = None

    try:
        with open(stderr_path, "w", encoding="utf-8") as stderr_file:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                text=True
            )

        startup_confirmed, startup_log = wait_for_mitmdump_start(
            proc,
            stderr_path,
            req.startup_timeout,
            req.port,
        )
        mitmdump_stderr = startup_log[:12000] if startup_log else None

        if not startup_confirmed:
            mitmdump_rc, process_note = stop_process(proc)
            try:
                script_path.unlink(missing_ok=True)
                capture_path.unlink(missing_ok=True)
                stderr_path.unlink(missing_ok=True)
            except Exception:
                pass

            return HttpCaptureResult(
                success=False,
                target=req.target,
                matched_host=host,
                port=req.port,
                proxy_url=f"http://127.0.0.1:{req.port}",
                usage_instructions=build_usage_instructions(req.port, host),
                mitmdump_return_code=mitmdump_rc,
                mitmdump_stderr=mitmdump_stderr,
                startup_confirmed=False,
                auto_probe_sent=auto_probe_sent,
                auto_probe_error=auto_probe_error,
                capture_response_body=req.capture_response_body,
                host_regex=req.host_regex,
                ca_files_present=ca_files_present,
                ca_hint=ca_hint,
                error="mitmdump did not confirm startup within startup_timeout",
                execution_time=round(time.time() - start, 2)
            ).model_dump()

        if req.auto_probe:
            auto_probe_sent = True
            auto_probe_error = send_auto_probe_via_proxy(req.target, req.port, req.auto_probe_timeout)
            time.sleep(0.5)  # Let mitmdump process the request

        time.sleep(req.timeout)

    except FileNotFoundError:
        return HttpCaptureResult(
            success=False,
            target=req.target,
            matched_host=host,
            port=req.port,
            proxy_url=f"http://127.0.0.1:{req.port}",
            usage_instructions=build_usage_instructions(req.port, host),
            startup_confirmed=False,
            auto_probe_sent=auto_probe_sent,
            auto_probe_error=auto_probe_error,
            capture_response_body=req.capture_response_body,
            host_regex=req.host_regex,
            ca_files_present=ca_files_present,
            ca_hint=ca_hint,
            error="Tool 'mitmdump' not installed",
            execution_time=round(time.time() - start, 2)
        ).model_dump()

    except Exception as e:
        if proc is not None:
            mitmdump_rc, process_note = stop_process(proc)
        mitmdump_stderr = read_file_safe(stderr_path, limit=12000)

        try:
            script_path.unlink(missing_ok=True)
            capture_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
        except Exception:
            pass

        return HttpCaptureResult(
            success=False,
            target=req.target,
            matched_host=host,
            port=req.port,
            proxy_url=f"http://127.0.0.1:{req.port}",
            usage_instructions=build_usage_instructions(req.port, host),
            mitmdump_return_code=mitmdump_rc,
            mitmdump_stderr=mitmdump_stderr or None,
            startup_confirmed=startup_confirmed,
            auto_probe_sent=auto_probe_sent,
            auto_probe_error=auto_probe_error,
            capture_response_body=req.capture_response_body,
            host_regex=req.host_regex,
            ca_files_present=ca_files_present,
            ca_hint=ca_hint,
            error=str(e),
            execution_time=round(time.time() - start, 2)
        ).model_dump()

    if proc is not None:
        mitmdump_rc, process_note = stop_process(proc)
        mitmdump_stderr = read_file_safe(stderr_path, limit=12000)

    flows, total, total_requests, total_responses, truncated = parse_capture_file(
        capture_path,
        req.max_results
    )

    error = None
    if process_note:
        error = process_note

    if total == 0 and not error:
        error = (
            "No traffic captured. Traffic must actually be routed through the proxy "
            f"http://127.0.0.1:{req.port}, and HTTPS clients must trust the mitmproxy CA."
        )
        if auto_probe_sent and auto_probe_error:
            error += f" Auto-probe failed: {auto_probe_error}"

    if auto_probe_error and not error:
        error = f"Auto-probe failed: {auto_probe_error}"

    usage = build_usage_instructions(req.port, host)

    try:
        script_path.unlink(missing_ok=True)
        capture_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
    except Exception:
        pass

    return HttpCaptureResult(
        success=(total > 0),
        target=req.target,
        matched_host=host,
        port=req.port,
        proxy_url=f"http://127.0.0.1:{req.port}",
        usage_instructions=usage,
        total_captured=total,
        total_requests=total_requests,
        total_responses=total_responses,
        truncated=truncated,
        flows=flows,
        mitmdump_return_code=mitmdump_rc,
        mitmdump_stderr=mitmdump_stderr or None,
        startup_confirmed=startup_confirmed,
        auto_probe_sent=auto_probe_sent,
        auto_probe_error=auto_probe_error,
        capture_response_body=req.capture_response_body,
        host_regex=req.host_regex,
        ca_files_present=ca_files_present,
        ca_hint=ca_hint,
        error=error,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

HTTP_CAPTURE_TOOL_DEFINITION = {
    "name": "http_capture",
    "description": (
        "Capture HTTP/HTTPS traffic for a target host using a mitmdump proxy. "
        "IMPORTANT: this tool only captures traffic that is explicitly routed through "
        "the proxy. It does not generate traffic by itself."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target host or URL, e.g. 'https://example.com'"
            },
            "port": {
                "type": "integer",
                "description": "Local proxy port",
                "default": 8080
            },
            "timeout": {
                "type": "integer",
                "description": "Capture duration in seconds",
                "default": 120
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum correlated flows returned",
                "default": 200
            },
            "exact_host": {
                "type": "boolean",
                "description": "If true, only exact host matches are captured; if false, subdomains are included",
                "default": True
            },
            "host_regex": {
                "type": "string",
                "description": "Optional regex for host filtering. If set, overrides exact_host/subdomain logic"
            },
            "capture_response_body": {
                "type": "boolean",
                "description": "Capture response body content",
                "default": False
            },
            "max_request_body_bytes": {
                "type": "integer",
                "description": "Maximum captured request body size",
                "default": 10000
            },
            "max_response_body_bytes": {
                "type": "integer",
                "description": "Maximum captured response body size",
                "default": 10000
            },
            "startup_timeout": {
                "type": "integer",
                "description": "Seconds to wait for mitmdump startup confirmation",
                "default": 15
            },
            "auto_probe": {
                "type": "boolean",
                "description": "Send one request through the local proxy to seed capture and validate setup",
                "default": False
            },
            "auto_probe_timeout": {
                "type": "integer",
                "description": "Seconds to wait for auto-probe request",
                "default": 8
            }
        },
        "required": ["target"]
    }
}


# ══════════════════════════════════════════════════════════════
# EXAMPLE
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("HTTP CAPTURE TOOL")

    result = http_capture(
        target="http://scanme.nmap.org",
        timeout=20,
        port=8080,
        max_results=100,
        exact_host=True,
        host_regex=None,
        capture_response_body=True,
        max_request_body_bytes=10000,
        max_response_body_bytes=15000,
        startup_timeout=15,
        auto_probe=True,
        auto_probe_timeout=8,
    )

    print("Success:", result["success"])
    print("Proxy:", result["proxy_url"])
    print("Matched host:", result["matched_host"])
    print("Startup confirmed:", result["startup_confirmed"])
    print("Auto probe sent:", result["auto_probe_sent"])
    print("Auto probe error:", result.get("auto_probe_error"))
    print("CA files present:", result["ca_files_present"])
    print("CA hint:", result.get("ca_hint"))
    print("Captured flows:", result["total_captured"])

    if result.get("error"):
        print("Error:", result["error"])

    print("\nUsage instructions:")
    for line in result["usage_instructions"]:
        print("-", line)

    print("\nSample flows:")
    for f in result["flows"][:10]:
        print(f"\n[Flow {f['flow_id']}]")
        print(f"  {f.get('method')} {f.get('url')}")
        print(f"  Status: {f.get('status')}")

        if f.get("request_headers"):
            print(f"  Request Headers:")
            for k, v in list(f.get("request_headers", {}).items())[:5]:
                print(f"    {k}: {v}")

        if f.get("request_post_data"):
            body = f.get("request_post_data", "")[:200]
            print(f"  Request Body: {body}")

        if f.get("response_headers"):
            print(f"  Response Headers:")
            for k, v in list(f.get("response_headers", {}).items())[:5]:
                print(f"    {k}: {v}")

        if f.get("response_body"):
            body = f.get("response_body", "")[:200]
            print(f"  Response Body: {body}...")
