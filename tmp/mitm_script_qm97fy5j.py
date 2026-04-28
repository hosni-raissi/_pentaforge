
from mitmproxy import http
import json
import time
import re
import threading
import sys

TARGET_DOMAIN = "127.0.0.1"
OUTPUT_FILE = "/home/hosnizap/projects/PentaForge/tmp/capture_kk9_vpsm.jsonl"
EXACT_HOST = True
HOST_REGEX = None
CAPTURE_RESPONSE_BODY = True
MAX_REQUEST_BODY_BYTES = 5000
MAX_RESPONSE_BODY_BYTES = 5000

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
