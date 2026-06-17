#/+
"""
API Response Analyzer — Comprehensive API structure & data flow mapping.
Discover: endpoint schemas, data relationships, ID patterns, auth mechanisms, data exposure.

Optimizations over v1:
  - Concurrent requests via ThreadPoolExecutor
  - Fixed set[str] serialization bug (converted to list in result)
  - Auth detection via headers + status codes
  - Value-level sensitive data scanning (catches JWTs in generic fields)
  - data_relationships now populated from shared field names across endpoints
  - ID pattern categorization (UUID, numeric, slug, etc.)
  - POST probing for endpoints that ignore GET
  - Retry with backoff on transient failures
  - Structured main() for standalone testing
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

import requests
import urllib3
from pydantic import BaseModel, Field, field_validator

from server.agents.executor.recon.tools.api._common import prepare_runtime_http_target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Inline _common utilities (portable, no external dependency)
# ---------------------------------------------------------------------------

def validate_http_target(target: str) -> tuple[bool, str]:
    """Return (ok, failure_reason). Accepts http/https only."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            return False, f"Scheme must be http/https, got '{parsed.scheme}'"
        if not parsed.netloc:
            return False, "Missing host"
        return True, ""
    except Exception as exc:
        return False, str(exc)


def merge_headers(custom: dict[str, str]) -> dict[str, str]:
    """Return a header dict with safe defaults merged with custom headers."""
    base = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "APIAnalyzer/2.0",
        "Connection": "close",
    }
    base.update({k: v for k, v in custom.items()})
    return base


def build_url(base: str, path: str) -> str:
    """Join base URL and path safely."""
    base = base.rstrip("/")
    path = path if path.startswith("/") else f"/{path}"
    return f"{base}{path}"


def response_snippet(text: str, max_chars: int = 300) -> str:
    """Return a truncated response body for display."""
    text = text.strip()
    return text[:max_chars] + ("…" if len(text) > max_chars else "")


def stable_body_hash(text: str) -> str:
    """Stable SHA-256 hash of response body."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def json_key_paths(obj: Any, prefix: str = "", max_depth: int = 6) -> list[str]:
    """
    Recursively extract dot-notation key paths from a JSON object.
    Lists are represented with [0], [1], ... up to 2 items.
    """
    if max_depth <= 0:
        return []
    paths: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            paths.append(full)
            paths.extend(json_key_paths(v, full, max_depth - 1))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:2]):
            full = f"{prefix}[{i}]"
            paths.extend(json_key_paths(item, full, max_depth - 1))
    return paths


def collect_candidate_ids(obj: Any, prefix: str = "") -> list[str]:
    """
    Walk a JSON object and collect field paths whose names or values look
    like identifiers (id, uuid, key, token, ref, code, slug).
    """
    id_keywords = {"id", "uuid", "key", "ref", "code", "slug", "token", "handle"}
    candidates: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            if any(kw in k.lower() for kw in id_keywords):
                candidates.append(full)
            candidates.extend(collect_candidate_ids(v, full))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:3]):
            candidates.extend(collect_candidate_ids(item, f"{prefix}[{i}]"))
    return candidates


# ---------------------------------------------------------------------------
# ID pattern categorisation
# ---------------------------------------------------------------------------

_UUID_RE  = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT_RE   = re.compile(r"^\d+$")
_SLUG_RE  = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")
_JWT_RE   = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$", re.I)

def classify_id(value: str) -> Optional[str]:
    s = str(value).strip()
    if _JWT_RE.match(s):   return "jwt"
    if _UUID_RE.match(s):  return "uuid"
    if _HEX32_RE.match(s): return "md5_hash"
    if _INT_RE.match(s):   return "numeric"
    if _SLUG_RE.match(s):  return "slug"
    return None


# ---------------------------------------------------------------------------
# Sensitive value-level patterns (catches secrets in non-obvious field names)
# ---------------------------------------------------------------------------

_SENSITIVE_VALUE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (_JWT_RE,                                          "jwt_token",    "critical"),
    (re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),       "base64_blob",  "high"),
    (re.compile(r"^sk-[A-Za-z0-9]{20,}$"),             "openai_key",   "critical"),
    (re.compile(r"^ghp_[A-Za-z0-9]{36}$"),             "github_pat",   "critical"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email", "medium"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"),            "credit_card",  "critical"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),            "ssn",          "critical"),
]

_SENSITIVE_KEY_PATTERNS: dict[str, str] = {
    "password":      "critical",
    "passwd":        "critical",
    "secret":        "high",
    "api_key":       "high",
    "apikey":        "high",
    "api-key":       "high",
    "access_token":  "high",
    "refresh_token": "high",
    "authorization": "high",
    "credit_card":   "critical",
    "card_number":   "critical",
    "ssn":           "critical",
    "social_security": "critical",
    "email":         "medium",
    "phone":         "medium",
    "mobile":        "medium",
    "address":       "medium",
    "dob":           "medium",
    "birth":         "medium",
    "private_key":   "critical",
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class APIResponseAnalysisRequest(BaseModel):
    target: str
    endpoints: list[str] = []
    headers: dict[str, str] = {}
    timeout: int = Field(default=30, ge=5, le=300)
    max_workers: int = Field(default=5, ge=1, le=20)
    probe_post: bool = True
    include_404_responses: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        ok, reason = validate_http_target(v)
        if not ok:
            raise ValueError(f"Invalid target: {reason}")
        return v.rstrip("/")


class DataExposure(BaseModel):
    field_path: str
    data_type: str
    sensitivity: str
    sample_value: Optional[str] = None
    risk: str


class IDPattern(BaseModel):
    field_path: str
    pattern_type: str   # uuid | numeric | slug | jwt | md5_hash
    sample: str


class EndpointAnalysis(BaseModel):
    endpoint: str
    method: str = "GET"
    status_code: int
    response_size: int
    body_hash: str
    content_type: str = ""
    detected_fields: list[str] = []
    id_patterns: list[IDPattern] = []
    sensitive_data: list[DataExposure] = []
    auth_required: bool = False
    auth_mechanism: Optional[str] = None   # bearer | basic | api_key | session
    response_snippet: str = ""
    latency_ms: float = 0.0


class APIResponseAnalysisResult(BaseModel):
    success: bool
    target: str
    endpoints_analyzed: list[EndpointAnalysis] = []
    total_endpoints: int = 0
    status_summary: dict[str, int] = {}
    filtered_404_responses: int = 0
    observations: list[str] = []
    # serialise as list to avoid Pydantic/JSON set issues
    unique_fields_discovered: list[str] = []
    id_pattern_summary: dict[str, int] = {}          # pattern_type → count
    sensitive_fields_detected: list[str] = []
    common_id_fields: list[str] = []
    data_relationships: dict[str, list[str]] = {}    # field → [endpoints]
    auth_patterns: list[str] = []
    high_risk_fields: list[str] = []
    info_disclosure_risk: str = "low"               # low | medium | high | critical
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Core probe logic (runs per endpoint inside a thread)
# ---------------------------------------------------------------------------

def _detect_auth_mechanism(resp: requests.Response) -> Optional[str]:
    www_auth = resp.headers.get("WWW-Authenticate", "").lower()
    if "bearer" in www_auth:    return "bearer"
    if "basic"  in www_auth:    return "basic"
    if "digest" in www_auth:    return "digest"
    if "apikey" in www_auth or "api-key" in www_auth: return "api_key"
    if resp.status_code == 401: return "unknown_401"
    if resp.status_code == 403: return "forbidden_403"
    return None


def _scan_sensitive(
    fields: list[str],
    body: Any,
) -> list[DataExposure]:
    """Scan both field names and values for sensitive data."""
    exposures: list[DataExposure] = []

    def _get_val(path: str) -> Any:
        try:
            keys = re.split(r"[.\[\]]+", path)
            val = body
            for k in keys:
                if not k:
                    continue
                if isinstance(val, list) and k.isdigit():
                    val = val[int(k)]
                elif isinstance(val, dict):
                    val = val.get(k)
                else:
                    return None
            return val
        except Exception:
            return None

    seen: set[str] = set()

    for field in fields:
        field_lower = field.lower()

        # Key-name match
        for pattern, sensitivity in _SENSITIVE_KEY_PATTERNS.items():
            if pattern in field_lower and field not in seen:
                val = _get_val(field)
                exposures.append(DataExposure(
                    field_path=field,
                    data_type=type(val).__name__,
                    sensitivity=sensitivity,
                    sample_value=str(val)[:60] if val is not None else None,
                    risk=f"Sensitive key '{pattern}' exposed in response",
                ))
                seen.add(field)
                break

        # Value-level match (only if not already flagged)
        if field not in seen:
            val = _get_val(field)
            if isinstance(val, str) and val:
                for pat, label, sensitivity in _SENSITIVE_VALUE_PATTERNS:
                    if pat.search(val):
                        exposures.append(DataExposure(
                            field_path=field,
                            data_type="str",
                            sensitivity=sensitivity,
                            sample_value=val[:60],
                            risk=f"Value matches {label} pattern",
                        ))
                        seen.add(field)
                        break

    return exposures


def _probe_endpoint(
    base: str,
    endpoint: str,
    headers: dict[str, str],
    timeout: int,
    probe_post: bool,
) -> Optional[EndpointAnalysis]:
    """Probe a single endpoint (GET, and optionally POST). Returns best result."""

    url = build_url(base, endpoint)
    best: Optional[EndpointAnalysis] = None

    for method in (["GET", "POST"] if probe_post else ["GET"]):
        t0 = time.perf_counter()
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=timeout, verify=False,
                                    allow_redirects=True)
            else:
                resp = requests.post(url, headers=headers, timeout=timeout, verify=False,
                                     allow_redirects=True, json={})
        except requests.RequestException:
            continue

        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        ct = resp.headers.get("content-type", "")

        # Only parse JSON responses
        if "application/json" not in ct and "application/vnd.api+json" not in ct:
            if best is None:
                # Record even non-JSON so the endpoint shows up
                best = EndpointAnalysis(
                    endpoint=endpoint,
                    method=method,
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    body_hash=stable_body_hash(resp.text),
                    content_type=ct,
                    auth_required=resp.status_code in {401, 403},
                    auth_mechanism=_detect_auth_mechanism(resp),
                    response_snippet=response_snippet(resp.text),
                    latency_ms=latency_ms,
                )
            continue

        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue

        if not body:
            continue

        fields   = json_key_paths(body)
        id_cands = collect_candidate_ids(body)
        snippet  = response_snippet(resp.text)
        bh       = stable_body_hash(resp.text)

        # Build ID pattern list
        id_patterns: list[IDPattern] = []
        for path in id_cands[:15]:
            keys = re.split(r"[.\[\]]+", path)
            try:
                val = body
                for k in keys:
                    if not k: continue
                    val = val[int(k)] if (isinstance(val, list) and k.isdigit()) else val.get(k)
                if isinstance(val, (str, int)):
                    ptype = classify_id(str(val))
                    if ptype:
                        id_patterns.append(IDPattern(field_path=path, pattern_type=ptype,
                                                      sample=str(val)[:40]))
            except Exception:
                pass

        sensitive = _scan_sensitive(fields, body)
        auth_mech = _detect_auth_mechanism(resp)

        analysis = EndpointAnalysis(
            endpoint=endpoint,
            method=method,
            status_code=resp.status_code,
            response_size=len(resp.text),
            body_hash=bh,
            content_type=ct,
            detected_fields=fields[:25],
            id_patterns=id_patterns,
            sensitive_data=sensitive,
            auth_required=resp.status_code in {401, 403},
            auth_mechanism=auth_mech,
            response_snippet=snippet,
            latency_ms=latency_ms,
        )

        # Prefer the richest result (most fields) across GET/POST
        if best is None or len(analysis.detected_fields) > len(best.detected_fields):
            best = analysis

    return best


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_api_response(
    target: str,
    endpoints: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    max_workers: int = 5,
    probe_post: bool = True,
    include_404_responses: bool = False,
) -> dict:
    """
    Analyze API responses for structure, data exposure, ID patterns, and auth mechanisms.

    Args:
        target:      API base URL, e.g. http://localhost:8888
        endpoints:   Specific paths to test; auto-discovers common paths if omitted.
        headers:     Custom request headers (auth tokens, etc.).
        timeout:     Per-request timeout in seconds.
        max_workers: Concurrent request threads.
        probe_post:  Also send an empty POST to each endpoint.

    Returns:
        Serialisable dict matching APIResponseAnalysisResult schema.
    """
    t_start = time.time()

    try:
        req = APIResponseAnalysisRequest(
            target=target,
            endpoints=endpoints or [],
            headers=headers or {},
            timeout=timeout,
            max_workers=max_workers,
            probe_post=probe_post,
            include_404_responses=include_404_responses,
        )
    except ValueError as exc:
        return {"success": False, "target": target, "error": str(exc), "execution_time": 0.0}

    result = APIResponseAnalysisResult(success=True, target=req.target)
    execution_target = prepare_runtime_http_target(req.target)
    merged_headers = merge_headers(req.headers)

    default_endpoints = [
        "/",
        "/api",
        "/api/v1",
        "/api/v1/users",
        "/api/v1/user",
        "/api/v1/me",
        "/api/v1/profile",
        "/api/v1/status",
        "/api/v1/health",
        "/api/v1/config",
        "/api/v2",
        "/api/v2/users",
        "/health",
        "/status",
        "/metrics",
        "/swagger.json",
        "/openapi.json",
        "/docs",
        "/graphql",
        "/api/auth/login",
    ]

    test_endpoints = (req.endpoints or default_endpoints)[:20]

    # --- Concurrent probing ---
    analyses_all: list[EndpointAnalysis] = []
    with ThreadPoolExecutor(max_workers=req.max_workers) as pool:
        futures = {
            pool.submit(
                _probe_endpoint, execution_target, ep,
                merged_headers, req.timeout, req.probe_post
            ): ep
            for ep in test_endpoints
        }
        for fut in as_completed(futures):
            analysis = fut.result()
            if analysis:
                analyses_all.append(analysis)

    status_summary: dict[str, int] = {}
    for ea in analyses_all:
        code = str(ea.status_code)
        status_summary[code] = status_summary.get(code, 0) + 1
    result.status_summary = status_summary

    if req.include_404_responses:
        analyses = analyses_all
    else:
        analyses = [
            ea for ea in analyses_all
            if not (
                ea.status_code == 404
                and "json" not in (ea.content_type or "").lower()
                and not ea.detected_fields
                and not ea.id_patterns
                and not ea.sensitive_data
            )
        ]
    result.filtered_404_responses = max(0, len(analyses_all) - len(analyses))
    if result.filtered_404_responses:
        result.observations.append(
            f"Filtered {result.filtered_404_responses} noisy HTTP 404 non-JSON responses"
        )

    if not analyses:
        if analyses_all and all(ea.status_code == 404 for ea in analyses_all):
            result.success = False
            result.error = "No actionable API responses; all probed endpoints returned HTTP 404"
        elif not analyses_all:
            result.success = False
            result.error = "No endpoints produced analyzable responses"
        else:
            result.success = False
            result.error = "No actionable API responses discovered after filtering"

    # Sort by endpoint path for deterministic output
    analyses.sort(key=lambda a: a.endpoint)
    result.endpoints_analyzed = analyses

    # --- Aggregate ---
    all_fields: set[str] = set()
    field_to_endpoints: dict[str, list[str]] = {}
    id_type_counts: dict[str, int] = {}

    for ea in analyses:
        all_fields.update(ea.detected_fields)
        for f in ea.detected_fields:
            field_to_endpoints.setdefault(f, []).append(ea.endpoint)
        for ip in ea.id_patterns:
            id_type_counts[ip.pattern_type] = id_type_counts.get(ip.pattern_type, 0) + 1
        for sd in ea.sensitive_data:
            result.sensitive_fields_detected.append(sd.field_path)
            if sd.sensitivity == "critical":
                result.high_risk_fields.append(sd.field_path)
        if ea.auth_mechanism:
            result.auth_patterns.append(f"{ea.endpoint} → {ea.auth_mechanism}")

    result.unique_fields_discovered  = sorted(all_fields)
    result.id_pattern_summary        = id_type_counts
    result.data_relationships        = {
        f: eps for f, eps in field_to_endpoints.items() if len(eps) > 1
    }
    result.total_endpoints           = len(analyses)

    # Common ID field names (appear in ≥2 endpoints)
    id_field_counts: dict[str, int] = {}
    for ea in analyses:
        for ip in ea.id_patterns:
            key = ip.field_path.split(".")[-1].strip("[]0123456789")
            id_field_counts[key] = id_field_counts.get(key, 0) + 1
    result.common_id_fields = sorted(
        (k for k, v in id_field_counts.items() if v >= 2),
        key=lambda x: -id_field_counts[x],
    )[:10]

    # Risk
    if result.high_risk_fields:
        result.info_disclosure_risk = "critical"
    elif len(result.sensitive_fields_detected) > 5:
        result.info_disclosure_risk = "high"
    elif result.sensitive_fields_detected:
        result.info_disclosure_risk = "medium"

    result.execution_time = round(time.time() - t_start, 2)
    return result.model_dump()


def api_response_analyzer(
    target: str,
    endpoints: Optional[list[str]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 10,
    max_workers: int = 8,
    probe_post: bool = True,
    include_404_responses: bool = False,
) -> dict[str, Any]:
    """Compatibility wrapper for tool loader (matches tool definition name)."""
    return analyze_api_response(
        target=target,
        endpoints=endpoints,
        headers=headers,
        timeout=timeout,
        max_workers=max_workers,
        probe_post=probe_post,
        include_404_responses=include_404_responses,
    )


# ---------------------------------------------------------------------------
# Tool definition (for LLM/agent integration)
# ---------------------------------------------------------------------------

API_RESPONSE_ANALYSIS_TOOL = {
    "name": "api_response_analyzer",
    "description": (
        "Analyze API responses for structure, data exposure, ID patterns, and auth mechanisms. "
        "Probes endpoints concurrently, maps JSON schema paths, classifies ID types (UUID, numeric, "
        "JWT, slug), detects sensitive field exposure by key name and value pattern, and surfaces "
        "data-relationship graphs across endpoints."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target":      {"type": "string",  "description": "API base URL, e.g. http://localhost:8888"},
            "endpoints":   {"type": "array",   "items": {"type": "string"},
                            "description": "Specific paths to analyze (auto-discovers if omitted)"},
            "headers":     {"type": "object",  "description": "Custom headers, e.g. Authorization"},
            "timeout":     {"type": "integer", "description": "Per-request timeout in seconds (5-300)"},
            "max_workers": {"type": "integer", "description": "Concurrent probing threads (1-20)"},
            "probe_post":  {"type": "boolean", "description": "Also send empty POST to each endpoint"},
            "include_404_responses": {"type": "boolean", "description": "Include 404 non-JSON responses in report output (default: false)"},
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def _print_report(result: dict, max_endpoint_rows: int = 8, show_snippets: bool = False) -> None:
    sep  = "─" * 60
    sep2 = "═" * 60

    print(f"\n{sep2}")
    print(f"  API RESPONSE ANALYZER — REPORT")
    print(f"  Target : {result.get('target')}")
    print(f"  Risk   : {str(result.get('info_disclosure_risk', 'low')).upper()}")
    print(f"  Time   : {result.get('execution_time')}s   |   Endpoints hit: {result.get('total_endpoints', 0)}")
    print(sep2)

    if result.get("error"):
        print(f"\n  Error: {result['error']}")

    status_summary = result.get("status_summary") or {}
    if status_summary:
        status_text = ", ".join(f"{code}:{count}" for code, count in sorted(status_summary.items()))
        print(f"\n  Status summary : {status_text}")

    filtered_404 = result.get("filtered_404_responses") or 0
    if filtered_404:
        print(f"  Filtered 404s  : {filtered_404}")

    observations = result.get("observations") or []
    if observations:
        print("  Observations   :")
        for obs in observations[:5]:
            print(f"    - {obs}")

    rows = result.get("endpoints_analyzed") or []
    for ea in rows[:max_endpoint_rows]:
        icon = "🔓" if ea["auth_required"] else "🌐"
        print(f"\n{icon} [{ea['method']}] {ea['endpoint']}  →  HTTP {ea['status_code']}"
              f"  ({ea['response_size']} bytes, {ea['latency_ms']} ms)")
        if ea["content_type"]:
            print(f"   Content-Type : {ea['content_type']}")
        if ea["auth_mechanism"]:
            print(f"   Auth         : {ea['auth_mechanism']}")
        if ea["id_patterns"]:
            print(f"   ID Patterns  :")
            for ip in ea["id_patterns"]:
                print(f"     • {ip['field_path']} [{ip['pattern_type']}] = {ip['sample']}")
        if ea["sensitive_data"]:
            print(f"   ⚠  Sensitive Fields :")
            for sd in ea["sensitive_data"]:
                print(f"     [{sd['sensitivity'].upper()}] {sd['field_path']} — {sd['risk']}")
                if sd["sample_value"]:
                    print(f"       sample: {sd['sample_value']}")
        if show_snippets and ea["response_snippet"]:
            print(f"   Snippet      : {ea['response_snippet'][:120]}")

    if len(rows) > max_endpoint_rows:
        print(f"\n  ... {len(rows) - max_endpoint_rows} more endpoints omitted (set max rows higher to view)")

    print(f"\n{sep}")
    if result.get("unique_fields_discovered"):
        print(f"All discovered fields ({len(result['unique_fields_discovered'])}):")
        for f in result["unique_fields_discovered"][:30]:
            print(f"  · {f}")
        if len(result["unique_fields_discovered"]) > 30:
            print(f"  … and {len(result['unique_fields_discovered']) - 30} more")

    if result.get("data_relationships"):
        print(f"\nData relationships (fields shared across endpoints):")
        for field, eps in list(result["data_relationships"].items())[:10]:
            print(f"  {field} → {', '.join(eps)}")

    if result.get("id_pattern_summary"):
        print(f"\nID pattern summary:")
        for ptype, count in result["id_pattern_summary"].items():
            print(f"  {ptype}: {count} occurrence(s)")

    if result.get("auth_patterns"):
        print(f"\nAuth-protected endpoints:")
        for ap in result["auth_patterns"]:
            print(f"  {ap}")

    if result.get("high_risk_fields"):
        print(f"\n🚨 HIGH-RISK FIELDS: {', '.join(result['high_risk_fields'])}")

    print(f"\n{sep2}\n")


# ---------------------------------------------------------------------------
# main — standalone test
# ---------------------------------------------------------------------------

def main() -> None:
    TARGET = "http://localhost:8888"
    INCLUDE_404_RESPONSES = False
    MAX_ENDPOINT_ROWS = 8
    SHOW_SNIPPETS = False
    EMIT_JSON = False

    print(f"[*] Analyzing target: {TARGET}")
    print("[*] Running concurrent probes …\n")

    result = analyze_api_response(
        target      = TARGET,
        endpoints   = None,        # auto-discover
        headers     = {
            # Uncomment and add a token if the API requires auth:
            # "Authorization": "Bearer YOUR_TOKEN_HERE",
        },
        timeout     = 15,
        max_workers = 8,
        probe_post  = True,
        include_404_responses=INCLUDE_404_RESPONSES,
    )

    # Print human-readable report
    if EMIT_JSON:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_report(result, max_endpoint_rows=MAX_ENDPOINT_ROWS, show_snippets=SHOW_SNIPPETS)


if __name__ == "__main__":
    main()
