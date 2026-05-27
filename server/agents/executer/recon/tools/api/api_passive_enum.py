#/+
from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.tools.api._common import extract_host
from server.agents.executer.recon.tools.api._common import is_valid_http_target
from server.agents.executer.recon.tools.api._common import normalize_http_target
from server.agents.executer.recon.tools.api._common import prepare_runtime_http_target
from server.agents.executer.recon.tools.api._common import remap_origin_url


from server.agents.executer.recon.config import is_blocked_host

_COMMON_PASSIVE_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/swagger-ui/index.html",
    "/openapi.json",
    "/openapi.yaml",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/robots.txt",
    "/sitemap.xml",
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

_JS_PATH_PATTERNS = [
    re.compile(r'["\'](/api/[a-zA-Z0-9_\-./{}:?=&]+)["\']'),
    re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-./{}:?=&]+)["\']'),
    re.compile(r'["\'](/graphql[a-zA-Z0-9_\-./{}:?=&]*)["\']'),
    re.compile(r'["\'](https?://[^"\']+/api/[a-zA-Z0-9_\-./{}:?=&]+)["\']'),
]

_SECRET_PATTERNS = [
    re.compile(r"(?i)(?:api_key|apikey|secret|token|password|passwd|pwd|jwt)[\s:=]+[\"']([^\"']{8,})[\"']"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), # JWT
]


class PassiveEnumRequest(BaseModel):
    target: str
    paths: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=15, ge=3, le=120)
    max_pages: int = Field(default=20, ge=5, le=200)
    max_js_files: int = Field(default=8, ge=0, le=100)
    include_js_scan: bool = True

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        cleaned = v.strip()
        host = extract_host(cleaned)

        host_lower = host.lower()
        if is_blocked_host(host_lower):
            raise ValueError(f"Target '{v}' is blocked.")

        if not is_valid_http_target(cleaned):
            raise ValueError(f"Invalid target format: {v}")
        return cleaned


class PassiveEndpoint(BaseModel):
    url: str
    status_code: int
    content_type: str = ""
    source: str = "passive_probe"
    auth_required: bool = False
    confidence: str = "low"
    tags: list[str] = Field(default_factory=list)


class PassiveEnumResult(BaseModel):
    success: bool
    target: str
    total_scanned: int = 0
    total_endpoints: int = 0
    endpoints: list[PassiveEndpoint] = Field(default_factory=list)
    interesting: list[PassiveEndpoint] = Field(default_factory=list)
    api_docs: list[str] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    robots_entries: list[str] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    html_comments: list[str] = Field(default_factory=list)
    js_secrets: list[str] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    cors: dict[str, str] = Field(default_factory=dict)
    llm_brief: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0


def _same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _looks_api_url(url: str) -> bool:
    low = url.lower()
    keys = ["/api", "/v1", "/v2", "graphql", "openapi", "swagger", "admin", "internal"]
    return any(k in low for k in keys)


def _extract_links_and_scripts(html: str, base_url: str) -> tuple[list[str], list[str], list[str]]:
    links: list[str] = []
    scripts: list[str] = []
    comments: list[str] = []

    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, flags=re.IGNORECASE):
        u = urljoin(base_url, m.group(1).strip())
        links.append(u)

    for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, flags=re.IGNORECASE):
        u = urljoin(base_url, m.group(1).strip())
        scripts.append(u)

    for m in re.finditer(r'<!--(.*?)-->', html, flags=re.DOTALL):
        c = m.group(1).strip()
        if c and len(c) > 5 and "DOCTYPE html" not in c:
            comments.append(c[:200])

    return links, scripts, comments


def _extract_js_api_paths(js_text: str, base_url: str) -> list[str]:
    out: set[str] = set()
    for pattern in _JS_PATH_PATTERNS:
        for m in pattern.finditer(js_text):
            raw = m.group(1).strip()
            raw = raw.replace("{", "").replace("}", "")
            if not raw:
                continue
            url = raw if raw.startswith("http") else urljoin(base_url, raw)
            if _looks_api_url(url):
                out.add(url)
    return sorted(out)


def _extract_js_secrets(js_text: str) -> list[str]:
    secrets: set[str] = set()
    for pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(js_text):
            val = m.group(1).strip() if m.groups() else m.group(0).strip()
            if len(val) > 5:
                secrets.add(val)
    return sorted(secrets)


def _parse_openapi_endpoints(text: str, base_url: str) -> list[str]:
    try:
        data = json.loads(text)
    except Exception:
        return []

    paths = data.get("paths")
    if not isinstance(paths, dict):
        return []

    endpoints: list[str] = []
    for p in list(paths.keys())[:300]:
        if not isinstance(p, str):
            continue
        full = p if p.startswith("http") else urljoin(base_url + "/", p.lstrip("/"))
        endpoints.append(full)

    return endpoints


def _parse_robots(text: str) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    sitemaps: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(("allow:", "disallow:")):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                paths.append(parts[1].strip())
        elif line.lower().startswith("sitemap:"):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                sitemaps.append(parts[1].strip())

    return paths, sitemaps


def _parse_sitemap(xml_text: str) -> list[str]:
    out: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out

    for elem in root.iter():
        if elem.tag.lower().endswith("loc") and elem.text:
            out.append(elem.text.strip())
    return out


def _classify_endpoint(url: str, status: int, ctype: str) -> tuple[bool, str, list[str]]:
    tags: list[str] = []
    low = url.lower()

    if "graphql" in low:
        tags.append("graphql")
    if "swagger" in low or "openapi" in low or "docs" in low:
        tags.append("api_docs")
    if "admin" in low:
        tags.append("admin")
    if "internal" in low or "debug" in low:
        tags.append("internal")
    if "/auth" in low or "token" in low or "login" in low:
        tags.append("auth")

    auth_required = status in {401, 403}

    confidence = "low"
    if status in {200, 201, 204}:
        confidence = "high"
    elif status in {301, 302, 307, 308, 401, 403, 405}:
        confidence = "medium"

    interesting = bool(tags) or auth_required or status in {500, 502}
    if "json" in ctype.lower() and status in {200, 401, 403}:
        interesting = True

    return interesting, confidence, tags


def api_passive_enum(
    target: str,
    paths: list[str] = [],
    headers: dict[str, str] = {},
    timeout: int = 15,
    max_pages: int = 20,
    max_js_files: int = 8,
    include_js_scan: bool = True,
) -> dict:
    start = time.time()

    try:
        req = PassiveEnumRequest(
            target=target,
            paths=paths,
            headers=headers,
            timeout=timeout,
            max_pages=max_pages,
            max_js_files=max_js_files,
            include_js_scan=include_js_scan,
        )
    except Exception as exc:
        return PassiveEnumResult(
            success=False,
            target=target,
            error=str(exc),
            execution_time=0.0,
        ).model_dump(exclude_none=True)

    base = normalize_http_target(req.target)
    execution_base = prepare_runtime_http_target(base)
    session = requests.Session()
    merged_headers = {"User-Agent": "PentaForge/PassiveEnum", "Accept": "*/*", **req.headers}

    queue: deque[str] = deque()
    seen: set[str] = set()
    endpoints: dict[str, PassiveEndpoint] = {}
    interesting_keys: set[str] = set()

    robots_entries: set[str] = set()
    sitemap_urls: set[str] = set()
    api_docs: set[str] = set()
    js_files: set[str] = set()
    all_html_comments: set[str] = set()
    js_secrets_found: set[str] = set()

    security_headers: dict[str, str] = {}
    cors: dict[str, str] = {}

    for p in (_COMMON_PASSIVE_PATHS + req.paths):
        u = p if p.startswith("http") else urljoin(base + "/", str(p).lstrip("/"))
        queue.append(u)

    scanned = 0

    while queue and scanned < req.max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        if not _same_origin(base, url):
            continue

        seen.add(url)
        scanned += 1

        try:
            t0 = time.time()
            execution_url = remap_origin_url(url, from_base=base, to_base=execution_base)
            resp = session.get(
                execution_url,
                headers=merged_headers,
                timeout=req.timeout,
                verify=False,
                allow_redirects=True,
            )
            _ = round(time.time() - t0, 3)
        except Exception:
            continue

        status = int(resp.status_code)
        ctype = resp.headers.get("Content-Type", "")
        body = resp.text[:400000] if resp.text else ""

        if not security_headers:
            for h in _SECURITY_HEADERS:
                if h in resp.headers:
                    security_headers[h] = resp.headers.get(h, "")

            cors_keys = [
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
            ]
            for ck in cors_keys:
                if ck in resp.headers:
                    cors[ck] = resp.headers.get(ck, "")

        if status in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}:
            is_interesting, confidence, tags = _classify_endpoint(url, status, ctype)
            ep = PassiveEndpoint(
                url=url,
                status_code=status,
                content_type=ctype,
                source="passive_probe",
                auth_required=status in {401, 403},
                confidence=confidence,
                tags=tags,
            )
            endpoints[url] = ep
            if is_interesting:
                interesting_keys.add(url)

        low_url = url.lower()

        if "robots.txt" in low_url and body:
            robot_paths, sitemaps = _parse_robots(body)
            for rp in robot_paths:
                robots_entries.add(rp)
                queue.append(urljoin(base + "/", rp.lstrip("/")))
            for sm in sitemaps:
                sm_url = sm if sm.startswith("http") else urljoin(base + "/", sm.lstrip("/"))
                sitemap_urls.add(sm_url)
                queue.append(sm_url)

        if ("sitemap" in low_url or "xml" in ctype.lower()) and body:
            for loc in _parse_sitemap(body):
                if _same_origin(base, loc):
                    sitemap_urls.add(loc)
                    queue.append(loc)

        if (
            "openapi" in low_url
            or "swagger" in low_url
            or ("json" in ctype.lower() and '"paths"' in body[:5000])
        ):
            api_docs.add(url)
            for ep_url in _parse_openapi_endpoints(body, base):
                if _same_origin(base, ep_url):
                    queue.append(ep_url)

        if "html" in ctype.lower() and body:
            links, scripts, comments = _extract_links_and_scripts(body, url)
            for link in links:
                if _same_origin(base, link) and (_looks_api_url(link) or len(seen) < req.max_pages // 2):
                    queue.append(link)
                    
            for c in comments:
                all_html_comments.add(c)

            if req.include_js_scan:
                for s in scripts:
                    if _same_origin(base, s):
                        js_files.add(s)

    if req.include_js_scan and js_files:
        for js_url in list(js_files)[: req.max_js_files]:
            try:
                resp = session.get(js_url, headers=merged_headers, timeout=req.timeout, verify=False)
                if resp.status_code != 200:
                    continue
                js_text = resp.text[:400000]
                candidates = _extract_js_api_paths(js_text, base)
                for c in candidates:
                    if not _same_origin(base, c):
                        continue
                     
                    if c not in endpoints:
                        endpoints[c] = PassiveEndpoint(
                            url=c,
                            status_code=0,
                            content_type="",
                            source="js_static_analysis",
                            auth_required=False,
                            confidence="medium",
                            tags=["from_js"],
                        )
                        interesting_keys.add(c)
                        
                secrets = _extract_js_secrets(js_text)
                for s in secrets:
                    js_secrets_found.add(s)
            except Exception:
                continue

    endpoint_list = sorted(endpoints.values(), key=lambda e: (e.status_code == 0, e.url))
    interesting = [endpoints[u] for u in sorted(interesting_keys) if u in endpoints]

    llm_brief: dict[str, Any] = {
        "total_endpoints": len(endpoint_list),
        "interesting_endpoints": [e.url for e in interesting[:10]],
        "api_docs": sorted(api_docs)[:8],
        "robots_entries": sorted(robots_entries)[:12],
        "sitemap_urls": sorted(sitemap_urls)[:12],
        "html_comments": sorted(all_html_comments)[:10],
        "js_secrets": sorted(js_secrets_found)[:10],
    }
    if security_headers:
        llm_brief["security_headers_present"] = list(security_headers.keys())
    if cors:
        llm_brief["cors_headers"] = cors

    result = PassiveEnumResult(
        success=True,
        target=base,
        total_scanned=scanned,
        total_endpoints=len(endpoint_list),
        endpoints=endpoint_list,
        interesting=interesting,
        api_docs=sorted(api_docs),
        js_files=sorted(js_files),
        robots_entries=sorted(robots_entries),
        sitemap_urls=sorted(sitemap_urls),
        html_comments=sorted(all_html_comments),
        js_secrets=sorted(js_secrets_found),
        security_headers=security_headers,
        cors=cors,
        llm_brief=llm_brief,
        execution_time=round(time.time() - start, 2),
    )
    return result.model_dump(exclude_none=True)


API_PASSIVE_ENUM_TOOL_DEFINITION = {
    "name": "api_passive_enum",
    "description": (
        "Strong passive API enumeration without intrusive fuzzing. "
        "Correlates robots.txt, sitemap.xml, OpenAPI/Swagger docs, HTML links, "
        "and JavaScript endpoint references; reports high-signal API surface, "
        "CORS and security-header posture, and compact LLM-ready summary."
    ),
    "parameters": {
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {"type": "string", "description": "Base URL or host."},
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra passive paths to probe (e.g., /v1, /internal/docs).",
            },
            "headers": {
                "type": "object",
                "description": "Optional headers (e.g., Authorization).",
            },
            "timeout": {
                "type": "integer",
                "minimum": 3,
                "maximum": 120,
                "default": 15,
            },
            "max_pages": {
                "type": "integer",
                "minimum": 5,
                "maximum": 200,
                "default": 20,
            },
            "max_js_files": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "default": 8,
            },
            "include_js_scan": {
                "type": "boolean",
                "default": True,
                "description": "If true, parse same-origin JS files for API paths.",
            },
        },
    },
}


if __name__ == "__main__":
    out = api_passive_enum(target="127.0.0.1:5000/api", timeout=10, max_pages=15)
    print(json.dumps(out, indent=2))
