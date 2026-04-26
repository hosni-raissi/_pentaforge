#/+
import subprocess
import json
import re
import time
import hashlib
import os
import shutil
import requests
import concurrent.futures
from typing import Optional, Any
from urllib.parse import urlparse, urlunparse
from pydantic import BaseModel, Field, field_validator
from server.agents.executer.recon.tools.api._common import (
    extract_host,
)
from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class APIDiscoveryRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = []
    wordlist: Optional[str] = None
    headers: dict[str, str] = {}
    compact_output: bool = True

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"kiterunner", "ffuf", "graphql", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        cleaned = v.strip()
        host = extract_host(cleaned)
        if is_blocked_host(host):
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        bare_domain    = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_with_scheme = r"^https?://(\d{1,3}\.){3}\d{1,3}"

        if not (re.match(domain_pattern, cleaned) or
                re.match(bare_domain, cleaned)    or
                re.match(ip_with_scheme, cleaned)):
            raise ValueError(f"Invalid target: {v}")
        return cleaned

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["--output", "-O", "-od"]  # Allow -o for kiterunner output format

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {flag}")
        return v


# ── Single discovered API endpoint ──
class APIEndpoint(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    response_time: Optional[float] = None
    redirect_url: Optional[str] = None
    source: str = "unknown"             # how we found it
    confidence: str = "low"            # low / medium / high / confirmed
    endpoint_type: str = "unknown"     # rest / graphql / soap / websocket /
                                       # swagger / openapi / grpc
    auth_required: bool = False
    parameters: list[str] = []         # detected params
    request_body: Optional[str] = None # sample body if POST
    response_snippet: Optional[str] = None
    issues: list[str] = []             # security issues on this endpoint
    tags: list[str] = []               # api / admin / internal / debug / etc.


# ── Swagger / OpenAPI spec ──
class SwaggerSpec(BaseModel):
    url: str
    version: str = "unknown"           # swagger 2.0 / openapi 3.x
    title: Optional[str] = None
    base_path: Optional[str] = None
    host: Optional[str] = None
    schemes: list[str] = []
    endpoints_defined: list[dict[str, Any]] = []   # {path, method, summary}
    security_schemes: list[str] = []
    auth_types: list[str] = []
    raw_snippet: Optional[str] = None
    issues: list[str] = []


# ── GraphQL introspection result ──
class GraphQLInfo(BaseModel):
    endpoint_url: str
    introspection_enabled: bool = False
    query_count: int = 0
    mutation_count: int = 0
    subscription_count: int = 0
    types: list[str] = []
    queries: list[dict[str, Any]] = []      # {name, args, type}
    mutations: list[dict[str, Any]] = []
    subscriptions: list[dict[str, Any]] = []
    sensitive_fields: list[str] = []        # password, token, secret, etc.
    debug_enabled: bool = False
    batch_enabled: bool = False
    introspection_issues: list[str] = []


# ── Final result ──
class APIDiscoveryResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_endpoints: int = 0
    total_unique: int = 0
    endpoints: list[APIEndpoint] = []
    swagger_specs: list[SwaggerSpec] = []
    graphql_info: list[GraphQLInfo] = []
    interesting: list[APIEndpoint] = []     # admin / debug / sensitive
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = []
    llm_brief: dict[str, Any] = Field(default_factory=dict)


# ══════════════════════════════════════════════════════════════
# 2. API WORDLISTS
# ══════════════════════════════════════════════════════════════

# Common API paths to probe
API_PATHS: list[str] = [

    # ── Swagger / OpenAPI / Docs ──
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/swagger/index.html",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/docs",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/docs/",
    "/docs/api",
    "/documentation",
    "/api/documentation",
    "/redoc",
    "/redoc.html",
    "/scalar",

    # ── REST API roots ──
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/v4",
    "/api/v5",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rest/api",
    "/rest/v1",
    "/rest/v2",
    "/restapi",
    "/service",
    "/services",
    "/webapi",
    "/web-api",
    "/backend",
    "/backend/api",

    # ── GraphQL ──
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/graphiql/",
    "/api/graphql",
    "/api/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/playground",
    "/altair",
    "/voyager",
    "/graphql/console",
    "/graphql/playground",
    "/subscriptions",

    # ── SOAP / WSDL ──
    "/wsdl",
    "/service.wsdl",
    "/api/wsdl",
    "/soap",
    "/soap/v1",
    "/?wsdl",
    "/?WSDL",
    "/ws",
    "/webservice",
    "/webservices",
    "/xmlrpc",
    "/xmlrpc.php",
    "/rpc",
    "/rpc/v1",

    # ── gRPC ──
    "/grpc",
    "/grpc.health.v1.Health/Check",
    "/grpc-web",

    # ── Authentication / Auth ──
    "/api/auth",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/register",
    "/api/auth/refresh",
    "/api/auth/token",
    "/api/auth/callback",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/signup",
    "/api/token",
    "/api/tokens",
    "/api/refresh",
    "/api/oauth",
    "/api/oauth2",
    "/oauth",
    "/oauth2",
    "/oauth/token",
    "/oauth2/token",
    "/auth",
    "/auth/login",
    "/auth/logout",
    "/auth/token",
    "/auth/refresh",
    "/login",
    "/logout",
    "/token",
    "/sso",
    "/saml",
    "/saml/metadata",
    "/saml/acs",

    # ── Admin / Management ──
    "/api/admin",
    "/api/admin/users",
    "/api/admin/config",
    "/api/admin/settings",
    "/api/admin/dashboard",
    "/api/management",
    "/api/manage",
    "/admin",
    "/admin/api",
    "/admin/console",
    "/management",
    "/manage",
    "/manager",
    "/control",
    "/cp",
    "/panel",
    "/dashboard",

    # ── User / Account ──
    "/api/user",
    "/api/users",
    "/api/user/profile",
    "/api/user/me",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    "/api/whoami",
    "/api/current-user",

    # ── Internal / Debug ──
    "/api/internal",
    "/api/debug",
    "/api/test",
    "/api/status",
    "/api/health",
    "/api/healthz",
    "/api/health/check",
    "/api/ready",
    "/api/readyz",
    "/api/live",
    "/api/livez",
    "/api/ping",
    "/api/info",
    "/api/version",
    "/api/config",
    "/api/settings",
    "/api/env",
    "/api/metrics",
    "/health",
    "/healthz",
    "/health/check",
    "/ready",
    "/readyz",
    "/status",
    "/ping",
    "/version",
    "/info",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/info",
    "/actuator/configprops",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/debug",
    "/debug/pprof",
    "/debug/vars",
    "/env",
    "/config",
    "/console",
    "/monitor",

    # ── Data / Search ──
    "/api/search",
    "/api/query",
    "/api/data",
    "/api/export",
    "/api/import",
    "/api/upload",
    "/api/download",
    "/api/files",
    "/api/file",
    "/api/report",
    "/api/reports",
    "/api/analytics",
    "/api/stats",
    "/api/statistics",
    "/api/logs",
    "/api/log",
    "/api/events",
    "/api/feed",
    "/api/feeds",
    "/api/list",
    "/api/all",

    # ── Webhooks / Callbacks ──
    "/api/webhook",
    "/api/webhooks",
    "/api/callback",
    "/api/callbacks",
    "/api/notify",
    "/webhook",
    "/webhooks",
    "/callback",

    # ── Payment / Commerce ──
    "/api/payment",
    "/api/payments",
    "/api/checkout",
    "/api/order",
    "/api/orders",
    "/api/invoice",
    "/api/billing",
    "/api/subscription",
    "/api/subscriptions",
    "/api/cart",

    # ── Cloud / DevOps ──
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/api/k8s",
    "/api/kubernetes",
    "/api/docker",
    "/api/deploy",
    "/api/deployments",

    # ── Legacy / Backup ──
    "/api_v1",
    "/api_v2",
    "/api1",
    "/api2",
    "/apiv1",
    "/apiv2",
    "/old/api",
    "/legacy/api",
    "/v1/api",
    "/v2/api",

    # ── Framework specific ──
    "/rails/info",
    "/rails/info/routes",
    "/rails/mailers",
    "/__debug__",
    "/_debugbar",
    "/telescope",
    "/telescope/api",
    "/horizon",
    "/horizon/api",
    "/_profiler",
    "/_wdt",
    "/api/explorer",
]

# Sensitive keywords to flag in endpoints
SENSITIVE_TAGS: dict[str, list[str]] = {
    "admin":    ["admin", "management", "manage", "manager", "control", "panel", "cp"],
    "debug":    ["debug", "test", "internal", "profiler", "devtools", "pprof", "vars"],
    "auth":     ["auth", "login", "token", "oauth", "sso", "saml", "credential"],
    "data":     ["export", "dump", "backup", "download", "report", "log", "metrics"],
    "config":   ["config", "settings", "env", "environment", "configprops"],
    "graphql":  ["graphql", "graphiql", "playground", "voyager", "altair", "query"],
    "swagger":  ["swagger", "openapi", "api-docs", "redoc", "scalar", "documentation"],
    "actuator": ["actuator", "heapdump", "threaddump", "beans", "mappings"],
    "payment":  ["payment", "checkout", "billing", "invoice", "order", "cart"],
    "user":     ["user", "users", "account", "profile", "me", "whoami"],
}

# HTTP methods to test per endpoint type
METHODS_TO_TRY: dict[str, list[str]] = {
    "default":  ["GET", "POST"],
    "rest":     ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "graphql":  ["GET", "POST"],
    "soap":     ["POST"],
    "swagger":  ["GET"],
    "actuator": ["GET"],
}

# Status codes that indicate something interesting
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308,
                     400, 401, 403, 405, 422, 500, 501, 503}


def _extract_kiterunner_wordlist(args: list[str]) -> Optional[str]:
    """Extract kiterunner wordlist path from args if provided."""
    for i, arg in enumerate(args):
        if arg in ("-w", "--wordlist") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--wordlist="):
            return arg.split("=", 1)[1]
    return None


def _replace_kiterunner_wordlist(args: list[str], resolved_path: str) -> list[str]:
    """Replace wordlist argument in kiterunner args with a resolved path."""
    updated = list(args)
    for i, arg in enumerate(updated):
        if arg in ("-w", "--wordlist") and i + 1 < len(updated):
            updated[i + 1] = resolved_path
            return updated
        if arg.startswith("--wordlist="):
            updated[i] = f"--wordlist={resolved_path}"
            return updated
    return updated


def _resolve_kiterunner_wordlist(wordlist: str) -> Optional[str]:
    """
    Resolve a kiterunner wordlist path from common locations.
    Returns an absolute/usable path if found, else None.
    """
    if not wordlist:
        return None

    candidates: list[str] = []
    basename = os.path.basename(wordlist)

    if os.path.isabs(wordlist):
        candidates.append(wordlist)
    else:
        module_dir = os.path.dirname(__file__)
        repo_root = os.path.abspath(
            os.path.join(module_dir, "..", "..", "..", "..", "..", "..")
        )
        candidates.extend([
            wordlist,
            os.path.join(os.getcwd(), wordlist),
            os.path.join(repo_root, wordlist),
            os.path.join(repo_root, "server", "share", "seclists", wordlist),
        ])

        common_dirs = [
            "/usr/share/kiterunner/wordlists",
            "/usr/local/share/kiterunner/wordlists",
            "/opt/kiterunner/wordlists",
            "/usr/share/seclists/Discovery/Web-Content/kiterunner",
        ]
        for cdir in common_dirs:
            candidates.append(os.path.join(cdir, wordlist))
            candidates.append(os.path.join(cdir, basename))

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _build_probe_url(base_url: str, path: str) -> str:
    """
    Join a target base URL with a candidate path without accidentally creating
    duplicate prefixes like `/api/api/...` when the target already includes `/api`.
    """
    parsed = urlparse(base_url.rstrip("/"))
    base_path = parsed.path.rstrip("/")
    normalized_path = "/" + path.lstrip("/")

    if base_path and (
        normalized_path == base_path
        or normalized_path.startswith(base_path + "/")
    ):
        final_path = normalized_path
    else:
        final_path = f"{base_path}{normalized_path}" if base_path else normalized_path

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            final_path,
            "",
            "",
            "",
        )
    )


def _response_fingerprint(
    *,
    status_code: int,
    content_type: str,
    body: str,
    content: bytes,
) -> dict[str, Any]:
    normalized_body = re.sub(r"\s+", " ", (body or "").lower())
    normalized_body = re.sub(r"[0-9a-f]{8,}", "<hex>", normalized_body)
    normalized_body = re.sub(r"\d+", "0", normalized_body)
    return {
        "status_code": status_code,
        "content_type": (content_type or "").split(";", 1)[0].strip().lower(),
        "content_length": len(content or b""),
        "body_hash": hashlib.sha256(content or b"").hexdigest() if content else "",
        "looks_like_html": "<html" in (body or "").lower(),
        "body_signature": normalized_body[:220],
    }


def _is_probable_fallback_match(
    candidate: dict[str, Any],
    baseline: Optional[dict[str, Any]],
) -> bool:
    if not baseline:
        return False
    if candidate.get("status_code") != baseline.get("status_code"):
        return False
    if candidate.get("content_type") != baseline.get("content_type"):
        return False

    # Exact match: strong fallback indicator.
    if (
        candidate.get("content_length") == baseline.get("content_length")
        and candidate.get("body_hash") == baseline.get("body_hash")
    ):
        return bool(candidate.get("looks_like_html"))

    # Soft match for dynamic SPAs (nonce/hash changes but same shell body).
    c_len = int(candidate.get("content_length") or 0)
    b_len = int(baseline.get("content_length") or 0)
    if abs(c_len - b_len) > 48:
        return False

    if candidate.get("body_signature") != baseline.get("body_signature"):
        return False

    return bool(candidate.get("looks_like_html"))


def _suppress_generic_html_shell(
    endpoints: list[APIEndpoint],
) -> tuple[list[APIEndpoint], int]:
    """
    Suppress repeated HTML-shell responses (soft-404/catch-all SPA behavior)
    that can inflate endpoint discovery results.
    """
    html_candidates: list[APIEndpoint] = []
    for ep in endpoints:
        if (
            ep.status_code == 200
            and (ep.content_type or "").lower().startswith("text/html")
            and ep.method == "GET"
        ):
            html_candidates.append(ep)

    if len(html_candidates) < 12:
        return endpoints, 0

    sig_counts: dict[str, int] = {}
    ep_sig: dict[str, str] = {}
    for ep in html_candidates:
        snippet = (ep.response_snippet or "").lower()
        norm = re.sub(r"\s+", " ", snippet)
        norm = re.sub(r"\d+", "0", norm)
        sig = f"{ep.content_length}:{norm[:180]}"
        key = f"{ep.method}:{ep.url}"
        ep_sig[key] = sig
        sig_counts[sig] = sig_counts.get(sig, 0) + 1

    dominant = max(sig_counts.values()) if sig_counts else 0
    if dominant < 10:
        return endpoints, 0

    kept: list[APIEndpoint] = []
    suppressed = 0
    for ep in endpoints:
        key = f"{ep.method}:{ep.url}"
        sig = ep_sig.get(key)
        is_shell = bool(sig and sig_counts.get(sig, 0) >= dominant)

        if is_shell and not ep.auth_required and not ep.issues:
            suppressed += 1
            continue
        kept.append(ep)

    return kept, suppressed


def _build_llm_brief(
    *,
    endpoints: list[APIEndpoint],
    interesting: list[APIEndpoint],
    graphql_infos: list[GraphQLInfo],
    swagger_specs: list[SwaggerSpec],
    suppressed_html_shell_count: int,
) -> dict[str, Any]:
    def _compact(ep: APIEndpoint) -> dict[str, Any]:
        signal = "candidate"
        if ep.status_code in (401, 403):
            signal = "protected_endpoint_exists"
        elif ep.status_code == 405:
            signal = "endpoint_exists_method_gated"
        elif ep.issues:
            signal = "security_finding"

        return {
            "url": ep.url,
            "method": ep.method,
            "status": ep.status_code,
            "type": ep.endpoint_type,
            "auth_required": ep.auth_required,
            "tags": ep.tags[:5],
            "issues": ep.issues[:3],
            "source": ep.source,
            "confidence": ep.confidence,
            "signal": signal,
        }

    high_signal: list[APIEndpoint] = []
    for ep in interesting:
        is_method_gated_signal = (
            ep.status_code == 405
            and any(
                t in ep.tags
                for t in ("auth", "admin", "graphql", "swagger", "actuator", "config", "debug")
            )
        )
        if ep.issues or ep.auth_required or ep.status_code in (401, 403, 500) or is_method_gated_signal:
            high_signal.append(ep)

    if not high_signal:
        for ep in endpoints:
            if ep.status_code in (401, 403, 500):
                high_signal.append(ep)
            elif ep.status_code == 405 and any(
                t in ep.tags
                for t in ("auth", "admin", "graphql", "swagger", "actuator", "config", "debug")
            ):
                high_signal.append(ep)

    gql_targets = [
        {
            "endpoint_url": g.endpoint_url,
            "introspection_enabled": g.introspection_enabled,
            "sensitive_fields": g.sensitive_fields[:5],
            "issues": g.introspection_issues[:3],
        }
        for g in graphql_infos[:15]
    ]

    swagger_targets = [
        {
            "url": s.url,
            "version": s.version,
            "security_schemes": s.security_schemes[:5],
            "auth_types": s.auth_types[:5],
            "issues": s.issues[:3],
            "path_count": len(s.endpoints_defined),
        }
        for s in swagger_specs[:15]
    ]

    return {
        "attack_surface_count": len(endpoints),
        "high_signal_count": len(high_signal),
        "suppressed_html_shell_count": suppressed_html_shell_count,
        "next_targets": [_compact(ep) for ep in high_signal[:12]],
        "graphql_targets": gql_targets,
        "swagger_targets": swagger_targets,
    }


def _prioritize_for_pentest(
    endpoints: list[APIEndpoint],
    limit: int,
) -> list[APIEndpoint]:
    def _score(ep: APIEndpoint) -> int:
        score = 0
        if ep.auth_required:
            score += 50
        if ep.status_code in (401, 403):
            score += 40
        if ep.status_code == 405 and any(
            t in ep.tags for t in ("auth", "admin", "graphql", "swagger", "actuator", "config", "debug")
        ):
            score += 28
        if ep.status_code and ep.status_code >= 500:
            score += 35
        if ep.endpoint_type in ("graphql", "swagger", "actuator"):
            score += 20
        score += min(len(ep.issues), 3) * 15
        if "admin" in ep.tags:
            score += 15
        if "config" in ep.tags:
            score += 12
        if "debug" in ep.tags:
            score += 10
        return score

    def _family(ep: APIEndpoint) -> str:
        if ep.issues:
            return ep.issues[0]
        tags = ",".join(sorted(ep.tags[:3]))
        return f"{ep.endpoint_type}:{tags}:{ep.status_code}"

    ranked = sorted(endpoints, key=_score, reverse=True)
    selected: list[APIEndpoint] = []
    used_families: set[str] = set()

    for ep in ranked:
        fam = _family(ep)
        if fam in used_families:
            continue
        used_families.add(fam)
        selected.append(ep)
        if len(selected) >= limit:
            return selected

    for ep in ranked:
        if ep not in selected:
            selected.append(ep)
        if len(selected) >= limit:
            break
    return selected


def _is_generic_html_shell(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if "html" not in ct:
        return False

    b = (body or "").lower()
    if "<html" not in b:
        return False

    shell_markers = [
        "<!doctype html",
        "<meta charset=",
        "<meta name=\"viewport\"",
        "<meta name=\"theme-color\"",
    ]
    app_root_markers = [
        "id=\"root\"",
        "id='root'",
        "id=\"app\"",
        "id='app'",
    ]
    return (
        sum(1 for m in shell_markers if m in b) >= 2
        and any(m in b for m in app_root_markers)
    )


def _probe_fallback_signature(
    target: str,
    headers: dict[str, str],
    timeout: int,
) -> Optional[dict[str, Any]]:
    """
    Fetch one clearly-nonexistent path. If the app returns a generic SPA shell
    or catch-all page with HTTP 200, we use it as a baseline to suppress false
    positives from path wordlists.
    """
    probe_url = _build_probe_url(
        target,
        f"/__pentaforge_nonexistent__{int(time.time() * 1000)}__",
    )
    try:
        resp = requests.get(
            probe_url,
            headers={**{"User-Agent": "APIDiscovery/1.0"}, **headers},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except Exception:
        return None

    body = resp.text[:3000]
    fingerprint = _response_fingerprint(
        status_code=resp.status_code,
        content_type=resp.headers.get("content-type", ""),
        body=body,
        content=resp.content,
    )
    if resp.status_code == 200 and fingerprint["looks_like_html"]:
        return fingerprint
    return None


# ══════════════════════════════════════════════════════════════
# 3. SWAGGER / OPENAPI PARSER
# ══════════════════════════════════════════════════════════════

def parse_swagger_spec(url: str, content: str) -> SwaggerSpec:
    """
    Parse a Swagger 2.0 or OpenAPI 3.x spec.
    Extract: title, paths, methods, security schemes, auth types.
    Flag security issues.
    """
    spec = SwaggerSpec(url=url)

    try:
        # Try JSON first, then YAML
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                data = yaml.safe_load(content)
            except Exception:
                data = {}

        if not isinstance(data, dict):
            return spec

        # ── Version detection ──
        if "openapi" in data:
            spec.version = data["openapi"]
        elif "swagger" in data:
            spec.version = data["swagger"]

        # ── Info ──
        info = data.get("info", {})
        spec.title = info.get("title")

        # ── Host / Base (Swagger 2.0) ──
        spec.host      = data.get("host")
        spec.base_path = data.get("basePath", "/")
        spec.schemes   = data.get("schemes", [])

        # ── Servers (OpenAPI 3.x) ──
        servers = data.get("servers", [])
        if servers and not spec.host:
            first = servers[0].get("url", "")
            spec.host = re.sub(r"https?://", "", first).split("/")[0]

        # ── Paths / Endpoints ──
        paths = data.get("paths", {})
        for path, path_data in paths.items():
            if not isinstance(path_data, dict):
                continue
            for method, op in path_data.items():
                if method.lower() in ("get", "post", "put", "patch",
                                      "delete", "options", "head"):
                    if isinstance(op, dict):
                        spec.endpoints_defined.append({
                            "path":        path,
                            "method":      method.upper(),
                            "summary":     op.get("summary", ""),
                            "operationId": op.get("operationId", ""),
                            "tags":        op.get("tags", []),
                            "parameters":  [
                                p.get("name") for p in op.get("parameters", [])
                                if isinstance(p, dict)
                            ],
                            "security":    op.get("security", []),
                            "deprecated":  op.get("deprecated", False),
                        })

        # ── Security Schemes ──
        # OpenAPI 3.x
        components = data.get("components", {})
        sec_schemes = components.get("securitySchemes", {})
        # Swagger 2.0
        sec_defs = data.get("securityDefinitions", {})
        all_schemes = {**sec_schemes, **sec_defs}

        for name, scheme in all_schemes.items():
            if isinstance(scheme, dict):
                spec.security_schemes.append(name)
                stype = scheme.get("type", "").lower()
                if stype == "apikey":
                    spec.auth_types.append("API Key")
                elif stype in ("oauth2", "oauth"):
                    spec.auth_types.append("OAuth2")
                elif stype == "http":
                    sscheme = scheme.get("scheme", "").lower()
                    spec.auth_types.append(f"HTTP {sscheme}")
                elif stype == "openidconnect":
                    spec.auth_types.append("OpenID Connect")

        # ── Security Issues ──
        if not spec.security_schemes:
            spec.issues.append(
                "No security schemes defined in spec — API may be unauthenticated"
            )

        # Check for endpoints without security
        unprotected = [
            e for e in spec.endpoints_defined
            if not e.get("security") and not data.get("security")
        ]
        if unprotected:
            spec.issues.append(
                f"{len(unprotected)} endpoints have no security requirement defined"
            )

        # HTTP scheme (non-HTTPS)
        if "http" in spec.schemes and "https" not in spec.schemes:
            spec.issues.append("Spec defines HTTP-only scheme — no TLS")

        # Deprecated endpoints still live
        deprecated = [e for e in spec.endpoints_defined if e.get("deprecated")]
        if deprecated:
            spec.issues.append(
                f"{len(deprecated)} deprecated endpoints still defined in spec"
            )

        # Raw snippet for agent context
        spec.raw_snippet = content[:1000]

    except Exception as e:
        spec.issues.append(f"Spec parse error: {e}")

    return spec


# ══════════════════════════════════════════════════════════════
# 4. GRAPHQL ANALYZER
# ══════════════════════════════════════════════════════════════

GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

GRAPHQL_SIMPLE_QUERY = "{ __typename }"

GRAPHQL_DEBUG_QUERIES = [
    "{ __schema { types { name } } }",
    '{ users { id email password } }',
    '{ user(id: 1) { id email role } }',
    '{ me { id email token } }',
]

SENSITIVE_GQL_FIELDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "auth", "credential", "private", "ssn", "credit_card", "cvv",
    "pin", "otp", "key", "hash", "salt", "seed", "private_key",
]


def probe_graphql(url: str, headers: dict[str, str] = {},
                  timeout: int = 10) -> Optional[GraphQLInfo]:
    """
    Full GraphQL endpoint analysis:
    1. Test if introspection is enabled
    2. Parse schema: queries, mutations, subscriptions, types
    3. Flag sensitive fields
    4. Test batch queries
    5. Detect debug/playground
    """
    info = GraphQLInfo(endpoint_url=url)

    req_headers = {
        "Content-Type":  "application/json",
        "User-Agent":    "APIDiscovery/1.0",
        "Accept":        "application/json",
        **headers,
    }

    # ── Step 1: Basic probe ──
    try:
        resp = requests.post(
            url,
            json={"query": GRAPHQL_SIMPLE_QUERY},
            headers=req_headers,
            timeout=timeout,
            verify=False,
        )
        if resp.status_code not in (200, 400):
            return None

        ct = resp.headers.get("content-type", "")
        if "json" not in ct and resp.status_code != 200:
            return None

    except Exception:
        return None

    # ── Step 2: Full introspection ──
    try:
        resp = requests.post(
            url,
            json={"query": GRAPHQL_INTROSPECTION_QUERY},
            headers=req_headers,
            timeout=timeout,
            verify=False,
        )

        if resp.status_code == 200:
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})

            if schema:
                info.introspection_enabled = True

                # Query / Mutation / Subscription root types
                qt = schema.get("queryType", {})
                mt = schema.get("mutationType", {})
                st = schema.get("subscriptionType", {})

                qt_name = qt.get("name") if qt else None
                mt_name = mt.get("name") if mt else None
                st_name = st.get("name") if st else None

                # Parse all types
                for type_def in schema.get("types", []):
                    type_name = type_def.get("name", "")
                    type_kind = type_def.get("kind", "")

                    # Skip built-in introspection types
                    if type_name.startswith("__"):
                        continue

                    info.types.append(type_name)
                    fields = type_def.get("fields") or []

                    # Classify as query / mutation / subscription
                    if type_name == qt_name:
                        for field in fields:
                            fname = field.get("name", "")
                            fargs = [
                                a.get("name") for a in field.get("args", [])
                            ]
                            ftype = (field.get("type") or {}).get("name")
                            info.queries.append({
                                "name": fname,
                                "args": fargs,
                                "type": ftype,
                            })
                    elif type_name == mt_name:
                        for field in fields:
                            fname = field.get("name", "")
                            fargs = [
                                a.get("name") for a in field.get("args", [])
                            ]
                            info.mutations.append({
                                "name": fname,
                                "args": fargs,
                            })
                    elif type_name == st_name:
                        for field in fields:
                            info.subscriptions.append({
                                "name": field.get("name", ""),
                            })

                    # Detect sensitive fields in any type
                    for field in fields:
                        fname_lower = field.get("name", "").lower()
                        for sf in SENSITIVE_GQL_FIELDS:
                            if sf in fname_lower:
                                if fname_lower not in info.sensitive_fields:
                                    info.sensitive_fields.append(
                                        f"{type_name}.{field.get('name')}"
                                    )

                info.query_count        = len(info.queries)
                info.mutation_count     = len(info.mutations)
                info.subscription_count = len(info.subscriptions)

                if info.introspection_enabled:
                    info.introspection_issues.append(
                        "GraphQL introspection is ENABLED — "
                        "full schema is publicly accessible"
                    )

                if info.sensitive_fields:
                    info.introspection_issues.append(
                        f"Sensitive fields exposed in schema: "
                        f"{', '.join(info.sensitive_fields[:5])}"
                    )

            elif "errors" in data:
                # Introspection disabled but endpoint exists
                info.introspection_enabled = False
                info.introspection_issues.append(
                    "Introspection disabled — endpoint exists but schema hidden"
                )

    except Exception:
        pass

    # ── Step 3: Batch query test ──
    try:
        batch_payload = [
            {"query": GRAPHQL_SIMPLE_QUERY},
            {"query": GRAPHQL_SIMPLE_QUERY},
        ]
        resp = requests.post(
            url,
            json=batch_payload,
            headers=req_headers,
            timeout=timeout,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                info.batch_enabled = True
                info.introspection_issues.append(
                    "GraphQL batch queries enabled — "
                    "can amplify brute-force / DoS attacks"
                )
    except Exception:
        pass

    # ── Step 4: Debug playground detection ──
    for scheme in ("https", "http"):
        base = re.sub(r"^https?://", f"{scheme}://", url)
        parsed_base = urlparse(base)
        base_path = parsed_base.path.rstrip("/")
        for suffix in ("/graphql", "/query"):
            if base_path.endswith(suffix):
                base_path = base_path[: -len(suffix)]
        base_path = base_path.rstrip("/")

        for path in ["/graphiql", "/playground", "/altair", "/voyager"]:
            try:
                test_path = f"{base_path}{path}" if base_path else path
                test_url = urlunparse(
                    (
                        parsed_base.scheme,
                        parsed_base.netloc,
                        test_path,
                        "",
                        "",
                        "",
                    )
                )
                resp = requests.get(
                    test_url,
                    timeout=5,
                    verify=False,
                    headers={"User-Agent": "APIDiscovery/1.0"},
                )
                if resp.status_code == 200 and any(
                    kw in resp.text.lower()
                    for kw in ["graphiql", "playground", "voyager", "altair"]
                ):
                    info.debug_enabled = True
                    info.introspection_issues.append(
                        f"GraphQL debug UI accessible at {test_url}"
                    )
                    break
            except Exception:
                pass

    return info


# ══════════════════════════════════════════════════════════════
# 5. ENDPOINT CLASSIFIER
# ══════════════════════════════════════════════════════════════

def classify_endpoint(url: str, status: int,
                       headers: dict[str, str],
                       body: str) -> tuple[str, list[str], list[str]]:
    """
    Classify endpoint type and assign tags + issues.
    Returns (endpoint_type, tags, issues).
    """
    url_lower    = url.lower()
    body_lower   = body.lower() if body else ""
    ct           = headers.get("content-type", "").lower()
    issues: list[str] = []
    tags:   list[str] = []
    is_shell_html = _is_generic_html_shell(ct, body_lower)

    # ── Type detection ──
    etype = "rest"

    if any(kw in url_lower for kw in ["graphql", "graphiql", "playground"]):
        etype = "graphql"
    elif any(kw in url_lower for kw in ["swagger", "openapi", "api-docs", "redoc"]):
        etype = "swagger"
    elif any(kw in url_lower for kw in ["wsdl", "soap", "xmlrpc"]):
        etype = "soap"
    elif any(kw in url_lower for kw in ["grpc", "grpc-web"]):
        etype = "grpc"
    elif "websocket" in ct or "upgrade" in headers.get("connection", "").lower():
        etype = "websocket"
    elif any(kw in body_lower for kw in ['"swagger"', '"openapi"',
                                          "swagger:", "openapi:"]):
        etype = "swagger"
    elif any(kw in body_lower for kw in ["__schema", "__typename",
                                          "graphql", "introspection"]):
        etype = "graphql"
    elif any(kw in body_lower for kw in ["<wsdl:", "<?xml", "<soap:"]):
        etype = "soap"

    # ── Tag assignment ──
    for tag_name, keywords in SENSITIVE_TAGS.items():
        if any(kw in url_lower for kw in keywords):
            if tag_name not in tags:
                tags.append(tag_name)

    # JSON response
    if "json" in ct:
        tags.append("json_api")

    # ── Security issues ──

    # Auth check
    if status in (200, 201, 204):
        if (
            any(t in tags for t in ("admin", "debug", "config", "data", "actuator"))
            and not is_shell_html
        ):
            issues.append(
                f"Sensitive endpoint ({','.join(tags)}) "
                f"accessible without authentication (HTTP {status})"
            )

    # Error verbose
    if status == 500:
        if any(kw in body_lower for kw in [
            "traceback", "exception", "stack trace",
            "error at line", "undefined method",
            "syntax error", "at 0x", "debug",
        ]):
            issues.append("500 response contains stack trace / debug info")

    # Info disclosure in headers
    server_hdr = headers.get("server", "")
    if server_hdr and any(v in server_hdr.lower() for v in [
        "apache/", "nginx/", "iis/", "express", "php/",
        "tomcat/", "jetty/", "gunicorn/",
    ]):
        issues.append(f"Server header reveals version: {server_hdr}")

    powered = headers.get("x-powered-by", "")
    if powered:
        issues.append(f"X-Powered-By reveals tech stack: {powered}")

    # Sensitive data in response
    sensitive_patterns = [
        (r"(api[_\-]?key|apikey)\s*[=:]\s*[\w\-]{10,}", "API key in response"),
        (r"(password|passwd)\s*[=:]\s*\S+", "Password in response"),
        (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "Email address in response"),
        (r"(secret|token)\s*[=:]\s*[\w\-]{10,}", "Secret/token in response"),
        (r"(aws_access_key|AKIA[0-9A-Z]{16})", "AWS credentials in response"),
        (r"Bearer\s+[\w\-\.]+", "Bearer token in response"),
    ]
    for pattern, label in sensitive_patterns:
        if re.search(pattern, body[:2000] if body else "", re.IGNORECASE):
            issues.append(label)

    # CORS wildcard
    if headers.get("access-control-allow-origin") == "*":
        issues.append("CORS: Access-Control-Allow-Origin: * on API endpoint")

    return etype, tags, issues


def tag_interesting(endpoint: APIEndpoint) -> bool:
    """Return True if endpoint is worth highlighting."""
    interesting_tags = {"admin", "debug", "config", "actuator",
                        "data", "auth", "payment"}
    if endpoint.issues:
        return True
    if any(t in interesting_tags for t in endpoint.tags):
        return True
    if endpoint.status_code in (200, 201) and "admin" in endpoint.url.lower():
        return True
    if endpoint.endpoint_type in ("graphql", "swagger"):
        return True
    return False


# ══════════════════════════════════════════════════════════════
# 6. MANUAL PROBER
# ══════════════════════════════════════════════════════════════

def probe_endpoint(
    base_url:   str,
    path:       str,
    method:     str = "GET",
    headers:    dict[str, str] = {},
    timeout:    int = 8,
    fallback_signature: Optional[dict[str, Any]] = None,
) -> Optional[APIEndpoint]:
    """
    Probe a single API path and return an APIEndpoint if interesting.
    """
    url = _build_probe_url(base_url, path)
    req_headers = {
        "User-Agent": "APIDiscovery/1.0",
        "Accept":     "application/json, text/html, */*",
        **headers,
    }

    try:
        start = time.time()
        resp = requests.request(
            method,
            url,
            headers=req_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        elapsed = round(time.time() - start, 3)

        if resp.status_code not in INTERESTING_CODES:
            return None

        body         = resp.text[:3000]
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        ct           = resp_headers.get("content-type", "")
        fingerprint  = _response_fingerprint(
            status_code=resp.status_code,
            content_type=ct,
            body=body,
            content=resp.content,
        )

        # Suppress SPA/catch-all fallback pages that make every guessed path
        # look like a real API endpoint.
        if _is_probable_fallback_match(fingerprint, fallback_signature):
            return None

        # Ignore generic app shell pages unless the path itself indicates
        # docs/graphql entrypoints worth further probing.
        if _is_generic_html_shell(ct, body):
            if not any(kw in url.lower() for kw in [
                "swagger", "openapi", "api-docs", "redoc",
                "graphql", "graphiql", "playground", "voyager",
            ]):
                return None

        etype, tags, issues = classify_endpoint(url, resp.status_code, resp_headers, body)

        ep = APIEndpoint(
            url=url,
            method=method,
            status_code=resp.status_code,
            content_type=ct,
            content_length=len(resp.content),
            response_time=elapsed,
            source="manual_probe",
            confidence="medium" if resp.status_code == 200 else "low",
            endpoint_type=etype,
            tags=tags,
            issues=issues,
            response_snippet=body[:500] if body else None,
        )

        # Redirect URL
        if resp.status_code in (301, 302, 307, 308):
            ep.redirect_url = resp_headers.get("location")

        # Auth required detection
        if resp.status_code in (401, 403):
            ep.auth_required = True
            ep.confidence    = "high"   # endpoint exists but protected

        return ep

    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def manual_api_discovery(
    target:     str,
    paths:      list[str] = API_PATHS,
    headers:    dict[str, str] = {},
    threads:    int = 30,
    http_timeout: int = 8,
) -> tuple[list[APIEndpoint], list[SwaggerSpec], list[GraphQLInfo]]:
    """
    Full manual API discovery:
    1. Probe all paths concurrently
    2. Parse any swagger/openapi specs found
    3. Probe any graphql endpoints
    4. Extract additional paths from swagger spec
    """
    endpoints:     list[APIEndpoint]  = []
    swagger_specs: list[SwaggerSpec]  = []
    graphql_infos: list[GraphQLInfo]  = []
    seen_urls:     set[str]           = set()
    fallback_signature = _probe_fallback_signature(target, headers, http_timeout)

    # ── Phase 1: Probe all paths ──
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(
                probe_endpoint,
                target,
                path,
                "GET",
                headers,
                http_timeout,
                fallback_signature,
            ): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result.url not in seen_urls:
                seen_urls.add(result.url)
                endpoints.append(result)

    # ── Phase 2: POST probe interesting paths ──
    post_paths = [
        p for p in paths
        if any(kw in p for kw in [
            "graphql", "login", "auth", "token",
            "register", "signup", "create",
        ])
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = {
            ex.submit(
                probe_endpoint,
                target,
                path,
                "POST",
                headers,
                http_timeout,
                fallback_signature,
            ): path
            for path in post_paths
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result.url not in seen_urls:
                seen_urls.add(result.url)
                endpoints.append(result)

    # ── Phase 3: Parse swagger specs ──
    swagger_endpoints = [e for e in endpoints if e.endpoint_type == "swagger"]
    for ep in swagger_endpoints:
        try:
            resp = requests.get(
                ep.url,
                headers={**{"User-Agent": "APIDiscovery/1.0"}, **headers},
                timeout=http_timeout,
                verify=False,
            )
            if resp.status_code == 200:
                spec = parse_swagger_spec(ep.url, resp.text)
                swagger_specs.append(spec)

                # Probe paths discovered in swagger spec
                extra_paths = [e["path"] for e in spec.endpoints_defined]
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                    futures2 = {}
                    for epath in extra_paths[:100]:   # cap at 100
                        for method in ["GET", "POST"]:
                            futures2[ex.submit(
                                probe_endpoint, target, epath,
                                method, headers, http_timeout, fallback_signature
                            )] = epath
                    for future in concurrent.futures.as_completed(futures2):
                        result = future.result()
                        if result and result.url not in seen_urls:
                            seen_urls.add(result.url)
                            result.source = "swagger_spec"
                            result.confidence = "confirmed"
                            endpoints.append(result)
        except Exception:
            pass

    # ── Phase 4: Probe GraphQL endpoints ──
    gql_endpoints = [e for e in endpoints if e.endpoint_type == "graphql"
                     or e.status_code in (200, 400)]
    gql_urls_checked: set[str] = set()

    for ep in gql_endpoints:
        if ep.url in gql_urls_checked:
            continue
        # Also test common GQL paths
        gql_paths_to_try = [ep.url]
        for gp in ["/graphql", "/api/graphql", "/query", "/graphiql"]:
            gql_paths_to_try.append(_build_probe_url(target, gp))

        for gql_url in gql_paths_to_try:
            if gql_url in gql_urls_checked:
                continue
            gql_urls_checked.add(gql_url)
            gql_info = probe_graphql(gql_url, headers, http_timeout)
            if gql_info:
                graphql_infos.append(gql_info)

    # ── Phase 5: OPTIONS method — discover allowed methods ──
    interesting_eps = [
        e for e in endpoints
        if e.status_code in (200, 201, 204, 401, 403)
    ][:20]  # cap to avoid excessive requests

    def _options_probe(ep: APIEndpoint) -> None:
        try:
            resp = requests.options(
                ep.url,
                headers={**{"User-Agent": "APIDiscovery/1.0"}, **headers},
                timeout=http_timeout,
                verify=False,
            )
            allow = resp.headers.get("Allow") or resp.headers.get("allow")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                if any(m in methods for m in ("PUT", "DELETE", "PATCH")):
                    ep.issues.append(
                        f"Unsafe HTTP methods allowed: {', '.join(methods)}"
                    )
                ep.parameters.extend(methods)   # store allowed methods
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(_options_probe, interesting_eps))

    return endpoints, swagger_specs, graphql_infos


# ══════════════════════════════════════════════════════════════
# 7. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_kiterunner(stdout: str, stderr: str,
                     target: str) -> list[APIEndpoint]:
    """
    Parse kiterunner output.
    kiterunner  scan outputs lines like:
      POST    403 [   287,   8,  1] https://example.com/api/v1/users
      GET     200 [ 12345, 120, 5] https://example.com/api/v1/health
    Also supports JSON output (kiterunner scan -o json).
    """
    endpoints: list[APIEndpoint] = []
    seen:      set[str] = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # ── JSON output ──
        try:
            data = json.loads(line)
            url    = data.get("url") or data.get("URL", "")
            method = data.get("method") or data.get("Method", "GET")
            status = data.get("status") or data.get("StatusCode")

            if url and url not in seen:
                seen.add(url)
                etype, tags, issues = classify_endpoint(
                    url, status or 0, {}, ""
                )
                endpoints.append(APIEndpoint(
                    url=url,
                    method=method.upper(),
                    status_code=status,
                    source="kiterunner",
                    confidence="high",
                    endpoint_type=etype,
                    tags=tags,
                    issues=issues,
                ))
            continue
        except json.JSONDecodeError:
            pass

        # ── Plain text output ──
        # Format: METHOD  STATUS [size, lines, words] URL
        m = re.match(
            r"(\w+)\s+(\d+)\s+\[\s*[\d,\s]+\]\s+(https?://\S+)",
            line
        )
        if m:
            method = m.group(1).upper()
            status = int(m.group(2))
            url    = m.group(3)

            if url not in seen and status in INTERESTING_CODES:
                seen.add(url)
                etype, tags, issues = classify_endpoint(url, status, {}, "")
                endpoints.append(APIEndpoint(
                    url=url,
                    method=method,
                    status_code=status,
                    source="kiterunner",
                    confidence="high",
                    endpoint_type=etype,
                    tags=tags,
                    issues=issues,
                ))

    return endpoints


def parse_ffuf(stdout: str, stderr: str, target: str) -> list[APIEndpoint]:
    """
    Parse ffuf output.
    Supports JSON output (ffuf -json) and plain text.

    JSON format:
    {
      "results": [
        {"url": "...", "status": 200, "length": 123,
         "words": 10, "lines": 5, "input": {"FUZZ": "api/v1"}}
      ]
    }
    """
    endpoints: list[APIEndpoint] = []
    seen:      set[str] = set()

    # ── Try full JSON output ──
    try:
        data = json.loads(stdout)
        results = data.get("results", [])
        for r in results:
            url    = r.get("url", "")
            status = r.get("status", 0)
            length = r.get("length", 0)
            words  = r.get("words", 0)
            method = r.get("method", "GET").upper()

            if url and url not in seen and status in INTERESTING_CODES:
                seen.add(url)
                etype, tags, issues = classify_endpoint(url, status, {}, "")
                endpoints.append(APIEndpoint(
                    url=url,
                    method=method,
                    status_code=status,
                    content_length=length,
                    source="ffuf",
                    confidence="high",
                    endpoint_type=etype,
                    tags=tags,
                    issues=issues,
                ))
        return endpoints
    except json.JSONDecodeError:
        pass

    # ── Plain text parse ──
    # Format: api/v1     [Status: 200, Size: 1234, Words: 56, Lines: 12]
    pattern = re.compile(
        r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)"
    )
    for line in stdout.splitlines():
        m = pattern.search(line)
        if m:
            fuzz_val = m.group(1)
            status   = int(m.group(2))
            size     = int(m.group(3))

            url = target.rstrip("/") + "/" + fuzz_val.lstrip("/")
            if url not in seen and status in INTERESTING_CODES:
                seen.add(url)
                etype, tags, issues = classify_endpoint(url, status, {}, "")
                endpoints.append(APIEndpoint(
                    url=url,
                    method="GET",
                    status_code=status,
                    content_length=size,
                    source="ffuf",
                    confidence="medium",
                    endpoint_type=etype,
                    tags=tags,
                    issues=issues,
                ))

    return endpoints


def parse_graphql_voyager(stdout: str, target: str) -> list[GraphQLInfo]:
    """
    Parse graphql-voyager / graphql-introspection CLI output.
    """
    infos: list[GraphQLInfo] = []

    try:
        data = json.loads(stdout)

        # graphql-introspection-cli output
        if "data" in data and "__schema" in data.get("data", {}):
            schema = data["data"]["__schema"]
            info   = GraphQLInfo(
                endpoint_url=target,
                introspection_enabled=True,
            )
            for t in schema.get("types", []):
                name = t.get("name", "")
                if not name.startswith("__"):
                    info.types.append(name)

            # Basic counts from types
            info.query_count = len([
                t for t in info.types
                if "query" in t.lower() or "Query" in t
            ])
            info.mutation_count = len([
                t for t in info.types
                if "mutation" in t.lower()
            ])

            info.introspection_issues.append(
                "GraphQL introspection enabled (detected via voyager/CLI)"
            )
            infos.append(info)

    except json.JSONDecodeError:
        # Plain text parsing
        ip = re.compile(r"(https?://\S+graphql\S*)", re.IGNORECASE)
        for line in stdout.splitlines():
            m = ip.search(line)
            if m:
                info = GraphQLInfo(
                    endpoint_url=m.group(1),
                    introspection_enabled="introspection" in line.lower()
                    or "schema" in line.lower(),
                )
                if info.endpoint_url not in [i.endpoint_url for i in infos]:
                    infos.append(info)

    return infos


# ══════════════════════════════════════════════════════════════
# 8. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run subprocess safely — no shell, no injection."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def api_endpoint_discovery(
    tool:      str,
    target:    str,
    args:      list[str] = [],
    endpoints: list[str] = [],
    wordlist:  Optional[str] = None,
    headers:   dict[str, str] = {},
    compact_output: bool = True,
) -> dict:
    """
    🔧 Agent Tool: API Endpoint Discovery

    Capabilities:
      ┌──────────────────────────────────────────────────────────────────────┐
      │  REST API DISCOVERY   250+ path wordlist, method bruteforce          │
      │  SWAGGER / OPENAPI    Auto-detect + parse spec, extract all paths    │
      │  GRAPHQL              Introspection, schema dump, sensitive fields    │
      │                       batch query, debug UI detection                 │
      │  SOAP / WSDL          WSDL endpoint detection                        │
      │  CONTENT ANALYSIS     Classify response, detect sensitive data leak   │
      │  AUTH DETECTION       401/403 = endpoint exists but protected        │
      │  SECURITY ISSUES      CORS wildcard, stack traces, version headers    │
      │  TOOL INTEGRATION     kiterunner, ffuf, graphql-voyager, manual      │
      └──────────────────────────────────────────────────────────────────────┘

    Args:
        tool:      "kiterunner" | "ffuf" | "graphql" | "manual"
        target:    Base URL (e.g. "https://api.example.com")
        args:      Raw tool arguments — agent decides
        endpoints: Additional paths to test
        wordlist:  Path to wordlist file (for ffuf/kiterunner)
        headers:   Custom HTTP headers (e.g. auth tokens)

    Tool args reference:
      kiterunner:
        Basic:  ["scan", "-w", "routes-small.kite"]
        Threads:["scan", "-w", "routes-large.kite", "-x", "20"]
        Delay:  ["scan", "-w", "routes.kite", "--delay", "100ms"]
        Output: ["scan", "-w", "routes.kite", "-o", "json"]

      ffuf:
        Basic:  ["-w", "/wordlists/api.txt", "-mc", "200,201,204,301,401,403"]
        Ext:    ["-w", "/wl.txt", "-e", ".json,.yaml,.php"]
        Filter: ["-w", "/wl.txt", "-fc", "404", "-fs", "0"]
        Rate:   ["-w", "/wl.txt", "-rate", "100"]
        Recur:  ["-w", "/wl.txt", "-recursion", "-recursion-depth", "2"]

      graphql:
        (custom probe — no external tool needed)
        args ignored. Runs full introspection + batch + debug checks.

      manual:
        (pure Python — 250+ paths, swagger parse, graphql probe)
        args ignored. All checks run automatically.

    Returns:
        Structured JSON: endpoints → swagger_specs → graphql_info →
                         interesting → issues
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = APIDiscoveryRequest(
            tool=tool, target=target, args=args,
            endpoints=endpoints, wordlist=wordlist,
            headers=headers, compact_output=compact_output,
        )
    except Exception as e:
        return APIDiscoveryResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target
    target = req.target
    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    all_endpoints:  list[APIEndpoint]  = []
    swagger_specs:  list[SwaggerSpec]  = []
    graphql_infos:  list[GraphQLInfo]  = []
    command_str:    str = ""
    raw_output:     str = ""
    error_msg:      Optional[str] = None
    techniques_used: list[str] = []

    # Merge custom paths into probe list
    extra_paths = req.endpoints + (endpoints or [])
    full_paths  = list(dict.fromkeys(API_PATHS + extra_paths))

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_api_discovery({target}, {len(full_paths)} paths)"

        eps, specs, gql = manual_api_discovery(
            target=target,
            paths=full_paths,
            headers=req.headers,
            threads=30,
            http_timeout=8,
        )
        all_endpoints.extend(eps)
        swagger_specs.extend(specs)
        graphql_infos.extend(gql)
        techniques_used += [
            "path_bruteforce", "swagger_parse",
            "graphql_introspection", "options_probe",
        ]

    # ══════════════════════════════
    # TOOL: KITERUNNER
    # ══════════════════════════════
    elif tool == "kiterunner":
        wl = req.wordlist or "routes-small.kite"
        requested_wl = _extract_kiterunner_wordlist(req.args) or wl
        resolved_wl = _resolve_kiterunner_wordlist(requested_wl)

        if requested_wl and not resolved_wl:
            msg = (
                f"Kiterunner wordlist not found: {requested_wl}. "
                "Falling back to manual API discovery."
            )
            command_str = (
                f"kiterunner(scan -w {requested_wl}) "
                f"-> manual_api_discovery({target})"
            )
            raw_output = msg
            error_msg = msg

            eps, specs, gql = manual_api_discovery(
                target=target,
                paths=full_paths,
                headers=req.headers,
                threads=30,
                http_timeout=8,
            )
            all_endpoints.extend(eps)
            swagger_specs.extend(specs)
            graphql_infos.extend(gql)
            techniques_used += [
                "kiterunner_scan_failed_wordlist",
                "manual_fallback",
                "path_bruteforce",
                "swagger_parse",
                "graphql_introspection",
                "options_probe",
            ]
        else:
            effective_wl = resolved_wl or requested_wl

            # Build default kiterunner command
            if req.args and req.args[0] in ("scan", "brute", "replay"):
                args_for_cmd = _replace_kiterunner_wordlist(req.args, effective_wl)
                has_target = any(
                    a.startswith("http://") or a.startswith("https://")
                    for a in args_for_cmd
                )
                cmd = ["kiterunner"] + list(args_for_cmd)
                if not has_target:
                    cmd.append(target)
            else:
                cmd = [
                    "kiterunner", "scan", target,
                    "-w", effective_wl,
                    "-o", "json",
                    "--fail-status-codes", "404,400",
                ]
                if req.args:
                    cmd += list(req.args)

            command_str = " ".join(cmd)
            stdout, stderr, rc = safe_execute(cmd, req.timeout)
            raw_output = (stdout or stderr)[:5000]

            parsed = parse_kiterunner(stdout, stderr, target)
            all_endpoints.extend(parsed)
            techniques_used.append("kiterunner_scan")

            if rc != 0 and not parsed:
                error_msg = (stderr or stdout)[:400]

            # Enrich: swagger + graphql on top of kiterunner results
            swagger_urls = [
                e.url for e in all_endpoints
                if e.endpoint_type == "swagger"
            ]
            for surl in swagger_urls:
                try:
                    resp = requests.get(surl, timeout=8, verify=False,
                                        headers=req.headers)
                    if resp.status_code == 200:
                        spec = parse_swagger_spec(surl, resp.text)
                        swagger_specs.append(spec)

                        # Probe paths from spec
                        extra_eps, _, _ = manual_api_discovery(
                            target=target,
                            paths=[e["path"] for e in spec.endpoints_defined[:80]],
                            headers=req.headers,
                            threads=20,
                        )
                        for ep in extra_eps:
                            ep.source = "swagger_spec"
                            all_endpoints.append(ep)
                except Exception:
                    pass

            # GraphQL check on found endpoints
            for ep in all_endpoints:
                if ep.endpoint_type == "graphql" or "graphql" in ep.url.lower():
                    gql_info = probe_graphql(ep.url, req.headers)
                    if gql_info:
                        graphql_infos.append(gql_info)

            techniques_used += ["swagger_parse", "graphql_introspection"]

    # ══════════════════════════════
    # TOOL: FFUF
    # ══════════════════════════════
    elif tool == "ffuf":
        # Write built-in wordlist to tmp file if no external wordlist given
        import tempfile, os
        tmp_wl = None

        if req.wordlist:
            wl_path = req.wordlist
        else:
            tmp_wl  = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="api_paths_"
            )
            tmp_wl.write("\n".join(p.lstrip("/") for p in full_paths))
            tmp_wl.close()
            wl_path = tmp_wl.name

        fuzz_url = f"{target}/FUZZ"

        cmd = [
            "ffuf",
            "-u",  fuzz_url,
            "-w",  wl_path,
            "-mc", "200,201,204,301,302,307,400,401,403,405,422,500",
            "-json",
            "-t",  "30",
            "-timeout", "8",
        ]

        # Add custom headers
        for k, v in req.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        parsed = parse_ffuf(stdout, stderr, target)
        all_endpoints.extend(parsed)
        techniques_used.append("ffuf_fuzz")

        # Cleanup
        if tmp_wl and os.path.exists(wl_path):
            os.unlink(wl_path)

        if rc != 0 and not parsed:
            error_msg = (stderr or stdout)[:400]

        # Enrich with swagger + graphql
        for ep in all_endpoints:
            if ep.endpoint_type == "swagger":
                try:
                    resp = requests.get(ep.url, timeout=8,
                                        verify=False, headers=req.headers)
                    if resp.status_code == 200:
                        spec = parse_swagger_spec(ep.url, resp.text)
                        swagger_specs.append(spec)
                        # Probe discovered paths
                        extra_eps, _, _ = manual_api_discovery(
                            target=target,
                            paths=[e["path"] for e in spec.endpoints_defined[:80]],
                            headers=req.headers,
                            threads=20,
                        )
                        for eep in extra_eps:
                            eep.source = "swagger_spec"
                            all_endpoints.append(eep)
                except Exception:
                    pass

            elif ep.endpoint_type == "graphql" or "graphql" in ep.url.lower():
                gql_info = probe_graphql(ep.url, req.headers)
                if gql_info:
                    graphql_infos.append(gql_info)

        techniques_used += ["swagger_parse", "graphql_introspection"]

    # ══════════════════════════════
    # TOOL: GRAPHQL (dedicated)
    # ══════════════════════════════
    elif tool == "graphql":
        # Try graphql-voyager / graphql-introspection CLI
        gql_paths = [
            "/graphql", "/graphiql", "/api/graphql",
            "/v1/graphql", "/v2/graphql", "/query", "/playground",
        ]

        command_str = f"graphql_probe({target})"
        external_errors: list[str] = []
        external_output_chunks: list[str] = []
        use_external_cli = any(
            a.strip().lower() in ("--use-external-cli", "--external-cli")
            for a in req.args
        )

        # Try external tools only when explicitly requested.
        if use_external_cli:
            for cli in ["graphql-introspect", "gql-cli"]:
                if not shutil.which(cli):
                    continue

                cmd = [cli, target] + list(req.args)
                stdout, stderr, rc = safe_execute(cmd, min(req.timeout, 8))
                snippet = (stdout or stderr or "").strip()
                if snippet:
                    external_output_chunks.append(f"[{cli}] {snippet[:400]}")

                if rc == 0 and stdout.strip():
                    parsed_gql = parse_graphql_voyager(stdout, target)
                    if parsed_gql:
                        graphql_infos.extend(parsed_gql)
                        techniques_used.append(f"{cli}_scan")
                elif rc != 0:
                    external_errors.append(f"{cli}: {(stderr or stdout)[:180]}")

        if external_output_chunks:
            raw_output = "\n".join(external_output_chunks)[:5000]

        # Always run our own probe (more thorough)
        checked: set[str] = set()
        for gql_path in gql_paths:
            gql_url = target.rstrip("/") + gql_path
            if gql_url in checked:
                continue
            checked.add(gql_url)

            # First verify endpoint exists
            try:
                resp = requests.get(
                    gql_url,
                    timeout=8,
                    verify=False,
                    headers={**{"User-Agent": "APIDiscovery/1.0"}, **req.headers},
                )
                if resp.status_code not in (200, 400, 405):
                    continue
            except Exception:
                continue

            # Full GraphQL analysis
            gql_info = probe_graphql(gql_url, req.headers)
            if gql_info:
                if gql_url not in [g.endpoint_url for g in graphql_infos]:
                    graphql_infos.append(gql_info)

                # Create endpoint entry for this GQL URL
                all_endpoints.append(APIEndpoint(
                    url=gql_url,
                    method="POST",
                    status_code=200,
                    source="graphql_probe",
                    confidence="confirmed",
                    endpoint_type="graphql",
                    tags=["graphql"],
                    issues=gql_info.introspection_issues,
                ))

        techniques_used += ["graphql_introspection", "graphql_batch_test",
                             "graphql_debug_detect"]

        if not graphql_infos and not all_endpoints:
            if external_errors:
                error_msg = (
                    "GraphQL discovery found no endpoints. "
                    f"External CLI probe errors: {'; '.join(external_errors[:2])}"
                )
            else:
                error_msg = "GraphQL discovery found no endpoints on common paths"

    # ══════════════════════════════
    # POST-PROCESS ALL RESULTS
    # ══════════════════════════════

    # Deduplicate endpoints
    seen_keys: set[str] = set()
    unique_eps: list[APIEndpoint] = []
    for ep in all_endpoints:
        key = f"{ep.method}:{ep.url}"
        if key not in seen_keys:
            seen_keys.add(key)
            unique_eps.append(ep)

    # Suppress repeated HTML shell false positives before final ranking.
    unique_eps, suppressed_html_shell_count = _suppress_generic_html_shell(unique_eps)

    # Flag interesting endpoints
    interesting = [ep for ep in unique_eps if tag_interesting(ep)]

    # Add GraphQL issues to interesting
    for gql in graphql_infos:
        if gql.introspection_enabled or gql.introspection_issues:
            gql_ep = APIEndpoint(
                url=gql.endpoint_url,
                method="POST",
                status_code=200,
                source="graphql_probe",
                confidence="confirmed",
                endpoint_type="graphql",
                tags=["graphql"],
                issues=gql.introspection_issues,
            )
            if gql_ep.url not in [e.url for e in interesting]:
                interesting.append(gql_ep)

    llm_brief = _build_llm_brief(
        endpoints=unique_eps,
        interesting=interesting,
        graphql_infos=graphql_infos,
        swagger_specs=swagger_specs,
        suppressed_html_shell_count=suppressed_html_shell_count,
    )

    # Compact mode returns only pentest-relevant endpoints to keep payload short.
    if req.compact_output:
        compact_pool = [
            ep for ep in interesting
            if ep.issues
            or ep.auth_required
            or (
                ep.status_code == 405
                and any(
                    t in ep.tags
                    for t in ("auth", "admin", "graphql", "swagger", "actuator", "config", "debug")
                )
            )
        ]
        if not compact_pool:
            compact_pool = interesting or unique_eps

        prioritized_compact = _prioritize_for_pentest(compact_pool, limit=12)
        llm_brief["next_targets"] = [
            {
                "url": ep.url,
                "method": ep.method,
                "status": ep.status_code,
                "type": ep.endpoint_type,
                "tags": ep.tags[:4],
                "issues": ep.issues[:2],
                "signal": (
                    "protected_endpoint_exists"
                    if ep.status_code in (401, 403)
                    else "endpoint_exists_method_gated"
                    if ep.status_code == 405
                    else "security_finding"
                    if ep.issues
                    else "candidate"
                ),
            }
            for ep in prioritized_compact[:10]
        ]

        # Alias llm_brief keys for compact transport to reduce tokens.
        brief_compact: dict[str, Any] = {
            "a": llm_brief.get("attack_surface_count", 0),
            "t": [
                {
                    "u": t.get("url"),
                    "m": t.get("method"),
                    "c": t.get("status"),
                    "y": t.get("type"),
                    "g": t.get("tags", []),
                    "i": t.get("issues", []),
                    "s": t.get("signal"),
                }
                for t in llm_brief.get("next_targets", [])
            ],
        }

        hs = int(llm_brief.get("high_signal_count", 0) or 0)
        if hs > 0:
            brief_compact["h"] = hs

        suppressed = int(llm_brief.get("suppressed_html_shell_count", 0) or 0)
        if suppressed > 0:
            brief_compact["sh"] = suppressed

        gql_targets = llm_brief.get("graphql_targets", [])
        if gql_targets:
            brief_compact["gql"] = [
                {
                    "u": g.get("endpoint_url"),
                    "i": g.get("introspection_enabled", False),
                    "f": g.get("sensitive_fields", []),
                    "x": g.get("issues", []),
                }
                for g in gql_targets[:6]
            ]

        swagger_targets = llm_brief.get("swagger_targets", [])
        if swagger_targets:
            brief_compact["sw"] = [
                {
                    "u": s.get("url"),
                    "v": s.get("version"),
                    "sec": s.get("security_schemes", []),
                    "a": s.get("auth_types", []),
                    "x": s.get("issues", []),
                    "p": s.get("path_count"),
                }
                for s in swagger_targets[:6]
            ]

        llm_brief = brief_compact

        # In compact mode, avoid duplicate large arrays. llm_brief holds the
        # actionable attack surface for the LLM.
        trimmed_endpoints = []
        trimmed_interesting = []
        swagger_specs = []
        graphql_infos = []

        output_techniques_used: list[str] = []

        # raw_output often duplicates error text and wastes tokens in compact mode.
        raw_output = None
    else:
        trimmed_endpoints = unique_eps
        trimmed_interesting = interesting
        output_techniques_used = list(dict.fromkeys(techniques_used))

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return APIDiscoveryResult(
        success=len(unique_eps) > 0 or len(graphql_infos) > 0,
        tool=tool,
        target=target,
        command=command_str,
        total_endpoints=len(unique_eps),
        total_unique=len(unique_eps),
        endpoints=trimmed_endpoints,
        swagger_specs=swagger_specs,
        graphql_info=graphql_infos,
        interesting=trimmed_interesting,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
        techniques_used=output_techniques_used,
        llm_brief=llm_brief,
    ).model_dump(exclude_none=True, exclude_defaults=True)


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

API_DISCOVERY_TOOL_DEFINITION = {
    "name": "api_endpoint_discovery",
    "description": (
        "Discover undocumented and documented API endpoints. "
        "Probes 250+ common API paths (REST, GraphQL, SOAP, gRPC, Swagger/OpenAPI). "
        "Auto-detects and parses Swagger/OpenAPI specs to extract all defined routes. "
        "Full GraphQL introspection: schema dump, query/mutation/subscription enumeration, "
        "sensitive field detection, batch query test, debug UI detection. "
        "Flags: auth bypass (200 on admin endpoints), stack traces in 500s, "
        "CORS wildcards, version header disclosure, sensitive data in responses. "
        "Supports kiterunner (API-aware), ffuf (wordlist fuzzing), "
        "graphql (dedicated GQL probe), manual (all techniques, no deps)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["kiterunner", "ffuf", "graphql", "manual"],
                "description": (
                    "kiterunner = API-aware route bruteforce (best for REST APIs) | "
                    "ffuf       = fast wordlist fuzzer | "
                    "graphql    = dedicated GraphQL introspection + analysis | "
                    "manual     = all techniques built-in (recommended)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Base URL (e.g. 'https://api.example.com' or 'https://example.com')",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "kiterunner: ['scan', '-w', 'routes-large.kite', '-x', '20']\n"
                    "ffuf:       ['-rate', '100', '-recursion', '-recursion-depth', '2']\n"
                    "graphql:    [] (probe runs automatically)\n"
                    "manual:     [] (all checks run automatically)"
                ),
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Additional paths to probe. "
                    "e.g. ['/api/v1/internal', '/backend/admin', '/v3/graphql']"
                ),
            },
            "wordlist": {
                "type": "string",
                "description": (
                    "Path to wordlist file for ffuf/kiterunner. "
                    "e.g. '/usr/share/wordlists/api-routes.txt' or 'routes-large.kite'"
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Custom HTTP headers to include in all requests. "
                    "e.g. {'Authorization': 'Bearer <token>', "
                    "'X-API-Key': 'abc123', 'Cookie': 'session=xyz'}"
                ),
            },
            "compact_output": {
                "type": "boolean",
                "description": (
                    "If true (default), return compact pentest-focused data: "
                    "trimmed endpoint lists and llm_brief summary. "
                    "Set false to return full endpoint structures."
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 11. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    import urllib3
    urllib3.disable_warnings()

    LOCAL_CRAPI_TARGET = "http://localhost:8888/api"
    """
    # ─────────────────────────────
    # 1. Manual — full discovery
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="manual",
        target=LOCAL_CRAPI_TARGET,
    )
    print("=== MANUAL FULL DISCOVERY ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Manual — with auth header
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="manual",
        target=LOCAL_CRAPI_TARGET,
        headers={"Authorization": "Bearer your_token_here"},
        endpoints=["/v1/internal", "/admin/users"],
    )
    print("=== MANUAL WITH AUTH ===")
    print(json.dumps(r, indent=2))
    """
    # ─────────────────────────────
    # 3. Kiterunner — large routes
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="kiterunner",
        target=LOCAL_CRAPI_TARGET,
        args=["scan", "-w", "routes-large.kite", "-x", "20",
              "-o", "json"],
    )
    print("=== KITERUNNER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. ffuf — recursive
    # ─────────────────────────────
    """
    r = api_endpoint_discovery(
        tool="ffuf",
        target=LOCAL_CRAPI_TARGET,
        args=["-rate", "100", "-recursion", "-recursion-depth", "2",
              "-fc", "404"],
    )
    print("=== FFUF RECURSIVE ===")
    print(json.dumps(r, indent=2))
    """
    # ─────────────────────────────
    # 5. GraphQL only
    # ─────────────────────────────
    """
    r = api_endpoint_discovery(
        tool="graphql",
        target=LOCAL_CRAPI_TARGET,
    )
    print("=== GRAPHQL INTROSPECTION ===")
    print(json.dumps(r, indent=2))
    """
    # ─────────────────────────────
    # 6. GraphQL with auth
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="graphql",
        target=LOCAL_CRAPI_TARGET,
        headers={"Authorization": "Bearer your_token"},
    )
    print("=== GRAPHQL WITH AUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. ffuf with custom wordlist
    # ─────────────────────────────
    """
    r = api_endpoint_discovery(
        tool="ffuf",
        target=LOCAL_CRAPI_TARGET,
        wordlist="/usr/share/wordlists/SecLists/Discovery/Web-Content/api"
                 "/api-endpoints.txt",
        args=["-mc", "200,201,301,401,403", "-rate", "50"],
        headers={"Cookie": "session=abc123"},
    )
    print("=== FFUF CUSTOM WORDLIST ===")
    print(json.dumps(r, indent=2))"""
