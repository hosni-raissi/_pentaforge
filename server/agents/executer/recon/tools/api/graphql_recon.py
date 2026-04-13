#/+
from __future__ import annotations

__all__ = ["graphql_recon", "GRAPHQL_RECON_TOOL_DEFINITION"]

import ipaddress
import json
import re
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any, Optional

import requests
try:
    from urllib3.exceptions import InsecureRequestWarning
except Exception:  # pragma: no cover - fallback for older/vendored layouts
    InsecureRequestWarning = Warning
from pydantic import BaseModel, Field, field_validator

# Suppress SSL warnings globally for pentest use
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_DANGEROUS      = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_CRLF_CHARS     = frozenset({"\r", "\n", "\x00"})

# IPs/hosts that must never be targeted
_BLOCKED_HOSTS  = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254",          # AWS IMDS
    "metadata.google.internal", # GCP metadata
    "metadata.azure.com",       # Azure metadata (SSRF guard)
})

_GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/gql",
    "/api/graphql", "/api/gql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/v1/gql",
    "/query", "/playground", "/altair", "/voyager",
    "/graphql/console", "/graphql/playground",
    "/subscriptions", "/graphql/subscriptions",
    "/graphql/schema", "/graphql/v1", "/graphql/v2",
]

_PLAYGROUND_PATHS = [
    "/graphiql", "/playground", "/altair", "/voyager",
    "/graphql/playground", "/graphql/graphiql",
    "/api/graphiql", "/api/playground",
    "/graphql-playground", "/graphql-explorer",
]

_SENSITIVE_PATTERNS = frozenset({
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "auth_token", "access_token", "refresh_token", "credential",
    "private_key", "private", "ssn", "credit_card", "cvv", "pin",
    "otp", "hash", "salt", "seed", "signing_key", "jwt",
    "session_id", "session_token", "csrf", "nonce",
})

_DANGEROUS_MUTATION_KW = frozenset({
    "delete", "remove", "drop", "destroy", "reset",
    "admin", "escalate", "privilege", "role",
})

_DEBUG_KEYWORDS = frozenset({
    "traceback", "stack", "debug", "line ",
    "file ", ".py", ".js", "node_modules",
    "internal server", "development",
})

_PLAYGROUND_KEYWORDS = frozenset({
    "graphiql", "graphql playground", "altair",
    "voyager", "graphql-playground", "graphql ide",
    "__schema", "introspection",
})

_FULL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    directives {
      name description locations
      args { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
    }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
        type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
      }
      inputFields { name type { name kind ofType { name kind ofType { name kind } } } }
      interfaces { name }
      enumValues(includeDeprecated: true) { name isDeprecated deprecationReason }
      possibleTypes { name }
    }
  }
}
"""

_SIMPLE_PROBE  = '{"query":"{ __typename }"}'
_MALFORMED_Q   = '{"query":"{ INVALID_QUERY_FOR_DEBUG_DETECTION"}'


# ══════════════════════════════════════════════════════════════
# 2. HELPERS
# ══════════════════════════════════════════════════════════════

def _extract_host(url: str) -> str:
    """Extract hostname from URL without external dependencies."""
    m = re.match(r"https?://([^/:?#]+)", url.lower())
    return m.group(1) if m else url.lower()


def _is_private_ip(host: str) -> bool:
    """Return True if host resolves to a private/loopback/link-local address."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class GraphQLReconRequest(BaseModel):
    target:    str
    endpoints: list[str]       = []
    headers:   dict[str, str]  = {}
    timeout:   int             = Field(default=30, ge=5, le=120)
    max_depth: int             = Field(default=5, ge=1, le=10)
    verify_ssl: bool           = False   # False = pentest mode (skip cert verification)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://[a-zA-Z0-9]", v):
            raise ValueError("Target must start with http:// or https://")
        host = _extract_host(v)
        # FIX: block ALL loopback/private/metadata hosts — not just allow them
        if host in _BLOCKED_HOSTS:
            raise ValueError(f"Target host '{host}' is blocked (internal/reserved)")
        if _is_private_ip(host):
            raise ValueError(f"Target IP '{host}' is private/loopback — blocked")
        return v

    @field_validator("endpoints", mode="before")
    @classmethod
    def validate_endpoints(cls, v: list[str]) -> list[str]:
        for ep in v:
            if not ep.startswith("/"):
                raise ValueError(f"Endpoint path must start with '/': {ep!r}")
            for ch in _DANGEROUS:
                if ch in ep:
                    raise ValueError(f"Dangerous character {ch!r} in endpoint: {ep!r}")
            # Block path traversal
            if ".." in ep:
                raise ValueError(f"Path traversal detected in endpoint: {ep!r}")
        return v

    @field_validator("headers", mode="before")
    @classmethod
    def validate_headers(cls, v: dict[str, str]) -> dict[str, str]:
        for key, val in v.items():
            for ch in _CRLF_CHARS:
                if ch in key or ch in str(val):
                    raise ValueError(f"CRLF/null character in header {key!r}")
        return v


class GraphQLField(BaseModel):
    name:               str
    type_name:          Optional[str] = None
    type_kind:          Optional[str] = None
    args:               list[str]     = []
    is_deprecated:      bool          = False
    deprecation_reason: Optional[str] = None


class GraphQLType(BaseModel):
    name:           str
    kind:           str
    fields:         list[GraphQLField] = []
    enum_values:    list[str]          = []
    interfaces:     list[str]          = []
    possible_types: list[str]          = []


class GraphQLSchemaInfo(BaseModel):
    endpoint:               str
    introspection_enabled:  bool           = False
    query_type:             Optional[str]  = None
    mutation_type:          Optional[str]  = None
    subscription_type:      Optional[str]  = None
    types:                  list[GraphQLType]  = []
    queries:                list[GraphQLField] = []
    mutations:              list[GraphQLField] = []
    subscriptions:          list[GraphQLField] = []
    directives:             list[str]      = []
    total_types:            int            = 0
    total_queries:          int            = 0
    total_mutations:        int            = 0
    total_subscriptions:    int            = 0
    sensitive_fields:       list[str]      = []
    batch_queries_enabled:  bool           = False
    debug_mode:             bool           = False
    playground_urls:        list[str]      = []
    issues:                 list[str]      = []


class GraphQLReconResult(BaseModel):
    success:              bool
    target:               str
    endpoints_probed:     int            = 0
    endpoints_found:      int            = 0
    schemas:              list[GraphQLSchemaInfo] = []
    all_sensitive_fields: list[str]      = []
    all_issues:           list[str]      = []
    error:                Optional[str]  = None
    execution_time:       float          = 0.0


# ══════════════════════════════════════════════════════════════
# 4. HTTP LAYER
# ══════════════════════════════════════════════════════════════

_DEFAULT_HEADERS = {
    "Content-Type":  "application/json",
    "Accept":        "application/json",
    "User-Agent":    "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
}


def _post(url: str, body: Any, extra_headers: dict[str, str],
          timeout: int, verify_ssl: bool) -> Optional[dict]:
    """POST a GraphQL request and return parsed JSON or None."""
    headers = {**_DEFAULT_HEADERS, **extra_headers}
    try:
        if isinstance(body, str):
            resp = requests.post(url, data=body, headers=headers,
                                 timeout=timeout, verify=verify_ssl,
                                 allow_redirects=True)
        else:
            resp = requests.post(url, json=body, headers=headers,
                                 timeout=timeout, verify=verify_ssl,
                                 allow_redirects=True)
        if resp.status_code not in (200, 400):
            return None
        return resp.json()
    except Exception:
        return None


def _get_html(url: str, extra_headers: dict[str, str],
              timeout: int, verify_ssl: bool) -> Optional[str]:
    """GET a URL and return text or None."""
    headers = {"User-Agent": _DEFAULT_HEADERS["User-Agent"], **extra_headers}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout,
                            verify=verify_ssl, allow_redirects=True)
        return resp.text if resp.status_code == 200 else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# 5. TYPE RESOLUTION
# ══════════════════════════════════════════════════════════════

def _resolve_type(type_obj: Optional[dict]) -> tuple[str, str]:
    """Recursively unwrap ofType wrappers to get the base type name and kind."""
    if not type_obj:
        return "Unknown", "UNKNOWN"
    name = type_obj.get("name")
    kind = type_obj.get("kind", "UNKNOWN")
    if name:
        return name, kind
    of_type = type_obj.get("ofType")
    if of_type:
        return _resolve_type(of_type)
    return "Unknown", kind


def _is_sensitive(field_name: str) -> bool:
    lower = field_name.lower()
    return any(p in lower for p in _SENSITIVE_PATTERNS)


# ══════════════════════════════════════════════════════════════
# 6. DISCOVERY
# ══════════════════════════════════════════════════════════════

def _probe(base_url: str, path: str, headers: dict[str, str],
           timeout: int, verify_ssl: bool) -> Optional[str]:
    url    = base_url.rstrip("/") + path
    result = _post(url, _SIMPLE_PROBE, headers, timeout, verify_ssl)
    if result and ("data" in result or "errors" in result):
        return url
    return None


def _discover_endpoints(base_url: str, custom_paths: list[str],
                        headers: dict[str, str], timeout: int,
                        verify_ssl: bool) -> list[str]:
    paths = list(set(custom_paths + _GRAPHQL_PATHS))
    found: list[str] = []

    # FIX: cancel futures after timeout; don't let stale threads linger
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_probe, base_url, p, headers, timeout, verify_ssl): p
            for p in paths
        }
        try:
            for future in as_completed(futures, timeout=timeout * 2):
                try:
                    r = future.result(timeout=1)
                    if r:
                        found.append(r)
                except Exception:
                    pass
        except FuturesTimeout:
            pass   # partial results are fine; cancel remaining via executor shutdown

    return list(set(found))


def _discover_playgrounds(base_url: str, headers: dict[str, str],
                          timeout: int, verify_ssl: bool) -> list[str]:
    found: list[str] = []
    for path in _PLAYGROUND_PATHS:
        url     = base_url.rstrip("/") + path
        content = _get_html(url, headers, timeout, verify_ssl)
        if content and any(kw in content.lower() for kw in _PLAYGROUND_KEYWORDS):
            found.append(url)
    return found


# ══════════════════════════════════════════════════════════════
# 7. SECURITY CHECKS
# ══════════════════════════════════════════════════════════════

def _check_batch(url: str, headers: dict[str, str],
                 timeout: int, verify_ssl: bool) -> bool:
    body = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
    result = _post(url, body, headers, timeout, verify_ssl)
    return isinstance(result, list) and len(result) >= 2


def _check_debug(url: str, headers: dict[str, str],
                 timeout: int, verify_ssl: bool) -> bool:
    # FIX: send a cleanly-formed JSON with an intentionally invalid GraphQL value
    result = _post(url, _MALFORMED_Q, headers, timeout, verify_ssl)
    if not result:
        return False
    for err in result.get("errors", []):
        msg = str(err.get("message", "")).lower()
        if any(kw in msg for kw in _DEBUG_KEYWORDS):
            return True
        ext = err.get("extensions", {})
        if isinstance(ext, dict) and ("stacktrace" in ext or "exception" in ext):
            return True
    return False


# ══════════════════════════════════════════════════════════════
# 8. INTROSPECTION PARSER
# ══════════════════════════════════════════════════════════════

def _run_introspection(url: str, headers: dict[str, str],
                       timeout: int, verify_ssl: bool) -> GraphQLSchemaInfo:
    info = GraphQLSchemaInfo(endpoint=url)

    result = _post(url, json.dumps({"query": _FULL_INTROSPECTION_QUERY}),
                   headers, timeout, verify_ssl)

    if not result:
        info.issues.append("Endpoint unreachable or returned non-JSON")
        return info

    schema = (result.get("data") or {}).get("__schema")

    if not schema:
        errors = result.get("errors", [])
        if errors:
            info.issues.append(
                "Introspection disabled — endpoint exists but schema is hidden"
            )
            for err in errors[:3]:
                msg = err.get("message", "")
                if msg:
                    info.issues.append(f"Error: {msg[:200]}")
        return info

    # ── Introspection is enabled ──────────────────────────────
    info.introspection_enabled = True
    info.issues.append(
        "CRITICAL: Introspection ENABLED — full schema publicly accessible"
    )

    qt = (schema.get("queryType")        or {}).get("name")
    mt = (schema.get("mutationType")     or {}).get("name")
    st = (schema.get("subscriptionType") or {}).get("name")
    info.query_type        = qt
    info.mutation_type     = mt
    info.subscription_type = st

    for d in schema.get("directives", []):
        name = d.get("name", "")
        if name:
            info.directives.append(name)

    for type_def in schema.get("types", []):
        type_name = type_def.get("name", "")
        type_kind = type_def.get("kind", "")
        if type_name.startswith("__"):
            continue

        gql_type = GraphQLType(name=type_name, kind=type_kind)

        for field_def in (type_def.get("fields") or []):
            fname         = field_def.get("name", "")
            ftype_name, ftype_kind = _resolve_type(field_def.get("type"))
            fargs         = [
                a.get("name", "") for a in field_def.get("args", [])
                if isinstance(a, dict)
            ]
            gql_field = GraphQLField(
                name=fname,
                type_name=ftype_name,
                type_kind=ftype_kind,
                args=fargs,
                is_deprecated=field_def.get("isDeprecated", False),
                deprecation_reason=field_def.get("deprecationReason"),
            )
            gql_type.fields.append(gql_field)

            if _is_sensitive(fname):
                info.sensitive_fields.append(f"{type_name}.{fname}")

            if type_name == qt:
                info.queries.append(gql_field)
            elif type_name == mt:
                info.mutations.append(gql_field)
            elif type_name == st:
                info.subscriptions.append(gql_field)

        for ev in (type_def.get("enumValues") or []):
            if isinstance(ev, dict) and ev.get("name"):
                gql_type.enum_values.append(ev["name"])

        for iface in (type_def.get("interfaces") or []):
            if isinstance(iface, dict) and iface.get("name"):
                gql_type.interfaces.append(iface["name"])

        for pt in (type_def.get("possibleTypes") or []):
            if isinstance(pt, dict) and pt.get("name"):
                gql_type.possible_types.append(pt["name"])

        info.types.append(gql_type)

    info.total_types         = len(info.types)
    info.total_queries       = len(info.queries)
    info.total_mutations     = len(info.mutations)
    info.total_subscriptions = len(info.subscriptions)

    # ── Security checks ───────────────────────────────────────
    info.batch_queries_enabled = _check_batch(url, headers, timeout, verify_ssl)
    if info.batch_queries_enabled:
        info.issues.append(
            "Batch queries enabled — amplifies brute-force and DoS attacks"
        )

    info.debug_mode = _check_debug(url, headers, timeout, verify_ssl)
    if info.debug_mode:
        info.issues.append(
            "Debug mode detected — verbose error messages / stack traces exposed"
        )

    if info.sensitive_fields:
        info.issues.append(
            f"Sensitive fields in schema: {', '.join(info.sensitive_fields[:10])}"
        )

    deprecated = [
        f"{t.name}.{f.name}"
        for t in info.types for f in t.fields if f.is_deprecated
    ]
    if deprecated:
        info.issues.append(
            f"{len(deprecated)} deprecated fields still exposed: "
            f"{', '.join(deprecated[:5])}"
        )

    dangerous_mutations = [
        m.name for m in info.mutations
        if any(kw in m.name.lower() for kw in _DANGEROUS_MUTATION_KW)
    ]
    if dangerous_mutations:
        info.issues.append(
            f"Potentially dangerous mutations: {', '.join(dangerous_mutations[:5])}"
        )

    return info


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def graphql_recon(
    target:     str,
    endpoints:  Optional[list[str]]      = None,   # FIX: no mutable default
    headers:    Optional[dict[str, str]] = None,   # FIX: no mutable default
    timeout:    int                      = 30,
    max_depth:  int                      = 5,
    verify_ssl: bool                     = False,
) -> dict[str, Any]:
    """
    GraphQL endpoint discovery and security reconnaissance.
    Returns structured dict — never writes to disk.

    Args:
        target     : Base URL (e.g. 'https://example.com')
        endpoints  : Extra endpoint paths to probe beyond defaults
        headers    : Custom HTTP headers (e.g. Authorization)
        timeout    : Seconds per request (5–120)
        max_depth  : Schema type recursion depth (1–10)
        verify_ssl : Verify TLS certificates (False = pentest mode)

    Returns:
        GraphQLReconResult as dict with keys:
        success, target, endpoints_probed, endpoints_found,
        schemas, all_sensitive_fields, all_issues, error, execution_time
    """
    start     = time.monotonic()
    endpoints = endpoints or []
    headers   = headers   or {}

    def _fail(msg: str) -> dict[str, Any]:
        return GraphQLReconResult(
            success=False, target=target, error=msg,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    try:
        req = GraphQLReconRequest(
            target=target, endpoints=endpoints, headers=headers,
            timeout=timeout, max_depth=max_depth, verify_ssl=verify_ssl,
        )
    except Exception as exc:
        return _fail(f"Validation: {exc}")

    # ── Endpoint discovery ────────────────────────────────────
    discovered = _discover_endpoints(
        req.target, req.endpoints, req.headers, req.timeout, req.verify_ssl,
    )
    total_probed = len(_GRAPHQL_PATHS) + len(req.endpoints)

    if not discovered:
        return GraphQLReconResult(
            success=False, target=target,
            endpoints_probed=total_probed,
            error="No GraphQL endpoints found",
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    # ── Introspect each endpoint ──────────────────────────────
    schemas: list[GraphQLSchemaInfo] = []
    all_sensitive: list[str] = []
    all_issues:    list[str] = []

    for ep_url in discovered:
        schema_info = _run_introspection(
            ep_url, req.headers, req.timeout, req.verify_ssl,
        )
        # Playground discovery relative to endpoint base
        base = re.sub(r"/graphql.*$", "", ep_url)
        schema_info.playground_urls = _discover_playgrounds(
            base, req.headers, req.timeout, req.verify_ssl,
        )
        if schema_info.playground_urls:
            schema_info.issues.append(
                f"GraphQL IDE/playground exposed: "
                f"{', '.join(schema_info.playground_urls[:3])}"
            )

        schemas.append(schema_info)
        all_sensitive.extend(schema_info.sensitive_fields)
        all_issues.extend(schema_info.issues)

    # FIX: success reflects whether actionable data was found
    has_data = any(s.introspection_enabled or s.sensitive_fields or s.issues
                   for s in schemas)

    return GraphQLReconResult(
        success=has_data,
        target=target,
        endpoints_probed=total_probed,
        endpoints_found=len(discovered),
        schemas=schemas,
        all_sensitive_fields=list(dict.fromkeys(all_sensitive)),  # dedup, preserve order
        all_issues=list(dict.fromkeys(all_issues)),
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

GRAPHQL_RECON_TOOL_DEFINITION: dict[str, Any] = {
    "name": "graphql_recon",
    "description": (
        "Discover and analyse GraphQL endpoints on a web target. "
        "Probes common paths, runs schema introspection, extracts all queries/"
        "mutations/types, detects sensitive field names, batch query support, "
        "debug mode stack traces, deprecated fields, dangerous mutations, "
        "and exposed playground IDEs. Non-destructive reconnaissance only."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL (e.g. 'https://example.com')",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra paths to probe beyond defaults (e.g. ['/custom/gql'])",
            },
            "headers": {
                "type": "object",
                "description": 'Custom HTTP headers e.g. {"Authorization": "Bearer <token>"}',
            },
            "timeout": {
                "type": "integer",
                "default": 30,
                "minimum": 5,
                "maximum": 120,
                "description": "Per-request timeout in seconds",
            },
            "max_depth": {
                "type": "integer",
                "default": 5,
                "minimum": 1,
                "maximum": 10,
                "description": "Schema type recursion depth",
            },
            "verify_ssl": {
                "type": "boolean",
                "default": False,
                "description": "Verify TLS certificates (False = pentest mode)",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 11. HELPERS
# ══════════════════════════════════════════════════════════════

def _sep(char: str = "─", width: int = 64) -> str:
    return char * width


def _print_result(label: str, r: dict, verbose_schemas: bool = False) -> None:
    print(f"\n{_sep()}\n  {label}\n{_sep()}")
    print(f"  success           : {r['success']}")
    print(f"  target            : {r['target']}")
    print(f"  endpoints_probed  : {r['endpoints_probed']}")
    print(f"  endpoints_found   : {r['endpoints_found']}")
    print(f"  execution_time    : {r['execution_time']}s")
    if r.get("error"):
        print(f"  error             : {r['error'][:200]}")

    schemas = r.get("schemas", []) or []
    if schemas:
        print(f"  schema_snapshots  : {len(schemas)}")
        for schema in schemas[:3]:
            print(
                f"    - {schema['endpoint']} "
                f"(intro={schema['introspection_enabled']}, "
                f"q={schema['total_queries']}, m={schema['total_mutations']})"
            )
        if len(schemas) > 3:
            print(f"    ... +{len(schemas) - 3} more endpoints")

    issues = r.get("all_issues", []) or []
    if issues:
        print(f"  unique_issues     : {len(issues)}")
        for issue in issues[:5]:
            print(f"    - {issue[:140]}")
        if len(issues) > 5:
            print(f"    ... +{len(issues) - 5} more")

    if verbose_schemas:
        for schema in schemas:
            print(f"\n  [{schema['endpoint']}]")
            print(f"    introspection   : {schema['introspection_enabled']}")
            print(f"    types           : {schema['total_types']}")
            print(f"    queries         : {schema['total_queries']}")
            print(f"    mutations       : {schema['total_mutations']}")
            print(f"    batch_enabled   : {schema['batch_queries_enabled']}")
            print(f"    debug_mode      : {schema['debug_mode']}")
            if schema.get("sensitive_fields"):
                print(f"    sensitive_fields: {schema['sensitive_fields'][:5]}")
            if schema.get("playground_urls"):
                print(f"    playgrounds     : {schema['playground_urls']}")
            if schema.get("issues"):
                print(f"    issues ({len(schema['issues'])}):")
                for issue in schema["issues"][:5]:
                    print(f"      - {issue[:100]}")
    print(_sep())


# ══════════════════════════════════════════════════════════════
# 12. MAIN — validation + live tests
# ══════════════════════════════════════════════════════════════

def _run_validation_tests() -> bool:
    cases: list[tuple[str, dict]] = [
        ("PASS — no scheme",                 dict(target="example.com")),
        ("PASS — localhost blocked",         dict(target="http://localhost/graphql")),
        ("PASS — 127.0.0.1 blocked",         dict(target="http://127.0.0.1/graphql")),
        ("PASS — AWS IMDS blocked",          dict(target="http://169.254.169.254/graphql")),
        ("PASS — path traversal endpoint",   dict(target="http://localhost:8888/api",
                                                   endpoints=["/../etc/passwd"])),
        ("PASS — injection in endpoint",     dict(target="http://localhost:8888/api",
                                                   endpoints=["/graphql;drop"])),
        ("PASS — CRLF in header value",      dict(target="http://localhost:8888/api",
                                                   headers={"X-Evil": "val\r\nX-Injected: 1"})),
        ("PASS — timeout out of range",      dict(target="http://localhost:8888/api",
                                                   timeout=200)),
        ("PASS — max_depth out of range",    dict(target="http://localhost:8888/api",
                                                   max_depth=20)),
    ]

    print(f"\n{_sep('═')}")
    print("  VALIDATION TESTS  (all should fail with error)")
    print(_sep("═"))

    all_ok = True
    for label, kwargs in cases:
        result = graphql_recon(**kwargs)
        ok     = not result["success"] and bool(result["error"])
        if not ok:
            all_ok = False
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}  {label}")
        if not ok:
            print(f"         → unexpected: {result['error']}")

    print(f"\n  Validation suite: {'all passed ✅' if all_ok else 'FAILURES ❌'}")
    return all_ok


def _run_live_tests(verbose_schemas: bool = False) -> None:
    """
    Live tests against known public GraphQL endpoints.
    These may fail if the targets are down or have disabled introspection.
    """
    live_cases: list[tuple[str, dict]] = [
        # Public demo GraphQL APIs — safe to probe
        ("countries.trevorblades.com — public GraphQL (introspection ON)",
         dict(target="https://countries.trevorblades.com",
              endpoints=["/graphql", "/"],
              timeout=20)),
        ("spacex-production.up.railway.app — SpaceX API",
         dict(target="https://spacex-production.up.railway.app",
              endpoints=["/"],
              timeout=20)),
        ("swapi-graphql.netlify.app — Star Wars API",
         dict(target="https://swapi-graphql.netlify.app",
              endpoints=["/.netlify/functions/index"],
              timeout=20)),
    ]

    print(f"\n{_sep('═')}")
    print("  LIVE TESTS — public GraphQL APIs")
    print(_sep("═"))

    for label, kwargs in live_cases:
        _print_result(label, graphql_recon(**kwargs), verbose_schemas=verbose_schemas)


def _run_single_target(
    target: str,
    endpoints: Optional[list[str]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 20,
    max_depth: int = 5,
    verify_ssl: bool = False,
    emit_json: bool = False,
    verbose_schemas: bool = False,
) -> None:
    result = graphql_recon(
        target=target,
        endpoints=endpoints or [],
        headers=headers or {},
        timeout=timeout,
        max_depth=max_depth,
        verify_ssl=verify_ssl,
    )
    if emit_json:
        print(json.dumps(result, indent=2))
        return
    _print_result("LIVE TEST", result, verbose_schemas=verbose_schemas)


def main() -> None:
    # ── Configure your scan here ────────────────────────────────────────────
    TARGET = "https://countries.trevorblades.com"
    ENDPOINTS = ["/graphql"]
    HEADERS = {}
    TIMEOUT = 20
    MAX_DEPTH = 5
    VERIFY_SSL = False

    EMIT_JSON = False
    VERBOSE_SCHEMAS = False

    RUN_VALIDATION_TESTS = False
    RUN_PUBLIC_LIVE_TESTS = False
    # ────────────────────────────────────────────────────────────────────────

    if RUN_VALIDATION_TESTS:
        _run_validation_tests()
    if RUN_PUBLIC_LIVE_TESTS:
        _run_live_tests(verbose_schemas=VERBOSE_SCHEMAS)

    _run_single_target(
        target=TARGET,
        endpoints=ENDPOINTS,
        headers=HEADERS,
        timeout=TIMEOUT,
        max_depth=MAX_DEPTH,
        verify_ssl=VERIFY_SSL,
        emit_json=EMIT_JSON,
        verbose_schemas=VERBOSE_SCHEMAS,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)