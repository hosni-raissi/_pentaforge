import json
import re
import time
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

DANGEROUS_CHARS = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']

BLOCKED_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "169.254.169.254", "metadata.google.internal",
]


class GraphQLReconRequest(BaseModel):
    target: str
    endpoints: list[str] = []
    headers: dict[str, str] = {}
    timeout: int = Field(default=30, ge=5, le=120)
    max_depth: int = Field(default=5, ge=1, le=10)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        cleaned = v.strip()
        for blocked in BLOCKED_TARGETS:
            if blocked in cleaned:
                raise ValueError(f"Target '{cleaned}' is blocked (internal/reserved)")
        if not re.match(r"^https?://[a-zA-Z0-9]", cleaned):
            raise ValueError(f"Target must start with http:// or https://")
        return cleaned


class GraphQLField(BaseModel):
    name: str
    type_name: Optional[str] = None
    type_kind: Optional[str] = None
    args: list[str] = []
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None


class GraphQLType(BaseModel):
    name: str
    kind: str
    fields: list[GraphQLField] = []
    enum_values: list[str] = []
    interfaces: list[str] = []
    possible_types: list[str] = []


class GraphQLSchemaInfo(BaseModel):
    endpoint: str
    introspection_enabled: bool = False
    query_type: Optional[str] = None
    mutation_type: Optional[str] = None
    subscription_type: Optional[str] = None
    types: list[GraphQLType] = []
    queries: list[GraphQLField] = []
    mutations: list[GraphQLField] = []
    subscriptions: list[GraphQLField] = []
    directives: list[str] = []
    total_types: int = 0
    total_queries: int = 0
    total_mutations: int = 0
    total_subscriptions: int = 0
    sensitive_fields: list[str] = []
    batch_queries_enabled: bool = False
    debug_mode: bool = False
    playground_urls: list[str] = []
    issues: list[str] = []


class GraphQLReconResult(BaseModel):
    success: bool
    target: str
    endpoints_probed: int = 0
    endpoints_found: int = 0
    schemas: list[GraphQLSchemaInfo] = []
    all_sensitive_fields: list[str] = []
    all_issues: list[str] = []
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. INTROSPECTION QUERIES
# ══════════════════════════════════════════════════════════════

FULL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    directives {
      name
      description
      locations
      args { name type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
    }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args {
          name
          type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
        }
        type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
      }
      inputFields {
        name
        type { name kind ofType { name kind ofType { name kind } } }
      }
      interfaces { name }
      enumValues(includeDeprecated: true) { name isDeprecated deprecationReason }
      possibleTypes { name }
    }
  }
}
"""

SIMPLE_PROBE_QUERY = '{"query":"{ __typename }"}'

FIELD_SUGGESTION_QUERY = '{"query":"{ __type(name: \\"%s\\") { name fields { name } } }"}'

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/gql",
    "/api/graphql", "/api/gql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/v1/gql",
    "/query", "/playground", "/altair", "/voyager",
    "/graphql/console", "/graphql/playground",
    "/subscriptions", "/graphql/subscriptions",
    "/graphql/schema", "/graphql/v1", "/graphql/v2",
]

# Playground / IDE paths
PLAYGROUND_PATHS = [
    "/graphiql", "/playground", "/altair", "/voyager",
    "/graphql/playground", "/graphql/graphiql",
    "/api/graphiql", "/api/playground",
    "/graphql-playground", "/graphql-explorer",
]

SENSITIVE_FIELD_PATTERNS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "auth_token", "access_token", "refresh_token", "credential",
    "private_key", "private", "ssn", "credit_card", "cvv", "pin",
    "otp", "key", "hash", "salt", "seed", "signing_key", "jwt",
    "session_id", "session_token", "csrf", "nonce",
]


# ══════════════════════════════════════════════════════════════
# 3. CORE FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _make_request(url: str, query: str, headers: dict,
                  timeout: int = 10) -> Optional[dict]:
    """Send GraphQL query and return parsed JSON response."""
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
        **headers,
    }

    try:
        if isinstance(query, str) and query.strip().startswith("{"):
            # Already JSON
            data = query
        else:
            data = json.dumps({"query": query})

        resp = requests.post(
            url, data=data, headers=req_headers,
            timeout=timeout, verify=False, allow_redirects=True,
        )

        if resp.status_code not in (200, 400):
            return None

        ct = resp.headers.get("content-type", "")
        if "json" not in ct and "graphql" not in ct:
            # Try parsing anyway
            try:
                return resp.json()
            except Exception:
                return None

        return resp.json()

    except Exception:
        return None


def _resolve_type_name(type_obj: Optional[dict]) -> tuple[str, str]:
    """Recursively resolve GraphQL type name and kind from nested ofType."""
    if not type_obj:
        return "Unknown", "UNKNOWN"

    name = type_obj.get("name")
    kind = type_obj.get("kind", "UNKNOWN")

    if name:
        return name, kind

    of_type = type_obj.get("ofType")
    if of_type:
        return _resolve_type_name(of_type)

    return "Unknown", kind


def _check_sensitive_field(type_name: str, field_name: str) -> bool:
    """Check if a field name matches sensitive patterns."""
    lower = field_name.lower()
    for pattern in SENSITIVE_FIELD_PATTERNS:
        if pattern in lower:
            return True
    return False


def _probe_endpoint(base_url: str, path: str, headers: dict,
                    timeout: int) -> Optional[str]:
    """Probe a potential GraphQL endpoint. Returns URL if valid."""
    url = base_url.rstrip("/") + path
    result = _make_request(url, SIMPLE_PROBE_QUERY, headers, timeout)

    if result and ("data" in result or "errors" in result):
        return url
    return None


def _discover_endpoints(base_url: str, custom_endpoints: list[str],
                        headers: dict, timeout: int) -> list[str]:
    """Discover GraphQL endpoints on the target."""
    found = []
    paths_to_try = list(set(custom_endpoints + GRAPHQL_PATHS))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(
                _probe_endpoint, base_url, path, headers, timeout
            ): path
            for path in paths_to_try
        }

        for future in concurrent.futures.as_completed(futures, timeout=timeout * 2):
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    return list(set(found))


def _check_batch_queries(url: str, headers: dict,
                         timeout: int) -> bool:
    """Check if batch queries are enabled."""
    batch_payload = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]

    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **headers,
    }

    try:
        resp = requests.post(
            url, json=batch_payload, headers=req_headers,
            timeout=timeout, verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            return isinstance(data, list) and len(data) >= 2
    except Exception:
        pass

    return False


def _check_debug_mode(url: str, headers: dict, timeout: int) -> bool:
    """Check for debug/development mode indicators."""
    debug_queries = [
        '{"query":"{ __schema { description } }"}',
        '{"query":"{"}',  # Malformed — check error verbosity
    ]

    for query in debug_queries:
        result = _make_request(url, query, headers, timeout)
        if result:
            errors = result.get("errors", [])
            for err in errors:
                msg = str(err.get("message", "")).lower()
                # Debug mode often returns stack traces or verbose errors
                if any(kw in msg for kw in [
                    "traceback", "stack", "debug", "line ",
                    "file ", ".py", ".js", "node_modules",
                    "internal server", "development",
                ]):
                    return True

                # Check for extensions with debug info
                ext = err.get("extensions", {})
                if "stacktrace" in ext or "exception" in ext:
                    return True

    return False


def _discover_playgrounds(base_url: str, headers: dict,
                          timeout: int) -> list[str]:
    """Find exposed GraphQL playgrounds and IDEs."""
    found = []

    for path in PLAYGROUND_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(
                url, headers={**headers, "User-Agent": "Mozilla/5.0"},
                timeout=timeout, verify=False, allow_redirects=True,
            )
            if resp.status_code == 200:
                content = resp.text.lower()
                if any(kw in content for kw in [
                    "graphiql", "graphql playground", "altair",
                    "voyager", "graphql-playground", "graphql ide",
                    "__schema", "introspection",
                ]):
                    found.append(url)
        except Exception:
            pass

    return found


def _run_introspection(url: str, headers: dict,
                       timeout: int) -> GraphQLSchemaInfo:
    """Full introspection analysis of a GraphQL endpoint."""
    info = GraphQLSchemaInfo(endpoint=url)

    # 1. Full introspection
    result = _make_request(url, FULL_INTROSPECTION_QUERY, headers, timeout)

    if not result:
        info.issues.append("Endpoint unreachable or returned non-JSON")
        return info

    schema = (result.get("data") or {}).get("__schema")

    if not schema:
        errors = result.get("errors", [])
        if errors:
            info.issues.append(
                "Introspection disabled — endpoint exists but schema hidden"
            )
            for err in errors:
                msg = err.get("message", "")
                if msg:
                    info.issues.append(f"Error: {msg[:200]}")
        return info

    # Introspection is enabled
    info.introspection_enabled = True
    info.issues.append(
        "CRITICAL: GraphQL introspection is ENABLED — "
        "full schema is publicly accessible"
    )

    # Root types
    qt = schema.get("queryType") or {}
    mt = schema.get("mutationType") or {}
    st = schema.get("subscriptionType") or {}
    info.query_type = qt.get("name")
    info.mutation_type = mt.get("name")
    info.subscription_type = st.get("name")

    # Directives
    for directive in schema.get("directives", []):
        name = directive.get("name", "")
        if name:
            info.directives.append(name)

    # Parse all types
    for type_def in schema.get("types", []):
        type_name = type_def.get("name", "")
        type_kind = type_def.get("kind", "")

        # Skip introspection built-ins
        if type_name.startswith("__"):
            continue

        gql_type = GraphQLType(
            name=type_name,
            kind=type_kind,
        )

        # Fields
        for field_def in type_def.get("fields") or []:
            fname = field_def.get("name", "")
            ftype_name, ftype_kind = _resolve_type_name(field_def.get("type"))
            fargs = [
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

            # Check for sensitive fields
            if _check_sensitive_field(type_name, fname):
                info.sensitive_fields.append(f"{type_name}.{fname}")

            # Classify as query / mutation / subscription
            if type_name == info.query_type:
                info.queries.append(gql_field)
            elif type_name == info.mutation_type:
                info.mutations.append(gql_field)
            elif type_name == info.subscription_type:
                info.subscriptions.append(gql_field)

        # Enum values
        for ev in type_def.get("enumValues") or []:
            if isinstance(ev, dict):
                gql_type.enum_values.append(ev.get("name", ""))

        # Interfaces
        for iface in type_def.get("interfaces") or []:
            if isinstance(iface, dict):
                gql_type.interfaces.append(iface.get("name", ""))

        # Possible types (unions)
        for pt in type_def.get("possibleTypes") or []:
            if isinstance(pt, dict):
                gql_type.possible_types.append(pt.get("name", ""))

        info.types.append(gql_type)

    info.total_types = len(info.types)
    info.total_queries = len(info.queries)
    info.total_mutations = len(info.mutations)
    info.total_subscriptions = len(info.subscriptions)

    # 2. Check batch queries
    info.batch_queries_enabled = _check_batch_queries(url, headers, timeout)
    if info.batch_queries_enabled:
        info.issues.append(
            "Batch queries enabled — can amplify brute-force and DoS attacks"
        )

    # 3. Check debug mode
    info.debug_mode = _check_debug_mode(url, headers, timeout)
    if info.debug_mode:
        info.issues.append(
            "Debug/development mode detected — verbose error messages exposed"
        )

    # 4. Sensitive fields summary
    if info.sensitive_fields:
        info.issues.append(
            f"Sensitive fields exposed in schema: "
            f"{', '.join(info.sensitive_fields[:10])}"
        )

    # 5. Deprecated fields still in schema
    deprecated = [
        f"{t.name}.{f.name}"
        for t in info.types for f in t.fields if f.is_deprecated
    ]
    if deprecated:
        info.issues.append(
            f"{len(deprecated)} deprecated fields still in schema: "
            f"{', '.join(deprecated[:5])}"
        )

    # 6. Mutation analysis
    dangerous_mutations = []
    for m in info.mutations:
        lower = m.name.lower()
        if any(kw in lower for kw in [
            "delete", "remove", "drop", "destroy", "reset",
            "admin", "escalate", "privilege", "role",
        ]):
            dangerous_mutations.append(m.name)

    if dangerous_mutations:
        info.issues.append(
            f"Potentially dangerous mutations: "
            f"{', '.join(dangerous_mutations[:5])}"
        )

    return info


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def graphql_recon(
    target: str,
    endpoints: list[str] = [],
    headers: dict[str, str] = {},
    timeout: int = 30,
    max_depth: int = 5,
) -> dict:
    """
    🔍 Agent Tool: GraphQL Reconnaissance

    Non-intrusive reconnaissance of GraphQL endpoints.
    Discovers endpoints, runs introspection, extracts schema,
    and identifies security issues.

    Args:
        target:     Base URL (e.g., "https://example.com")
        endpoints:  Custom endpoint paths to probe (in addition to defaults)
        headers:    Custom HTTP headers (e.g., Authorization)
        timeout:    Timeout per request in seconds
        max_depth:  Max type recursion depth for schema parsing

    Returns:
        Structured JSON with schemas, fields, issues, and sensitive data.
    """
    start = time.time()

    # Validate
    try:
        req = GraphQLReconRequest(
            target=target, endpoints=endpoints,
            headers=headers, timeout=timeout,
            max_depth=max_depth,
        )
    except Exception as e:
        return GraphQLReconResult(
            success=False, target=target,
            error=f"Validation: {e}",
        ).model_dump()

    # Discover endpoints
    discovered = _discover_endpoints(
        req.target, req.endpoints, req.headers, req.timeout
    )

    if not discovered:
        return GraphQLReconResult(
            success=False, target=target,
            endpoints_probed=len(GRAPHQL_PATHS) + len(req.endpoints),
            error="No GraphQL endpoints found",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # Run introspection on each found endpoint
    schemas = []
    all_sensitive = []
    all_issues = []

    for endpoint_url in discovered:
        schema_info = _run_introspection(
            endpoint_url, req.headers, req.timeout
        )

        # Discover playgrounds for this base
        base = re.sub(r"/graphql.*$", "", endpoint_url)
        schema_info.playground_urls = _discover_playgrounds(
            base, req.headers, req.timeout
        )
        if schema_info.playground_urls:
            schema_info.issues.append(
                f"GraphQL playground/IDE exposed: "
                f"{', '.join(schema_info.playground_urls[:3])}"
            )

        schemas.append(schema_info)
        all_sensitive.extend(schema_info.sensitive_fields)
        all_issues.extend(schema_info.issues)

    return GraphQLReconResult(
        success=True,
        target=target,
        endpoints_probed=len(GRAPHQL_PATHS) + len(req.endpoints),
        endpoints_found=len(discovered),
        schemas=schemas,
        all_sensitive_fields=list(set(all_sensitive)),
        all_issues=all_issues,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

GRAPHQL_RECON_TOOL_DEFINITION = {
    "name": "graphql_recon",
    "description": (
        "Discover and analyze GraphQL endpoints. Probes for introspection, "
        "extracts full schema (queries, mutations, subscriptions, types), "
        "detects sensitive fields, batch query support, debug mode, and "
        "exposed playgrounds/IDEs. Non-intrusive reconnaissance only."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL (e.g., https://example.com)",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Custom endpoint paths to probe in addition to defaults "
                    "(e.g., ['/custom/graphql'])"
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Custom HTTP headers (e.g., "
                    '{"Authorization": "Bearer <token>"})'
                ),
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout per request in seconds (default: 30)",
            },
            "max_depth": {
                "type": "integer",
                "description": "Max type recursion depth (default: 5)",
            },
        },
        "required": ["target"],
    },
}
