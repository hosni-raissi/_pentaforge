import subprocess
import json
import re
import time
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

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

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"kiterunner", "ffuf", "graphql", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        bare_domain    = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_with_scheme = r"^https?://(\d{1,3}\.){3}\d{1,3}"

        if not (re.match(domain_pattern, v) or
                re.match(bare_domain, v)    or
                re.match(ip_with_scheme, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["-o", "--output", "-O", "-od"]

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
        for path in ["/graphiql", "/playground", "/altair", "/voyager"]:
            try:
                test_url = base.rstrip("/graphql").rstrip("/") + path
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
        if any(t in tags for t in ("admin", "debug", "config", "data", "actuator")):
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
) -> Optional[APIEndpoint]:
    """
    Probe a single API path and return an APIEndpoint if interesting.
    """
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
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

    # ── Phase 1: Probe all paths ──
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(probe_endpoint, target, path, "GET", headers, http_timeout): path
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
            ex.submit(probe_endpoint, target, path, "POST", headers, http_timeout): path
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
                                method, headers, http_timeout
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
            gql_paths_to_try.append(target.rstrip("/") + gp)

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
    kr scan outputs lines like:
      POST    403 [   287,   8,  1] https://example.com/api/v1/users
      GET     200 [ 12345, 120, 5] https://example.com/api/v1/health
    Also supports JSON output (kr scan --output-format json).
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
        Output: ["scan", "-w", "routes.kite", "--output-format", "json"]

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
            headers=headers,
        )
    except Exception as e:
        return APIDiscoveryResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target
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

        # Build default kiterunner command
        if req.args and req.args[0] in ("scan", "brute", "replay"):
            cmd = ["kr"] + list(req.args) + [target]
        else:
            cmd = [
                "kr", "scan", target,
                "-w", wl,
                "--output-format", "json",
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

        # Try external tool first
        external_tried = False
        for cli in ["graphql-introspect", "gql-cli", "graphql-voyager"]:
            cmd = [cli, target] + list(req.args)
            command_str = " ".join(cmd)
            stdout, stderr, rc = safe_execute(cmd, min(req.timeout, 60))
            raw_output = (stdout or stderr)[:5000]

            if rc == 0 and stdout.strip():
                parsed_gql = parse_graphql_voyager(stdout, target)
                graphql_infos.extend(parsed_gql)
                external_tried = True
                techniques_used.append(f"{cli}_scan")
                break

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

        if not command_str:
            command_str = f"graphql_probe({target})"

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
        endpoints=unique_eps,
        swagger_specs=swagger_specs,
        graphql_info=graphql_infos,
        interesting=interesting,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
        techniques_used=list(dict.fromkeys(techniques_used)),
    ).model_dump()


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
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 11. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # ─────────────────────────────
    # 1. Manual — full discovery
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="manual",
        target="https://api.example.com",
    )
    print("=== MANUAL FULL DISCOVERY ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Manual — with auth header
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="manual",
        target="https://api.example.com",
        headers={"Authorization": "Bearer your_token_here"},
        endpoints=["/api/v1/internal", "/api/admin/users"],
    )
    print("=== MANUAL WITH AUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Kiterunner — large routes
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="kiterunner",
        target="https://api.example.com",
        args=["scan", "-w", "routes-large.kite", "-x", "20",
              "--output-format", "json"],
    )
    print("=== KITERUNNER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. ffuf — recursive
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="ffuf",
        target="https://example.com",
        args=["-rate", "100", "-recursion", "-recursion-depth", "2",
              "-fc", "404"],
    )
    print("=== FFUF RECURSIVE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. GraphQL only
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="graphql",
        target="https://api.example.com",
    )
    print("=== GRAPHQL INTROSPECTION ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. GraphQL with auth
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="graphql",
        target="https://api.example.com",
        headers={"Authorization": "Bearer your_token"},
    )
    print("=== GRAPHQL WITH AUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. ffuf with custom wordlist
    # ─────────────────────────────
    r = api_endpoint_discovery(
        tool="ffuf",
        target="https://api.example.com",
        wordlist="/usr/share/wordlists/SecLists/Discovery/Web-Content/api"
                 "/api-endpoints.txt",
        args=["-mc", "200,201,301,401,403", "-rate", "50"],
        headers={"Cookie": "session=abc123"},
    )
    print("=== FFUF CUSTOM WORDLIST ===")
    print(json.dumps(r, indent=2))