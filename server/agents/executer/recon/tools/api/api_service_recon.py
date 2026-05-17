#/+
from __future__ import annotations

import json
import re
import sys
import time
import warnings
import logging
import shutil
import subprocess
import concurrent.futures
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any, Optional, Union, List, Dict
from urllib.parse import urlparse, urlunparse, urljoin

import requests
try:
    from urllib3.exceptions import InsecureRequestWarning
except Exception:
    InsecureRequestWarning = Warning

from pydantic import BaseModel, Field, field_validator
from server.agents.executer.recon.config import is_blocked_host

# Suppress SSL warnings globally for pentest use
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("api_service_recon")

# ===========================================================================
# SHARED UTILITIES
# ===========================================================================

def extract_host(url: str) -> str:
    """Extract hostname from URL without external dependencies."""
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
        m = re.match(r"https?://([^/:?#]+)", url.lower())
        if m:
            return m.group(1)
        return url.lower()
    except Exception:
        return url.lower()

def build_url(base: str, path: str) -> str:
    """Append path to base URL safely."""
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

def response_snippet(text: str, limit: int = 500) -> Optional[str]:
    """Return a snippet of the response text."""
    if not text:
        return None
    return text[:limit]

def safe_request(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: int,
    verify_tls: bool,
    allow_redirects: bool = True,
) -> Optional[requests.Response]:
    """Make an HTTP request safely."""
    try:
        return requests.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=allow_redirects,
        )
    except Exception as exc:
        log.debug("Request failed for %s: %s", url, exc)
        return None

def summarize_validation_error(exc: Exception) -> str:
    """Concise summary of Pydantic validation error."""
    try:
        from pydantic import ValidationError
        if isinstance(exc, ValidationError):
            msgs = [f"{e['loc'][-1]}: {e['msg']}" for e in exc.errors()]
            return "; ".join(msgs[:3])
    except Exception:
        pass
    return str(exc)

def validate_headers(headers: dict[str, str]) -> dict[str, str]:
    """Basic header validation."""
    DANGEROUS_CHARS = {"\r", "\n", "\x00"}
    HEADER_NAME_RE = re.compile(r"^[a-zA-Z0-9\-]+$")
    for name, val in headers.items():
        if not HEADER_NAME_RE.match(name):
            raise ValueError(f"Invalid header name: {name}")
        if any(c in str(val) for c in DANGEROUS_CHARS):
            raise ValueError(f"Dangerous characters in header value for {name}")
    return headers

def validate_http_target(target: str, allow_paths: bool = False) -> str:
    """Validate target URL."""
    v = target.strip()
    if not v:
        raise ValueError("Target must not be empty")
    if "://" not in v:
        v = "https://" + v
    parsed = urlparse(v)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme: {parsed.scheme}")
    host = parsed.hostname or ""
    if is_blocked_host(host):
        raise ValueError(f"Target host '{host}' is blocked")
    return target if allow_paths else f"{parsed.scheme}://{parsed.netloc}"

# ===========================================================================
# 1. GRAPHQL RECON
# ===========================================================================

_GQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/gql",
    "/api/graphql", "/api/gql", "/api/graphiql",
    "/v1/graphql", "/v2/graphql", "/v1/gql",
    "/query", "/playground", "/altair", "/voyager",
    "/graphql/console", "/graphql/playground",
    "/subscriptions", "/graphql/subscriptions",
    "/graphql/schema", "/graphql/v1", "/graphql/v2",
]

_GQL_PLAYGROUND_PATHS = [
    "/graphiql", "/playground", "/altair", "/voyager",
    "/graphql/playground", "/graphql/graphiql",
    "/api/graphiql", "/api/playground",
    "/graphql-playground", "/graphql-explorer",
]

_GQL_SENSITIVE_PATTERNS = frozenset({
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "auth_token", "access_token", "refresh_token", "credential",
    "private_key", "private", "ssn", "credit_card", "cvv", "pin",
    "otp", "hash", "salt", "seed", "signing_key", "jwt",
    "session_id", "session_token", "csrf", "nonce",
})

_GQL_DANGEROUS_MUTATION_KW = frozenset({
    "delete", "remove", "drop", "destroy", "reset",
    "admin", "escalate", "privilege", "role",
})

_GQL_DEBUG_KEYWORDS = frozenset({
    "traceback", "stack", "debug", "line ",
    "file ", ".py", ".js", "node_modules",
    "internal server", "development",
})

_GQL_PLAYGROUND_KEYWORDS = frozenset({
    "graphiql", "graphql playground", "altair",
    "voyager", "graphql-playground", "graphql ide",
    "__schema", "introspection",
})

_GQL_FULL_INTROSPECTION_QUERY = """
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

def _gql_post(url: str, body: Any, headers: dict[str, str], timeout: int, verify: bool) -> Optional[dict]:
    resp = safe_request("POST", url, headers, timeout, verify)
    if resp and resp.status_code in (200, 400):
        try:
            return resp.json()
        except Exception:
            return None
    return None

def _gql_resolve_type(type_obj: Optional[dict]) -> tuple[str, str]:
    if not type_obj: return "Unknown", "UNKNOWN"
    name, kind = type_obj.get("name"), type_obj.get("kind", "UNKNOWN")
    if name: return name, kind
    of_type = type_obj.get("ofType")
    return _gql_resolve_type(of_type) if of_type else ("Unknown", kind)

def _gql_run_introspection(url: str, headers: dict[str, str], timeout: int, verify: bool) -> GraphQLSchemaInfo:
    info = GraphQLSchemaInfo(endpoint=url)
    result = _gql_post(url, {"query": _GQL_FULL_INTROSPECTION_QUERY}, headers, timeout, verify)
    if not result:
        info.issues.append("Endpoint unreachable or returned non-JSON")
        return info
    schema = (result.get("data") or {}).get("__schema")
    if not schema:
        info.issues.append("Introspection disabled — endpoint exists but schema is hidden")
        return info
    info.introspection_enabled = True
    info.issues.append("CRITICAL: Introspection ENABLED — full schema publicly accessible")
    qt, mt, st = (schema.get("queryType") or {}).get("name"), (schema.get("mutationType") or {}).get("name"), (schema.get("subscriptionType") or {}).get("name")
    info.query_type, info.mutation_type, info.subscription_type = qt, mt, st
    for type_def in schema.get("types", []):
        type_name, type_kind = type_def.get("name", ""), type_def.get("kind", "")
        if type_name.startswith("__"): continue
        gql_type = GraphQLType(name=type_name, kind=type_kind)
        for field_def in (type_def.get("fields") or []):
            fname = field_def.get("name", "")
            ftype_name, ftype_kind = _gql_resolve_type(field_def.get("type"))
            gql_field = GraphQLField(name=fname, type_name=ftype_name, type_kind=ftype_kind,
                                    args=[a.get("name", "") for a in field_def.get("args", []) if isinstance(a, dict)],
                                    is_deprecated=field_def.get("isDeprecated", False),
                                    deprecation_reason=field_def.get("deprecationReason"))
            gql_type.fields.append(gql_field)
            if any(p in fname.lower() for p in _GQL_SENSITIVE_PATTERNS): info.sensitive_fields.append(f"{type_name}.{fname}")
            if type_name == qt: info.queries.append(gql_field)
            elif type_name == mt: info.mutations.append(gql_field)
            elif type_name == st: info.subscriptions.append(gql_field)
        info.types.append(gql_type)
    info.total_types, info.total_queries, info.total_mutations, info.total_subscriptions = len(info.types), len(info.queries), len(info.mutations), len(info.subscriptions)
    
    # Security checks
    batch_res = _gql_post(url, [{"query": "{ __typename }"}, {"query": "{ __typename }"}], headers, timeout, verify)
    info.batch_queries_enabled = isinstance(batch_res, list) and len(batch_res) >= 2
    if info.batch_queries_enabled: info.issues.append("Batch queries enabled — amplifies brute-force and DoS attacks")
    
    debug_res = _gql_post(url, {"query": "{ INVALID_QUERY_FOR_DEBUG_DETECTION }"}, headers, timeout, verify)
    if debug_res:
        for err in debug_res.get("errors", []):
            msg = str(err.get("message", "")).lower()
            ext = err.get("extensions", {})
            if any(kw in msg for kw in _GQL_DEBUG_KEYWORDS) or (isinstance(ext, dict) and ("stacktrace" in ext or "exception" in ext)):
                info.debug_mode = True
                info.issues.append("Debug mode detected — verbose error messages / stack traces exposed")
                break
    return info

def graphql_recon(target: str, endpoints: list[str] = [], headers: dict[str, str] = {}, timeout: int = 30, verify_ssl: bool = False) -> dict:
    start = time.monotonic()
    found: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(safe_request, "POST", target.rstrip("/") + p, {**{"Content-Type": "application/json"}, **headers}, timeout, verify_ssl, True): p for p in set(endpoints + _GQL_PATHS)}
        for future in as_completed(futures):
            resp = future.result()
            if resp and resp.status_code in (200, 400):
                try:
                    res = resp.json()
                    if "data" in res or "errors" in res: found.append(str(resp.url))
                except Exception: pass
    
    schemas: list[GraphQLSchemaInfo] = []
    for ep_url in set(found):
        info = _gql_run_introspection(ep_url, headers, timeout, verify_ssl)
        base = re.sub(r"/graphql.*$", "", ep_url)
        for p in _GQL_PLAYGROUND_PATHS:
            play_url = base.rstrip("/") + p
            resp = safe_request("GET", play_url, headers, timeout, verify_ssl)
            if resp and resp.status_code == 200 and any(kw in resp.text.lower() for kw in _GQL_PLAYGROUND_KEYWORDS):
                info.playground_urls.append(play_url)
        if info.playground_urls: info.issues.append(f"GraphQL IDE/playground exposed: {', '.join(info.playground_urls[:3])}")
        schemas.append(info)
    
    return {
        "success": any(s.introspection_enabled or s.issues for s in schemas),
        "target": target,
        "endpoints_found": len(schemas),
        "schemas": [s.model_dump() for s in schemas],
        "all_issues": list(dict.fromkeys([iss for s in schemas for iss in s.issues])),
        "execution_time": round(time.monotonic() - start, 2)
    }

# ===========================================================================
# 2. GRPC RECON
# ===========================================================================

GRPC_HTTP_PROBE_PATHS = ["/grpc", "/grpc-web", "/grpc.health.v1.Health/Check", "/healthz", "/health"]
GRPC_SENSITIVE_PATTERNS = ["admin", "debug", "secret", "token", "password", "delete", "execute", "upload", "internal", "private"]
RPC_RE = re.compile(r"rpc\s+([A-Za-z0-9_]+)\s*\(\s*(stream\s+)?([A-Za-z0-9_.]+)\s*\)\s*returns\s*\(\s*(stream\s+)?([A-Za-z0-9_.]+)", re.MULTILINE)

class GRPCMethod(BaseModel):
    service: str; name: str; request_type: Optional[str] = None; response_type: Optional[str] = None; streaming: bool = False; sensitive: bool = False

class GRPCService(BaseModel):
    name: str; methods: list[GRPCMethod] = []; raw_description: Optional[str] = None; sensitive: bool = False

class GRPCFinding(BaseModel):
    title: str; severity: str = "info"; description: str; evidence: list[str] = []

def grpc_recon(target: str, headers: dict[str, str] = {}, timeout: int = 30, verify_tls: bool = True, use_plaintext: bool = False) -> dict:
    start = time.monotonic()
    parsed = urlparse(target if "://" in target else "http://" + target)
    host, use_tls = parsed.hostname or "", parsed.scheme.lower() == "https"
    port = parsed.port or (443 if use_tls else 80)
    authority = f"{host}:{port}"
    
    probes: list[dict] = []
    for p in GRPC_HTTP_PROBE_PATHS:
        url = build_url(target if "://" in target else f"http{'s' if use_tls else ''}://{target}", p)
        resp = safe_request("GET", url, headers, timeout, verify_tls)
        if resp:
            inds = [m for m in ("application/grpc", "grpc-status", "grpc-message", "grpc-web") if m in (resp.headers.get("content-type", "") + resp.text[:500]).lower()]
            probes.append({"url": url, "status": resp.status_code, "indicators": inds})
    
    web_exposed = any(p["indicators"] for p in probes)
    services: list[GRPCService] = []
    reflection = False
    
    if shutil.which("grpcurl"):
        base_cmd = ["grpcurl", "-max-time", str(timeout)]
        if use_plaintext or not use_tls: base_cmd.append("-plaintext")
        elif not verify_tls: base_cmd.append("-insecure")
        for k, v in headers.items(): base_cmd.extend(["-H", f"{k}: {v}"])
        base_cmd.append(authority)
        
        cp = subprocess.run(base_cmd + ["list"], capture_output=True, text=True, timeout=timeout)
        if cp.returncode == 0:
            reflection = True
            for svc_name in [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]:
                dcp = subprocess.run(base_cmd + ["describe", svc_name], capture_output=True, text=True, timeout=timeout)
                methods = [GRPCMethod(service=svc_name, name=m.group(1), request_type=m.group(3), response_type=m.group(5), streaming=bool(m.group(2) or m.group(4)), sensitive=any(p in f"{svc_name}.{m.group(1)}".lower() for p in GRPC_SENSITIVE_PATTERNS)) for m in RPC_RE.finditer(dcp.stdout)]
                services.append(GRPCService(name=svc_name, methods=methods, sensitive=any(p in svc_name.lower() for p in GRPC_SENSITIVE_PATTERNS) or any(m.sensitive for m in methods)))

    findings: list[GRPCFinding] = []
    if reflection: findings.append(GRPCFinding(title="gRPC server reflection enabled", severity="medium", description="Reflection allows easy enumeration of services.", evidence=[s.name for s in services[:5]]))
    if any(s.name == "grpc.health.v1.Health" for s in services): findings.append(GRPCFinding(title="Health check service exposed", severity="low", description="Standard health service is reachable."))
    if web_exposed: findings.append(GRPCFinding(title="gRPC-web surface detected", severity="info", description="HTTP probes found gRPC-web indicators."))
    if (use_plaintext or not use_tls) and (reflection or web_exposed): findings.append(GRPCFinding(title="Plaintext gRPC transport allowed", severity="high", description="Unencrypted gRPC connections are accepted."))
    
    return {
        "success": reflection or web_exposed,
        "detected": reflection or web_exposed,
        "target": target,
        "authority": authority,
        "reflection_enabled": reflection,
        "services": [s.model_dump() for s in services],
        "findings": [f.model_dump() for f in findings],
        "execution_time": round(time.monotonic() - start, 2)
    }

# ===========================================================================
# 3. SOAP/WSDL RECON
# ===========================================================================

WSDL_PATHS = ["/service?wsdl", "/soap?wsdl", "/api?wsdl", "/wsdl", "/service.wsdl", "/soap", "/webservice?wsdl", "/xmlrpc.php"]
SOAP_SENSITIVE = ["admin", "debug", "delete", "execute", "token", "secret", "password", "upload"]

class SOAPOperation(BaseModel):
    name: str; sensitive: bool = False
class WSDLDocument(BaseModel):
    url: str; services: list[str] = []; operations: list[SOAPOperation] = []; issues: list[str] = []

def soap_wsdl_recon(target: str, endpoints: list[str] = [], headers: dict[str, str] = {}, timeout: int = 30, verify_tls: bool = True) -> dict:
    start = time.monotonic()
    docs: list[WSDLDocument] = []
    seen: set[str] = set()
    base = target.rstrip("/")
    candidates = [build_url(base, p) for p in set(WSDL_PATHS + endpoints)]
    
    for url in candidates:
        if url in seen: continue
        seen.add(url)
        resp = safe_request("GET", url, headers, timeout, verify_tls)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            if "<definitions" in body.lower() or "wsdl:" in body.lower():
                doc = WSDLDocument(url=url)
                try:
                    root = ET.fromstring(body)
                    ns = {"wsdl": "http://schemas.xmlsoap.org/wsdl/"}
                    doc.services = [s.attrib.get("name", "unknown") for s in root.findall(".//wsdl:service", ns)]
                    for pt in root.findall(".//wsdl:portType", ns):
                        for op in pt.findall("wsdl:operation", ns):
                            name = op.attrib.get("name", "unknown")
                            doc.operations.append(SOAPOperation(name=name, sensitive=any(p in name.lower() for p in SOAP_SENSITIVE)))
                    if doc.services: doc.issues.append("Public WSDL exposed")
                    if any(op.sensitive for op in doc.operations): doc.issues.append("Sensitive SOAP operations found")
                    docs.append(doc)
                except Exception: pass

    findings = []
    if docs: findings.append({"title": "Public WSDL exposed", "severity": "medium", "description": "WSDL accessible without auth.", "evidence": [d.url for d in docs]})
    
    return {
        "success": bool(docs),
        "target": target,
        "wsdl_documents": [d.model_dump() for d in docs],
        "findings": findings,
        "execution_time": round(time.monotonic() - start, 2)
    }

# ===========================================================================
# 4. UNIFIED ORCHESTRATOR
# ===========================================================================

class APIServiceReconRequest(BaseModel):
    target: str
    protocols: list[str] = ["graphql", "grpc", "soap_wsdl"]
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=5, le=180)
    verify_tls: bool = True

class APIServiceReconResult(BaseModel):
    success: bool
    target: str
    http_target: Optional[str] = None
    grpc_target: Optional[str] = None
    protocols_checked: list[str] = []
    protocols_with_findings: list[str] = []
    findings_summary: list[str] = []
    graphql: Optional[dict] = None
    grpc: Optional[dict] = None
    soap_wsdl: Optional[dict] = None
    error: Optional[str] = None
    execution_time: float = 0.0

def _infer_http_target(target: str) -> str:
    """Ensure the target has an http/https scheme."""
    if "://" in target:
        return target
    return f"https://{target.lstrip('/')}"

def api_service_recon(
    target: str,
    protocols: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    verify_tls: bool = True,
) -> dict:
    """Unified API service reconnaissance across GraphQL, gRPC, and SOAP/WSDL."""
    start = time.monotonic()
    protocols = protocols or ["graphql", "grpc", "soap_wsdl"]
    headers = headers or {}
    allowed_protocols = {"graphql", "grpc", "soap_wsdl"}
    unsupported = [name for name in protocols if name not in allowed_protocols]
    if unsupported:
        return APIServiceReconResult(
            success=False,
            target=target,
            protocols_checked=list(protocols),
            error=f"Unsupported protocol(s): {', '.join(unsupported)}",
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    # Pre-validate and infer targets
    http_target = _infer_http_target(target)
    grpc_target = target

    results: dict[str, Any] = APIServiceReconResult(
        target=target,
        success=False,
        http_target=http_target,
        grpc_target=grpc_target,
        protocols_checked=list(protocols),
        protocols_with_findings=[],
        findings_summary=[],
        execution_time=0.0,
    ).model_dump()

    if "graphql" in protocols:
        results["graphql"] = graphql_recon(
            target=http_target,
            headers=headers,
            timeout=timeout,
            verify_ssl=not verify_tls,
        )
        if results["graphql"].get("success"):
            results["success"] = True
            results["protocols_with_findings"].append("graphql")
            results["findings_summary"].append(
                f"GraphQL: {len(results['graphql'].get('all_issues', []))} issues detected"
            )

    if "grpc" in protocols:
        results["grpc"] = grpc_recon(
            target=grpc_target,
            headers=headers,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if results["grpc"].get("success"):
            results["success"] = True
            results["protocols_with_findings"].append("grpc")
            results["findings_summary"].append(
                f"gRPC: {len(results['grpc'].get('findings', []))} findings detected"
            )

    if "soap_wsdl" in protocols:
        results["soap_wsdl"] = soap_wsdl_recon(
            target=http_target,
            headers=headers,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if results["soap_wsdl"].get("success"):
            results["success"] = True
            results["protocols_with_findings"].append("soap_wsdl")
            results["findings_summary"].append(
                f"SOAP: {len(results['soap_wsdl'].get('findings', []))} findings detected"
            )

    results["execution_time"] = round(time.monotonic() - start, 2)
    return results

API_SERVICE_RECON_TOOL_DEFINITION = {
    "name": "api_service_recon",
    "description": "Run unified API service reconnaissance across GraphQL, gRPC, and SOAP/WSDL. Aggregates protocol-specific findings into one focused service-surface result.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base target, e.g. 'https://api.example.com'"},
            "protocols": {"type": "array", "items": {"type": "string", "enum": ["graphql", "grpc", "soap_wsdl"]}},
            "headers": {"type": "object", "description": "Optional HTTP headers"},
            "timeout": {"type": "integer", "default": 30},
            "verify_tls": {"type": "boolean", "default": True}
        },
        "required": ["target"]
    }
}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python api_service_recon.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    print(f"[*] Starting unified API recon for: {target}")
    res = api_service_recon(target)
    print(json.dumps(res, indent=2))
