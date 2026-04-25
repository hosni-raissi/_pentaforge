#/+
from __future__ import annotations

import json
import re
import time
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlparse, urlencode, parse_qs
from server.agents.executer.recon.tools.api._common import (
    extract_host,
)


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════
import os

from server.agents.executer.recon.config import is_blocked_host


class OAuthCheckRequest(BaseModel):
    target: str
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=5, le=120)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        cleaned = v.strip()
        host = extract_host(cleaned)
        
        if host == "localhost" or host == "127.0.0.1" or host == "::1":
            if os.getenv("PENTAFORGE_ALLOW_LOCAL_API_TARGETS") != "1":
                raise ValueError(f"Target '{v}' is blocked. Set PENTAFORGE_ALLOW_LOCAL_API_TARGETS=1 to test localhost.")
            if not re.match(r"^https?://[a-zA-Z0-9]", cleaned):
                raise ValueError("Target must start with http:// or https://")
            return cleaned

        host_lower = host.lower()
        if is_blocked_host(host_lower):
            raise ValueError(f"Target '{v}' is blocked.")

        if not re.match(r"^https?://[a-zA-Z0-9]", cleaned):
            raise ValueError("Target must start with http:// or https://")
        return cleaned


class OIDCConfig(BaseModel):
    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    registration_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None
    scopes_supported: list[str] = []
    response_types_supported: list[str] = []
    grant_types_supported: list[str] = []
    token_endpoint_auth_methods: list[str] = []
    code_challenge_methods_supported: list[str] = []
    claims_supported: list[str] = []
    id_token_signing_alg_values: list[str] = []


class JWKSInfo(BaseModel):
    url: str
    keys_count: int = 0
    algorithms: list[str] = []
    key_types: list[str] = []
    key_ids: list[str] = []
    weak_keys: list[str] = []
    issues: list[str] = []


class OAuthEndpointCheck(BaseModel):
    url: str
    status_code: Optional[int] = None
    accessible: bool = False
    requires_auth: bool = False
    supports_cors: bool = False
    issues: list[str] = []


class OAuthFlowCheck(BaseModel):
    flow_type: str
    supported: bool = False
    issues: list[str] = []


class OAuthCheckResult(BaseModel):
    success: bool
    target: str
    oidc_config: Optional[OIDCConfig] = None
    oidc_config_url: Optional[str] = None
    jwks_info: Optional[JWKSInfo] = None
    endpoint_checks: list[OAuthEndpointCheck] = []
    flow_checks: list[OAuthFlowCheck] = []
    observations: list[str] = []
    redirect_issues: list[str] = []
    token_issues: list[str] = []
    all_issues: list[str] = []
    severity: str = "info"
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. OIDC DISCOVERY PATHS
# ══════════════════════════════════════════════════════════════

OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/realms/master/.well-known/openid-configuration",
    "/.well-known/openid-configuration/",
    "/identity/.well-known/openid-configuration",
    "/connect/.well-known/openid-configuration",
    "/v1/.well-known/openid-configuration",
    "/v2/.well-known/openid-configuration",
    "/oauth2/.well-known/openid-configuration",
]

JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/jwks", "/jwks.json",
    "/oauth/jwks", "/.well-known/jwks",
    "/protocol/openid-connect/certs",
    "/oauth2/v1/keys", "/oauth2/v2/keys",
    "/connect/jwk_uri", "/discovery/keys",
]

OAUTH_ENDPOINT_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/oauth/token", "/oauth2/token", "/token",
    "/oauth/revoke", "/oauth2/revoke", "/revoke",
    "/oauth/introspect", "/oauth2/introspect", "/introspect",
    "/oauth/register", "/oauth2/register", "/register",
    "/oauth/userinfo", "/oauth2/userinfo", "/userinfo",
    "/oauth/callback", "/oauth2/callback", "/callback",
    "/oauth/device", "/oauth2/device",
    "/logout", "/oauth/logout", "/oauth2/logout",
    "/auth/login", "/auth/authorize",
]


# ══════════════════════════════════════════════════════════════
# 3. CORE FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _safe_get(url: str, headers: dict, timeout: int) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                "Accept": "application/json",
                **headers,
            },
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except Exception:
        return None


def _candidate_base_urls(target: str) -> list[str]:
    base = target.rstrip("/")
    candidates = [base]
    parsed = urlparse(base)
    if parsed.path and parsed.path != "/" and parsed.scheme and parsed.netloc:
        host_root = f"{parsed.scheme}://{parsed.netloc}"
        if host_root not in candidates:
            candidates.append(host_root)
    return candidates


def _discover_oidc_config(
    base_url: str, headers: dict, timeout: int
) -> tuple[Optional[OIDCConfig], Optional[str]]:
    for candidate_base in _candidate_base_urls(base_url):
        for path in OIDC_DISCOVERY_PATHS:
            url = candidate_base + path
            resp = _safe_get(url, headers, timeout)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "issuer" in data or "authorization_endpoint" in data:
                        return OIDCConfig(
                            issuer=data.get("issuer"),
                            authorization_endpoint=data.get("authorization_endpoint"),
                            token_endpoint=data.get("token_endpoint"),
                            userinfo_endpoint=data.get("userinfo_endpoint"),
                            jwks_uri=data.get("jwks_uri"),
                            registration_endpoint=data.get("registration_endpoint"),
                            revocation_endpoint=data.get("revocation_endpoint"),
                            introspection_endpoint=data.get("introspection_endpoint"),
                            end_session_endpoint=data.get("end_session_endpoint"),
                            scopes_supported=data.get("scopes_supported", []),
                            response_types_supported=data.get("response_types_supported", []),
                            grant_types_supported=data.get("grant_types_supported", []),
                            token_endpoint_auth_methods=data.get(
                                "token_endpoint_auth_methods_supported", []
                            ),
                            code_challenge_methods_supported=data.get(
                                "code_challenge_methods_supported", []
                            ),
                            claims_supported=data.get("claims_supported", []),
                            id_token_signing_alg_values=data.get(
                                "id_token_signing_alg_values_supported", []
                            ),
                        ), url
                except Exception:
                    pass
    return None, None


def _analyze_jwks(jwks_url: str, headers: dict, timeout: int) -> Optional[JWKSInfo]:
    resp = _safe_get(jwks_url, headers, timeout)
    if not resp or resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        return None

    keys = data.get("keys", [])
    info = JWKSInfo(url=jwks_url, keys_count=len(keys))

    for key in keys:
        alg = key.get("alg", "unknown")
        kty = key.get("kty", "unknown")
        kid = key.get("kid", "")
        if alg not in info.algorithms:
            info.algorithms.append(alg)
        if kty not in info.key_types:
            info.key_types.append(kty)
        if kid:
            info.key_ids.append(kid)
        if kty == "RSA":
            n = key.get("n", "")
            if n and len(n) < 342:
                info.weak_keys.append(f"RSA key '{kid}' may be < 2048 bits")
                info.issues.append(f"Weak RSA key size detected (kid: {kid})")
        if alg in ("HS256", "HS384", "HS512"):
            info.issues.append(
                f"Symmetric algorithm '{alg}' in JWKS — "
                f"verify shared secret is not exposed"
            )
        if alg == "none":
            info.issues.append(
                "CRITICAL: 'none' algorithm found in JWKS — "
                "tokens can be forged without signature"
            )

    if not keys:
        info.issues.append("JWKS endpoint exists but contains no keys")

    return info


def _discover_jwks(
    base_url: str, oidc_config: Optional[OIDCConfig], headers: dict, timeout: int
) -> Optional[JWKSInfo]:
    if oidc_config and oidc_config.jwks_uri:
        result = _analyze_jwks(oidc_config.jwks_uri, headers, timeout)
        if result:
            return result
    for candidate_base in _candidate_base_urls(base_url):
        for path in JWKS_PATHS:
            result = _analyze_jwks(candidate_base + path, headers, timeout)
            if result:
                return result
    return None


def _check_endpoints(
    base_url: str, oidc_config: Optional[OIDCConfig], headers: dict, timeout: int
) -> list[OAuthEndpointCheck]:
    endpoints_to_check: set[str] = set()
    if oidc_config:
        for attr in (
            "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
            "registration_endpoint", "revocation_endpoint", "introspection_endpoint",
        ):
            val = getattr(oidc_config, attr, None)
            if val:
                endpoints_to_check.add(val)
    for candidate_base in _candidate_base_urls(base_url):
        for path in OAUTH_ENDPOINT_PATHS:
            endpoints_to_check.add(candidate_base + path)

    def _check_one(url: str) -> OAuthEndpointCheck:
        check = OAuthEndpointCheck(url=url)
        resp = _safe_get(url, headers, timeout)
        if resp is None:
            return check
        check.status_code = resp.status_code
        check.accessible = resp.status_code in (200, 301, 302, 400, 401, 403, 405)
        if resp.status_code in (401, 403):
            check.requires_auth = True
        cors_resp = _safe_get(url, {**headers, "Origin": "https://evil.com"}, timeout)
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or "evil.com" in acao:
                check.supports_cors = True
                check.issues.append(f"Permissive CORS on OAuth endpoint: {acao}")
        if "/register" in url and resp.status_code in (200, 201):
            check.issues.append(
                "Dynamic client registration may be open — "
                "attackers could register malicious clients"
            )
        if "/token" in url and url.startswith("http://"):
            check.issues.append(
                "Token endpoint served over HTTP — credentials exposed in transit"
            )
        return check

    checks: list[OAuthEndpointCheck] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_check_one, url): url for url in endpoints_to_check}
        for future in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                result = future.result()
                if result.accessible:
                    checks.append(result)
            except Exception:
                pass
    return checks


def _check_oauth_flows(oidc_config: Optional[OIDCConfig]) -> list[OAuthFlowCheck]:
    if not oidc_config:
        return []

    flows: list[OAuthFlowCheck] = []
    response_types = set(oidc_config.response_types_supported)
    grant_types = set(oidc_config.grant_types_supported)

    implicit = OAuthFlowCheck(flow_type="implicit")
    if "token" in response_types or "id_token token" in response_types:
        implicit.supported = True
        implicit.issues.append(
            "Implicit flow supported — tokens exposed in URL fragment, "
            "vulnerable to token leakage via browser history/referrer"
        )
    flows.append(implicit)

    ropc = OAuthFlowCheck(flow_type="resource_owner_password")
    if "password" in grant_types:
        ropc.supported = True
        ropc.issues.append(
            "Resource Owner Password Credentials grant supported — "
            "client directly handles user credentials"
        )
    flows.append(ropc)

    client_creds = OAuthFlowCheck(flow_type="client_credentials")
    if "client_credentials" in grant_types:
        client_creds.supported = True
    flows.append(client_creds)

    auth_code = OAuthFlowCheck(flow_type="authorization_code")
    if "code" in response_types or "authorization_code" in grant_types:
        auth_code.supported = True
        pkce_methods = oidc_config.code_challenge_methods_supported
        if not pkce_methods:
            auth_code.issues.append(
                "Authorization Code flow without PKCE — "
                "vulnerable to authorization code interception"
            )
        elif "plain" in pkce_methods and "S256" not in pkce_methods:
            auth_code.issues.append(
                "PKCE with 'plain' method only — "
                "code_challenge is not hashed, weak protection"
            )
    flows.append(auth_code)

    device = OAuthFlowCheck(flow_type="device_code")
    if "urn:ietf:params:oauth:grant-type:device_code" in grant_types:
        device.supported = True
    flows.append(device)

    return flows


def _check_redirect_issues(
    base_url: str,
    oidc_config: Optional[OIDCConfig],
    client_id: Optional[str],
    redirect_uri: Optional[str],
    headers: dict,
    timeout: int,
) -> list[str]:
    issues: list[str] = []
    if not oidc_config or not oidc_config.authorization_endpoint:
        return issues

    auth_url = oidc_config.authorization_endpoint
    test_client_id = client_id or "test_client"
    test_redirects = [
        "https://evil.com",
        "https://evil.com/callback",
        "http://localhost/callback",
        "https://evil.com%40legitimate.com",
        "https://legitimate.com.evil.com",
        "https://legitimate.com@evil.com",
        "//evil.com",
        "https://legitimate.com/..;/evil",
    ]

    for redirect in test_redirects:
        params = {
            "response_type": "code",
            "client_id": test_client_id,
            "redirect_uri": redirect,
            "scope": "openid",
        }
        try:
            resp = requests.get(
                f"{auth_url}?{urlencode(params)}",
                headers={"User-Agent": "Mozilla/5.0", **headers},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in location or "localhost" in location:
                    issues.append(
                        f"Open redirect via redirect_uri: "
                        f"'{redirect}' → server redirected to '{location[:100]}'"
                    )
            elif resp.status_code == 200 and "evil.com" in resp.text[:2000]:
                issues.append(f"Redirect URI reflected in page: '{redirect}'")
        except Exception:
            pass

    return issues


def _check_token_issues(oidc_config: Optional[OIDCConfig]) -> list[str]:
    if not oidc_config:
        return []

    issues: list[str] = []
    algs = oidc_config.id_token_signing_alg_values
    if "none" in algs:
        issues.append(
            "CRITICAL: 'none' signing algorithm supported for ID tokens — "
            "tokens can be forged"
        )
    if "HS256" in algs and "RS256" not in algs:
        issues.append(
            "Only symmetric signing (HS256) for ID tokens — "
            "shared secret must be kept secure"
        )

    auth_methods = oidc_config.token_endpoint_auth_methods
    if "none" in auth_methods:
        issues.append(
            "Token endpoint allows 'none' authentication — "
            "public clients can request tokens"
        )
    if "client_secret_post" in auth_methods:
        issues.append(
            "Token endpoint accepts client_secret_post — "
            "credentials in body (less secure than client_secret_basic)"
        )

    sensitive_scopes = [
        s for s in oidc_config.scopes_supported
        if any(kw in s.lower() for kw in ["admin", "write", "delete", "manage", "all", "root", "superuser"])
    ]
    if sensitive_scopes:
        issues.append(f"Potentially over-privileged scopes available: {', '.join(sensitive_scopes[:5])}")

    sensitive_claims = [
        c for c in oidc_config.claims_supported
        if any(kw in c.lower() for kw in ["password", "secret", "key", "token", "credential", "ssn", "credit", "phone"])
    ]
    if sensitive_claims:
        issues.append(f"Sensitive claims available: {', '.join(sensitive_claims[:5])}")

    return issues


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def oauth_oidc_check(
    target: str,
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> dict:
    """
    Non-intrusive analysis of OAuth 2.0 and OpenID Connect implementations.
    Discovers OIDC configuration, analyzes JWKS, checks endpoint security,
    evaluates supported flows, and tests for redirect vulnerabilities.
    """
    start = time.monotonic()

    try:
        req = OAuthCheckRequest(
            target=target,
            client_id=client_id,
            redirect_uri=redirect_uri,
            headers=headers or {},
            timeout=timeout,
        )
    except Exception as exc:
        return OAuthCheckResult(
            success=False,
            target=target,
            error=f"Validation: {exc}",
        ).model_dump()

    all_issues: list[str] = []
    observations: list[str] = []

    oidc_config, oidc_url = _discover_oidc_config(req.target, req.headers, req.timeout)
    if oidc_config:
        observations.append(f"OIDC discovery endpoint found: {oidc_url}")
    else:
        observations.append("No OIDC discovery document found on base or host-root fallback paths")

    jwks_info = _discover_jwks(req.target, oidc_config, req.headers, req.timeout)
    if jwks_info:
        observations.append(
            f"JWKS endpoint discovered: {jwks_info.url} ({jwks_info.keys_count} keys)"
        )
        all_issues.extend(jwks_info.issues)
        if not oidc_config:
            observations.append(
                "JWKS is exposed without matching OIDC discovery metadata; verify this key endpoint is intentional"
            )
    else:
        observations.append("No JWKS endpoint discovered on base or host-root fallback paths")

    endpoint_checks = _check_endpoints(req.target, oidc_config, req.headers, req.timeout)
    for check in endpoint_checks:
        all_issues.extend(check.issues)
    if endpoint_checks:
        observations.append(f"OAuth endpoint candidates accessible: {len(endpoint_checks)}")
    else:
        observations.append("No OAuth authorization/token/etc. endpoints responded with expected statuses")

    flow_checks = _check_oauth_flows(oidc_config)
    for flow in flow_checks:
        all_issues.extend(flow.issues)

    redirect_issues = _check_redirect_issues(
        req.target, oidc_config, req.client_id, req.redirect_uri, req.headers, req.timeout
    )
    all_issues.extend(redirect_issues)

    token_issues = _check_token_issues(oidc_config)
    all_issues.extend(token_issues)

    if not oidc_config and not jwks_info and not endpoint_checks:
        all_issues.append(
            "No OAuth/OIDC discovery endpoints, JWKS, or OAuth routes were found on base and host-root paths. "
            "Likely not an OAuth/OIDC provider at this target."
        )

    severity = "info"
    for issue in all_issues:
        lower = issue.lower()
        if "critical" in lower:
            severity = "critical"
            break
        elif "open redirect" in lower or "'none'" in lower:
            severity = "high"
        elif severity not in ("high", "critical") and any(
            kw in lower for kw in ["implicit", "without pkce", "http —"]
        ):
            severity = "medium"

    return OAuthCheckResult(
        success=True,
        target=target,
        oidc_config=oidc_config,
        oidc_config_url=oidc_url,
        jwks_info=jwks_info,
        endpoint_checks=endpoint_checks,
        flow_checks=flow_checks,
        observations=observations,
        redirect_issues=redirect_issues,
        token_issues=token_issues,
        all_issues=all_issues,
        severity=severity,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

OAUTH_OIDC_CHECK_TOOL_DEFINITION = {
    "name": "oauth_oidc_check",
    "description": (
        "Scan OAuth 2.0 / OpenID Connect implementations for misconfigurations. "
        "Discovers OIDC config, analyzes JWKS keys, checks endpoint accessibility, "
        "evaluates supported flows (implicit, ROPC, auth code without PKCE), "
        "tests for open redirect via redirect_uri, and analyzes token signing. "
        "Non-intrusive reconnaissance."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL of the OAuth/OIDC provider",
            },
            "client_id": {
                "type": "string",
                "description": "Known OAuth client ID for deeper redirect testing",
            },
            "redirect_uri": {
                "type": "string",
                "description": "Known legitimate redirect URI for comparison",
            },
            "headers": {
                "type": "object",
                "description": "Custom HTTP headers",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout per request in seconds (default: 30)",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 6. ENTRY POINT
# ══════════════════════════════════════════════════════════════

# ── Configure your scan here ─────────────────────────────────────────────────
TARGET       = "http://localhost:8888/api"   # base URL of the OAuth/OIDC provider
CLIENT_ID    = None                         # known client ID, or None
REDIRECT_URI = None                         # known redirect URI, or None
HEADERS      = {}                           # e.g. {"Authorization": "Bearer ..."}
TIMEOUT      = 30                           # per-request timeout in seconds (5–120)
EMIT_JSON    = False                        # True → raw JSON output, False → summary
ALLOW_LOCAL_TARGETS_IN_MAIN = True         # convenience for local lab runs
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    if ALLOW_LOCAL_TARGETS_IN_MAIN and os.getenv("PENTAFORGE_ALLOW_LOCAL_API_TARGETS") is None:
        os.environ["PENTAFORGE_ALLOW_LOCAL_API_TARGETS"] = "1"

    result = oauth_oidc_check(
        target=TARGET,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        headers=HEADERS,
        timeout=TIMEOUT,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2))
        return

    status = "OK" if result["success"] else "FAILED"
    sev = result["severity"].upper()
    print(f"\n[{status}] {result['target']}  severity={sev}  ({result['execution_time']}s)\n")

    if result.get("error"):
        print(f"  Error: {result['error']}\n")
        return

    if result.get("oidc_config_url"):
        print(f"  OIDC config : {result['oidc_config_url']}")

    if result.get("jwks_info"):
        jwks = result["jwks_info"]
        print(f"  JWKS        : {jwks['url']}  ({jwks['keys_count']} keys, algs: {', '.join(jwks['algorithms'])})")

    accessible = [c for c in result["endpoint_checks"] if c["accessible"]]
    print(f"  Endpoints   : {len(accessible)} accessible\n")

    observations = result.get("observations") or []
    if observations:
        print("  Observations:")
        for note in observations:
            print(f"    - {note}")
        print()

    flows = [f for f in result["flow_checks"] if f["supported"]]
    if flows:
        print("  Supported flows:")
        for flow in flows:
            print(f"    {flow['flow_type']}")
        print()

    if result["all_issues"]:
        print("  Issues:")
        for issue in result["all_issues"]:
            prefix = "  [!!!]" if "CRITICAL" in issue else "  [!]  "
            print(f"{prefix} {issue}")
    else:
        if observations:
            print("  No security issues found. Review observations above for context.")
        else:
            print("  No issues found.")

    print()


if __name__ == "__main__":
    main()