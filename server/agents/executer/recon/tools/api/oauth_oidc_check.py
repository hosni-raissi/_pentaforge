import json
import re
import time
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlparse, urlencode, parse_qs


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

BLOCKED_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "169.254.169.254", "metadata.google.internal",
]


class OAuthCheckRequest(BaseModel):
    target: str
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    headers: dict[str, str] = {}
    timeout: int = Field(default=30, ge=5, le=120)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        cleaned = v.strip()
        for blocked in BLOCKED_TARGETS:
            if blocked in cleaned:
                raise ValueError(f"Target '{cleaned}' is blocked")
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

# Well-known OAuth endpoints to probe
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
    """Safe HTTP GET request."""
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


def _discover_oidc_config(base_url: str, headers: dict,
                          timeout: int) -> tuple[Optional[OIDCConfig], Optional[str]]:
    """Discover and parse OIDC configuration."""
    for path in OIDC_DISCOVERY_PATHS:
        url = base_url.rstrip("/") + path
        resp = _safe_get(url, headers, timeout)

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "issuer" in data or "authorization_endpoint" in data:
                    config = OIDCConfig(
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
                    )
                    return config, url
            except Exception:
                pass

    return None, None


def _analyze_jwks(jwks_url: str, headers: dict,
                  timeout: int) -> Optional[JWKSInfo]:
    """Analyze JWKS endpoint for weak keys and misconfigurations."""
    resp = _safe_get(jwks_url, headers, timeout)
    if not resp or resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except Exception:
        return None

    keys = data.get("keys", [])
    info = JWKSInfo(
        url=jwks_url,
        keys_count=len(keys),
    )

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

        # Check for weak keys
        if kty == "RSA":
            n = key.get("n", "")
            # Rough check: RSA key size < 2048 bits
            if n and len(n) < 342:  # base64url of 2048-bit modulus
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


def _discover_jwks(base_url: str, oidc_config: Optional[OIDCConfig],
                   headers: dict, timeout: int) -> Optional[JWKSInfo]:
    """Find and analyze JWKS."""
    # Try from OIDC config first
    if oidc_config and oidc_config.jwks_uri:
        result = _analyze_jwks(oidc_config.jwks_uri, headers, timeout)
        if result:
            return result

    # Brute-force JWKS paths
    for path in JWKS_PATHS:
        url = base_url.rstrip("/") + path
        result = _analyze_jwks(url, headers, timeout)
        if result:
            return result

    return None


def _check_endpoints(base_url: str, oidc_config: Optional[OIDCConfig],
                     headers: dict, timeout: int) -> list[OAuthEndpointCheck]:
    """Check accessibility and security of OAuth endpoints."""
    checks = []

    # Collect endpoints from OIDC config + brute force
    endpoints_to_check = set()

    if oidc_config:
        for attr in [
            "authorization_endpoint", "token_endpoint",
            "userinfo_endpoint", "registration_endpoint",
            "revocation_endpoint", "introspection_endpoint",
        ]:
            val = getattr(oidc_config, attr, None)
            if val:
                endpoints_to_check.add(val)

    for path in OAUTH_ENDPOINT_PATHS:
        endpoints_to_check.add(base_url.rstrip("/") + path)

    def _check_one(url: str) -> OAuthEndpointCheck:
        check = OAuthEndpointCheck(url=url)
        resp = _safe_get(url, headers, timeout)

        if resp is None:
            return check

        check.status_code = resp.status_code
        check.accessible = resp.status_code in (200, 301, 302, 400, 401, 403, 405)

        if resp.status_code in (401, 403):
            check.requires_auth = True

        # CORS check
        cors_headers = {
            **headers,
            "Origin": "https://evil.com",
        }
        cors_resp = _safe_get(url, cors_headers, timeout)
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*" or "evil.com" in acao:
                check.supports_cors = True
                check.issues.append(
                    f"Permissive CORS on OAuth endpoint: {acao}"
                )

        # Check for open registration
        if "/register" in url and resp.status_code in (200, 201):
            check.issues.append(
                "Dynamic client registration may be open — "
                "attackers could register malicious clients"
            )

        # Check for token endpoint without TLS
        if "/token" in url and url.startswith("http://"):
            check.issues.append(
                "Token endpoint served over HTTP — credentials exposed in transit"
            )

        return check

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_check_one, url): url
            for url in endpoints_to_check
        }
        for future in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                result = future.result()
                if result.accessible:
                    checks.append(result)
            except Exception:
                pass

    return checks


def _check_oauth_flows(oidc_config: Optional[OIDCConfig]) -> list[OAuthFlowCheck]:
    """Analyze supported OAuth flows for security issues."""
    flows = []

    if not oidc_config:
        return flows

    response_types = set(oidc_config.response_types_supported)
    grant_types = set(oidc_config.grant_types_supported)

    # Implicit flow
    implicit = OAuthFlowCheck(flow_type="implicit")
    if "token" in response_types or "id_token token" in response_types:
        implicit.supported = True
        implicit.issues.append(
            "Implicit flow supported — tokens exposed in URL fragment, "
            "vulnerable to token leakage via browser history/referrer"
        )
    flows.append(implicit)

    # Resource Owner Password Credentials
    ropc = OAuthFlowCheck(flow_type="resource_owner_password")
    if "password" in grant_types:
        ropc.supported = True
        ropc.issues.append(
            "Resource Owner Password Credentials grant supported — "
            "client directly handles user credentials"
        )
    flows.append(ropc)

    # Client Credentials
    client_creds = OAuthFlowCheck(flow_type="client_credentials")
    if "client_credentials" in grant_types:
        client_creds.supported = True
        # Not necessarily a vulnerability, just noting it
    flows.append(client_creds)

    # Authorization Code without PKCE
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

    # Device Code
    device = OAuthFlowCheck(flow_type="device_code")
    if "urn:ietf:params:oauth:grant-type:device_code" in grant_types:
        device.supported = True
    flows.append(device)

    return flows


def _check_redirect_issues(base_url: str, oidc_config: Optional[OIDCConfig],
                           client_id: Optional[str],
                           redirect_uri: Optional[str],
                           headers: dict, timeout: int) -> list[str]:
    """Check for open redirect vulnerabilities in OAuth flow."""
    issues = []

    if not oidc_config or not oidc_config.authorization_endpoint:
        return issues

    auth_url = oidc_config.authorization_endpoint

    # Test payloads for redirect_uri manipulation
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

    test_client_id = client_id or "test_client"

    for redirect in test_redirects:
        params = {
            "response_type": "code",
            "client_id": test_client_id,
            "redirect_uri": redirect,
            "scope": "openid",
        }

        test_url = f"{auth_url}?{urlencode(params)}"

        try:
            resp = requests.get(
                test_url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    **headers,
                },
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )

            # If server redirects to our evil URL, it's vulnerable
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in location or "localhost" in location:
                    issues.append(
                        f"Open redirect via redirect_uri: "
                        f"'{redirect}' → server redirected to '{location[:100]}'"
                    )

            # If server returns 200 with the redirect in the page
            elif resp.status_code == 200:
                if "evil.com" in resp.text[:2000]:
                    issues.append(
                        f"Redirect URI reflected in page: '{redirect}'"
                    )

        except Exception:
            pass

    return issues


def _check_token_issues(oidc_config: Optional[OIDCConfig]) -> list[str]:
    """Analyze token configuration for security issues."""
    issues = []

    if not oidc_config:
        return issues

    # Weak signing algorithms
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

    # Weak auth methods
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

    # Excessive scopes
    sensitive_scopes = [
        s for s in oidc_config.scopes_supported
        if any(kw in s.lower() for kw in [
            "admin", "write", "delete", "manage", "all",
            "root", "superuser",
        ])
    ]
    if sensitive_scopes:
        issues.append(
            f"Potentially over-privileged scopes available: "
            f"{', '.join(sensitive_scopes[:5])}"
        )

    # Sensitive claims
    sensitive_claims = [
        c for c in oidc_config.claims_supported
        if any(kw in c.lower() for kw in [
            "password", "secret", "key", "token", "credential",
            "ssn", "credit", "phone",
        ])
    ]
    if sensitive_claims:
        issues.append(
            f"Sensitive claims available: {', '.join(sensitive_claims[:5])}"
        )

    return issues


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def oauth_oidc_check(
    target: str,
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    headers: dict[str, str] = {},
    timeout: int = 30,
) -> dict:
    """
    🔍 Agent Tool: OAuth/OIDC Misconfiguration Scanner

    Non-intrusive analysis of OAuth 2.0 and OpenID Connect implementations.
    Discovers OIDC configuration, analyzes JWKS, checks endpoint security,
    evaluates supported flows, and tests for redirect vulnerabilities.

    Args:
        target:       Base URL (e.g., "https://auth.example.com")
        client_id:    Known OAuth client ID for deeper testing
        redirect_uri: Known redirect URI for comparison
        headers:      Custom HTTP headers
        timeout:      Timeout per request in seconds

    Returns:
        Structured JSON with OIDC config, JWKS analysis, flow checks, issues.
    """
    start = time.time()

    # Validate
    try:
        req = OAuthCheckRequest(
            target=target, client_id=client_id,
            redirect_uri=redirect_uri, headers=headers,
            timeout=timeout,
        )
    except Exception as e:
        return OAuthCheckResult(
            success=False, target=target,
            error=f"Validation: {e}",
        ).model_dump()

    all_issues = []

    # 1. Discover OIDC configuration
    oidc_config, oidc_url = _discover_oidc_config(
        req.target, req.headers, req.timeout
    )

    if oidc_config:
        all_issues.append(
            f"OIDC discovery endpoint found: {oidc_url}"
        )

    # 2. Analyze JWKS
    jwks_info = _discover_jwks(
        req.target, oidc_config, req.headers, req.timeout
    )
    if jwks_info:
        all_issues.extend(jwks_info.issues)

    # 3. Check endpoints
    endpoint_checks = _check_endpoints(
        req.target, oidc_config, req.headers, req.timeout
    )
    for check in endpoint_checks:
        all_issues.extend(check.issues)

    # 4. Analyze OAuth flows
    flow_checks = _check_oauth_flows(oidc_config)
    for flow in flow_checks:
        all_issues.extend(flow.issues)

    # 5. Check redirect issues
    redirect_issues = _check_redirect_issues(
        req.target, oidc_config, req.client_id,
        req.redirect_uri, req.headers, req.timeout,
    )
    all_issues.extend(redirect_issues)

    # 6. Token configuration issues
    token_issues = _check_token_issues(oidc_config)
    all_issues.extend(token_issues)

    # Determine severity
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
        redirect_issues=redirect_issues,
        token_issues=token_issues,
        all_issues=all_issues,
        severity=severity,
        execution_time=round(time.time() - start, 2),
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
