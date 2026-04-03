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

class HeaderAnalysisRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = []
    methods: list[str] = ["GET", "POST", "OPTIONS"]

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"curl", "httpx", "securityheaders", "manual"}
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
        ip_pattern     = r"^https?://(\d{1,3}\.){3}\d{1,3}"

        if not (re.match(domain_pattern, v) or
                re.match(bare_domain, v)    or
                re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["-o", "--output", "-O"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {flag}")
        return v

    @validator("methods")
    def validate_methods(cls, v):
        allowed = {"GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"}
        for m in v:
            if m.upper() not in allowed:
                raise ValueError(f"Method '{m}' not allowed")
        return [m.upper() for m in v]


# ── Single header check result ──
class HeaderCheckResult(BaseModel):
    header_name: str
    present: bool = False
    value: Optional[str] = None
    valid: bool = False
    score: int = 0                      # 0-10 per header
    issues: list[str] = []
    recommendations: list[str] = []
    severity: str = "info"             # info / low / medium / high / critical
    finding_keys: list[str] = []


# ── Cookie analysis result ──
class CookieResult(BaseModel):
    name: str
    value_snippet: Optional[str] = None    # first 20 chars only
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None        # Strict / Lax / None
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[str] = None
    issues: list[str] = []
    severity: str = "info"
    score: int = 0                         # 0-10


# ── CSP directive analysis ──
class CSPAnalysis(BaseModel):
    raw: Optional[str] = None
    directives: dict[str, list[str]] = {}
    issues: list[str] = []
    score: int = 0                         # 0-10
    has_unsafe_inline: bool = False
    has_unsafe_eval: bool = False
    has_wildcard: bool = False
    has_nonce: bool = False
    has_hash: bool = False
    missing_directives: list[str] = []


# ── HSTS analysis ──
class HSTSAnalysis(BaseModel):
    raw: Optional[str] = None
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    issues: list[str] = []
    score: int = 0                         # 0-10


# ── Per-endpoint result ──
class EndpointHeaderResult(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    headers_raw: dict[str, str] = {}
    header_checks: list[HeaderCheckResult] = []
    cookies: list[CookieResult] = []
    csp_analysis: Optional[CSPAnalysis] = None
    hsts_analysis: Optional[HSTSAnalysis] = None
    total_score: int = 0                   # 0-100
    grade: str = "F"                       # A+ / A / B / C / D / F
    vulnerable: bool = False
    findings: list[str] = []
    severity: str = "info"
    missing_headers: list[str] = []
    insecure_headers: list[str] = []


# ── Final result ──
class HeaderScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_endpoints: int = 0
    total_vulnerable: int = 0
    average_grade: str = "F"
    endpoints: list[EndpointHeaderResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SECURITY HEADER DEFINITIONS
# ══════════════════════════════════════════════════════════════

SECURITY_HEADERS: dict[str, dict] = {

    # ── Critical ──────────────────────────────────────────────
    "content-security-policy": {
        "severity":      "high",
        "weight":        20,               # score contribution
        "description":   "Controls which resources browser can load. Prevents XSS.",
        "required":      True,
        "recommendations": [
            "Define a strict CSP: default-src 'self'",
            "Avoid unsafe-inline and unsafe-eval",
            "Use nonces or hashes for inline scripts",
            "Add report-uri or report-to for violation monitoring",
        ],
    },
    "strict-transport-security": {
        "severity":      "high",
        "weight":        15,
        "description":   "Forces HTTPS. Prevents protocol downgrade and MITM.",
        "required":      True,
        "recommendations": [
            "Set max-age to at least 31536000 (1 year)",
            "Add includeSubDomains",
            "Add preload directive and submit to HSTS preload list",
        ],
    },
    "x-frame-options": {
        "severity":      "high",
        "weight":        10,
        "description":   "Prevents clickjacking by controlling iframe embedding.",
        "required":      True,
        "valid_values":  ["DENY", "SAMEORIGIN"],
        "recommendations": [
            "Use X-Frame-Options: DENY if no iframe embedding needed",
            "Use SAMEORIGIN to allow same-origin framing only",
            "Prefer CSP frame-ancestors directive (supersedes X-Frame-Options)",
        ],
    },
    "x-content-type-options": {
        "severity":      "medium",
        "weight":        10,
        "description":   "Prevents MIME-type sniffing attacks.",
        "required":      True,
        "valid_values":  ["nosniff"],
        "recommendations": [
            "Set X-Content-Type-Options: nosniff",
            "Ensure all responses include correct Content-Type",
        ],
    },
    "referrer-policy": {
        "severity":      "medium",
        "weight":        8,
        "description":   "Controls referrer information sent with requests.",
        "required":      True,
        "valid_values":  [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
        "recommendations": [
            "Use strict-origin-when-cross-origin as a safe default",
            "Use no-referrer for sensitive pages",
        ],
    },
    "permissions-policy": {
        "severity":      "medium",
        "weight":        8,
        "description":   "Controls browser feature access (camera, mic, geolocation, etc.).",
        "required":      True,
        "recommendations": [
            "Disable unused features: camera=(), microphone=(), geolocation=()",
            "Apply least-privilege principle to feature access",
        ],
    },
    "cross-origin-opener-policy": {
        "severity":      "medium",
        "weight":        7,
        "description":   "Isolates browsing context. Prevents cross-origin attacks.",
        "required":      True,
        "valid_values":  ["same-origin", "same-origin-allow-popups", "unsafe-none"],
        "recommendations": [
            "Use same-origin for strict isolation",
            "Required for SharedArrayBuffer and performance.measureUserAgentSpecificMemory()",
        ],
    },
    "cross-origin-embedder-policy": {
        "severity":      "medium",
        "weight":        7,
        "description":   "Prevents document from loading cross-origin resources without permission.",
        "required":      True,
        "valid_values":  ["require-corp", "unsafe-none"],
        "recommendations": [
            "Use require-corp alongside COOP for full cross-origin isolation",
        ],
    },
    "cross-origin-resource-policy": {
        "severity":      "medium",
        "weight":        5,
        "description":   "Controls cross-origin resource sharing at resource level.",
        "required":      False,
        "valid_values":  ["same-site", "same-origin", "cross-origin"],
        "recommendations": [
            "Use same-origin for sensitive resources",
            "Use same-site to allow subdomains",
        ],
    },
    "x-permitted-cross-domain-policies": {
        "severity":      "low",
        "weight":        3,
        "description":   "Controls Adobe Flash/PDF cross-domain access.",
        "required":      False,
        "valid_values":  ["none", "master-only"],
        "recommendations": [
            "Set to none to block all cross-domain policies",
        ],
    },
    "cache-control": {
        "severity":      "medium",
        "weight":        5,
        "description":   "Controls response caching behavior.",
        "required":      True,
        "recommendations": [
            "Use no-store for sensitive pages",
            "Use no-cache, no-store, must-revalidate for authenticated content",
        ],
    },
    "clear-site-data": {
        "severity":      "low",
        "weight":        2,
        "description":   "Clears browsing data on logout.",
        "required":      False,
        "recommendations": [
            "Send Clear-Site-Data: \"cache\",\"cookies\",\"storage\" on logout endpoint",
        ],
    },

    # ── Information Disclosure (headers that SHOULD NOT be present) ──
    "server": {
        "severity":      "low",
        "weight":        0,
        "description":   "Server header reveals software version. Should be removed or generic.",
        "required":      False,
        "should_be_absent": True,
        "recommendations": [
            "Remove or genericize Server header",
            "Configure web server to suppress version info",
        ],
    },
    "x-powered-by": {
        "severity":      "low",
        "weight":        0,
        "description":   "Reveals backend technology (PHP, ASP.NET, etc.).",
        "required":      False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-Powered-By header",
            "For Express: app.disable('x-powered-by')",
            "For PHP: expose_php = Off in php.ini",
        ],
    },
    "x-aspnet-version": {
        "severity":      "low",
        "weight":        0,
        "description":   "Reveals ASP.NET version.",
        "required":      False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-AspNet-Version header in web.config",
        ],
    },
    "x-aspnetmvc-version": {
        "severity":      "low",
        "weight":        0,
        "description":   "Reveals ASP.NET MVC version.",
        "required":      False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-AspNetMvc-Version header",
        ],
    },
}

# Headers that should be present (scored)
REQUIRED_HEADERS = [
    k for k, v in SECURITY_HEADERS.items()
    if v.get("required") and not v.get("should_be_absent")
]

# Headers that should be absent (info disclosure)
DISCLOSURE_HEADERS = [
    k for k, v in SECURITY_HEADERS.items()
    if v.get("should_be_absent")
]


# ══════════════════════════════════════════════════════════════
# 3. CSP ANALYZER
# ══════════════════════════════════════════════════════════════

IMPORTANT_CSP_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src",
    "connect-src", "font-src", "object-src", "media-src",
    "frame-src", "frame-ancestors", "form-action",
    "base-uri", "upgrade-insecure-requests", "block-all-mixed-content",
]


def analyze_csp(csp_value: str) -> CSPAnalysis:
    """
    Deep-parse a Content-Security-Policy header value.
    Detect: unsafe-inline, unsafe-eval, wildcards, missing directives,
    nonces, hashes, dangling directives.
    """
    analysis = CSPAnalysis(raw=csp_value)

    if not csp_value:
        analysis.issues.append("CSP header is empty")
        analysis.score = 0
        return analysis

    # ── Parse directives ──
    for directive in csp_value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name   = parts[0].lower()
        values = parts[1:] if len(parts) > 1 else []
        analysis.directives[name] = values

    score = 10

    # ── Check for dangerous keywords ──
    all_values_str = csp_value.lower()

    if "'unsafe-inline'" in all_values_str:
        analysis.has_unsafe_inline = True
        analysis.issues.append("unsafe-inline detected — allows inline script/style execution (XSS risk)")
        score -= 3

    if "'unsafe-eval'" in all_values_str:
        analysis.has_unsafe_eval = True
        analysis.issues.append("unsafe-eval detected — allows eval() and Function() (XSS risk)")
        score -= 3

    if re.search(r"(^|\s)\*(\s|;|$)", all_values_str):
        analysis.has_wildcard = True
        analysis.issues.append("Wildcard (*) source detected — allows any origin")
        score -= 2

    # Check http: sources on any directive
    if re.search(r"\bhttp:", all_values_str):
        analysis.issues.append("http: source allows insecure content loading")
        score -= 1

    # Check data: in script-src
    script_src = analysis.directives.get("script-src", [])
    if "data:" in " ".join(script_src).lower():
        analysis.issues.append("data: URI in script-src allows data URI script execution")
        score -= 2

    # ── Nonce / hash detection ──
    if re.search(r"'nonce-[^']+'" , csp_value):
        analysis.has_nonce = True
        # nonce partially mitigates unsafe-inline
        if analysis.has_unsafe_inline:
            score += 1

    if re.search(r"'(sha256|sha384|sha512)-[^']+'", csp_value):
        analysis.has_hash = True
        if analysis.has_unsafe_inline:
            score += 1

    # ── Check missing important directives ──
    for directive in IMPORTANT_CSP_DIRECTIVES:
        if directive not in analysis.directives:
            # only flag if not covered by default-src
            if "default-src" not in analysis.directives:
                analysis.missing_directives.append(directive)

    if "default-src" not in analysis.directives:
        analysis.issues.append("No default-src directive — browser uses permissive defaults")
        score -= 2

    if "object-src" not in analysis.directives:
        default = analysis.directives.get("default-src", [])
        if "none" not in " ".join(default).lower() and "'none'" not in " ".join(default).lower():
            analysis.issues.append("Missing object-src 'none' — Flash/plugin execution possible")
            score -= 1

    if "base-uri" not in analysis.directives:
        analysis.issues.append("Missing base-uri — allows base tag injection (XSS)")
        score -= 1

    if "frame-ancestors" not in analysis.directives:
        analysis.issues.append(
            "Missing frame-ancestors — CSP doesn't prevent clickjacking "
            "(use frame-ancestors 'none' or 'self')"
        )

    if "form-action" not in analysis.directives:
        analysis.issues.append("Missing form-action — form submissions not restricted")

    # ── Upgrade insecure ──
    if "upgrade-insecure-requests" not in analysis.directives:
        analysis.issues.append("Missing upgrade-insecure-requests")

    analysis.score = max(0, min(10, score))
    return analysis


# ══════════════════════════════════════════════════════════════
# 4. HSTS ANALYZER
# ══════════════════════════════════════════════════════════════

MIN_HSTS_MAX_AGE = 31_536_000   # 1 year in seconds


def analyze_hsts(hsts_value: str) -> HSTSAnalysis:
    """
    Parse and score a Strict-Transport-Security header value.
    """
    analysis = HSTSAnalysis(raw=hsts_value)

    if not hsts_value:
        analysis.issues.append("HSTS header is empty")
        analysis.score = 0
        return analysis

    score = 10
    hsts_lower = hsts_value.lower()

    # ── max-age ──
    ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
    if ma_match:
        analysis.max_age = int(ma_match.group(1))
        if analysis.max_age == 0:
            analysis.issues.append("max-age=0 — HSTS effectively disabled")
            score -= 8
        elif analysis.max_age < 2592000:           # < 30 days
            analysis.issues.append(
                f"max-age too short ({analysis.max_age}s < 2592000s/30 days)"
            )
            score -= 4
        elif analysis.max_age < MIN_HSTS_MAX_AGE:  # < 1 year
            analysis.issues.append(
                f"max-age below recommended 1 year ({analysis.max_age}s)"
            )
            score -= 2
    else:
        analysis.issues.append("No max-age directive found")
        score -= 6

    # ── includeSubDomains ──
    if "includesubdomains" in hsts_lower:
        analysis.include_subdomains = True
    else:
        analysis.issues.append("Missing includeSubDomains — subdomains not protected")
        score -= 2

    # ── preload ──
    if "preload" in hsts_lower:
        analysis.preload = True
        if not analysis.include_subdomains:
            analysis.issues.append(
                "preload requires includeSubDomains — preload won't work without it"
            )
            score -= 1
        if analysis.max_age and analysis.max_age < MIN_HSTS_MAX_AGE:
            analysis.issues.append(
                "preload requires max-age >= 31536000 (1 year)"
            )
            score -= 1
    else:
        analysis.issues.append(
            "Missing preload — not submitted to browser preload lists"
        )

    analysis.score = max(0, min(10, score))
    return analysis


# ══════════════════════════════════════════════════════════════
# 5. COOKIE ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_cookie(set_cookie_header: str) -> CookieResult:
    """
    Parse a Set-Cookie header value and score its security flags.
    """
    # Split name=value from directives
    parts    = [p.strip() for p in set_cookie_header.split(";")]
    name_val = parts[0]

    name  = name_val.split("=")[0].strip() if "=" in name_val else name_val
    value = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

    cookie = CookieResult(
        name=name,
        value_snippet=value[:20] + "..." if len(value) > 20 else value,
    )

    score    = 10
    directives_lower = set_cookie_header.lower()

    # ── Flags ──
    cookie.secure    = "secure" in directives_lower
    cookie.http_only = "httponly" in directives_lower

    ss_match = re.search(r"samesite\s*=\s*(\w+)", directives_lower)
    if ss_match:
        cookie.same_site = ss_match.group(1).capitalize()

    path_match   = re.search(r"path\s*=\s*([^;]+)",   directives_lower)
    domain_match = re.search(r"domain\s*=\s*([^;]+)", directives_lower)
    expires_match= re.search(r"expires\s*=\s*([^;]+)",directives_lower)
    maxage_match = re.search(r"max-age\s*=\s*([^;]+)", directives_lower)

    cookie.path    = path_match.group(1).strip()    if path_match    else None
    cookie.domain  = domain_match.group(1).strip()  if domain_match  else None
    cookie.expires = expires_match.group(1).strip() if expires_match else None
    cookie.max_age = maxage_match.group(1).strip()  if maxage_match  else None

    # ── Security checks ──
    if not cookie.secure:
        cookie.issues.append("Missing Secure flag — cookie sent over HTTP")
        score -= 3

    if not cookie.http_only:
        cookie.issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
        score -= 3

    if not cookie.same_site:
        cookie.issues.append("Missing SameSite attribute — vulnerable to CSRF")
        score -= 2
    elif cookie.same_site.lower() == "none":
        if not cookie.secure:
            cookie.issues.append("SameSite=None requires Secure flag")
            score -= 2
        cookie.issues.append("SameSite=None — cookie sent in all cross-site requests")
        score -= 1
    elif cookie.same_site.lower() == "lax":
        cookie.issues.append("SameSite=Lax — some CSRF protection but weaker than Strict")

    # Check for session-like cookie names without security
    sensitive_names = {
        "session", "sess", "auth", "token", "jwt",
        "login", "user", "account", "admin", "key",
        "secret", "credential", "passwd", "password",
    }
    if any(s in name.lower() for s in sensitive_names):
        if not cookie.secure:
            cookie.issues.append(
                f"Sensitive cookie '{name}' missing Secure flag — CRITICAL risk"
            )
            score -= 3
        if not cookie.http_only:
            cookie.issues.append(
                f"Sensitive cookie '{name}' missing HttpOnly — token theft via XSS"
            )
            score -= 2

    # Wildcard domain
    if cookie.domain and cookie.domain.startswith("."):
        cookie.issues.append(
            f"Cookie scoped to wildcard domain '{cookie.domain}' — "
            "accessible on all subdomains"
        )
        score -= 1

    cookie.score = max(0, min(10, score))

    # Severity
    if score <= 2:
        cookie.severity = "critical"
    elif score <= 4:
        cookie.severity = "high"
    elif score <= 6:
        cookie.severity = "medium"
    elif score <= 8:
        cookie.severity = "low"
    else:
        cookie.severity = "info"

    return cookie


# ══════════════════════════════════════════════════════════════
# 6. HEADER CHECKER
# ══════════════════════════════════════════════════════════════

def check_header(
    header_name: str,
    headers_dict: dict[str, str],
) -> HeaderCheckResult:
    """
    Check a single security header:
    - Is it present?
    - Is its value valid / secure?
    - What are the issues?
    """
    cfg       = SECURITY_HEADERS.get(header_name, {})
    value     = headers_dict.get(header_name)
    result    = HeaderCheckResult(header_name=header_name)
    severity  = cfg.get("severity", "info")
    weight    = cfg.get("weight", 5)
    should_absent = cfg.get("should_be_absent", False)

    # ══ Headers that should NOT be present (info disclosure) ══
    if should_absent:
        if value:
            result.present  = True
            result.value    = value
            result.valid    = False
            result.score    = 0
            result.severity = severity
            result.issues.append(
                f"{header_name} reveals server info: '{value}' — remove or genericize"
            )
            result.recommendations = cfg.get("recommendations", [])
            result.finding_keys.append(f"info_disclosure_{header_name.replace('-','_')}")
        else:
            result.present = False
            result.valid   = True
            result.score   = 10
            result.severity = "info"
        return result

    # ══ Required security headers ══
    if not value:
        result.present  = False
        result.valid    = False
        result.score    = 0
        result.severity = severity
        result.issues.append(f"{header_name} is missing")
        result.recommendations = cfg.get("recommendations", [])
        result.finding_keys.append(f"missing_{header_name.replace('-','_')}")
        return result

    result.present = True
    result.value   = value
    score          = 10

    # ── Header-specific validation ──

    # X-Frame-Options
    if header_name == "x-frame-options":
        valid_vals = [v.upper() for v in cfg.get("valid_values", [])]
        val_upper  = value.strip().upper()
        if val_upper not in valid_vals:
            result.issues.append(
                f"Invalid value '{value}' — use DENY or SAMEORIGIN"
            )
            score -= 5
        elif val_upper == "ALLOWALL":
            result.issues.append("ALLOWALL effectively disables clickjacking protection")
            score -= 8
        else:
            result.valid = True

    # X-Content-Type-Options
    elif header_name == "x-content-type-options":
        if value.strip().lower() != "nosniff":
            result.issues.append(f"Value should be 'nosniff', got '{value}'")
            score -= 5
        else:
            result.valid = True

    # Referrer-Policy
    elif header_name == "referrer-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower  = value.strip().lower()
        if val_lower not in valid_vals:
            result.issues.append(f"Unrecognised Referrer-Policy value: '{value}'")
            score -= 3
        elif val_lower in ("unsafe-url", "no-referrer-when-downgrade"):
            result.issues.append(
                f"Referrer-Policy '{value}' leaks full URL to cross-origin requests"
            )
            score -= 3
        else:
            result.valid = True

    # Permissions-Policy
    elif header_name == "permissions-policy":
        # Check for unrestricted powerful features
        risky_features = [
            "camera", "microphone", "geolocation",
            "payment", "usb", "magnetometer",
            "accelerometer", "gyroscope",
        ]
        for feat in risky_features:
            if f"{feat}=*" in value.lower() or f"{feat}=(allow)" in value.lower():
                result.issues.append(f"Feature '{feat}' unrestricted — should be restricted or disabled")
                score -= 1
        result.valid = score >= 8

    # COOP
    elif header_name == "cross-origin-opener-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower  = value.strip().lower()
        if val_lower == "unsafe-none":
            result.issues.append(
                "COOP: unsafe-none provides no isolation"
            )
            score -= 5
        elif val_lower not in valid_vals:
            result.issues.append(f"Unrecognised COOP value: '{value}'")
            score -= 3
        else:
            result.valid = True

    # COEP
    elif header_name == "cross-origin-embedder-policy":
        val_lower = value.strip().lower()
        if val_lower == "unsafe-none":
            result.issues.append("COEP: unsafe-none provides no embedding protection")
            score -= 5
        elif val_lower == "require-corp":
            result.valid = True
        else:
            result.issues.append(f"Unrecognised COEP value: '{value}'")
            score -= 3

    # Cache-Control
    elif header_name == "cache-control":
        val_lower = value.lower()
        if "no-store" in val_lower:
            result.valid = True
        elif "private" in val_lower:
            result.issues.append(
                "Cache-Control: private — sensitive data may be stored in browser cache"
            )
            score -= 2
        elif "public" in val_lower:
            result.issues.append(
                "Cache-Control: public — response may be cached by CDN/proxy"
            )
            score -= 4
        if "no-cache" not in val_lower and "no-store" not in val_lower:
            result.issues.append(
                "Missing no-cache / no-store — sensitive data caching risk"
            )
            score -= 3

    # CORP
    elif header_name == "cross-origin-resource-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower  = value.strip().lower()
        if val_lower not in valid_vals:
            result.issues.append(f"Unrecognised CORP value: '{value}'")
            score -= 3
        elif val_lower == "cross-origin":
            result.issues.append("CORP: cross-origin — resource loadable from anywhere")
            score -= 2
        else:
            result.valid = True

    # X-Permitted-Cross-Domain-Policies
    elif header_name == "x-permitted-cross-domain-policies":
        val_lower = value.strip().lower()
        if val_lower in ("all", "by-content-type", "by-ftp-filename"):
            result.issues.append(
                f"X-Permitted-Cross-Domain-Policies: '{value}' — too permissive"
            )
            score -= 5
        else:
            result.valid = True

    else:
        # Generic: just being present is good
        result.valid = True

    result.score    = max(0, min(10, score))
    result.severity = severity if result.issues else "info"
    if result.issues:
        result.recommendations = cfg.get("recommendations", [])
        result.finding_keys.append(f"insecure_{header_name.replace('-','_')}")

    return result


# ══════════════════════════════════════════════════════════════
# 7. GRADE CALCULATOR
# ══════════════════════════════════════════════════════════════

GRADE_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (0,  "F"),
]


def calculate_grade(
    header_checks: list[HeaderCheckResult],
    cookies: list[CookieResult],
    csp: Optional[CSPAnalysis],
    hsts: Optional[HSTSAnalysis],
) -> tuple[int, str]:
    """
    Calculate total security score (0-100) and letter grade.

    Weights:
      Security headers (required) → 60 points
      CSP quality                 → 20 points
      HSTS quality                → 10 points
      Cookie security             → 10 points
    """

    # ── Required headers score (60 pts) ──
    required = [h for h in header_checks
                if not SECURITY_HEADERS.get(h.header_name, {}).get("should_be_absent")]
    total_weight = sum(
        SECURITY_HEADERS.get(h.header_name, {}).get("weight", 5)
        for h in required
    )
    earned_weight = sum(
        SECURITY_HEADERS.get(h.header_name, {}).get("weight", 5) * (h.score / 10)
        for h in required
        if h.score > 0
    )
    header_score = int((earned_weight / total_weight * 60) if total_weight else 0)

    # ── CSP score (20 pts) ──
    csp_score = int((csp.score / 10 * 20) if csp and csp.raw else 0)

    # ── HSTS score (10 pts) ──
    hsts_score = int((hsts.score / 10 * 10) if hsts and hsts.raw else 0)

    # ── Cookie score (10 pts) ──
    if cookies:
        avg_cookie = sum(c.score for c in cookies) / len(cookies)
        cookie_score = int(avg_cookie / 10 * 10)
    else:
        cookie_score = 10   # no cookies = full marks for this category

    total = min(100, header_score + csp_score + hsts_score + cookie_score)

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if total >= threshold:
            grade = letter
            break

    return total, grade


# ══════════════════════════════════════════════════════════════
# 8. CORE ENDPOINT ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_endpoint(
    url:          str,
    method:       str = "GET",
    extra_headers: dict[str, str] = {},
    http_timeout: int = 10,
) -> EndpointHeaderResult:
    """
    Fetch an endpoint and run the full header security analysis:
      - All security headers
      - CSP deep-parse
      - HSTS deep-parse
      - All cookies
      - Info disclosure headers
      - Score + grade
    """
    ep = EndpointHeaderResult(url=url, method=method)

    try:
        req_headers = {
            "User-Agent": "Mozilla/5.0 (SecurityHeaderScanner/1.0)",
            **extra_headers,
        }
        resp = requests.request(
            method,
            url,
            headers=req_headers,
            timeout=http_timeout,
            allow_redirects=True,
            verify=False,
        )
        ep.status_code = resp.status_code

        # Normalise headers to lowercase keys
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        ep.headers_raw = raw_headers

        # Surface info-disclosure headers
        ep.server       = raw_headers.get("server")
        ep.x_powered_by = raw_headers.get("x-powered-by")

    except requests.exceptions.RequestException as e:
        ep.findings.append(f"Request failed: {e}")
        return ep

    # ══════════════════════════════
    # HEADER CHECKS
    # ══════════════════════════════
    for header_name in SECURITY_HEADERS:
        hc = check_header(header_name, raw_headers)
        ep.header_checks.append(hc)

        if not hc.present and SECURITY_HEADERS[header_name].get("required"):
            ep.missing_headers.append(header_name)

        if hc.issues and not SECURITY_HEADERS[header_name].get("should_be_absent"):
            ep.insecure_headers.append(header_name)

        for fk in hc.finding_keys:
            if fk not in ep.findings:
                ep.findings.append(fk)

    # ══════════════════════════════
    # CSP DEEP ANALYSIS
    # ══════════════════════════════
    csp_value = raw_headers.get("content-security-policy")
    if csp_value:
        ep.csp_analysis = analyze_csp(csp_value)

    # ══════════════════════════════
    # HSTS DEEP ANALYSIS
    # ══════════════════════════════
    hsts_value = raw_headers.get("strict-transport-security")
    if hsts_value:
        ep.hsts_analysis = analyze_hsts(hsts_value)

    # ══════════════════════════════
    # COOKIE ANALYSIS
    # ══════════════════════════════
    # requests merges Set-Cookie into one — use raw response cookies
    try:
        resp_obj = requests.request(
            method, url,
            headers=req_headers,
            timeout=http_timeout,
            allow_redirects=False,
            verify=False,
        )
        # All Set-Cookie headers
        set_cookie_headers = resp_obj.raw.headers.getlist("Set-Cookie") \
            if hasattr(resp_obj.raw.headers, "getlist") \
            else [v for k, v in resp_obj.raw.headers.items() if k.lower() == "set-cookie"]

        for sc in set_cookie_headers:
            ep.cookies.append(analyze_cookie(sc))

    except Exception:
        # fallback: parse from merged header
        sc_val = raw_headers.get("set-cookie")
        if sc_val:
            ep.cookies.append(analyze_cookie(sc_val))

    # ══════════════════════════════
    # SCORE + GRADE
    # ══════════════════════════════
    ep.total_score, ep.grade = calculate_grade(
        ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
    )

    # ══════════════════════════════
    # OVERALL VERDICT
    # ══════════════════════════════
    ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)

    # Worst severity across all checks
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = "info"
    for hc in ep.header_checks:
        if severity_rank.get(hc.severity, 0) > severity_rank.get(worst, 0):
            worst = hc.severity
    for ck in ep.cookies:
        if severity_rank.get(ck.severity, 0) > severity_rank.get(worst, 0):
            worst = ck.severity
    ep.severity = worst

    return ep


def bulk_analyze(
    urls:         list[str],
    methods:      list[str] = ["GET"],
    extra_headers: dict[str, str] = {},
    threads:      int = 10,
    http_timeout: int = 10,
) -> list[EndpointHeaderResult]:
    """Analyze multiple endpoints in parallel."""
    results = []
    tasks   = [(url, method) for url in urls for method in methods]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(analyze_endpoint, url, method, extra_headers, http_timeout): (url, method)
            for url, method in tasks
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                url, method = futures[future]
                results.append(EndpointHeaderResult(
                    url=url, method=method,
                    findings=[f"Analysis failed: {e}"],
                ))
    return results


# ══════════════════════════════════════════════════════════════
# 9. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_curl_headers(stdout: str, stderr: str, url: str) -> EndpointHeaderResult:
    """
    Parse curl -I / -v output into an EndpointHeaderResult.
    Extracts all response headers from verbose output.
    """
    ep  = EndpointHeaderResult(url=url)
    raw = stdout + "\n" + stderr

    headers_dict: dict[str, str] = {}

    for line in raw.splitlines():
        # Remove curl verbose prefix (< for response headers)
        clean = re.sub(r"^[<*]\s*", "", line).strip()

        # HTTP status line
        status_m = re.match(r"HTTP/[\d.]+ (\d+)", clean)
        if status_m:
            ep.status_code = int(status_m.group(1))
            continue

        # Header lines
        colon_idx = clean.find(":")
        if colon_idx > 0:
            name  = clean[:colon_idx].strip().lower()
            value = clean[colon_idx + 1:].strip()
            if re.match(r"^[a-z][a-z0-9\-]*$", name):
                headers_dict[name] = value

    ep.headers_raw  = headers_dict
    ep.server       = headers_dict.get("server")
    ep.x_powered_by = headers_dict.get("x-powered-by")

    # Run all header checks
    for header_name in SECURITY_HEADERS:
        hc = check_header(header_name, headers_dict)
        ep.header_checks.append(hc)
        if not hc.present and SECURITY_HEADERS[header_name].get("required"):
            ep.missing_headers.append(header_name)
        if hc.issues:
            ep.insecure_headers.append(header_name)
        for fk in hc.finding_keys:
            if fk not in ep.findings:
                ep.findings.append(fk)

    csp_val = headers_dict.get("content-security-policy")
    if csp_val:
        ep.csp_analysis = analyze_csp(csp_val)

    hsts_val = headers_dict.get("strict-transport-security")
    if hsts_val:
        ep.hsts_analysis = analyze_hsts(hsts_val)

    sc_val = headers_dict.get("set-cookie")
    if sc_val:
        ep.cookies.append(analyze_cookie(sc_val))

    ep.total_score, ep.grade = calculate_grade(
        ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
    )
    ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)

    return ep


def parse_httpx_output(stdout: str, stderr: str) -> list[EndpointHeaderResult]:
    """
    Parse httpx JSON output.
    httpx -json outputs one JSON object per line.
    """
    results = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            url  = data.get("url", data.get("input", "unknown"))
            ep   = EndpointHeaderResult(url=url)
            ep.status_code = data.get("status-code")

            # httpx puts headers in a dict
            raw_hdrs = {}
            for k, v in (data.get("header", {}) or {}).items():
                raw_hdrs[k.lower()] = v if isinstance(v, str) else v[0] if v else ""

            ep.headers_raw  = raw_hdrs
            ep.server       = raw_hdrs.get("server")
            ep.x_powered_by = raw_hdrs.get("x-powered-by")

            for header_name in SECURITY_HEADERS:
                hc = check_header(header_name, raw_hdrs)
                ep.header_checks.append(hc)
                if not hc.present and SECURITY_HEADERS[header_name].get("required"):
                    ep.missing_headers.append(header_name)
                if hc.issues:
                    ep.insecure_headers.append(header_name)
                for fk in hc.finding_keys:
                    if fk not in ep.findings:
                        ep.findings.append(fk)

            csp_val = raw_hdrs.get("content-security-policy")
            if csp_val:
                ep.csp_analysis = analyze_csp(csp_val)

            hsts_val = raw_hdrs.get("strict-transport-security")
            if hsts_val:
                ep.hsts_analysis = analyze_hsts(hsts_val)

            ep.total_score, ep.grade = calculate_grade(
                ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
            )
            ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)
            results.append(ep)

        except json.JSONDecodeError:
            continue

    return results


def parse_securityheaders(stdout: str, target: str) -> EndpointHeaderResult:
    """
    Parse securityheaders.com API / CLI JSON response.
    """
    ep = EndpointHeaderResult(url=target)

    try:
        data = json.loads(stdout)
        headers_section = data.get("headers", data.get("responseHeaders", {}))

        raw_hdrs = {}
        for k, v in headers_section.items():
            raw_hdrs[k.lower()] = v if isinstance(v, str) else json.dumps(v)

        ep.headers_raw = raw_hdrs

        # Grade from securityheaders.com
        grade_raw = data.get("grade", data.get("score", ""))
        if grade_raw:
            ep.grade = str(grade_raw).upper()

        # Run our own checks on top
        for header_name in SECURITY_HEADERS:
            hc = check_header(header_name, raw_hdrs)
            ep.header_checks.append(hc)
            if not hc.present and SECURITY_HEADERS[header_name].get("required"):
                ep.missing_headers.append(header_name)

        csp_val = raw_hdrs.get("content-security-policy")
        if csp_val:
            ep.csp_analysis = analyze_csp(csp_val)

        hsts_val = raw_hdrs.get("strict-transport-security")
        if hsts_val:
            ep.hsts_analysis = analyze_hsts(hsts_val)

        ep.total_score, ep.grade = calculate_grade(
            ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
        )
        ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)

    except (json.JSONDecodeError, Exception) as e:
        ep.findings.append(f"Parse error: {e}")

    return ep


# ══════════════════════════════════════════════════════════════
# 10. EXECUTOR
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
# 11. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def http_header_analysis(
    tool:      str,
    target:    str,
    args:      list[str] = [],
    endpoints: list[str] = [],
    methods:   list[str] = ["GET"],
) -> dict:
    """
    🔧 Agent Tool: HTTP Security Header Analyzer

    Capabilities:
      ┌───────────────────────────────────────────────────────────────────┐
      │  SECURITY HEADERS     CSP, HSTS, X-Frame, X-Content-Type,        │
      │                       Referrer-Policy, Permissions-Policy,        │
      │                       COOP, COEP, CORP, Cache-Control             │
      │  CSP ANALYSIS         Deep directive parse, unsafe-inline/eval,   │
      │                       wildcards, nonces, hashes, missing dirs      │
      │  HSTS ANALYSIS        max-age, includeSubDomains, preload         │
      │  COOKIE FLAGS         Secure, HttpOnly, SameSite, domain scope    │
      │  INFO DISCLOSURE      Server, X-Powered-By, X-AspNet-Version      │
      │  SCORING              Per-header + total score (0-100) + grade    │
      │  TOOL INTEGRATION     curl, httpx, securityheaders, manual        │
      └───────────────────────────────────────────────────────────────────┘

    Args:
        tool:      "curl" | "httpx" | "securityheaders" | "manual"
        target:    URL or domain
        args:      Raw tool arguments — agent decides
        endpoints: Additional paths/URLs to test
        methods:   HTTP methods to test (GET, POST, OPTIONS...)

    Tool args reference:
      curl:
        Verbose:  ["-v"] → auto-injected
        Headers:  ["-H", "Cookie: session=abc"]
        Follow:   ["-L"]
        Timeout:  ["--max-time", "10"]

      httpx:
        Threads:  ["-threads", "50"]
        Rate:     ["-rate-limit", "100"]
        Headers:  ["-H", "Cookie: session=abc"]
        Silent:   ["-silent"] → auto-injected
        JSON:     ["-json"]   → auto-injected

      securityheaders:
        (uses securityheaders.com API or local CLI)
        Score:    ["--score"]
        Format:   ["--json"]  → auto-injected

      manual:
        (pure Python requests — no args needed)
        Full analysis with all checks built-in.

    Returns:
        Structured JSON: endpoints → header_checks → CSP → HSTS →
                         cookies → score → grade → findings
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = HeaderAnalysisRequest(
            tool=tool, target=target, args=args,
            endpoints=endpoints, methods=methods,
        )
    except Exception as e:
        return HeaderScanResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target
    if not target.startswith("http"):
        target = f"https://{target}"

    results:     list[EndpointHeaderResult] = []
    command_str: str = ""
    raw_output:  str = ""
    error_msg:   Optional[str] = None

    # Build full URL list
    all_urls = [target]
    for ep_path in req.endpoints:
        if ep_path.startswith("http"):
            all_urls.append(ep_path)
        else:
            all_urls.append(f"{target.rstrip('/')}/{ep_path.lstrip('/')}")
    all_urls = list(dict.fromkeys(all_urls))

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_header_analysis({target}, methods={req.methods})"
        results = bulk_analyze(
            urls=all_urls,
            methods=req.methods,
            http_timeout=10,
            threads=10,
        )

    # ══════════════════════════════
    # TOOL: CURL
    # ══════════════════════════════
    elif tool == "curl":
        for url in all_urls:
            for method in req.methods:
                cmd = [
                    "curl", "-v", "-s", "-I",
                    "--max-time", "15",
                    "-X", method,
                    "-A", "Mozilla/5.0 (SecurityHeaderScanner/1.0)",
                    "-L",
                ]
                cmd += list(req.args)
                cmd.append(url)

                command_str = " ".join(cmd)
                stdout, stderr, rc = safe_execute(cmd, req.timeout)
                raw_output += (stderr or stdout)[:2000]

                ep = parse_curl_headers(stdout, stderr, url)
                ep.method = method
                results.append(ep)

                if rc != 0 and not ep.headers_raw:
                    error_msg = (stderr or stdout)[:300]

    # ══════════════════════════════
    # TOOL: HTTPX
    # ══════════════════════════════
    elif tool == "httpx":
        import tempfile, os

        tmp_file = None
        if len(all_urls) > 1:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="header_urls_"
            )
            tmp_file.write("\n".join(all_urls))
            tmp_file.close()
            cmd = ["httpx", "-l", tmp_file.name]
        else:
            cmd = ["httpx", "-u", target]

        # Auto-inject useful flags
        if "-json" not in req.args:
            cmd.append("-json")
        if "-silent" not in req.args:
            cmd.append("-silent")
        if "-include-response-header" not in req.args:
            cmd.extend(["-include-response-header"])

        # Include response headers for analysis
        header_flags = [
            "-H", "content-security-policy",
            "-H", "strict-transport-security",
            "-H", "x-frame-options",
            "-H", "x-content-type-options",
            "-H", "referrer-policy",
            "-H", "permissions-policy",
        ]
        cmd += header_flags
        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        parsed = parse_httpx_output(stdout, stderr)
        results.extend(parsed)

        # Enrich with manual check for missed endpoints
        checked_urls = {r.url for r in results}
        missed = [u for u in all_urls if u not in checked_urls]
        if missed:
            extra = bulk_analyze(missed, methods=["GET"], threads=10)
            results.extend(extra)

        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)

        if rc != 0 and not results:
            error_msg = (stderr or stdout)[:500]

    # ══════════════════════════════
    # TOOL: SECURITYHEADERS
    # ══════════════════════════════
    elif tool == "securityheaders":
        # Try CLI tool first, fallback to API
        cmd = ["securityheaders", "--json"]
        cmd += list(req.args)
        cmd.append(target)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        if stdout.strip():
            ep = parse_securityheaders(stdout, target)
            results.append(ep)
        else:
            # Fallback: use securityheaders.com API
            try:
                api_url = f"https://securityheaders.com/?q={target}&followRedirects=on"
                resp = requests.get(
                    api_url,
                    headers={"User-Agent": "SecurityHeaderScanner/1.0"},
                    timeout=20,
                )
                # API returns HTML — fall back to manual check
                ep = analyze_endpoint(target, method="GET")
                results.append(ep)
            except Exception as e:
                error_msg = f"securityheaders tool not found, API fallback failed: {e}"
                # Last resort: manual
                results = bulk_analyze(all_urls, methods=["GET"])

        # Always enrich all endpoints with manual check
        if len(all_urls) > 1:
            extra = bulk_analyze(all_urls[1:], methods=["GET"])
            results.extend(extra)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    vulnerable = [r for r in results if r.vulnerable]

    # Average grade
    grade_map    = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    grade_inv    = {v: k for k, v in grade_map.items()}
    if results:
        avg_val      = sum(grade_map.get(r.grade, 1) for r in results) // len(results)
        average_grade = grade_inv.get(avg_val, "F")
    else:
        average_grade = "F"

    return HeaderScanResult(
        success=len(results) > 0,
        tool=tool,
        target=target,
        command=command_str,
        total_endpoints=len(results),
        total_vulnerable=len(vulnerable),
        average_grade=average_grade,
        endpoints=results,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 12. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

HTTP_HEADER_TOOL_DEFINITION = {
    "name": "http_header_analysis",
    "description": (
        "Analyze HTTP security headers for a target. Checks: "
        "Content-Security-Policy (with full directive analysis), "
        "Strict-Transport-Security (max-age, includeSubDomains, preload), "
        "X-Frame-Options, X-Content-Type-Options, Referrer-Policy, "
        "Permissions-Policy, COOP, COEP, CORP, Cache-Control. "
        "Also checks cookie flags (Secure, HttpOnly, SameSite) and "
        "detects information disclosure headers (Server, X-Powered-By). "
        "Returns a score (0-100) and grade (A+ to F) per endpoint."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["curl", "httpx", "securityheaders", "manual"],
                "description": (
                    "curl            = raw HTTP header inspection via curl -v | "
                    "httpx           = fast multi-URL header collection | "
                    "securityheaders = securityheaders.com CLI / API | "
                    "manual          = built-in Python requests (full analysis, no deps)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Target URL or domain (e.g. 'https://example.com' or 'example.com')",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "curl:   ['-H', 'Cookie: session=abc', '-L', '--max-time', '15']\n"
                    "httpx:  ['-threads', '50', '-rate-limit', '100']\n"
                    "manual: [] (no args needed)"
                ),
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Additional endpoints to test beyond root. "
                    "e.g. ['/api/v1/user', '/login', '/admin', "
                    "'https://api.example.com/data']"
                ),
            },
            "methods": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "HTTP methods to test. "
                    "Default: ['GET']. "
                    "e.g. ['GET', 'POST', 'OPTIONS'] for full coverage"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # ─────────────────────────────
    # 1. Manual — full check
    # ─────────────────────────────
    r = http_header_analysis(
        tool="manual",
        target="https://example.com",
        endpoints=["/api/v1/user", "/login", "/admin"],
        methods=["GET", "POST"],
    )
    print("=== MANUAL FULL CHECK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. curl — verbose header dump
    # ─────────────────────────────
    r = http_header_analysis(
        tool="curl",
        target="https://example.com",
        args=["-H", "Cookie: session=test", "-L"],
        endpoints=["/api/user"],
    )
    print("=== CURL HEADER CHECK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. httpx — multi-URL fast scan
    # ─────────────────────────────
    r = http_header_analysis(
        tool="httpx",
        target="https://example.com",
        args=["-threads", "50"],
        endpoints=["/login", "/api/v1", "/admin", "/checkout"],
    )
    print("=== HTTPX MULTI-URL ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. securityheaders.com
    # ─────────────────────────────
    r = http_header_analysis(
        tool="securityheaders",
        target="https://example.com",
    )
    print("=== SECURITYHEADERS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. OPTIONS method (CORS pre-flight surface)
    # ─────────────────────────────
    r = http_header_analysis(
        tool="manual",
        target="https://api.example.com",
        methods=["GET", "OPTIONS"],
        endpoints=["/api/v1/data", "/api/v1/auth"],
    )
    print("=== OPTIONS METHOD CHECK ===")
    print(json.dumps(r, indent=2))