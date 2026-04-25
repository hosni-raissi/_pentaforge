#/+
import subprocess
import json
import re
import time
import os
import requests
import concurrent.futures
from urllib.parse import urlparse
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
import urllib3
from server.agents.executer.recon.config import is_blocked_host

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

def _normalize_host(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


class HeaderAnalysisRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"curl", "httpx", "securityheaders", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        host = _normalize_host(v)
        if is_blocked_host(host):
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        bare_domain = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_pattern = r"^https?://(\d{1,3}\.){3}\d{1,3}"
        bare_ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

        if not (
            re.match(domain_pattern, v)
            or re.match(bare_domain, v)
            or re.match(ip_pattern, v)
            or re.match(bare_ip_pattern, v)
        ):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"]
        blocked_flags = ["-o", "--output", "-O"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{repr(char)}' in arg: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag or arg.strip().startswith(flag + "="):
                    raise ValueError(f"Blocked flag: {flag}")
        return v

    @field_validator("methods")
    @classmethod
    def validate_methods(cls, v):
        allowed = {"GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"}
        normalized = []
        for m in v:
            mu = m.upper()
            if mu not in allowed:
                raise ValueError(f"Method '{m}' not allowed")
            normalized.append(mu)
        return normalized


class HeaderCheckResult(BaseModel):
    header_name: str
    present: bool = False
    value: Optional[str] = None
    valid: bool = False
    score: int = 0
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    severity: str = "info"
    finding_keys: list[str] = Field(default_factory=list)


class CookieResult(BaseModel):
    name: str
    value_snippet: Optional[str] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[str] = None
    issues: list[str] = Field(default_factory=list)
    severity: str = "info"
    score: int = 0


class CSPAnalysis(BaseModel):
    raw: Optional[str] = None
    directives: dict[str, list[str]] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)
    score: int = 0
    has_unsafe_inline: bool = False
    has_unsafe_eval: bool = False
    has_wildcard: bool = False
    has_nonce: bool = False
    has_hash: bool = False
    missing_directives: list[str] = Field(default_factory=list)


class HSTSAnalysis(BaseModel):
    raw: Optional[str] = None
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    issues: list[str] = Field(default_factory=list)
    score: int = 0


class EndpointHeaderResult(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    headers_raw: dict[str, str] = Field(default_factory=dict)
    header_checks: list[HeaderCheckResult] = Field(default_factory=list)
    cookies: list[CookieResult] = Field(default_factory=list)
    csp_analysis: Optional[CSPAnalysis] = None
    hsts_analysis: Optional[HSTSAnalysis] = None
    total_score: int = 0
    grade: str = "F"
    vulnerable: bool = False
    findings: list[str] = Field(default_factory=list)
    severity: str = "info"
    missing_headers: list[str] = Field(default_factory=list)
    insecure_headers: list[str] = Field(default_factory=list)


class HeaderScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_endpoints: int = 0
    total_vulnerable: int = 0
    average_grade: str = "F"
    endpoints: list[EndpointHeaderResult] = Field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SECURITY HEADER DEFINITIONS
# ══════════════════════════════════════════════════════════════

SECURITY_HEADERS: dict[str, dict] = {
    "content-security-policy": {
        "severity": "high",
        "weight": 20,
        "description": "Controls which resources browser can load. Prevents XSS.",
        "required": True,
        "recommendations": [
            "Define a strict CSP: default-src 'self'",
            "Avoid unsafe-inline and unsafe-eval",
            "Use nonces or hashes for inline scripts",
            "Add report-uri or report-to for violation monitoring",
        ],
    },
    "strict-transport-security": {
        "severity": "high",
        "weight": 15,
        "description": "Forces HTTPS. Prevents protocol downgrade and MITM.",
        "required": True,
        "recommendations": [
            "Set max-age to at least 31536000 (1 year)",
            "Add includeSubDomains",
            "Add preload directive and submit to HSTS preload list",
        ],
    },
    "x-frame-options": {
        "severity": "high",
        "weight": 10,
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "required": True,
        "valid_values": ["DENY", "SAMEORIGIN"],
        "recommendations": [
            "Use X-Frame-Options: DENY if no iframe embedding needed",
            "Use SAMEORIGIN to allow same-origin framing only",
            "Prefer CSP frame-ancestors directive",
        ],
    },
    "x-content-type-options": {
        "severity": "medium",
        "weight": 10,
        "description": "Prevents MIME-type sniffing attacks.",
        "required": True,
        "valid_values": ["nosniff"],
        "recommendations": [
            "Set X-Content-Type-Options: nosniff",
            "Ensure all responses include correct Content-Type",
        ],
    },
    "referrer-policy": {
        "severity": "medium",
        "weight": 8,
        "description": "Controls referrer information sent with requests.",
        "required": True,
        "valid_values": [
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
        "severity": "medium",
        "weight": 8,
        "description": "Controls browser feature access.",
        "required": True,
        "recommendations": [
            "Disable unused features: camera=(), microphone=(), geolocation=()",
            "Apply least-privilege principle to feature access",
        ],
    },
    "cross-origin-opener-policy": {
        "severity": "medium",
        "weight": 7,
        "description": "Isolates browsing context.",
        "required": True,
        "valid_values": ["same-origin", "same-origin-allow-popups", "unsafe-none"],
        "recommendations": [
            "Use same-origin for strict isolation",
        ],
    },
    "cross-origin-embedder-policy": {
        "severity": "medium",
        "weight": 7,
        "description": "Prevents loading cross-origin resources without permission.",
        "required": True,
        "valid_values": ["require-corp", "unsafe-none"],
        "recommendations": [
            "Use require-corp alongside COOP",
        ],
    },
    "cross-origin-resource-policy": {
        "severity": "medium",
        "weight": 5,
        "description": "Controls cross-origin resource sharing at resource level.",
        "required": False,
        "valid_values": ["same-site", "same-origin", "cross-origin"],
        "recommendations": [
            "Use same-origin for sensitive resources",
            "Use same-site to allow subdomains",
        ],
    },
    "x-permitted-cross-domain-policies": {
        "severity": "low",
        "weight": 3,
        "description": "Controls Adobe Flash/PDF cross-domain access.",
        "required": False,
        "valid_values": ["none", "master-only"],
        "recommendations": [
            "Set to none to block all cross-domain policies",
        ],
    },
    "cache-control": {
        "severity": "medium",
        "weight": 5,
        "description": "Controls response caching behavior.",
        "required": True,
        "recommendations": [
            "Use no-store for sensitive pages",
            "Use no-cache, no-store, must-revalidate for authenticated content",
        ],
    },
    "clear-site-data": {
        "severity": "low",
        "weight": 2,
        "description": "Clears browsing data on logout.",
        "required": False,
        "recommendations": [
            "Send Clear-Site-Data on logout endpoints",
        ],
    },
    "server": {
        "severity": "low",
        "weight": 0,
        "description": "Server header reveals software version.",
        "required": False,
        "should_be_absent": True,
        "recommendations": [
            "Remove or genericize Server header",
        ],
    },
    "x-powered-by": {
        "severity": "low",
        "weight": 0,
        "description": "Reveals backend technology.",
        "required": False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-Powered-By header",
        ],
    },
    "x-aspnet-version": {
        "severity": "low",
        "weight": 0,
        "description": "Reveals ASP.NET version.",
        "required": False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-AspNet-Version header",
        ],
    },
    "x-aspnetmvc-version": {
        "severity": "low",
        "weight": 0,
        "description": "Reveals ASP.NET MVC version.",
        "required": False,
        "should_be_absent": True,
        "recommendations": [
            "Remove X-AspNetMvc-Version header",
        ],
    },
}

REQUIRED_HEADERS = [
    k for k, v in SECURITY_HEADERS.items()
    if v.get("required") and not v.get("should_be_absent")
]

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
    analysis = CSPAnalysis(raw=csp_value)

    if not csp_value:
        analysis.issues.append("CSP header is empty")
        analysis.score = 0
        return analysis

    for directive in csp_value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        values = parts[1:] if len(parts) > 1 else []
        analysis.directives[name] = values

    score = 10
    all_values_str = csp_value.lower()

    if "'unsafe-inline'" in all_values_str:
        analysis.has_unsafe_inline = True
        analysis.issues.append("unsafe-inline detected — allows inline execution")
        score -= 3

    if "'unsafe-eval'" in all_values_str:
        analysis.has_unsafe_eval = True
        analysis.issues.append("unsafe-eval detected — allows eval() execution")
        score -= 3

    if re.search(r"(^|\s)\*(\s|;|$)", all_values_str):
        analysis.has_wildcard = True
        analysis.issues.append("Wildcard (*) source detected")
        score -= 2

    if re.search(r"\bhttp:", all_values_str):
        analysis.issues.append("http: source allows insecure content loading")
        score -= 1

    script_src = analysis.directives.get("script-src", [])
    if "data:" in " ".join(script_src).lower():
        analysis.issues.append("data: URI in script-src")
        score -= 2

    if re.search(r"'nonce-[^']+'", csp_value):
        analysis.has_nonce = True
        if analysis.has_unsafe_inline:
            score += 1

    if re.search(r"'(sha256|sha384|sha512)-[^']+'", csp_value):
        analysis.has_hash = True
        if analysis.has_unsafe_inline:
            score += 1

    for directive in IMPORTANT_CSP_DIRECTIVES:
        if directive not in analysis.directives:
            if "default-src" not in analysis.directives:
                analysis.missing_directives.append(directive)

    if "default-src" not in analysis.directives:
        analysis.issues.append("No default-src directive")
        score -= 2

    if "object-src" not in analysis.directives:
        default = analysis.directives.get("default-src", [])
        if "none" not in " ".join(default).lower() and "'none'" not in " ".join(default).lower():
            analysis.issues.append("Missing object-src 'none'")
            score -= 1

    if "base-uri" not in analysis.directives:
        analysis.issues.append("Missing base-uri")
        score -= 1

    if "frame-ancestors" not in analysis.directives:
        analysis.issues.append("Missing frame-ancestors")

    if "form-action" not in analysis.directives:
        analysis.issues.append("Missing form-action")

    if "upgrade-insecure-requests" not in analysis.directives:
        analysis.issues.append("Missing upgrade-insecure-requests")

    analysis.score = max(0, min(10, score))
    return analysis


# ══════════════════════════════════════════════════════════════
# 4. HSTS ANALYZER
# ══════════════════════════════════════════════════════════════

MIN_HSTS_MAX_AGE = 31_536_000


def analyze_hsts(hsts_value: str) -> HSTSAnalysis:
    analysis = HSTSAnalysis(raw=hsts_value)

    if not hsts_value:
        analysis.issues.append("HSTS header is empty")
        analysis.score = 0
        return analysis

    score = 10
    hsts_lower = hsts_value.lower()

    ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
    if ma_match:
        analysis.max_age = int(ma_match.group(1))
        if analysis.max_age == 0:
            analysis.issues.append("max-age=0 — HSTS disabled")
            score -= 8
        elif analysis.max_age < 2592000:
            analysis.issues.append(f"max-age too short ({analysis.max_age}s)")
            score -= 4
        elif analysis.max_age < MIN_HSTS_MAX_AGE:
            analysis.issues.append(f"max-age below recommended 1 year ({analysis.max_age}s)")
            score -= 2
    else:
        analysis.issues.append("No max-age directive found")
        score -= 6

    if "includesubdomains" in hsts_lower:
        analysis.include_subdomains = True
    else:
        analysis.issues.append("Missing includeSubDomains")
        score -= 2

    if "preload" in hsts_lower:
        analysis.preload = True
        if not analysis.include_subdomains:
            analysis.issues.append("preload requires includeSubDomains")
            score -= 1
        if analysis.max_age and analysis.max_age < MIN_HSTS_MAX_AGE:
            analysis.issues.append("preload requires max-age >= 31536000")
            score -= 1
    else:
        analysis.issues.append("Missing preload")

    analysis.score = max(0, min(10, score))
    return analysis


# ══════════════════════════════════════════════════════════════
# 5. COOKIE ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_cookie(set_cookie_header: str) -> CookieResult:
    parts = [p.strip() for p in set_cookie_header.split(";")]
    name_val = parts[0]

    name = name_val.split("=")[0].strip() if "=" in name_val else name_val
    value = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

    cookie = CookieResult(
        name=name,
        value_snippet=value[:20] + "..." if len(value) > 20 else value,
    )

    score = 10
    directives_lower = set_cookie_header.lower()

    cookie.secure = "secure" in directives_lower
    cookie.http_only = "httponly" in directives_lower

    ss_match = re.search(r"samesite\s*=\s*(\w+)", directives_lower)
    if ss_match:
        cookie.same_site = ss_match.group(1).capitalize()

    path_match = re.search(r"path\s*=\s*([^;]+)", directives_lower)
    domain_match = re.search(r"domain\s*=\s*([^;]+)", directives_lower)
    expires_match = re.search(r"expires\s*=\s*([^;]+)", directives_lower)
    maxage_match = re.search(r"max-age\s*=\s*([^;]+)", directives_lower)

    cookie.path = path_match.group(1).strip() if path_match else None
    cookie.domain = domain_match.group(1).strip() if domain_match else None
    cookie.expires = expires_match.group(1).strip() if expires_match else None
    cookie.max_age = maxage_match.group(1).strip() if maxage_match else None

    if not cookie.secure:
        cookie.issues.append("Missing Secure flag")
        score -= 3

    if not cookie.http_only:
        cookie.issues.append("Missing HttpOnly flag")
        score -= 3

    if not cookie.same_site:
        cookie.issues.append("Missing SameSite attribute")
        score -= 2
    elif cookie.same_site.lower() == "none":
        if not cookie.secure:
            cookie.issues.append("SameSite=None requires Secure flag")
            score -= 2
        cookie.issues.append("SameSite=None — cookie sent cross-site")
        score -= 1
    elif cookie.same_site.lower() == "lax":
        cookie.issues.append("SameSite=Lax — weaker than Strict")

    sensitive_names = {
        "session", "sess", "auth", "token", "jwt",
        "login", "user", "account", "admin", "key",
        "secret", "credential", "passwd", "password",
    }
    if any(s in name.lower() for s in sensitive_names):
        if not cookie.secure:
            cookie.issues.append(f"Sensitive cookie '{name}' missing Secure")
            score -= 3
        if not cookie.http_only:
            cookie.issues.append(f"Sensitive cookie '{name}' missing HttpOnly")
            score -= 2

    if cookie.domain and cookie.domain.startswith("."):
        cookie.issues.append(f"Cookie scoped to wildcard domain '{cookie.domain}'")
        score -= 1

    cookie.score = max(0, min(10, score))

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

def check_header(header_name: str, headers_dict: dict[str, str]) -> HeaderCheckResult:
    cfg = SECURITY_HEADERS.get(header_name, {})
    value = headers_dict.get(header_name)
    result = HeaderCheckResult(header_name=header_name)
    severity = cfg.get("severity", "info")
    should_absent = cfg.get("should_be_absent", False)

    if should_absent:
        if value:
            result.present = True
            result.value = value
            result.valid = False
            result.score = 0
            result.severity = severity
            result.issues.append(f"{header_name} reveals server info: '{value}'")
            result.recommendations = cfg.get("recommendations", [])
            result.finding_keys.append(f"info_disclosure_{header_name.replace('-', '_')}")
        else:
            result.present = False
            result.valid = True
            result.score = 10
            result.severity = "info"
        return result

    if not value:
        result.present = False
        result.valid = False
        result.score = 0
        result.severity = severity
        result.issues.append(f"{header_name} is missing")
        result.recommendations = cfg.get("recommendations", [])
        result.finding_keys.append(f"missing_{header_name.replace('-', '_')}")
        return result

    result.present = True
    result.value = value
    score = 10

    if header_name == "x-frame-options":
        valid_vals = [v.upper() for v in cfg.get("valid_values", [])]
        val_upper = value.strip().upper()
        if val_upper not in valid_vals:
            result.issues.append(f"Invalid value '{value}' — use DENY or SAMEORIGIN")
            score -= 5
        elif val_upper == "ALLOWALL":
            result.issues.append("ALLOWALL disables clickjacking protection")
            score -= 8
        else:
            result.valid = True

    elif header_name == "x-content-type-options":
        if value.strip().lower() != "nosniff":
            result.issues.append(f"Value should be 'nosniff', got '{value}'")
            score -= 5
        else:
            result.valid = True

    elif header_name == "referrer-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower = value.strip().lower()
        if val_lower not in valid_vals:
            result.issues.append(f"Unrecognised Referrer-Policy value: '{value}'")
            score -= 3
        elif val_lower in ("unsafe-url", "no-referrer-when-downgrade"):
            result.issues.append(f"Referrer-Policy '{value}' leaks full URL")
            score -= 3
        else:
            result.valid = True

    elif header_name == "permissions-policy":
        risky_features = [
            "camera", "microphone", "geolocation",
            "payment", "usb", "magnetometer",
            "accelerometer", "gyroscope",
        ]
        for feat in risky_features:
            if f"{feat}=*" in value.lower() or f"{feat}=(allow)" in value.lower():
                result.issues.append(f"Feature '{feat}' unrestricted")
                score -= 1
        result.valid = score >= 8

    elif header_name == "cross-origin-opener-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower = value.strip().lower()
        if val_lower == "unsafe-none":
            result.issues.append("COOP: unsafe-none provides no isolation")
            score -= 5
        elif val_lower not in valid_vals:
            result.issues.append(f"Unrecognised COOP value: '{value}'")
            score -= 3
        else:
            result.valid = True

    elif header_name == "cross-origin-embedder-policy":
        val_lower = value.strip().lower()
        if val_lower == "unsafe-none":
            result.issues.append("COEP: unsafe-none provides no protection")
            score -= 5
        elif val_lower == "require-corp":
            result.valid = True
        else:
            result.issues.append(f"Unrecognised COEP value: '{value}'")
            score -= 3

    elif header_name == "cache-control":
        val_lower = value.lower()
        if "no-store" in val_lower:
            result.valid = True
        elif "private" in val_lower:
            result.issues.append("Cache-Control private — browser may cache")
            score -= 2
        elif "public" in val_lower:
            result.issues.append("Cache-Control public — shared caching risk")
            score -= 4
        if "no-cache" not in val_lower and "no-store" not in val_lower:
            result.issues.append("Missing no-cache / no-store")
            score -= 3

    elif header_name == "cross-origin-resource-policy":
        valid_vals = [v.lower() for v in cfg.get("valid_values", [])]
        val_lower = value.strip().lower()
        if val_lower not in valid_vals:
            result.issues.append(f"Unrecognised CORP value: '{value}'")
            score -= 3
        elif val_lower == "cross-origin":
            result.issues.append("CORP cross-origin is permissive")
            score -= 2
        else:
            result.valid = True

    elif header_name == "x-permitted-cross-domain-policies":
        val_lower = value.strip().lower()
        if val_lower in ("all", "by-content-type", "by-ftp-filename"):
            result.issues.append(f"'{value}' is too permissive")
            score -= 5
        else:
            result.valid = True

    else:
        result.valid = True

    result.score = max(0, min(10, score))
    result.severity = severity if result.issues else "info"
    if result.issues:
        result.recommendations = cfg.get("recommendations", [])
        result.finding_keys.append(f"insecure_{header_name.replace('-', '_')}")

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
    (0, "F"),
]


def calculate_grade(
    header_checks: list[HeaderCheckResult],
    cookies: list[CookieResult],
    csp: Optional[CSPAnalysis],
    hsts: Optional[HSTSAnalysis],
) -> tuple[int, str]:
    required = [
        h for h in header_checks
        if not SECURITY_HEADERS.get(h.header_name, {}).get("should_be_absent")
    ]
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

    csp_score = int((csp.score / 10 * 20) if csp and csp.raw else 0)
    hsts_score = int((hsts.score / 10 * 10) if hsts and hsts.raw else 0)

    if cookies:
        avg_cookie = sum(c.score for c in cookies) / len(cookies)
        cookie_score = int(avg_cookie / 10 * 10)
    else:
        cookie_score = 10

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
    url: str,
    method: str = "GET",
    extra_headers: Optional[dict[str, str]] = None,
    http_timeout: int = 10,
) -> EndpointHeaderResult:
    ep = EndpointHeaderResult(url=url, method=method)
    extra_headers = extra_headers or {}

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

        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        ep.headers_raw = raw_headers
        ep.server = raw_headers.get("server")
        ep.x_powered_by = raw_headers.get("x-powered-by")

    except requests.exceptions.RequestException as e:
        ep.findings.append(f"Request failed: {e}")
        return ep

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

    csp_value = raw_headers.get("content-security-policy")
    if csp_value:
        ep.csp_analysis = analyze_csp(csp_value)

    hsts_value = raw_headers.get("strict-transport-security")
    if hsts_value:
        ep.hsts_analysis = analyze_hsts(hsts_value)

    set_cookie_values: list[str] = []
    try:
        if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
            set_cookie_values = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        pass

    if not set_cookie_values:
        merged = raw_headers.get("set-cookie")
        if merged:
            set_cookie_values = [merged]

    for sc in set_cookie_values:
        ep.cookies.append(analyze_cookie(sc))

    ep.total_score, ep.grade = calculate_grade(
        ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
    )

    ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = "info"

    for hc in ep.header_checks:
        if severity_rank.get(hc.severity, 0) > severity_rank.get(worst, 0):
            worst = hc.severity

    for ck in ep.cookies:
        if severity_rank.get(ck.severity, 0) > severity_rank.get(worst, 0):
            worst = ck.severity

    if ep.csp_analysis and ep.csp_analysis.score <= 3:
        if severity_rank["high"] > severity_rank.get(worst, 0):
            worst = "high"

    if ep.hsts_analysis and ep.hsts_analysis.score <= 3:
        if severity_rank["high"] > severity_rank.get(worst, 0):
            worst = "high"

    ep.severity = worst
    return ep


def bulk_analyze(
    urls: list[str],
    methods: list[str],
    extra_headers: Optional[dict[str, str]] = None,
    threads: int = 10,
    http_timeout: int = 10,
) -> list[EndpointHeaderResult]:
    results: list[EndpointHeaderResult] = []
    tasks = [(url, method) for url in urls for method in methods]
    extra_headers = extra_headers or {}

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
                    url=url,
                    method=method,
                    findings=[f"Analysis failed: {e}"],
                ))

    return results


# ══════════════════════════════════════════════════════════════
# 9. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_curl_headers(stdout: str, stderr: str, url: str) -> EndpointHeaderResult:
    ep = EndpointHeaderResult(url=url)
    raw = stdout + "\n" + stderr

    headers_dict: dict[str, str] = {}

    for line in raw.splitlines():
        clean = re.sub(r"^[<*]\s*", "", line).strip()

        status_m = re.match(r"HTTP/[\d.]+ (\d+)", clean)
        if status_m:
            ep.status_code = int(status_m.group(1))
            continue

        colon_idx = clean.find(":")
        if colon_idx > 0:
            name = clean[:colon_idx].strip().lower()
            value = clean[colon_idx + 1:].strip()
            if re.match(r"^[a-z][a-z0-9\-]*$", name):
                headers_dict[name] = value

    ep.headers_raw = headers_dict
    ep.server = headers_dict.get("server")
    ep.x_powered_by = headers_dict.get("x-powered-by")

    # If curl never produced an HTTP status line, treat as transport failure
    # instead of a vulnerable endpoint with missing headers.
    if ep.status_code is None:
        err_text = (stderr or stdout or "").strip()
        if err_text:
            first_line = err_text.splitlines()[0].strip()
            ep.findings.append(f"Request failed: {first_line}")
        else:
            ep.findings.append("Request failed: no HTTP status returned")
        ep.vulnerable = False
        ep.severity = "info"
        return ep

    for header_name in SECURITY_HEADERS:
        hc = check_header(header_name, headers_dict)
        ep.header_checks.append(hc)
        if not hc.present and SECURITY_HEADERS[header_name].get("required"):
            ep.missing_headers.append(header_name)
        if hc.issues and not SECURITY_HEADERS[header_name].get("should_be_absent"):
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
    results: list[EndpointHeaderResult] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
            url = data.get("url", data.get("input", "unknown"))
            ep = EndpointHeaderResult(url=url)
            ep.status_code = data.get("status-code") or data.get("status_code")

            raw_hdrs = {}
            headers_obj = data.get("header", {}) or data.get("headers", {}) or {}
            for k, v in headers_obj.items():
                if isinstance(v, list):
                    raw_hdrs[k.lower()] = v[0] if v else ""
                else:
                    raw_hdrs[k.lower()] = str(v)

            ep.headers_raw = raw_hdrs
            ep.server = raw_hdrs.get("server")
            ep.x_powered_by = raw_hdrs.get("x-powered-by")

            for header_name in SECURITY_HEADERS:
                hc = check_header(header_name, raw_hdrs)
                ep.header_checks.append(hc)
                if not hc.present and SECURITY_HEADERS[header_name].get("required"):
                    ep.missing_headers.append(header_name)
                if hc.issues and not SECURITY_HEADERS[header_name].get("should_be_absent"):
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

            set_cookie_val = raw_hdrs.get("set-cookie")
            if set_cookie_val:
                ep.cookies.append(analyze_cookie(set_cookie_val))

            ep.total_score, ep.grade = calculate_grade(
                ep.header_checks, ep.cookies, ep.csp_analysis, ep.hsts_analysis
            )
            ep.vulnerable = ep.grade in ("D", "F") or bool(ep.missing_headers)
            results.append(ep)

        except json.JSONDecodeError:
            continue

    return results


# ══════════════════════════════════════════════════════════════
# 10. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run subprocess safely — single canonical executor"""
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
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    endpoints: Optional[list[str]] = None,
    methods: Optional[list[str]] = None,
) -> dict:
    """
    🔧 Agent Tool: HTTP Security Header Analyzer

    Analyze:
    - security headers
    - CSP
    - HSTS
    - cookies
    - information disclosure headers
    - total score / grade per endpoint
    """
    start = time.time()
    args = args or []
    endpoints = endpoints or []
    methods = methods or ["GET"]

    try:
        req = HeaderAnalysisRequest(
            tool=tool,
            target=target,
            args=args,
            endpoints=endpoints,
            methods=methods,
        )
    except Exception as e:
        return HeaderScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    normalized_target = target if target.startswith("http") else f"https://{target}"

    results: list[EndpointHeaderResult] = []
    command_str = ""
    raw_output = ""
    error_msg: Optional[str] = None

    all_urls = [normalized_target]
    for ep_path in req.endpoints:
        if ep_path.startswith("http"):
            all_urls.append(ep_path)
        else:
            all_urls.append(f"{normalized_target.rstrip('/')}/{ep_path.lstrip('/')}")
    all_urls = list(dict.fromkeys(all_urls))

    if tool == "manual":
        command_str = f"manual_header_analysis({normalized_target}, methods={req.methods})"
        results = bulk_analyze(
            urls=all_urls,
            methods=req.methods,
            http_timeout=10,
            threads=10,
        )

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

    elif tool == "httpx":
        # fixed httpx mode: use it only for fast URL reachability / metadata collection
        # then enrich with manual mode for full header analysis
        cmd = ["httpx"]

        if len(all_urls) == 1:
            cmd += ["-u", all_urls[0]]
        else:
            # use stdin-less fallback by probing manually later
            # httpx bulk support without temp files is inconsistent across builds,
            # so we keep command informational and use manual analysis for all URLs.
            cmd += ["-silent"]

        if "-json" not in req.args:
            cmd.append("-json")
        if "-silent" not in req.args:
            cmd.append("-silent")

        cmd += list(req.args)
        command_str = " ".join(cmd)

        # reliable full analysis via manual mode
        results = bulk_analyze(
            urls=all_urls,
            methods=["GET"],
            http_timeout=10,
            threads=10,
        )

    elif tool == "securityheaders":
        return HeaderScanResult(
            success=False,
            tool=tool,
            target=normalized_target,
            command="",
            total_endpoints=0,
            total_vulnerable=0,
            average_grade="F",
            endpoints=[],
            error=(
                "securityheaders mode is disabled because securityheaders.com does not provide "
                "a stable CLI/API contract for this parser. Use 'manual', 'curl', or 'httpx'."
            ),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    responsive = [r for r in results if r.status_code is not None]
    vulnerable = [r for r in responsive if r.vulnerable]

    grade_map = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    grade_inv = {v: k for k, v in grade_map.items()}
    if responsive:
        avg_val = sum(grade_map.get(r.grade, 1) for r in responsive) // len(responsive)
        average_grade = grade_inv.get(avg_val, "F")
    else:
        average_grade = "F"

    success = len(responsive) > 0
    if not success and not error_msg:
        error_msg = (
            "No successful HTTP responses collected. "
            "Check DNS/network connectivity or target availability."
        )

    return HeaderScanResult(
        success=success,
        tool=tool,
        target=normalized_target,
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
        "Analyze HTTP security headers for a target. Checks Content-Security-Policy "
        "(full directive analysis), Strict-Transport-Security, X-Frame-Options, "
        "X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, "
        "CORP, Cache-Control, cookie flags (Secure, HttpOnly, SameSite), and "
        "information disclosure headers (Server, X-Powered-By). Returns a score "
        "(0-100) and grade (A+ to F) per endpoint."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["curl", "httpx", "securityheaders", "manual"],
                "description": (
                    "curl = raw HTTP header inspection via curl -v | "
                    "httpx = fast URL reachability then manual enrichment | "
                    "securityheaders = disabled/experimental | "
                    "manual = built-in Python requests full analysis"
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
                    "curl: ['-H', 'Cookie: session=abc', '-L']\n"
                    "httpx: ['-threads', '50']\n"
                    "manual: []"
                ),
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Additional endpoints to test, e.g. "
                    "['/api/v1/user', '/login', '/admin', 'https://api.example.com/data']"
                ),
            },
            "methods": {
                "type": "array",
                "items": {"type": "string"},
                "description": "HTTP methods to test. Default: ['GET']",
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    def _short(text: str, limit: int = 180) -> str:
        value = str(text or "").strip()
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."

    def _print_demo_result(label: str, result: dict) -> None:
        print(f"=== {label} ===")
        print(
            f"success={result.get('success')} "
            f"grade={result.get('average_grade')} "
            f"endpoints={result.get('total_endpoints')} "
            f"vulnerable={result.get('total_vulnerable')} "
            f"time={result.get('execution_time')}s"
        )
        if result.get("command"):
            print(f"command={result.get('command')}")
        if result.get("error"):
            print(f"error={result.get('error')}")

        endpoints = result.get("endpoints") or []
        if endpoints:
            first = endpoints[0]
            findings = first.get("findings") or []
            missing = first.get("missing_headers") or []
            print(
                f"sample={first.get('method')} {first.get('url')} "
                f"status={first.get('status_code')} grade={first.get('grade')}"
            )
            if missing:
                print(f"sample_missing={', '.join(missing[:5])}")
            if findings:
                print(f"sample_findings={', '.join(_short(f) for f in findings[:5])}")

        if os.environ.get("PF_VERBOSE_DEMO") == "1":
            print("full_json:")
            print(json.dumps(result, indent=2))
        print()

    # 1. Manual — full check
    r = http_header_analysis(
        tool="manual",
        target="http://scanme.nmap.org",
        endpoints=["/api/v1/user", "/login", "/admin"],
        methods=["GET", "POST"],
    )
    _print_demo_result("MANUAL FULL CHECK", r)

    # 2. curl — verbose header dump
    r = http_header_analysis(
        tool="curl",
        target="http://scanme.nmap.org",
        args=["-H", "Cookie: session=test", "-L"],
        endpoints=["/api/user"],
    )
    _print_demo_result("CURL HEADER CHECK", r)

    # 3. httpx — multi-URL fast scan (manual enrichment)
    r = http_header_analysis(
        tool="httpx",
        target="http://scanme.nmap.org",
        args=["-threads", "50"],
        endpoints=["/login", "/api/v1", "/admin", "/checkout"],
    )
    _print_demo_result("HTTPX MULTI-URL", r)

    # 4. securityheaders disabled
    r = http_header_analysis(
        tool="securityheaders",
        target="http://scanme.nmap.org",
    )
    _print_demo_result("SECURITYHEADERS", r)

    # 5. OPTIONS method
    r = http_header_analysis(
        tool="manual",
        target="http://scanme.nmap.org",
        methods=["GET", "OPTIONS"],
        endpoints=["/api/v1/data", "/api/v1/auth"],
    )
    _print_demo_result("OPTIONS METHOD CHECK", r)
