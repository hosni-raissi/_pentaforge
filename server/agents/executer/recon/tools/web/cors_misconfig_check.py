#/+
import subprocess
import json
import re
import time
import threading
import os
import tempfile
from urllib.parse import urlparse
from typing import Optional
import requests
import concurrent.futures
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """Thread-safe limiter for noisy active checks"""

    def __init__(self, calls_per_second: float = 2.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call = time.time()


CORS_RATE_LIMITER = RateLimiter(calls_per_second=2.0)


# ══════════════════════════════════════════════════════════════
# 2. HELPERS
# ══════════════════════════════════════════════════════════════

def _extract_host(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


def _normalize_target_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def _is_blocked_host(host: str) -> bool:
    blocked = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
    return host in blocked


def _get_bare(url: str) -> str:
    parsed = urlparse(_normalize_target_url(url))
    return parsed.hostname or url


def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Single canonical subprocess executor"""
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


def check_tool_installed(tool: str) -> tuple[bool, str]:
    if tool == "corscanner":
        # common possibilities
        import shutil
        if shutil.which("corscanner"):
            return True, ""
        if shutil.which("CORScanner"):
            return True, ""
        if shutil.which("python3"):
            # we still may run python -m CORScanner, but warn if module path likely absent
            return True, ""
        return False, "CORScanner not installed. Install the tool or use 'manual' mode."
    if tool == "curl":
        import shutil
        if shutil.which("curl"):
            return True, ""
        return False, "curl not installed"
    if tool == "manual":
        return True, ""
    return False, f"Unsupported tool: {tool}"


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CORSCheckRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = Field(default_factory=list)
    origins: list[str] = Field(default_factory=list)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"corscanner", "curl", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        host = _extract_host(v)
        if not host:
            raise ValueError(f"Invalid target: {v}")
        if _is_blocked_host(host):
            raise ValueError(f"Target '{v}' is blocked")

        normalized = _normalize_target_url(v)
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"Invalid target scheme: {v}")

        return v

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

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, v):
        cleaned = []
        for ep in v:
            ep = ep.strip()
            if ep:
                cleaned.append(ep)
        return cleaned

    @field_validator("origins")
    @classmethod
    def validate_origins(cls, v):
        cleaned = []
        for origin in v:
            origin = origin.strip()
            if origin:
                cleaned.append(origin)
        return cleaned


class CORSTestResult(BaseModel):
    origin_sent: str
    acao_header: Optional[str] = None
    acac_header: Optional[str] = None
    acam_header: Optional[str] = None
    acah_header: Optional[str] = None
    acae_header: Optional[str] = None
    acma_header: Optional[str] = None
    http_status: Optional[int] = None
    varies_origin: bool = False
    vulnerable: bool = False
    finding: str = "none"
    evidence: list[str] = Field(default_factory=list)


class EndpointResult(BaseModel):
    url: str
    method: str = "GET"
    tests: list[CORSTestResult] = Field(default_factory=list)
    vulnerable: bool = False
    severity: str = "info"
    findings: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class CORSScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_endpoints: int = 0
    total_vulnerable: int = 0
    endpoints: list[EndpointResult] = Field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 4. FINDINGS
# ══════════════════════════════════════════════════════════════

FINDINGS: dict[str, dict] = {
    "wildcard_with_credentials": {
        "severity": "critical",
        "title": "Wildcard Origin with Credentials Allowed",
        "description": "ACAO: * combined with ACAC: true.",
        "remediation": [
            "Never combine ACAO: * with ACAC: true",
            "Use an explicit allowlist of trusted origins",
        ],
    },
    "origin_reflected_with_credentials": {
        "severity": "critical",
        "title": "Arbitrary Origin Reflected + Credentials",
        "description": "Server echoes back any Origin and sets ACAC: true.",
        "remediation": [
            "Validate Origin against a strict allowlist",
            "Never reflect arbitrary origins with credentials enabled",
        ],
    },
    "null_origin_with_credentials": {
        "severity": "critical",
        "title": "Null Origin Accepted with Credentials",
        "description": "Server accepts Origin: null with credentials.",
        "remediation": [
            "Never whitelist the null origin in production",
            "Reject requests with Origin: null",
        ],
    },
    "origin_reflected_no_credentials": {
        "severity": "high",
        "title": "Arbitrary Origin Reflected (No Credentials)",
        "description": "Server reflects arbitrary Origin without credentials.",
        "remediation": [
            "Validate Origin against a strict allowlist",
            "Return ACAO only for explicitly trusted origins",
        ],
    },
    "pre_domain_bypass": {
        "severity": "high",
        "title": "Pre-Domain Bypass",
        "description": "Origin validation likely uses suffix matching.",
        "remediation": [
            "Use exact-match or anchored regex origin validation",
        ],
    },
    "post_domain_bypass": {
        "severity": "high",
        "title": "Post-Domain Bypass",
        "description": "Origin validation likely uses prefix matching.",
        "remediation": [
            "Anchor regex to the end of string",
        ],
    },
    "subdomain_bypass": {
        "severity": "high",
        "title": "Wildcard Subdomain Accepted",
        "description": "Server accepts arbitrary subdomains.",
        "remediation": [
            "Allowlist only required subdomains",
        ],
    },
    "http_origin_trusted_on_https": {
        "severity": "high",
        "title": "HTTP Origin Trusted on HTTPS Endpoint",
        "description": "HTTPS endpoint accepts insecure HTTP origin.",
        "remediation": [
            "Only trust HTTPS origins for HTTPS endpoints",
        ],
    },
    "wildcard_origin_no_credentials": {
        "severity": "medium",
        "title": "Wildcard Origin (No Credentials)",
        "description": "ACAO: * without credentials.",
        "remediation": [
            "Restrict to specific allowed origins unless truly public",
        ],
    },
    "null_origin_no_credentials": {
        "severity": "medium",
        "title": "Null Origin Accepted",
        "description": "Server accepts Origin: null without credentials.",
        "remediation": [
            "Remove null from origin allowlist",
        ],
    },
    "vary_origin_missing": {
        "severity": "medium",
        "title": "Vary: Origin Missing",
        "description": "Dynamic ACAO returned without Vary: Origin.",
        "remediation": [
            "Include Vary: Origin when ACAO changes per request",
        ],
    },
    "exposed_sensitive_headers": {
        "severity": "low",
        "title": "Sensitive Headers Exposed",
        "description": "Sensitive headers exposed through ACAE.",
        "remediation": [
            "Expose only headers strictly required by clients",
        ],
    },
    "overly_permissive_methods": {
        "severity": "low",
        "title": "Overly Permissive Methods",
        "description": "Unsafe methods allowed cross-origin.",
        "remediation": [
            "Restrict ACAM to the minimum required methods",
        ],
    },
    "preflight_wildcard_headers": {
        "severity": "low",
        "title": "Wildcard ACAH",
        "description": "ACAH: * allows any custom header cross-origin.",
        "remediation": [
            "Enumerate only required request headers",
        ],
    },
}


# ══════════════════════════════════════════════════════════════
# 5. TEST ORIGIN PAYLOADS
# ══════════════════════════════════════════════════════════════

def build_test_origins(target_url: str) -> list[dict[str, str]]:
    m = re.search(r"https?://([^/:]+)", _normalize_target_url(target_url))
    base_domain = m.group(1) if m else target_url
    bare_domain = re.sub(r":\d+$", "", base_domain)

    parts = bare_domain.split(".")
    tld = ".".join(parts[-2:]) if len(parts) >= 2 else bare_domain

    origins = [
        {
            "origin": "null",
            "label": "Null origin",
            "test_type": "null_origin",
        },
        {
            "origin": "https://evil.com",
            "label": "Arbitrary external origin",
            "test_type": "arbitrary_origin",
        },
        {
            "origin": "https://attacker.io",
            "label": "Attacker domain",
            "test_type": "arbitrary_origin",
        },
        {
            "origin": f"https://evil-{tld}",
            "label": "Pre-domain bypass",
            "test_type": "pre_domain_bypass",
        },
        {
            "origin": f"https://evil.{tld}.attacker.com",
            "label": "Suffix confusion",
            "test_type": "pre_domain_bypass",
        },
        {
            "origin": f"https://{bare_domain}.evil.com",
            "label": "Post-domain bypass",
            "test_type": "post_domain_bypass",
        },
        {
            "origin": f"https://{bare_domain}.attacker.io",
            "label": "Post-domain variation",
            "test_type": "post_domain_bypass",
        },
        {
            "origin": f"https://evil.{bare_domain}",
            "label": "Arbitrary subdomain",
            "test_type": "subdomain_bypass",
        },
        {
            "origin": f"https://xss.{bare_domain}",
            "label": "XSS subdomain simulation",
            "test_type": "subdomain_bypass",
        },
        {
            "origin": f"https://pwned.{bare_domain}",
            "label": "Attacker subdomain",
            "test_type": "subdomain_bypass",
        },
        {
            "origin": f"http://{bare_domain}",
            "label": "HTTP origin on HTTPS endpoint",
            "test_type": "http_origin",
        },
        {
            "origin": f"http://evil.{bare_domain}",
            "label": "HTTP subdomain origin",
            "test_type": "http_origin",
        },
        {
            "origin": f"https://{bare_domain}%60.evil.com",
            "label": "Backtick injection",
            "test_type": "special_char",
        },
        {
            "origin": f"https://{bare_domain}_.evil.com",
            "label": "Underscore bypass",
            "test_type": "special_char",
        },
        {
            "origin": f"https://{bare_domain}!.evil.com",
            "label": "Exclamation bypass",
            "test_type": "special_char",
        },
        {
            "origin": f"https://{bare_domain}#.evil.com",
            "label": "Fragment bypass",
            "test_type": "special_char",
        },
        {
            "origin": f"https://{bare_domain}%00.evil.com",
            "label": "Null byte bypass",
            "test_type": "special_char",
        },
        {
            "origin": f"https://{bare_domain}",
            "label": "Same-origin baseline",
            "test_type": "same_origin_baseline",
        },
        {
            "origin": f"http://{bare_domain}",
            "label": "Same domain HTTP baseline",
            "test_type": "same_origin_baseline",
        },
    ]

    return origins


# ══════════════════════════════════════════════════════════════
# 6. HTTP PROBES
# ══════════════════════════════════════════════════════════════

SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie",
    "x-auth-token", "x-api-key", "x-csrf-token",
    "x-secret", "x-access-token",
}

UNSAFE_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}


def probe_cors(
    url: str,
    origin: str,
    method: str = "GET",
    with_credentials: bool = True,
    http_timeout: int = 10,
) -> CORSTestResult:
    CORS_RATE_LIMITER.acquire()

    result = CORSTestResult(origin_sent=origin)
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (CORS-Scanner)",
    }
    if with_credentials:
        headers["Cookie"] = "session=test_cors_probe"

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            timeout=http_timeout,
            allow_redirects=True,
            verify=False,
        )
        result.http_status = resp.status_code
        h = {k.lower(): v for k, v in resp.headers.items()}

        result.acao_header = h.get("access-control-allow-origin")
        result.acac_header = h.get("access-control-allow-credentials")
        result.acam_header = h.get("access-control-allow-methods")
        result.acah_header = h.get("access-control-allow-headers")
        result.acae_header = h.get("access-control-expose-headers")
        result.acma_header = h.get("access-control-max-age")
        result.varies_origin = "origin" in h.get("vary", "").lower()

    except requests.exceptions.RequestException as e:
        result.evidence.append(f"Request failed: {e}")
        return result

    if not result.acao_header:
        return result

    acao = result.acao_header.strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    if acao == "*" and creds:
        result.vulnerable = True
        result.finding = "wildcard_with_credentials"
        result.evidence.append("ACAO: * + ACAC: true")

    elif acao == origin and creds and origin not in ("null", "*"):
        if origin not in (f"https://{_get_bare(url)}", f"http://{_get_bare(url)}"):
            result.vulnerable = True
            result.finding = "origin_reflected_with_credentials"
            result.evidence.append("ACAO echoes attacker origin + ACAC: true")

    elif origin == "null" and acao == "null" and creds:
        result.vulnerable = True
        result.finding = "null_origin_with_credentials"
        result.evidence.append("Server reflects null origin with credentials")

    elif acao == origin and origin not in ("null", "*"):
        if origin not in (f"https://{_get_bare(url)}", f"http://{_get_bare(url)}"):
            result.vulnerable = True
            result.finding = "origin_reflected_no_credentials"
            result.evidence.append("ACAO echoes attacker origin (no credentials)")

    elif acao == "*" and not creds:
        result.vulnerable = True
        result.finding = "wildcard_origin_no_credentials"
        result.evidence.append("ACAO: * (public data exposed)")

    elif origin == "null" and acao == "null" and not creds:
        result.vulnerable = True
        result.finding = "null_origin_no_credentials"
        result.evidence.append("Server reflects null origin")

    if acao and acao != "*" and not result.varies_origin:
        if not result.finding or result.finding == "none":
            result.finding = "vary_origin_missing"
        result.evidence.append("Vary: Origin header is missing")

    if result.acae_header:
        exposed = [
            h.strip() for h in result.acae_header.lower().split(",")
            if h.strip() in SENSITIVE_HEADERS
        ]
        if exposed:
            result.vulnerable = True
            if not result.finding or result.finding == "none":
                result.finding = "exposed_sensitive_headers"
            result.evidence.append(f"Sensitive headers exposed: {', '.join(exposed)}")

    if result.acam_header:
        methods_allowed = {m.strip().upper() for m in result.acam_header.split(",")}
        unsafe = methods_allowed & UNSAFE_METHODS
        if unsafe:
            if not result.finding or result.finding == "none":
                result.finding = "overly_permissive_methods"
            result.evidence.append(f"Unsafe methods allowed cross-origin: {', '.join(sorted(unsafe))}")

    if result.acah_header and result.acah_header.strip() == "*":
        if not result.finding or result.finding == "none":
            result.finding = "preflight_wildcard_headers"
        result.evidence.append("ACAH: * allows any header cross-origin")

    return result


def probe_preflight(url: str, origin: str, http_timeout: int = 10) -> CORSTestResult:
    CORS_RATE_LIMITER.acquire()

    result = CORSTestResult(origin_sent=f"[PREFLIGHT] {origin}")
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization, X-Custom-Header",
        "User-Agent": "Mozilla/5.0 (CORS-Scanner)",
    }

    try:
        resp = requests.options(
            url,
            headers=headers,
            timeout=http_timeout,
            allow_redirects=False,
            verify=False,
        )
        result.http_status = resp.status_code
        h = {k.lower(): v for k, v in resp.headers.items()}

        result.acao_header = h.get("access-control-allow-origin")
        result.acac_header = h.get("access-control-allow-credentials")
        result.acam_header = h.get("access-control-allow-methods")
        result.acah_header = h.get("access-control-allow-headers")
        result.acma_header = h.get("access-control-max-age")
        result.varies_origin = "origin" in h.get("vary", "").lower()

    except requests.exceptions.RequestException as e:
        result.evidence.append(f"Preflight request failed: {e}")
        return result

    acao = (result.acao_header or "").strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    if acao == origin and creds:
        result.vulnerable = True
        result.finding = "origin_reflected_with_credentials"
        result.evidence.append("Preflight reflects origin + credentials")
    elif acao == origin:
        result.vulnerable = True
        result.finding = "origin_reflected_no_credentials"
        result.evidence.append("Preflight reflects arbitrary origin")
    elif acao == "*":
        result.finding = "wildcard_origin_no_credentials"
        result.evidence.append("Preflight ACAO: *")

    return result


# ══════════════════════════════════════════════════════════════
# 7. ENDPOINT CHECKER
# ══════════════════════════════════════════════════════════════

def check_endpoint(
    url: str,
    custom_origins: Optional[list[str]] = None,
    http_timeout: int = 10,
) -> EndpointResult:
    ep = EndpointResult(url=url)
    custom_origins = custom_origins or []

    test_origins = build_test_origins(url)

    for co in custom_origins:
        test_origins.insert(0, {
            "origin": co,
            "label": f"Custom agent origin: {co}",
            "test_type": "custom",
        })

    for o in test_origins:
        origin = o["origin"]

        t = probe_cors(
            url,
            origin,
            method="GET",
            with_credentials=True,
            http_timeout=http_timeout,
        )
        ep.tests.append(t)

        if o["test_type"] in (
            "null_origin", "arbitrary_origin",
            "pre_domain_bypass", "post_domain_bypass", "subdomain_bypass",
            "http_origin", "custom",
        ):
            pf = probe_preflight(url, origin, http_timeout=http_timeout)
            ep.tests.append(pf)

    for o in test_origins:
        if o["test_type"] in ("null_origin", "arbitrary_origin", "custom"):
            t = probe_cors(
                url,
                o["origin"],
                method="POST",
                with_credentials=True,
                http_timeout=http_timeout,
            )
            ep.tests.append(t)

    seen_findings = set()
    for t in ep.tests:
        if t.vulnerable or t.finding not in ("none", ""):
            if t.finding and t.finding != "none":
                seen_findings.add(t.finding)

    ep.findings = list(seen_findings)
    ep.vulnerable = any(t.vulnerable for t in ep.tests)

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = "info"
    for f in ep.findings:
        if f in FINDINGS:
            sev = FINDINGS[f]["severity"]
            if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                worst = sev
    ep.severity = worst

    rems = []
    for f in ep.findings:
        if f in FINDINGS:
            for r in FINDINGS[f]["remediation"]:
                if r not in rems:
                    rems.append(r)
    ep.remediation = rems

    return ep


def bulk_check(
    urls: list[str],
    custom_origins: Optional[list[str]] = None,
    threads: int = 10,
    http_timeout: int = 10,
) -> list[EndpointResult]:
    results = []
    custom_origins = custom_origins or []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(check_endpoint, url, custom_origins, http_timeout): url
            for url in urls
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                url = futures[future]
                results.append(EndpointResult(
                    url=url,
                    findings=[f"Check failed: {e}"],
                ))
    return results


# ══════════════════════════════════════════════════════════════
# 8. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_corscanner(stdout: str, stderr: str) -> list[EndpointResult]:
    results = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            url = data.get("url", "unknown")
            ep = EndpointResult(url=url)

            vuln_types = data.get("type", [])
            if isinstance(vuln_types, str):
                vuln_types = [vuln_types]

            for vt in vuln_types:
                vt_lower = vt.lower().replace(" ", "_").replace("-", "_")
                mapped = _map_corscanner_type(vt_lower)
                if mapped and mapped not in ep.findings:
                    ep.findings.append(mapped)

            ep.vulnerable = bool(ep.findings)

            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            worst = "info"
            for f in ep.findings:
                if f in FINDINGS:
                    sev = FINDINGS[f]["severity"]
                    if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                        worst = sev
            ep.severity = worst

            ep.tests.append(CORSTestResult(
                origin_sent=data.get("origin", "unknown"),
                acao_header=data.get("acao"),
                acac_header=data.get("acac"),
                vulnerable=ep.vulnerable,
                finding=ep.findings[0] if ep.findings else "none",
                evidence=[json.dumps(data)],
            ))

            results.append(ep)
        except json.JSONDecodeError:
            continue

    if not results:
        current_ep = None
        for line in stdout.splitlines():
            url_m = re.search(r"https?://\S+", line)
            if url_m and ("cors" in line.lower() or "vuln" in line.lower() or "reflect" in line.lower() or "origin" in line.lower()):
                if current_ep and current_ep.url:
                    results.append(current_ep)
                current_ep = EndpointResult(url=url_m.group(0), vulnerable=True)
                finding = _classify_plain_line(line)
                if finding:
                    current_ep.findings.append(finding)
                    current_ep.severity = FINDINGS.get(finding, {}).get("severity", "medium")
                current_ep.tests.append(CORSTestResult(
                    origin_sent="parsed",
                    vulnerable=True,
                    finding=finding or "none",
                    evidence=[line],
                ))
        if current_ep and current_ep.url:
            results.append(current_ep)

    return results


def parse_curl_cors(stdout: str, stderr: str, url: str, origin: str) -> CORSTestResult:
    raw = stdout + "\n" + stderr
    result = CORSTestResult(origin_sent=origin)

    header_map = {
        "access-control-allow-origin": "acao_header",
        "access-control-allow-credentials": "acac_header",
        "access-control-allow-methods": "acam_header",
        "access-control-allow-headers": "acah_header",
        "access-control-expose-headers": "acae_header",
        "access-control-max-age": "acma_header",
    }

    for line in raw.splitlines():
        status_m = re.match(r"(?:HTTP/[\d.]+|<)\s+(\d{3})", line)
        if status_m:
            result.http_status = int(status_m.group(1))

        line_clean = re.sub(r"^[<>*]\s*", "", line).strip()
        colon_idx = line_clean.find(":")
        if colon_idx > 0:
            hdr_name = line_clean[:colon_idx].strip().lower()
            hdr_value = line_clean[colon_idx + 1:].strip()
            if hdr_name in header_map:
                setattr(result, header_map[hdr_name], hdr_value)
            if hdr_name == "vary" and "origin" in hdr_value.lower():
                result.varies_origin = True

    acao = (result.acao_header or "").strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    if acao == origin and creds:
        result.vulnerable = True
        result.finding = "origin_reflected_with_credentials"
        result.evidence.append("curl: origin reflected + credentials")
    elif acao == origin:
        result.vulnerable = True
        result.finding = "origin_reflected_no_credentials"
        result.evidence.append("curl: origin reflected")
    elif acao == "*" and creds:
        result.vulnerable = True
        result.finding = "wildcard_with_credentials"
        result.evidence.append("curl: wildcard + credentials")
    elif acao == "*":
        result.finding = "wildcard_origin_no_credentials"
        result.evidence.append("curl: ACAO: *")
    elif acao == "null" and origin == "null":
        result.vulnerable = True
        result.finding = "null_origin_with_credentials" if creds else "null_origin_no_credentials"
        result.evidence.append("curl: null origin accepted")

    return result


def _map_corscanner_type(vt: str) -> Optional[str]:
    mapping = {
        "origin_reflected": "origin_reflected_with_credentials",
        "third_party_allowed": "origin_reflected_no_credentials",
        "wildcard_value": "wildcard_origin_no_credentials",
        "wildcard_with_credentials": "wildcard_with_credentials",
        "null_origin": "null_origin_with_credentials",
        "pre_domain_bypass": "pre_domain_bypass",
        "post_domain_bypass": "post_domain_bypass",
        "subdomain_allowed": "subdomain_bypass",
        "http_trust": "http_origin_trusted_on_https",
        "vary_missing": "vary_origin_missing",
    }
    for key, val in mapping.items():
        if key in vt:
            return val
    return None


def _classify_plain_line(line: str) -> Optional[str]:
    line_l = line.lower()
    if "wildcard" in line_l and "credential" in line_l:
        return "wildcard_with_credentials"
    if "null" in line_l and "credential" in line_l:
        return "null_origin_with_credentials"
    if "reflect" in line_l and "credential" in line_l:
        return "origin_reflected_with_credentials"
    if "reflect" in line_l:
        return "origin_reflected_no_credentials"
    if "wildcard" in line_l:
        return "wildcard_origin_no_credentials"
    if "null" in line_l:
        return "null_origin_no_credentials"
    return None


# ══════════════════════════════════════════════════════════════
# 9. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _cors_misconfig_check_impl(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    endpoints: Optional[list[str]] = None,
    origins: Optional[list[str]] = None,
    timeout: int = 600,
) -> dict:
    start = time.time()
    args = args or []
    endpoints = endpoints or []
    origins = origins or []
    warnings: list[str] = []

    try:
        req = CORSCheckRequest(
            tool=tool,
            target=target,
            args=args,
            endpoints=endpoints,
            origins=origins,
            timeout=timeout,
        )
    except Exception as e:
        return CORSScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    normalized_target = _normalize_target_url(req.target)

    installed, install_msg = check_tool_installed(req.tool)
    if not installed:
        return CORSScanResult(
            success=False,
            tool=req.tool,
            target=normalized_target,
            command="",
            error=install_msg,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    results: list[EndpointResult] = []
    command_str = ""
    raw_output = ""
    error_msg: Optional[str] = None

    all_urls = [normalized_target] + [
        u if u.startswith("http") else f"{normalized_target.rstrip('/')}/{u.lstrip('/')}"
        for u in req.endpoints
    ]
    all_urls = list(dict.fromkeys(all_urls))

    if req.tool == "manual":
        command_str = f"manual_cors_check({normalized_target}, {len(all_urls)} endpoints)"
        results = bulk_check(
            urls=all_urls,
            custom_origins=req.origins,
            threads=10,
            http_timeout=10,
        )

    elif req.tool == "corscanner":
        tmp_file = None

        # Try common invocation styles
        if len(all_urls) > 1:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                delete=False,
                prefix="cors_urls_"
            )
            tmp_file.write("\n".join(all_urls))
            tmp_file.close()

            # more realistic default than python -m CORScanner only
            cmd = ["python3", "-m", "CORScanner", "-i", tmp_file.name]
        else:
            cmd = ["python3", "-m", "CORScanner", "-u", normalized_target]

        if "-o" not in req.args:
            cmd.extend(["-o", "json"])

        cmd += list(req.args)
        command_str = " ".join(cmd)

        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        results = parse_corscanner(stdout, stderr)

        checked_urls = {r.url for r in results}
        missed = [u for u in all_urls if u not in checked_urls]
        if missed:
            warnings.append(f"{len(missed)} endpoint(s) were not covered by CORScanner output and were enriched with manual checks")
            extra = bulk_check(missed, custom_origins=req.origins, threads=10)
            results.extend(extra)

        if tmp_file:
            try:
                os.unlink(tmp_file.name)
            except OSError:
                pass

        if rc != 0 and not results:
            error_msg = stderr[:500] if stderr else "CORScanner execution failed"

    elif req.tool == "curl":
        test_origins_for_curl = [
            "null",
            "https://evil.com",
            f"https://evil-{_get_bare(normalized_target)}",
            f"https://{_get_bare(normalized_target)}.evil.com",
            f"https://evil.{_get_bare(normalized_target)}",
            f"http://{_get_bare(normalized_target)}",
        ] + req.origins

        for url in all_urls:
            ep = EndpointResult(url=url)

            for origin in test_origins_for_curl:
                cmd = [
                    "curl", "-v", "-s", "--max-time", "10",
                    "-H", f"Origin: {origin}",
                    "-H", "Cookie: session=cors_test",
                    "-X", "GET",
                ]
                cmd += list(req.args)
                cmd.append(url)

                command_str = " ".join(cmd)
                stdout, stderr, rc = safe_execute(cmd, req.timeout)
                raw_output += (stderr or stdout)[:1000]

                t = parse_curl_cors(stdout, stderr, url, origin)
                ep.tests.append(t)

                pf_cmd = [
                    "curl", "-v", "-s", "--max-time", "10",
                    "-X", "OPTIONS",
                    "-H", f"Origin: {origin}",
                    "-H", "Access-Control-Request-Method: POST",
                    "-H", "Access-Control-Request-Headers: Content-Type, Authorization",
                ]
                pf_cmd += list(req.args)
                pf_cmd.append(url)

                pf_stdout, pf_stderr, _ = safe_execute(pf_cmd, req.timeout)
                pf_t = parse_curl_cors(pf_stdout, pf_stderr, url, f"[PREFLIGHT] {origin}")
                ep.tests.append(pf_t)

            seen = set()
            for t in ep.tests:
                if t.finding and t.finding != "none":
                    seen.add(t.finding)
            ep.findings = list(seen)
            ep.vulnerable = any(t.vulnerable for t in ep.tests)

            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            worst = "info"
            for f in ep.findings:
                if f in FINDINGS:
                    sev = FINDINGS[f]["severity"]
                    if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                        worst = sev
            ep.severity = worst

            rems = []
            for f in ep.findings:
                if f in FINDINGS:
                    for r in FINDINGS[f]["remediation"]:
                        if r not in rems:
                            rems.append(r)
            ep.remediation = rems
            results.append(ep)

    vulnerable = [r for r in results if r.vulnerable]

    return CORSScanResult(
        success=len(results) > 0,
        tool=req.tool,
        target=normalized_target,
        command=command_str,
        total_endpoints=len(results),
        total_vulnerable=len(vulnerable),
        endpoints=[r.model_dump() for r in results],
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        warnings=warnings,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_cors_misconfig_check(
    tool: str,
    target: str,
    args_tuple: tuple[str, ...],
    endpoints_tuple: tuple[str, ...],
    origins_tuple: tuple[str, ...],
    timeout: int,
) -> str:
    result = _cors_misconfig_check_impl(
        tool=tool,
        target=target,
        args=list(args_tuple),
        endpoints=list(endpoints_tuple),
        origins=list(origins_tuple),
        timeout=timeout,
    )
    return json.dumps(result)


def clear_cache():
    _cached_cors_misconfig_check.cache_clear()


def get_cache_info():
    return _cached_cors_misconfig_check.cache_info()


# ══════════════════════════════════════════════════════════════
# 11. PUBLIC API
# ══════════════════════════════════════════════════════════════

def cors_misconfig_check(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    endpoints: Optional[list[str]] = None,
    origins: Optional[list[str]] = None,
    timeout: int = 600,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: CORS Misconfiguration Checker

    Tests:
    - wildcard origin
    - arbitrary origin reflection
    - null origin acceptance
    - credential leakage
    - suffix/prefix/subdomain bypasses
    - preflight behavior
    - exposed headers
    - unsafe methods
    - missing Vary: Origin

    Tools:
    - manual
    - curl
    - corscanner
    """
    args = args or []
    endpoints = endpoints or []
    origins = origins or []

    if use_cache:
        cached = _cached_cors_misconfig_check(
            tool,
            target,
            tuple(args),
            tuple(endpoints),
            tuple(origins),
            timeout,
        )
        return json.loads(cached)

    return _cors_misconfig_check_impl(
        tool=tool,
        target=target,
        args=args,
        endpoints=endpoints,
        origins=origins,
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════
# 12. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

CORS_MISCONFIG_TOOL_DEFINITION = {
    "name": "cors_misconfig_check",
    "description": (
        "Test a target for CORS misconfigurations including wildcard origin, arbitrary origin reflection, "
        "null origin acceptance, credential leakage (ACAC: true), pre/post-domain bypass, subdomain bypass, "
        "HTTP origin on HTTPS, cache poisoning (Vary: Origin missing), sensitive header exposure, and unsafe method allowance. "
        "Supports CORScanner, curl, and built-in manual Python checks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["corscanner", "curl", "manual"],
                "description": (
                    "corscanner = automated scanner | "
                    "curl = raw HTTP header inspection | "
                    "manual = built-in Python checker"
                ),
            },
            "target": {
                "type": "string",
                "description": "Target URL or domain",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw tool arguments",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific endpoints to test in addition to root target",
            },
            "origins": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Custom origins to inject",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds",
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable result caching",
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 13. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import urllib3
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser(description="CORS misconfiguration checker demo runner")
    parser.add_argument("--full-json", action="store_true", help="Print full JSON results")
    parser.add_argument("--quick", action="store_true", help="Run only the first manual scenario")
    args = parser.parse_args()

    def _print_summary(label: str, result: dict, full_json: bool = False) -> None:
        print(f"=== {label} ===")
        print(
            f"success={result.get('success')} tool={result.get('tool')} "
            f"endpoints={result.get('total_endpoints', 0)} "
            f"vulnerable={result.get('total_vulnerable', 0)} "
            f"time={result.get('execution_time', 0)}s"
        )
        print(f"command={result.get('command')}")
        if result.get("warnings"):
            print("warnings=" + " | ".join(result["warnings"][:3]))
        if result.get("error"):
            print("error=" + str(result["error"]))

        endpoints = result.get("endpoints") or []
        if endpoints:
            sample = endpoints[0]
            tests = sample.get("tests") or []
            print(
                f"sample={sample.get('method', 'GET')} {sample.get('url')} "
                f"tests={len(tests)} findings={len(sample.get('findings') or [])}"
            )

        if full_json:
            print(json.dumps(result, indent=2))
        print()

    scenarios: list[tuple[str, dict]] = []
    scenarios.append((
        "MANUAL FULL CHECK",
        cors_misconfig_check(
            tool="manual",
            target="http://scanme.nmap.org",
            endpoints=["/api/v1/user", "/api/v1/admin", "/api/v1/data"],
            use_cache=False,
        ),
    ))

    if not args.quick:
        scenarios.append((
            "MANUAL CUSTOM ORIGINS",
            cors_misconfig_check(
                tool="manual",
                target="http://scanme.nmap.org",
                origins=["http://scanme.nmap.org", "null", "http://scanme.nmap.org"],
                use_cache=False,
            ),
        ))
        scenarios.append((
            "CORSCANNER",
            cors_misconfig_check(
                tool="corscanner",
                target="http://scanme.nmap.org",
                args=["-t", "50", "-v"],
                endpoints=["/api/user", "/api/admin"],
                use_cache=False,
            ),
        ))
        scenarios.append((
            "CURL WITH AUTH",
            cors_misconfig_check(
                tool="curl",
                target="http://scanme.nmap.org",
                args=["-H", "Authorization: Bearer test_token", "-L"],
                endpoints=["/api/v1/profile", "/api/v1/payments"],
                use_cache=False,
            ),
        ))

    for label, result in scenarios:
        _print_summary(label, result, full_json=args.full_json)

    print("=== CACHE TEST ===")
    start = time.time()
    _ = cors_misconfig_check(
        tool="manual",
        target="http://scanme.nmap.org",
        use_cache=True,
    )
    first = time.time() - start

    start = time.time()
    _ = cors_misconfig_check(
        tool="manual",
        target="http://scanme.nmap.org",
        use_cache=True,
    )
    second = time.time() - start

    print(f"First run:  {first:.2f}s")
    print(f"Cached run: {second:.4f}s")
    print(f"Cache info: {get_cache_info()}")
