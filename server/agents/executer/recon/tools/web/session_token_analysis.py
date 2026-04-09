#/+
import json
import math
import re
import time
import requests
import statistics
from typing import Optional
from collections import Counter
from pydantic import BaseModel, Field, field_validator
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLOCKED_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
    "169.254.169.254", "metadata.google.internal",
]

COMMON_COOKIE_NAMES = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session",
    "sessionid", "sid", "connect.sid", "token", "auth_token",
]

class SessionAnalysisRequest(BaseModel):
    target: str
    cookie_name: Optional[str] = None
    sample_count: int = Field(default=20, ge=5, le=100)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=15, ge=5, le=60)
    verify_tls: bool = True

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

class TokenCharacteristics(BaseModel):
    name: str
    avg_length: float = 0.0
    min_length: int = 0
    max_length: int = 0
    charset: str = ""
    hex_only: bool = False
    base64_likely: bool = False
    jwt_format: bool = False

class EntropyAnalysis(BaseModel):
    shannon_entropy: float = 0.0
    max_possible_entropy: float = 0.0
    entropy_ratio: float = 0.0
    entropy_grade: str = "unknown"
    chi_squared: Optional[float] = None
    serial_correlation: Optional[float] = None

class PredictabilityAnalysis(BaseModel):
    identical_tokens_detected: bool = False
    sequential_detected: bool = False
    timestamp_based: bool = False
    counter_based: bool = False
    common_prefix_length: int = 0
    hamming_distance_avg: Optional[float] = None
    predictability_score: float = 0.0
    predictability_grade: str = "unknown"

class CookieSecurityFlags(BaseModel):
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    issues: list[str] = Field(default_factory=list)

class SessionTokenResult(BaseModel):
    success: bool
    target: str
    tokens_collected: int = 0
    token_characteristics: Optional[TokenCharacteristics] = None
    entropy_analysis: Optional[EntropyAnalysis] = None
    predictability_analysis: Optional[PredictabilityAnalysis] = None
    cookie_security: list[CookieSecurityFlags] = Field(default_factory=list)
    sample_tokens: list[str] = Field(default_factory=list)
    all_issues: list[str] = Field(default_factory=list)
    severity: str = "info"
    error: Optional[str] = None
    execution_time: float = 0.0

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in freq.values()), 4)

def _chi_squared_test(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    unique = len(freq)
    expected = len(data) / unique if unique else 1
    return round(sum(((c - expected) ** 2) / expected for c in freq.values()), 4)

def _serial_correlation(values: list[int]) -> float:
    if len(values) < 3:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    num = sum((values[i] - mean) * (values[i + 1] - mean) for i in range(n - 1))
    den = sum((v - mean) ** 2 for v in values)
    return round(num / den, 4) if den else 1.0

def _analyze_entropy(tokens: list[str]) -> EntropyAnalysis:
    combined = "".join(tokens)
    unique_chars = len(set(combined))
    shannon = _shannon_entropy(combined)
    max_ent = math.log2(unique_chars) if unique_chars > 1 else 0
    ratio = shannon / max_ent if max_ent > 0 else 0
    if ratio >= 0.95: grade = "excellent"
    elif ratio >= 0.85: grade = "good"
    elif ratio >= 0.70: grade = "weak"
    else: grade = "poor"
    chi_sq = _chi_squared_test(combined)
    byte_vals = [ord(c) for c in combined[:10000]]
    sc = _serial_correlation(byte_vals)
    return EntropyAnalysis(
        shannon_entropy=shannon, max_possible_entropy=round(max_ent, 4),
        entropy_ratio=round(ratio, 4), entropy_grade=grade,
        chi_squared=chi_sq, serial_correlation=sc,
    )

def _common_prefix_length(tokens: list[str]) -> int:
    if not tokens: return 0
    prefix = tokens[0]
    for t in tokens[1:]:
        i = 0
        while i < len(prefix) and i < len(t) and prefix[i] == t[i]:
            i += 1
        prefix = prefix[:i]
    return len(prefix)

def _hamming_distance(s1: str, s2: str) -> int:
    return sum(c1 != c2 for c1, c2 in zip(s1, s2)) + abs(len(s1) - len(s2))

def _detect_sequential(tokens: list[str]) -> bool:
    if len(tokens) < 3: return False
    nums = []
    for t in tokens:
        found = re.findall(r"\d+", t)
        if found: nums.append([int(n) for n in found])
    if len(nums) < 3: return False
    max_pos = min(len(p) for p in nums)
    for pos in range(max_pos):
        vals = [p[pos] for p in nums]
        diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
        if len(set(diffs)) == 1 and diffs[0] != 0: return True
    return False

def _detect_timestamp(tokens: list[str]) -> bool:
    now = int(time.time())
    for t in tokens:
        for n in re.findall(r"\d{10,13}", t):
            v = int(n)
            if abs(v - now) < 86400 or abs(v // 1000 - now) < 86400:
                return True
    return False

def _analyze_predictability(tokens: list[str]) -> PredictabilityAnalysis:
    a = PredictabilityAnalysis()
    if len(tokens) < 3:
        return a

    min_length = min(len(t) for t in tokens)
    unique_token_count = len(set(tokens))

    a.identical_tokens_detected = unique_token_count == 1
    a.common_prefix_length = _common_prefix_length(tokens)
    a.sequential_detected = _detect_sequential(tokens)
    a.timestamp_based = _detect_timestamp(tokens)
    dists = [_hamming_distance(tokens[i], tokens[i+1]) for i in range(len(tokens)-1)]
    if dists:
        a.hamming_distance_avg = round(statistics.mean(dists), 2)
    score = 0.0
    if a.identical_tokens_detected:
        score += 0.7
    if a.sequential_detected:
        score += 0.3
    if a.timestamp_based:
        score += 0.2
    if a.counter_based:
        score += 0.3
    if min_length and a.common_prefix_length >= max(8, min_length // 2):
        score += 0.1
    if a.hamming_distance_avg is not None and a.hamming_distance_avg <= max(2, min_length * 0.1):
        score += 0.2
    a.predictability_score = round(min(score, 1.0), 2)
    if score >= 0.6: a.predictability_grade = "highly_predictable"
    elif score >= 0.3: a.predictability_grade = "partially_predictable"
    else: a.predictability_grade = "unpredictable"
    return a

def _extract_set_cookie_headers(response: requests.Response) -> list[str]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        if values:
            return values

    header_value = response.headers.get("Set-Cookie", "")
    return [header_value] if header_value else []


def _extract_cookie_pairs(set_cookie_headers: list[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for header in set_cookie_headers:
        parts = header.split(";", 1)
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def _collect_tokens(target, cookie_name, sample_count, headers, timeout, verify_tls):
    tokens, cookie_flags, target_cookie = [], [], cookie_name
    flags_captured = False
    for i in range(sample_count):
        try:
            with requests.Session() as session:
                r = session.get(
                    target,
                    headers={"User-Agent": f"Mozilla/5.0 (Audit/{i})", **headers},
                    timeout=timeout,
                    verify=verify_tls,
                    allow_redirects=True,
                )

            response_chain = [*r.history, r]
            set_cookie_headers: list[str] = []
            for response in response_chain:
                set_cookie_headers.extend(_extract_set_cookie_headers(response))

            response_cookies = requests.utils.dict_from_cookiejar(session.cookies)
            if not response_cookies:
                response_cookies = dict(r.cookies.items())
            if not response_cookies and set_cookie_headers:
                response_cookies = _extract_cookie_pairs(set_cookie_headers)
            if not response_cookies:
                continue
            if not target_cookie:
                for n in COMMON_COOKIE_NAMES:
                    if n in response_cookies:
                        target_cookie = n
                        break
                if not target_cookie:
                    target_cookie = next(iter(response_cookies))
            if target_cookie and target_cookie in response_cookies:
                tokens.append(response_cookies[target_cookie])
            if not flags_captured:
                for sc in set_cookie_headers:
                    _parse_cookie_flags(sc.strip(), cookie_flags)
                flags_captured = bool(cookie_flags)
        except Exception:
            pass
        time.sleep(0.1)
    return tokens, cookie_flags, target_cookie

def _parse_cookie_flags(header, flags_list):
    parts = header.split(";")
    if not parts or "=" not in parts[0]: return
    name = parts[0].split("=", 1)[0].strip()
    f = CookieSecurityFlags(name=name)
    for p in parts[1:]:
        p = p.strip().lower()
        if p == "secure": f.secure = True
        elif p == "httponly": f.httponly = True
        elif p.startswith("samesite="): f.samesite = p.split("=", 1)[1]
    if not f.secure: f.issues.append(f"Cookie '{name}' missing Secure flag")
    if not f.httponly: f.issues.append(f"Cookie '{name}' missing HttpOnly flag")
    if not f.samesite or f.samesite == "none":
        f.issues.append(f"Cookie '{name}' SameSite={f.samesite or 'missing'} — CSRF risk")
    flags_list.append(f)

def _analyze_characteristics(tokens, cookie_name):
    c = TokenCharacteristics(name=cookie_name)
    if not tokens:
        return c
    lengths = [len(t) for t in tokens]
    c.avg_length = round(statistics.mean(lengths), 1)
    c.min_length, c.max_length = min(lengths), max(lengths)
    all_chars = set("".join(tokens))
    if all_chars <= set("0123456789abcdefABCDEF"):
        c.hex_only, c.charset = True, "hex"
    elif all_chars <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="):
        c.base64_likely, c.charset = True, "base64"
    else:
        c.charset = "mixed"
    if all(t.count(".") == 2 for t in tokens):
        c.jwt_format = True
    return c


def _summarize_validation_error(exc: Exception) -> str:
    try:
        errors = exc.errors()  # type: ignore[attr-defined]
    except Exception:
        errors = []

    messages = []
    for item in errors:
        location = ".".join(str(part) for part in item.get("loc", []))
        message = item.get("msg", "Invalid input")
        if message.lower().startswith("value error, "):
            message = message[len("Value error, "):]
        messages.append(f"{location}: {message}" if location else message)

    return "; ".join(messages) if messages else str(exc)

def session_token_analysis(
    target: str, cookie_name: Optional[str] = None,
    sample_count: int = 20, headers: Optional[dict[str, str]] = None,
    timeout: int = 15, verify_tls: bool = True,
) -> dict:
    """Analyze session tokens for entropy, predictability, and cookie security."""
    start = time.time()
    if headers is None:
        headers = {}
    try:
        req = SessionAnalysisRequest(target=target, cookie_name=cookie_name,
                                     sample_count=sample_count, headers=headers,
                                     timeout=timeout, verify_tls=verify_tls)
    except Exception as e:
        return SessionTokenResult(
            success=False,
            target=target,
            error=f"Validation: {_summarize_validation_error(e)}",
            execution_time=round(time.time()-start, 2),
        ).model_dump()

    tokens, cookie_flags, detected = _collect_tokens(
        req.target, req.cookie_name, req.sample_count, req.headers, req.timeout, req.verify_tls
    )
    if not tokens:
        return SessionTokenResult(success=False, target=target, error="No session tokens collected",
                                  cookie_security=cookie_flags, execution_time=round(time.time()-start, 2)).model_dump()

    cookie_name_used = detected or "unknown"
    issues = []
    chars = _analyze_characteristics(tokens, cookie_name_used)
    if chars.avg_length < 16: issues.append(f"Short token length (avg: {chars.avg_length})")
    entropy = _analyze_entropy(tokens)
    if entropy.entropy_grade in ("poor", "weak"):
        issues.append(f"{'CRITICAL: Poor' if entropy.entropy_grade == 'poor' else 'Weak'} entropy ({entropy.entropy_ratio:.2%})")
    pred = _analyze_predictability(tokens)
    if pred.identical_tokens_detected:
        issues.append("Identical tokens collected across requests — token appears fixed or highly predictable")
    if pred.sequential_detected: issues.append("Sequential tokens detected — predictable")
    if pred.timestamp_based: issues.append("Timestamp-based token component detected")
    for f in cookie_flags: issues.extend(f.issues)
    issues = list(dict.fromkeys(issues))

    cookie_issue_count = sum(len(flag.issues) for flag in cookie_flags)
    sev = "info"
    if pred.predictability_score >= 0.6: sev = "critical"
    elif pred.predictability_score >= 0.3: sev = "high"
    elif entropy.entropy_grade == "poor": sev = "high"
    elif entropy.entropy_grade == "weak": sev = "medium"
    elif cookie_issue_count: sev = "medium"
    elif issues: sev = "low"
    masked = [t[:4] + "..." + t[-4:] if len(t) > 12 else t[:4] + "..." for t in tokens[:5]]
    return SessionTokenResult(
        success=True, target=target, tokens_collected=len(tokens),
        token_characteristics=chars, entropy_analysis=entropy,
        predictability_analysis=pred, cookie_security=cookie_flags,
        sample_tokens=masked, all_issues=issues, severity=sev,
        execution_time=round(time.time()-start, 2),
    ).model_dump()

SESSION_TOKEN_ANALYSIS_TOOL_DEFINITION = {
    "name": "session_token_analysis",
    "description": (
        "Analyze session tokens for randomness, predictability, and cookie security. "
        "Collects tokens, performs Shannon entropy, chi-squared, serial correlation, "
        "sequential/timestamp detection, and evaluates cookie flags."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL to collect tokens from"},
            "cookie_name": {"type": "string", "description": "Cookie name to analyze (auto-detected if not set)"},
            "sample_count": {"type": "integer", "description": "Tokens to collect (default: 20)"},
            "headers": {"type": "object", "description": "Custom HTTP headers"},
            "timeout": {"type": "integer", "description": "Timeout per request"},
            "verify_tls": {"type": "boolean", "description": "Verify TLS certificates (default: true)"},
        },
        "required": ["target"],
    },
}


def run_examples() -> None:
    examples: list[tuple[str, dict]] = [
        (
            "Public fixed-cookie demo",
            {
                "target": "https://httpbin.org/cookies/set?sessionid=pentaforge-demo-token-1234567890",
                "sample_count": 5,
            },
        ),
        (
            "Explicit cookie name",
            {
                "target": "https://httpbin.org/cookies/set?sessionid=pentaforge-demo-token-1234567890",
                "cookie_name": "sessionid",
                "sample_count": 5,
            },
        ),
        (
            "SSRF guard (should fail validation)",
            {
                "target": "http://localhost:8080/",
                "sample_count": 5,
            },
        ),
    ]

    for label, kwargs in examples:
        print(f"\n{'=' * 60}")
        print(f"=== {label} ===")
        print(json.dumps(session_token_analysis(**kwargs), indent=2))


if __name__ == "__main__":
    run_examples()
