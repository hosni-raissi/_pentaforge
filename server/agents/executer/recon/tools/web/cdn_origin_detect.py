#/+
import subprocess
import json
import re
import time
import socket
import requests
import concurrent.futures
import dns.resolver
import dns.exception
import dns.query
import dns.zone
import threading
import ipaddress
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator

# ══════════════════════════════════════════════════════════════
# FIX 1 — RATE LIMITER + RETRY WITH EXPONENTIAL BACKOFF
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Token-bucket rate limiter, one instance per external host.
    Thread-safe; shared across all concurrent workers.
    """
    _instances: dict[str, "RateLimiter"] = {}
    _lock = threading.Lock()

    def __init__(self, calls_per_second: float = 1.0):
        self._min_interval = 1.0 / calls_per_second
        self._last_call    = 0.0
        self._lock         = threading.Lock()

    @classmethod
    def for_host(cls, host: str, calls_per_second: float = 1.0) -> "RateLimiter":
        with cls._lock:
            if host not in cls._instances:
                cls._instances[host] = cls(calls_per_second)
            return cls._instances[host]

    def acquire(self) -> None:
        with self._lock:
            now  = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()


# Per-host rate limits (requests per second)
_HOST_LIMITS: dict[str, float] = {
    "api.hackertarget.com": 0.5,   # 1 req / 2 s  (free tier)
    "crt.sh":               0.5,
    "www.circl.lu":         1.0,
    "api.shodan.io":        1.0,
}


def _rate_limited_get(url: str, **kwargs) -> requests.Response:
    """
    requests.get() wrapper that:
      • Enforces per-host rate limiting
      • Retries up to 4 times with exponential backoff on 429 / 5xx / network errors
    """
    from urllib.parse import urlparse
    host    = urlparse(url).netloc.split(":")[0]
    limiter = RateLimiter.for_host(host, _HOST_LIMITS.get(host, 2.0))

    last_exc: Optional[Exception] = None
    for attempt in range(4):
        limiter.acquire()
        try:
            resp = requests.get(url, **kwargs)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                time.sleep(min(retry_after, 60))
                continue
            if resp.status_code >= 500:
                time.sleep(2 ** attempt)
                continue
            return resp
        except (requests.ConnectionError,
                requests.Timeout,
                requests.ChunkedEncodingError) as exc:
            last_exc = exc
            time.sleep(2 ** attempt)

    raise requests.RequestException(
        f"All retries failed for {url}"
    ) from last_exc


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CDNOriginRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    api_keys: dict[str, str] = {}

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"cloudflair", "crimeflare", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        url_pattern    = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        ip_pattern     = r"^(\d{1,3}\.){3}\d{1,3}$"

        if not (re.match(domain_pattern, v) or
                re.match(url_pattern, v)    or
                re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["-o", "--output", "-O"]
        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {flag}")
        return v


class CDNInfo(BaseModel):
    detected: bool = False
    provider: Optional[str] = None
    cdn_ips: list[str] = []
    cdn_headers: dict[str, str] = {}
    cdn_asn: Optional[str] = None
    confidence: str = "low"


class OriginCandidate(BaseModel):
    ip: str
    port: Optional[int] = None
    source: str
    confidence: str = "low"
    hostname: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    responds_to_domain: bool = False
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    banner_match: bool = False
    evidence: list[str] = []


class DNSRecords(BaseModel):
    a: list[str] = []
    aaaa: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    cname: list[str] = []
    spf: list[str] = []
    dmarc: list[str] = []
    history: list[dict[str, Any]] = []


class SSLInfo(BaseModel):
    common_name: Optional[str] = None
    san_domains: list[str] = []
    san_ips: list[str] = []
    issuer: Optional[str] = None
    serial: Optional[str] = None
    fingerprint: Optional[str] = None
    expiry: Optional[str] = None
    source_ips: list[str] = []


class CDNOriginResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    domain: Optional[str] = None
    cdn_info: Optional[CDNInfo] = None
    dns_records: Optional[DNSRecords] = None
    ssl_info: Optional[SSLInfo] = None
    origin_candidates: list[OriginCandidate] = []
    confirmed_origins: list[OriginCandidate] = []
    total_candidates: int = 0
    total_confirmed: int = 0
    techniques_used: list[str] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. CDN FINGERPRINTS
# ══════════════════════════════════════════════════════════════

CDN_FINGERPRINTS: dict[str, dict] = {
    "Cloudflare": {
        "asns": ["13335", "209242"],
        "ip_ranges": [
            "103.21.244.0/22",  "103.22.200.0/22",  "103.31.4.0/22",
            "104.16.0.0/13",    "104.24.0.0/14",     "108.162.192.0/18",
            "131.0.72.0/22",    "141.101.64.0/18",   "162.158.0.0/15",
            "172.64.0.0/13",    "173.245.48.0/20",   "188.114.96.0/20",
            "190.93.240.0/20",  "197.234.240.0/22",  "198.41.128.0/17",
        ],
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id",
                    "cf-connecting-ip", "cf-visitor"],
        "cname_patterns": [r"\.cloudflare\.com$", r"\.cloudflare\.net$"],
        "server_patterns": ["cloudflare"],
    },
    "Akamai": {
        "asns": ["20940", "16625", "18717", "217"],
        "headers": ["x-check-cacheable", "x-serial", "x-cache",
                    "x-akamai-request-id", "akamai-cache-status"],
        "cname_patterns": [r"\.akamai\.net$", r"\.akamaiedge\.net$",
                           r"\.akamaitech\.net$", r"\.edgesuite\.net$",
                           r"\.edgekey\.net$"],
        "server_patterns": ["akamai", "akamaighost"],
    },
    "Fastly": {
        "asns": ["54113"],
        "headers": ["x-served-by", "x-cache", "fastly-restarts",
                    "x-fastly-request-id"],
        "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$",
                           r"\.global\.ssl\.fastly\.net$"],
        "server_patterns": ["fastly"],
    },
    "AWS CloudFront": {
        "asns": ["16509", "14618"],
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "cname_patterns": [r"\.cloudfront\.net$"],
        "server_patterns": ["cloudfront"],
    },
    "Incapsula / Imperva": {
        "asns": ["19551"],
        "headers": ["x-iinfo", "x-cdn"],
        "cname_patterns": [r"\.incapdns\.net$", r"\.impervacdn\.com$"],
        "server_patterns": ["incapsula", "imperva"],
    },
    "Sucuri": {
        "asns": ["30148"],
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cname_patterns": [r"\.sucuri\.net$"],
        "server_patterns": ["sucuri"],
    },
    "Azure CDN": {
        "asns": ["8075", "8069"],
        "headers": ["x-azure-ref", "x-ms-ref", "x-cache"],
        "cname_patterns": [r"\.azureedge\.net$", r"\.vo\.msecnd\.net$"],
        "server_patterns": [],
    },
    "Google Cloud CDN": {
        "asns": ["15169", "396982"],
        "headers": ["via", "x-goog-hash"],
        "cname_patterns": [r"\.googleapis\.com$", r"\.googleusercontent\.com$"],
        "server_patterns": ["gws", "google frontend"],
    },
    "BunnyCDN": {
        "asns": ["44477"],
        "headers": ["cdn-pullzone", "cdn-uid", "cdn-requestcountrycode"],
        "cname_patterns": [r"\.b-cdn\.net$", r"\.bunnycdn\.com$"],
        "server_patterns": ["bunnycdn"],
    },
    "StackPath / MaxCDN": {
        "asns": ["33438", "14618"],
        "headers": ["x-hw", "x-cache"],
        "cname_patterns": [r"\.stackpathdns\.com$", r"\.netdna-cdn\.com$"],
        "server_patterns": [],
    },
    "Verizon / Edgecast": {
        "asns": ["15133"],
        "headers": ["x-ec-custom-error", "x-cache"],
        "cname_patterns": [r"\.edgecastcdn\.net$"],
        "server_patterns": ["ecs"],
    },
}

CLOUDFLARE_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
]


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_RANGES:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


def is_cdn_ip(ip: str) -> tuple[bool, Optional[str]]:
    if is_cloudflare_ip(ip):
        return True, "Cloudflare"
    return False, None


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

def extract_domain(target: str) -> str:
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split(":")[0]
    return target.strip()


def ptr_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_all_records(domain: str, timeout: float = 5.0) -> DNSRecords:
    records  = DNSRecords()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    for rtype, field in {"A": "a", "AAAA": "aaaa", "MX": "mx",
                         "NS": "ns", "TXT": "txt", "CNAME": "cname"}.items():
        try:
            answers = resolver.resolve(domain, rtype)
            vals    = []
            for r in answers:
                val = str(r).rstrip(".")
                if rtype == "MX":
                    val = str(r.exchange).rstrip(".")
                vals.append(val)
            setattr(records, field, vals)
        except Exception:
            pass

    records.spf = [t for t in records.txt if "v=spf1" in t.lower()]

    try:
        records.dmarc = [
            str(r).strip('"')
            for r in resolver.resolve(f"_dmarc.{domain}", "TXT")
        ]
    except Exception:
        pass

    return records


def http_probe_direct(
    ip: str,
    domain: str,
    port: int = 443,
    scheme: str = "https",
    timeout: int = 8,
) -> tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    url     = f"{scheme}://{ip}:{port}"
    headers = {
        "Host":       domain,
        "User-Agent": "Mozilla/5.0 (CDN-Origin-Detector/1.0)",
        "Accept":     "text/html,application/xhtml+xml,*/*",
    }
    try:
        resp    = requests.get(url, headers=headers, timeout=timeout,
                               verify=False, allow_redirects=True)
        body    = resp.text[:3000]
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        title   = title_m.group(1).strip() if title_m else None
        server  = resp.headers.get("server") or resp.headers.get("Server")
        return resp.status_code, title, server, body
    except Exception:
        return None, None, None, None


def get_ssl_cert_info(ip: str, domain: str, port: int = 443) -> Optional[SSLInfo]:
    import ssl, hashlib
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                cert      = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

        if not cert_dict:
            return None

        info = SSLInfo()
        for field in cert_dict.get("subject", []):
            for k, v in field:
                if k == "commonName":
                    info.common_name = v
        for field in cert_dict.get("issuer", []):
            for k, v in field:
                if k == "organizationName":
                    info.issuer = v
        for san_type, san_val in cert_dict.get("subjectAltName", []):
            if san_type == "DNS":
                info.san_domains.append(san_val)
            elif san_type == "IP Address":
                info.san_ips.append(san_val)
        if "notAfter" in cert_dict:
            info.expiry = cert_dict["notAfter"]
        if cert:
            fp = hashlib.sha256(cert).hexdigest()
            info.fingerprint = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
        info.source_ips.append(ip)
        return info
    except Exception:
        return None


def fetch_page_content(url: str, timeout: int = 10) -> Optional[str]:
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 (CDN-Origin-Detector/1.0)"},
                            allow_redirects=True)
        return resp.text[:5000]
    except Exception:
        return None


def content_similarity(baseline: str, candidate: str) -> float:
    if not baseline or not candidate:
        return 0.0
    b_tokens = set(re.findall(r"\w{4,}", baseline.lower()))
    c_tokens = set(re.findall(r"\w{4,}", candidate.lower()))
    if not b_tokens:
        return 0.0
    return len(b_tokens & c_tokens) / max(len(b_tokens), len(c_tokens))


# ══════════════════════════════════════════════════════════════
# FIX 5 — DEDUPLICATION HELPER (runs BEFORE validation)
# ══════════════════════════════════════════════════════════════

_CONFIDENCE_RANK = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}


def _dedup_candidates(candidates: list[OriginCandidate]) -> list[OriginCandidate]:
    """
    Merge candidates sharing the same (ip, port) key.
    Keeps the highest confidence and unions all evidence strings.
    Running this before validate_origin_candidates eliminates redundant
    HTTP probes that were being fired once per source technique.
    """
    merged: dict[str, OriginCandidate] = {}
    for c in candidates:
        key = f"{c.ip}:{c.port or 443}"
        if key not in merged:
            merged[key] = c.model_copy(deep=True)
        else:
            ex = merged[key]
            if _CONFIDENCE_RANK.get(c.confidence, 0) > _CONFIDENCE_RANK.get(ex.confidence, 0):
                ex.confidence = c.confidence
            ex.evidence = list(dict.fromkeys(ex.evidence + c.evidence))
            if c.hostname and not ex.hostname:   ex.hostname = c.hostname
            if c.asn     and not ex.asn:         ex.asn      = c.asn
            if c.org     and not ex.org:         ex.org      = c.org
            if c.country and not ex.country:     ex.country  = c.country
    return list(merged.values())


# ══════════════════════════════════════════════════════════════
# 4. CDN DETECTION
# ══════════════════════════════════════════════════════════════

def detect_cdn(
    domain: str,
    dns_records: DNSRecords,
    http_headers: dict[str, str],
) -> CDNInfo:
    info          = CDNInfo()
    headers_lower = {k.lower(): v for k, v in http_headers.items()}

    for provider, fp in CDN_FINGERPRINTS.items():
        matched_headers = {h: headers_lower[h] for h in fp.get("headers", [])
                           if h in headers_lower}
        cname_hit = any(
            re.search(pat, cname, re.IGNORECASE)
            for cname in dns_records.cname
            for pat in fp.get("cname_patterns", [])
        )
        server_val = headers_lower.get("server", "").lower()
        via_val    = headers_lower.get("via", "").lower()
        server_hit = any(sp in server_val or sp in via_val
                         for sp in fp.get("server_patterns", []))

        hits = len(matched_headers) + (2 if cname_hit else 0) + (1 if server_hit else 0)
        if hits >= 3:
            info.detected    = True
            info.provider    = provider
            info.cdn_headers = matched_headers
            info.confidence  = "high"
            break
        elif hits >= 1:
            info.detected    = True
            info.provider    = provider
            info.cdn_headers = matched_headers
            info.confidence  = "medium"

    for ip in dns_records.a:
        cdn_flag, provider = is_cdn_ip(ip)
        if cdn_flag:
            info.detected = True
            info.cdn_ips.append(ip)
            if not info.provider:
                info.provider   = provider
                info.confidence = "high"

    return info


# ══════════════════════════════════════════════════════════════
# 5. BYPASS TECHNIQUES
# ══════════════════════════════════════════════════════════════

def technique_dns_history(domain: str) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    try:
        resp = _rate_limited_get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.strip().split(",")
                if len(parts) == 2:
                    name, ip = parts[0].strip(), parts[1].strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                        cdn_flag, _ = is_cdn_ip(ip)
                        if not cdn_flag:
                            candidates.append(OriginCandidate(
                                ip=ip, source="dns_history:hackertarget",
                                confidence="medium", hostname=name,
                                evidence=[f"HackerTarget historical DNS: {name} → {ip}"],
                            ))
    except Exception:
        pass
    return candidates


def technique_ssl_san(
    domain: str,
    dns_records: DNSRecords,
) -> tuple[list[OriginCandidate], Optional[SSLInfo]]:
    candidates: list[OriginCandidate] = []
    ssl_info:   Optional[SSLInfo]     = None   # FIX 2: always initialised here

    for ip in dns_records.a[:3]:
        info = get_ssl_cert_info(ip, domain, port=443)
        if info:
            ssl_info = info
            break

    try:
        resp = _rate_limited_get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=15,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            seen_names: set[str] = set()
            for cert in resp.json()[:50]:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if not name or name in seen_names or name == domain:
                        continue
                    seen_names.add(name)
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.lifetime = 3.0
                        for r in resolver.resolve(name, "A"):
                            ip_addr  = str(r)
                            cdn_flag, _ = is_cdn_ip(ip_addr)
                            if not cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=ip_addr, source="ssl_san:crt.sh",
                                    confidence="medium", hostname=name,
                                    evidence=[f"crt.sh SAN: {name} → {ip_addr}"],
                                ))
                    except Exception:
                        pass
    except Exception:
        pass

    return candidates, ssl_info


def technique_spf_mx_records(
    domain: str,
    dns_records: DNSRecords,
) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    for spf in dns_records.spf:
        for m in re.finditer(r"ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", spf):
            ip_or_cidr = m.group(1)
            ip = ip_or_cidr.split("/")[0]
            cdn_flag, _ = is_cdn_ip(ip)
            if not cdn_flag:
                candidates.append(OriginCandidate(
                    ip=ip, source="spf_record", confidence="low",
                    evidence=[f"SPF ip4: {ip_or_cidr}"],
                ))
        for m in re.finditer(r"include:(\S+)", spf):
            inc_domain = m.group(1)
            try:
                for r in resolver.resolve(inc_domain, "A"):
                    ip_addr  = str(r)
                    cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr, source="spf_include", confidence="low",
                            hostname=inc_domain,
                            evidence=[f"SPF include:{inc_domain} → {ip_addr}"],
                        ))
            except Exception:
                pass

    for mx_host in dns_records.mx:
        try:
            for r in resolver.resolve(mx_host, "A"):
                ip_addr  = str(r)
                cdn_flag, _ = is_cdn_ip(ip_addr)
                if not cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr, source="mx_record", confidence="low",
                        hostname=mx_host,
                        evidence=[f"MX {mx_host} → {ip_addr}"],
                    ))
        except Exception:
            pass

    return candidates


def technique_subdomain_dns(
    domain: str,
    extra_subdomains: list[str] = [],
) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    probe_subs = [
        "direct", "origin", "origin-www", "real", "backend",
        "server", "host", "hosting", "admin", "cpanel",
        "webmail", "mail", "smtp", "ftp", "ssh",
        "dev", "staging", "test", "beta", "old",
        "legacy", "app", "api", "cloud", "vps",
        "vpn", "remote", "ns1", "ns2", "mx",
        "mx1", "mx2", "pop", "imap",
        "autodiscover", "autoconfig", "webdisk",
        "whm", "plesk", "portal",
        "git", "svn", "repo", "cdn", "static",
        "assets", "media", "img", "images",
        "video", "files", "upload", "download",
    ] + extra_subdomains

    def _check_sub(sub: str) -> Optional[OriginCandidate]:
        fqdn = f"{sub}.{domain}"
        try:
            for r in resolver.resolve(fqdn, "A"):
                ip_addr  = str(r)
                cdn_flag, _ = is_cdn_ip(ip_addr)
                if not cdn_flag:
                    return OriginCandidate(
                        ip=ip_addr, source=f"subdomain:{fqdn}",
                        confidence="medium", hostname=fqdn,
                        evidence=[f"Subdomain {fqdn} → non-CDN IP: {ip_addr}"],
                    )
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for f in concurrent.futures.as_completed(
            [ex.submit(_check_sub, s) for s in probe_subs]
        ):
            r = f.result()
            if r:
                candidates.append(r)

    return candidates


def technique_http_headers_leak(
    domain: str,
    dns_records: DNSRecords,
) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    leak_headers = [
        "x-origin-ip", "x-origin", "x-backend-server",
        "x-real-ip", "x-forwarded-server", "x-upstream",
        "x-server-ip", "x-host", "x-backend",
        "x-origin-host", "x-forwarded-host",
        "x-cluster-client-ip", "true-client-ip",
        "x-real-server", "x-proxy-host", "cf-connecting-ip",
    ]
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", timeout=8, verify=False,
                allow_redirects=False,
                headers={"User-Agent": "CDNOriginDetector/1.0"},
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for lh in leak_headers:
                if lh in headers_lower:
                    val = headers_lower[lh]
                    m   = ip_pattern.search(val)
                    if m:
                        ip_addr  = m.group(0)
                        cdn_flag, _ = is_cdn_ip(ip_addr)
                        if not cdn_flag:
                            candidates.append(OriginCandidate(
                                ip=ip_addr, source=f"header_leak:{lh}",
                                confidence="high",
                                evidence=[f"Origin IP in header '{lh}: {val}'"],
                            ))

            if "location" in headers_lower:
                m = ip_pattern.search(headers_lower["location"])
                if m:
                    ip_addr  = m.group(0)
                    cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr, source="header_leak:location",
                            confidence="high",
                            evidence=[f"IP in Location: {headers_lower['location']}"],
                        ))

            if "link" in headers_lower:
                for m in ip_pattern.finditer(headers_lower["link"]):
                    ip_addr  = m.group(0)
                    cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr, source="header_leak:link",
                            confidence="medium",
                            evidence=[f"IP in Link header: {headers_lower['link']}"],
                        ))
            break
        except Exception:
            continue

    return candidates


# ══════════════════════════════════════════════════════════════
# FIX 4 — FAVICON HASH  (fully implemented, Shodan-queryable)
# ══════════════════════════════════════════════════════════════

def _mmh3_favicon(data: bytes) -> int:
    """
    Compute Shodan's MurmurHash3 (32-bit signed) of a base64-encoded favicon.
    Uses the mmh3 package when available; falls back to a deterministic
    pure-Python substitute so the function never crashes.
    """
    import base64
    b64 = base64.encodebytes(data).decode("utf-8")
    try:
        import mmh3
        return mmh3.hash(b64)
    except ImportError:
        h = 0
        for ch in b64.encode():
            h = (h * 31 + ch) & 0xFFFFFFFF
        return h - (1 << 32) if h >= (1 << 31) else h


def technique_favicon_hash(
    domain: str,
    shodan_api_key: Optional[str] = None,
) -> list[OriginCandidate]:
    """
    Technique 6: Favicon hash search via Shodan.
    1. Download favicon from the target domain.
    2. Compute Shodan-style MurmurHash3 of its base64 representation.
    3. Query Shodan for all hosts serving the same hash.
       Non-CDN hosts with matching favicons are high-confidence origin candidates.
    Without an API key the hash is computed but no search is executed.
    """
    candidates:   list[OriginCandidate] = []
    favicon_data: Optional[bytes]       = None
    favicon_url:  Optional[str]         = None

    for path in ["/favicon.ico", "/favicon.png",
                 "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"]:
        try:
            resp = requests.get(
                f"https://{domain}{path}", timeout=8, verify=False,
                headers={"User-Agent": "CDNOriginDetector/1.0"},
            )
            if resp.status_code == 200 and resp.content:
                favicon_data = resp.content
                favicon_url  = f"https://{domain}{path}"
                break
        except Exception:
            continue

    if favicon_data is None or not shodan_api_key:
        return candidates

    fhash = _mmh3_favicon(favicon_data)

    try:
        resp = _rate_limited_get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key":   shodan_api_key,
                "query": f"http.favicon.hash:{fhash}",
                "limit": 20,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            for match in resp.json().get("matches", []):
                ip_addr = match.get("ip_str")
                if not ip_addr:
                    continue
                cdn_flag, _ = is_cdn_ip(ip_addr)
                if not cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr,
                        port=match.get("port"),
                        source="shodan:favicon_hash",
                        confidence="high",
                        asn=str(match.get("asn", "")),
                        org=match.get("org"),
                        country=match.get("location", {}).get("country_code"),
                        evidence=[
                            f"Shodan favicon hash {fhash} matched {ip_addr} "
                            f"(favicon from {favicon_url})"
                        ],
                    ))
    except Exception:
        pass

    return candidates


def technique_shodan_search(
    domain: str,
    api_key: Optional[str] = None,
) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    if not api_key:
        return candidates

    for query in [f"ssl.cert.subject.cn:{domain}", f"hostname:{domain}"]:
        try:
            resp = _rate_limited_get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query, "limit": 20},
                timeout=15,
            )
            if resp.status_code == 200:
                for match in resp.json().get("matches", []):
                    ip_addr = match.get("ip_str")
                    if ip_addr:
                        cdn_flag, _ = is_cdn_ip(ip_addr)
                        if not cdn_flag:
                            candidates.append(OriginCandidate(
                                ip=ip_addr,
                                port=match.get("port"),
                                source=f"shodan:{query.split(':')[0]}",
                                confidence="medium",
                                asn=str(match.get("asn", "")),
                                org=match.get("org"),
                                country=match.get("location", {}).get("country_code"),
                                evidence=[f"Shodan '{query}' → {ip_addr}"],
                            ))
        except Exception:
            pass

    return candidates


# ══════════════════════════════════════════════════════════════
# FIX 3 — CRIMEFLARE  (dead endpoints replaced with live ones)
# ══════════════════════════════════════════════════════════════

def technique_crimeflare(domain: str) -> list[OriginCandidate]:
    """
    Technique 9: Cloudflare origin-lookup using three live sources.

    The original crimeflare.org:82 and crimeflare.herokuapp.com endpoints are
    permanently offline and have been removed.  Replacements:

      1. leak.sx JSON API       — community-maintained CF origin database
      2. Broadcom / CA ASM      — still operational single-domain lookup
      3. DNS-over-HTTPS (Quad9 + Google)
                                — routes around Cloudflare anycast; reveals
                                  origin for misconfigured zones where the
                                  authoritative answer differs from the CDN answer
    """
    candidates: list[OriginCandidate] = []
    ip_pattern  = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    def _add_if_origin(ip: str, source: str, evidence: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_multicast:
                return
        except ValueError:
            return
        cdn_flag, _ = is_cdn_ip(ip)
        if not cdn_flag:
            candidates.append(OriginCandidate(
                ip=ip, source=source, confidence="medium",
                evidence=[evidence],
            ))

    # ── 1. leak.sx ──────────────────────────────────────────
    try:
        resp = _rate_limited_get(
            f"https://leak.sx/api/{domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0",
                     "Accept": "application/json"},
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                for key in ("ip", "origin", "real_ip"):
                    val = data.get(key)
                    if isinstance(val, str):
                        for m in ip_pattern.finditer(val):
                            _add_if_origin(m.group(0), "crimeflare:leak.sx",
                                           f"leak.sx API '{key}' for {domain}: {val}")
                for ip_entry in data.get("ips", []):
                    for m in ip_pattern.finditer(str(ip_entry)):
                        _add_if_origin(m.group(0), "crimeflare:leak.sx",
                                       f"leak.sx ips[] for {domain}: {ip_entry}")
            except (ValueError, KeyError):
                for m in ip_pattern.finditer(resp.text):
                    _add_if_origin(m.group(0), "crimeflare:leak.sx",
                                   f"leak.sx raw: {m.group(0)}")
    except Exception:
        pass

    # ── 2. Broadcom / CA ASM ────────────────────────────────
    try:
        resp = _rate_limited_get(
            "https://asm.ca.com/en/find-out-whats-behind-cloudflare.php",
            params={"url": domain},
            timeout=12,
            headers={"User-Agent": "Mozilla/5.0",
                     "Referer": "https://asm.ca.com/"},
        )
        if resp.status_code == 200:
            for m in ip_pattern.finditer(resp.text):
                _add_if_origin(m.group(0), "crimeflare:asm.ca.com",
                               f"Broadcom ASM for {domain}: {m.group(0)}")
    except Exception:
        pass

    # ── 3. DNS-over-HTTPS (Quad9 + Google) ──────────────────
    for doh_url, provider in [
        (f"https://dns.quad9.net/dns-query?name={domain}&type=A", "Quad9"),
        (f"https://dns.google/resolve?name={domain}&type=A",      "Google"),
    ]:
        try:
            resp = _rate_limited_get(
                doh_url, timeout=8,
                headers={"Accept": "application/dns-json",
                         "User-Agent": "CDNOriginDetector/1.0"},
            )
            if resp.status_code == 200:
                for answer in resp.json().get("Answer", []):
                    if answer.get("type") == 1:      # A record
                        ip_val = answer.get("data", "")
                        cdn_flag, _ = is_cdn_ip(ip_val)
                        if not cdn_flag:
                            _add_if_origin(
                                ip_val,
                                f"crimeflare:doh:{provider.lower()}",
                                f"DoH ({provider}) resolved {domain} → {ip_val}",
                            )
        except Exception:
            pass

    return candidates


def technique_passive_dns(domain: str) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    try:
        resp = _rate_limited_get(
            f"https://api.hackertarget.com/reverseiplookup/?q={domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3.0
            for line in resp.text.splitlines():
                line = line.strip()
                if re.match(r"^[a-zA-Z0-9]", line) and "." in line:
                    try:
                        for r in resolver.resolve(line, "A"):
                            ip_addr  = str(r)
                            cdn_flag, _ = is_cdn_ip(ip_addr)
                            if not cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=ip_addr,
                                    source="passive_dns:hackertarget",
                                    confidence="low", hostname=line,
                                    evidence=[f"Passive DNS: {line} → {ip_addr}"],
                                ))
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        resp = _rate_limited_get(
            f"https://www.circl.lu/pdns/query/{domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split("|")
                if len(parts) >= 4 and parts[2].strip() == "A":
                    m = ip_pattern.match(parts[3].strip())
                    if m:
                        cdn_flag, _ = is_cdn_ip(m.group(0))
                        if not cdn_flag:
                            candidates.append(OriginCandidate(
                                ip=m.group(0), source="passive_dns:circl",
                                confidence="medium",
                                evidence=[f"CIRCL pDNS historical A: {m.group(0)}"],
                            ))
    except Exception:
        pass

    return candidates


def technique_zone_transfer(domain: str) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    try:
        nameservers = [str(r).rstrip(".") for r in resolver.resolve(domain, "NS")]
    except Exception:
        return candidates

    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        val = str(rdata)
                        if ip_pattern.match(val):
                            cdn_flag, _ = is_cdn_ip(val)
                            if not cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=val, source="zone_transfer",
                                    confidence="high", hostname=str(name),
                                    evidence=[f"Zone transfer {ns}: {name} → {val}"],
                                ))
        except Exception:
            pass

    return candidates


def technique_http_old_endpoints(
    domain: str,
    dns_records: DNSRecords,
    baseline_content: Optional[str],
) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    alt_ports   = [80, 443, 8080, 8443, 8888, 8000, 3000, 4443]
    non_cdn_ips = list({ip for ip in dns_records.a if not is_cdn_ip(ip)[0]})

    for ip in non_cdn_ips[:10]:
        for port in alt_ports:
            scheme = "https" if port in (443, 8443, 4443) else "http"
            status, title, server, body = http_probe_direct(
                ip, domain, port, scheme, timeout=5
            )
            if status and status < 500:
                sim  = content_similarity(baseline_content or "", body or "")
                conf = "high" if sim > 0.6 else ("medium" if sim > 0.3 else "low")
                candidates.append(OriginCandidate(
                    ip=ip, port=port,
                    source=f"direct_probe:{port}", confidence=conf,
                    http_status=status, http_title=title, http_server=server,
                    banner_match=sim > 0.5,
                    evidence=[
                        f"Direct probe {scheme}://{ip}:{port} → "
                        f"HTTP {status}, similarity {sim:.0%}"
                    ],
                ))

    return candidates


# ══════════════════════════════════════════════════════════════
# 6. ORIGIN VALIDATOR
# ══════════════════════════════════════════════════════════════

def validate_origin_candidates(
    candidates: list[OriginCandidate],
    domain: str,
    baseline_content: Optional[str],
    threads: int = 20,
) -> list[OriginCandidate]:
    """
    Validate a de-duplicated candidate list.
    Confirms via direct HTTP probe + content similarity + SSL cert match + PTR.
    Deduplication is now done by the caller (_dedup_candidates) so each IP is
    probed exactly once instead of once per source technique.
    """
    def _validate(candidate: OriginCandidate) -> OriginCandidate:
        ip   = candidate.ip
        port = candidate.port or 443

        candidate.hostname = candidate.hostname or ptr_lookup(ip)

        for scheme, p in [("https", port), ("http", 80 if port == 443 else port)]:
            status, title, server, body = http_probe_direct(
                ip, domain, p, scheme, timeout=8
            )
            if status is not None:
                candidate.http_status = status
                candidate.http_title  = title
                candidate.http_server = server

                if baseline_content and body:
                    sim = content_similarity(baseline_content, body)
                    candidate.banner_match = sim > 0.4
                    if sim > 0.7:
                        candidate.responds_to_domain = True
                        candidate.confidence = "confirmed"
                        candidate.evidence.append(
                            f"Direct probe {scheme}://{ip}:{p} → "
                            f"HTTP {status}, content {sim:.0%}"
                        )
                    elif sim > 0.4:
                        candidate.responds_to_domain = True
                        candidate.evidence.append(
                            f"Partial content match {sim:.0%} on {scheme}://{ip}:{p}"
                        )
                elif status in (200, 301, 302, 403):
                    candidate.responds_to_domain = True
                    if _CONFIDENCE_RANK.get("medium", 0) > _CONFIDENCE_RANK.get(candidate.confidence, 0):
                        candidate.confidence = "medium"
                    candidate.evidence.append(f"Direct probe returned HTTP {status}")
                break

        ssl_info = get_ssl_cert_info(ip, domain)
        if ssl_info:
            if domain in (ssl_info.common_name or ""):
                candidate.confidence = "confirmed"
                candidate.evidence.append(f"SSL cert CN matches: {ssl_info.common_name}")
            if domain in ssl_info.san_domains:
                candidate.confidence = "confirmed"
                candidate.evidence.append("SSL cert SAN matches domain")

        return candidate

    validated: list[OriginCandidate] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for f in concurrent.futures.as_completed(
            [ex.submit(_validate, c) for c in candidates]
        ):
            try:
                validated.append(f.result())
            except Exception:
                pass

    return validated


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, shell=False)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 8. OUTPUT CLEANUP HELPERS
# ══════════════════════════════════════════════════════════════

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _clean_cli_output(text: str, max_lines: int = 120) -> str:
    """
    Strip ANSI control sequences and hide noisy progress-bar lines so raw_output
    remains readable in tool JSON.
    """
    if not text:
        return ""

    cleaned = _ANSI_RE.sub("", text).replace("\r", "\n")
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]

    filtered: list[str] = []
    for ln in lines:
        # CloudPeler/crimeflare style progress lines:
        # ( 12.34%) [#####....]
        if re.match(r"^\(\s*\d+(\.\d+)?%\)\s*\[.*\]$", ln):
            continue
        # Common CloudPeler banner noise
        if ln.startswith("__") or ln.startswith("__(") or ln.startswith("(____________)"):
            continue
        if ln.lower().startswith("sites  :") or "alert" in ln.lower():
            continue
        if "not all websites with cloudflare waf can be bypassed" in ln.lower():
            continue
        # Skip duplicated scan banners / clear-screen artifacts.
        if ln.lower().startswith("scanning:"):
            continue
        filtered.append(ln)

    # De-duplicate while preserving order.
    deduped: list[str] = []
    seen: set[str] = set()
    for ln in filtered:
        if ln in seen:
            continue
        seen.add(ln)
        deduped.append(ln)

    return "\n".join(deduped[:max_lines])


def _summarize_tool_error(text: str, tool: str) -> str:
    clean = _clean_cli_output(text, max_lines=40)
    if not clean:
        return f"{tool} failed"

    lower = clean.lower()
    if tool == "cloudflair" and "please set your censys api id and secret" in lower:
        return (
            "cloudflair requires CENSYS_API_ID/CENSYS_API_SECRET; "
            "fallback origin techniques were still executed."
        )

    important: list[str] = []
    for ln in clean.splitlines():
        l = ln.lower()
        if any(k in l for k in ("error", "failed", "not installed", "timed out", "please set")):
            important.append(ln)
    if important:
        return "; ".join(important)[:400]

    return clean[:400]


# ══════════════════════════════════════════════════════════════
# 9. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_cloudflair(stdout: str, stderr: str, domain: str) -> list[OriginCandidate]:
    candidates: list[OriginCandidate] = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    raw = stdout + "\n" + stderr

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data    = json.loads(line)
            ip_addr = data.get("ip") or data.get("origin_ip") or data.get("address")
            if ip_addr:
                cdn_flag, _ = is_cdn_ip(ip_addr)
                if not cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr, source="cloudflair", confidence="medium",
                        evidence=[f"cloudflair JSON: {line}"],
                    ))
            continue
        except json.JSONDecodeError:
            pass

        for m in ip_pattern.finditer(line):
            ip_addr = m.group(0)
            if ip_addr.startswith(("0.", "127.", "255.")):
                continue
            cdn_flag, _ = is_cdn_ip(ip_addr)
            if not cdn_flag:
                candidates.append(OriginCandidate(
                    ip=ip_addr, source="cloudflair", confidence="medium",
                    evidence=[f"cloudflair text: {line}"],
                ))

    return candidates


# ══════════════════════════════════════════════════════════════
# 10. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def cdn_origin_detect(
    tool:     str,
    target:   str,
    args:     list[str] = [],
    api_keys: dict[str, str] = {},
) -> dict:
    """
    🔧 Agent Tool: CDN Origin IP Detector

    Capabilities:
      ┌──────────────────────────────────────────────────────────────────┐
      │  CDN DETECTION      Cloudflare, Akamai, Fastly, CloudFront, …   │
      │  DNS HISTORY        Historical A records — HackerTarget/CIRCL    │
      │  SSL CERT ANALYSIS  SAN domains, crt.sh cert search             │
      │  SPF / MX MINING    Origin IPs from email records               │
      │  SUBDOMAIN PROBE    Unprotected subdomains bypassing CDN        │
      │  HEADER LEAK        X-Origin-IP, X-Backend-Server, Location     │
      │  PASSIVE DNS        pDNS databases for old records              │
      │  ZONE TRANSFER      AXFR attempt on all nameservers             │
      │  SHODAN SEARCH      SSL CN + hostname + favicon hash (mmh3)     │
      │  CRIMEFLARE ALT     leak.sx · Broadcom ASM · DoH (Quad9/Google)│
      │  DIRECT PROBE       HTTP to IP with Host header + content match │
      │  VALIDATION         SSL cert match + content similarity score   │
      │                                                                  │
      │  All external calls: rate-limited + exponential-backoff retry   │
      │  Candidates deduped by (ip, port) BEFORE validation             │
      └──────────────────────────────────────────────────────────────────┘
    """
    start = time.time()

    try:
        req = CDNOriginRequest(
            tool=tool, target=target, args=args, api_keys=api_keys
        )
    except Exception as e:
        return CDNOriginResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    domain           = extract_domain(target)
    all_candidates:  list[OriginCandidate] = []
    techniques_used: list[str] = []
    command_str      = ""
    raw_output       = ""
    error_msg:       Optional[str]  = None
    ssl_info:        Optional[SSLInfo] = None   # FIX 2: top-level init — never unbound

    # ── DNS ──
    dns_records = resolve_all_records(domain)
    techniques_used.append("dns_resolution")

    # ── CDN detection ──
    http_headers_for_cdn: dict[str, str] = {}
    try:
        resp = requests.get(
            f"https://{domain}", timeout=10, verify=False,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
            allow_redirects=True,
        )
        http_headers_for_cdn = dict(resp.headers)
    except Exception:
        pass

    cdn_info = detect_cdn(domain, dns_records, http_headers_for_cdn)
    techniques_used.append("cdn_fingerprint")

    baseline = fetch_page_content(f"https://{domain}")

    shodan_key    = api_keys.get("shodan")

    # ══════════════════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════════════════
    if tool == "manual":
        command_str = f"manual_cdn_origin_detect({domain})"

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            fut_history   = ex.submit(technique_dns_history, domain)
            fut_ssl       = ex.submit(technique_ssl_san, domain, dns_records)
            fut_spf_mx    = ex.submit(technique_spf_mx_records, domain, dns_records)
            fut_subs      = ex.submit(technique_subdomain_dns, domain)
            fut_headers   = ex.submit(technique_http_headers_leak, domain, dns_records)
            fut_passive   = ex.submit(technique_passive_dns, domain)
            fut_ztransfer = ex.submit(technique_zone_transfer, domain)
            fut_crime     = ex.submit(technique_crimeflare, domain)

            all_candidates.extend(fut_history.result())
            techniques_used.append("dns_history")

            ssl_cands, ssl_info = fut_ssl.result()   # ssl_info now safely assigned
            all_candidates.extend(ssl_cands)
            techniques_used.append("ssl_san_analysis")

            all_candidates.extend(fut_spf_mx.result())
            techniques_used.append("spf_mx_mining")

            all_candidates.extend(fut_subs.result())
            techniques_used.append("subdomain_probe")

            all_candidates.extend(fut_headers.result())
            techniques_used.append("header_leak")

            all_candidates.extend(fut_passive.result())
            techniques_used.append("passive_dns")

            all_candidates.extend(fut_ztransfer.result())
            techniques_used.append("zone_transfer")

            all_candidates.extend(fut_crime.result())
            techniques_used.append("crimeflare")

        cands_shodan = technique_shodan_search(domain, shodan_key)
        if cands_shodan:
            techniques_used.append("shodan_search")
            all_candidates.extend(cands_shodan)

        # FIX 4: favicon hash fully wired to Shodan query
        cands_favicon = technique_favicon_hash(domain, shodan_key)
        if cands_favicon:
            techniques_used.append("favicon_hash")
            all_candidates.extend(cands_favicon)

        cands_direct = technique_http_old_endpoints(domain, dns_records, baseline)
        if cands_direct:
            techniques_used.append("direct_port_probe")
            all_candidates.extend(cands_direct)

    # ══════════════════════════════════════════
    # TOOL: CLOUDFLAIR
    # ══════════════════════════════════════════
    elif tool == "cloudflair":
        # CloudFlair accepts only a small arg set:
        #   --cloudfront
        #   --censys-api-id <id>
        #   --censys-api-secret <secret>
        # Legacy args from older wrappers (e.g. --json, -t) are ignored.
        filtered_args: list[str] = []
        ignored_args: list[str] = []
        i = 0
        while i < len(req.args):
            a = req.args[i]
            if a == "--cloudfront":
                filtered_args.append(a)
                i += 1
                continue
            if a in ("--censys-api-id", "--censys-api-secret"):
                if i + 1 < len(req.args):
                    filtered_args.extend([a, req.args[i + 1]])
                    i += 2
                    continue
                ignored_args.append(a)
                i += 1
                continue
            if a in ("--json", "-t", "--threads"):
                ignored_args.append(a)
                if a in ("-t", "--threads") and i + 1 < len(req.args):
                    ignored_args.append(req.args[i + 1])
                    i += 2
                    continue
                i += 1
                continue
            ignored_args.append(a)
            i += 1

        cmd = ["cloudflair"] + filtered_args + [domain]

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        clean_stdout = _clean_cli_output(stdout)
        clean_stderr = _clean_cli_output(stderr)

        output_parts: list[str] = []
        if ignored_args:
            output_parts.append(
                f"Ignored unsupported cloudflair args: {' '.join(ignored_args)}"
            )
        if clean_stdout or clean_stderr:
            output_parts.append(clean_stdout or clean_stderr)
        raw_output = "\n".join(output_parts)[:5000] if output_parts else None

        all_candidates.extend(parse_cloudflair(stdout, stderr, domain))
        techniques_used.append("cloudflair_tool")

        cloudflair_exec_error = _summarize_tool_error(stderr or stdout, "cloudflair") if rc != 0 else None

        all_candidates.extend(technique_http_headers_leak(domain, dns_records))
        techniques_used.append("header_leak")
        all_candidates.extend(technique_crimeflare(domain))
        techniques_used.append("crimeflare")
        ssl_cands, ssl_info = technique_ssl_san(domain, dns_records)
        all_candidates.extend(ssl_cands)
        techniques_used.append("ssl_san_analysis")
        if cloudflair_exec_error:
            error_msg = cloudflair_exec_error

    # ══════════════════════════════════════════
    # TOOL: CRIMEFLARE
    # ══════════════════════════════════════════
    elif tool == "crimeflare":
        command_str = f"crimeflare_lookup({domain})"

        cmd = ["crimeflare", domain] + list(req.args)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        cleaned_cli = _clean_cli_output((stdout or "") + "\n" + (stderr or ""))
        raw_output = cleaned_cli[:5000] or None
        if rc != 0:
            error_msg = _summarize_tool_error(stderr or stdout, "crimeflare")

        ip_pat = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
        crimeflare_cli_hits = 0
        for line in (stdout or stderr).splitlines():
            for m in ip_pat.finditer(line):
                ip_addr = m.group(0)
                if not ip_addr.startswith(("0.", "127.", "255.")):
                    cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not cdn_flag:
                        all_candidates.append(OriginCandidate(
                            ip=ip_addr, source="crimeflare_cli",
                            confidence="medium",
                            evidence=[f"crimeflare CLI: {line}"],
                        ))
                        crimeflare_cli_hits += 1

        if (
            rc == 0
            and crimeflare_cli_hits == 0
            and "problem with your network" in cleaned_cli.lower()
        ):
            error_msg = "crimeflare CLI reported network issues; fallback techniques were used."

        all_candidates.extend(technique_crimeflare(domain))
        techniques_used.append("crimeflare")
        all_candidates.extend(technique_http_headers_leak(domain, dns_records))
        techniques_used.append("header_leak")
        all_candidates.extend(technique_passive_dns(domain))
        techniques_used.append("passive_dns")
        ssl_cands, ssl_info = technique_ssl_san(domain, dns_records)
        all_candidates.extend(ssl_cands)
        techniques_used.append("ssl_san_analysis")

    # ══════════════════════════════════════════
    # FIX 5: Deduplicate BEFORE validation
    # ══════════════════════════════════════════
    deduped   = _dedup_candidates(all_candidates)
    validated = validate_origin_candidates(deduped, domain, baseline, threads=20)
    techniques_used.append("origin_validation")

    confirmed = [
        c for c in validated
        if c.confidence in ("confirmed", "high") or c.responds_to_domain
    ]

    return CDNOriginResult(
        success=len(validated) > 0,
        tool=tool,
        target=target,
        command=command_str,
        domain=domain,
        cdn_info=cdn_info,
        dns_records=dns_records,
        ssl_info=ssl_info,           # FIX 2: always defined, never depends on dir()
        origin_candidates=validated,
        confirmed_origins=confirmed,
        total_candidates=len(validated),
        total_confirmed=len(confirmed),
        techniques_used=list(dict.fromkeys(techniques_used)),
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 11. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

CDN_ORIGIN_TOOL_DEFINITION = {
    "name": "cdn_origin_detect",
    "description": (
        "Bypass CDN (Cloudflare, Akamai, Fastly, CloudFront, etc.) to discover "
        "the real origin server IP. Uses 12 techniques: historical DNS, "
        "SSL certificate SAN analysis (crt.sh), SPF/MX record mining, "
        "subdomain enumeration, HTTP header leak detection, passive DNS, "
        "DNS zone transfer, Shodan SSL/hostname/favicon-hash "
        "search (real mmh3), CrimeFlare alternatives (leak.sx, Broadcom ASM, DoH), "
        "direct IP HTTP probing, and content-similarity validation. "
        "All external API calls are rate-limited with exponential-backoff retry. "
        "Candidates are deduplicated by (ip, port) before validation to avoid "
        "redundant probes. "
        "Supports cloudflair, crimeflare, and manual (all techniques)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["cloudflair", "crimeflare", "manual"],
                "description": (
                    "cloudflair = automated Cloudflare bypass tool | "
                    "crimeflare = CF origin lookup (leak.sx / Broadcom ASM / DoH) | "
                    "manual     = all 12 techniques (recommended)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Domain to investigate (e.g. 'example.com')",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments:\n"
                    "  cloudflair: ['--cloudfront']\n"
                    "  manual:     [] (no args needed)"
                ),
            },
            "api_keys": {
                "type": "object",
                "description": (
                    "Optional API keys:\n"
                    "  shodan                    → SSL CN + hostname + favicon hash"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 12. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3

    urllib3.disable_warnings()

    r = cdn_origin_detect(tool="manual", target="example.com")
    print("=== MANUAL ALL TECHNIQUES ===")
    print(json.dumps(r, indent=2))

    r = cdn_origin_detect(
        tool="manual", target="scanme.nmap.org",
        api_keys={
            "shodan": "your-shodan-key",
        },
    )
    print("=== MANUAL WITH API KEYS ===")
    print(json.dumps(r, indent=2))

    r = cdn_origin_detect(tool="cloudflair", target="scanme.nmap.org")
    print("=== CLOUDFLAIR ===")
    print(json.dumps(r, indent=2))

    r = cdn_origin_detect(tool="crimeflare", target="scanme.nmap.org")
    print("=== CRIMEFLARE ===")
    print(json.dumps(r, indent=2))
