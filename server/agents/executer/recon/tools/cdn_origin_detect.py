import subprocess
import json
import re
import time
import socket
import requests
import concurrent.futures
import dns.resolver
import dns.exception
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CDNOriginRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    api_keys: dict[str, str] = {}      # {"censys_id": "...", "censys_secret": "...", "shodan": "..."}

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"cloudflair", "crimeflare", "censys", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
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

    @validator("args")
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


# ── CDN detection result ──
class CDNInfo(BaseModel):
    detected: bool = False
    provider: Optional[str] = None          # Cloudflare / Akamai / Fastly / etc.
    cdn_ips: list[str] = []                 # IPs belonging to CDN
    cdn_headers: dict[str, str] = {}        # CF-Ray, X-Cache, Via, etc.
    cdn_asn: Optional[str] = None
    confidence: str = "low"                 # low / medium / high


# ── A single candidate origin IP ──
class OriginCandidate(BaseModel):
    ip: str
    port: Optional[int] = None
    source: str                             # how we found it
    confidence: str = "low"                 # low / medium / high / confirmed
    hostname: Optional[str] = None          # PTR record
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    responds_to_domain: bool = False        # direct HTTP request returned target content
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    banner_match: bool = False              # response matches CDN-fronted site
    evidence: list[str] = []


# ── DNS records collected ──
class DNSRecords(BaseModel):
    a: list[str] = []
    aaaa: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    cname: list[str] = []
    spf: list[str] = []
    dmarc: list[str] = []
    history: list[dict[str, Any]] = []     # historical DNS (if available)


# ── SSL certificate info ──
class SSLInfo(BaseModel):
    common_name: Optional[str] = None
    san_domains: list[str] = []
    san_ips: list[str] = []
    issuer: Optional[str] = None
    serial: Optional[str] = None
    fingerprint: Optional[str] = None
    expiry: Optional[str] = None
    source_ips: list[str] = []             # IPs where this cert was found


# ── Final result ──
class CDNOriginResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    domain: Optional[str] = None           # cleaned domain
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

# ── Known CDN IP ranges for quick classification ──
import ipaddress

CLOUDFLARE_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
]


def is_cloudflare_ip(ip: str) -> bool:
    """Check if an IP belongs to Cloudflare's published ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_RANGES:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


def is_cdn_ip(ip: str) -> tuple[bool, Optional[str]]:
    """
    Check if an IP belongs to ANY known CDN.
    Returns (is_cdn, provider_name).
    """
    if is_cloudflare_ip(ip):
        return True, "Cloudflare"
    # Expand for other CDNs via ASN lookup (runtime)
    return False, None


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

def extract_domain(target: str) -> str:
    """Extract bare domain from URL or return as-is."""
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split(":")[0]
    return target.strip()


def ptr_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_all_records(domain: str, timeout: float = 5.0) -> DNSRecords:
    """
    Collect all DNS record types for a domain.
    A, AAAA, MX, NS, TXT, CNAME, SPF, DMARC.
    """
    records = DNSRecords()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    record_types = {
        "A":     "a",
        "AAAA":  "aaaa",
        "MX":    "mx",
        "NS":    "ns",
        "TXT":   "txt",
        "CNAME": "cname",
    }

    for rtype, field in record_types.items():
        try:
            answers = resolver.resolve(domain, rtype)
            vals = []
            for r in answers:
                val = str(r).rstrip(".")
                # MX: strip priority
                if rtype == "MX":
                    val = str(r.exchange).rstrip(".")
                vals.append(val)
            setattr(records, field, vals)
        except Exception:
            pass

    # SPF (TXT records starting with v=spf1)
    records.spf = [t for t in records.txt if "v=spf1" in t.lower()]

    # DMARC
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        records.dmarc = [str(r).strip('"') for r in dmarc_answers]
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
    """
    Send HTTP request directly to an IP with Host header set to target domain.
    Returns (status_code, title, server, body_snippet).
    This bypasses CDN because we connect directly to the IP.
    """
    url = f"{scheme}://{ip}:{port}"
    headers = {
        "Host":       domain,
        "User-Agent": "Mozilla/5.0 (CDN-Origin-Detector/1.0)",
        "Accept":     "text/html,application/xhtml+xml,*/*",
    }
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        body    = resp.text[:3000]
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        title   = title_m.group(1).strip() if title_m else None
        server  = resp.headers.get("server") or resp.headers.get("Server")
        return resp.status_code, title, server, body
    except Exception:
        return None, None, None, None


def get_ssl_cert_info(ip: str, domain: str, port: int = 443) -> Optional[SSLInfo]:
    """
    Fetch SSL certificate from an IP and extract:
    - Common Name
    - SAN domains (other domains on same cert → may reveal origin)
    - SAN IPs
    - Issuer
    - Serial / Fingerprint
    """
    import ssl
    import hashlib
    import datetime

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

        # Common Name
        for field in cert_dict.get("subject", []):
            for k, v in field:
                if k == "commonName":
                    info.common_name = v

        # Issuer
        for field in cert_dict.get("issuer", []):
            for k, v in field:
                if k == "organizationName":
                    info.issuer = v

        # SANs
        for san_type, san_val in cert_dict.get("subjectAltName", []):
            if san_type == "DNS":
                info.san_domains.append(san_val)
            elif san_type == "IP Address":
                info.san_ips.append(san_val)

        # Expiry
        if "notAfter" in cert_dict:
            info.expiry = cert_dict["notAfter"]

        # Fingerprint (SHA-256)
        if cert:
            fp = hashlib.sha256(cert).hexdigest()
            info.fingerprint = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

        info.source_ips.append(ip)
        return info

    except Exception:
        return None


def fetch_page_content(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch page content via CDN for comparison baseline."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (CDN-Origin-Detector/1.0)"},
            allow_redirects=True,
        )
        return resp.text[:5000]
    except Exception:
        return None


def content_similarity(baseline: str, candidate: str) -> float:
    """
    Simple token-based similarity between two page contents.
    Returns 0.0 - 1.0.
    """
    if not baseline or not candidate:
        return 0.0
    b_tokens = set(re.findall(r"\w{4,}", baseline.lower()))
    c_tokens = set(re.findall(r"\w{4,}", candidate.lower()))
    if not b_tokens:
        return 0.0
    intersection = b_tokens & c_tokens
    return len(intersection) / max(len(b_tokens), len(c_tokens))


# ══════════════════════════════════════════════════════════════
# 4. CDN DETECTION
# ══════════════════════════════════════════════════════════════

def detect_cdn(
    domain: str,
    dns_records: DNSRecords,
    http_headers: dict[str, str],
) -> CDNInfo:
    """
    Detect which CDN (if any) is fronting the domain.
    Uses: DNS CNAME patterns, response headers, IP range matching.
    """
    info = CDNInfo()

    headers_lower = {k.lower(): v for k, v in http_headers.items()}

    for provider, fp in CDN_FINGERPRINTS.items():

        # ── Check response headers ──
        matched_headers = {}
        for hdr in fp.get("headers", []):
            if hdr in headers_lower:
                matched_headers[hdr] = headers_lower[hdr]

        # ── Check CNAME patterns ──
        cname_hit = False
        for cname in dns_records.cname:
            for pattern in fp.get("cname_patterns", []):
                if re.search(pattern, cname, re.IGNORECASE):
                    cname_hit = True
                    break

        # ── Check Server header ──
        server_hit = False
        server_val = headers_lower.get("server", "").lower()
        via_val    = headers_lower.get("via", "").lower()
        for sp in fp.get("server_patterns", []):
            if sp in server_val or sp in via_val:
                server_hit = True

        # ── Score confidence ──
        hits = len(matched_headers) + (2 if cname_hit else 0) + (1 if server_hit else 0)

        if hits >= 3:
            info.detected  = True
            info.provider  = provider
            info.cdn_headers = matched_headers
            info.confidence = "high"
            break
        elif hits >= 1:
            info.detected  = True
            info.provider  = provider
            info.cdn_headers = matched_headers
            info.confidence = "medium"
            # Don't break — keep looking for higher-confidence match

    # ── IP-based check ──
    for ip in dns_records.a:
        is_cdn, provider = is_cdn_ip(ip)
        if is_cdn:
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
    """
    Technique 1: Historical DNS records.
    Query SecurityTrails / HackerTarget / ViewDNS APIs for old A records
    that may reveal the origin IP before CDN was added.
    """
    candidates = []
    sources = [
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        f"https://viewdns.info/iphistory/?domain={domain}&output=json",
    ]

    # HackerTarget host search
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.strip().split(",")
                if len(parts) == 2:
                    name, ip = parts[0].strip(), parts[1].strip()
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                        is_cdn_ip_flag, _ = is_cdn_ip(ip)
                        if not is_cdn_ip_flag:
                            candidates.append(OriginCandidate(
                                ip=ip,
                                source="dns_history:hackertarget",
                                confidence="medium",
                                hostname=name,
                                evidence=[f"Historical DNS record from HackerTarget: {name} → {ip}"],
                            ))
    except Exception:
        pass

    return candidates


def technique_ssl_san(
    domain: str,
    dns_records: DNSRecords,
) -> tuple[list[OriginCandidate], Optional[SSLInfo]]:
    """
    Technique 2: SSL Certificate SAN analysis.
    Fetch cert from CDN IPs → extract SANs → those domains may share
    the same origin. Also search Censys/crt.sh for certs with same SANs.
    """
    candidates = []
    ssl_info   = None

    # Fetch cert from CDN-fronted IPs
    for ip in dns_records.a[:3]:
        info = get_ssl_cert_info(ip, domain, port=443)
        if info:
            ssl_info = info
            break

    # Query crt.sh for certificates matching domain
    try:
        resp = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=15,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            certs = resp.json()
            seen_names: set[str] = set()

            for cert in certs[:50]:
                name_val = cert.get("name_value", "")
                for name in name_val.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen_names and name != domain:
                        seen_names.add(name)
                        # Try resolving these SANs → may point to origin
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.lifetime = 3.0
                            answers  = resolver.resolve(name, "A")
                            for r in answers:
                                ip_addr = str(r)
                                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                                if not is_cdn_flag:
                                    candidates.append(OriginCandidate(
                                        ip=ip_addr,
                                        source="ssl_san:crt.sh",
                                        confidence="medium",
                                        hostname=name,
                                        evidence=[
                                            f"Found via crt.sh certificate SAN: {name} → {ip_addr}"
                                        ],
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
    """
    Technique 3: SPF / MX record IP extraction.
    Mail servers often reveal the real hosting provider / IP range.
    SPF records list all IPs/ranges authorized to send email.
    """
    candidates = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    # ── Parse SPF records ──
    for spf in dns_records.spf:
        # Extract ip4: and ip6: mechanisms
        for m in re.finditer(r"ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", spf):
            ip_or_cidr = m.group(1)
            ip = ip_or_cidr.split("/")[0]
            is_cdn_flag, _ = is_cdn_ip(ip)
            if not is_cdn_flag:
                candidates.append(OriginCandidate(
                    ip=ip,
                    source="spf_record",
                    confidence="low",
                    evidence=[f"SPF ip4 mechanism: {ip_or_cidr}"],
                ))

        # Extract include: domains and resolve them
        for m in re.finditer(r"include:(\S+)", spf):
            inc_domain = m.group(1)
            try:
                answers = resolver.resolve(inc_domain, "A")
                for r in answers:
                    ip_addr = str(r)
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="spf_include",
                            confidence="low",
                            hostname=inc_domain,
                            evidence=[f"SPF include:{inc_domain} → {ip_addr}"],
                        ))
            except Exception:
                pass

    # ── Resolve MX records ──
    for mx_host in dns_records.mx:
        try:
            answers = resolver.resolve(mx_host, "A")
            for r in answers:
                ip_addr = str(r)
                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                if not is_cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr,
                        source="mx_record",
                        confidence="low",
                        hostname=mx_host,
                        evidence=[f"MX record {mx_host} → {ip_addr}"],
                    ))
        except Exception:
            pass

    return candidates


def technique_subdomain_dns(
    domain: str,
    extra_subdomains: list[str] = [],
) -> list[OriginCandidate]:
    """
    Technique 4: Subdomain enumeration for unprotected subdomains.
    Some subdomains (direct.*, origin.*, mail.*, etc.) bypass CDN
    and point directly to the origin server.
    """
    candidates = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    # Common subdomains that often bypass CDN
    probe_subs = [
        "direct", "origin", "origin-www", "real", "backend",
        "server", "host", "hosting", "admin", "cpanel",
        "webmail", "mail", "smtp", "ftp", "ssh",
        "dev", "staging", "test", "beta", "old",
        "legacy", "app", "api", "cloud", "vps",
        "vpn", "remote", "ns1", "ns2", "mx",
        "mx1", "mx2", "smtp", "pop", "imap",
        "autodiscover", "autoconfig", "webdisk",
        "whm", "plesk", "cpanel", "portal",
        "git", "svn", "repo", "cdn", "static",
        "assets", "media", "img", "images",
        "video", "files", "upload", "download",
    ] + extra_subdomains

    def _check_sub(sub: str) -> Optional[OriginCandidate]:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            for r in answers:
                ip_addr = str(r)
                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                if not is_cdn_flag:
                    return OriginCandidate(
                        ip=ip_addr,
                        source=f"subdomain:{fqdn}",
                        confidence="medium",
                        hostname=fqdn,
                        evidence=[
                            f"Subdomain {fqdn} resolves to non-CDN IP: {ip_addr}"
                        ],
                    )
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(_check_sub, sub) for sub in probe_subs]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                candidates.append(result)

    return candidates


def technique_http_headers_leak(
    domain: str,
    dns_records: DNSRecords,
) -> list[OriginCandidate]:
    """
    Technique 5: HTTP response header analysis for origin leaks.
    Some CDN configs leak origin IP in:
    - X-Origin-IP
    - X-Backend-Server
    - X-Real-IP
    - X-Forwarded-Server
    - Location header (redirects to IP)
    - Server header (may contain IP)
    - Link header
    """
    candidates = []
    leak_headers = [
        "x-origin-ip", "x-origin", "x-backend-server",
        "x-real-ip", "x-forwarded-server", "x-upstream",
        "x-server-ip", "x-host", "x-backend",
        "x-origin-host", "x-forwarded-host",
        "x-cluster-client-ip", "true-client-ip",
        "x-real-server", "x-proxy-host",
        "cf-connecting-ip",                            # may leak in error pages
    ]

    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    for scheme in ("https", "http"):
        try:
            url  = f"{scheme}://{domain}"
            resp = requests.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=False,        # don't follow — capture Location
                headers={"User-Agent": "CDNOriginDetector/1.0"},
            )
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for lh in leak_headers:
                if lh in headers_lower:
                    val = headers_lower[lh]
                    m   = ip_pattern.search(val)
                    if m:
                        ip_addr = m.group(0)
                        is_cdn_flag, _ = is_cdn_ip(ip_addr)
                        if not is_cdn_flag:
                            candidates.append(OriginCandidate(
                                ip=ip_addr,
                                source=f"header_leak:{lh}",
                                confidence="high",
                                evidence=[
                                    f"Origin IP leaked in response header "
                                    f"'{lh}: {val}'"
                                ],
                            ))

            # Location header IP leak
            if "location" in headers_lower:
                loc = headers_lower["location"]
                m   = ip_pattern.search(loc)
                if m:
                    ip_addr = m.group(0)
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="header_leak:location",
                            confidence="high",
                            evidence=[f"IP in Location redirect: {loc}"],
                        ))

            # Link header
            if "link" in headers_lower:
                for m in ip_pattern.finditer(headers_lower["link"]):
                    ip_addr = m.group(0)
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="header_leak:link",
                            confidence="medium",
                            evidence=[f"IP in Link header: {headers_lower['link']}"],
                        ))

            break   # got a response — don't try http

        except Exception:
            continue

    return candidates


def technique_favicon_hash(
    domain: str,
    baseline_content: Optional[str] = None,
) -> list[OriginCandidate]:
    """
    Technique 6: Favicon hash / content fingerprinting via Shodan/Censys.
    Download favicon from CDN, compute hash, search for same hash on other IPs.
    Falls back to keyword search if no API key.
    """
    candidates = []

    # Try to fetch favicon
    favicon_hash = None
    for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
        try:
            resp = requests.get(
                f"https://{domain}{path}",
                timeout=8,
                verify=False,
                headers={"User-Agent": "CDNOriginDetector/1.0"},
            )
            if resp.status_code == 200 and resp.content:
                import hashlib, base64
                # MurmurHash2 (Shodan style)
                b64   = base64.encodebytes(resp.content).decode("utf-8")
                fhash = hash(b64) & 0xFFFFFFFF   # simplified — real shodan uses mmh3
                favicon_hash = str(fhash)
                break
        except Exception:
            pass

    # (Shodan favicon search would go here with API key)
    # candidates would be populated from Shodan results

    return candidates


def technique_censys_search(
    domain: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
) -> list[OriginCandidate]:
    """
    Technique 7: Censys certificate + host search.
    Search Censys for hosts that have certificates matching the domain.
    These hosts may be the unprotected origin.
    """
    candidates = []

    if not api_id or not api_secret:
        # Try without auth (limited)
        try:
            resp = requests.get(
                f"https://search.censys.io/api/v2/hosts/search",
                params={"q": f"services.tls.certificates.leaf_data.names: {domain}",
                        "per_page": 25},
                timeout=15,
                headers={"User-Agent": "CDNOriginDetector/1.0"},
            )
            if resp.status_code == 401:
                return candidates   # need auth
        except Exception:
            return candidates

    try:
        resp = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={
                "q":        f"services.tls.certificates.leaf_data.names: {domain}",
                "per_page": 25,
            },
            auth=(api_id, api_secret),
            timeout=20,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )

        if resp.status_code == 200:
            data = resp.json()
            for hit in data.get("result", {}).get("hits", []):
                ip_addr = hit.get("ip")
                if ip_addr:
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        asn  = hit.get("autonomous_system", {}).get("asn")
                        org  = hit.get("autonomous_system", {}).get("description")
                        country = hit.get("location", {}).get("country_code")
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="censys:cert_search",
                            confidence="medium",
                            asn=str(asn) if asn else None,
                            org=org,
                            country=country,
                            evidence=[
                                f"Censys found host {ip_addr} with TLS cert "
                                f"matching domain {domain}"
                            ],
                        ))
    except Exception:
        pass

    # Also search by HTTP host header response
    try:
        resp = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={
                "q":        f"services.http.response.headers.Server: * AND "
                            f"services.http.request.headers.Host: {domain}",
                "per_page": 10,
            },
            auth=(api_id, api_secret) if api_id else None,
            timeout=20,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for hit in data.get("result", {}).get("hits", []):
                ip_addr = hit.get("ip")
                if ip_addr:
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="censys:http_search",
                            confidence="medium",
                            evidence=[f"Censys HTTP search matched {ip_addr}"],
                        ))
    except Exception:
        pass

    return candidates


def technique_shodan_search(
    domain: str,
    api_key: Optional[str] = None,
) -> list[OriginCandidate]:
    """
    Technique 8: Shodan host search for SSL cert matches.
    """
    candidates = []
    if not api_key:
        return candidates

    try:
        # SSL cert CN search
        resp = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key":   api_key,
                "query": f"ssl.cert.subject.cn:{domain}",
                "limit": 20,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for match in data.get("matches", []):
                ip_addr = match.get("ip_str")
                if ip_addr:
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        org  = match.get("org")
                        asn  = str(match.get("asn", ""))
                        country = match.get("location", {}).get("country_code")
                        ports   = match.get("port")
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            port=ports,
                            source="shodan:ssl_cn",
                            confidence="medium",
                            asn=asn,
                            org=org,
                            country=country,
                            evidence=[
                                f"Shodan SSL CN match: {domain} → {ip_addr}"
                            ],
                        ))
    except Exception:
        pass

    try:
        # Hostname search
        resp = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key":   api_key,
                "query": f"hostname:{domain}",
                "limit": 20,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for match in data.get("matches", []):
                ip_addr = match.get("ip_str")
                if ip_addr:
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="shodan:hostname",
                            confidence="medium",
                            org=match.get("org"),
                            evidence=[f"Shodan hostname match: {ip_addr}"],
                        ))
    except Exception:
        pass

    return candidates


def technique_crimeflare(domain: str) -> list[OriginCandidate]:
    """
    Technique 9: CrimeFlare / CloudFlare origin lookup.
    Queries public CrimeFlare database for known CF bypasses.
    """
    candidates = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    endpoints = [
        f"http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi?cfS={domain}",
        f"https://crimeflare.herokuapp.com/{domain}",
        f"https://asm.ca.com/en/find-out-whats-behind-cloudflare.php"
         f"?url={domain}",
    ]

    for url in endpoints:
        try:
            resp = requests.get(
                url,
                timeout=10,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Referer":    url,
                },
                verify=False,
            )
            if resp.status_code == 200:
                body = resp.text
                for m in ip_pattern.finditer(body):
                    ip_addr = m.group(0)
                    # Filter out obvious non-IPs
                    if ip_addr.startswith(("0.", "255.", "127.", "192.168.",
                                           "10.", "172.")):
                        continue
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="crimeflare",
                            confidence="medium",
                            evidence=[
                                f"CrimeFlare database match for {domain}: {ip_addr}"
                            ],
                        ))
                if candidates:
                    break
        except Exception:
            continue

    return candidates


def technique_passive_dns(domain: str) -> list[OriginCandidate]:
    """
    Technique 10: Passive DNS via public APIs.
    HackerTarget, RiskIQ Community, CIRCL pDNS.
    """
    candidates = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    # HackerTarget IP → hostname lookup (reverse)
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if re.match(r"^[a-zA-Z0-9]", line) and "." in line:
                    # This is a hostname on same IP
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.lifetime = 3.0
                        answers  = resolver.resolve(line, "A")
                        for r in answers:
                            ip_addr = str(r)
                            is_cdn_flag, _ = is_cdn_ip(ip_addr)
                            if not is_cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=ip_addr,
                                    source="passive_dns:hackertarget",
                                    confidence="low",
                                    hostname=line,
                                    evidence=[
                                        f"Passive DNS: {line} shares IP {ip_addr}"
                                    ],
                                ))
                    except Exception:
                        pass
    except Exception:
        pass

    # CIRCL pDNS
    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            timeout=10,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    rtype  = parts[2].strip()
                    rvalue = parts[3].strip()
                    if rtype == "A":
                        m = ip_pattern.match(rvalue)
                        if m:
                            ip_addr = m.group(0)
                            is_cdn_flag, _ = is_cdn_ip(ip_addr)
                            if not is_cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=ip_addr,
                                    source="passive_dns:circl",
                                    confidence="medium",
                                    evidence=[
                                        f"CIRCL pDNS historical A record: {ip_addr}"
                                    ],
                                ))
    except Exception:
        pass

    return candidates


def technique_zone_transfer(domain: str) -> list[OriginCandidate]:
    """
    Technique 11: DNS Zone Transfer (AXFR).
    Attempt zone transfer from all nameservers.
    May reveal internal IPs and subdomains.
    """
    candidates = []
    resolver   = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    try:
        ns_answers = resolver.resolve(domain, "NS")
        nameservers = [str(r).rstrip(".") for r in ns_answers]
    except Exception:
        return candidates

    for ns in nameservers:
        try:
            import dns.zone
            import dns.query

            zone = dns.zone.from_xfr(
                dns.query.xfr(ns, domain, timeout=10)
            )
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        val = str(rdata)
                        if ip_pattern.match(val):
                            ip_addr = val
                            is_cdn_flag, _ = is_cdn_ip(ip_addr)
                            if not is_cdn_flag:
                                candidates.append(OriginCandidate(
                                    ip=ip_addr,
                                    source="zone_transfer",
                                    confidence="high",
                                    hostname=str(name),
                                    evidence=[
                                        f"Zone transfer from {ns}: "
                                        f"{name} → {ip_addr}"
                                    ],
                                ))
        except Exception:
            pass

    return candidates


def technique_http_old_endpoints(
    domain: str,
    dns_records: DNSRecords,
    baseline_content: Optional[str],
) -> list[OriginCandidate]:
    """
    Technique 12: Direct HTTP requests to discovered IPs on alt ports.
    Tries ports 80, 443, 8080, 8443 on all non-CDN IPs found so far.
    """
    candidates = []
    alt_ports  = [80, 443, 8080, 8443, 8888, 8000, 3000, 4443]

    non_cdn_ips = [
        ip for ip in dns_records.a
        if not is_cdn_ip(ip)[0]
    ]
    # Include IPs from A records as initial seed
    non_cdn_ips = list(set(non_cdn_ips))

    for ip in non_cdn_ips[:10]:
        for port in alt_ports:
            scheme = "https" if port in (443, 8443, 4443) else "http"
            status, title, server, body = http_probe_direct(
                ip, domain, port, scheme, timeout=5
            )
            if status and status < 500:
                sim = content_similarity(baseline_content or "", body or "")
                conf = "high" if sim > 0.6 else ("medium" if sim > 0.3 else "low")
                candidates.append(OriginCandidate(
                    ip=ip,
                    port=port,
                    source=f"direct_probe:{port}",
                    confidence=conf,
                    http_status=status,
                    http_title=title,
                    http_server=server,
                    banner_match=sim > 0.5,
                    evidence=[
                        f"Direct HTTP probe {scheme}://{ip}:{port} "
                        f"returned {status}, "
                        f"content similarity: {sim:.0%}"
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
    Confirm candidates by:
    1. Sending HTTP request with Host: domain directly to the IP
    2. Comparing response content to CDN-served baseline
    3. Checking SSL cert CN
    4. PTR lookup
    """
    dedupe: dict[str, OriginCandidate] = {}
    for c in candidates:
        key = f"{c.ip}:{c.port or 443}"
        if key not in dedupe:
            dedupe[key] = c
        else:
            # Merge evidence
            dedupe[key].evidence.extend(c.evidence)
            # Keep highest confidence
            rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}
            if rank.get(c.confidence, 0) > rank.get(dedupe[key].confidence, 0):
                dedupe[key].confidence = c.confidence

    unique = list(dedupe.values())

    def _validate(candidate: OriginCandidate) -> OriginCandidate:
        ip   = candidate.ip
        port = candidate.port or 443

        # PTR lookup
        candidate.hostname = candidate.hostname or ptr_lookup(ip)

        # Try HTTPS first, then HTTP
        for scheme, p in [("https", port), ("http", 80 if port == 443 else port)]:
            status, title, server, body = http_probe_direct(
                ip, domain, p, scheme, timeout=8
            )
            if status is not None:
                candidate.http_status  = status
                candidate.http_title   = title
                candidate.http_server  = server

                # Compare content similarity to baseline
                if baseline_content and body:
                    sim = content_similarity(baseline_content, body)
                    candidate.banner_match = sim > 0.4
                    if sim > 0.7:
                        candidate.responds_to_domain = True
                        candidate.confidence = "confirmed"
                        candidate.evidence.append(
                            f"Direct probe {scheme}://{ip}:{p} → "
                            f"HTTP {status}, content match {sim:.0%}"
                        )
                    elif sim > 0.4:
                        candidate.responds_to_domain = True
                        candidate.evidence.append(
                            f"Partial content match {sim:.0%} on {scheme}://{ip}:{p}"
                        )
                elif status in (200, 301, 302, 403):
                    candidate.responds_to_domain = True
                    candidate.confidence = max(
                        candidate.confidence, "medium",
                        key=lambda x: {"confirmed": 4, "high": 3,
                                       "medium": 2, "low": 1}.get(x, 0)
                    )
                    candidate.evidence.append(
                        f"Direct probe returned HTTP {status}"
                    )
                break

        # Validate SSL cert
        ssl_info = get_ssl_cert_info(ip, domain)
        if ssl_info:
            if domain in (ssl_info.common_name or ""):
                candidate.confidence = "confirmed"
                candidate.evidence.append(
                    f"SSL cert CN matches domain: {ssl_info.common_name}"
                )
            if domain in ssl_info.san_domains:
                candidate.confidence = "confirmed"
                candidate.evidence.append(
                    f"SSL cert SAN matches domain"
                )

        return candidate

    validated = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_validate, c) for c in unique]
        for f in concurrent.futures.as_completed(futures):
            try:
                validated.append(f.result())
            except Exception:
                pass

    return validated


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
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
# 8. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_cloudflair(stdout: str, stderr: str, domain: str) -> list[OriginCandidate]:
    """
    Parse cloudflair output.
    cloudflair outputs IPs / results to stdout.
    """
    candidates = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    raw = stdout + "\n" + stderr

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # JSON output
        try:
            data = json.loads(line)
            ip_addr = (
                data.get("ip")
                or data.get("origin_ip")
                or data.get("address")
            )
            if ip_addr:
                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                if not is_cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr,
                        source="cloudflair",
                        confidence="medium",
                        evidence=[f"cloudflair: {line}"],
                    ))
            continue
        except json.JSONDecodeError:
            pass

        # Plain text: "Found origin IP: 1.2.3.4" or similar
        for m in ip_pattern.finditer(line):
            ip_addr = m.group(0)
            if ip_addr.startswith(("0.", "127.", "255.")):
                continue
            is_cdn_flag, _ = is_cdn_ip(ip_addr)
            if not is_cdn_flag:
                candidates.append(OriginCandidate(
                    ip=ip_addr,
                    source="cloudflair",
                    confidence="medium",
                    evidence=[f"cloudflair output: {line}"],
                ))

    return candidates


def parse_censys_cli(stdout: str, domain: str) -> list[OriginCandidate]:
    """
    Parse censys CLI output (censys search --index-type hosts).
    """
    candidates = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            ip_addr = data.get("ip")
            if ip_addr:
                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                if not is_cdn_flag:
                    asn  = data.get("autonomous_system", {}).get("asn")
                    org  = data.get("autonomous_system", {}).get("name")
                    candidates.append(OriginCandidate(
                        ip=ip_addr,
                        source="censys_cli",
                        confidence="medium",
                        asn=str(asn) if asn else None,
                        org=org,
                        evidence=[f"Censys CLI result: {ip_addr}"],
                    ))
        except json.JSONDecodeError:
            ip_m = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", line)
            if ip_m:
                ip_addr = ip_m.group(0)
                is_cdn_flag, _ = is_cdn_ip(ip_addr)
                if not is_cdn_flag:
                    candidates.append(OriginCandidate(
                        ip=ip_addr,
                        source="censys_cli",
                        confidence="low",
                        evidence=[f"Censys CLI (text): {line}"],
                    ))

    return candidates


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
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
      ┌────────────────────────────────────────────────────────────────────┐
      │  CDN DETECTION        Cloudflare, Akamai, Fastly, CloudFront, ... │
      │  DNS HISTORY          Historical A records via HackerTarget/CIRCL  │
      │  SSL CERT ANALYSIS    SAN domains, crt.sh cert search             │
      │  SPF / MX MINING      Origin IPs from email records               │
      │  SUBDOMAIN PROBE      Unprotected subdomains bypassing CDN        │
      │  HEADER LEAK          X-Origin-IP, X-Backend-Server, Location     │
      │  PASSIVE DNS          pDNS databases for old records              │
      │  ZONE TRANSFER        AXFR attempt on all nameservers             │
      │  CENSYS SEARCH        TLS cert + host search via Censys API       │
      │  SHODAN SEARCH        SSL CN + hostname search via Shodan API     │
      │  CRIMEFLARE           Public CF origin database lookup            │
      │  DIRECT PROBE         HTTP to IP with Host header + content match │
      │  VALIDATION           SSL cert match + content similarity score   │
      └────────────────────────────────────────────────────────────────────┘

    Args:
        tool:     "cloudflair" | "crimeflare" | "censys" | "manual"
        target:   Domain or URL (e.g. "example.com")
        args:     Raw tool arguments — agent decides
        api_keys: Optional API keys:
                  {
                    "censys_id":     "...",
                    "censys_secret": "...",
                    "shodan":        "..."
                  }

    Tool args reference:
      cloudflair:
        Basic:  ["--domain", "example.com"]
        Threads:["-t", "20"]
        Output: ["--json"] → auto-injected

      crimeflare:
        Basic:  [] (domain passed automatically)

      censys:
        Query:  ["search", "--index-type", "hosts",
                 "services.tls.certificates.leaf_data.names: example.com"]
        Format: ["--format", "json"] → auto-injected

      manual:
        (no args — all techniques run automatically)

    Returns:
        Structured JSON: cdn_info → dns_records → ssl_info →
                         origin_candidates → confirmed_origins
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = CDNOriginRequest(
            tool=tool, target=target, args=args, api_keys=api_keys
        )
    except Exception as e:
        return CDNOriginResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    domain      = extract_domain(target)
    all_candidates: list[OriginCandidate] = []
    techniques_used: list[str] = []
    command_str = ""
    raw_output  = ""
    error_msg: Optional[str] = None

    # ══════════════════════════════
    # STEP 1: DNS Records (always)
    # ══════════════════════════════
    dns_records = resolve_all_records(domain)
    techniques_used.append("dns_resolution")

    # ══════════════════════════════
    # STEP 2: CDN Detection (always)
    # ══════════════════════════════
    http_headers_for_cdn: dict[str, str] = {}
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=10,
            verify=False,
            headers={"User-Agent": "CDNOriginDetector/1.0"},
            allow_redirects=True,
        )
        http_headers_for_cdn = dict(resp.headers)
    except Exception:
        pass

    cdn_info = detect_cdn(domain, dns_records, http_headers_for_cdn)
    techniques_used.append("cdn_fingerprint")

    # ══════════════════════════════
    # STEP 3: Baseline content
    # ══════════════════════════════
    baseline = fetch_page_content(f"https://{domain}")

    # ══════════════════════════════
    # TOOL: MANUAL  (all techniques)
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_cdn_origin_detect({domain})"

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:

            fut_history  = ex.submit(technique_dns_history, domain)
            fut_ssl      = ex.submit(technique_ssl_san, domain, dns_records)
            fut_spf_mx   = ex.submit(technique_spf_mx_records, domain, dns_records)
            fut_subs     = ex.submit(technique_subdomain_dns, domain)
            fut_headers  = ex.submit(technique_http_headers_leak, domain, dns_records)
            fut_passive  = ex.submit(technique_passive_dns, domain)
            fut_ztransfer= ex.submit(technique_zone_transfer, domain)
            fut_crime    = ex.submit(technique_crimeflare, domain)

            cands_history = fut_history.result()
            techniques_used.append("dns_history")
            all_candidates.extend(cands_history)

            cands_ssl, ssl_info = fut_ssl.result()
            techniques_used.append("ssl_san_analysis")
            all_candidates.extend(cands_ssl)

            cands_spf = fut_spf_mx.result()
            techniques_used.append("spf_mx_mining")
            all_candidates.extend(cands_spf)

            cands_subs = fut_subs.result()
            techniques_used.append("subdomain_probe")
            all_candidates.extend(cands_subs)

            cands_headers = fut_headers.result()
            techniques_used.append("header_leak")
            all_candidates.extend(cands_headers)

            cands_passive = fut_passive.result()
            techniques_used.append("passive_dns")
            all_candidates.extend(cands_passive)

            cands_zone = fut_ztransfer.result()
            techniques_used.append("zone_transfer")
            all_candidates.extend(cands_zone)

            cands_crime = fut_crime.result()
            techniques_used.append("crimeflare")
            all_candidates.extend(cands_crime)

        # Censys + Shodan (API-dependent)
        censys_id     = api_keys.get("censys_id")
        censys_secret = api_keys.get("censys_secret")
        shodan_key    = api_keys.get("shodan")

        cands_censys = technique_censys_search(domain, censys_id, censys_secret)
        if cands_censys:
            techniques_used.append("censys_search")
            all_candidates.extend(cands_censys)

        cands_shodan = technique_shodan_search(domain, shodan_key)
        if cands_shodan:
            techniques_used.append("shodan_search")
            all_candidates.extend(cands_shodan)

        # Direct probe on alt ports
        cands_direct = technique_http_old_endpoints(domain, dns_records, baseline)
        if cands_direct:
            techniques_used.append("direct_port_probe")
            all_candidates.extend(cands_direct)

        ssl_info = ssl_info if "ssl_info" in dir() else None

    # ══════════════════════════════
    # TOOL: CLOUDFLAIR
    # ══════════════════════════════
    elif tool == "cloudflair":
        cmd = ["cloudflair", domain]
        if "--json" not in req.args:
            cmd.append("--json")
        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output  = (stdout or stderr)[:5000]

        cands = parse_cloudflair(stdout, stderr, domain)
        all_candidates.extend(cands)
        techniques_used.append("cloudflair_tool")

        if rc != 0 and not cands:
            error_msg = (stderr or stdout)[:400]

        # Supplement with our own techniques
        cands_headers = technique_http_headers_leak(domain, dns_records)
        all_candidates.extend(cands_headers)
        techniques_used.append("header_leak")

        cands_crime = technique_crimeflare(domain)
        all_candidates.extend(cands_crime)
        techniques_used.append("crimeflare")

        ssl_info = None
        cands_ssl, ssl_info = technique_ssl_san(domain, dns_records)
        all_candidates.extend(cands_ssl)
        techniques_used.append("ssl_san_analysis")

    # ══════════════════════════════
    # TOOL: CRIMEFLARE
    # ══════════════════════════════
    elif tool == "crimeflare":
        command_str = f"crimeflare_lookup({domain})"

        # Try CLI tool
        cmd = ["crimeflare", domain] + list(req.args)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        # Parse CLI output
        ip_pat = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
        for line in (stdout or stderr).splitlines():
            for m in ip_pat.finditer(line):
                ip_addr = m.group(0)
                if not ip_addr.startswith(("0.", "127.", "255.")):
                    is_cdn_flag, _ = is_cdn_ip(ip_addr)
                    if not is_cdn_flag:
                        all_candidates.append(OriginCandidate(
                            ip=ip_addr,
                            source="crimeflare_cli",
                            confidence="medium",
                            evidence=[f"crimeflare CLI: {line}"],
                        ))

        # Also run HTTP technique
        cands_http = technique_crimeflare(domain)
        all_candidates.extend(cands_http)
        techniques_used.append("crimeflare")

        # Supplement
        cands_headers = technique_http_headers_leak(domain, dns_records)
        all_candidates.extend(cands_headers)
        techniques_used.append("header_leak")

        cands_passive = technique_passive_dns(domain)
        all_candidates.extend(cands_passive)
        techniques_used.append("passive_dns")

        ssl_info = None
        cands_ssl, ssl_info = technique_ssl_san(domain, dns_records)
        all_candidates.extend(cands_ssl)
        techniques_used.append("ssl_san_analysis")

    # ══════════════════════════════
    # TOOL: CENSYS
    # ══════════════════════════════
    elif tool == "censys":
        censys_id     = api_keys.get("censys_id")
        censys_secret = api_keys.get("censys_secret")

        cmd = [
            "censys", "search",
            "--index-type", "hosts",
            f"services.tls.certificates.leaf_data.names: {domain}",
            "--format", "json",
        ]
        if censys_id:
            cmd.extend(["--api-id", censys_id])
        if censys_secret:
            cmd.extend(["--api-secret", censys_secret])
        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        cands = parse_censys_cli(stdout, domain)
        all_candidates.extend(cands)
        techniques_used.append("censys_cli")

        # Also run API search
        cands_api = technique_censys_search(domain, censys_id, censys_secret)
        all_candidates.extend(cands_api)
        techniques_used.append("censys_api")

        # Supplement
        cands_ssl, ssl_info = technique_ssl_san(domain, dns_records)
        all_candidates.extend(cands_ssl)
        techniques_used.append("ssl_san_analysis")

        cands_passive = technique_passive_dns(domain)
        all_candidates.extend(cands_passive)
        techniques_used.append("passive_dns")

        if rc != 0 and not cands:
            error_msg = (stderr or stdout)[:400]

    else:
        ssl_info = None

    # ══════════════════════════════
    # STEP 4: Validate all candidates
    # ══════════════════════════════
    validated = validate_origin_candidates(
        all_candidates, domain, baseline, threads=20
    )
    techniques_used.append("origin_validation")

    confirmed = [
        c for c in validated
        if c.confidence in ("confirmed", "high")
        or c.responds_to_domain
    ]

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    return CDNOriginResult(
        success=len(validated) > 0,
        tool=tool,
        target=target,
        command=command_str,
        domain=domain,
        cdn_info=cdn_info,
        dns_records=dns_records,
        ssl_info=ssl_info if "ssl_info" in dir() and ssl_info else None,
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
# 10. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

CDN_ORIGIN_TOOL_DEFINITION = {
    "name": "cdn_origin_detect",
    "description": (
        "Bypass CDN (Cloudflare, Akamai, Fastly, CloudFront, etc.) to discover "
        "the real origin server IP. Uses 12 techniques: historical DNS, "
        "SSL certificate SAN analysis (crt.sh), SPF/MX record mining, "
        "subdomain enumeration for unprotected hosts, HTTP header leak detection, "
        "passive DNS databases, DNS zone transfer, Censys cert search, "
        "Shodan SSL/hostname search, CrimeFlare database, direct IP HTTP probing, "
        "and content similarity validation. "
        "Supports cloudflair, crimeflare, censys CLI, and manual (all techniques)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["cloudflair", "crimeflare", "censys", "manual"],
                "description": (
                    "cloudflair = automated Cloudflare bypass tool | "
                    "crimeflare = CrimeFlare CF origin database | "
                    "censys     = Censys.io certificate + host search | "
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
                    "Raw tool arguments. Examples:\n"
                    "cloudflair: ['-t', '20']\n"
                    "censys:     ['--per-page', '50']\n"
                    "manual:     [] (no args needed)"
                ),
            },
            "api_keys": {
                "type": "object",
                "description": (
                    "Optional API keys for enriched search:\n"
                    "{\n"
                    "  'censys_id':     'your-censys-api-id',\n"
                    "  'censys_secret': 'your-censys-secret',\n"
                    "  'shodan':        'your-shodan-api-key'\n"
                    "}"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 11. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # ─────────────────────────────
    # 1. Manual — all techniques
    # ─────────────────────────────
    r = cdn_origin_detect(
        tool="manual",
        target="example.com",
    )
    print("=== MANUAL ALL TECHNIQUES ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Manual + API keys
    # ─────────────────────────────
    r = cdn_origin_detect(
        tool="manual",
        target="example.com",
        api_keys={
            "censys_id":     "your-censys-id",
            "censys_secret": "your-censys-secret",
            "shodan":        "your-shodan-key",
        },
    )
    print("=== MANUAL WITH API KEYS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Cloudflair
    # ─────────────────────────────
    r = cdn_origin_detect(
        tool="cloudflair",
        target="example.com",
        args=["-t", "20"],
    )
    print("=== CLOUDFLAIR ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Crimeflare
    # ─────────────────────────────
    r = cdn_origin_detect(
        tool="crimeflare",
        target="example.com",
    )
    print("=== CRIMEFLARE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Censys with API key
    # ─────────────────────────────
    r = cdn_origin_detect(
        tool="censys",
        target="example.com",
        api_keys={
            "censys_id":     "your-id",
            "censys_secret": "your-secret",
        },
    )
    print("=== CENSYS ===")
    print(json.dumps(r, indent=2))