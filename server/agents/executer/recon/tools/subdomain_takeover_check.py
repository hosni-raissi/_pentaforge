import subprocess
import json
import re
import time
import dns.resolver
import dns.exception
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SubdomainTakeoverRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    subdomains: list[str] = []          # optional pre-supplied subdomain list

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"subjack", "nuclei", "dnsx", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_pattern     = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"

        if not (re.match(domain_pattern, v) or re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars   = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags     = ["-o", "--output"]            # prevent silent file writes
        dangerous_scripts = ["rce", "exploit", "dos"]    # nuclei template categories

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {flag}")
            if arg.startswith("-t") or arg.startswith("--tags"):
                value = arg.split("=", 1)[-1] if "=" in arg else ""
                for ds in dangerous_scripts:
                    if ds in value:
                        raise ValueError(f"Dangerous template tag blocked: {ds}")
        return v


# ── Fingerprint for a single service ──
class ServiceFingerprint(BaseModel):
    name: str                           # e.g. "AWS S3", "GitHub Pages"
    cname_pattern: Optional[str] = None # matching CNAME
    response_pattern: Optional[str] = None
    status_code: Optional[int] = None
    confidence: str = "medium"          # low / medium / high


# ── Result for a single subdomain ──
class SubdomainResult(BaseModel):
    subdomain: str
    cname_chain: list[str] = []         # full CNAME resolution chain
    dangling: bool = False              # CNAME points to unclaimed resource
    a_records: list[str] = []          # resolved A records (if any)
    nxdomain: bool = False             # final CNAME target → NXDOMAIN
    http_status: Optional[int] = None
    http_body_snippet: Optional[str] = None
    vulnerable: bool = False           # confirmed takeover possible
    service: Optional[str] = None      # which cloud service is affected
    fingerprint: Optional[ServiceFingerprint] = None
    tool_finding: Optional[str] = None # raw output from subjack / nuclei
    evidence: list[str] = []           # why we flagged this
    severity: str = "info"             # info / low / medium / high / critical


# ── Final aggregated result ──
class TakeoverScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_checked: int = 0
    total_dangling: int = 0
    total_vulnerable: int = 0
    results: list[SubdomainResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. CLOUD-SERVICE FINGERPRINTS
#    Source: EdOverflow/can-i-take-over-xyz
# ══════════════════════════════════════════════════════════════

FINGERPRINTS: list[ServiceFingerprint] = [
    # ── AWS ──
    ServiceFingerprint(
        name="AWS S3",
        cname_pattern=r"\.s3[.\-]amazonaws\.com",
        response_pattern=r"NoSuchBucket|The specified bucket does not exist",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="AWS CloudFront",
        cname_pattern=r"\.cloudfront\.net",
        response_pattern=r"Bad Request|ERROR: The request could not be satisfied",
        status_code=403,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="AWS Elastic Beanstalk",
        cname_pattern=r"\.elasticbeanstalk\.com",
        response_pattern=r"NXDOMAIN|NoSuchDomain",
        confidence="high",
    ),
    # ── GitHub ──
    ServiceFingerprint(
        name="GitHub Pages",
        cname_pattern=r"\.github\.io",
        response_pattern=r"There isn't a GitHub Pages site here|404",
        status_code=404,
        confidence="high",
    ),
    # ── Heroku ──
    ServiceFingerprint(
        name="Heroku",
        cname_pattern=r"\.herokudns\.com|\.herokussl\.com|\.herokuapp\.com",
        response_pattern=r"No such app|herokucdn\.com/error-pages/no-such-app",
        status_code=404,
        confidence="high",
    ),
    # ── Netlify ──
    ServiceFingerprint(
        name="Netlify",
        cname_pattern=r"\.netlify\.app|\.netlify\.com",
        response_pattern=r"Not Found - Request ID",
        status_code=404,
        confidence="high",
    ),
    # ── Vercel ──
    ServiceFingerprint(
        name="Vercel",
        cname_pattern=r"\.vercel\.app|\.now\.sh",
        response_pattern=r"The deployment could not be found|404",
        status_code=404,
        confidence="high",
    ),
    # ── Azure ──
    ServiceFingerprint(
        name="Azure App Service",
        cname_pattern=r"\.azurewebsites\.net",
        response_pattern=r"404 Web Site not found|does not exist",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Azure Blob Storage",
        cname_pattern=r"\.blob\.core\.windows\.net",
        response_pattern=r"BlobNotFound|The specified container does not exist",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Azure CDN",
        cname_pattern=r"\.azureedge\.net",
        response_pattern=r"CDN endpoint is not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Azure Traffic Manager",
        cname_pattern=r"\.trafficmanager\.net",
        response_pattern=r"NXDOMAIN",
        confidence="high",
    ),
    # ── GCP ──
    ServiceFingerprint(
        name="Google Cloud Storage",
        cname_pattern=r"\.storage\.googleapis\.com",
        response_pattern=r"NoSuchBucket|The specified bucket does not exist",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Firebase",
        cname_pattern=r"\.firebaseapp\.com|\.web\.app",
        response_pattern=r"Site Not Found",
        status_code=404,
        confidence="high",
    ),
    # ── Shopify ──
    ServiceFingerprint(
        name="Shopify",
        cname_pattern=r"\.myshopify\.com",
        response_pattern=r"Sorry, this shop is currently unavailable|only accessible to",
        status_code=404,
        confidence="high",
    ),
    # ── Zendesk ──
    ServiceFingerprint(
        name="Zendesk",
        cname_pattern=r"\.zendesk\.com",
        response_pattern=r"Help Center Closed|this help center no longer exists",
        status_code=404,
        confidence="high",
    ),
    # ── Fastly ──
    ServiceFingerprint(
        name="Fastly",
        cname_pattern=r"\.fastly\.net|\.fastlylb\.net",
        response_pattern=r"Fastly error: unknown domain|Please check that this domain",
        status_code=500,
        confidence="high",
    ),
    # ── Pantheon ──
    ServiceFingerprint(
        name="Pantheon",
        cname_pattern=r"\.pantheonsite\.io",
        response_pattern=r"404 error unknown site",
        status_code=404,
        confidence="high",
    ),
    # ── Ghost ──
    ServiceFingerprint(
        name="Ghost",
        cname_pattern=r"\.ghost\.io",
        response_pattern=r"The thing you were looking for is no longer here",
        status_code=404,
        confidence="high",
    ),
    # ── Tumblr ──
    ServiceFingerprint(
        name="Tumblr",
        cname_pattern=r"\.tumblr\.com",
        response_pattern=r"There's nothing here|Whatever you were looking for doesn't currently exist",
        status_code=404,
        confidence="medium",
    ),
    # ── HubSpot ──
    ServiceFingerprint(
        name="HubSpot",
        cname_pattern=r"\.hubspot\.com|\.hs-sites\.com|\.hubspotpagebuilder\.com",
        response_pattern=r"Domain not configured|does not exist in our system",
        status_code=404,
        confidence="high",
    ),
    # ── Cargo ──
    ServiceFingerprint(
        name="Cargo",
        cname_pattern=r"\.cargocollective\.com",
        response_pattern=r"404 Not Found",
        status_code=404,
        confidence="medium",
    ),
    # ── Launchrock ──
    ServiceFingerprint(
        name="Launchrock",
        cname_pattern=r"\.launchrock\.com",
        response_pattern=r"It looks like you may have taken a wrong turn",
        status_code=404,
        confidence="medium",
    ),
    # ── WP Engine ──
    ServiceFingerprint(
        name="WP Engine",
        cname_pattern=r"\.wpengine\.com",
        response_pattern=r"The site you were looking for couldn't be found",
        status_code=404,
        confidence="medium",
    ),
    # ── Kinsta ──
    ServiceFingerprint(
        name="Kinsta",
        cname_pattern=r"\.kinsta\.cloud|\.kinstacdn\.com",
        response_pattern=r"No Site For Domain",
        status_code=404,
        confidence="medium",
    ),
    # ── Surge.sh ──
    ServiceFingerprint(
        name="Surge",
        cname_pattern=r"\.surge\.sh",
        response_pattern=r"project not found",
        status_code=404,
        confidence="high",
    ),
    # ── Readme.io ──
    ServiceFingerprint(
        name="Readme.io",
        cname_pattern=r"\.readme\.io",
        response_pattern=r"Project doesnt exist|page not found",
        status_code=404,
        confidence="medium",
    ),
    # ── Wix ──
    ServiceFingerprint(
        name="Wix",
        cname_pattern=r"\.wixdns\.net|\.wix\.com",
        response_pattern=r"Error ConnectYourDomain",
        status_code=404,
        confidence="medium",
    ),
    # ── Digital Ocean ──
    ServiceFingerprint(
        name="DigitalOcean Spaces",
        cname_pattern=r"\.digitaloceanspaces\.com",
        response_pattern=r"NoSuchBucket",
        status_code=404,
        confidence="high",
    ),
    # ── Fly.io ──
    ServiceFingerprint(
        name="Fly.io",
        cname_pattern=r"\.fly\.dev",
        response_pattern=r"404 Not Found|not found",
        status_code=404,
        confidence="medium",
    ),
    # ── Render ──
    ServiceFingerprint(
        name="Render",
        cname_pattern=r"\.onrender\.com",
        response_pattern=r"does not exist|not found",
        status_code=404,
        confidence="medium",
    ),
    # ── Railway ──
    ServiceFingerprint(
        name="Railway",
        cname_pattern=r"\.railway\.app",
        response_pattern=r"not found|no deployment",
        status_code=404,
        confidence="medium",
    ),
    # ── Bitbucket ──
    ServiceFingerprint(
        name="Bitbucket Pages",
        cname_pattern=r"\.bitbucket\.io",
        response_pattern=r"Repository not found",
        status_code=404,
        confidence="high",
    ),
    # ── Webflow ──
    ServiceFingerprint(
        name="Webflow",
        cname_pattern=r"\.webflow\.io",
        response_pattern=r"The page you are looking for doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    # ── Squarespace ──
    ServiceFingerprint(
        name="Squarespace",
        cname_pattern=r"\.squarespace\.com",
        response_pattern=r"No Such Account|isn't live yet",
        status_code=404,
        confidence="medium",
    ),
    # ── Intercom ──
    ServiceFingerprint(
        name="Intercom",
        cname_pattern=r"\.intercom\.help|\.custom\.intercom\.help",
        response_pattern=r"This page doesn't exist|Uh oh. That page doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    # ── Unbounce ──
    ServiceFingerprint(
        name="Unbounce",
        cname_pattern=r"\.unbounce\.com",
        response_pattern=r"The requested URL was not found|page not found",
        status_code=404,
        confidence="medium",
    ),
]


# ══════════════════════════════════════════════════════════════
# 3. DNS HELPERS
# ══════════════════════════════════════════════════════════════

def resolve_cname_chain(subdomain: str, timeout: float = 5.0) -> list[str]:
    """
    Follow full CNAME chain:
        sub.example.com → alias.github.io → ... → NXDOMAIN / A record
    Returns ordered list of CNAME targets.
    """
    chain = []
    current = subdomain
    seen = set()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    for _ in range(20):                     # max 20 hops to avoid loops
        if current in seen:
            break
        seen.add(current)
        try:
            answers = resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            break
        except Exception:
            break

    return chain


def resolve_a_records(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve A records for a hostname."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def is_nxdomain(hostname: str, timeout: float = 5.0) -> bool:
    """Check if a hostname resolves to NXDOMAIN."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        resolver.resolve(hostname, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════
# 4. HTTP PROBE
# ══════════════════════════════════════════════════════════════

def http_probe(subdomain: str, timeout: int = 10) -> tuple[Optional[int], Optional[str]]:
    """
    Probe subdomain over HTTP/HTTPS.
    Returns (status_code, body_snippet).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (subdomain-takeover-scanner)"},
                verify=False,   # some targets have broken TLS — still want the body
            )
            snippet = resp.text[:800].strip()
            return resp.status_code, snippet
        except requests.exceptions.SSLError:
            # try http fallback on ssl error
            continue
        except requests.exceptions.ConnectionError:
            return None, None
        except requests.exceptions.Timeout:
            return None, None
        except Exception:
            return None, None
    return None, None


# ══════════════════════════════════════════════════════════════
# 5. FINGERPRINT MATCHER
# ══════════════════════════════════════════════════════════════

def match_fingerprint(
    cname_chain: list[str],
    http_status: Optional[int],
    body_snippet: Optional[str],
) -> Optional[ServiceFingerprint]:
    """
    Try to match one of our fingerprints against:
      - CNAME chain (pattern match)
      - HTTP status code
      - HTTP response body
    Returns first matching fingerprint, or None.
    """
    cname_str = " ".join(cname_chain)

    for fp in FINGERPRINTS:
        cname_hit   = False
        status_hit  = False
        body_hit    = False

        # ── CNAME match ──
        if fp.cname_pattern and re.search(fp.cname_pattern, cname_str, re.IGNORECASE):
            cname_hit = True

        # ── Status code match ──
        if fp.status_code and http_status == fp.status_code:
            status_hit = True

        # ── Body match ──
        if fp.response_pattern and body_snippet:
            if re.search(fp.response_pattern, body_snippet, re.IGNORECASE):
                body_hit = True

        # Decision matrix:
        #   high confidence → CNAME + (status OR body)
        #   medium          → CNAME alone is enough
        #   any             → body match alone is suspicious
        if cname_hit and (status_hit or body_hit):
            return fp
        if cname_hit and fp.confidence == "medium":
            return fp
        if body_hit and not cname_hit:
            # body-only → lower confidence, still flag
            fp_copy = fp.model_copy()
            fp_copy.confidence = "low"
            return fp_copy

    return None


# ══════════════════════════════════════════════════════════════
# 6. MANUAL CHECK (core logic — no external tool)
# ══════════════════════════════════════════════════════════════

def check_single_subdomain(subdomain: str, http_timeout: int = 10) -> SubdomainResult:
    """
    Full takeover check for one subdomain:
      1. Resolve CNAME chain
      2. Check if final target is NXDOMAIN (dangling)
      3. HTTP probe the subdomain
      4. Match fingerprints
      5. Score severity
    """
    result = SubdomainResult(subdomain=subdomain)

    # ── 1. CNAME chain ──
    result.cname_chain = resolve_cname_chain(subdomain)

    # ── 2. A records + NXDOMAIN ──
    final_target = result.cname_chain[-1] if result.cname_chain else subdomain
    result.a_records = resolve_a_records(final_target)
    result.nxdomain  = is_nxdomain(final_target)

    # Dangling = has CNAME chain AND final target is unresolvable
    if result.cname_chain and (result.nxdomain or not result.a_records):
        result.dangling = True
        result.evidence.append(
            f"CNAME chain ends at '{final_target}' which has no A record"
        )

    # ── 3. HTTP probe ──
    result.http_status, result.http_body_snippet = http_probe(subdomain, timeout=http_timeout)

    # ── 4. Fingerprint match ──
    fp = match_fingerprint(result.cname_chain, result.http_status, result.http_body_snippet)

    if fp:
        result.fingerprint = fp
        result.service     = fp.name
        result.evidence.append(
            f"Matched fingerprint: {fp.name} "
            f"(CNAME={fp.cname_pattern}, confidence={fp.confidence})"
        )

    # ── 5. Verdict ──
    if result.dangling and fp:
        result.vulnerable = True
        result.severity   = "high" if fp.confidence == "high" else "medium"
        result.evidence.append("Dangling CNAME + service fingerprint match = likely TAKEOVER")
    elif result.dangling:
        result.severity = "medium"
        result.evidence.append("Dangling CNAME detected — service not fingerprinted, manual review needed")
    elif fp and result.http_status in (404, 403, 500):
        result.vulnerable = True
        result.severity   = "medium"
        result.evidence.append("Service fingerprint error page — may be claimable")

    return result


def manual_bulk_check(
    subdomains: list[str],
    threads: int = 30,
    http_timeout: int = 10,
) -> list[SubdomainResult]:
    """Check a list of subdomains in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_single_subdomain, sd, http_timeout): sd
            for sd in subdomains
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                sd = futures[future]
                results.append(SubdomainResult(
                    subdomain=sd,
                    evidence=[f"Check failed: {e}"],
                ))
    return results


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

def parse_subjack(stdout: str, stderr: str) -> list[SubdomainResult]:
    """
    Parse subjack output.
    Subjack outputs lines like:
        [Can Be Taken Over] subdomain.example.com
        [Not Vulnerable]    other.example.com
        [Vulnerable]        another.example.com (S3 Bucket)
    """
    results = []
    raw = stdout or stderr

    patterns = [
        # [Can Be Taken Over] sub.domain.com
        r"\[Can Be Taken Over\]\s+(\S+)",
        r"\[Vulnerable\]\s+(\S+)(?:\s+\((.+?)\))?",
        r"\[Not Vulnerable\]\s+(\S+)",
        r"\[(.*?)\]\s+(\S+\.\S+)",
    ]

    processed = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        subdomain = None
        vulnerable = False
        service = None
        finding = line

        # Detect vulnerable lines
        m = re.search(r"\[Can Be Taken Over\]\s+(\S+)", line, re.IGNORECASE)
        if m:
            subdomain  = m.group(1)
            vulnerable = True

        if not subdomain:
            m = re.search(r"\[Vulnerable\]\s+(\S+)(?:\s+\((.+?)\))?", line, re.IGNORECASE)
            if m:
                subdomain  = m.group(1)
                service    = m.group(2) if m.lastindex > 1 else None
                vulnerable = True

        if not subdomain:
            m = re.search(r"\[Not Vulnerable\]\s+(\S+)", line, re.IGNORECASE)
            if m:
                subdomain  = m.group(1)
                vulnerable = False

        if not subdomain:
            # Generic bracketed format
            m = re.search(r"\[(.+?)\]\s+(\S+\.\S+)", line)
            if m:
                tag       = m.group(1)
                subdomain = m.group(2)
                vulnerable = "take" in tag.lower() or "vuln" in tag.lower()

        if subdomain and subdomain not in processed:
            processed.add(subdomain)
            results.append(SubdomainResult(
                subdomain=subdomain,
                vulnerable=vulnerable,
                service=service,
                severity="high" if vulnerable else "info",
                tool_finding=finding,
                evidence=[finding],
            ))

    return results


def parse_nuclei(stdout: str, stderr: str) -> list[SubdomainResult]:
    """
    Parse nuclei output.
    Nuclei outputs JSON lines or plain text like:
        [takeover:github-pages] [http] [high] https://sub.example.com
        [subdomain-takeover:aws-s3-bucket] [high] sub.example.com
    """
    results = []
    processed = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        result = None

        # ── Try JSON first ──
        try:
            data = json.loads(line)
            subdomain = (
                data.get("host")
                or data.get("matched-at")
                or data.get("input", "")
            )
            subdomain = re.sub(r"https?://", "", subdomain).split("/")[0]

            severity  = data.get("info", {}).get("severity", "medium")
            template  = data.get("template-id", data.get("templateID", ""))
            service   = _extract_service_from_template(template)

            if subdomain and subdomain not in processed:
                processed.add(subdomain)
                result = SubdomainResult(
                    subdomain=subdomain,
                    vulnerable=True,
                    service=service,
                    severity=severity,
                    tool_finding=line,
                    evidence=[f"nuclei template: {template}"],
                )
        except json.JSONDecodeError:
            pass

        # ── Fallback: plain text parse ──
        if result is None:
            # [takeover:github-pages] [http] [high] https://sub.example.com
            m = re.search(
                r"\[([^\]]+takeover[^\]]*)\]\s+(?:\[[^\]]+\]\s+)*(?:https?://)?(\S+\.\S+)",
                line, re.IGNORECASE
            )
            if m:
                template  = m.group(1)
                subdomain = re.sub(r"https?://", "", m.group(2)).split("/")[0]
                severity  = "high"
                sev_match = re.search(r"\[(low|medium|high|critical|info)\]", line, re.IGNORECASE)
                if sev_match:
                    severity = sev_match.group(1).lower()

                service = _extract_service_from_template(template)

                if subdomain and subdomain not in processed:
                    processed.add(subdomain)
                    result = SubdomainResult(
                        subdomain=subdomain,
                        vulnerable=True,
                        service=service,
                        severity=severity,
                        tool_finding=line,
                        evidence=[f"nuclei finding: {template}"],
                    )

        if result:
            results.append(result)

    return results


def _extract_service_from_template(template_id: str) -> Optional[str]:
    """
    Extract a human-readable service name from a nuclei template ID.
    e.g. 'takeover:github-pages' → 'GitHub Pages'
         'aws-s3-bucket-takeover' → 'AWS S3'
    """
    service_map = {
        "github":      "GitHub Pages",
        "s3":          "AWS S3",
        "cloudfront":  "AWS CloudFront",
        "heroku":      "Heroku",
        "netlify":     "Netlify",
        "vercel":      "Vercel",
        "azure":       "Azure",
        "shopify":     "Shopify",
        "zendesk":     "Zendesk",
        "fastly":      "Fastly",
        "firebase":    "Firebase",
        "ghost":       "Ghost",
        "hubspot":     "HubSpot",
        "tumblr":      "Tumblr",
        "surge":       "Surge",
        "webflow":     "Webflow",
        "squarespace": "Squarespace",
        "pantheon":    "Pantheon",
    }
    tl = template_id.lower()
    for key, name in service_map.items():
        if key in tl:
            return name
    return template_id or None


def parse_dnsx(stdout: str) -> list[str]:
    """
    Parse dnsx output to extract subdomains with CNAME records.
    dnsx -resp outputs lines like:
        sub.example.com [alias.github.io]
    Returns list of subdomains that have CNAMEs.
    """
    subdomains = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Match: sub.example.com [cname.target.com]
        m = re.match(r"^(\S+)\s+\[(.+?)\]", line)
        if m:
            subdomains.append(m.group(1))
        elif re.match(r"^[a-zA-Z0-9][\w\.\-]+\.[a-zA-Z]{2,}$", line):
            subdomains.append(line)
    return subdomains


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def subdomain_takeover_check(
    tool: str,
    target: str,
    args: list[str] = [],
    subdomains: list[str] = [],
) -> dict:
    """
    🔧 Agent Tool: Subdomain Takeover Check

    Capabilities:
      ┌──────────────────────────────────────────────────────────────────┐
      │  DANGLING CNAME DETECTION   Full CNAME chain resolution          │
      │  SERVICE FINGERPRINTING     35+ cloud services (can-i-take-over) │
      │  HTTP PROBING               Error page pattern matching          │
      │  TOOL INTEGRATION           subjack, nuclei, dnsx, manual        │
      │  BULK CHECKING              Parallel subdomain processing        │
      └──────────────────────────────────────────────────────────────────┘

    Args:
        tool:       "subjack" | "nuclei" | "dnsx" | "manual"
        target:     Root domain (e.g. "example.com")
        args:       Raw tool arguments — agent decides
        subdomains: Pre-supplied subdomain list (optional)
                    If empty, tool will probe target directly

    Tool-specific args reference:
      subjack:
        Basic:    ["-w", "subdomains.txt", "-t", "100", "-timeout", "30"]
        SSL:      ["-ssl"]
        Verbose:  ["-v"]
        All:      ["-a"]  (check all CNAME fingerprints)

      nuclei:
        Template: ["-t", "takeovers/"]
        Tags:     ["-tags", "takeover"]
        Rate:     ["-rl", "50", "-c", "10"]
        Severity: ["-severity", "medium,high,critical"]
        Verbose:  ["-v"]

      dnsx:
        CNAME:    ["-cname", "-resp"]
        Resolver: ["-r", "1.1.1.1"]
        Threads:  ["-t", "50"]

      manual:
        (no external tool — pure Python DNS + HTTP)
        args ignored, uses built-in fingerprints

    Returns:
        Structured JSON: subdomains → CNAME chain → fingerprint → verdict
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = SubdomainTakeoverRequest(
            tool=tool, target=target, args=args, subdomains=subdomains
        )
    except Exception as e:
        return TakeoverScanResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    results: list[SubdomainResult] = []
    command_str = ""
    raw_output  = ""
    error_msg   = None

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_bulk_check({target})"
        targets = req.subdomains if req.subdomains else [target]
        results = manual_bulk_check(targets, threads=30, http_timeout=10)

    # ══════════════════════════════
    # TOOL: SUBJACK
    # ══════════════════════════════
    elif tool == "subjack":
        import tempfile, os

        # Write subdomains to a temp file if provided
        wordlist_path = None
        tmp_file = None

        if req.subdomains:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="takeover_"
            )
            tmp_file.write("\n".join(req.subdomains))
            tmp_file.close()
            wordlist_path = tmp_file.name

        cmd = ["subjack"]

        if wordlist_path:
            cmd.extend(["-w", wordlist_path])
        elif "-w" not in req.args:
            # No wordlist → just check target directly
            cmd.extend(["-d", target])

        cmd += list(req.args)

        # Always add JSON-friendly output flags if not present
        if "-m" not in cmd:
            cmd.extend(["-m"])

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        results = parse_subjack(stdout, stderr)

        # Enrich subjack findings with our DNS check
        for r in results:
            if not r.cname_chain:
                r.cname_chain = resolve_cname_chain(r.subdomain)
            if not r.fingerprint:
                fp = match_fingerprint(r.cname_chain, r.http_status, r.http_body_snippet)
                if fp:
                    r.fingerprint = fp
                    r.service = fp.name

        # Cleanup temp file
        if tmp_file and os.path.exists(wordlist_path):
            os.unlink(wordlist_path)

        if rc != 0 and not results:
            error_msg = stderr[:500]

    # ══════════════════════════════
    # TOOL: NUCLEI
    # ══════════════════════════════
    elif tool == "nuclei":
        import tempfile, os

        # Write subdomains to temp file if provided
        tmp_file = None

        if req.subdomains:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="takeover_nuclei_"
            )
            tmp_file.write("\n".join(req.subdomains))
            tmp_file.close()

        cmd = ["nuclei"]

        if tmp_file:
            cmd.extend(["-l", tmp_file.name])
        else:
            cmd.extend(["-u", target])

        # Default to takeover templates if agent didn't specify
        has_template_flag = any(
            a in req.args for a in ["-t", "-tags", "--tags", "--template"]
        )
        if not has_template_flag:
            cmd.extend(["-tags", "takeover"])

        # Always output JSON for reliable parsing
        if "-json" not in req.args and "-j" not in req.args:
            cmd.append("-json")

        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        results = parse_nuclei(stdout, stderr)

        # Enrich nuclei findings with our DNS check
        for r in results:
            if not r.cname_chain:
                r.cname_chain = resolve_cname_chain(r.subdomain)
            if not r.a_records:
                final = r.cname_chain[-1] if r.cname_chain else r.subdomain
                r.a_records = resolve_a_records(final)

        # Cleanup
        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)

        if rc != 0 and not results:
            error_msg = stderr[:500]

    # ══════════════════════════════
    # TOOL: DNSX  (enumerate CNAMEs first → then manual check)
    # ══════════════════════════════
    elif tool == "dnsx":
        import tempfile, os

        tmp_file = None

        if req.subdomains:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="takeover_dnsx_"
            )
            tmp_file.write("\n".join(req.subdomains))
            tmp_file.close()

        cmd = ["dnsx"]

        if tmp_file:
            cmd.extend(["-l", tmp_file.name])
        else:
            cmd.extend(["-d", target])

        # Default: resolve CNAMEs with response
        if "-cname" not in req.args:
            cmd.append("-cname")
        if "-resp" not in req.args:
            cmd.append("-resp")

        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        # Parse dnsx output → get subdomains with CNAMEs
        cname_subdomains = parse_dnsx(stdout)

        # Cleanup
        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)

        # Now run full manual check on those with CNAMEs
        if cname_subdomains:
            results = manual_bulk_check(cname_subdomains, threads=30)
        else:
            error_msg = "dnsx returned no CNAME records" if rc == 0 else stderr[:500]

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    dangling    = [r for r in results if r.dangling]
    vulnerable  = [r for r in results if r.vulnerable]

    return TakeoverScanResult(
        success=len(results) > 0 or error_msg is None,
        tool=tool,
        target=target,
        command=command_str,
        total_checked=len(results),
        total_dangling=len(dangling),
        total_vulnerable=len(vulnerable),
        results=results,
        raw_output=raw_output or None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

SUBDOMAIN_TAKEOVER_TOOL_DEFINITION = {
    "name": "subdomain_takeover_check",
    "description": (
        "Check subdomains for takeover vulnerabilities. "
        "Detects dangling CNAMEs pointing to unclaimed resources on AWS S3, "
        "GitHub Pages, Heroku, Netlify, Vercel, Azure, GCP, Shopify, Zendesk, "
        "Fastly, and 25+ other services. "
        "Supports subjack (fast fingerprinting), nuclei (template-based), "
        "dnsx (CNAME enumeration), and manual (built-in DNS+HTTP check). "
        "Provide a list of subdomains for bulk checking."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["subjack", "nuclei", "dnsx", "manual"],
                "description": (
                    "subjack = fast CNAME fingerprint scanner | "
                    "nuclei  = template-based takeover detection | "
                    "dnsx    = CNAME enumeration → then manual check | "
                    "manual  = pure Python DNS + HTTP fingerprint (no external tool needed)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Root domain (e.g. 'example.com')",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "subjack: ['-t', '100', '-timeout', '30', '-ssl']\n"
                    "nuclei:  ['-tags', 'takeover', '-severity', 'high,critical']\n"
                    "dnsx:    ['-cname', '-resp', '-t', '50']\n"
                    "manual:  [] (no args needed)"
                ),
            },
            "subdomains": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "List of subdomains to check. "
                    "e.g. ['api.example.com', 'blog.example.com', 'dev.example.com']. "
                    "If empty, only the root target is checked."
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
    urllib3.disable_warnings()     # suppress InsecureRequestWarning for SSL

    SUBS = [
        "blog.example.com",
        "api.example.com",
        "dev.example.com",
        "staging.example.com",
        "shop.example.com",
    ]

    # ─────────────────────────────
    # 1. Manual check (no tool required)
    # ─────────────────────────────
    r = subdomain_takeover_check(
        tool="manual",
        target="example.com",
        subdomains=SUBS,
    )
    print("=== MANUAL CHECK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Subjack
    # ─────────────────────────────
    r = subdomain_takeover_check(
        tool="subjack",
        target="example.com",
        args=["-t", "100", "-timeout", "30", "-ssl", "-v"],
        subdomains=SUBS,
    )
    print("=== SUBJACK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Nuclei takeover templates
    # ─────────────────────────────
    r = subdomain_takeover_check(
        tool="nuclei",
        target="example.com",
        args=["-tags", "takeover", "-severity", "medium,high,critical", "-rl", "50"],
        subdomains=SUBS,
    )
    print("=== NUCLEI TAKEOVER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. dnsx CNAME enumeration → auto manual check
    # ─────────────────────────────
    r = subdomain_takeover_check(
        tool="dnsx",
        target="example.com",
        args=["-cname", "-resp", "-t", "100"],
        subdomains=SUBS,
    )
    print("=== DNSX + MANUAL ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Single subdomain check
    # ─────────────────────────────
    r = subdomain_takeover_check(
        tool="manual",
        target="blog.example.com",
    )
    print("=== SINGLE SUBDOMAIN ===")
    print(json.dumps(r, indent=2))