#/+
import subprocess
import json
import re
import time
import threading
import dns.resolver
import dns.exception
import requests
import concurrent.futures
from typing import Optional
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator
from server.agents.executer.recon.config import is_blocked_host


# ══════════════════════════════════════════════════════════════
# 1. RATE LIMITER (Thread-Safe Token Bucket)
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Thread-safe rate limiter using token bucket algorithm.
    Prevents triggering WAF/CloudFlare blocks during bulk scanning.
    """
    
    def __init__(self, calls_per_second: float = 10.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Block until rate limit allows next call"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_call = time.time()
    
    def reset(self):
        """Reset the limiter"""
        with self.lock:
            self.last_call = 0.0


# Global rate limiters
HTTP_RATE_LIMITER = RateLimiter(calls_per_second=10.0)   # 10 HTTP requests/sec
DNS_RATE_LIMITER = RateLimiter(calls_per_second=50.0)    # 50 DNS queries/sec


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS (Pydantic Models)
# ══════════════════════════════════════════════════════════════

class SubdomainTakeoverRequest(BaseModel):
    """Validated request for subdomain takeover check"""
    tool: str
    target: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=600, ge=30, le=7200)
    subdomains: list[str] = Field(default_factory=list)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        allowed = {"subjack", "nuclei", "dnsx", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean = v.strip().lower()
        if is_blocked_host(clean):
            raise ValueError(f"Target '{v}' is blocked")

        # Domain or IP validation
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"

        if not (re.match(domain_pattern, v) or re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target format: {v}")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        # Dangerous shell characters
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"]
        
        # Blocked flags (prevent file writes, we use stdin)
        blocked_flags = ["-o", "--output", "-w", "--wordlist", "-l", "--list", "-oJ", "-oA"]
        
        # Dangerous nuclei template categories
        dangerous_scripts = ["rce", "exploit", "dos", "fuzz", "intrusive"]

        for arg in v:
            # Check dangerous chars
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
            
            # Check blocked flags
            arg_clean = arg.strip().lower()
            for flag in blocked_flags:
                if arg_clean == flag or arg_clean.startswith(flag + "="):
                    raise ValueError(f"Blocked flag: {flag} (use subdomains parameter instead)")
            
            # Check dangerous nuclei tags
            if arg.startswith("-t") or arg.startswith("--tags"):
                value = arg.split("=", 1)[-1] if "=" in arg else ""
                for ds in dangerous_scripts:
                    if ds in value.lower():
                        raise ValueError(f"Dangerous template tag blocked: {ds}")
        return v

    @field_validator("subdomains")
    @classmethod
    def validate_subdomains(cls, v: list[str]) -> list[str]:
        """Validate subdomain list"""
        validated = []
        for sub in v:
            clean = sub.strip().lower()
            if not clean:
                continue
            # Basic subdomain format check
            if re.match(r"^[a-zA-Z0-9][\w\.\-]*\.[a-zA-Z]{2,}$", clean):
                validated.append(clean)
            else:
                raise ValueError(f"Invalid subdomain format: {sub}")
        return validated


class ServiceFingerprint(BaseModel):
    """Fingerprint for a cloud service takeover detection"""
    name: str
    cname_pattern: Optional[str] = None
    response_pattern: Optional[str] = None
    status_code: Optional[int] = None
    confidence: str = "medium"  # low, medium, high


class SubdomainResult(BaseModel):
    """Result for a single subdomain check"""
    subdomain: str
    cname_chain: list[str] = Field(default_factory=list)
    dangling: bool = False
    a_records: list[str] = Field(default_factory=list)
    nxdomain: bool = False
    http_status: Optional[int] = None
    http_body_snippet: Optional[str] = None
    vulnerable: bool = False
    service: Optional[str] = None
    fingerprint: Optional[ServiceFingerprint] = None
    tool_finding: Optional[str] = None
    evidence: list[str] = Field(default_factory=list)
    severity: str = "info"  # info, low, medium, high, critical


class TakeoverScanResult(BaseModel):
    """Aggregated scan result"""
    success: bool
    tool: str
    target: str
    command: str
    total_checked: int = 0
    total_dangling: int = 0
    total_vulnerable: int = 0
    results: list[SubdomainResult] = Field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. CLOUD SERVICE FINGERPRINTS (35+ Services)
#    Source: EdOverflow/can-i-take-over-xyz (with enhancements)
# ══════════════════════════════════════════════════════════════

FINGERPRINTS: list[ServiceFingerprint] = [
    # ═══════════════════════════════════════════
    # AWS
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="AWS S3",
        cname_pattern=r"\.s3[.\-]amazonaws\.com|\.s3\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com",
        response_pattern=r"NoSuchBucket|The specified bucket does not exist|BucketNotFound",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="AWS CloudFront",
        cname_pattern=r"\.cloudfront\.net",
        response_pattern=r"Bad Request|ERROR: The request could not be satisfied|The distribution is not available",
        status_code=403,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="AWS Elastic Beanstalk",
        cname_pattern=r"\.elasticbeanstalk\.com",
        response_pattern=r"NXDOMAIN|NoSuchDomain|InvalidParameterValue",
        confidence="high",
    ),
    ServiceFingerprint(
        name="AWS Elastic Load Balancer",
        cname_pattern=r"\.elb\.amazonaws\.com",
        response_pattern=r"NXDOMAIN",
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # AZURE
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Azure App Service",
        cname_pattern=r"\.azurewebsites\.net",
        response_pattern=r"404 Web Site not found|does not exist|Error 404",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Azure Blob Storage",
        cname_pattern=r"\.blob\.core\.windows\.net",
        response_pattern=r"BlobNotFound|The specified container does not exist|ContainerNotFound",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Azure CDN",
        cname_pattern=r"\.azureedge\.net",
        response_pattern=r"CDN endpoint is not found|The resource you are looking for has been removed",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Azure Traffic Manager",
        cname_pattern=r"\.trafficmanager\.net",
        response_pattern=r"NXDOMAIN",
        confidence="high",
    ),
    ServiceFingerprint(
        name="Azure Cloud Services",
        cname_pattern=r"\.cloudapp\.azure\.com|\.cloudapp\.net",
        response_pattern=r"NXDOMAIN|404",
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # GCP
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Google Cloud Storage",
        cname_pattern=r"\.storage\.googleapis\.com|c\.storage\.googleapis\.com",
        response_pattern=r"NoSuchBucket|The specified bucket does not exist|BucketNotFound",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Firebase Hosting",
        cname_pattern=r"\.firebaseapp\.com|\.web\.app",
        response_pattern=r"Site Not Found|Firebase Hosting Setup Complete",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Google App Engine",
        cname_pattern=r"\.appspot\.com",
        response_pattern=r"404|The requested URL was not found|Error: Not Found",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # GITHUB / GITLAB / BITBUCKET
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="GitHub Pages",
        cname_pattern=r"\.github\.io|\.githubusercontent\.com",
        response_pattern=r"There isn't a GitHub Pages site here|404 - File or directory not found|For root URLs",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="GitLab Pages",
        cname_pattern=r"\.gitlab\.io",
        response_pattern=r"The page you're looking for could not be found|404",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Bitbucket Pages",
        cname_pattern=r"\.bitbucket\.io",
        response_pattern=r"Repository not found|404 Not Found",
        status_code=404,
        confidence="high",
    ),
    
    # ═══════════════════════════════════════════
    # HOSTING PLATFORMS
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Heroku",
        cname_pattern=r"\.herokudns\.com|\.herokussl\.com|\.herokuapp\.com",
        response_pattern=r"No such app|herokucdn\.com/error-pages/no-such-app|There is no app configured",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Netlify",
        cname_pattern=r"\.netlify\.app|\.netlify\.com|\.bitballoon\.com",
        response_pattern=r"Not Found - Request ID|Page Not Found|Looks like you've followed a broken link",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Vercel",
        cname_pattern=r"\.vercel\.app|\.now\.sh|\.zeit\.co",
        response_pattern=r"The deployment could not be found|404|DEPLOYMENT_NOT_FOUND",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Surge",
        cname_pattern=r"\.surge\.sh",
        response_pattern=r"project not found|404 - Not Found",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Fly.io",
        cname_pattern=r"\.fly\.dev|\.fly\.io",
        response_pattern=r"404 Not Found|not found|Could not resolve",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Render",
        cname_pattern=r"\.onrender\.com",
        response_pattern=r"does not exist|not found|This service is unavailable",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Railway",
        cname_pattern=r"\.railway\.app|\.up\.railway\.app",
        response_pattern=r"not found|no deployment|Application not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Pantheon",
        cname_pattern=r"\.pantheonsite\.io|\.pantheon\.io",
        response_pattern=r"404 error unknown site|The gods are wise|Site not found",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Ghost",
        cname_pattern=r"\.ghost\.io",
        response_pattern=r"The thing you were looking for is no longer here|404|Site not found",
        status_code=404,
        confidence="high",
    ),
    
    # ═══════════════════════════════════════════
    # WORDPRESS / CMS
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="WP Engine",
        cname_pattern=r"\.wpengine\.com|\.wpenginepowered\.com",
        response_pattern=r"The site you were looking for couldn't be found|Site not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Kinsta",
        cname_pattern=r"\.kinsta\.cloud|\.kinstacdn\.com",
        response_pattern=r"No Site For Domain|Site not configured",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Wordpress.com",
        cname_pattern=r"\.wordpress\.com",
        response_pattern=r"Do you want to register|doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # WEBSITE BUILDERS
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Webflow",
        cname_pattern=r"\.webflow\.io|proxy-ssl\.webflow\.com",
        response_pattern=r"The page you are looking for doesn't exist|404|Page not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Squarespace",
        cname_pattern=r"\.squarespace\.com|ext-cust\.squarespace\.com",
        response_pattern=r"No Such Account|isn't live yet|This site is private",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Wix",
        cname_pattern=r"\.wixdns\.net|\.wix\.com|\.wixsite\.com",
        response_pattern=r"Error ConnectYourDomain|Looks like this domain isn't connected",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Cargo",
        cname_pattern=r"\.cargocollective\.com",
        response_pattern=r"404 Not Found|Page not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Strikingly",
        cname_pattern=r"\.s\.strikinglydns\.com|\.strikingly\.com",
        response_pattern=r"page not found|404",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Launchrock",
        cname_pattern=r"\.launchrock\.com",
        response_pattern=r"It looks like you may have taken a wrong turn|404",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # E-COMMERCE
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Shopify",
        cname_pattern=r"\.myshopify\.com|shops\.myshopify\.com",
        response_pattern=r"Sorry, this shop is currently unavailable|only accessible to|Store not available",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="BigCommerce",
        cname_pattern=r"\.mybigcommerce\.com|\.bigcommerce\.com",
        response_pattern=r"Store not found|not available",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # SUPPORT / HELP DESK
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Zendesk",
        cname_pattern=r"\.zendesk\.com|\.zd\.cloud",
        response_pattern=r"Help Center Closed|this help center no longer exists|Oops, this help center",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Freshdesk",
        cname_pattern=r"\.freshdesk\.com",
        response_pattern=r"We couldn't find|There is no helpdesk here|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Helpscout",
        cname_pattern=r"\.helpscoutdocs\.com",
        response_pattern=r"No settings were found|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Intercom",
        cname_pattern=r"\.intercom\.help|custom\.intercom\.help",
        response_pattern=r"This page doesn't exist|Uh oh. That page doesn't exist|404",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # MARKETING / LANDING PAGES
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="HubSpot",
        cname_pattern=r"\.hubspot\.com|\.hs-sites\.com|\.hubspotpagebuilder\.com",
        response_pattern=r"Domain not configured|does not exist in our system|404",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Unbounce",
        cname_pattern=r"\.unbounce\.com|unbouncepages\.com",
        response_pattern=r"The requested URL was not found|page not found|404",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Instapage",
        cname_pattern=r"\.instapage\.com|\.postclickmarketing\.com",
        response_pattern=r"Looks like you're lost|page not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Leadpages",
        cname_pattern=r"\.leadpages\.net|\.lpages\.co",
        response_pattern=r"not found|doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # CDN / INFRASTRUCTURE
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Fastly",
        cname_pattern=r"\.fastly\.net|\.fastlylb\.net|\.global\.fastly\.net",
        response_pattern=r"Fastly error: unknown domain|Please check that this domain|connection failure",
        status_code=500,
        confidence="high",
    ),
    ServiceFingerprint(
        name="Cloudflare",
        cname_pattern=r"\.cdn\.cloudflare\.net",
        response_pattern=r"Error 1001|DNS resolution error|direct IP access",
        status_code=530,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="KeyCDN",
        cname_pattern=r"\.kxcdn\.com",
        response_pattern=r"Failed to resolve|NXDOMAIN",
        confidence="medium",
    ),
    ServiceFingerprint(
        name="DigitalOcean Spaces",
        cname_pattern=r"\.digitaloceanspaces\.com",
        response_pattern=r"NoSuchBucket|The specified bucket does not exist",
        status_code=404,
        confidence="high",
    ),
    ServiceFingerprint(
        name="DigitalOcean App Platform",
        cname_pattern=r"\.ondigitalocean\.app",
        response_pattern=r"not found|Application error",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # DOCUMENTATION
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Readme.io",
        cname_pattern=r"\.readme\.io|\.readme\.com",
        response_pattern=r"Project doesnt exist|page not found|The page you're looking for",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="ReadTheDocs",
        cname_pattern=r"\.readthedocs\.io|\.rtfd\.io",
        response_pattern=r"This project doesn't exist|404",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="GitBook",
        cname_pattern=r"\.gitbook\.io",
        response_pattern=r"Space not found|404|This space does not exist",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # SOCIAL / BLOGS
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Tumblr",
        cname_pattern=r"\.tumblr\.com",
        response_pattern=r"There's nothing here|Whatever you were looking for doesn't currently exist|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Medium",
        cname_pattern=r"\.medium\.com",
        response_pattern=r"page not found|doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # EMAIL / COMMUNICATION
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Mailchimp",
        cname_pattern=r"\.mailchimp\.com|\.list-manage\.com",
        response_pattern=r"This page isn't available|404",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Campaign Monitor",
        cname_pattern=r"\.createsend\.com",
        response_pattern=r"not found|doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    
    # ═══════════════════════════════════════════
    # MISC
    # ═══════════════════════════════════════════
    ServiceFingerprint(
        name="Tilda",
        cname_pattern=r"\.tilda\.ws|\.tildacdn\.com",
        response_pattern=r"Please renew subscription|page not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Agile CRM",
        cname_pattern=r"\.agilecrm\.com",
        response_pattern=r"Sorry, this page is no longer available",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Aha.io",
        cname_pattern=r"\.ideas\.aha\.io",
        response_pattern=r"There is no portal here|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Anima",
        cname_pattern=r"\.animaapp\.io",
        response_pattern=r"The page you were looking for doesn't exist",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="JetBrains YouTrack",
        cname_pattern=r"\.myjetbrains\.com|\.youtrack\.cloud",
        response_pattern=r"is not a registered InCloud YouTrack|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Ngrok",
        cname_pattern=r"\.ngrok\.io|\.ngrok-free\.app",
        response_pattern=r"Tunnel.*not found|ERR_NGROK",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="SmartJobBoard",
        cname_pattern=r"\.smartjobboard\.com",
        response_pattern=r"This job board website is either expired|not found",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="Smugmug",
        cname_pattern=r"\.smugmug\.com",
        response_pattern=r"Not Found|page you're looking for",
        status_code=404,
        confidence="medium",
    ),
    ServiceFingerprint(
        name="UserVoice",
        cname_pattern=r"\.uservoice\.com",
        response_pattern=r"This UserVoice subdomain is currently available|not found",
        status_code=404,
        confidence="high",
    ),
]


# ══════════════════════════════════════════════════════════════
# 4. DNS RESOLUTION HELPERS (with Rate Limiting)
# ══════════════════════════════════════════════════════════════

def resolve_cname_chain(subdomain: str, timeout: float = 5.0) -> list[str]:
    """
    Resolve full CNAME chain with rate limiting.
    
    Example:
        blog.example.com → alias.herokudns.com → proxy.heroku.com → NXDOMAIN
    
    Returns ordered list of CNAME targets.
    """
    chain = []
    current = subdomain
    seen = set()
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Use reliable public DNS

    for _ in range(20):  # Max 20 hops to prevent infinite loops
        if current in seen:
            break
        seen.add(current)
        
        # Rate limit DNS queries
        DNS_RATE_LIMITER.acquire()
        
        try:
            answers = resolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except dns.resolver.NoAnswer:
            # No CNAME, might have A record directly
            break
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist - this is what we're looking for!
            break
        except dns.exception.Timeout:
            break
        except dns.resolver.NoNameservers:
            break
        except Exception:
            break

    return chain


def resolve_a_records(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve A records with rate limiting"""
    DNS_RATE_LIMITER.acquire()
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    
    try:
        answers = resolver.resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def is_nxdomain(hostname: str, timeout: float = 5.0) -> bool:
    """Check if hostname returns NXDOMAIN"""
    DNS_RATE_LIMITER.acquire()
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    
    try:
        resolver.resolve(hostname, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        # Other errors (timeout, etc.) - not conclusively NXDOMAIN
        return False


def check_ns_records(hostname: str, timeout: float = 5.0) -> list[str]:
    """Check NS records - useful for detecting abandoned delegations"""
    DNS_RATE_LIMITER.acquire()
    
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    
    try:
        answers = resolver.resolve(hostname, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════
# 5. HTTP PROBE (with Rate Limiting and Smart SSL)
# ══════════════════════════════════════════════════════════════

def http_probe(subdomain: str, timeout: int = 10) -> tuple[Optional[int], Optional[str]]:
    """
    Probe subdomain via HTTP/HTTPS with rate limiting.
    
    - Tries HTTPS first with SSL verification
    - Falls back to HTTP on SSL errors
    - Returns (status_code, body_snippet)
    """
    HTTP_RATE_LIMITER.acquire()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }
    
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        
        try:
            # First try with SSL verification
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=headers,
                verify=True
            )
            snippet = resp.text[:1000].strip()
            return resp.status_code, snippet
            
        except requests.exceptions.SSLError:
            # SSL error - retry without verification
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers=headers,
                    verify=False
                )
                snippet = resp.text[:1000].strip()
                return resp.status_code, snippet
            except Exception:
                continue
                
        except requests.exceptions.ConnectionError:
            # Connection refused/failed - try next scheme
            continue
            
        except requests.exceptions.Timeout:
            continue
            
        except requests.exceptions.TooManyRedirects:
            return None, "Too many redirects"
            
        except Exception:
            continue
    
    return None, None


# ══════════════════════════════════════════════════════════════
# 6. FINGERPRINT MATCHER
# ══════════════════════════════════════════════════════════════

def match_fingerprint(
    cname_chain: list[str],
    http_status: Optional[int],
    body_snippet: Optional[str],
) -> Optional[ServiceFingerprint]:
    """
    Match fingerprints against DNS and HTTP data.
    
    Decision matrix:
        - HIGH confidence: CNAME pattern + (status OR body match)
        - MEDIUM confidence: CNAME pattern alone
        - LOW confidence: Body pattern alone (downgraded)
    
    Returns first matching fingerprint, or None.
    """
    if not cname_chain and not body_snippet:
        return None
    
    cname_str = " ".join(cname_chain).lower()

    for fp in FINGERPRINTS:
        cname_hit = False
        status_hit = False
        body_hit = False

        # Check CNAME pattern
        if fp.cname_pattern and cname_str:
            if re.search(fp.cname_pattern, cname_str, re.IGNORECASE):
                cname_hit = True

        # Check HTTP status
        if fp.status_code and http_status:
            if http_status == fp.status_code:
                status_hit = True

        # Check response body
        if fp.response_pattern and body_snippet:
            if re.search(fp.response_pattern, body_snippet, re.IGNORECASE):
                body_hit = True

        # Decision matrix
        if cname_hit and (status_hit or body_hit):
            # Strong match - CNAME + evidence
            return fp
        
        if cname_hit and fp.confidence in ("medium", "high"):
            # CNAME alone is enough for medium/high confidence services
            return fp
        
        if body_hit and not cname_hit:
            # Body match only - downgrade confidence
            fp_copy = fp.model_copy()
            fp_copy.confidence = "low"
            return fp_copy

    return None


def get_service_from_cname(cname_chain: list[str]) -> Optional[str]:
    """Extract likely service name from CNAME chain without full fingerprint match"""
    cname_str = " ".join(cname_chain).lower()
    
    service_patterns = {
        r"herokuapp|herokudns|herokussl": "Heroku",
        r"github\.io": "GitHub Pages",
        r"netlify": "Netlify",
        r"vercel|now\.sh|zeit": "Vercel",
        r"s3.*amazonaws": "AWS S3",
        r"cloudfront\.net": "AWS CloudFront",
        r"azurewebsites\.net": "Azure App Service",
        r"blob\.core\.windows": "Azure Blob Storage",
        r"firebaseapp|web\.app": "Firebase",
        r"shopify": "Shopify",
        r"zendesk": "Zendesk",
        r"fastly": "Fastly",
        r"cloudflare": "Cloudflare",
        r"wpengine": "WP Engine",
        r"ghost\.io": "Ghost",
        r"tumblr": "Tumblr",
        r"surge\.sh": "Surge",
        r"webflow": "Webflow",
        r"squarespace": "Squarespace",
    }
    
    for pattern, service in service_patterns.items():
        if re.search(pattern, cname_str, re.IGNORECASE):
            return service
    
    return None


# ══════════════════════════════════════════════════════════════
# 7. SINGLE SUBDOMAIN CHECK (Core Logic)
# ══════════════════════════════════════════════════════════════

def check_single_subdomain(subdomain: str, http_timeout: int = 10) -> SubdomainResult:
    """
    Comprehensive takeover check for a single subdomain.
    
    Steps:
        1. Resolve CNAME chain
        2. Check if final target is NXDOMAIN (dangling)
        3. HTTP probe the subdomain
        4. Match against fingerprints
        5. Calculate severity
    
    Returns SubdomainResult with all findings.
    """
    result = SubdomainResult(subdomain=subdomain)

    # ══════════════════════════════════════════
    # Step 1: Resolve CNAME chain
    # ══════════════════════════════════════════
    result.cname_chain = resolve_cname_chain(subdomain, timeout=http_timeout)

    # ══════════════════════════════════════════
    # Step 2: Check A records + NXDOMAIN
    # ══════════════════════════════════════════
    final_target = result.cname_chain[-1] if result.cname_chain else subdomain
    result.a_records = resolve_a_records(final_target, timeout=http_timeout)
    result.nxdomain = is_nxdomain(final_target, timeout=http_timeout)

    # Dangling CNAME = has CNAME chain AND final target is unresolvable
    if result.cname_chain and (result.nxdomain or not result.a_records):
        result.dangling = True
        result.evidence.append(
            f"CNAME chain ends at '{final_target}' which has no A record (NXDOMAIN={result.nxdomain})"
        )

    # ══════════════════════════════════════════
    # Step 3: HTTP probe
    # ══════════════════════════════════════════
    result.http_status, result.http_body_snippet = http_probe(subdomain, timeout=http_timeout)
    
    if result.http_status:
        result.evidence.append(f"HTTP status: {result.http_status}")

    # ══════════════════════════════════════════
    # Step 4: Fingerprint matching
    # ══════════════════════════════════════════
    fp = match_fingerprint(result.cname_chain, result.http_status, result.http_body_snippet)

    if fp:
        result.fingerprint = fp
        result.service = fp.name
        result.evidence.append(
            f"Matched fingerprint: {fp.name} (pattern={fp.cname_pattern}, confidence={fp.confidence})"
        )
    elif result.cname_chain:
        # Try to at least identify the service
        service = get_service_from_cname(result.cname_chain)
        if service:
            result.service = service
            result.evidence.append(f"CNAME suggests service: {service}")

    # ══════════════════════════════════════════
    # Step 5: Verdict & Severity
    # ══════════════════════════════════════════
    if result.dangling and fp:
        # Dangling + Fingerprint = HIGH confidence takeover
        result.vulnerable = True
        result.severity = "critical" if fp.confidence == "high" else "high"
        result.evidence.append(
            f"⚠️ VULNERABLE: Dangling CNAME + {fp.name} fingerprint = TAKEOVER POSSIBLE"
        )
    
    elif result.dangling:
        # Dangling without fingerprint = needs manual review
        result.severity = "medium"
        result.evidence.append(
            "⚠️ SUSPICIOUS: Dangling CNAME detected — service not fingerprinted, manual review needed"
        )
    
    elif fp and result.http_status in (404, 403, 500, 502, 503):
        # Fingerprint match with error page = potentially vulnerable
        result.vulnerable = True
        result.severity = "medium" if fp.confidence == "low" else "high"
        result.evidence.append(
            f"⚠️ LIKELY VULNERABLE: {fp.name} error page detected — may be claimable"
        )
    
    elif result.cname_chain and result.http_status in (404,):
        # CNAME exists + 404 = suspicious
        result.severity = "low"
        result.evidence.append(
            "Suspicious: CNAME exists but returns 404 — worth investigating"
        )
    
    else:
        result.severity = "info"

    return result


def manual_bulk_check(
    subdomains: list[str],
    threads: int = 30,
    http_timeout: int = 10,
) -> list[SubdomainResult]:
    """
    Check multiple subdomains in parallel with thread pool.
    
    Rate limiting is handled at the DNS/HTTP level, not here.
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(check_single_subdomain, sd, http_timeout): sd
            for sd in subdomains
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                # Handle individual subdomain failures gracefully
                results.append(SubdomainResult(
                    subdomain=subdomain,
                    evidence=[f"Check failed: {str(e)}"],
                    severity="info",
                ))
    
    return results


# ══════════════════════════════════════════════════════════════
# 8. SUBPROCESS EXECUTOR (stdin-based, no temp files)
# ══════════════════════════════════════════════════════════════

def safe_execute(
    cmd: list[str],
    timeout: int = 600,
    stdin_data: Optional[str] = None
) -> tuple[str, str, int]:
    """
    Execute subprocess safely.
    
    - No shell=True (prevents injection)
    - Uses stdin for data (no temp files)
    - Captures stdout/stderr
    - Handles timeouts
    
    Returns (stdout, stderr, return_code)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            input=stdin_data
        )
        return result.stdout, result.stderr, result.returncode
        
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
        
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed. Install with: go install github.com/...", -1
        
    except PermissionError:
        return "", f"Permission denied executing '{cmd[0]}'", -1
        
    except Exception as e:
        return "", f"Execution error: {str(e)}", -1


# ══════════════════════════════════════════════════════════════
# 9. OUTPUT PARSERS
# ══════════════════════════════════════════════════════════════

def parse_subjack(stdout: str, stderr: str) -> list[SubdomainResult]:
    """
    Parse subjack output.
    
    Example formats:
        [Can Be Taken Over] sub.example.com
        [Vulnerable] api.example.com (S3 Bucket)
        [Not Vulnerable] www.example.com
    """
    results = []
    raw = stdout or stderr
    processed = set()

    patterns = [
        (r"\[Can Be Taken Over\]\s+(\S+)", True, None),
        (r"\[Vulnerable\]\s+(\S+)(?:\s+\((.+?)\))?", True, 2),
        (r"\[Not Vulnerable\]\s+(\S+)", False, None),
    ]

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        subdomain = None
        vulnerable = False
        service = None
        finding = line

        for pattern, is_vuln, service_group in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                subdomain = m.group(1)
                vulnerable = is_vuln
                if service_group and m.lastindex >= service_group:
                    service = m.group(service_group)
                break

        # Generic fallback
        if not subdomain:
            m = re.search(r"\[(.+?)\]\s+(\S+\.\S+)", line)
            if m:
                tag = m.group(1).lower()
                subdomain = m.group(2)
                vulnerable = any(x in tag for x in ["take", "vuln", "danger", "critical"])

        if subdomain and subdomain not in processed:
            processed.add(subdomain)
            results.append(SubdomainResult(
                subdomain=subdomain,
                vulnerable=vulnerable,
                service=service,
                severity="critical" if vulnerable else "info",
                tool_finding=finding,
                evidence=[f"subjack: {finding}"],
            ))

    return results


def parse_nuclei(stdout: str, stderr: str) -> list[SubdomainResult]:
    """
    Parse nuclei output (JSON lines or plain text).
    
    JSON format:
        {"host":"sub.com","template-id":"takeover:aws-s3","severity":"high"}
    
    Plain format:
        [takeover:github-pages] [http] [high] https://sub.example.com
    """
    results = []
    processed = set()

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        result = None

        # Try JSON first
        try:
            data = json.loads(line)
            
            # Extract subdomain from various fields
            subdomain = (
                data.get("host") or
                data.get("matched-at") or
                data.get("input") or
                ""
            )
            subdomain = re.sub(r"https?://", "", subdomain).split("/")[0].strip()

            if not subdomain:
                continue

            severity = data.get("info", {}).get("severity", "medium")
            template = data.get("template-id", data.get("templateID", "unknown"))
            service = _extract_service_from_template(template)
            matcher_name = data.get("matcher-name", "")

            if subdomain not in processed:
                processed.add(subdomain)
                result = SubdomainResult(
                    subdomain=subdomain,
                    vulnerable=True,
                    service=service,
                    severity=severity.lower(),
                    tool_finding=line[:500],
                    evidence=[
                        f"nuclei template: {template}",
                        f"matcher: {matcher_name}" if matcher_name else "",
                    ],
                )
                
        except json.JSONDecodeError:
            pass

        # Fallback: plain text parsing
        if result is None:
            # [takeover:aws-s3] [http] [high] https://sub.example.com
            m = re.search(
                r"\[([^\]]*takeover[^\]]*)\]\s+(?:\[[^\]]+\]\s+)*(?:\[[^\]]+\]\s+)?(?:https?://)?(\S+)",
                line, re.IGNORECASE
            )
            if m:
                template = m.group(1)
                subdomain = re.sub(r"https?://", "", m.group(2)).split("/")[0].strip()
                
                # Extract severity
                severity = "high"
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
                        tool_finding=line[:500],
                        evidence=[f"nuclei finding: {template}"],
                    )

        if result:
            # Clean up evidence
            result.evidence = [e for e in result.evidence if e]
            results.append(result)

    return results


def _extract_service_from_template(template_id: str) -> Optional[str]:
    """Map nuclei template IDs to human-readable service names"""
    if not template_id:
        return None
    
    service_map = {
        "github": "GitHub Pages",
        "gitlab": "GitLab Pages",
        "bitbucket": "Bitbucket Pages",
        "s3": "AWS S3",
        "cloudfront": "AWS CloudFront",
        "elasticbeanstalk": "AWS Elastic Beanstalk",
        "elb": "AWS ELB",
        "heroku": "Heroku",
        "netlify": "Netlify",
        "vercel": "Vercel",
        "azure": "Azure",
        "azurewebsites": "Azure App Service",
        "blob": "Azure Blob Storage",
        "shopify": "Shopify",
        "zendesk": "Zendesk",
        "fastly": "Fastly",
        "firebase": "Firebase",
        "ghost": "Ghost",
        "hubspot": "HubSpot",
        "tumblr": "Tumblr",
        "surge": "Surge",
        "webflow": "Webflow",
        "squarespace": "Squarespace",
        "pantheon": "Pantheon",
        "wordpress": "WordPress.com",
        "wpengine": "WP Engine",
        "readme": "Readme.io",
        "freshdesk": "Freshdesk",
        "intercom": "Intercom",
        "unbounce": "Unbounce",
        "cargo": "Cargo",
        "strikingly": "Strikingly",
        "tilda": "Tilda",
        "digitalocean": "DigitalOcean",
        "fly": "Fly.io",
        "render": "Render",
        "railway": "Railway",
    }
    
    tl = template_id.lower()
    for key, name in service_map.items():
        if key in tl:
            return name
    
    # Return cleaned template ID as fallback
    return template_id.replace("-", " ").replace("_", " ").title() if template_id else None


def parse_dnsx(stdout: str) -> list[str]:
    """
    Parse dnsx output to extract subdomains with CNAME records.
    
    Example format:
        sub.example.com [alias.github.io]
        api.example.com [CNAME] [target.herokudns.com]
    """
    subdomains = []
    
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        
        # Format: subdomain [cname_target]
        m = re.match(r"^(\S+)\s+\[(.+?)\]", line)
        if m:
            subdomain = m.group(1).strip()
            if subdomain and re.match(r"^[a-zA-Z0-9][\w\.\-]*\.[a-zA-Z]{2,}$", subdomain):
                subdomains.append(subdomain)
        
        # Plain subdomain format
        elif re.match(r"^[a-zA-Z0-9][\w\.\-]+\.[a-zA-Z]{2,}$", line):
            subdomains.append(line)
    
    return list(set(subdomains))  # Deduplicate


# ══════════════════════════════════════════════════════════════
# 10. RESULT CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=512)
def _cached_takeover_check(
    tool: str,
    target: str,
    args_tuple: tuple,
    subdomains_tuple: tuple,
    timeout: int
) -> str:
    """
    Cached internal implementation.
    Returns JSON string (hashable for lru_cache).
    """
    args = list(args_tuple)
    subdomains = list(subdomains_tuple)
    result = _takeover_check_impl(tool, target, args, subdomains, timeout)
    return json.dumps(result)


def clear_cache():
    """Clear the result cache"""
    _cached_takeover_check.cache_clear()


def get_cache_info():
    """Get cache statistics"""
    return _cached_takeover_check.cache_info()


# ══════════════════════════════════════════════════════════════
# 11. CORE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _takeover_check_impl(
    tool: str,
    target: str,
    args: list[str],
    subdomains: list[str],
    timeout: int
) -> dict:
    """
    Core implementation — stdin-based, no temp files.
    """
    start = time.time()

    # ══════════════════════════════════════════
    # VALIDATION
    # ══════════════════════════════════════════
    try:
        req = SubdomainTakeoverRequest(
            tool=tool,
            target=target,
            args=args,
            subdomains=subdomains,
            timeout=timeout
        )
    except Exception as e:
        return TakeoverScanResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation error: {str(e)}"
        ).model_dump()

    results: list[SubdomainResult] = []
    command_str = ""
    raw_output = ""
    error_msg = None

    # ══════════════════════════════════════════
    # TOOL: MANUAL (Pure Python)
    # ══════════════════════════════════════════
    if tool == "manual":
        command_str = f"manual_bulk_check(target={target}, subdomains={len(req.subdomains)})"
        targets = req.subdomains if req.subdomains else [target]
        results = manual_bulk_check(targets, threads=30, http_timeout=10)

    # ══════════════════════════════════════════
    # TOOL: SUBJACK (stdin-based)
    # ══════════════════════════════════════════
    elif tool == "subjack":
        stdin_data = None
        cmd = ["subjack"]

        if req.subdomains:
            stdin_data = "\n".join(req.subdomains)
            cmd.extend(["-w", "/dev/stdin"])
        else:
            cmd.extend(["-d", target])

        # Add user args
        cmd += list(req.args)

        # Ensure machine-readable output
        if "-m" not in cmd:
            cmd.append("-m")

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout, stdin_data=stdin_data)
        raw_output = (stdout or stderr)[:5000]

        # Parse results
        results = parse_subjack(stdout, stderr)

        # Enrich with DNS data
        for r in results:
            if not r.cname_chain:
                r.cname_chain = resolve_cname_chain(r.subdomain)
            if not r.fingerprint and r.cname_chain:
                fp = match_fingerprint(r.cname_chain, r.http_status, r.http_body_snippet)
                if fp:
                    r.fingerprint = fp
                    r.service = r.service or fp.name

        if rc != 0 and not results:
            error_msg = stderr[:500] if stderr else f"subjack returned code {rc}"

    # ══════════════════════════════════════════
    # TOOL: NUCLEI (stdin-based)
    # ══════════════════════════════════════════
    elif tool == "nuclei":
        stdin_data = None
        cmd = ["nuclei"]

        if req.subdomains:
            stdin_data = "\n".join(req.subdomains)
            cmd.extend(["-l", "/dev/stdin"])
        else:
            cmd.extend(["-u", target])

        # Default to takeover templates if not specified
        has_template_flag = any(a in req.args for a in ["-t", "-tags", "--tags", "--template"])
        if not has_template_flag:
            cmd.extend(["-tags", "takeover"])

        # Ensure JSON output
        if "-json" not in req.args and "-j" not in req.args:
            cmd.append("-json")

        # Add user args
        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout, stdin_data=stdin_data)
        raw_output = (stdout or stderr)[:5000]

        # Parse results
        results = parse_nuclei(stdout, stderr)

        # Enrich with DNS data
        for r in results:
            if not r.cname_chain:
                r.cname_chain = resolve_cname_chain(r.subdomain)
            if not r.a_records:
                final = r.cname_chain[-1] if r.cname_chain else r.subdomain
                r.a_records = resolve_a_records(final)
            if r.cname_chain and not r.fingerprint:
                fp = match_fingerprint(r.cname_chain, r.http_status, r.http_body_snippet)
                if fp:
                    r.fingerprint = fp

        if rc != 0 and not results:
            error_msg = stderr[:500] if stderr else f"nuclei returned code {rc}"

    # ══════════════════════════════════════════
    # TOOL: DNSX (CNAME enum → manual check)
    # ══════════════════════════════════════════
    elif tool == "dnsx":
        stdin_data = None
        cmd = ["dnsx"]

        if req.subdomains:
            stdin_data = "\n".join(req.subdomains)
            cmd.extend(["-l", "/dev/stdin"])
        else:
            cmd.extend(["-d", target])

        # Default flags for CNAME detection
        if "-cname" not in req.args:
            cmd.append("-cname")
        if "-resp" not in req.args:
            cmd.append("-resp")

        # Add user args
        cmd += list(req.args)

        command_str = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout, stdin_data=stdin_data)
        raw_output = (stdout or stderr)[:5000]

        # Parse CNAME subdomains
        cname_subdomains = parse_dnsx(stdout)

        if cname_subdomains:
            # Run manual check on subdomains with CNAMEs
            results = manual_bulk_check(cname_subdomains, threads=30, http_timeout=10)
        else:
            if rc == 0:
                error_msg = "dnsx returned no CNAME records"
            else:
                error_msg = stderr[:500] if stderr else f"dnsx returned code {rc}"

    # ══════════════════════════════════════════
    # BUILD FINAL RESULT
    # ══════════════════════════════════════════
    
    # Count categories
    dangling = [r for r in results if r.dangling]
    vulnerable = [r for r in results if r.vulnerable]

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: severity_order.get(r.severity, 5))

    return TakeoverScanResult(
        success=len(results) > 0 or error_msg is None,
        tool=tool,
        target=target,
        command=command_str,
        total_checked=len(results),
        total_dangling=len(dangling),
        total_vulnerable=len(vulnerable),
        results=results,
        raw_output=raw_output,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 12. PUBLIC API
# ══════════════════════════════════════════════════════════════

def subdomain_takeover_check(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    subdomains: Optional[list[str]] = None,
    timeout: int = 600,
    use_cache: bool = True,
) -> dict:
    """
    🔧 Agent Tool: Subdomain Takeover Check

    Detect subdomain takeover vulnerabilities by analyzing:
    - Dangling CNAME records pointing to unclaimed cloud resources
    - Service-specific error pages (35+ cloud providers)
    - DNS resolution chains and NXDOMAIN responses

    ┌──────────────────────────────────────────────────────────────────┐
    │  CAPABILITIES                                                    │
    ├──────────────────────────────────────────────────────────────────┤
    │  • Dangling CNAME Detection    Full chain resolution             │
    │  • Service Fingerprinting      35+ cloud services supported      │
    │  • HTTP Error Page Analysis    Pattern matching on responses     │
    │  • Tool Integration            subjack, nuclei, dnsx, manual     │
    │  • Rate Limiting               10 HTTP/sec, 50 DNS/sec           │
    │  • Result Caching              LRU cache (512 entries)           │
    │  • No Temp Files               stdin-based tool communication    │
    └──────────────────────────────────────────────────────────────────┘

    Args:
        tool: Scanner to use
            - "manual"  : Pure Python (no external tools needed)
            - "subjack" : Fast Go-based CNAME fingerprinter
            - "nuclei"  : Template-based vulnerability scanner
            - "dnsx"    : DNS enumeration → then manual check

        target: Root domain (e.g., "example.com")

        args: Tool-specific arguments
            subjack: ["-t", "100", "-timeout", "30", "-ssl", "-v"]
            nuclei:  ["-severity", "high,critical", "-rl", "50"]
            dnsx:    ["-t", "100", "-retry", "3"]
            manual:  [] (no args needed)

        subdomains: List of subdomains to check
            e.g., ["api.example.com", "blog.example.com"]
            If empty, only the root target is checked.

        timeout: Execution timeout in seconds (default: 600)

        use_cache: Enable LRU caching (default: True)

    Returns:
        dict: Structured scan results with:
            - success: bool
            - tool: str
            - target: str
            - command: str
            - total_checked: int
            - total_dangling: int
            - total_vulnerable: int
            - results: list[SubdomainResult]
            - raw_output: str
            - error: Optional[str]
            - execution_time: float

    Supported Cloud Services:
        AWS (S3, CloudFront, Elastic Beanstalk, ELB)
        Azure (App Service, Blob Storage, CDN, Traffic Manager)
        GCP (Cloud Storage, Firebase, App Engine)
        GitHub Pages, GitLab Pages, Bitbucket Pages
        Heroku, Netlify, Vercel, Surge, Fly.io, Render, Railway
        Shopify, Zendesk, Fastly, HubSpot, Ghost, Tumblr
        Webflow, Squarespace, Wix, WP Engine, Kinsta
        And 15+ more...

    Example:
        >>> result = subdomain_takeover_check(
        ...     tool="manual",
        ...     target="example.com",
        ...     subdomains=["api.example.com", "blog.example.com"]
        ... )
        >>> print(f"Found {result['total_vulnerable']} vulnerable subdomains")
    """
    args = list(args or [])
    subdomains = list(subdomains or [])

    if use_cache:
        # Use cached version
        cached_json = _cached_takeover_check(
            tool,
            target,
            tuple(args),
            tuple(subdomains),
            timeout
        )
        return json.loads(cached_json)
    else:
        return _takeover_check_impl(tool, target, args, subdomains, timeout)


# ══════════════════════════════════════════════════════════════
# 13. LLM TOOL DEFINITION (Function Calling Schema)
# ══════════════════════════════════════════════════════════════

SUBDOMAIN_TAKEOVER_TOOL_DEFINITION = {
    "name": "subdomain_takeover_check",
    "description": (
        "Detect subdomain takeover vulnerabilities by identifying dangling CNAME records "
        "pointing to unclaimed cloud resources. Supports 35+ cloud services including "
        "AWS S3, GitHub Pages, Heroku, Netlify, Vercel, Azure, Shopify, Zendesk, and more. "
        "Features rate limiting (10 HTTP/sec, 50 DNS/sec) and result caching. "
        "Use 'manual' tool for pure Python scanning (no external dependencies), or "
        "'subjack'/'nuclei'/'dnsx' for specialized tool integration."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["subjack", "nuclei", "dnsx", "manual"],
                "description": (
                    "Scanner to use:\n"
                    "• manual  = Pure Python DNS+HTTP check (no tools needed, recommended for quick scans)\n"
                    "• subjack = Fast Go-based CNAME fingerprinter (requires: go install github.com/haccer/subjack)\n"
                    "• nuclei  = Template-based scanner (requires: nuclei installed, auto-uses takeover templates)\n"
                    "• dnsx    = DNS enumeration then manual check (requires: dnsx installed)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Root domain to check (e.g., 'example.com'). Must be a valid domain format.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Tool-specific arguments:\n"
                    "• subjack: ['-t', '100', '-timeout', '30', '-ssl', '-v']\n"
                    "• nuclei:  ['-severity', 'high,critical', '-rl', '50', '-c', '25']\n"
                    "• dnsx:    ['-t', '100', '-retry', '3']\n"
                    "• manual:  [] (no arguments needed)"
                ),
            },
            "subdomains": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "List of subdomains to check for takeover. "
                    "Example: ['api.example.com', 'blog.example.com', 'dev.example.com']. "
                    "If empty, only the root target domain is checked."
                ),
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds (default: 600, min: 30, max: 7200)",
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable LRU caching to avoid re-scanning same targets (default: true)",
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 14. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def list_supported_services() -> list[str]:
    """Return list of all supported cloud services"""
    return sorted(set(fp.name for fp in FINGERPRINTS))


def get_fingerprint_count() -> int:
    """Return total number of fingerprints"""
    return len(FINGERPRINTS)


def get_rate_limiter_stats() -> dict:
    """Return current rate limiter statistics"""
    return {
        "http": {
            "calls_per_second": HTTP_RATE_LIMITER.calls_per_second,
            "min_interval": HTTP_RATE_LIMITER.min_interval,
        },
        "dns": {
            "calls_per_second": DNS_RATE_LIMITER.calls_per_second,
            "min_interval": DNS_RATE_LIMITER.min_interval,
        },
    }


def set_rate_limits(http_per_second: float = 10.0, dns_per_second: float = 50.0):
    """Adjust rate limits"""
    global HTTP_RATE_LIMITER, DNS_RATE_LIMITER
    HTTP_RATE_LIMITER = RateLimiter(calls_per_second=http_per_second)
    DNS_RATE_LIMITER = RateLimiter(calls_per_second=dns_per_second)


# ══════════════════════════════════════════════════════════════
# 15. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()  # Suppress SSL warnings for testing

    clear_cache()

    print("=" * 70)
    print("SUBDOMAIN TAKEOVER CHECK — v2.0")
    print("Rate Limited | Cached | No Temp Files | 35+ Services")
    print("=" * 70)

    # Test subdomains
    TEST_SUBS = [
        "blog.scanme.nmap.org",
        "api.scanme.nmap.org",
        "dev.scanme.nmap.org",
        "staging.scanme.nmap.org",
        "shop.scanme.nmap.org",
    ]

    # ─────────────────────────────────────────
    # 1. Manual check (no external tools)
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 1: Manual Check (Pure Python)")
    print("─" * 50)
    
    r = subdomain_takeover_check(
        tool="manual",
        target="scanme.nmap.org",
        subdomains=TEST_SUBS,
        use_cache=False,
    )
    
    print(f"Target:      {r['target']}")
    print(f"Checked:     {r['total_checked']}")
    print(f"Dangling:    {r['total_dangling']}")
    print(f"Vulnerable:  {r['total_vulnerable']}")
    print(f"Exec Time:   {r['execution_time']}s")
    if r.get("error"):
        print(f"Error:       {r['error']}")
    
    if r['results']:
        print("\nResults:")
        for res in r['results'][:5]:
            status = "🔴 VULN" if res['vulnerable'] else ("🟡 DANG" if res['dangling'] else "🟢 SAFE")
            print(f"  {status} {res['subdomain']}")
            if res['cname_chain']:
                print(f"       CNAME: {' → '.join(res['cname_chain'][:3])}")
            if res['service']:
                print(f"       Service: {res['service']}")

    # ─────────────────────────────────────────
    # 2. Cache test
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 2: Cache Performance")
    print("─" * 50)

    # First cacheable call (miss)
    start_miss = time.time()
    _ = subdomain_takeover_check(
        tool="manual",
        target="scanme.nmap.org",
        subdomains=TEST_SUBS,
        use_cache=True,
    )
    miss_time = time.time() - start_miss

    # Second identical call (hit)
    start_hit = time.time()
    r_cache_hit = subdomain_takeover_check(
        tool="manual",
        target="scanme.nmap.org",
        subdomains=TEST_SUBS,
        use_cache=True,
    )
    hit_time = time.time() - start_hit

    print(f"No-cache run:      {r['execution_time']}s")
    print(f"Cache miss run:    {miss_time:.4f}s")
    print(f"Cache hit run:     {hit_time:.4f}s")
    print(f"Hit speedup:       {miss_time / hit_time:.1f}x" if hit_time > 0 else "Instant")
    print(f"Cache-hit checked: {r_cache_hit['total_checked']}")

    info = get_cache_info()
    print(f"Cache stats: hits={info.hits}, misses={info.misses}, size={info.currsize}/{info.maxsize}")

    # ─────────────────────────────────────────
    # 3. Rate limiter stats
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 3: Rate Limiter Configuration")
    print("─" * 50)
    
    stats = get_rate_limiter_stats()
    print(f"HTTP: {stats['http']['calls_per_second']} req/sec")
    print(f"DNS:  {stats['dns']['calls_per_second']} req/sec")

    # ─────────────────────────────────────────
    # 4. Supported services
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 4: Supported Cloud Services")
    print("─" * 50)
    
    services = list_supported_services()
    print(f"Total: {len(services)} services")
    print("Services:", ", ".join(services[:10]), "...")

    # ─────────────────────────────────────────
    # 5. Full JSON output
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 5: Full JSON Output (first result)")
    print("─" * 50)
    
    if r['results']:
        print(json.dumps(r['results'][0], indent=2))

    # ─────────────────────────────────────────
    # 6. Tool definition for LLM
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("LLM TOOL DEFINITION")
    print("─" * 50)
    print(json.dumps(SUBDOMAIN_TAKEOVER_TOOL_DEFINITION, indent=2))

    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)
