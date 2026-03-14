from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field

from server.db.knowledge.models.document import SourceType

__all__ = [
    "ContentType",
    "SourceConfig",
    "PayloadSourceConfig",
    "ALL_SOURCES",
    "PAYLOAD_SOURCES",
    "get_enabled_sources",
    "get_runtime_sources",
    "get_sources_by_domain",
    "get_sources_by_type",
    "get_source_by_name",
    "get_all_domains",
    "get_sources_by_priority",
    "get_sources_by_content_type",
    "get_fixed_sources",
    "get_variable_sources",
]


class ContentType(StrEnum):
    """The 5 Qdrant collection types for vector storage."""
    STRATEGIES = "strategies"
    EXPLOITS = "exploits"
    TOOLS = "tools"
    STANDARDS = "standards"
    ATTACK_TYPES = "attack_types"


class SourceConfig(BaseModel):
    """Configuration for a single knowledge source."""
    name: str
    url: str
    source_type: SourceType
    domain: str = "shared"
    category: str = "general"
    content_type: ContentType = ContentType.STRATEGIES
    enabled: bool = True
    is_runtime: bool = False
    is_fixed: bool = True
    priority: int = Field(default=2, ge=1, le=3)
    branch: str = "master"
    subdirectory: str | None = None
    clone_id: str | None = None
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.md"])
    exclude_patterns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    license: str | None = None
    description: str = ""
    cooldown_days: int = 3
    last_updated: datetime | None = None
    default_metadata: dict[str, Any] = Field(default_factory=dict)
    api_params: dict[str, str] = Field(default_factory=dict)
    css_selector: str | None = None
    max_pages: int = 1000

    @property
    def is_cooldown_active(self) -> bool:
        """True if this source was updated recently and should not be re-fetched."""
        if self.last_updated is None:
            return False
        from datetime import timedelta
        return (datetime.now(timezone.utc) - self.last_updated) < timedelta(days=self.cooldown_days)


# ═════════════════════════════════════════════════════════════════════════════
# SHARED — Cross-domain knowledge, queried by ALL agents
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_SHARED_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="HackTricks", url="https://github.com/HackTricks-wiki/hacktricks", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", subdirectory="src", include_patterns=["**/*.md"], exclude_patterns=["**/SUMMARY.md", "**/banners/**"], tags=["hacktricks", "web", "pentest", "methodology"], license="CC-BY-NC-4.0", description="HackTricks — comprehensive pentest tricks & techniques."),
    SourceConfig(name="HackTricks-Book", url="https://book.hacktricks.xyz/", source_type=SourceType.GITBOOK, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, priority=1, max_pages=1500, tags=["hacktricks", "methodology"], description="HackTricks Book — GitBook version."),
    SourceConfig(name="PayloadsAllTheThings", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["payloads", "injection", "bypass", "methodology"], license="MIT", description="PayloadsAllTheThings — payloads, bypass techniques, methodology."),
    SourceConfig(name="AwesomeBugbountyWriteups", url="https://github.com/devanshbatham/Awesome-Bugbounty-Writeups", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "writeups"], description="Curated bug bounty writeups."),
    SourceConfig(name="BugBountyReference", url="https://github.com/ngalongc/bug-bounty-reference", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "reference"], description="Bug bounty write-up reference list."),
    SourceConfig(name="KeyHacks", url="https://github.com/streaak/keyhacks", source_type=SourceType.GITHUB_REPO, domain="shared", category="secrets", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["api-keys", "secrets", "validation"], license="MIT", description="KeyHacks — validate & exploit leaked API keys."),
    SourceConfig(name="PayloadsAllTheThings-APIKeyLeaks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="secrets", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="API Key Leaks", include_patterns=["**/*.md"], tags=["api-keys", "leaks"], license="MIT", description="PayloadsAllTheThings — API Key Leaks section."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_SHARED_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_SHARED_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="CISA-KEV", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", source_type=SourceType.WEBSITE, domain="shared", category="threat_intel", content_type=ContentType.EXPLOITS, max_pages=50, tags=["cisa", "kev", "exploited"], description="CISA Known Exploited Vulnerabilities Catalog."),
    SourceConfig(name="Vulhub", url="https://github.com/vulhub/vulhub", source_type=SourceType.GITHUB_REPO, domain="shared", category="exploits", content_type=ContentType.EXPLOITS, branch="master", include_patterns=["**/*.md"], tags=["vulhub", "docker", "vulnerable"], description="Vulhub — pre-built vulnerable environments (READMEs only)."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_SHARED_EXPLOITS_VARIABLE: list[SourceConfig] = []

# ── Tools (fixed) ───────────────────────────────────────────────────────
_SHARED_TOOLS_FIXED: list[SourceConfig] = [
    SourceConfig(name="RedTeamingToolkit", url="https://github.com/infosecn1nja/Red-Teaming-Toolkit", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.TOOLS, branch="master", include_patterns=["**/*.md"], tags=["red-team", "methodology"], description="Red Teaming Toolkit reference."),
]

# ── Tools (variable — Intel agent managed) ─────────────────────────────────────
_SHARED_TOOLS_VARIABLE: list[SourceConfig] = []

# ── Standards (fixed) ───────────────────────────────────────────────────
_SHARED_STANDARDS_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-ASVS", url="https://github.com/OWASP/ASVS", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["owasp", "asvs", "compliance"], description="OWASP ASVS."),
    SourceConfig(name="OWASP-ASVS-Web", url="https://owasp.org/www-project-application-security-verification-standard/", source_type=SourceType.WEBSITE, domain="shared", category="compliance", content_type=ContentType.STANDARDS, max_pages=100, tags=["owasp", "asvs"], description="OWASP ASVS web documentation."),
    SourceConfig(name="OWASP-CheatSheets", url="https://github.com/OWASP/CheatSheetSeries", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md"], tags=["owasp", "cheatsheets"], description="OWASP Cheat Sheet Series."),
    SourceConfig(name="ATTACKControlMappings", url="https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", content_type=ContentType.STANDARDS, branch="main", include_patterns=["**/*.md", "**/*.json"], tags=["mitre", "nist", "mappings"], description="ATT&CK ↔ NIST 800-53 control mappings."),
]

# ── Standards (variable — Intel agent managed) ─────────────────────────────────
_SHARED_STANDARDS_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_SHARED_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="AtomicRedTeam", url="https://github.com/redcanaryco/atomic-red-team", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.ATTACK_TYPES, priority=1, branch="master", include_patterns=["**/*.md", "**/*.yaml"], exclude_patterns=["**/LICENSE*"], tags=["atomic", "red-team", "mitre", "testing"], license="MIT", description="Atomic Red Team — portable detection tests."),
    SourceConfig(name="AdversaryEmulationLibrary", url="https://github.com/center-for-threat-informed-defense/adversary_emulation_library", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md", "**/*.yaml"], tags=["emulation", "mitre", "apt", "campaigns"], description="MITRE adversary emulation plans."),
    SourceConfig(name="PayloadsAllTheThings-Evasion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="detection_evasion", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Evasion.md", "**/Defense Evasion.md"], tags=["evasion", "defense-evasion", "bypass"], description="Evasion and defense evasion techniques."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_SHARED_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# WEB — Web application security
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_WEB_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-WSTG", url="https://github.com/OWASP/wstg", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", subdirectory="document", include_patterns=["**/*.md"], exclude_patterns=["**/images/**"], tags=["owasp", "wstg", "web-security"], license="CC-BY-SA-4.0", description="OWASP Web Security Testing Guide."),
    SourceConfig(name="PortSwigger-WebSecurity", url="https://portswigger.net/web-security/all-topics", source_type=SourceType.WEBSITE, domain="web", category="methodology", content_type=ContentType.STRATEGIES, priority=1, include_patterns=["https://portswigger.net/web-security/*"], max_pages=500, tags=["portswigger", "burp", "web-security"], description="PortSwigger Web Security Academy."),
    SourceConfig(name="PortSwigger-Research", url="https://portswigger.net/research", source_type=SourceType.WEBSITE, domain="web", category="methodology", content_type=ContentType.STRATEGIES, include_patterns=["https://portswigger.net/research/*"], max_pages=300, tags=["portswigger", "research"], description="PortSwigger research blog."),
    SourceConfig(name="AllAboutBugBounty", url="https://github.com/daffainfo/AllAboutBugBounty", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "web"], description="All About Bug Bounty."),
    SourceConfig(name="HowToHunt", url="https://github.com/KathanP19/HowToHunt", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "hunting", "web"], description="How to Hunt — bug bounty methodology."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_WEB_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_WEB_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="WeirdProxies", url="https://github.com/GrrrDog/weird_proxies", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["proxy", "misconfig", "web"], description="Weird Proxies — proxy misconfigurations."),
    SourceConfig(name="Web-SQLi", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="SQL Injection", include_patterns=["**/*.md"], tags=["sqli", "sql-injection"], description="SQL Injection payloads."),
    SourceConfig(name="Web-XSS", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="XSS Injection", include_patterns=["**/*.md"], tags=["xss", "cross-site-scripting"], description="XSS Injection payloads."),
    SourceConfig(name="Web-SSRF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Server Side Request Forgery", include_patterns=["**/*.md"], tags=["ssrf"], description="SSRF payloads."),
    SourceConfig(name="BlindSSRFChains", url="https://github.com/assetnote/blind-ssrf-chains", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="main", include_patterns=["**/*.md"], tags=["ssrf", "blind", "chains"], description="Blind SSRF exploitation chains."),
    SourceConfig(name="Web-SSTI", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Server Side Template Injection", include_patterns=["**/*.md"], tags=["ssti", "template-injection"], description="SSTI payloads."),
    SourceConfig(name="Web-FileUpload", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Upload Insecure Files", include_patterns=["**/*.md"], tags=["file-upload", "webshell"], description="File upload bypass payloads."),
    SourceConfig(name="Web-CommandInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Command Injection", include_patterns=["**/*.md"], tags=["command-injection", "rce"], description="OS Command Injection payloads."),
    SourceConfig(name="Web-XXE", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="XXE Injection", include_patterns=["**/*.md"], tags=["xxe", "xml"], description="XXE Injection payloads."),
    SourceConfig(name="Web-CSRF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Cross-Site Request Forgery", include_patterns=["**/*.md"], tags=["csrf"], description="CSRF techniques."),
    SourceConfig(name="Web-OpenRedirect", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Open Redirect", include_patterns=["**/*.md"], tags=["open-redirect"], description="Open Redirect payloads."),
    SourceConfig(name="Web-Deserialization", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Insecure Deserialization", include_patterns=["**/*.md"], tags=["deserialization", "rce"], description="Insecure deserialization payloads."),
    SourceConfig(name="Web-IDOR", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Insecure Direct Object References", include_patterns=["**/*.md"], tags=["idor", "access-control"], description="IDOR techniques."),
    SourceConfig(name="Web-CRLF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="CRLF Injection", include_patterns=["**/*.md"], tags=["crlf", "injection"], description="CRLF Injection payloads."),
    SourceConfig(name="Web-PrototypePollution", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Prototype Pollution", include_patterns=["**/*.md"], tags=["prototype-pollution", "javascript"], description="Prototype Pollution payloads."),
    SourceConfig(name="Web-CacheDeception", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Web Cache Deception", include_patterns=["**/*.md"], tags=["cache-deception", "web-cache"], description="Web Cache Deception payloads."),
    SourceConfig(name="Web-RequestSmuggling", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Request Smuggling", include_patterns=["**/*.md"], tags=["request-smuggling", "http"], description="HTTP Request Smuggling techniques."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_WEB_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []

# ── Tools (fixed) ───────────────────────────────────────────────────────
_WEB_TOOLS_FIXED: list[SourceConfig] = [
    SourceConfig(name="H4cker-WebAppTesting", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="web", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="web-application-testing", include_patterns=["**/*.md"], tags=["web-tools", "sqli", "ssrf", "api-security"], description="H4cker — web app testing guides (SQLi tools, SSRF, API security)."),
    SourceConfig(name="H4cker-WebToolsCatalog", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="web", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="organized_tools", include_patterns=["**/web-application-testing_tools.md"], tags=["web-tools", "catalog"], description="H4cker — curated catalog of web application testing tools."),
    SourceConfig(name="H4cker-ExploitCheatsheets", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="web", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/exploitation", include_patterns=["**/*.md"], tags=["exploitation", "cheatsheets"], description="H4cker — exploitation cheat sheets and technique references."),
]

# ── Tools (variable — Intel agent managed) ─────────────────────────────────────
_WEB_TOOLS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# API — API security testing
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_API_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="AwesomeAPISecurity", url="https://github.com/arainho/awesome-api-security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["api", "security"], description="Awesome API Security."),
    SourceConfig(name="31DaysAPISecurityTips", url="https://github.com/inonshk/31-days-of-API-Security-Tips", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["api", "tips"], description="31 days of API security tips."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_API_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Standards (fixed) ───────────────────────────────────────────────────
_API_STANDARDS_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-APISecurity", url="https://github.com/OWASP/API-Security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["owasp", "api-security", "top10"], description="OWASP API Security Top 10."),
]

# ── Standards (variable — Intel agent managed) ─────────────────────────────────
_API_STANDARDS_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_API_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="API-GraphQLInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="GraphQL Injection", include_patterns=["**/*.md"], tags=["graphql", "injection"], description="GraphQL Injection payloads."),
    SourceConfig(name="API-JWTAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="JSON Web Token", include_patterns=["**/*.md"], tags=["jwt", "auth-bypass"], description="JWT attack payloads."),
    SourceConfig(name="API-OAuthMisconfig", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="OAuth Misconfiguration", include_patterns=["**/*.md"], tags=["oauth", "misconfiguration"], description="OAuth misconfiguration payloads."),
    SourceConfig(name="GraphQLSecurityTesting", url="https://github.com/nicowillis/graphql-security-testing", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="main", include_patterns=["**/*.md"], tags=["graphql", "testing"], description="GraphQL security testing methodology.", enabled=False),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_API_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# MOBILE — Mobile application security
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_MOBILE_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-MASTG", url="https://github.com/OWASP/owasp-mastg", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/images/**", "**/CHANGELOG*"], tags=["mobile", "android", "ios", "owasp"], license="CC-BY-SA-4.0", description="OWASP MASTG."),
    SourceConfig(name="HackTricks-Android", url="https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["android", "mobile", "hacktricks"], description="HackTricks — Android pentesting."),
    SourceConfig(name="HackTricks-iOS", url="https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["ios", "mobile", "hacktricks"], description="HackTricks — iOS pentesting."),
    SourceConfig(name="MobileAppPentestCheatsheet", url="https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["mobile", "cheatsheet"], description="Mobile app pentesting cheatsheet."),
    SourceConfig(name="MobileHackingCheatSheet", url="https://github.com/randorisec/MobileHackingCheatSheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["mobile", "hacking"], description="Randorisec mobile hacking cheat sheet."),
    SourceConfig(name="AwesomeFrida", url="https://github.com/dweinstein/awesome-frida", source_type=SourceType.GITHUB_REPO, domain="mobile", category="dynamic_instrumentation", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["frida", "awesome-list"], description="Awesome Frida resources."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_MOBILE_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_MOBILE_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="WithSecureAndroidTutorials", url="https://github.com/WithSecureLabs/android-tutorials", source_type=SourceType.GITHUB_REPO, domain="mobile", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["android", "exploitation"], description="WithSecure Android security tutorials."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_MOBILE_EXPLOITS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# IOT — IoT, hardware, firmware, radio protocols
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_IOT_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="IoTSecurity101", url="https://github.com/V33RU/IoTSecurity101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["iot", "security"], description="IoT Security 101."),
    SourceConfig(name="OWASP-FSTM", url="https://github.com/scriptingxss/owasp-fstm", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "firmware", "testing"], description="OWASP Firmware Security Testing Methodology."),
    SourceConfig(name="OWASP-IoT", url="https://github.com/OWASP/www-project-internet-of-things", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot"], description="OWASP IoT project."),
    SourceConfig(name="OWASP-IoTTop10", url="https://github.com/OWASP/IoT-Top-Ten", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot", "top10"], description="OWASP IoT Top 10."),
    SourceConfig(name="PayatuIoTSecurity101", url="https://github.com/payatu/IoT-Security-101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["iot", "payatu"], description="Payatu IoT Security 101."),
    SourceConfig(name="AwesomeIoTHacks", url="https://github.com/nebgnahz/awesome-iot-hacks", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["iot", "hacks"], description="Awesome IoT hacks."),
    SourceConfig(name="HardwareAllTheThings", url="https://github.com/swisskyrepo/HardwareAllTheThings", source_type=SourceType.GITHUB_REPO, domain="iot", category="hardware_interfaces", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["hardware", "uart", "jtag", "spi", "ble", "zigbee", "rf"], license="MIT", description="Hardware/IoT pentesting — UART, JTAG, SPI, BLE, ZigBee, RF."),
    SourceConfig(name="EmbeddedAppSec", url="https://github.com/scriptingxss/embeddedappsec", source_type=SourceType.GITHUB_REPO, domain="iot", category="firmware", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["embedded", "firmware"], description="Embedded application security guide."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_IOT_STRATEGIES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# CLOUD — Cloud security (AWS, Azure, GCP, K8s)
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_CLOUD_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="HackingTheCloud", url="https://github.com/Hacking-the-Cloud/hackingthe.cloud", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws", "azure", "gcp"], description="Hacking the Cloud encyclopedia."),
    SourceConfig(name="StratusRedTeam", url="https://github.com/DataDog/stratus-red-team", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md", "**/*.yaml"], tags=["cloud", "red-team", "detection"], description="Stratus Red Team — cloud attack simulation."),
    SourceConfig(name="CloudGoat", url="https://github.com/RhinoSecurityLabs/cloudgoat", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["cloud", "aws", "labs"], description="CloudGoat — vulnerable AWS deployment."),
    SourceConfig(name="CloudPentestCheatsheets", url="https://github.com/dafthack/CloudPentestCheatsheets", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["cloud", "cheatsheets"], description="Cloud pentest cheatsheets."),
    SourceConfig(name="OWASP-K8sTop10", url="https://github.com/OWASP/www-project-kubernetes-top-ten", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "k8s", "owasp", "top10"], description="OWASP Kubernetes Top 10."),
    SourceConfig(name="K8sThreatMatrix", url="https://github.com/kubernetes-threat-matrix/threat-matrix-for-kubernetes", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "threat-matrix"], description="MITRE threat matrix for K8s."),
    SourceConfig(name="K8sSecurity", url="https://github.com/sergiomarotco/k8s-security", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "security"], description="K8s security best practices."),
    SourceConfig(name="ContainerEscapeCheck", url="https://github.com/BishopFox/container-escape-check", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["container", "escape"], description="Container escape detection."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_CLOUD_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_CLOUD_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="CloudFoxable", url="https://github.com/BishopFox/cloudfoxable", source_type=SourceType.GITHUB_REPO, domain="cloud", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws"], description="CloudFoxable — exploitable cloud environment."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_CLOUD_EXPLOITS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE — Internal pentest, AD, privilege escalation
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_INFRASTRUCTURE_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="main", clone_id="InternalAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["active-directory", "internal", "kerberos"], license="MIT", description="AD & internal pentest cheatsheets."),
    SourceConfig(name="OSCP-Notes", url="https://github.com/0xsyr0/OSCP", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["oscp", "methodology"], description="OSCP notes and cheatsheets."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_INFRASTRUCTURE_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_INFRASTRUCTURE_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="ADExploitCheatSheet", url="https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="active_directory", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["active-directory", "exploitation"], description="AD exploitation cheat sheet."),
    SourceConfig(name="GOAD", url="https://github.com/Orange-Cyberdefense/GOAD", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="active_directory", content_type=ContentType.ATTACK_TYPES, branch="main", include_patterns=["**/*.md"], tags=["active-directory", "lab", "goad"], description="Game of Active Directory."),
    SourceConfig(name="GTFOBins", url="https://gtfobins.github.io/", source_type=SourceType.WEBSITE, domain="infrastructure", category="privilege_escalation", content_type=ContentType.ATTACK_TYPES, priority=1, include_patterns=["https://gtfobins.github.io/gtfobins/**"], css_selector="article.bins", max_pages=500, default_metadata={"target": "infrastructure", "attack_phase": "privilege_escalation", "platform": ["linux"]}, tags=["gtfobins", "linux", "privilege-escalation"], description="GTFOBins — Unix binaries for privesc."),
    SourceConfig(name="LOLBAS", url="https://lolbas-project.github.io/", source_type=SourceType.WEBSITE, domain="infrastructure", category="privilege_escalation", content_type=ContentType.ATTACK_TYPES, priority=1, include_patterns=["https://lolbas-project.github.io/lolbas/**"], css_selector=".main-content", max_pages=500, default_metadata={"target": "infrastructure", "attack_phase": "privilege_escalation", "platform": ["windows"]}, tags=["lolbas", "windows", "living-off-the-land"], description="LOLBAS — Living Off The Land Binaries for Windows."),
    SourceConfig(name="Infra-WindowsPersistence", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Windows - Persistence.md"], tags=["windows", "persistence"], description="Windows persistence techniques."),
    SourceConfig(name="Infra-LinuxPersistence", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Linux - Persistence.md"], tags=["linux", "persistence"], description="Linux persistence techniques."),
    SourceConfig(name="Infra-CredentialAccess", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Credential Access.md"], tags=["credentials", "dumping"], description="Credential access techniques."),
    SourceConfig(name="Infra-LateralMovement", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Lateral Movement.md"], tags=["lateral-movement", "pivoting"], description="Lateral movement techniques."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_INFRASTRUCTURE_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# NETWORK — Network pentesting, wireless
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_NETWORK_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings-Network", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", content_type=ContentType.STRATEGIES, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/redteam/pivoting", include_patterns=["**/*.md"], tags=["network", "pivoting", "internal"], description="InternalAllTheThings — network pivoting techniques and tools."),
    SourceConfig(name="InternalAllTheThings-NetDiscovery", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", content_type=ContentType.STRATEGIES, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/cheatsheets", include_patterns=["**/network-discovery.md"], tags=["network", "discovery", "nmap"], description="InternalAllTheThings — network discovery (nmap, masscan, etc.)."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_NETWORK_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Tools (fixed) ───────────────────────────────────────────────────────
_NETWORK_TOOLS_FIXED: list[SourceConfig] = [
    SourceConfig(name="H4cker-NetToolCheatsheets", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/networking", include_patterns=["**/*.md"], tags=["nmap", "wireshark", "tcpdump", "netcat", "scapy", "tshark"], description="H4cker — network tool cheat sheets (nmap, wireshark, tcpdump, netcat, scapy)."),
    SourceConfig(name="H4cker-NetToolsCatalog", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="organized_tools", include_patterns=["**/networking_tools.md"], tags=["network-tools", "catalog"], description="H4cker — curated catalog of networking tools."),
    SourceConfig(name="H4cker-WirelessTools", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="wireless-resources", include_patterns=["**/*.md"], tags=["wireless", "wifi", "responder", "network-tools"], description="H4cker — wireless hacking tools and resources."),
]

# ── Tools (variable — Intel agent managed) ─────────────────────────────────────
_NETWORK_TOOLS_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_NETWORK_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="H4cker-ProtocolExploits", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/networking", include_patterns=["**/insecure-protocols.md"], tags=["arp-poisoning", "dns-poisoning", "vlan-hopping", "protocol-exploits"], description="H4cker — insecure protocol exploitation (ARP, DNS, DHCP, VLAN)."),
    SourceConfig(name="H4cker-ExploitFrameworks", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/exploitation", include_patterns=["**/*.md"], tags=["metasploit", "msfvenom", "network-exploitation"], description="H4cker — exploitation frameworks (metasploit, msfvenom)."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_NETWORK_EXPLOITS_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_NETWORK_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="PayloadsAllTheThings-DNSRebinding", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="DNS Rebinding", include_patterns=["**/*.md"], tags=["dns", "dns-rebinding", "network-payloads"], description="PayloadsAllTheThings — DNS rebinding attack payloads."),
    SourceConfig(name="PayloadsAllTheThings-LDAP", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="LDAP Injection", include_patterns=["**/*.md"], tags=["ldap", "ldap-injection", "network-payloads"], description="PayloadsAllTheThings — LDAP injection payloads."),
    SourceConfig(name="MitreAttack-Discovery", url="https://attack.mitre.org/tactics/TA0007/", source_type=SourceType.WEBSITE, domain="network", category="attack-types", content_type=ContentType.ATTACK_TYPES, max_pages=30, tags=["mitre", "discovery", "T1046", "T1040", "network-scanning"], description="MITRE ATT&CK Discovery tactic — network service discovery, sniffing, etc."),
    SourceConfig(name="MitreAttack-LateralMovement", url="https://attack.mitre.org/tactics/TA0008/", source_type=SourceType.WEBSITE, domain="network", category="attack-types", content_type=ContentType.ATTACK_TYPES, max_pages=30, tags=["mitre", "lateral-movement", "T1557", "T1021", "network-attacks"], description="MITRE ATT&CK Lateral Movement tactic — MITM, remote services, etc."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_NETWORK_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# RECON — Reconnaissance and OSINT
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_RECON_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="AwesomeOSINT", url="https://github.com/jivoi/awesome-osint", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["osint", "recon"], description="Awesome OSINT resources."),
    SourceConfig(name="Recon-Subdomain", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Subdomains Enumeration.md"], tags=["recon", "subdomains"], description="Subdomain enumeration methodology."),
    SourceConfig(name="Recon-ScopeAndRecon", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Methodology and enumeration.md"], tags=["recon", "methodology"], description="Recon methodology and enumeration."),
    SourceConfig(name="AwesomeAssetDiscovery", url="https://github.com/redhuntlabs/Awesome-Asset-Discovery", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["recon", "asset-discovery"], description="Awesome Asset Discovery resources."),
    SourceConfig(name="InternalAllTheThings-Recon", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", content_type=ContentType.STRATEGIES, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/recon", include_patterns=["**/*.md"], tags=["recon", "internal"], description="InternalAllTheThings — recon techniques."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_RECON_STRATEGIES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# RED_TEAM — Red team operations
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_RED_TEAM_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="RedTeamInfraWiki", url="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki", source_type=SourceType.GITHUB_REPO, domain="red_team", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["red-team", "infrastructure", "c2"], description="Red Team Infrastructure Wiki."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_RED_TEAM_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Tools (fixed) ───────────────────────────────────────────────────────
_RED_TEAM_TOOLS_FIXED: list[SourceConfig] = [
    SourceConfig(name="MythicC2-Docs", url="https://docs.mythic-c2.net/", source_type=SourceType.WEBSITE, domain="red_team", category="c2_knowledge", content_type=ContentType.TOOLS, max_pages=200, tags=["mythic", "c2"], description="Mythic C2 documentation."),
    SourceConfig(name="SliverC2-Wiki", url="https://github.com/BishopFox/sliver", source_type=SourceType.GITHUB_REPO, domain="red_team", category="c2_knowledge", content_type=ContentType.TOOLS, branch="master", include_patterns=["**/*.md"], tags=["sliver", "c2"], description="Sliver C2 wiki."),
]

# ── Tools (variable — Intel agent managed) ─────────────────────────────────────
_RED_TEAM_TOOLS_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_RED_TEAM_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="RT-Phishing", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="red_team", category="payloads_evasion", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Phishing.md"], tags=["phishing", "social-engineering"], description="Phishing techniques."),
    SourceConfig(name="RT-ReverseShells", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="red_team", category="payloads_evasion", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Reverse Shell Cheatsheet.md"], tags=["reverse-shell", "payloads"], description="Reverse shell cheatsheet."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_RED_TEAM_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# BINARY — Binary exploitation and reverse engineering
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_BINARY_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="Ir0nstoneNotes", url="https://ir0nstone.gitbook.io/notes", source_type=SourceType.GITBOOK, domain="binary", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["binary", "exploitation", "rop", "heap"], description="ir0nstone's binary exploitation notes."),
    SourceConfig(name="CTFAllInOne", url="https://github.com/firmianay/CTF-All-In-One", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["ctf", "binary"], description="CTF All-In-One guide."),
    SourceConfig(name="BinaryExploitation-Payloads", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Binary Exploitation", include_patterns=["**/*.md"], tags=["binary", "exploitation"], description="Binary exploitation payloads."),
    SourceConfig(name="RPISEC-MBE", url="https://github.com/RPISEC/MBE", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["binary", "education"], description="RPISEC Modern Binary Exploitation."),
    SourceConfig(name="ARMExploitation", url="https://github.com/IOActive/ARM-Exploitation", source_type=SourceType.GITHUB_REPO, domain="binary", category="arm_embedded", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["arm", "exploitation", "embedded"], description="ARM exploitation techniques."),
    SourceConfig(name="ReverseEngineeringBeginners", url="https://github.com/malware-unicorn/reverse-engineering-for-beginners", source_type=SourceType.GITHUB_REPO, domain="binary", category="reverse_engineering", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["reverse-engineering", "malware"], description="Reverse engineering for beginners."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_BINARY_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Attack Types (fixed) ────────────────────────────────────────────────
_BINARY_ATTACK_TYPES_FIXED: list[SourceConfig] = [
    SourceConfig(name="How2Heap", url="https://github.com/shellphish/how2heap", source_type=SourceType.GITHUB_REPO, domain="binary", category="techniques", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md", "**/*.c"], tags=["heap", "exploitation"], description="How2Heap — heap exploitation techniques."),
    SourceConfig(name="CTFPwnTips", url="https://github.com/Naetw/CTF-pwn-tips", source_type=SourceType.GITHUB_REPO, domain="binary", category="techniques", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["ctf", "pwn"], description="CTF pwn tips."),
]

# ── Attack Types (variable — Intel agent managed) ──────────────────────────────
_BINARY_ATTACK_TYPES_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# IDENTITY — Identity security (AAD, OAuth, SAML, Kerberos)
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_IDENTITY_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="AzureADAttackDefense", url="https://github.com/dirkjanm/AzureAD-Attack-Defense", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["azure-ad", "identity"], description="Azure AD attack and defense."),
    SourceConfig(name="Identity-OAuthMisconfig", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="OAuth Misconfiguration", include_patterns=["**/*.md"], tags=["oauth", "identity"], description="OAuth misconfiguration attacks."),
    SourceConfig(name="Identity-JWTAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="JSON Web Token", include_patterns=["**/*.md"], tags=["jwt", "identity"], description="JWT attack techniques."),
    SourceConfig(name="Identity-SAMLAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="SAML Injection", include_patterns=["**/*.md"], tags=["saml", "identity", "sso-bypass"], description="SAML attack techniques."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_IDENTITY_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_IDENTITY_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings-AzureAD", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/cloud", include_patterns=["**/azure-azure-active-directory.md", "**/azure-azure-ad-connect.md"], tags=["azure-ad", "exploitation"], description="Azure AD exploitation techniques."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_IDENTITY_EXPLOITS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# SUPPLY_CHAIN — CI/CD, dependency confusion, IaC
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_SUPPLY_CHAIN_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-CICDTop10", url="https://github.com/OWASP/www-project-top-10-ci-cd-security-risks", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["cicd", "owasp", "supply-chain"], description="OWASP Top 10 CI/CD Security Risks."),
    SourceConfig(name="OSSFScorecard", url="https://github.com/ossf/scorecard", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["ossf", "supply-chain"], description="OpenSSF Scorecard."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_SUPPLY_CHAIN_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_SUPPLY_CHAIN_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="DependencyConfusion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Dependency Confusion", include_patterns=["**/*.md"], tags=["dependency-confusion", "supply-chain"], description="Dependency confusion exploitation."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_SUPPLY_CHAIN_EXPLOITS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# WEB3 — Smart contracts, DeFi, blockchain
# ═════════════════════════════════════════════════════════════════════════════

# ── Strategies (fixed) ──────────────────────────────────────────────────
_WEB3_STRATEGIES_FIXED: list[SourceConfig] = [
    SourceConfig(name="NotSoSmartContracts", url="https://github.com/crytic/not-so-smart-contracts", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md", "**/*.sol"], tags=["solidity", "smart-contracts"], description="Not So Smart Contracts vulnerabilities."),
    SourceConfig(name="SmartContractVulnerabilities", url="https://github.com/kadenzipfel/smart-contract-vulnerabilities", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["smart-contracts", "vulnerabilities"], description="Smart contract vulnerability patterns."),
    SourceConfig(name="SoliditySecurityBlog", url="https://github.com/sigp/solidity-security-blog", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["solidity", "security"], description="Solidity security attack patterns."),
    SourceConfig(name="SWCRegistry", url="https://swcregistry.io/", source_type=SourceType.WEBSITE, domain="web3", category="methodology", content_type=ContentType.STRATEGIES, max_pages=100, tags=["swc", "smart-contracts"], description="SWC Registry."),
    SourceConfig(name="SmartContractBestPractices", url="https://github.com/ConsenSys/smart-contract-best-practices", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["smart-contracts", "best-practices"], description="ConsenSys smart contract best practices."),
]

# ── Strategies (variable — Intel agent managed) ────────────────────────────────
_WEB3_STRATEGIES_VARIABLE: list[SourceConfig] = []

# ── Exploits (fixed) ────────────────────────────────────────────────────
_WEB3_EXPLOITS_FIXED: list[SourceConfig] = [
    SourceConfig(name="Web3SecurityLibrary", url="https://github.com/immunefi-team/Web3-Security-Library", source_type=SourceType.GITHUB_REPO, domain="web3", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["web3", "security", "immunefi"], description="Immunefi Web3 Security Library."),
    SourceConfig(name="DamnVulnerableDeFi", url="https://github.com/damnvulnerabledefi/damn-vulnerable-defi", source_type=SourceType.GITHUB_REPO, domain="web3", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", include_patterns=["**/*.md"], tags=["defi", "vulnerable"], description="Damn Vulnerable DeFi challenges."),
]

# ── Exploits (variable — Intel agent managed) ──────────────────────────────────
_WEB3_EXPLOITS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# COMPLIANCE — Reporting and compliance frameworks
# ═════════════════════════════════════════════════════════════════════════════

# ── Standards (fixed) ───────────────────────────────────────────────────
_COMPLIANCE_STANDARDS_FIXED: list[SourceConfig] = [
    SourceConfig(name="OWASP-SAMM", url="https://github.com/OWASP/owasp-samm", source_type=SourceType.GITHUB_REPO, domain="compliance", category="frameworks", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["owasp", "samm", "maturity-model"], description="OWASP SAMM."),
    SourceConfig(name="PublicPentestReports", url="https://github.com/juliocesarfort/public-pentesting-reports", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["reports", "pentest"], description="Public penetration testing reports."),
    SourceConfig(name="TCMSampleReport", url="https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md", "**/*.pdf"], tags=["report", "template"], description="TCM Security sample report."),
    SourceConfig(name="ReconmapReportTemplates", url="https://github.com/reconmap/pentest-report-templates", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", content_type=ContentType.STANDARDS, branch="main", include_patterns=["**/*.md"], tags=["reports", "templates"], description="Reconmap report templates."),
]

# ── Standards (variable — Intel agent managed) ─────────────────────────────────
_COMPLIANCE_STANDARDS_VARIABLE: list[SourceConfig] = []


# ═════════════════════════════════════════════════════════════════════════════
# CVE_EXPLOIT
# ═════════════════════════════════════════════════════════════════════════════


# ═════════════════════════════════════════════════════════════════════════════
# RUNTIME APIS — Never embedded, called live at scan time
# ═════════════════════════════════════════════════════════════════════════════

_RUNTIME_APIS: list[SourceConfig] = [
    SourceConfig(name="Shodan", url="https://api.shodan.io", source_type=SourceType.API, domain="recon", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, api_params={"key": "env:SHODAN_API_KEY"}, tags=["shodan", "recon", "iot"], description="Shodan API — live asset discovery and banner grabbing."),
    SourceConfig(name="Censys", url="https://search.censys.io/api", source_type=SourceType.API, domain="recon", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, api_params={"key": "env:CENSYS_API_KEY"}, tags=["censys", "recon", "certificates"], description="Censys API — internet-wide scan data and certificate search."),
    SourceConfig(name="CrtSh", url="https://crt.sh", source_type=SourceType.API, domain="recon", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, tags=["crt.sh", "certificates", "subdomains"], description="crt.sh — certificate transparency log search."),
    SourceConfig(name="HIBP", url="https://haveibeenpwned.com/api/v3", source_type=SourceType.API, domain="recon", category="credential_intel", content_type=ContentType.STRATEGIES, is_runtime=True, api_params={"key": "env:HIBP_API_KEY"}, tags=["hibp", "breach", "credentials"], description="Have I Been Pwned API — breach and paste lookups."),
    SourceConfig(name="VirusTotal", url="https://www.virustotal.com/api/v3", source_type=SourceType.API, domain="recon", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:VT_API_KEY"}, tags=["virustotal", "malware", "ioc"], description="VirusTotal API — file, URL, domain, and IP analysis."),
    SourceConfig(name="GreyNoise", url="https://api.greynoise.io/v3", source_type=SourceType.API, domain="recon", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:GREYNOISE_API_KEY"}, tags=["greynoise", "noise", "threat-intel"], description="GreyNoise API — internet scanner and mass-exploitation detection."),
    SourceConfig(name="AbuseIPDB", url="https://api.abuseipdb.com/api/v2", source_type=SourceType.API, domain="recon", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:ABUSEIPDB_API_KEY"}, tags=["abuseipdb", "ip-reputation"], description="AbuseIPDB API — IP abuse reporting and lookup."),
    SourceConfig(name="NVD-Runtime", url="https://services.nvd.nist.gov/rest/json/cves/2.0", source_type=SourceType.API, domain="cve_exploit", category="intelligence", content_type=ContentType.EXPLOITS, is_runtime=True, priority=1, api_params={"key": "env:NVD_API_KEY"}, tags=["cve", "nvd", "vulnerability"], description="NVD CVE 2.0 API — live vulnerability lookups."),
    SourceConfig(name="ExploitDB-Runtime", url="https://exploit-db.com", source_type=SourceType.API, domain="cve_exploit", category="exploits", content_type=ContentType.EXPLOITS, is_runtime=True, priority=1, tags=["exploitdb", "exploits"], description="ExploitDB — searchsploit queries at runtime."),
    SourceConfig(name="GitHub-SecLists", url="https://api.github.com/repos/danielmiessler/SecLists", source_type=SourceType.API, domain="shared", category="wordlists", content_type=ContentType.TOOLS, is_runtime=True, priority=1, tags=["seclists", "wordlists"], description="SecLists — wordlists fetched at runtime via GitHub API."),
]


# ═════════════════════════════════════════════════════════════════════════════
# PAYLOAD SOURCES — Raw payload strings → PayloadStore (JSON), NOT Qdrant
# ═════════════════════════════════════════════════════════════════════════════


class PayloadSourceConfig(BaseModel):
    """Configuration for a raw payload source (goes to PayloadStore, not Qdrant)."""
    name: str
    url: str
    domain: str
    category: str
    branch: str = "master"
    clone_id: str | None = None
    subdirectory: str | None = None
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.txt"])
    tags: list[str] = Field(default_factory=list)
    description: str = ""


# ── Web payloads ────────────────────────────────────────────────────────
_WEB_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="FuzzDB-SQLi", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="sqli", branch="master", clone_id="fuzzdb", subdirectory="attack/sql-injection", include_patterns=["**/*.txt"], tags=["sqli", "fuzzdb"], description="FuzzDB — SQL injection payloads (detect, exploit, blind)."),
    PayloadSourceConfig(name="FuzzDB-XSS", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="xss", branch="master", clone_id="fuzzdb", subdirectory="attack/xss", include_patterns=["**/*.txt"], tags=["xss", "fuzzdb"], description="FuzzDB — XSS payloads (polyglots, event handlers, URI-based)."),
    PayloadSourceConfig(name="FuzzDB-OSCmd", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="command_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/os-cmd-execution", include_patterns=["**/*.txt"], tags=["command-injection", "rce", "fuzzdb"], description="FuzzDB — OS command injection payloads (Linux, Windows, PowerShell)."),
    PayloadSourceConfig(name="FuzzDB-LFI", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="lfi", branch="master", clone_id="fuzzdb", subdirectory="attack/lfi", include_patterns=["**/*.txt"], tags=["lfi", "path-traversal", "fuzzdb"], description="FuzzDB — local file inclusion / path traversal payloads."),
    PayloadSourceConfig(name="FuzzDB-FileUpload", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="file_upload", branch="master", clone_id="fuzzdb", subdirectory="attack/file-upload", include_patterns=["**/*.txt"], tags=["file-upload", "fuzzdb"], description="FuzzDB — file upload bypass payloads and malicious extensions."),
    PayloadSourceConfig(name="FuzzDB-LDAP", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="ldap_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/ldap", include_patterns=["**/*.txt"], tags=["ldap", "injection", "fuzzdb"], description="FuzzDB — LDAP injection payloads."),
    PayloadSourceConfig(name="FuzzDB-XPath", url="https://github.com/fuzzdb-project/fuzzdb", domain="web", category="xpath_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/xpath", include_patterns=["**/*.txt"], tags=["xpath", "injection", "fuzzdb"], description="FuzzDB — XPath injection payloads."),
    PayloadSourceConfig(name="H4cker-XSSPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web", category="xss", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/more-xxs-payloads.txt", "**/xss_obfuscation_vectors.txt"], tags=["xss", "obfuscation"], description="H4cker — XSS payloads and obfuscation vectors."),
    PayloadSourceConfig(name="H4cker-SQLiPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web", category="sqli", branch="master", clone_id="h4cker", subdirectory="more-payloads/SQLi", include_patterns=["**/*.txt"], tags=["sqli"], description="H4cker — SQL injection payloads (blind, MSSQL, MySQL, PostgreSQL)."),
    PayloadSourceConfig(name="H4cker-CmdInjPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web", category="command_injection", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/command_injection_unix.txt"], tags=["command-injection", "unix"], description="H4cker — Unix command injection payloads."),
    PayloadSourceConfig(name="H4cker-SSTIPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web", category="ssti", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/server-side-template-injection.txt"], tags=["ssti", "template-injection"], description="H4cker — server-side template injection payloads."),
    PayloadSourceConfig(name="H4cker-XXEPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web", category="xxe", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/xxe-injection-payloads.md"], tags=["xxe", "xml"], description="H4cker — XXE injection payloads."),
    PayloadSourceConfig(name="IntruderPayloads-SQLi", url="https://github.com/1N3/IntruderPayloads", domain="web", category="sqli", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/sqli-*.txt"], tags=["sqli", "intruder"], description="IntruderPayloads — SQLi error-based and time-based fuzz lists."),
    PayloadSourceConfig(name="IntruderPayloads-XSS", url="https://github.com/1N3/IntruderPayloads", domain="web", category="xss", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/xss*.txt"], tags=["xss", "intruder"], description="IntruderPayloads — XSS fuzz lists."),
    PayloadSourceConfig(name="IntruderPayloads-LFI", url="https://github.com/1N3/IntruderPayloads", domain="web", category="lfi", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/lfi.txt"], tags=["lfi", "intruder"], description="IntruderPayloads — LFI fuzz list."),
    PayloadSourceConfig(name="IntruderPayloads-CmdExec", url="https://github.com/1N3/IntruderPayloads", domain="web", category="command_injection", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/command_exec.txt"], tags=["command-injection", "intruder"], description="IntruderPayloads — command execution fuzz list."),
]

PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    *_WEB_PAYLOAD_SOURCES,
]


# ═════════════════════════════════════════════════════════════════════════════
# AGGREGATE REGISTRY
# ═════════════════════════════════════════════════════════════════════════════

ALL_SOURCES: list[SourceConfig] = [
    # SHARED
    *_SHARED_STRATEGIES_FIXED,
    *_SHARED_STRATEGIES_VARIABLE,
    *_SHARED_EXPLOITS_FIXED,
    *_SHARED_EXPLOITS_VARIABLE,
    *_SHARED_TOOLS_FIXED,
    *_SHARED_TOOLS_VARIABLE,
    *_SHARED_STANDARDS_FIXED,
    *_SHARED_STANDARDS_VARIABLE,
    *_SHARED_ATTACK_TYPES_FIXED,
    *_SHARED_ATTACK_TYPES_VARIABLE,

    # WEB
    *_WEB_STRATEGIES_FIXED,
    *_WEB_STRATEGIES_VARIABLE,
    *_WEB_ATTACK_TYPES_FIXED,
    *_WEB_ATTACK_TYPES_VARIABLE,
    *_WEB_TOOLS_FIXED,
    *_WEB_TOOLS_VARIABLE,

    # API
    *_API_STRATEGIES_FIXED,
    *_API_STRATEGIES_VARIABLE,
    *_API_STANDARDS_FIXED,
    *_API_STANDARDS_VARIABLE,
    *_API_ATTACK_TYPES_FIXED,
    *_API_ATTACK_TYPES_VARIABLE,

    # MOBILE
    *_MOBILE_STRATEGIES_FIXED,
    *_MOBILE_STRATEGIES_VARIABLE,
    *_MOBILE_EXPLOITS_FIXED,
    *_MOBILE_EXPLOITS_VARIABLE,

    # IOT
    *_IOT_STRATEGIES_FIXED,
    *_IOT_STRATEGIES_VARIABLE,

    # CLOUD
    *_CLOUD_STRATEGIES_FIXED,
    *_CLOUD_STRATEGIES_VARIABLE,
    *_CLOUD_EXPLOITS_FIXED,
    *_CLOUD_EXPLOITS_VARIABLE,

    # INFRASTRUCTURE
    *_INFRASTRUCTURE_STRATEGIES_FIXED,
    *_INFRASTRUCTURE_STRATEGIES_VARIABLE,
    *_INFRASTRUCTURE_ATTACK_TYPES_FIXED,
    *_INFRASTRUCTURE_ATTACK_TYPES_VARIABLE,

    # NETWORK
    *_NETWORK_STRATEGIES_FIXED,
    *_NETWORK_STRATEGIES_VARIABLE,
    *_NETWORK_TOOLS_FIXED,
    *_NETWORK_TOOLS_VARIABLE,
    *_NETWORK_EXPLOITS_FIXED,
    *_NETWORK_EXPLOITS_VARIABLE,
    *_NETWORK_ATTACK_TYPES_FIXED,
    *_NETWORK_ATTACK_TYPES_VARIABLE,

    # RECON
    *_RECON_STRATEGIES_FIXED,
    *_RECON_STRATEGIES_VARIABLE,

    # RED_TEAM
    *_RED_TEAM_STRATEGIES_FIXED,
    *_RED_TEAM_STRATEGIES_VARIABLE,
    *_RED_TEAM_TOOLS_FIXED,
    *_RED_TEAM_TOOLS_VARIABLE,
    *_RED_TEAM_ATTACK_TYPES_FIXED,
    *_RED_TEAM_ATTACK_TYPES_VARIABLE,

    # BINARY
    *_BINARY_STRATEGIES_FIXED,
    *_BINARY_STRATEGIES_VARIABLE,
    *_BINARY_ATTACK_TYPES_FIXED,
    *_BINARY_ATTACK_TYPES_VARIABLE,

    # IDENTITY
    *_IDENTITY_STRATEGIES_FIXED,
    *_IDENTITY_STRATEGIES_VARIABLE,
    *_IDENTITY_EXPLOITS_FIXED,
    *_IDENTITY_EXPLOITS_VARIABLE,

    # SUPPLY_CHAIN
    *_SUPPLY_CHAIN_STRATEGIES_FIXED,
    *_SUPPLY_CHAIN_STRATEGIES_VARIABLE,
    *_SUPPLY_CHAIN_EXPLOITS_FIXED,
    *_SUPPLY_CHAIN_EXPLOITS_VARIABLE,

    # WEB3
    *_WEB3_STRATEGIES_FIXED,
    *_WEB3_STRATEGIES_VARIABLE,
    *_WEB3_EXPLOITS_FIXED,
    *_WEB3_EXPLOITS_VARIABLE,

    # COMPLIANCE
    *_COMPLIANCE_STANDARDS_FIXED,
    *_COMPLIANCE_STANDARDS_VARIABLE,

    # Runtime APIs — never embedded, queried live by agents at scan time
    *_RUNTIME_APIS,
]


_all_names = [s.name.lower() for s in ALL_SOURCES]
_dupes = [n for n in _all_names if _all_names.count(n) > 1]
assert not _dupes, f"Duplicate source names in ALL_SOURCES: {set(_dupes)}"


@lru_cache(maxsize=1)
def _build_name_index() -> dict[str, SourceConfig]:
    """Lazy O(1) lookup index keyed by lowercased name."""
    return {s.name.lower(): s for s in ALL_SOURCES}


def get_enabled_sources() -> list[SourceConfig]:
    """All enabled sources (excludes runtime APIs)."""
    return [s for s in ALL_SOURCES if s.enabled and not s.is_runtime]


def get_runtime_sources() -> list[SourceConfig]:
    """All runtime API sources — called live at scan time, never embedded."""
    return [s for s in ALL_SOURCES if s.is_runtime and s.enabled]


def get_sources_by_domain(domain: str) -> list[SourceConfig]:
    """Get all enabled, non-runtime sources for a specific domain."""
    return [s for s in ALL_SOURCES if s.domain == domain and s.enabled and not s.is_runtime]


def get_sources_by_type(source_type: SourceType) -> list[SourceConfig]:
    """Filter sources by extraction type."""
    return [s for s in ALL_SOURCES if s.source_type == source_type and s.enabled]


def get_source_by_name(name: str) -> SourceConfig | None:
    """Lookup a source by name (case-insensitive). O(1) via cached index."""
    return _build_name_index().get(name.lower())


def get_all_domains() -> list[str]:
    """Return all unique domain names from the source registry."""
    return sorted(set(s.domain for s in ALL_SOURCES))


def get_sources_by_priority(priority: int) -> list[SourceConfig]:
    """Get all enabled sources at a specific priority level."""
    return [s for s in ALL_SOURCES if s.priority == priority and s.enabled and not s.is_runtime]


def get_sources_by_content_type(content_type: ContentType) -> list[SourceConfig]:
    """Get all enabled, non-runtime sources for a specific content type."""
    return [s for s in ALL_SOURCES if s.content_type == content_type and s.enabled and not s.is_runtime]


def get_fixed_sources() -> list[SourceConfig]:
    """Get all fixed (curated baseline) sources."""
    return [s for s in ALL_SOURCES if s.is_fixed and s.enabled and not s.is_runtime]


def get_variable_sources() -> list[SourceConfig]:
    """Get all variable (Intel agent updateable) sources."""
    return [s for s in ALL_SOURCES if not s.is_fixed and s.enabled and not s.is_runtime]

