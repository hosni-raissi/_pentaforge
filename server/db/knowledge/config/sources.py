"""
Source Registry — Central definition of ALL cybersecurity knowledge sources.

Architecture:
  - Sources organized by domain (shared, web, api, mobile, iot, cloud, etc.)
  - Each source maps to a domain → vector index
  - api_runtime sources are NEVER embedded — fetched live at scan time
  - Shared sources ingested ONCE into vector_shared, queried by all agents
  - Tools referenced as metadata only — NO tool repos in RAG
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field

from server.db.knowledge.models.document import SourceType

__all__ = [
    "SourceConfig",
    "ALL_SOURCES",
    "get_enabled_sources",
    "get_runtime_sources",
    "get_sources_by_domain",
    "get_sources_by_type",
    "get_source_by_name",
    "get_all_domains",
    "get_sources_by_priority",
]


class SourceConfig(BaseModel):
    """Configuration for a single knowledge source."""
    name: str
    url: str
    source_type: SourceType
    domain: str = "shared"
    category: str = "general"
    enabled: bool = True
    is_runtime: bool = False          # True = never embedded, called live at scan time
    priority: int = Field(default=2, ge=1, le=3)  # 1=critical, 2=standard, 3=supplementary
    branch: str = "master"            # NOTE: many repos use "main" — always set explicitly
    subdirectory: str | None = None
    clone_id: str | None = None       # Group sources that share a repo clone (e.g. "PayloadsAllTheThings")
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.md"])
    exclude_patterns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    license: str | None = None
    description: str = ""
    # Default metadata stamped on every chunk from this source.
    # Keys must match KnowledgeChunk field names (e.g. target, attack_phase, platform).
    # Only fills empty fields — never overwrites chunk-level values.
    default_metadata: dict[str, Any] = Field(default_factory=dict)
    # API-specific — values prefixed with "env:" are resolved from environment variables
    api_params: dict[str, str] = Field(default_factory=dict)
    # Website-specific
    css_selector: str | None = None
    max_pages: int = 1000


# ═══════════════════════════════════════════════════════════════════════════════
# _SHARED — Ingested ONCE into vector_shared. All agents query this index.
# ═══════════════════════════════════════════════════════════════════════════════

_SHARED_METHODOLOGY: list[SourceConfig] = [
    SourceConfig(name="HackTricks", url="https://github.com/HackTricks-wiki/hacktricks", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", priority=1, branch="master", subdirectory="src", include_patterns=["**/*.md"], exclude_patterns=["**/SUMMARY.md", "**/banners/**"], tags=["hacktricks", "web", "pentest", "methodology"], license="CC-BY-NC-4.0", description="HackTricks — comprehensive pentest tricks & techniques."),
    SourceConfig(name="HackTricks-Book", url="https://book.hacktricks.xyz/", source_type=SourceType.GITBOOK, domain="shared", category="methodology", priority=1, max_pages=1500, tags=["hacktricks", "methodology"], description="HackTricks Book — GitBook version."),
    SourceConfig(name="PayloadsAllTheThings", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", priority=1, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["payloads", "injection", "bypass", "methodology"], license="MIT", description="PayloadsAllTheThings — payloads, bypass techniques, methodology."),
    # NOTE: SecLists is NOT in RAG — wordlists are fetched at runtime by agents via GitHub API.
    # Repo structure: https://github.com/danielmiessler/SecLists/tree/master
    SourceConfig(name="RedTeamingToolkit", url="https://github.com/infosecn1nja/Red-Teaming-Toolkit", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["red-team", "methodology"], description="Red Teaming Toolkit reference."),
    SourceConfig(name="AtomicRedTeam", url="https://github.com/redcanaryco/atomic-red-team", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", priority=1, branch="master", include_patterns=["**/*.md", "**/*.yaml"], exclude_patterns=["**/LICENSE*"], tags=["atomic", "red-team", "mitre", "testing"], license="MIT", description="Atomic Red Team — portable detection tests."),
    SourceConfig(name="AdversaryEmulationLibrary", url="https://github.com/center-for-threat-informed-defense/adversary_emulation_library", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", branch="master", include_patterns=["**/*.md", "**/*.yaml"], tags=["emulation", "mitre", "apt", "campaigns"], description="MITRE adversary emulation plans."),
    # NOTE: ATTACKFlow is NOT in RAG — it's an SDK/tool for building diagrams. ATT&CK data covered by AdversaryEmulationLibrary.
    SourceConfig(name="AwesomeBugbountyWriteups", url="https://github.com/devanshbatham/Awesome-Bugbounty-Writeups", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "writeups"], description="Curated bug bounty writeups."),
    SourceConfig(name="BugBountyReference", url="https://github.com/ngalongc/bug-bounty-reference", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "reference"], description="Bug bounty write-up reference list."),
]

_SHARED_THREAT_INTEL: list[SourceConfig] = [
    # NOTE: MITRE-CTI and ATTACKStixData are NOT in RAG — STIX JSON is structured graph data.
    # Query via ATT&CK API or load into graph DB at runtime.
    SourceConfig(name="CISA-KEV", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", source_type=SourceType.WEBSITE, domain="shared", category="threat_intel", max_pages=50, tags=["cisa", "kev", "exploited"], description="CISA Known Exploited Vulnerabilities Catalog."),
]

_SHARED_THREAT_ACTORS: list[SourceConfig] = [
    # NOTE: APT1-Report removed — github.com/mandiant/apt1 no longer exists (404).
    # NOTE: APTCampaignCollections removed — 6.3 GB repo of mostly PDFs, our extractor only
    # handles .md so the vast majority of content is unreachable.  Too large to clone in Docker.
]

_SHARED_EXPLOITS: list[SourceConfig] = [
    # NOTE: ExploitDB is NOT in RAG — 300K+ exploits, use searchsploit or ExploitDB API at runtime.
    # NOTE: Metasploit modules are NOT in RAG — Ruby tool code, use `msfconsole search` at runtime.
    # NOTE: PoCInGitHub is NOT in RAG — JSON lookup table of PoC links, query at runtime.
    # NOTE: TrickestCVE removed — 761 MB repo with 200K+ individual CVE .md files.
    # Would produce millions of chunks.  Query via Trickest API or NVD at runtime.
    SourceConfig(name="Vulhub", url="https://github.com/vulhub/vulhub", source_type=SourceType.GITHUB_REPO, domain="shared", category="exploits", branch="master", include_patterns=["**/*.md"], tags=["vulhub", "docker", "vulnerable"], description="Vulhub — pre-built vulnerable environments (READMEs only)."),
]

_SHARED_SECRETS: list[SourceConfig] = [
    SourceConfig(name="KeyHacks", url="https://github.com/streaak/keyhacks", source_type=SourceType.GITHUB_REPO, domain="shared", category="secrets", branch="master", include_patterns=["**/*.md"], tags=["api-keys", "secrets", "validation"], license="MIT", description="KeyHacks — validate & exploit leaked API keys."),
    # NOTE: SecretsPatternDB is NOT in RAG — regex patterns loaded into scanner at runtime.
    SourceConfig(name="PayloadsAllTheThings-APIKeyLeaks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="secrets", branch="master", clone_id="PayloadsAllTheThings", subdirectory="API Key Leaks", include_patterns=["**/*.md"], tags=["api-keys", "leaks"], license="MIT", description="PayloadsAllTheThings — API Key Leaks section."),
]

_SHARED_COMPLIANCE: list[SourceConfig] = [
    SourceConfig(name="OWASP-ASVS", url="https://github.com/OWASP/ASVS", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", branch="master", include_patterns=["**/*.md"], tags=["owasp", "asvs", "compliance"], description="OWASP ASVS."),
    SourceConfig(name="OWASP-ASVS-Web", url="https://owasp.org/www-project-application-security-verification-standard/", source_type=SourceType.WEBSITE, domain="shared", category="compliance", max_pages=100, tags=["owasp", "asvs"], description="OWASP ASVS web documentation."),
    SourceConfig(name="OWASP-CheatSheets", url="https://github.com/OWASP/CheatSheetSeries", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md"], tags=["owasp", "cheatsheets"], description="OWASP Cheat Sheet Series."),
    SourceConfig(name="ATTACKControlMappings", url="https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", branch="main", include_patterns=["**/*.md", "**/*.json"], tags=["mitre", "nist", "mappings"], description="ATT&CK ↔ NIST 800-53 control mappings."),
]

_SHARED_DETECTION_EVASION: list[SourceConfig] = [
    # NOTE: SigmaRules, ElasticDetectionRules, PantherAnalysis are NOT in RAG —
    # structured YAML/TOML/Python detection signatures. Load into SIEM or query at runtime.
    # NOTE: PentestingTools-Evasion is NOT in RAG — tool collection, not methodology.
    SourceConfig(name="PayloadsAllTheThings-Evasion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="detection_evasion", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Evasion.md", "**/Defense Evasion.md"], tags=["evasion", "defense-evasion", "bypass"], description="Evasion and defense evasion techniques."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# WEB — Web application security
# ═══════════════════════════════════════════════════════════════════════════════

_WEB: list[SourceConfig] = [
    SourceConfig(name="OWASP-WSTG", url="https://github.com/OWASP/wstg", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", priority=1, branch="master", subdirectory="document", include_patterns=["**/*.md"], exclude_patterns=["**/images/**"], tags=["owasp", "wstg", "web-security"], license="CC-BY-SA-4.0", description="OWASP Web Security Testing Guide."),
    SourceConfig(name="PortSwigger-WebSecurity", url="https://portswigger.net/web-security/all-topics", source_type=SourceType.WEBSITE, domain="web", category="methodology", priority=1, max_pages=500, tags=["portswigger", "burp", "web-security"], description="PortSwigger Web Security Academy."),
    SourceConfig(name="PortSwigger-Research", url="https://portswigger.net/research", source_type=SourceType.WEBSITE, domain="web", category="methodology", max_pages=300, tags=["portswigger", "research"], description="PortSwigger research blog."),
    SourceConfig(name="AllAboutBugBounty", url="https://github.com/daffainfo/AllAboutBugBounty", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "web"], description="All About Bug Bounty."),
    SourceConfig(name="HowToHunt", url="https://github.com/KathanP19/HowToHunt", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["bugbounty", "hunting", "web"], description="How to Hunt — bug bounty methodology."),
    SourceConfig(name="WeirdProxies", url="https://github.com/GrrrDog/weird_proxies", source_type=SourceType.GITHUB_REPO, domain="web", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["proxy", "misconfig", "web"], description="Weird Proxies — proxy misconfigurations."),
    SourceConfig(name="Web-SQLi", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="SQL Injection", include_patterns=["**/*.md"], tags=["sqli", "sql-injection"], description="SQL Injection payloads."),
    SourceConfig(name="Web-XSS", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="XSS Injection", include_patterns=["**/*.md"], tags=["xss", "cross-site-scripting"], description="XSS Injection payloads."),
    SourceConfig(name="Web-SSRF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Server Side Request Forgery", include_patterns=["**/*.md"], tags=["ssrf"], description="SSRF payloads."),
    SourceConfig(name="BlindSSRFChains", url="https://github.com/assetnote/blind-ssrf-chains", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", include_patterns=["**/*.md"], tags=["ssrf", "blind", "chains"], description="Blind SSRF exploitation chains."),
    SourceConfig(name="Web-SSTI", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Server Side Template Injection", include_patterns=["**/*.md"], tags=["ssti", "template-injection"], description="SSTI payloads."),
    SourceConfig(name="Web-FileUpload", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="File Upload", include_patterns=["**/*.md"], tags=["file-upload", "webshell"], description="File upload bypass payloads."),
    SourceConfig(name="Web-CommandInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Command Injection", include_patterns=["**/*.md"], tags=["command-injection", "rce"], description="OS Command Injection payloads."),
    SourceConfig(name="Web-XXE", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="XXE Injection", include_patterns=["**/*.md"], tags=["xxe", "xml"], description="XXE Injection payloads."),
    SourceConfig(name="Web-CSRF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="CSRF Injection", include_patterns=["**/*.md"], tags=["csrf"], description="CSRF techniques."),
    SourceConfig(name="Web-OpenRedirect", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Open Redirect", include_patterns=["**/*.md"], tags=["open-redirect"], description="Open Redirect payloads."),
    SourceConfig(name="Web-Deserialization", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Insecure Deserialization", include_patterns=["**/*.md"], tags=["deserialization", "rce"], description="Insecure deserialization payloads."),
    SourceConfig(name="Web-IDOR", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="IDOR", include_patterns=["**/*.md"], tags=["idor", "access-control"], description="IDOR techniques."),
    SourceConfig(name="Web-CRLF", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="CRLF Injection", include_patterns=["**/*.md"], tags=["crlf", "injection"], description="CRLF Injection payloads."),
    SourceConfig(name="Web-PrototypePollution", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Prototype Pollution", include_patterns=["**/*.md"], tags=["prototype-pollution", "javascript"], description="Prototype Pollution payloads."),
    SourceConfig(name="Web-CacheDeception", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Web Cache Deception", include_patterns=["**/*.md"], tags=["cache-deception", "web-cache"], description="Web Cache Deception payloads."),
    SourceConfig(name="Web-RequestSmuggling", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Request Smuggling", include_patterns=["**/*.md"], tags=["request-smuggling", "http"], description="HTTP Request Smuggling techniques."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# API — API security testing
# ═══════════════════════════════════════════════════════════════════════════════

_API: list[SourceConfig] = [
    SourceConfig(name="OWASP-APISecurity", url="https://github.com/OWASP/API-Security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["owasp", "api-security", "top10"], description="OWASP API Security Top 10."),
    SourceConfig(name="AwesomeAPISecurity", url="https://github.com/arainho/awesome-api-security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["api", "security"], description="Awesome API Security."),
    SourceConfig(name="31DaysAPISecurityTips", url="https://github.com/inonshk/31-days-of-API-Security-Tips", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["api", "tips"], description="31 days of API security tips."),
    SourceConfig(name="API-GraphQLInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="GraphQL Injection", include_patterns=["**/*.md"], tags=["graphql", "injection"], description="GraphQL Injection payloads."),
    SourceConfig(name="API-JWTAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="JWT Attacks", include_patterns=["**/*.md"], tags=["jwt", "auth-bypass"], description="JWT attack payloads."),
    SourceConfig(name="API-OAuthMisconfig", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", branch="master", clone_id="PayloadsAllTheThings", subdirectory="OAuth Misconfiguration", include_patterns=["**/*.md"], tags=["oauth", "misconfiguration"], description="OAuth misconfiguration payloads."),
    SourceConfig(name="GraphQLSecurityTesting", url="https://github.com/nicowillis/graphql-security-testing", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", branch="main", include_patterns=["**/*.md"], tags=["graphql", "testing"], description="GraphQL security testing methodology."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# MOBILE — Mobile application security
# ═══════════════════════════════════════════════════════════════════════════════

_MOBILE: list[SourceConfig] = [
    SourceConfig(name="OWASP-MASTG", url="https://github.com/OWASP/owasp-mastg", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", priority=1, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/images/**", "**/CHANGELOG*"], tags=["mobile", "android", "ios", "owasp"], license="CC-BY-SA-4.0", description="OWASP MASTG."),
    SourceConfig(name="HackTricks-Android", url="https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", max_pages=200, tags=["android", "mobile", "hacktricks"], description="HackTricks — Android pentesting."),
    SourceConfig(name="HackTricks-iOS", url="https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", max_pages=200, tags=["ios", "mobile", "hacktricks"], description="HackTricks — iOS pentesting."),
    SourceConfig(name="MobileAppPentestCheatsheet", url="https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["mobile", "cheatsheet"], description="Mobile app pentesting cheatsheet."),
    SourceConfig(name="MobileHackingCheatSheet", url="https://github.com/randorisec/MobileHackingCheatSheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["mobile", "hacking"], description="Randorisec mobile hacking cheat sheet."),
    # NOTE: FridaCodeshare is NOT in RAG — Frida scripts (tool code), fetch at runtime.
    SourceConfig(name="AwesomeFrida", url="https://github.com/dweinstein/awesome-frida", source_type=SourceType.GITHUB_REPO, domain="mobile", category="dynamic_instrumentation", branch="master", include_patterns=["**/*.md"], tags=["frida", "awesome-list"], description="Awesome Frida resources."),
    SourceConfig(name="WithSecureAndroidTutorials", url="https://github.com/WithSecureLabs/android-tutorials", source_type=SourceType.GITHUB_REPO, domain="mobile", category="exploitation", branch="main", include_patterns=["**/*.md"], tags=["android", "exploitation"], description="WithSecure Android security tutorials."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# IOT — IoT, hardware, firmware, radio protocols
# ═══════════════════════════════════════════════════════════════════════════════

_IOT: list[SourceConfig] = [
    SourceConfig(name="IoTSecurity101", url="https://github.com/V33RU/IoTSecurity101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["iot", "security"], description="IoT Security 101."),
    SourceConfig(name="OWASP-FSTM", url="https://github.com/scriptingxss/owasp-fstm", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["owasp", "firmware", "testing"], description="OWASP Firmware Security Testing Methodology."),
    SourceConfig(name="OWASP-IoT", url="https://github.com/OWASP/www-project-internet-of-things", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot"], description="OWASP IoT project."),
    SourceConfig(name="OWASP-IoTTop10", url="https://github.com/OWASP/IoT-Top-Ten", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot", "top10"], description="OWASP IoT Top 10."),
    SourceConfig(name="PayatuIoTSecurity101", url="https://github.com/payatu/IoT-Security-101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["iot", "payatu"], description="Payatu IoT Security 101."),
    SourceConfig(name="AwesomeIoTHacks", url="https://github.com/nebgnahz/awesome-iot-hacks", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["iot", "hacks"], description="Awesome IoT hacks."),
    SourceConfig(name="HardwareAllTheThings", url="https://github.com/swisskyrepo/HardwareAllTheThings", source_type=SourceType.GITHUB_REPO, domain="iot", category="hardware_interfaces", branch="main", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["hardware", "uart", "jtag", "spi", "ble", "zigbee", "rf"], license="MIT", description="Hardware/IoT pentesting — UART, JTAG, SPI, BLE, ZigBee, RF."),
    SourceConfig(name="EmbeddedAppSec", url="https://github.com/scriptingxss/embeddedappsec", source_type=SourceType.GITHUB_REPO, domain="iot", category="firmware", branch="master", include_patterns=["**/*.md"], tags=["embedded", "firmware"], description="Embedded application security guide."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD — Cloud security (AWS, Azure, GCP, K8s)
# ═══════════════════════════════════════════════════════════════════════════════

_CLOUD: list[SourceConfig] = [
    SourceConfig(name="HackingTheCloud", url="https://github.com/Hacking-the-Cloud/hackingthe.cloud", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", priority=1, branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws", "azure", "gcp"], description="Hacking the Cloud encyclopedia."),
    SourceConfig(name="StratusRedTeam", url="https://github.com/DataDog/stratus-red-team", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", branch="main", include_patterns=["**/*.md", "**/*.yaml"], tags=["cloud", "red-team", "detection"], description="Stratus Red Team — cloud attack simulation."),
    SourceConfig(name="CloudGoat", url="https://github.com/RhinoSecurityLabs/cloudgoat", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["cloud", "aws", "labs"], description="CloudGoat — vulnerable AWS deployment."),
    SourceConfig(name="CloudPentestCheatsheets", url="https://github.com/dafthack/CloudPentestCheatsheets", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["cloud", "cheatsheets"], description="Cloud pentest cheatsheets."),
    SourceConfig(name="CloudFoxable", url="https://github.com/BishopFox/cloudfoxable", source_type=SourceType.GITHUB_REPO, domain="cloud", category="exploitation", branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws"], description="CloudFoxable — exploitable cloud environment."),
    SourceConfig(name="OWASP-K8sTop10", url="https://github.com/OWASP/www-project-kubernetes-top-ten", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "k8s", "owasp", "top10"], description="OWASP Kubernetes Top 10."),
    SourceConfig(name="K8sThreatMatrix", url="https://github.com/kubernetes-threat-matrix/threat-matrix-for-kubernetes", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "threat-matrix"], description="MITRE threat matrix for K8s."),
    SourceConfig(name="K8sSecurity", url="https://github.com/sergiomarotco/k8s-security", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "security"], description="K8s security best practices."),
    SourceConfig(name="ContainerEscapeCheck", url="https://github.com/BishopFox/container-escape-check", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", branch="main", include_patterns=["**/*.md"], tags=["container", "escape"], description="Container escape detection."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE — Internal pentest, AD, privilege escalation
# ═══════════════════════════════════════════════════════════════════════════════

_INFRASTRUCTURE: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="methodology", priority=1, branch="main", clone_id="InternalAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["active-directory", "internal", "kerberos"], license="MIT", description="AD & internal pentest cheatsheets."),
    SourceConfig(name="ADExploitCheatSheet", url="https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="active_directory", branch="master", include_patterns=["**/*.md"], tags=["active-directory", "exploitation"], description="AD exploitation cheat sheet."),
    SourceConfig(name="GOAD", url="https://github.com/Orange-Cyberdefense/GOAD", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="active_directory", branch="main", include_patterns=["**/*.md"], tags=["active-directory", "lab", "goad"], description="Game of Active Directory."),
    SourceConfig(name="OSCP-Notes", url="https://github.com/0xsyr0/OSCP", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["oscp", "methodology"], description="OSCP notes and cheatsheets."),
    SourceConfig(name="GTFOBins", url="https://gtfobins.github.io/", source_type=SourceType.WEBSITE, domain="infrastructure", category="privilege_escalation", priority=1, include_patterns=["https://gtfobins.github.io/gtfobins/**"], css_selector="article.bins", max_pages=500, default_metadata={"target": "infrastructure", "attack_phase": "privilege_escalation", "platform": ["linux"]}, tags=["gtfobins", "linux", "privilege-escalation"], description="GTFOBins — Unix binaries for privesc."),
    SourceConfig(name="LOLBAS", url="https://lolbas-project.github.io/", source_type=SourceType.WEBSITE, domain="infrastructure", category="privilege_escalation", priority=1, include_patterns=["https://lolbas-project.github.io/lolbas/**"], css_selector=".main-content", max_pages=500, default_metadata={"target": "infrastructure", "attack_phase": "privilege_escalation", "platform": ["windows"]}, tags=["lolbas", "windows", "living-off-the-land"], description="LOLBAS — Living Off The Land Binaries for Windows."),
    SourceConfig(name="Infra-WindowsPersistence", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Windows - Persistence.md"], tags=["windows", "persistence"], description="Windows persistence techniques."),
    SourceConfig(name="Infra-LinuxPersistence", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Linux - Persistence.md"], tags=["linux", "persistence"], description="Linux persistence techniques."),
    SourceConfig(name="Infra-CredentialAccess", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Credential Access.md"], tags=["credentials", "dumping"], description="Credential access techniques."),
    SourceConfig(name="Infra-LateralMovement", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="infrastructure", category="post_exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Lateral Movement.md"], tags=["lateral-movement", "pivoting"], description="Lateral movement techniques."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK — Network pentesting, wireless
# ═══════════════════════════════════════════════════════════════════════════════

_NETWORK: list[SourceConfig] = [
    SourceConfig(name="Net-NetworkDiscovery", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Network Discovery.md"], tags=["network", "discovery"], description="Network discovery methodology."),
    SourceConfig(name="InternalAllTheThings-Network", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", branch="main", clone_id="InternalAllTheThings", subdirectory="docs/network", include_patterns=["**/*.md"], tags=["network", "internal"], description="InternalAllTheThings — network attacks."),
    SourceConfig(name="InfosecReference", url="https://github.com/rmusser01/Infosec_Reference", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["infosec", "reference"], description="Infosec Reference."),
    SourceConfig(name="Net-Pivoting", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Network Pivoting Techniques", include_patterns=["**/*.md"], tags=["pivoting", "tunneling"], description="Network pivoting techniques."),
    # NOTE: KRACKAttacks, FragAttacks, EAPHammer are NOT in RAG — attack tool repos with thin READMEs.
    # WiFi attack methodology is covered by HackTricks and InternalAllTheThings.
]


# ═══════════════════════════════════════════════════════════════════════════════
# RECON — Reconnaissance and OSINT
# ═══════════════════════════════════════════════════════════════════════════════

_RECON: list[SourceConfig] = [
    # NOTE: ReconFTW is NOT in RAG — bash automation tool. SecretFinder and TruffleHog are scanner tools.
    # Recon methodology is covered by HackTricks and PayloadsAllTheThings.
    SourceConfig(name="AwesomeOSINT", url="https://github.com/jivoi/awesome-osint", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["osint", "recon"], description="Awesome OSINT resources."),
    SourceConfig(name="Recon-Subdomain", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Subdomains Enumeration.md"], tags=["recon", "subdomains"], description="Subdomain enumeration methodology."),
    SourceConfig(name="Recon-ScopeAndRecon", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Methodology and enumeration.md"], tags=["recon", "methodology"], description="Recon methodology and enumeration."),
    SourceConfig(name="AwesomeAssetDiscovery", url="https://github.com/redhuntlabs/Awesome-Asset-Discovery", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["recon", "asset-discovery"], description="Awesome Asset Discovery resources."),
    SourceConfig(name="InternalAllTheThings-Recon", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="recon", category="methodology", branch="main", clone_id="InternalAllTheThings", subdirectory="docs/recon", include_patterns=["**/*.md"], tags=["recon", "internal"], description="InternalAllTheThings — recon techniques."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# CVE_EXPLOIT — CVE intelligence and exploit chains
# ═══════════════════════════════════════════════════════════════════════════════

_CVE_EXPLOIT: list[SourceConfig] = [
    # NOTE: NucleiTemplates-CVEs is NOT in RAG — YAML scanner templates, feed to nuclei at scan time.
    # NOTE: NVD-CVE batch ingestion removed — use NVD-Runtime in _RUNTIME_APIS for live lookups.
]


# ═══════════════════════════════════════════════════════════════════════════════
# RED_TEAM — Red team operations
# ═══════════════════════════════════════════════════════════════════════════════

_RED_TEAM: list[SourceConfig] = [
    SourceConfig(name="RedTeamInfraWiki", url="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki", source_type=SourceType.GITHUB_REPO, domain="red_team", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["red-team", "infrastructure", "c2"], description="Red Team Infrastructure Wiki."),
    SourceConfig(name="RT-Phishing", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="red_team", category="payloads_evasion", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Phishing.md"], tags=["phishing", "social-engineering"], description="Phishing techniques."),
    SourceConfig(name="RT-ReverseShells", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="red_team", category="payloads_evasion", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Reverse Shell Cheatsheet.md"], tags=["reverse-shell", "payloads"], description="Reverse shell cheatsheet."),
    SourceConfig(name="MythicC2-Docs", url="https://docs.mythic-c2.net/", source_type=SourceType.WEBSITE, domain="red_team", category="c2_knowledge", max_pages=200, tags=["mythic", "c2"], description="Mythic C2 documentation."),
    SourceConfig(name="SliverC2-Wiki", url="https://github.com/BishopFox/sliver", source_type=SourceType.GITHUB_REPO, domain="red_team", category="c2_knowledge", branch="master", include_patterns=["**/*.md"], tags=["sliver", "c2"], description="Sliver C2 wiki."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# BINARY — Binary exploitation and reverse engineering
# ═══════════════════════════════════════════════════════════════════════════════

_BINARY: list[SourceConfig] = [
    SourceConfig(name="Ir0nstoneNotes", url="https://ir0nstone.gitbook.io/notes", source_type=SourceType.GITBOOK, domain="binary", category="methodology", max_pages=200, tags=["binary", "exploitation", "rop", "heap"], description="ir0nstone's binary exploitation notes."),
    SourceConfig(name="CTFAllInOne", url="https://github.com/firmianay/CTF-All-In-One", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["ctf", "binary"], description="CTF All-In-One guide."),
    SourceConfig(name="BinaryExploitation-Payloads", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Binary Exploitation", include_patterns=["**/*.md"], tags=["binary", "exploitation"], description="Binary exploitation payloads."),
    SourceConfig(name="RPISEC-MBE", url="https://github.com/RPISEC/MBE", source_type=SourceType.GITHUB_REPO, domain="binary", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["binary", "education"], description="RPISEC Modern Binary Exploitation."),
    SourceConfig(name="How2Heap", url="https://github.com/shellphish/how2heap", source_type=SourceType.GITHUB_REPO, domain="binary", category="techniques", branch="master", include_patterns=["**/*.md", "**/*.c"], tags=["heap", "exploitation"], description="How2Heap — heap exploitation techniques."),
    SourceConfig(name="CTFPwnTips", url="https://github.com/Naetw/CTF-pwn-tips", source_type=SourceType.GITHUB_REPO, domain="binary", category="techniques", branch="master", include_patterns=["**/*.md"], tags=["ctf", "pwn"], description="CTF pwn tips."),
    SourceConfig(name="ARMExploitation", url="https://github.com/IOActive/ARM-Exploitation", source_type=SourceType.GITHUB_REPO, domain="binary", category="arm_embedded", branch="master", include_patterns=["**/*.md"], tags=["arm", "exploitation", "embedded"], description="ARM exploitation techniques."),
    SourceConfig(name="ReverseEngineeringBeginners", url="https://github.com/malware-unicorn/reverse-engineering-for-beginners", source_type=SourceType.GITHUB_REPO, domain="binary", category="reverse_engineering", branch="master", include_patterns=["**/*.md"], tags=["reverse-engineering", "malware"], description="Reverse engineering for beginners."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY — Identity security (AAD, OAuth, SAML, Kerberos)
# ═══════════════════════════════════════════════════════════════════════════════

_IDENTITY: list[SourceConfig] = [
    SourceConfig(name="AzureADAttackDefense", url="https://github.com/dirkjanm/AzureAD-Attack-Defense", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["azure-ad", "identity"], description="Azure AD attack and defense."),
    SourceConfig(name="Identity-OAuthMisconfig", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="OAuth Misconfiguration", include_patterns=["**/*.md"], tags=["oauth", "identity"], description="OAuth misconfiguration attacks."),
    SourceConfig(name="Identity-JWTAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="JWT Attacks", include_patterns=["**/*.md"], tags=["jwt", "identity"], description="JWT attack techniques."),
    SourceConfig(name="Identity-SAMLAttacks", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="methodology", branch="master", clone_id="PayloadsAllTheThings", subdirectory="SAML Attacks", include_patterns=["**/*.md"], tags=["saml", "identity", "sso-bypass"], description="SAML attack techniques."),
    SourceConfig(name="InternalAllTheThings-AzureAD", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="identity", category="exploitation", branch="main", clone_id="InternalAllTheThings", subdirectory="docs/cloud", include_patterns=["**/azure-azure-active-directory.md", "**/azure-azure-ad-connect.md"], tags=["azure-ad", "exploitation"], description="Azure AD exploitation techniques."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SUPPLY_CHAIN — CI/CD, dependency confusion, IaC
# ═══════════════════════════════════════════════════════════════════════════════

_SUPPLY_CHAIN: list[SourceConfig] = [
    SourceConfig(name="OWASP-CICDTop10", url="https://github.com/OWASP/www-project-top-10-ci-cd-security-risks", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["cicd", "owasp", "supply-chain"], description="OWASP Top 10 CI/CD Security Risks."),
    SourceConfig(name="OSSFScorecard", url="https://github.com/ossf/scorecard", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["ossf", "supply-chain"], description="OpenSSF Scorecard."),
    # NOTE: Checkov-Policies is NOT in RAG — IaC tool documentation, run checkov at scan time.
    SourceConfig(name="DependencyConfusion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="supply_chain", category="exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Dependency Confusion", include_patterns=["**/*.md"], tags=["dependency-confusion", "supply-chain"], description="Dependency confusion exploitation."),
    # NOTE: Confused is NOT in RAG — Go binary tool, run at scan time.
]


# ═══════════════════════════════════════════════════════════════════════════════
# WEB3 — Smart contracts, DeFi, blockchain
# ═══════════════════════════════════════════════════════════════════════════════

_WEB3: list[SourceConfig] = [
    SourceConfig(name="NotSoSmartContracts", url="https://github.com/crytic/not-so-smart-contracts", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", branch="master", include_patterns=["**/*.md", "**/*.sol"], tags=["solidity", "smart-contracts"], description="Not So Smart Contracts vulnerabilities."),
    SourceConfig(name="SmartContractVulnerabilities", url="https://github.com/kadenzipfel/smart-contract-vulnerabilities", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", branch="main", include_patterns=["**/*.md"], tags=["smart-contracts", "vulnerabilities"], description="Smart contract vulnerability patterns."),
    SourceConfig(name="SoliditySecurityBlog", url="https://github.com/sigp/solidity-security-blog", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["solidity", "security"], description="Solidity security attack patterns."),
    SourceConfig(name="SWCRegistry", url="https://swcregistry.io/", source_type=SourceType.WEBSITE, domain="web3", category="methodology", max_pages=100, tags=["swc", "smart-contracts"], description="SWC Registry."),
    SourceConfig(name="SmartContractBestPractices", url="https://github.com/ConsenSys/smart-contract-best-practices", source_type=SourceType.GITHUB_REPO, domain="web3", category="methodology", branch="master", include_patterns=["**/*.md"], tags=["smart-contracts", "best-practices"], description="ConsenSys smart contract best practices."),
    SourceConfig(name="Web3SecurityLibrary", url="https://github.com/immunefi-team/Web3-Security-Library", source_type=SourceType.GITHUB_REPO, domain="web3", category="exploitation", branch="main", include_patterns=["**/*.md"], tags=["web3", "security", "immunefi"], description="Immunefi Web3 Security Library."),
    SourceConfig(name="DamnVulnerableDeFi", url="https://github.com/damnvulnerabledefi/damn-vulnerable-defi", source_type=SourceType.GITHUB_REPO, domain="web3", category="exploitation", branch="master", include_patterns=["**/*.md"], tags=["defi", "vulnerable"], description="Damn Vulnerable DeFi challenges."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE — Reporting and compliance frameworks
# ═══════════════════════════════════════════════════════════════════════════════

_COMPLIANCE: list[SourceConfig] = [
    SourceConfig(name="OWASP-SAMM", url="https://github.com/OWASP/owasp-samm", source_type=SourceType.GITHUB_REPO, domain="compliance", category="frameworks", branch="master", include_patterns=["**/*.md"], tags=["owasp", "samm", "maturity-model"], description="OWASP SAMM."),
    SourceConfig(name="PublicPentestReports", url="https://github.com/juliocesarfort/public-pentesting-reports", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", branch="master", include_patterns=["**/*.md"], tags=["reports", "pentest"], description="Public penetration testing reports."),
    SourceConfig(name="TCMSampleReport", url="https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", branch="master", include_patterns=["**/*.md", "**/*.pdf"], tags=["report", "template"], description="TCM Security sample report."),
    SourceConfig(name="ReconmapReportTemplates", url="https://github.com/reconmap/pentest-report-templates", source_type=SourceType.GITHUB_REPO, domain="compliance", category="report_templates", branch="main", include_patterns=["**/*.md"], tags=["reports", "templates"], description="Reconmap report templates."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# RUNTIME APIS — Never embedded, called live at scan time by executor agents.
# Cataloged here so the registry is the single source of truth for ALL sources.
# ═══════════════════════════════════════════════════════════════════════════════

_RUNTIME_APIS: list[SourceConfig] = [
    SourceConfig(name="Shodan", url="https://api.shodan.io", source_type=SourceType.API, domain="recon", category="asset_discovery", is_runtime=True, priority=1, api_params={"key": "env:SHODAN_API_KEY"}, tags=["shodan", "recon", "iot"], description="Shodan API — live asset discovery and banner grabbing."),
    SourceConfig(name="Censys", url="https://search.censys.io/api", source_type=SourceType.API, domain="recon", category="asset_discovery", is_runtime=True, priority=1, api_params={"key": "env:CENSYS_API_KEY"}, tags=["censys", "recon", "certificates"], description="Censys API — internet-wide scan data and certificate search."),
    SourceConfig(name="CrtSh", url="https://crt.sh", source_type=SourceType.API, domain="recon", category="asset_discovery", is_runtime=True, priority=1, tags=["crt.sh", "certificates", "subdomains"], description="crt.sh — certificate transparency log search."),
    SourceConfig(name="HIBP", url="https://haveibeenpwned.com/api/v3", source_type=SourceType.API, domain="recon", category="credential_intel", is_runtime=True, api_params={"key": "env:HIBP_API_KEY"}, tags=["hibp", "breach", "credentials"], description="Have I Been Pwned API — breach and paste lookups."),
    SourceConfig(name="VirusTotal", url="https://www.virustotal.com/api/v3", source_type=SourceType.API, domain="recon", category="threat_intel", is_runtime=True, api_params={"key": "env:VT_API_KEY"}, tags=["virustotal", "malware", "ioc"], description="VirusTotal API — file, URL, domain, and IP analysis."),
    SourceConfig(name="GreyNoise", url="https://api.greynoise.io/v3", source_type=SourceType.API, domain="recon", category="threat_intel", is_runtime=True, api_params={"key": "env:GREYNOISE_API_KEY"}, tags=["greynoise", "noise", "threat-intel"], description="GreyNoise API — internet scanner and mass-exploitation detection."),
    SourceConfig(name="AbuseIPDB", url="https://api.abuseipdb.com/api/v2", source_type=SourceType.API, domain="recon", category="threat_intel", is_runtime=True, api_params={"key": "env:ABUSEIPDB_API_KEY"}, tags=["abuseipdb", "ip-reputation"], description="AbuseIPDB API — IP abuse reporting and lookup."),
    SourceConfig(name="NVD-Runtime", url="https://services.nvd.nist.gov/rest/json/cves/2.0", source_type=SourceType.API, domain="cve_exploit", category="intelligence", is_runtime=True, priority=1, api_params={"key": "env:NVD_API_KEY"}, tags=["cve", "nvd", "vulnerability"], description="NVD CVE 2.0 API — live vulnerability lookups."),
    SourceConfig(name="ExploitDB-Runtime", url="https://exploit-db.com", source_type=SourceType.API, domain="cve_exploit", category="exploits", is_runtime=True, priority=1, tags=["exploitdb", "exploits"], description="ExploitDB — searchsploit queries at runtime."),
    SourceConfig(name="GitHub-SecLists", url="https://api.github.com/repos/danielmiessler/SecLists", source_type=SourceType.API, domain="shared", category="wordlists", is_runtime=True, priority=1, tags=["seclists", "wordlists"], description="SecLists — wordlists fetched at runtime via GitHub API."),
]


# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ALL_SOURCES: list[SourceConfig] = [
    # Shared (ingested into vector_shared — queried by ALL agents)
    *_SHARED_METHODOLOGY,
    *_SHARED_THREAT_INTEL,
    *_SHARED_THREAT_ACTORS,
    *_SHARED_EXPLOITS,
    *_SHARED_SECRETS,
    *_SHARED_COMPLIANCE,
    *_SHARED_DETECTION_EVASION,
    # Domain-specific
    *_WEB,
    *_API,
    *_MOBILE,
    *_IOT,
    *_CLOUD,
    *_INFRASTRUCTURE,
    *_NETWORK,
    *_RECON,
    *_CVE_EXPLOIT,
    *_RED_TEAM,
    *_BINARY,
    *_IDENTITY,
    *_SUPPLY_CHAIN,
    *_WEB3,
    *_COMPLIANCE,
    # Runtime APIs — never embedded, queried live by agents at scan time
    *_RUNTIME_APIS,
]

# ── Name uniqueness guard ────────────────────────────────────────────────────
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
