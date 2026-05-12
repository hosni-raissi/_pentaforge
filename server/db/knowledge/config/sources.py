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
    "INTEL_UPDATABLE_SOURCES",
    "get_enabled_sources",
    "get_runtime_sources",
    "get_sources_by_domain",
    "get_sources_by_type",
    "get_source_by_name",
    "get_all_domains",
    "get_sources_by_priority",
    "get_sources_by_content_type",
    "get_fixed_sources",
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
        if self.last_updated is None:
            return False
        from datetime import timedelta
        return (datetime.now(timezone.utc) - self.last_updated) < timedelta(days=self.cooldown_days)


# ═════════════════════════════════════════════════════════════════════════════
# SHARED — Cross-domain knowledge, queried by ALL agents
# ═════════════════════════════════════════════════════════════════════════════

_SHARED_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="HackTricks", url="https://github.com/HackTricks-wiki/hacktricks", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", subdirectory="src", include_patterns=["**/*.md"], exclude_patterns=["**/SUMMARY.md", "**/banners/**"], tags=["hacktricks", "web", "pentest", "methodology"], license="CC-BY-NC-4.0", description="HackTricks — comprehensive pentest tricks & techniques."),
    SourceConfig(name="PayloadsAllTheThings", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["payloads", "injection", "bypass", "methodology"], license="MIT", description="PayloadsAllTheThings — payloads, bypass techniques, methodology."),
    SourceConfig(name="KeyHacks", url="https://github.com/streaak/keyhacks", source_type=SourceType.GITHUB_REPO, domain="shared", category="secrets", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["api-keys", "secrets", "validation"], license="MIT", description="KeyHacks — validate & exploit leaked API keys."),
]

_SHARED_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="CISA-KEV", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", source_type=SourceType.WEBSITE, domain="shared", category="threat_intel", content_type=ContentType.EXPLOITS, max_pages=50, tags=["cisa", "kev", "exploited"], description="CISA Known Exploited Vulnerabilities Catalog."),
    SourceConfig(name="Vulhub", url="https://github.com/vulhub/vulhub", source_type=SourceType.GITHUB_REPO, domain="shared", category="exploits", content_type=ContentType.EXPLOITS, branch="master", include_patterns=["**/*.md"], tags=["vulhub", "docker", "vulnerable"], description="Vulhub — pre-built vulnerable environments (READMEs only)."),
]

_SHARED_TOOLS: list[SourceConfig] = [
    SourceConfig(name="RedTeamingToolkit", url="https://github.com/infosecn1nja/Red-Teaming-Toolkit", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.TOOLS, branch="master", include_patterns=["**/*.md"], tags=["red-team", "methodology"], description="Red Teaming Toolkit reference."),
]

_SHARED_STANDARDS: list[SourceConfig] = [
    SourceConfig(name="OWASP-ASVS", url="https://github.com/OWASP/ASVS", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["owasp", "asvs", "compliance"], description="OWASP ASVS."),
    SourceConfig(name="OWASP-CheatSheets", url="https://github.com/OWASP/CheatSheetSeries", source_type=SourceType.GITHUB_REPO, domain="shared", category="compliance", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md"], tags=["owasp", "cheatsheets"], description="OWASP Cheat Sheet Series."),
]

_SHARED_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="AtomicRedTeam", url="https://github.com/redcanaryco/atomic-red-team", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.ATTACK_TYPES, priority=1, branch="master", include_patterns=["**/*.md", "**/*.yaml"], exclude_patterns=["**/LICENSE*"], tags=["atomic", "red-team", "mitre", "testing"], license="MIT", description="Atomic Red Team — portable detection tests."),
    SourceConfig(name="AdversaryEmulationLibrary", url="https://github.com/center-for-threat-informed-defense/adversary_emulation_library", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md", "**/*.yaml"], tags=["emulation", "mitre", "apt", "campaigns"], description="MITRE adversary emulation plans."),
    SourceConfig(name="MITRE-ATTACK-Enterprise", url="https://attack.mitre.org/techniques/enterprise/", source_type=SourceType.WEBSITE, domain="shared", category="attack_framework", content_type=ContentType.ATTACK_TYPES, priority=1, max_pages=500, tags=["mitre", "att&ck", "enterprise", "techniques", "tactics"], description="MITRE ATT&CK Enterprise — complete tactic and technique reference."),
    SourceConfig(name="PAT-SharedEvasion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="detection_evasion", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Evasion.md", "**/Defense Evasion.md"], tags=["payloadsallthethings", "evasion", "defense-evasion", "bypass"], description="Consolidated PayloadsAllTheThings evasion techniques."),
]


# ═════════════════════════════════════════════════════════════════════════════
# WEB — Web application security
# ═════════════════════════════════════════════════════════════════════════════

_WEB_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="OWASP-WSTG", url="https://github.com/OWASP/wstg", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", subdirectory="document", include_patterns=["**/*.md"], exclude_patterns=["**/images/**"], tags=["owasp", "wstg", "web-security"], license="CC-BY-SA-4.0", description="OWASP Web Security Testing Guide."),
    SourceConfig(name="PortSwigger-WebSecurity", url="https://portswigger.net/web-security/all-topics", source_type=SourceType.WEBSITE, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, priority=1, include_patterns=["https://portswigger.net/web-security/*"], max_pages=500, tags=["portswigger", "burp", "web-security"], description="PortSwigger Web Security Academy."),
    SourceConfig(name="PortSwigger-Research", url="https://portswigger.net/research", source_type=SourceType.WEBSITE, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, include_patterns=["https://portswigger.net/research/*"], max_pages=300, tags=["portswigger", "research"], description="PortSwigger research blog."),
]

_WEB_STANDARDS: list[SourceConfig] = [
    SourceConfig(name="OWASP-Top10", url="https://github.com/OWASP/Top10", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STANDARDS, priority=1, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/images/**"], tags=["owasp", "top10", "web-security"], description="OWASP Top 10 (2021) — most critical web application security risks."),
]

_WEB_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="WeirdProxies", url="https://github.com/GrrrDog/weird_proxies", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["proxy", "misconfig", "web"], description="Weird Proxies — proxy misconfigurations."),
    SourceConfig(name="BlindSSRFChains", url="https://github.com/assetnote/blind-ssrf-chains", source_type=SourceType.GITHUB_REPO, domain="web_app", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="main", include_patterns=["**/*.md"], tags=["ssrf", "blind", "chains"], description="Blind SSRF exploitation chains."),
    SourceConfig(name="PAT-WebAttackTypes", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="web_app", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["SQL Injection/**/*.md", "XSS Injection/**/*.md", "Server Side Request Forgery/**/*.md", "Server Side Template Injection/**/*.md", "Upload Insecure Files/**/*.md", "Command Injection/**/*.md", "XXE Injection/**/*.md", "Cross-Site Request Forgery/**/*.md", "Open Redirect/**/*.md", "Insecure Deserialization/**/*.md", "Insecure Direct Object References/**/*.md", "CRLF Injection/**/*.md", "Prototype Pollution/**/*.md", "Web Cache Deception/**/*.md", "Request Smuggling/**/*.md"], tags=["payloadsallthethings", "web", "attack-types"], description="Consolidated web attack-type payload references from PayloadsAllTheThings."),
]

_WEB_TOOLS: list[SourceConfig] = [
    SourceConfig(name="H4cker-WebAppTesting", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="web_app", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="web-application-testing", include_patterns=["**/*.md"], tags=["web-tools", "sqli", "ssrf", "api-security"], description="H4cker — web app testing guides."),
]


# ═════════════════════════════════════════════════════════════════════════════
# API — API security testing
# ═════════════════════════════════════════════════════════════════════════════

_API_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="AwesomeAPISecurity", url="https://github.com/arainho/awesome-api-security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["api", "security"], description="Awesome API Security."),
]

_API_STANDARDS: list[SourceConfig] = [
    SourceConfig(name="OWASP-APISecurity", url="https://github.com/OWASP/API-Security", source_type=SourceType.GITHUB_REPO, domain="api", category="methodology", content_type=ContentType.STANDARDS, branch="master", include_patterns=["**/*.md"], tags=["owasp", "api-security", "top10"], description="OWASP API Security Top 10."),
]

_API_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="PAT-ApiAttackTypes", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="api", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["GraphQL Injection/**/*.md", "JSON Web Token/**/*.md", "OAuth Misconfiguration/**/*.md"], tags=["payloadsallthethings", "api", "attack-types"], description="Consolidated API attack-type payload references from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# MOBILE — Mobile application security
# ═════════════════════════════════════════════════════════════════════════════

_MOBILE_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="OWASP-MASTG", url="https://github.com/OWASP/owasp-mastg", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="master", include_patterns=["**/*.md"], exclude_patterns=["**/images/**", "**/CHANGELOG*"], tags=["mobile", "android", "ios", "owasp"], license="CC-BY-SA-4.0", description="OWASP MASTG."),
    SourceConfig(name="HackTricks-Android", url="https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["android", "mobile", "hacktricks"], description="HackTricks — Android pentesting."),
    SourceConfig(name="HackTricks-iOS", url="https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting", source_type=SourceType.GITBOOK, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["ios", "mobile", "hacktricks"], description="HackTricks — iOS pentesting."),
    SourceConfig(name="MobileAppPentestCheatsheet", url="https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["mobile", "cheatsheet"], description="Mobile app pentesting cheatsheet."),
    SourceConfig(name="MobileHackingCheatSheet", url="https://github.com/randorisec/MobileHackingCheatSheet", source_type=SourceType.GITHUB_REPO, domain="mobile", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["mobile", "hacking"], description="Randorisec mobile hacking cheat sheet."),
]

_MOBILE_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="WithSecureAndroidTutorials", url="https://github.com/WithSecureLabs/android-tutorials", source_type=SourceType.GITHUB_REPO, domain="mobile", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["android", "exploitation"], description="WithSecure Android security tutorials."),
]


# ═════════════════════════════════════════════════════════════════════════════
# IOT — IoT, hardware, firmware, radio protocols
# ═════════════════════════════════════════════════════════════════════════════

_IOT_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="IoTSecurity101", url="https://github.com/V33RU/IoTSecurity101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["iot", "security"], description="IoT Security 101."),
    SourceConfig(name="OWASP-FSTM", url="https://github.com/scriptingxss/owasp-fstm", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "firmware", "testing"], description="OWASP Firmware Security Testing Methodology."),
    SourceConfig(name="OWASP-IoT", url="https://github.com/OWASP/www-project-internet-of-things", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot"], description="OWASP IoT project."),
    SourceConfig(name="OWASP-IoTTop10", url="https://github.com/OWASP/IoT-Top-Ten", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["owasp", "iot", "top10"], description="OWASP IoT Top 10."),
    SourceConfig(name="PayatuIoTSecurity101", url="https://github.com/payatu/IoT-Security-101", source_type=SourceType.GITHUB_REPO, domain="iot", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["iot", "payatu"], description="Payatu IoT Security 101."),
    SourceConfig(name="HardwareAllTheThings", url="https://github.com/swisskyrepo/HardwareAllTheThings", source_type=SourceType.GITHUB_REPO, domain="iot", category="hardware_interfaces", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["hardware", "uart", "jtag", "spi", "ble", "zigbee", "rf"], license="MIT", description="Hardware/IoT pentesting — UART, JTAG, SPI, BLE, ZigBee, RF."),
    SourceConfig(name="EmbeddedAppSec", url="https://github.com/scriptingxss/embeddedappsec", source_type=SourceType.GITHUB_REPO, domain="iot", category="firmware", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["embedded", "firmware"], description="Embedded application security guide."),
]


# ═════════════════════════════════════════════════════════════════════════════
# CLOUD — Cloud security (AWS, Azure, GCP, K8s)
# ═════════════════════════════════════════════════════════════════════════════

_CLOUD_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="HackingTheCloud", url="https://github.com/Hacking-the-Cloud/hackingthe.cloud", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws", "azure", "gcp"], description="Hacking the Cloud encyclopedia."),
    SourceConfig(name="StratusRedTeam", url="https://github.com/DataDog/stratus-red-team", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md", "**/*.yaml"], tags=["cloud", "red-team", "detection"], description="Stratus Red Team — cloud attack simulation."),
    SourceConfig(name="CloudGoat", url="https://github.com/RhinoSecurityLabs/cloudgoat", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["cloud", "aws", "labs"], description="CloudGoat — vulnerable AWS deployment."),
    SourceConfig(name="CloudPentestCheatsheets", url="https://github.com/dafthack/CloudPentestCheatsheets", source_type=SourceType.GITHUB_REPO, domain="cloud", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["cloud", "cheatsheets"], description="Cloud pentest cheatsheets."),
    SourceConfig(name="OWASP-K8sTop10", url="https://github.com/OWASP/www-project-kubernetes-top-ten", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "k8s", "owasp", "top10"], description="OWASP Kubernetes Top 10."),
    SourceConfig(name="K8sThreatMatrix", url="https://github.com/kubernetes-threat-matrix/threat-matrix-for-kubernetes", source_type=SourceType.GITHUB_REPO, domain="cloud", category="containers_kubernetes", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["kubernetes", "threat-matrix"], description="MITRE threat matrix for K8s."),
]

_CLOUD_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="CloudFoxable", url="https://github.com/BishopFox/cloudfoxable", source_type=SourceType.GITHUB_REPO, domain="cloud", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["cloud", "aws"], description="CloudFoxable — exploitable cloud environment."),
]


# ═════════════════════════════════════════════════════════════════════════════
# DATABASE — Database security assessment
# ═════════════════════════════════════════════════════════════════════════════

_DATABASE_STRATEGIES: list[SourceConfig] = [
    SourceConfig(
        name="DatabaseSecurityAudit",
        url="https://github.com/JFR-C/Database-Security-Audit",
        source_type=SourceType.GITHUB_REPO,
        domain="database",
        category="methodology",
        content_type=ContentType.STRATEGIES,
        branch="main",
        include_patterns=["**/*.md"],
        tags=["database", "audit", "sql", "security"],
        description="Database Security Audit — practical database security assessment checklist and guidance.",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE — Internal pentest, AD, privilege escalation
# ═════════════════════════════════════════════════════════════════════════════

_INFRASTRUCTURE_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, priority=1, branch="main", clone_id="InternalAllTheThings", include_patterns=["**/*.md"], exclude_patterns=["**/CONTRIBUTING.md", "**/LICENSE*"], tags=["active-directory", "internal", "kerberos"], license="MIT", description="AD & internal pentest cheatsheets."),
    SourceConfig(name="OSCP-Notes", url="https://github.com/0xsyr0/OSCP", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["oscp", "methodology"], description="OSCP notes and cheatsheets."),
]

_INFRASTRUCTURE_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="ADExploitCheatSheet", url="https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="active_directory", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["active-directory", "exploitation"], description="AD exploitation cheat sheet."),
    SourceConfig(name="GOAD", url="https://github.com/Orange-Cyberdefense/GOAD", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="active_directory", content_type=ContentType.ATTACK_TYPES, branch="main", include_patterns=["**/*.md"], tags=["active-directory", "lab", "goad"], description="Game of Active Directory."),
    SourceConfig(name="GTFOBins", url="https://gtfobins.github.io/", source_type=SourceType.WEBSITE, domain="linux_server", category="privilege_escalation", content_type=ContentType.ATTACK_TYPES, priority=1, include_patterns=["https://gtfobins.github.io/gtfobins/**"], css_selector="article.bins", max_pages=500, default_metadata={"target": "linux_server", "attack_phase": "privilege_escalation", "platform": ["linux"]}, tags=["gtfobins", "linux", "privilege-escalation"], description="GTFOBins — Unix binaries for privesc."),
    SourceConfig(name="LOLBAS", url="https://lolbas-project.github.io/", source_type=SourceType.WEBSITE, domain="linux_server", category="privilege_escalation", content_type=ContentType.ATTACK_TYPES, priority=1, include_patterns=["https://lolbas-project.github.io/lolbas/**"], css_selector=".main-content", max_pages=500, default_metadata={"target": "linux_server", "attack_phase": "privilege_escalation", "platform": ["windows"]}, tags=["lolbas", "windows", "living-off-the-land"], description="LOLBAS — Living Off The Land Binaries for Windows."),
    SourceConfig(name="PAT-InfraPostExploitation", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="post_exploitation", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Windows - Persistence.md", "**/Linux - Persistence.md", "**/Credential Access.md", "**/Lateral Movement.md"], tags=["payloadsallthethings", "post-exploitation", "persistence", "lateral-movement"], description="Consolidated infrastructure post-exploitation techniques from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# NETWORK — Network pentesting, wireless
# ═════════════════════════════════════════════════════════════════════════════

_NETWORK_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings-Network", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="methodology", content_type=ContentType.STRATEGIES, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/redteam/pivoting", include_patterns=["**/*.md"], tags=["network", "pivoting", "internal"], description="InternalAllTheThings — network pivoting techniques and tools."),
]

_NETWORK_TOOLS: list[SourceConfig] = [
    SourceConfig(name="H4cker-NetToolCheatsheets", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="tools", content_type=ContentType.TOOLS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/networking", include_patterns=["**/*.md"], tags=["nmap", "wireshark", "tcpdump", "netcat", "scapy", "tshark"], description="H4cker — network tool cheat sheets."),
]

_NETWORK_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="H4cker-ProtocolExploits", url="https://github.com/The-Art-of-Hacking/h4cker", source_type=SourceType.GITHUB_REPO, domain="network", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", clone_id="h4cker", subdirectory="cheat-sheets/networking", include_patterns=["**/insecure-protocols.md"], tags=["arp-poisoning", "dns-poisoning", "vlan-hopping", "protocol-exploits"], description="H4cker — insecure protocol exploitation."),
]

_NETWORK_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="MitreAttack-Discovery", url="https://attack.mitre.org/tactics/TA0007/", source_type=SourceType.WEBSITE, domain="network", category="attack-types", content_type=ContentType.ATTACK_TYPES, max_pages=30, tags=["mitre", "discovery", "T1046", "T1040", "network-scanning"], description="MITRE ATT&CK Discovery tactic."),
    SourceConfig(name="MitreAttack-LateralMovement", url="https://attack.mitre.org/tactics/TA0008/", source_type=SourceType.WEBSITE, domain="network", category="attack-types", content_type=ContentType.ATTACK_TYPES, max_pages=30, tags=["mitre", "lateral-movement", "T1557", "T1021", "network-attacks"], description="MITRE ATT&CK Lateral Movement tactic."),
    SourceConfig(name="PAT-NetworkAttackTypes", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="network", category="payloads", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", include_patterns=["DNS Rebinding/**/*.md", "LDAP Injection/**/*.md"], tags=["payloadsallthethings", "network", "attack-types"], description="Consolidated network attack-type payload references from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# RECON — Reconnaissance and OSINT
# ═════════════════════════════════════════════════════════════════════════════

_RECON_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="AwesomeAssetDiscovery", url="https://github.com/redhuntlabs/Awesome-Asset-Discovery", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["recon", "asset-discovery"], description="Awesome Asset Discovery resources."),
    SourceConfig(name="InternalAllTheThings-Recon", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/recon", include_patterns=["**/*.md"], tags=["recon", "internal"], description="InternalAllTheThings — recon techniques."),
    SourceConfig(name="PAT-ReconStrategies", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Subdomains Enumeration.md", "**/Methodology and enumeration.md"], tags=["payloadsallthethings", "recon", "methodology"], description="Consolidated reconnaissance methodology from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# RED_TEAM — Red team operations
# ═════════════════════════════════════════════════════════════════════════════

_RED_TEAM_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="RedTeamInfraWiki", url="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki", source_type=SourceType.GITHUB_REPO, domain="shared", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["red-team", "infrastructure", "c2"], description="Red Team Infrastructure Wiki."),
]

_RED_TEAM_TOOLS: list[SourceConfig] = [
    SourceConfig(name="MythicC2-Docs", url="https://docs.mythic-c2.net/", source_type=SourceType.WEBSITE, domain="shared", category="c2_knowledge", content_type=ContentType.TOOLS, max_pages=200, tags=["mythic", "c2"], description="Mythic C2 documentation."),
    SourceConfig(name="SliverC2-Wiki", url="https://github.com/BishopFox/sliver", source_type=SourceType.GITHUB_REPO, domain="shared", category="c2_knowledge", content_type=ContentType.TOOLS, branch="master", include_patterns=["**/*.md"], tags=["sliver", "c2"], description="Sliver C2 wiki."),
]

_RED_TEAM_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="PAT-RedTeamAttackTypes", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="shared", category="payloads_evasion", content_type=ContentType.ATTACK_TYPES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Phishing.md", "**/Reverse Shell Cheatsheet.md"], tags=["payloadsallthethings", "red-team", "phishing", "reverse-shell"], description="Consolidated red-team attack techniques from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# BINARY — Binary exploitation and reverse engineering
# ═════════════════════════════════════════════════════════════════════════════

_BINARY_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="Ir0nstoneNotes", url="https://ir0nstone.gitbook.io/notes", source_type=SourceType.GITBOOK, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, max_pages=200, tags=["binary", "exploitation", "rop", "heap"], description="ir0nstone's binary exploitation notes."),
    SourceConfig(name="CTFAllInOne", url="https://github.com/firmianay/CTF-All-In-One", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["ctf", "binary"], description="CTF All-In-One guide."),
    SourceConfig(name="RPISEC-MBE", url="https://github.com/RPISEC/MBE", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["binary", "education"], description="RPISEC Modern Binary Exploitation."),
    SourceConfig(name="ARMExploitation", url="https://github.com/IOActive/ARM-Exploitation", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="arm_embedded", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["arm", "exploitation", "embedded"], description="ARM exploitation techniques."),
    SourceConfig(name="ReverseEngineeringBeginners", url="https://github.com/malware-unicorn/reverse-engineering-for-beginners", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="reverse_engineering", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["reverse-engineering", "malware"], description="Reverse engineering for beginners."),
    SourceConfig(name="PAT-BinaryStrategies", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Binary Exploitation", include_patterns=["**/*.md"], tags=["payloadsallthethings", "binary", "exploitation"], description="Consolidated binary exploitation methodology from PayloadsAllTheThings."),
]

_BINARY_ATTACK_TYPES: list[SourceConfig] = [
    SourceConfig(name="How2Heap", url="https://github.com/shellphish/how2heap", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="techniques", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md", "**/*.c"], tags=["heap", "exploitation"], description="How2Heap — heap exploitation techniques."),
    SourceConfig(name="CTFPwnTips", url="https://github.com/Naetw/CTF-pwn-tips", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="techniques", content_type=ContentType.ATTACK_TYPES, branch="master", include_patterns=["**/*.md"], tags=["ctf", "pwn"], description="CTF pwn tips."),
]


# ═════════════════════════════════════════════════════════════════════════════
# IDENTITY — Identity security (AAD, OAuth, SAML, Kerberos)
# ═════════════════════════════════════════════════════════════════════════════

_IDENTITY_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="AzureADAttackDefense", url="https://github.com/dirkjanm/AzureAD-Attack-Defense", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["azure-ad", "identity"], description="Azure AD attack and defense."),
    SourceConfig(name="PAT-IdentityStrategies", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="methodology", content_type=ContentType.STRATEGIES, branch="master", clone_id="PayloadsAllTheThings", subdirectory="SAML Injection", include_patterns=["**/*.md"], tags=["payloadsallthethings", "identity", "saml"], description="Consolidated identity/SAML attack techniques from PayloadsAllTheThings."),
]

_IDENTITY_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="InternalAllTheThings-AzureAD", url="https://github.com/swisskyrepo/InternalAllTheThings", source_type=SourceType.GITHUB_REPO, domain="linux_server", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", clone_id="InternalAllTheThings", subdirectory="docs/cloud", include_patterns=["**/azure-azure-active-directory.md", "**/azure-azure-ad-connect.md"], tags=["azure-ad", "exploitation"], description="Azure AD exploitation techniques."),
]


# ═════════════════════════════════════════════════════════════════════════════
# SUPPLY_CHAIN — CI/CD, dependency confusion, IaC
# ═════════════════════════════════════════════════════════════════════════════

_SUPPLY_CHAIN_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="OWASP-CICDTop10", url="https://github.com/OWASP/www-project-top-10-ci-cd-security-risks", source_type=SourceType.GITHUB_REPO, domain="repository", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["cicd", "owasp", "supply-chain"], description="OWASP Top 10 CI/CD Security Risks."),
    SourceConfig(name="OSSFScorecard", url="https://github.com/ossf/scorecard", source_type=SourceType.GITHUB_REPO, domain="repository", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["ossf", "supply-chain"], description="OpenSSF Scorecard."),
]

_SUPPLY_CHAIN_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="PAT-SupplyChainExploits", url="https://github.com/swisskyrepo/PayloadsAllTheThings", source_type=SourceType.GITHUB_REPO, domain="repository", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", clone_id="PayloadsAllTheThings", subdirectory="Dependency Confusion", include_patterns=["**/*.md"], tags=["payloadsallthethings", "supply-chain", "dependency-confusion"], description="Consolidated supply-chain exploitation techniques from PayloadsAllTheThings."),
]


# ═════════════════════════════════════════════════════════════════════════════
# WEB3 — Smart contracts, DeFi, blockchain
# ═════════════════════════════════════════════════════════════════════════════

_WEB3_STRATEGIES: list[SourceConfig] = [
    SourceConfig(name="NotSoSmartContracts", url="https://github.com/crytic/not-so-smart-contracts", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md", "**/*.sol"], tags=["solidity", "smart-contracts"], description="Not So Smart Contracts vulnerabilities."),
    SourceConfig(name="SmartContractVulnerabilities", url="https://github.com/kadenzipfel/smart-contract-vulnerabilities", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, branch="main", include_patterns=["**/*.md"], tags=["smart-contracts", "vulnerabilities"], description="Smart contract vulnerability patterns."),
    SourceConfig(name="SoliditySecurityBlog", url="https://github.com/sigp/solidity-security-blog", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["solidity", "security"], description="Solidity security attack patterns."),
    SourceConfig(name="SWCRegistry", url="https://swcregistry.io/", source_type=SourceType.WEBSITE, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, max_pages=100, tags=["swc", "smart-contracts"], description="SWC Registry."),
    SourceConfig(name="SmartContractBestPractices", url="https://github.com/ConsenSys/smart-contract-best-practices", source_type=SourceType.GITHUB_REPO, domain="web_app", category="methodology", content_type=ContentType.STRATEGIES, branch="master", include_patterns=["**/*.md"], tags=["smart-contracts", "best-practices"], description="ConsenSys smart contract best practices."),
]

_WEB3_EXPLOITS: list[SourceConfig] = [
    SourceConfig(name="Web3SecurityLibrary", url="https://github.com/immunefi-team/Web3-Security-Library", source_type=SourceType.GITHUB_REPO, domain="web_app", category="exploitation", content_type=ContentType.EXPLOITS, branch="main", include_patterns=["**/*.md"], tags=["web3", "security", "immunefi"], description="Immunefi Web3 Security Library."),
    SourceConfig(name="DamnVulnerableDeFi", url="https://github.com/damnvulnerabledefi/damn-vulnerable-defi", source_type=SourceType.GITHUB_REPO, domain="web_app", category="exploitation", content_type=ContentType.EXPLOITS, branch="master", include_patterns=["**/*.md"], tags=["defi", "vulnerable"], description="Damn Vulnerable DeFi challenges."),
]


# ═════════════════════════════════════════════════════════════════════════════
# COMPLIANCE — Reporting and compliance frameworks
# ═════════════════════════════════════════════════════════════════════════════

_COMPLIANCE_STANDARDS: list[SourceConfig] = [
]


# ═════════════════════════════════════════════════════════════════════════════
# RUNTIME APIS — Never embedded, called live at scan time
# ═════════════════════════════════════════════════════════════════════════════

_RUNTIME_APIS: list[SourceConfig] = [
    SourceConfig(name="Shodan", url="https://api.shodan.io", source_type=SourceType.API, domain="shared", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, api_params={"key": "env:SHODAN_API_KEY"}, tags=["shodan", "recon", "iot"], description="Shodan API."),
    SourceConfig(name="Censys", url="https://search.censys.io/api", source_type=SourceType.API, domain="shared", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, api_params={"key": "env:CENSYS_API_KEY"}, tags=["censys", "recon", "certificates"], description="Censys API."),
    SourceConfig(name="CrtSh", url="https://crt.sh", source_type=SourceType.API, domain="shared", category="asset_discovery", content_type=ContentType.STRATEGIES, is_runtime=True, priority=1, tags=["crt.sh", "certificates", "subdomains"], description="crt.sh — certificate transparency log search."),
    SourceConfig(name="HIBP", url="https://haveibeenpwned.com/api/v3", source_type=SourceType.API, domain="shared", category="credential_intel", content_type=ContentType.STRATEGIES, is_runtime=True, api_params={"key": "env:HIBP_API_KEY"}, tags=["hibp", "breach", "credentials"], description="Have I Been Pwned API."),
    SourceConfig(name="VirusTotal", url="https://www.virustotal.com/api/v3", source_type=SourceType.API, domain="shared", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:VT_API_KEY"}, tags=["virustotal", "malware", "ioc"], description="VirusTotal API."),
    SourceConfig(name="GreyNoise", url="https://api.greynoise.io/v3", source_type=SourceType.API, domain="shared", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:GREYNOISE_API_KEY"}, tags=["greynoise", "noise", "threat-intel"], description="GreyNoise API."),
    SourceConfig(name="AbuseIPDB", url="https://api.abuseipdb.com/api/v2", source_type=SourceType.API, domain="shared", category="threat_intel", content_type=ContentType.EXPLOITS, is_runtime=True, api_params={"key": "env:ABUSEIPDB_API_KEY"}, tags=["abuseipdb", "ip-reputation"], description="AbuseIPDB API."),
    SourceConfig(name="NVD-Runtime", url="https://services.nvd.nist.gov/rest/json/cves/2.0", source_type=SourceType.API, domain="shared", category="intelligence", content_type=ContentType.EXPLOITS, is_runtime=True, priority=1, api_params={"key": "env:NVD_API_KEY"}, tags=["cve", "nvd", "vulnerability"], description="NVD CVE 2.0 API."),
    SourceConfig(name="ExploitDB-Runtime", url="https://exploit-db.com", source_type=SourceType.API, domain="shared", category="exploits", content_type=ContentType.EXPLOITS, is_runtime=True, priority=1, tags=["exploitdb", "exploits"], description="ExploitDB — searchsploit at runtime."),
    SourceConfig(name="GitHub-SecLists", url="https://api.github.com/repos/danielmiessler/SecLists", source_type=SourceType.API, domain="shared", category="wordlists", content_type=ContentType.TOOLS, is_runtime=True, priority=1, tags=["seclists", "wordlists"], description="SecLists via GitHub API."),
]


# ═════════════════════════════════════════════════════════════════════════════
# INTEL AGENT — Updatable source names
# ═════════════════════════════════════════════════════════════════════════════

INTEL_UPDATABLE_SOURCES: list[str] = [
    "PayloadsAllTheThings",
    "HackTricks",
    "CISA-KEV",
    "Vulhub",
    "OWASP-WSTG",
    "OWASP-APISecurity",
    "OWASP-MASTG",
    "OWASP-FSTM",
    "MITRE-ATTACK-Enterprise",
]


# ═════════════════════════════════════════════════════════════════════════════
# PAYLOAD SOURCES — Raw payload strings → PayloadStore (JSON), NOT Qdrant
# ═════════════════════════════════════════════════════════════════════════════

class PayloadSourceConfig(BaseModel):
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


_WEB_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="FuzzDB-SQLi", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="sqli", branch="master", clone_id="fuzzdb", subdirectory="attack/sql-injection", include_patterns=["**/*.txt"], tags=["sqli", "fuzzdb"], description="FuzzDB — SQL injection payloads."),
    PayloadSourceConfig(name="FuzzDB-XSS", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="xss", branch="master", clone_id="fuzzdb", subdirectory="attack/xss", include_patterns=["**/*.txt"], tags=["xss", "fuzzdb"], description="FuzzDB — XSS payloads."),
    PayloadSourceConfig(name="FuzzDB-OSCmd", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="command_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/os-cmd-execution", include_patterns=["**/*.txt"], tags=["command-injection", "rce", "fuzzdb"], description="FuzzDB — OS command injection payloads."),
    PayloadSourceConfig(name="FuzzDB-LFI", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="lfi", branch="master", clone_id="fuzzdb", subdirectory="attack/lfi", include_patterns=["**/*.txt"], tags=["lfi", "path-traversal", "fuzzdb"], description="FuzzDB — LFI / path traversal payloads."),
    PayloadSourceConfig(name="FuzzDB-FileUpload", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="file_upload", branch="master", clone_id="fuzzdb", subdirectory="attack/file-upload", include_patterns=["**/*.txt"], tags=["file-upload", "fuzzdb"], description="FuzzDB — file upload bypass payloads."),
    PayloadSourceConfig(name="FuzzDB-LDAP", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="ldap_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/ldap", include_patterns=["**/*.txt"], tags=["ldap", "injection", "fuzzdb"], description="FuzzDB — LDAP injection payloads."),
    PayloadSourceConfig(name="FuzzDB-XPath", url="https://github.com/fuzzdb-project/fuzzdb", domain="web_app", category="xpath_injection", branch="master", clone_id="fuzzdb", subdirectory="attack/xpath", include_patterns=["**/*.txt"], tags=["xpath", "injection", "fuzzdb"], description="FuzzDB — XPath injection payloads."),
    PayloadSourceConfig(name="H4cker-XSSPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web_app", category="xss", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/more-xxs-payloads.txt", "**/xss_obfuscation_vectors.txt"], tags=["xss", "obfuscation"], description="H4cker — XSS payloads."),
    PayloadSourceConfig(name="H4cker-SQLiPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web_app", category="sqli", branch="master", clone_id="h4cker", subdirectory="more-payloads/SQLi", include_patterns=["**/*.txt"], tags=["sqli"], description="H4cker — SQL injection payloads."),
    PayloadSourceConfig(name="H4cker-CmdInjPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web_app", category="command_injection", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/command_injection_unix.txt"], tags=["command-injection", "unix"], description="H4cker — Unix command injection payloads."),
    PayloadSourceConfig(name="H4cker-SSTIPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web_app", category="ssti", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/server-side-template-injection.txt"], tags=["ssti", "template-injection"], description="H4cker — SSTI payloads."),
    PayloadSourceConfig(name="H4cker-XXEPayloads", url="https://github.com/The-Art-of-Hacking/h4cker", domain="web_app", category="xxe", branch="master", clone_id="h4cker", subdirectory="more-payloads", include_patterns=["**/xxe-injection-payloads.md"], tags=["xxe", "xml"], description="H4cker — XXE injection payloads."),
    PayloadSourceConfig(name="IntruderPayloads-SQLi", url="https://github.com/1N3/IntruderPayloads", domain="web_app", category="sqli", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/sqli-*.txt"], tags=["sqli", "intruder"], description="IntruderPayloads — SQLi fuzz lists."),
    PayloadSourceConfig(name="IntruderPayloads-XSS", url="https://github.com/1N3/IntruderPayloads", domain="web_app", category="xss", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/xss*.txt"], tags=["xss", "intruder"], description="IntruderPayloads — XSS fuzz lists."),
    PayloadSourceConfig(name="IntruderPayloads-LFI", url="https://github.com/1N3/IntruderPayloads", domain="web_app", category="lfi", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/lfi.txt"], tags=["lfi", "intruder"], description="IntruderPayloads — LFI fuzz list."),
    PayloadSourceConfig(name="IntruderPayloads-CmdExec", url="https://github.com/1N3/IntruderPayloads", domain="web_app", category="command_injection", branch="master", clone_id="IntruderPayloads", subdirectory="FuzzLists", include_patterns=["**/command_exec.txt"], tags=["command-injection", "intruder"], description="IntruderPayloads — command execution fuzz list."),
]

_API_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-API-GraphQL", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="api", category="graphql_injection", branch="master", clone_id="PayloadsAllTheThings", subdirectory="GraphQL Injection", include_patterns=["**/*.md"], tags=["api", "graphql", "payloadsallthethings"], description="PayloadsAllTheThings — GraphQL injection payload references."),
    PayloadSourceConfig(name="PATPayload-API-JWT", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="api", category="jwt_attacks", branch="master", clone_id="PayloadsAllTheThings", subdirectory="JSON Web Token", include_patterns=["**/*.md"], tags=["api", "jwt", "payloadsallthethings"], description="PayloadsAllTheThings — JWT attack payload references."),
    PayloadSourceConfig(name="PATPayload-API-OAuth", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="api", category="oauth_misconfig", branch="master", clone_id="PayloadsAllTheThings", subdirectory="OAuth Misconfiguration", include_patterns=["**/*.md"], tags=["api", "oauth", "payloadsallthethings"], description="PayloadsAllTheThings — OAuth misconfiguration payload references."),
]

_NETWORK_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-NET-DNSRebinding", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="network", category="dns_rebinding", branch="master", clone_id="PayloadsAllTheThings", subdirectory="DNS Rebinding", include_patterns=["**/*.md"], tags=["network", "dns-rebinding", "payloadsallthethings"], description="PayloadsAllTheThings — DNS rebinding payload references."),
    PayloadSourceConfig(name="PATPayload-NET-LDAPInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="network", category="ldap_injection", branch="master", clone_id="PayloadsAllTheThings", subdirectory="LDAP Injection", include_patterns=["**/*.md"], tags=["network", "ldap", "payloadsallthethings"], description="PayloadsAllTheThings — LDAP injection payload references."),
]

_INFRASTRUCTURE_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-INFRA-PersistenceWindows", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="windows_persistence", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Windows - Persistence.md"], tags=["infrastructure", "windows", "persistence"], description="PayloadsAllTheThings — Windows persistence payload references."),
    PayloadSourceConfig(name="PATPayload-INFRA-PersistenceLinux", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="linux_persistence", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Linux - Persistence.md"], tags=["infrastructure", "linux", "persistence"], description="PayloadsAllTheThings — Linux persistence payload references."),
    PayloadSourceConfig(name="PATPayload-INFRA-CredentialAccess", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="credential_access", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Credential Access.md"], tags=["infrastructure", "credentials", "payloadsallthethings"], description="PayloadsAllTheThings — credential access payload references."),
    PayloadSourceConfig(name="PATPayload-INFRA-LateralMovement", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="lateral_movement", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Lateral Movement.md"], tags=["infrastructure", "lateral-movement", "payloadsallthethings"], description="PayloadsAllTheThings — lateral movement payload references."),
]

_IDENTITY_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-IDENTITY-SAML", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="saml_injection", branch="master", clone_id="PayloadsAllTheThings", subdirectory="SAML Injection", include_patterns=["**/*.md"], tags=["identity", "saml", "payloadsallthethings"], description="PayloadsAllTheThings — SAML injection payload references."),
]

_BINARY_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-BINARY-Exploitation", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="linux_server", category="binary_exploitation", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Binary Exploitation", include_patterns=["**/*.md"], tags=["binary", "exploitation", "payloadsallthethings"], description="PayloadsAllTheThings — binary exploitation payload references."),
]

_SUPPLY_CHAIN_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-SUPPLY-DependencyConfusion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="repository", category="dependency_confusion", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Dependency Confusion", include_patterns=["**/*.md"], tags=["supply-chain", "dependency-confusion", "payloadsallthethings"], description="PayloadsAllTheThings — dependency confusion payload references."),
]

_SHARED_PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    PayloadSourceConfig(name="PATPayload-SHARED-Evasion", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="shared", category="evasion", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Methodology and Resources", include_patterns=["**/Evasion.md", "**/Defense Evasion.md"], tags=["shared", "evasion", "payloadsallthethings"], description="PayloadsAllTheThings — evasion payload references."),
    PayloadSourceConfig(name="PromptInjection-Defenses", url="https://github.com/tldrsec/prompt-injection-defenses", domain="shared", category="prompt_injection", branch="main", clone_id="prompt-injection-defenses", include_patterns=["**/*.md"], tags=["prompt-injection", "llm", "jailbreak"], description="Prompt-injection patterns and defenses (used as prompt-attack corpus)."),
    PayloadSourceConfig(name="PATPayload-PromptInjection", url="https://github.com/swisskyrepo/PayloadsAllTheThings", domain="shared", category="prompt_injection", branch="master", clone_id="PayloadsAllTheThings", subdirectory="Prompt Injection", include_patterns=["**/*.md"], tags=["prompt-injection", "llm", "payloadsallthethings"], description="PayloadsAllTheThings — prompt injection payload references."),
]

PAYLOAD_SOURCES: list[PayloadSourceConfig] = [
    *_WEB_PAYLOAD_SOURCES,
    *_API_PAYLOAD_SOURCES,
    *_NETWORK_PAYLOAD_SOURCES,
    *_INFRASTRUCTURE_PAYLOAD_SOURCES,
    *_IDENTITY_PAYLOAD_SOURCES,
    *_BINARY_PAYLOAD_SOURCES,
    *_SUPPLY_CHAIN_PAYLOAD_SOURCES,
    *_SHARED_PAYLOAD_SOURCES,
]


# ═════════════════════════════════════════════════════════════════════════════
# AGGREGATE REGISTRY
# ═════════════════════════════════════════════════════════════════════════════

ALL_SOURCES: list[SourceConfig] = [
    # SHARED
    *_SHARED_STRATEGIES,
    *_SHARED_EXPLOITS,
    *_SHARED_TOOLS,
    *_SHARED_STANDARDS,
    *_SHARED_ATTACK_TYPES,

    # WEB
    *_WEB_STRATEGIES,
    *_WEB_STANDARDS,
    *_WEB_ATTACK_TYPES,
    *_WEB_TOOLS,

    # API
    *_API_STRATEGIES,
    *_API_STANDARDS,
    *_API_ATTACK_TYPES,

    # MOBILE
    *_MOBILE_STRATEGIES,
    *_MOBILE_EXPLOITS,

    # IOT
    *_IOT_STRATEGIES,

    # CLOUD
    *_CLOUD_STRATEGIES,
    *_CLOUD_EXPLOITS,

    # DATABASE
    *_DATABASE_STRATEGIES,

    # INFRASTRUCTURE
    *_INFRASTRUCTURE_STRATEGIES,
    *_INFRASTRUCTURE_ATTACK_TYPES,

    # NETWORK
    *_NETWORK_STRATEGIES,
    *_NETWORK_TOOLS,
    *_NETWORK_EXPLOITS,
    *_NETWORK_ATTACK_TYPES,

    # RECON
    *_RECON_STRATEGIES,

    # RED_TEAM
    *_RED_TEAM_STRATEGIES,
    *_RED_TEAM_TOOLS,
    *_RED_TEAM_ATTACK_TYPES,

    # BINARY
    *_BINARY_STRATEGIES,
    *_BINARY_ATTACK_TYPES,

    # IDENTITY
    *_IDENTITY_STRATEGIES,
    *_IDENTITY_EXPLOITS,

    # SUPPLY_CHAIN
    *_SUPPLY_CHAIN_STRATEGIES,
    *_SUPPLY_CHAIN_EXPLOITS,

    # WEB3
    *_WEB3_STRATEGIES,
    *_WEB3_EXPLOITS,

    # COMPLIANCE
    *_COMPLIANCE_STANDARDS,

    # Runtime APIs
    *_RUNTIME_APIS,
]


_all_names = [s.name.lower() for s in ALL_SOURCES]
_dupes = [n for n in _all_names if _all_names.count(n) > 1]
assert not _dupes, f"Duplicate source names in ALL_SOURCES: {set(_dupes)}"


@lru_cache(maxsize=1)
def _build_name_index() -> dict[str, SourceConfig]:
    return {s.name.lower(): s for s in ALL_SOURCES}


def get_enabled_sources() -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.enabled and not s.is_runtime]


def get_runtime_sources() -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.is_runtime and s.enabled]


def get_sources_by_domain(domain: str) -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.domain == domain and s.enabled and not s.is_runtime]


def get_sources_by_type(source_type: SourceType) -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.source_type == source_type and s.enabled]


def get_source_by_name(name: str) -> SourceConfig | None:
    return _build_name_index().get(name.lower())


def get_all_domains() -> list[str]:
    return sorted(set(s.domain for s in ALL_SOURCES))


def get_sources_by_priority(priority: int) -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.priority == priority and s.enabled and not s.is_runtime]


def get_sources_by_content_type(content_type: ContentType) -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.content_type == content_type and s.enabled and not s.is_runtime]


def get_fixed_sources() -> list[SourceConfig]:
    return [s for s in ALL_SOURCES if s.is_fixed and s.enabled and not s.is_runtime]
