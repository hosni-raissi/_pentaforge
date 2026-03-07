"""
Domain Registry — Maps security testing domains to their vector indexes.

Each domain has:
  - A dedicated Qdrant collection (pentaforge_<domain>)
  - A list of source categories it ingests
  - Runtime API endpoints (fetched live, never embedded)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Domain:
    """A security testing domain with its vector index and runtime APIs."""
    name: str
    vector_index: str
    description: str = ""
    api_runtime: list[str] = field(default_factory=list)


# ── Domain definitions ────────────────────────────────────────────────────

DOMAINS: dict[str, Domain] = {
    "shared": Domain(
        name="shared",
        vector_index="vector_shared",
        description="Cross-domain knowledge: methodologies, threat intel, exploits, secrets, compliance, detection/evasion",
    ),
    "web": Domain(
        name="web",
        vector_index="vector_web",
        description="Web application security testing",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://vulners.com/api/v3/search/lucene/",
            "https://sploitus.com/",
            "https://exploit.circl.lu/api/search",
        ],
    ),
    "api": Domain(
        name="api",
        vector_index="vector_api",
        description="API security testing (REST, GraphQL, gRPC)",
        api_runtime=[
            "https://keyhacks.io/",
            "https://haveibeenpwned.com/API/v3/breachedaccount",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://vulners.com/api/v3/search/lucene/",
        ],
    ),
    "mobile": Domain(
        name="mobile",
        vector_index="vector_mobile",
        description="Mobile application security (Android, iOS)",
        api_runtime=[
            "https://mobsf.live/api/v1",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
    ),
    "iot": Domain(
        name="iot",
        vector_index="vector_iot",
        description="IoT, hardware, firmware, radio protocols",
        api_runtime=[
            "https://api.shodan.io",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://sploitus.com/",
        ],
    ),
    "cloud": Domain(
        name="cloud",
        vector_index="vector_cloud",
        description="Cloud security (AWS, Azure, GCP, K8s, containers)",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://vulners.com/api/v3/search/lucene/",
            "https://sploitus.com/",
        ],
    ),
    "infrastructure": Domain(
        name="infrastructure",
        vector_index="vector_infrastructure",
        description="Infrastructure, Active Directory, privilege escalation, post-exploitation",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://vulners.com/api/v3/search/lucene/",
            "https://sploitus.com/",
        ],
    ),
    "network": Domain(
        name="network",
        vector_index="vector_network",
        description="Network pentesting, pivoting, wireless attacks",
        api_runtime=[
            "https://api.shodan.io",
            "https://api.censys.io/v2",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
    ),
    "recon": Domain(
        name="recon",
        vector_index="vector_recon",
        description="Reconnaissance, OSINT, passive/active discovery",
        api_runtime=[
            "https://api.shodan.io",
            "https://api.censys.io/v2",
            "https://crt.sh/?q=DOMAIN&output=json",
            "https://haveibeenpwned.com/API/v3/breachedaccount",
            "https://api.hunter.io/v2/domain-search",
            "https://leakix.net/api",
            "https://otx.alienvault.com/api/v1",
            "https://urlscan.io/api/v1/search/",
            "https://api.securitytrails.com/v1",
            "https://api.github.com/search/code",
            "https://www.virustotal.com/api/v3",
            "https://api.fullhunt.io/v1",
            "https://api.fofa.io",
            "https://api.binaryedge.io/v1",
        ],
    ),
    "cve_exploit": Domain(
        name="cve_exploit",
        vector_index="vector_cve_exploit",
        description="CVE intelligence, PoCs, attack chains",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://sploitus.com/",
            "https://exploit.circl.lu/api/search",
            "https://vulners.com/api/v3/search/lucene/",
            "https://api.github.com/search/repositories?q=CVE",
            "https://www.exploit-db.com/search",
        ],
    ),
    "red_team": Domain(
        name="red_team",
        vector_index="vector_red_team",
        description="Red team operations, C2, social engineering, threat actor simulation",
        api_runtime=[
            "https://otx.alienvault.com/api/v1",
            "https://api.github.com/search/repositories",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
    ),
    "binary": Domain(
        name="binary",
        vector_index="vector_binary",
        description="Binary exploitation, reverse engineering, ARM/embedded",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://sploitus.com/",
        ],
    ),
    "identity": Domain(
        name="identity",
        vector_index="vector_identity",
        description="Identity security (AAD, Okta, SAML, OAuth, Kerberos)",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
    ),
    "supply_chain": Domain(
        name="supply_chain",
        vector_index="vector_supply_chain",
        description="CI/CD attacks, dependency confusion, package takeover, IaC misconfigs",
        api_runtime=[
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://osv.dev/",
            "https://api.deps.dev/api/v3alpha/",
        ],
    ),
    "web3": Domain(
        name="web3",
        vector_index="vector_web3",
        description="Smart contracts, DeFi, on-chain vulnerabilities",
        api_runtime=[
            "https://api.etherscan.io/api",
            "https://api.opensea.io/api/v1",
        ],
    ),
    "compliance": Domain(
        name="compliance",
        vector_index="vector_compliance",
        description="Compliance frameworks, reporting templates, ASVS/PCI/NIST mappings",
        api_runtime=[],
    ),
}


# ── All vector index names ────────────────────────────────────────────────

VECTOR_INDEXES: list[str] = [d.vector_index for d in DOMAINS.values()]


class DomainRegistry:
    """Lookup helpers for domains."""

    @staticmethod
    def all_domains() -> list[Domain]:
        return list(DOMAINS.values())

    @staticmethod
    def get(name: str) -> Domain | None:
        return DOMAINS.get(name)

    @staticmethod
    def get_vector_index(name: str) -> str:
        domain = DOMAINS.get(name)
        if domain is None:
            raise ValueError(f"Unknown domain: {name}")
        return domain.vector_index

    @staticmethod
    def all_vector_indexes() -> list[str]:
        return VECTOR_INDEXES


def get_domain(name: str) -> Domain | None:
    """Shortcut to get a domain by name."""
    return DOMAINS.get(name)
