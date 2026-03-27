from __future__ import annotations

from server.db.knowledge.config.sources import ContentType

GITHUB_API = "https://api.github.com"

REDIS_INTEL_CHANNEL = "pentaforge:intel_updates"

TRUSTED_SOURCES: dict[str, dict[str, str]] = {
    "OWASP-WSTG": {
        "url": "https://github.com/OWASP/wstg",
        "type": "standards_body",
    },
    "OWASP-APISecurity": {
        "url": "https://github.com/OWASP/API-Security",
        "type": "standards_body",
    },
    "MITRE-ATTACK": {
        "url": "https://attack.mitre.org",
        "type": "standards_body",
    },
    "MITRE-ATTACK-Enterprise": {
        "url": "https://attack.mitre.org/techniques/enterprise/",
        "type": "standards_body",
    },
    "PayloadsAllTheThings": {
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "type": "community_verified",
    },
    "HackTricks": {
        "url": "https://github.com/HackTricks-wiki/hacktricks",
        "type": "community_verified",
    },
    "ExploitDB": {"url": "https://www.exploit-db.com", "type": "curated"},
    "GitHub-PoC": {"url": "https://github.com", "type": "community"},
    "InternalAllTheThings": {
        "url": "https://github.com/swisskyrepo/InternalAllTheThings",
        "type": "community_verified",
    },
}

DOMAIN_CONTENT_TYPE: dict[str, str] = {
    "web_app": ContentType.EXPLOITS,
    "api": ContentType.EXPLOITS,
    "network": ContentType.ATTACK_TYPES,
    "mobile": ContentType.EXPLOITS,
    "cloud": ContentType.STRATEGIES,
    "container": ContentType.STRATEGIES,
    "iot": ContentType.STRATEGIES,
    "linux_server": ContentType.ATTACK_TYPES,
    "database": ContentType.ATTACK_TYPES,
    "desktop": ContentType.EXPLOITS,
    "repository": ContentType.STRATEGIES,
    "shared": ContentType.STRATEGIES,
    # Legacy aliases for backward compatibility.
    "web": ContentType.EXPLOITS,
    "infrastructure": ContentType.ATTACK_TYPES,
    "binary": ContentType.EXPLOITS,
    "identity": ContentType.ATTACK_TYPES,
    "supply_chain": ContentType.STRATEGIES,
    "web3": ContentType.EXPLOITS,
    "recon": ContentType.STRATEGIES,
    "red_team": ContentType.STRATEGIES,
}
