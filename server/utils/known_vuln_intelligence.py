from __future__ import annotations

import re
from typing import Any


_PRODUCT_PROFILES: dict[str, dict[str, Any]] = {
    "nginx": {
        "aliases": ["openresty"],
        "legacy_field": "server",
        "run_custom_tools": ["nuclei", "nikto", "curl"],
        "nuclei_tags": ["nginx", "http", "misconfig", "cve"],
        "nuclei_templates": ["http/misconfiguration/", "http/cves/"],
        "kb_terms": ["nginx", "reverse proxy", "server banner"],
    },
    "apache http server": {
        "aliases": ["apache", "httpserver"],
        "legacy_field": "server",
        "run_custom_tools": ["nuclei", "nikto", "curl"],
        "nuclei_tags": ["apache", "http", "misconfig", "cve"],
        "nuclei_templates": ["http/misconfiguration/", "http/cves/"],
        "kb_terms": ["apache http server", "httpd"],
    },
    "apache tomcat": {
        "aliases": ["tomcat"],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["tomcat", "java", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposed-panels/"],
        "kb_terms": ["apache tomcat", "tomcat manager"],
    },
    "wordpress": {
        "aliases": ["wp"],
        "legacy_field": "framework",
        "run_custom_tools": ["wpscan", "nuclei", "curl"],
        "nuclei_tags": ["wordpress", "wp-plugin", "wp-theme", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposed-panels/wordpress/"],
        "kb_terms": ["wordpress", "wp plugin", "wp theme"],
    },
    "drupal": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["droopescan", "nuclei", "curl"],
        "nuclei_tags": ["drupal", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["drupal", "drupal module"],
    },
    "joomla": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["joomscan", "nuclei", "curl"],
        "nuclei_tags": ["joomla", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["joomla", "joomla extension"],
    },
    "django": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["django", "python", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["django"],
    },
    "flask": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["flask", "python", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["flask"],
    },
    "fastapi": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["fastapi", "python", "api", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposures/apis/"],
        "kb_terms": ["fastapi", "starlette"],
    },
    "express": {
        "aliases": ["express.js", "expressjs"],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["node", "express", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposures/apis/"],
        "kb_terms": ["express", "node.js"],
    },
    "next.js": {
        "aliases": ["nextjs", "next"],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["nextjs", "react", "node", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposures/"],
        "kb_terms": ["next.js"],
    },
    "react": {
        "aliases": [],
        "legacy_field": "frontend",
        "run_custom_tools": ["retire_js", "nuclei", "curl"],
        "nuclei_tags": ["react", "javascript", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["react"],
    },
    "angular": {
        "aliases": ["angularjs"],
        "legacy_field": "frontend",
        "run_custom_tools": ["retire_js", "nuclei", "curl"],
        "nuclei_tags": ["angular", "javascript", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["angular"],
    },
    "vue": {
        "aliases": ["vue.js", "vuejs"],
        "legacy_field": "frontend",
        "run_custom_tools": ["retire_js", "nuclei", "curl"],
        "nuclei_tags": ["vue", "javascript", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["vue"],
    },
    "jquery": {
        "aliases": [],
        "legacy_field": "frontend",
        "run_custom_tools": ["retire_js", "nuclei", "curl"],
        "nuclei_tags": ["jquery", "javascript", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["jquery", "frontend library"],
    },
    "bootstrap": {
        "aliases": [],
        "legacy_field": "frontend",
        "run_custom_tools": ["retire_js", "nuclei", "curl"],
        "nuclei_tags": ["bootstrap", "javascript", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["bootstrap"],
    },
    "php": {
        "aliases": [],
        "legacy_field": "backend_language",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["php", "cve"],
        "nuclei_templates": ["http/cves/"],
        "kb_terms": ["php"],
    },
    "spring": {
        "aliases": ["spring boot", "spring framework"],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["spring", "java", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposed-panels/"],
        "kb_terms": ["spring", "spring boot", "spring framework"],
    },
    "jenkins": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["jenkins", "cve"],
        "nuclei_templates": ["http/exposed-panels/", "http/cves/"],
        "kb_terms": ["jenkins"],
    },
    "grafana": {
        "aliases": [],
        "legacy_field": "framework",
        "run_custom_tools": ["nuclei", "curl"],
        "nuclei_tags": ["grafana", "cve"],
        "nuclei_templates": ["http/cves/", "http/exposed-panels/"],
        "kb_terms": ["grafana"],
    },
    "postgresql": {
        "aliases": ["postgres"],
        "legacy_field": "database",
        "run_custom_tools": ["nmap", "nuclei", "openssl"],
        "nuclei_tags": ["postgres", "cve"],
        "nuclei_templates": ["network/cves/"],
        "kb_terms": ["postgresql", "postgres"],
    },
    "mysql": {
        "aliases": ["mariadb"],
        "legacy_field": "database",
        "run_custom_tools": ["nmap", "nuclei", "openssl"],
        "nuclei_tags": ["mysql", "cve"],
        "nuclei_templates": ["network/cves/"],
        "kb_terms": ["mysql", "mariadb"],
    },
    "mongodb": {
        "aliases": ["mongo"],
        "legacy_field": "database",
        "run_custom_tools": ["nmap", "nuclei", "openssl"],
        "nuclei_tags": ["mongodb", "cve"],
        "nuclei_templates": ["network/cves/"],
        "kb_terms": ["mongodb"],
    },
    "redis": {
        "aliases": [],
        "legacy_field": "database",
        "run_custom_tools": ["nmap", "nuclei", "openssl"],
        "nuclei_tags": ["redis", "cve"],
        "nuclei_templates": ["network/cves/"],
        "kb_terms": ["redis"],
    },
}


_CANONICAL_BY_ALIAS: dict[str, str] = {}
for _canonical_name, _profile in _PRODUCT_PROFILES.items():
    alias_values = [_canonical_name, *(_profile.get("aliases", []) or [])]
    for _alias in alias_values:
        _CANONICAL_BY_ALIAS[re.sub(r"[^a-z0-9]+", "", _alias.lower())] = _canonical_name


def normalize_version_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"[-_][a-z]+.*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^[^0-9]+", "", text)
    text = re.sub(r"[^0-9.]+", "", text)
    return text.strip(".")


def canonicalize_product_name(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "", text.lower())
    if compact in _CANONICAL_BY_ALIAS:
        return _CANONICAL_BY_ALIAS[compact]

    lowered = text.lower()
    if lowered.startswith("apache/"):
        return "apache http server"
    if lowered.startswith("nginx/"):
        return "nginx"
    if lowered.startswith("openresty/"):
        return "nginx"
    if "wordpress" in lowered:
        return "wordpress"
    if "drupal" in lowered:
        return "drupal"
    if "joomla" in lowered:
        return "joomla"
    if "tomcat" in lowered:
        return "apache tomcat"
    if "spring" in lowered:
        return "spring"
    if "fastapi" in lowered:
        return "fastapi"
    if "django" in lowered:
        return "django"
    if "flask" in lowered:
        return "flask"
    if "express" in lowered:
        return "express"
    if "next" in lowered:
        return "next.js"
    if "react" in lowered:
        return "react"
    if "angular" in lowered:
        return "angular"
    if "vue" in lowered:
        return "vue"
    if "jquery" in lowered:
        return "jquery"
    if "bootstrap" in lowered:
        return "bootstrap"
    if "postgres" in lowered:
        return "postgresql"
    if "mysql" in lowered or "mariadb" in lowered:
        return "mysql"
    if "mongodb" in lowered:
        return "mongodb"
    if "redis" in lowered:
        return "redis"
    if "php" == lowered or lowered.startswith("php/"):
        return "php"
    return text


def get_product_profile(product_name: Any) -> dict[str, Any]:
    canonical = canonicalize_product_name(product_name)
    profile = _PRODUCT_PROFILES.get(canonical, {})
    merged = dict(profile)
    merged["canonical_name"] = canonical
    return merged


def confidence_label(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "low"
    if score >= 0.85:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def build_known_vuln_query(
    *,
    product: Any = "",
    version: Any = "",
    query: Any = "",
    attack_type: Any = "",
    severity: Any = "",
    target_type: Any = "",
    extra_terms: list[str] | None = None,
) -> str:
    canonical = canonicalize_product_name(product)
    normalized_version = normalize_version_text(version)
    clean_query = str(query or "").strip()
    clean_attack_type = str(attack_type or "").strip().lower()
    clean_severity = str(severity or "").strip().upper()
    clean_target_type = str(target_type or "").strip().lower()

    if clean_query:
        return clean_query

    terms: list[str] = []
    if canonical:
        terms.append(canonical)
    if normalized_version:
        terms.append(normalized_version)
    if clean_attack_type:
        terms.append(clean_attack_type)
    else:
        terms.append("known vulnerability")
    if clean_severity:
        terms.append(clean_severity)
    if clean_target_type:
        terms.append(clean_target_type)

    profile = get_product_profile(canonical)
    for term in profile.get("kb_terms", [])[:3]:
        text = str(term or "").strip()
        if text and text not in terms:
            terms.append(text)

    for term in extra_terms or []:
        text = str(term or "").strip()
        if text and text not in terms:
            terms.append(text)

    return " ".join(terms).strip() or "known vulnerability"


def recommend_run_custom_tools(
    fingerprints: list[dict[str, Any]] | None,
    *,
    limit: int = 8,
) -> list[str]:
    recommended: list[str] = []
    seen: set[str] = set()
    for row in fingerprints or []:
        if not isinstance(row, dict):
            continue
        profile = get_product_profile(row.get("product", row.get("name", "")))
        for tool_name in profile.get("run_custom_tools", []):
            clean = str(tool_name or "").strip()
            if clean and clean not in seen:
                seen.add(clean)
                recommended.append(clean)
                if len(recommended) >= limit:
                    return recommended
    return recommended


def recommend_nuclei_hints(fingerprints: list[dict[str, Any]] | None) -> dict[str, Any]:
    tags: list[str] = []
    templates: list[str] = []
    reasons: list[str] = []
    seen_tags: set[str] = set()
    seen_templates: set[str] = set()
    seen_reasons: set[str] = set()

    for row in fingerprints or []:
        if not isinstance(row, dict):
            continue
        product = canonicalize_product_name(row.get("product", row.get("name", "")))
        version = normalize_version_text(row.get("version"))
        profile = get_product_profile(product)
        for tag in profile.get("nuclei_tags", []):
            clean = str(tag or "").strip()
            if clean and clean not in seen_tags:
                seen_tags.add(clean)
                tags.append(clean)
        for template in profile.get("nuclei_templates", []):
            clean = str(template or "").strip()
            if clean and clean not in seen_templates:
                seen_templates.add(clean)
                templates.append(clean)
        reason = product
        if version:
            reason = f"{product} {version}"
        if reason and reason not in seen_reasons:
            seen_reasons.add(reason)
            reasons.append(reason)

    return {
        "tags": tags[:12],
        "templates": templates[:10],
        "reasons": reasons[:8],
        "mode": "selective" if tags or templates else "broad",
    }


def project_legacy_tech_stack(fingerprints: list[dict[str, Any]] | None) -> dict[str, str]:
    projected: dict[str, str] = {}
    for row in fingerprints or []:
        if not isinstance(row, dict):
            continue
        profile = get_product_profile(row.get("product", row.get("name", "")))
        field_name = str(profile.get("legacy_field", "")).strip()
        product = canonicalize_product_name(row.get("product", row.get("name", "")))
        version = normalize_version_text(row.get("version"))
        if not field_name or not product or field_name in projected:
            continue
        projected[field_name] = f"{product} {version}".strip()
    return projected
