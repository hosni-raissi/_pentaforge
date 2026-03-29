from __future__ import annotations

import json
import re

from server.core.tool import tool

from .get_checklists import _normalize_target_type

_GENERIC_VULNERABILITY_NAMES = frozenset(
    {
        "vulnerability reproduction",
        "vulnerability reproduce",
        "reproduction",
        "exploit",
        "exploitation",
        "vulnerability",
    }
)

_KNOWN_VULNERABILITY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("sql injection", "SQL Injection"),
    ("stored cross site scripting", "Stored XSS"),
    ("reflected cross site scripting", "Reflected XSS"),
    ("dom based cross site scripting", "DOM XSS"),
    ("cross site scripting", "Cross-Site Scripting (XSS)"),
    ("xss", "Cross-Site Scripting (XSS)"),
    ("server-side request forgery", "Server-Side Request Forgery (SSRF)"),
    ("ssrf", "Server-Side Request Forgery (SSRF)"),
    ("server-side template injection", "Server-Side Template Injection (SSTI)"),
    ("ssti", "Server-Side Template Injection (SSTI)"),
    ("command injection", "Command Injection"),
    ("code injection", "Code Injection"),
    ("xml injection", "XML Injection"),
    ("xxe", "XML External Entity (XXE)"),
    ("csrf", "Cross-Site Request Forgery (CSRF)"),
    ("cross site request forgery", "Cross-Site Request Forgery (CSRF)"),
    ("idor", "Insecure Direct Object Reference (IDOR)"),
    ("insecure direct object reference", "Insecure Direct Object Reference (IDOR)"),
    ("mass assignment", "Mass Assignment"),
    ("oauth", "OAuth Weaknesses"),
    ("jwt", "JWT Weaknesses"),
    ("path traversal", "Path Traversal"),
    ("directory traversal", "Directory Traversal"),
    ("file include", "File Inclusion"),
    ("deserialization", "Insecure Deserialization"),
    ("request smuggling", "HTTP Request Smuggling"),
    ("host header injection", "Host Header Injection"),
    ("prototype pollution", "Prototype Pollution"),
    ("clickjacking", "Clickjacking"),
    ("open redirect", "Open Redirect"),
    ("file upload", "Unrestricted File Upload"),
    ("privilege escalation", "Privilege Escalation"),
    ("authentication schema", "Authentication Bypass"),
    ("authorization schema", "Authorization Bypass"),
    ("default credentials", "Default Credentials"),
    ("weak password", "Weak Password Policy"),
)


def _split_items(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []

    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("- ", "* ", "• ")):
            line = line[2:].strip()
        elif re.match(r"^\d+[\.\)]\s+", line):
            line = re.sub(r"^\d+[\.\)]\s+", "", line).strip()
        lines.append(line)

    if not lines and text:
        lines = [part.strip() for part in re.split(r"[;,]", text) if part.strip()]

    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(line)
    return deduped


def _normalize_known_vulnerability(value: str) -> str:
    clean = re.sub(r"\s+", " ", str(value or "").strip(" -\t\r\n:;,")).strip()
    if not clean:
        return ""

    lowered = clean.lower()
    if lowered in _GENERIC_VULNERABILITY_NAMES:
        return ""
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, flags=re.IGNORECASE):
        return clean

    for needle, label in _KNOWN_VULNERABILITY_PATTERNS:
        if needle in lowered:
            return label
    return ""


def _filter_known_vulnerabilities(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = _normalize_known_vulnerability(item)
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def _as_section(title: str, items: list[str]) -> str:
    if not items:
        return f"{title}:\n- (none found)"
    return "\n".join([f"{title}:", *[f"- {item}" for item in items]])


@tool(
    name="set_checklist",
    description=(
        "Finalize and normalize checklist output for the target. "
        "Accepts text blocks for methods, techniques, vulnerabilities, and checklist items, "
        "then returns a normalized JSON object and summary block."
    ),
)
async def set_checklist(
    target_type: str,
    checklist: str,
    techniques: str = "",
    vulnerabilities: str = "",
    methods: str = "",
    gaps: str = "",
) -> str:
    normalized_target = _normalize_target_type(target_type)
    methods_items = _split_items(methods)
    techniques_items = _split_items(techniques)
    vulnerabilities_items = _filter_known_vulnerabilities(_split_items(vulnerabilities))
    checklist_items = _split_items(checklist)
    gap_items = _split_items(gaps)

    sections = []
    if vulnerabilities_items:
        sections.append(_as_section("KNOWN VULNERABILITIES", vulnerabilities_items))
    sections.append(_as_section("CHECKLIST", checklist_items))
    sections.append(_as_section("GAPS", gap_items))
    summary = "\n\n".join(sections)

    return json.dumps(
        {
            "target_type": normalized_target,
            "counts": {
                "methods": len(methods_items),
                "techniques": len(techniques_items),
                "vulnerabilities": len(vulnerabilities_items),
                "checklist": len(checklist_items),
                "gaps": len(gap_items),
            },
            "methods": methods_items,
            "techniques": techniques_items,
            "vulnerabilities": vulnerabilities_items,
            "checklist": checklist_items,
            "gaps": gap_items,
            "summary": summary,
        },
        ensure_ascii=True,
    )
