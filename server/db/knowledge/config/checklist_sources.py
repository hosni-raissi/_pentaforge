
# ═══════════════════════════════════════════════════════════════════════════════
#  Source registry
# ═══════════════════════════════════════════════════════════════════════════════

CHECKLIST_SOURCES: dict[str, dict[str, list[str]]] = {
    "web": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/tactics/TA0002/",
            "https://attack.mitre.org/tactics/TA0009/",
            "https://attack.mitre.org/tactics/TA0010/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "api": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0x11-t10.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa1-broken-object-level-authorization.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa2-broken-authentication.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa3-broken-object-property-level-authorization.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa4-unrestricted-resource-consumption.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa5-broken-function-level-authorization.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa7-server-side-request-forgery.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa8-security-misconfiguration.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa9-improper-inventory-management.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xaa-unsafe-consumption-of-apis.md",
        ],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/tactics/TA0010/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "mobile": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/mastg/master/Document/0x04b-Mobile-App-Security-Testing.md",
            "https://raw.githubusercontent.com/OWASP/mastg/master/Document/0x05b-Android-Security-Testing.md",
            "https://raw.githubusercontent.com/OWASP/mastg/master/Document/0x06b-iOS-Security-Testing.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/mobile/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "infra": {
        "owasp": [],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0003/",
            "https://attack.mitre.org/tactics/TA0004/",
            "https://attack.mitre.org/tactics/TA0008/",
            "https://attack.mitre.org/tactics/TA0006/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "cloud": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/main/index.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/enterprise/cloud/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "iot": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/owasp-istg/main/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/ics/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "network": {
        "owasp": [],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0007/",
            "https://attack.mitre.org/tactics/TA0008/",
            "https://attack.mitre.org/tactics/TA0011/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "database": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/tactics/TA0009/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "linux_server": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0003/",
            "https://attack.mitre.org/tactics/TA0004/",
            "https://attack.mitre.org/tactics/TA0008/",
            "https://attack.mitre.org/tactics/TA0006/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "container": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/main/index.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/enterprise/cloud/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    "repository": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/tactics/TA0003/",
            "https://attack.mitre.org/tactics/TA0006/",
        ],
        "ptes": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
}

