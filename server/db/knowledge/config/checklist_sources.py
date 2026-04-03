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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-44ver2.pdf",
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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-95.pdf",
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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-124r2.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-163r1.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf",
        ],
    },
    "cloud": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/main/index.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/enterprise/cloud/",
        ],
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-144.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-145.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-210.pdf",
        ],
    },
    "iot": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/owasp-istg/main/checklists/checklist.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/ics/",
        ],
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-183.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8259A.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        ],
    },
    "network": {
        "owasp": [],
        "mitre": [
            "https://attack.mitre.org/tactics/TA0007/",
            "https://attack.mitre.org/tactics/TA0008/",
            "https://attack.mitre.org/tactics/TA0011/",
        ],
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-113.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf",
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
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-128.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf",
        ],
    },
    "container": {
        "owasp": [
            "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-top-ten/main/index.md",
        ],
        "mitre": [
            "https://attack.mitre.org/matrices/enterprise/cloud/",
        ],
        "nist": [
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-125Ar1.pdf",
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
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
        "nist": [
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
            #"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf",g
            #"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v1r1.pdf",
        ],
    },
}