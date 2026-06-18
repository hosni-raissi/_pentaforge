"""Assistant-visible security tool catalog for the sandbox."""

from __future__ import annotations

from collections.abc import Iterable
import json

_ASSISTANT_SECURITY_TOOL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Core diagnostics",
        (
            "cat",
            "curl",
            "cut",
            "dig",
            "find",
            "git",
            "grep",
            "head",
            "jq",
            "ls",
            "mtr",
            "pwd",
            "searchsploit",
            "sed",
            "sort",
            "tail",
            "testssl",
            "testssl.sh",
            "tr",
            "traceroute",
            "uniq",
            "whois",
        ),
    ),
        (
            "Recon and fingerprinting",
            (
                "amass",
                "dnsrecon",
                "dnsx",
                "fping",
                "gau",
            "httpx",
            "katana",
            "naabu",
            "nbtscan",
            "nikto",
            "nmap",
            "nuclei",
                "subfinder",
                "subjs",
                "wafw00f",
                "whatweb",
                "wappalyzer",
                "zgrab2",
        ),
    ),
    (
        "Web and API testing",
        (
            "arjun",
            "dalfox",
            "ffuf",
            "gobuster",
            "gospider",
            "graphql-cop",
            "graphw00f",
            "grpcurl",
            "inql",
            "jwt-tool",
            "jwt_tool",
            "js-beautify",
            "kiterunner",
            "nosqlmap",
            "paramspider",
            "retire_js",
            "secretfinder",
            "sqlmap",
            "sslyze",
            "tplmap",
            "commix",
        ),
    ),
    (
        "Network and protocol tooling",
        (
            "enum4linux",
            "ike-scan",
            "impacket",
            "ldapsearch",
            "ldapdomaindump",
            "masscan",
            "onesixtyone",
            "proxychains",
            "rdp-sec-check",
            "smbclient",
            "smbmap",
            "snmpwalk",
            "ssh-audit",
            "ssh-mitm",
            "tcpdump",
            "tshark",
        ),
    ),
        (
            "Cloud and container security",
            (
                "aws",
                "checkov",
                "cloud_enum",
                "crane",
                "ctop",
                "dive",
            "docker",
            "grype",
            "kubectl",
            "kubectx",
            "kubens",
            "osv-scanner",
            "pacu",
            "prowler",
            "s3scanner",
            "skopeo",
            "stern",
            "syft",
            "trivy",
        ),
    ),
    (
        "Code, mobile, and firmware",
        (
            "aapt2",
            "actionlint",
            "apkid",
            "apkleaks",
            "apktool",
            "bandit",
            "binwalk",
            "cloc",
            "detect-secrets",
            "firmwalker",
            "gitleaks",
            "joomscan",
            "linpeas",
            "mobsfscan",
            "repo-supervisor",
            "semgrep",
            "trufflehog",
        ),
    ),
)


def _flatten(groups: Iterable[tuple[str, Iterable[str]]]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for _, tools in groups:
        for tool in tools:
            normalized = str(tool).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
    return tuple(ordered)


ASSISTANT_AVAILABLE_SECURITY_TOOLS: tuple[str, ...] = _flatten(_ASSISTANT_SECURITY_TOOL_GROUPS)

# Commands the assistant may execute in chat when they exist in the sandbox.
from server.agents.executor.run_custom_guard import _NETWORK_TARGET_COMMANDS

ASSISTANT_ALLOWED_NETWORK_COMMANDS: frozenset[str] = frozenset(
    _NETWORK_TARGET_COMMANDS
    | {
        "awk",
        "cat",
        "cut",
        "file",
        "find",
        "grep",
        "head",
        "jq",
        "ls",
        "pwd",
        "sed",
        "sha256sum",
        "sort",
        "split",
        "stat",
        "sudo",
        "tail",
        "tr",
        "uniq",
        "wc",
        "whois",
        "echo",
        "printf",
        "base64",
        "tee",
        "xargs",
        "less",
        "more",
    }
)


# Installed tools that can operate on local artifacts, code, containers, or cloud
# resources and therefore do not need the current target host embedded in args.
ASSISTANT_TARGET_OPTIONAL_COMMANDS: frozenset[str] = frozenset(
    {
        "aapt2",
        "actionlint",
        "apkid",
        "apkleaks",
        "apktool",
        "aws",
        "awk",
        "bandit",
        "binwalk",
        "cat",
        "checkov",
        "chisel",
        "cloc",
        "cloud_enum",
        "commix",
        "crane",
        "ctop",
        "cut",
        "detect-secrets",
        "dive",
        "docker",
        "file",
        "firmwalker",
        "find",
        "ffuf",
        "git",
        "gitleaks",
        "grep",
        "grype",
        "head",
        "impacket",
        "inql",
        "joomscan",
        "jq",
        "kubectl",
        "kubectx",
        "kubens",
        "linpeas",
        "ls",
        "mobsfscan",
        "nosqlmap",
        "osv-scanner",
        "pacu",
        "prowler",
        "pwd",
        "repo-supervisor",
        "s3scanner",
        "searchsploit",
        "sed",
        "semgrep",
        "sha256sum",
        "skopeo",
        "sort",
        "split",
        "sqlmap",
        "stat",
        "stern",
        "syft",
        "tail",
        "testssl",
        "testssl.sh",
        "tplmap",
        "tr",
        "trivy",
        "trufflehog",
        "uniq",
        "wc",
        "echo",
        "printf",
        "base64",
        "tee",
        "xargs",
        "less",
        "more",
    }
)

from server.agents.sandbox_wordlists import GLOBAL_SANDBOX_WORDLISTS as ASSISTANT_SANDBOX_WORDLISTS

ASSISTANT_SANDBOX_RUN_CUSTOM_CATALOG: dict[str, dict[str, object]] = {
    "curl": {
        "t": "http_client",
        "c": "manual_probe",
        "u": "curl -sk -o /dev/null -w \"%{http_code}\\n\" http://TARGET",
        "d": ["basic reachability", "status-code checks", "quick TLS-tolerant validation"],
        "tgt": ["web", "api", "host"],
    },
    "dig": {
        "t": "dns",
        "c": "resolution_check",
        "u": "dig +short TARGET",
        "d": ["hostname resolution", "DNS troubleshooting", "A/AAAA lookup"],
        "tgt": ["domain", "host"],
    },
    "httpx": {
        "t": "recon",
        "c": "http_probe",
        "u": "httpx -u http://TARGET -status-code -title -tech-detect",
        "d": ["web probing", "title and status capture", "tech fingerprinting"],
        "tgt": ["web", "api"],
    },
    "nmap": {
        "t": "scan",
        "c": "targeted_port_check",
        "u": "sudo nmap -n -T4 -F TARGET",
        "d": ["fast top-port scan", "targeted service checks", "lightweight validation"],
        "tgt": ["host", "network"],
    },
    "ffuf": {
        "t": "fuzzing",
        "c": "content_discovery",
        "u": "ffuf -u http://TARGET/FUZZ -w wordlists/web/files_short.txt -ic -mc all -fc 404",
        "d": ["path discovery", "endpoint brute force", "wordlist-based content enumeration"],
        "tgt": ["web", "api"],
    },
    "gobuster": {
        "t": "fuzzing",
        "c": "directory_bruteforce",
        "u": "gobuster dir -u http://TARGET -w wordlists/web/folders_short.txt -q",
        "d": ["directory enumeration", "simple brute force", "alternate ffuf workflow"],
        "tgt": ["web"],
    },
    "subfinder": {
        "t": "recon",
        "c": "passive_subdomain_enum",
        "u": "subfinder -d TARGET -silent",
        "d": ["passive subdomain discovery", "quick asset enumeration"],
        "tgt": ["domain"],
    },
    "nuclei": {
        "t": "template_scan",
        "c": "known_exposure_checks",
        "u": "nuclei -u http://TARGET -tags exposure,misconfig",
        "d": ["known exposure checks", "misconfiguration detection", "template-based validation"],
        "tgt": ["web", "api", "host"],
    },
    "sqlmap": {
        "t": "injection",
        "c": "sqli_probe",
        "u": "sqlmap -u \"http://TARGET/item?id=1\" --batch",
        "d": ["SQL injection validation", "parameter testing", "DB fingerprinting"],
        "tgt": ["web", "api"],
    },
    "arjun": {
        "t": "fuzzing",
        "c": "parameter_discovery",
        "u": "arjun -u http://TARGET/api --get",
        "d": ["hidden parameter discovery", "query/input enumeration"],
        "tgt": ["web", "api"],
    },
    "jwt-tool": {
        "t": "auth",
        "c": "token_analysis",
        "u": "jwt-tool TOKEN",
        "d": ["JWT header inspection", "claim review", "token analysis"],
        "tgt": ["auth", "api"],
    },
    "syft": {
        "t": "container",
        "c": "sbom",
        "u": "syft IMAGE -o json",
        "d": ["SBOM generation", "dependency inventory", "container package mapping"],
        "tgt": ["container image"],
    },
    "trivy": {
        "t": "container",
        "c": "image_scan",
        "u": "trivy image IMAGE",
        "d": ["container CVEs", "secrets", "misconfiguration checks"],
        "tgt": ["container image", "filesystem"],
    },
    "semgrep": {
        "t": "repo",
        "c": "sast",
        "u": "semgrep scan --config auto REPO_PATH",
        "d": ["code pattern scanning", "security rule checks", "repo analysis"],
        "tgt": ["source code"],
    },
    "gitleaks": {
        "t": "repo",
        "c": "secret_scan",
        "u": "gitleaks detect -s REPO_PATH",
        "d": ["hardcoded secret detection", "token leak checks", "source scanning"],
        "tgt": ["source code", "git history"],
    },
    "apktool": {
        "t": "mobile",
        "c": "apk_unpack",
        "u": "apktool d APP.apk -o unpacked_apk",
        "d": ["APK decoding", "resource extraction", "Android static analysis prep"],
        "tgt": ["android apk"],
    },
    "binwalk": {
        "t": "firmware",
        "c": "firmware_extract",
        "u": "binwalk -e FIRMWARE.bin",
        "d": ["firmware unpacking", "embedded artifact discovery", "IoT analysis"],
        "tgt": ["firmware"],
    },
    "ssh-audit": {
        "t": "recon",
        "c": "ssh_audit",
        "u": "ssh-audit TARGET",
        "d": ["SSH server audit", "encryption/algorithm check", "vulnerability scan"],
        "tgt": ["host"],
    },
    "ssh-mitm": {
        "t": "exploitation",
        "c": "ssh_mitm",
        "u": "ssh-mitm --remote-host TARGET",
        "d": ["SSH man-in-the-middle audit", "credential and key validation check"],
        "tgt": ["host"],
    },
}

assistant_security_tools = ASSISTANT_SANDBOX_RUN_CUSTOM_CATALOG
assistant_wordlists = ASSISTANT_SANDBOX_WORDLISTS


def _render_json_block(data: dict[str, dict[str, object]]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def render_assistant_security_tools_prompt() -> str:
    lines = [
        "- Installed security and diagnostic tools currently available through `run_custom` in the sandbox:",
    ]
    for category, tools in _ASSISTANT_SECURITY_TOOL_GROUPS:
        rendered_tools = ", ".join(f"`{tool}`" for tool in tools)
        lines.append(f"    - {category}: {rendered_tools}")
    lines.append(
        "- In assistant chat, command execution is still limited to read-only diagnostics against the current active target."
    )
    lines.append(
        "- Sandbox wordlist catalog for commands that need `-w` or similar inputs (use these exact bundled sandbox paths):"
    )
    lines.append("```json")
    lines.append(_render_json_block(ASSISTANT_SANDBOX_WORDLISTS))
    lines.append("```")
    lines.append(
        "- Sandbox run_custom starter catalog for Echo (JSON-style, aligned with exploit/recon agent catalogs):"
    )
    lines.append("```json")
    lines.append(_render_json_block(ASSISTANT_SANDBOX_RUN_CUSTOM_CATALOG))
    lines.append("```")
    return "\n".join(lines)
