"""Shared guardrails for run_custom command execution."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.agents.executer.tool_safety import (
    ToolSafetyProfile,
    get_run_custom_command_profile,
)
from server.db.projects import ProjectsStore
from server.utils.target_scope import describe_network_target_scope_issue

_HOST_VALUE_FLAGS = {
    "-h",
    "--host",
    "--hostname",
    "--connect",
    "-connect",
    "--server",
    "--domain",
}
_URL_VALUE_FLAGS = {
    "-u",
    "--url",
    "--target",
    "--uri",
    "-t",
}
_DATA_VALUE_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-H",
    "--header",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-A",
    "--user-agent",
    "-o",
    "--output",
    "-v",
    "--verbose",
}
_NETWORK_TARGET_COMMANDS = {
    # Web & API Fuzzing
    "commix", "ffuf", "gobuster", "dirb", "dirbuster", "wfuzz", "nikto", "wpscan", "joomscan",
    "arjun", "paramspider", "katana", "gospider", "gau", "waybackurls", "subjs", "linkfinder",
    "secretfinder", "getjs", "getJS", "graphql-cop", "graphw00f", "inql", "ssrfmap", "tplmap", "xsstrike", "dalfox", "corscanner",
    "linpeas", "linpeas.sh", "lse", "pspy", "kerbrute",
    
    # Network Scanning & Discovery
    "nmap", "amap", "shodan", "censys", "naabu", "masscan", "zgrab2", "dnsx", "tlsx", "httpx", "subfinder", "amass",
    "assetfinder", "dig", "host", "nslookup", "dnsrecon", "fping", "ike-scan", "nbtscan",
    "onesixtyone", "snmpwalk", "snmpcheck", "mtr", "traceroute", "ping", "nc", "netcat", "tshark", "tcpdump",
    
    # Vulnerability & Cloud Scanning
    "nuclei", "trivy", "grype", "syft", "dive", "osv-scanner", "gitleaks", "trufflehog",
    "scoutsuite", "prowler", "pacu", "cloudsploit", "cloud_enum",
    "s3scanner", "kube-hunter", "checkov", "bandit", "semgrep", "retire", "retire_js",
    "whatweb", "wappalyzer", "wafw00f", "sslyze", "ssh-audit", "testssl", "testssl.sh", "mitmproxy",
    "pynt", "frida", "frida-ps", "frida-trace", "frida-discover", "objection", "mobsfscan",
    
    # Exploitation & Auth
    "sqlmap", "nosqlmap", "hydra", "medusa", "patator", "responder", "msfconsole",
    "john", "hashcat", "jwt_tool", "jwt-tool", "smbclient", "smbmap", "rpcclient", "enum4linux", "enum4linux-ng",
    "ldapdomaindump", "bloodhound", "impacket", "crackmapexec", "netexec", "ldapsearch",
    
    # Utility & Misc
    "curl", "wget", "openssl", "git", "docker", "kubectl", "az", "gcloud", "gsutil", "aws", "crane", "searchsploit",
    "kiterunner", "kr", "interactsh-client", "grpcurl", "chisel", "git-dumper", "protoc",
    "ctop", "whaler", "k9s", "nomad", "kube-bench", "stern", "calicoctl", "clair-scanner", "skopeo", "reg", "kubenscan",
    "binwalk", "apktool", "apkid", "firmwalker", "dmesg", "pulumi", "blobenum", "steampipe",
    "gcpbucketbrute", "stormspotter", "kubescan.sh", "showmount", "oauth-scanner", "oauth-scanner.py",
    "newman", "zap-cli", "paramminer", "param-miner",
    "arp-scan", "rustscan", "knockpy", "secretsdump.py", "impacket-secretsdump",
    "rdp-sec-check", "rdp-sec-check.pl", "ssh", "ftp", "theHarvester", "besttrace", "netdiscover",
    "proxychains4", "proxychains", "ligolo-ng-agent", "sshuttle", "gh", "glab", "repo-supervisor", "detect-secrets", "git-dumper", "git-dumper.py", "codeql", "yq", "diggit", "recon-ng", "feroxbuster", "cmseek", "droopescan", "gowitness", "subjack", "alterx", "massdns", "cloudbrute",
}
_HOSTISH_RE = re.compile(
    r"^(?:localhost|"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|[A-Za-z0-9.-]+:\d{1,5}"
    r"|(?:[0-9a-fA-F:]+))$"
)


def current_execution_context() -> dict[str, Any]:
    try:
        from server.agents.executer.base import _executer_tool_context

        value = _executer_tool_context.get({})
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def detect_recon_role_violation(command: str, *, role: str) -> str | None:
    profile = get_run_custom_command_profile(command, role=role)
    if str(role or "").strip().lower() == "recon" and profile.category == "exploitation":
        return (
            f"Command '{command}' is classified as exploitation and is blocked in the recon execution lane. "
            "Escalate this scenario to the exploit agent instead."
        )
    return None


def extract_network_targets(command: str, args: list[str]) -> list[str]:
    clean_command = str(command or "").strip().lower()
    if clean_command not in _NETWORK_TARGET_COMMANDS:
        return []

    targets: list[str] = []
    skip_next = False
    for idx, raw_token in enumerate(args):
        token = str(raw_token or "").strip().strip("'\"")
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        lowered = token.lower()
        if lowered in _DATA_VALUE_FLAGS:
            skip_next = True
            continue
        if lowered in _URL_VALUE_FLAGS | _HOST_VALUE_FLAGS:
            next_value = str(args[idx + 1]).strip().strip("'\"") if idx + 1 < len(args) else ""
            if next_value:
                targets.append(next_value)
            skip_next = True
            continue
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            targets.append(token)
            continue
        if token.startswith("-"):
            continue
        if Path(token).is_absolute() or "/" in token:
            continue
        
        # Ignore common local file extensions to avoid false-positive scope violations
        if token.lower().endswith((".txt", ".json", ".log", ".xml", ".csv", ".bak", ".html", ".js")):
            continue

        if _HOSTISH_RE.fullmatch(token):
            targets.append(token)

    deduped: list[str] = []
    seen: set[str] = set()
    for target in targets:
        normalized = target.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(target)
    return deduped


def detect_scope_violation(command: str, args: list[str], *, active_target: str) -> str | None:
    declared_target = str(active_target or "").strip()
    if not declared_target:
        return None
    for target in extract_network_targets(command, args):
        issue = describe_network_target_scope_issue(target, declared_target)
        if issue:
            return issue
    return None


def collect_artifact_paths(args: list[str], *, execution_cwd: str) -> list[str]:
    cwd = Path(execution_cwd).resolve()
    out: list[str] = []
    seen: set[str] = set()
    for raw_value in args:
        value = str(raw_value or "").strip().strip("'\"")
        if not value or value.startswith("-"):
            continue
        try:
            candidate = Path(value).expanduser()
            resolved = candidate.resolve() if candidate.is_absolute() else (cwd / candidate).resolve()
            resolved.relative_to(cwd)
        except Exception:
            continue
        text = str(resolved)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out[:12]


def append_audit_record(
    *,
    command: str,
    args: list[str],
    full_command: str,
    reason: str,
    status: str,
    execution_cwd: str,
    return_code: int | None,
    execution_time: float,
    error: str | None = None,
    artifact_paths: list[str] | None = None,
    stripped_args: list[str] | None = None,
    redirected_output_paths: list[str] | None = None,
    scope_target: str = "",
    profile: ToolSafetyProfile | None = None,
) -> None:
    context = current_execution_context()
    record = {
        "project_id": str(context.get("project_id", "")).strip(),
        "scan_id": str(context.get("scan_id", "")).strip(),
        "role": str(context.get("role", "")).strip().lower(),
        "tool_name": "run_custom",
        "command_name": str(command or "").strip().lower(),
        "safety_category": (profile.category if profile else ""),
        "risk_level": (profile.risk_level if profile else ""),
        "requires_human_approval": bool(profile.requires_human_approval) if profile else False,
        "full_command": str(full_command or "").strip(),
        "args": list(args),
        "reason": str(reason or "").strip(),
        "status": str(status or "").strip().lower() or "unknown",
        "execution_cwd": str(execution_cwd or "").strip(),
        "return_code": return_code,
        "execution_time": float(execution_time or 0.0),
        "error": str(error or "").strip() or None,
        "artifact_paths": list(artifact_paths or []),
        "stripped_args": list(stripped_args or []),
        "redirected_output_paths": list(redirected_output_paths or []),
        "scope_target": str(scope_target or context.get("target_url", "")).strip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if record["project_id"]:
        try:
            ProjectsStore().append_tool_audit_log(record)
            return
        except Exception:
            pass

    fallback = {
        "audit": True,
        "tool": "run_custom",
        "ts": record["timestamp"],
        "role": record["role"],
        "cmd": record["full_command"],
        "risk_level": record["risk_level"],
        "status": record["status"],
        "reason": record["reason"],
    }
    print(json.dumps(fallback, ensure_ascii=True), file=sys.stderr)
