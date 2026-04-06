import subprocess
import json
import re
import time
import os
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class DependencyScanRequest(BaseModel):
    tool: str
    target: str
    ecosystem: str = "auto"
    scan_type: str = "vuln"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {
            "snyk",
            "dependency-check",
            "safety",
            "npm-audit",
            "retire-js"
        }
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")

        return v

    @validator("ecosystem")
    def validate_ecosystem(cls, v):
        allowed = {
            "auto", "python", "node", "java", "javascript", "typescript",
            "maven", "gradle", "pip", "npm"
        }
        if v not in allowed:
            raise ValueError(f"Ecosystem '{v}' not allowed. Use: {allowed}")
        return v

    @validator("scan_type")
    def validate_scan_type(cls, v):
        allowed = {"vuln", "licenses", "all"}
        if v not in allowed:
            raise ValueError(f"scan_type '{v}' not allowed. Use: {allowed}")
        return v

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--out", "--report", "--format-file"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")

        return v


class DependencyVulnerability(BaseModel):
    vulnerability_id: Optional[str] = None
    package_name: str
    ecosystem: Optional[str] = None
    severity: str = "unknown"
    title: Optional[str] = None
    description: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    direct_dependency: Optional[bool] = None
    cve: list[str] = []
    cwe: list[str] = []
    cvss: Optional[float] = None
    references: list[str] = []
    path: Optional[str] = None
    file: Optional[str] = None
    exploit_maturity: Optional[str] = None


class DependencyPackage(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    file: Optional[str] = None
    license: Optional[str] = None


class DependencyScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    ecosystem: str
    scan_type: str
    command: str
    total_vulnerabilities: int = 0
    severity_summary: dict[str, int] = {}
    package_count: Optional[int] = None
    vulnerable_packages: list[DependencyVulnerability] = []
    packages: Optional[list[DependencyPackage]] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 1800, cwd: Optional[str] = None) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

def detect_ecosystem(target: str) -> str:
    if os.path.isfile(target):
        base = os.path.basename(target).lower()
        if base in {"requirements.txt", "poetry.lock", "pipfile", "pipfile.lock"}:
            return "python"
        if base in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}:
            return "node"
        if base in {"pom.xml"}:
            return "maven"
        if base in {"build.gradle", "build.gradle.kts", "settings.gradle"}:
            return "gradle"

    if os.path.isdir(target):
        files = {f.lower() for f in os.listdir(target)}
        if {"requirements.txt", "poetry.lock", "pipfile", "pipfile.lock"} & files:
            return "python"
        if {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"} & files:
            return "node"
        if "pom.xml" in files:
            return "maven"
        if "build.gradle" in files or "build.gradle.kts" in files:
            return "gradle"

    return "auto"


def normalize_severity(sev: Optional[str]) -> str:
    if not sev:
        return "unknown"
    s = sev.lower().strip()
    if s in {"critical", "high", "medium", "low", "info", "unknown"}:
        return s
    if s in {"moderate"}:
        return "medium"
    return "unknown"


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_snyk_json(stdout: str, ecosystem: str) -> tuple[list[DependencyVulnerability], Optional[list[DependencyPackage]]]:
    vulns = []
    packages = []

    try:
        data = json.loads(stdout)
    except Exception:
        return vulns, None

    for v in data.get("vulnerabilities", []) or []:
        identifiers = v.get("identifiers", {}) or {}
        cves = identifiers.get("CVE", []) or []
        cwes = identifiers.get("CWE", []) or []
        refs = v.get("references", []) or []

        vulns.append(DependencyVulnerability(
            vulnerability_id=v.get("id"),
            package_name=v.get("packageName", "unknown"),
            ecosystem=ecosystem,
            severity=normalize_severity(v.get("severity")),
            title=v.get("title"),
            description=v.get("description"),
            installed_version=v.get("version"),
            fixed_version=v.get("fixedIn", [None])[0] if isinstance(v.get("fixedIn"), list) else None,
            direct_dependency=v.get("isUpgradable") or v.get("isPatchable"),
            cve=cves,
            cwe=cwes,
            cvss=v.get("cvssScore"),
            references=refs[:20] if isinstance(refs, list) else [],
            path=" > ".join(v.get("from", [])) if isinstance(v.get("from"), list) else None,
            exploit_maturity=v.get("exploitMaturity"),
        ))

    dep_graph = data.get("dependencyCount")
    if isinstance(dep_graph, int):
        for dep in data.get("filtered", {}).get("packages", []) if isinstance(data.get("filtered"), dict) else []:
            packages.append(DependencyPackage(
                name=dep.get("name"),
                version=dep.get("version"),
                ecosystem=ecosystem,
            ))

    return vulns, (packages or None)


def parse_safety_json(stdout: str) -> tuple[list[DependencyVulnerability], Optional[list[DependencyPackage]]]:
    vulns = []

    try:
        data = json.loads(stdout)
    except Exception:
        return vulns, None

    if isinstance(data, dict) and "vulnerabilities" in data:
        items = data.get("vulnerabilities", [])
    else:
        items = data if isinstance(data, list) else []

    for item in items:
        advisory = item.get("advisory") or {}
        vulns.append(DependencyVulnerability(
            vulnerability_id=str(item.get("vulnerability_id") or advisory.get("id") or item.get("id") or "unknown"),
            package_name=item.get("package_name") or item.get("package") or "unknown",
            ecosystem="python",
            severity=normalize_severity(item.get("severity") or advisory.get("severity")),
            title=item.get("advisory") if isinstance(item.get("advisory"), str) else advisory.get("summary"),
            description=item.get("advisory") if isinstance(item.get("advisory"), str) else advisory.get("description"),
            installed_version=item.get("analyzed_version") or item.get("installed_version"),
            fixed_version=", ".join(item.get("fixed_versions", [])[:5]) if item.get("fixed_versions") else None,
            cve=item.get("CVE", []) if isinstance(item.get("CVE"), list) else [],
            references=item.get("more_info_urls", [])[:20] if isinstance(item.get("more_info_urls"), list) else [],
        ))

    return vulns, None


def parse_npm_audit_json(stdout: str) -> tuple[list[DependencyVulnerability], Optional[list[DependencyPackage]]]:
    vulns = []
    packages = []

    try:
        data = json.loads(stdout)
    except Exception:
        return vulns, None

    vuln_obj = data.get("vulnerabilities", {}) or {}
    for pkg_name, details in vuln_obj.items():
        via = details.get("via", [])
        installed_version = details.get("range")

        for item in via:
            if isinstance(item, str):
                continue

            vulns.append(DependencyVulnerability(
                vulnerability_id=item.get("source") or item.get("url"),
                package_name=pkg_name,
                ecosystem="node",
                severity=normalize_severity(item.get("severity")),
                title=item.get("title"),
                description=item.get("overview"),
                installed_version=installed_version,
                fixed_version=details.get("fixAvailable", {}).get("name") if isinstance(details.get("fixAvailable"), dict) else None,
                direct_dependency=details.get("isDirect"),
                cve=item.get("cves", []) if isinstance(item.get("cves"), list) else [],
                cvss=item.get("cvss", {}).get("score") if isinstance(item.get("cvss"), dict) else None,
                references=[item.get("url")] if item.get("url") else [],
                path=pkg_name,
            ))

    for pkg_name, details in vuln_obj.items():
        packages.append(DependencyPackage(
            name=pkg_name,
            version=details.get("range"),
            ecosystem="node",
        ))

    return vulns, (packages or None)


def parse_retire_json(stdout: str) -> tuple[list[DependencyVulnerability], Optional[list[DependencyPackage]]]:
    vulns = []
    packages = []

    try:
        data = json.loads(stdout)
    except Exception:
        return vulns, None

    if not isinstance(data, list):
        return vulns, None

    for item in data:
        file_path = item.get("file")
        for result in item.get("results", []) or []:
            pkg = result.get("component") or "unknown"
            ver = result.get("version")

            packages.append(DependencyPackage(
                name=pkg,
                version=ver,
                ecosystem="javascript",
                file=file_path,
            ))

            for vuln in result.get("vulnerabilities", []) or []:
                identifiers = vuln.get("identifiers", {}) or {}
                refs = vuln.get("info", []) or []

                vulns.append(DependencyVulnerability(
                    vulnerability_id=(identifiers.get("summary") or [None])[0] if isinstance(identifiers.get("summary"), list) else None,
                    package_name=pkg,
                    ecosystem="javascript",
                    severity=normalize_severity(vuln.get("severity")),
                    title=vuln.get("identifiers", {}).get("summary", [None])[0] if isinstance(vuln.get("identifiers", {}).get("summary"), list) and vuln.get("identifiers", {}).get("summary") else None,
                    description=vuln.get("below"),
                    installed_version=ver,
                    fixed_version=vuln.get("above"),
                    cve=identifiers.get("CVE", []) if isinstance(identifiers.get("CVE"), list) else [],
                    references=refs[:20] if isinstance(refs, list) else [],
                    file=file_path,
                ))

    return vulns, (packages or None)


def parse_dependency_check_json(stdout: str) -> tuple[list[DependencyVulnerability], Optional[list[DependencyPackage]]]:
    vulns = []
    packages = []

    try:
        data = json.loads(stdout)
    except Exception:
        return vulns, None

    for dep in data.get("dependencies", []) or []:
        file_name = dep.get("fileName")
        file_path = dep.get("filePath")
        packages.append(DependencyPackage(
            name=file_name or "unknown",
            ecosystem="java",
            file=file_path,
        ))

        for v in dep.get("vulnerabilities", []) or []:
            refs = []
            for r in v.get("references", []) or []:
                url = r.get("url")
                if url:
                    refs.append(url)

            cvss = None
            if isinstance(v.get("cvssv3"), dict):
                cvss = v.get("cvssv3", {}).get("baseScore")
            elif isinstance(v.get("cvssv2"), dict):
                cvss = v.get("cvssv2", {}).get("score")

            vulns.append(DependencyVulnerability(
                vulnerability_id=v.get("name"),
                package_name=file_name or "unknown",
                ecosystem="java",
                severity=normalize_severity(v.get("severity")),
                title=v.get("name"),
                description=v.get("description"),
                installed_version=None,
                fixed_version=None,
                cve=[v.get("name")] if v.get("name", "").startswith("CVE-") else [],
                cwe=v.get("cwes", []) if isinstance(v.get("cwes"), list) else [],
                cvss=cvss,
                references=refs[:20],
                file=file_path,
            ))

    return vulns, (packages or None)


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def dependency_scan(tool: str, target: str, ecosystem: str = "auto", scan_type: str = "vuln", args: list[str] = []) -> dict:
    """
    📦 Agent Tool: Dependency / SCA Scanner

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  VULNERABLE DEPS      CVEs in package manifests/lockfiles   │
      │  ECOSYSTEM SUPPORT    Python, Node, Java, JS                │
      │  PACKAGE INVENTORY    enumerate vulnerable packages         │
      │  LOG4J / COMMON RISK  detect known library vulnerabilities  │
      │  SCA TOOLS            snyk, dependency-check, safety, npm   │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:       "snyk" | "dependency-check" | "safety" | "npm-audit" | "retire-js"
        target:     project directory or manifest path
        ecosystem:  "auto" | "python" | "node" | "java" | "javascript" | ...
        scan_type:  "vuln" | "licenses" | "all"
        args:       raw tool arguments — agent decides

    Examples:
        dependency_scan("snyk", "/src/app", "auto", "vuln", [])
        dependency_scan("safety", "/src/app/requirements.txt", "python", "vuln", [])
        dependency_scan("npm-audit", "/src/nodeapp", "node", "vuln", [])
        dependency_scan("dependency-check", "/src/javaapp", "java", "vuln", [])
        dependency_scan("retire-js", "/src/webapp", "javascript", "vuln", [])
    """

    start = time.time()

    try:
        req = DependencyScanRequest(
            tool=tool,
            target=target,
            ecosystem=ecosystem,
            scan_type=scan_type,
            args=args,
        )
    except Exception as e:
        return DependencyScanResult(
            success=False,
            tool=tool,
            target=target,
            ecosystem=ecosystem,
            scan_type=scan_type,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    resolved_ecosystem = req.ecosystem if req.ecosystem != "auto" else detect_ecosystem(req.target)

    cmd = []
    cwd = req.target if os.path.isdir(req.target) else os.path.dirname(req.target) or None

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if req.tool == "snyk":
        cmd = ["snyk", "test", "--json"]
        if os.path.isfile(req.target):
            cmd.extend(["--file=" + os.path.basename(req.target)])
        cmd.extend(list(req.args))

    elif req.tool == "safety":
        # Safety works best with requirements files or current python env
        if os.path.isfile(req.target):
            cmd = ["safety", "check", "--json", "-r", req.target]
        else:
            cmd = ["safety", "check", "--json"]
        cmd.extend(list(req.args))

    elif req.tool == "npm-audit":
        cmd = ["npm", "audit", "--json"]
        cmd.extend(list(req.args))

    elif req.tool == "retire-js":
        cmd = ["retire", "--outputformat", "json", "--path", req.target]
        cmd.extend(list(req.args))

    elif req.tool == "dependency-check":
        # JSON output typically written to report directory in real usage;
        # here we assume JSON to stdout if supported by wrapper/env.
        cmd = ["dependency-check", "--scan", req.target, "--format", "JSON"]
        cmd.extend(list(req.args))

    else:
        return DependencyScanResult(
            success=False,
            tool=tool,
            target=target,
            ecosystem=resolved_ecosystem,
            scan_type=scan_type,
            command="",
            error=f"Unknown tool: {tool}",
        ).model_dump()

    command_str = " ".join(cmd)

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout, cwd=cwd)

    # Some tools return non-zero when vulns are found, which is normal.
    # We parse output first before deciding error handling.

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    vulns: list[DependencyVulnerability] = []
    packages: Optional[list[DependencyPackage]] = None

    if req.tool == "snyk":
        vulns, packages = parse_snyk_json(stdout, resolved_ecosystem)
    elif req.tool == "safety":
        vulns, packages = parse_safety_json(stdout)
    elif req.tool == "npm-audit":
        vulns, packages = parse_npm_audit_json(stdout)
    elif req.tool == "retire-js":
        vulns, packages = parse_retire_json(stdout)
    elif req.tool == "dependency-check":
        vulns, packages = parse_dependency_check_json(stdout)

    severity_summary: dict[str, int] = {}
    for v in vulns:
        severity_summary[v.severity] = severity_summary.get(v.severity, 0) + 1

    return DependencyScanResult(
        success=(rc == 0 or len(vulns) > 0 or packages is not None),
        tool=req.tool,
        target=req.target,
        ecosystem=resolved_ecosystem,
        scan_type=req.scan_type,
        command=command_str,
        total_vulnerabilities=len(vulns),
        severity_summary=severity_summary,
        package_count=len(packages) if packages else None,
        vulnerable_packages=vulns,
        packages=packages[:500] if packages else None,
        raw_output=(stdout or stderr)[:12000],
        error=stderr[:4000] if rc != 0 and not vulns and packages is None else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

DEPENDENCY_SCAN_TOOL_DEFINITION = {
    "name": "dependency_scan",
    "description": (
        "Scan project dependencies for known vulnerable libraries and packages using Snyk, "
        "OWASP Dependency-Check, Safety, npm audit, or Retire.js. Supports Python, Node, Java, and JS ecosystems."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["snyk", "dependency-check", "safety", "npm-audit", "retire-js"],
                "description": (
                    "snyk = general SCA | dependency-check = Java/general dependency CVEs | "
                    "safety = Python packages | npm-audit = Node/npm deps | retire-js = JS libraries"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Project directory or manifest/lockfile path. "
                    "Examples: '/src/app', '/src/app/requirements.txt', '/src/app/package.json'"
                )
            },
            "ecosystem": {
                "type": "string",
                "enum": ["auto", "python", "node", "java", "javascript", "typescript", "maven", "gradle", "pip", "npm"],
                "default": "auto",
                "description": "Project ecosystem"
            },
            "scan_type": {
                "type": "string",
                "enum": ["vuln", "licenses", "all"],
                "default": "vuln",
                "description": "Type of dependency/SCA scan"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "Snyk: ['--severity-threshold=high']\n"
                    "Safety: ['--full-report']\n"
                    "npm-audit: ['--omit=dev']\n"
                    "Retire.js: ['--jsrepo', '/path/custom-repo.json']"
                )
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Snyk on project dir
    # ─────────────────────────────
    r = dependency_scan(
        tool="snyk",
        target="/src/app",
        ecosystem="auto",
        scan_type="vuln",
        args=["--severity-threshold=high"]
    )
    print("=== SNYK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Safety on requirements.txt
    # ─────────────────────────────
    r = dependency_scan(
        tool="safety",
        target="/src/app/requirements.txt",
        ecosystem="python",
        scan_type="vuln",
        args=[]
    )
    print("=== SAFETY ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. npm audit
    # ─────────────────────────────
    r = dependency_scan(
        tool="npm-audit",
        target="/src/nodeapp",
        ecosystem="node",
        scan_type="vuln",
        args=["--omit=dev"]
    )
    print("=== NPM AUDIT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Retire.js
    # ─────────────────────────────
    r = dependency_scan(
        tool="retire-js",
        target="/src/webapp",
        ecosystem="javascript",
        scan_type="vuln",
        args=[]
    )
    print("=== RETIRE JS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Dependency-Check
    # ─────────────────────────────
    r = dependency_scan(
        tool="dependency-check",
        target="/src/javaapp",
        ecosystem="java",
        scan_type="vuln",
        args=[]
    )
    print("=== DEPENDENCY CHECK ===")
    print(json.dumps(r, indent=2))