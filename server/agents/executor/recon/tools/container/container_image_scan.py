import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class ContainerImageScanRequest(BaseModel):
    tool: str
    target: str
    scan_type: str = "vuln"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=30, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"trivy", "grype", "syft"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")

        # allow image refs, tar files, OCI dirs, Dockerfile paths
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        allowed = {
            "vuln", "secret", "config", "sbom", "dockerfile",
            "all", "packages", "licenses"
        }
        if v not in allowed:
            raise ValueError(f"Unknown scan_type: {v}")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--file", "--template"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")

        return v


class PackageVuln(BaseModel):
    vulnerability_id: str
    pkg_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    severity: str = "unknown"
    title: Optional[str] = None
    description: Optional[str] = None
    cvss: Optional[float] = None
    references: list[str] = []
    layer: Optional[str] = None
    path: Optional[str] = None
    data_source: Optional[str] = None


class EmbeddedSecret(BaseModel):
    rule_id: Optional[str] = None
    category: str = "secret"
    severity: str = "high"
    title: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    match: Optional[str] = None
    recommendation: Optional[str] = None


class DockerfileFinding(BaseModel):
    check_id: Optional[str] = None
    title: str
    severity: str = "medium"
    status: str = "warning"
    instruction: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


class ImageMetadata(BaseModel):
    image: Optional[str] = None
    digest: Optional[str] = None
    os_family: Optional[str] = None
    os_name: Optional[str] = None
    architecture: Optional[str] = None
    total_packages: Optional[int] = None


class ContainerImageScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    scan_type: str
    command: str
    metadata: Optional[ImageMetadata] = None
    total_vulnerabilities: int = 0
    severity_summary: dict[str, int] = {}
    vulnerabilities: list[PackageVuln] = []
    secrets: list[EmbeddedSecret] = []
    dockerfile_findings: list[DockerfileFinding] = []
    packages: Optional[list[dict[str, Any]]] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 1800) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 3. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_trivy_json(stdout: str, scan_type: str, target: str) -> tuple[Optional[ImageMetadata], list[PackageVuln], list[EmbeddedSecret], list[DockerfileFinding], Optional[list[dict[str, Any]]]]:
    metadata = ImageMetadata(image=target)
    vulns: list[PackageVuln] = []
    secrets: list[EmbeddedSecret] = []
    dockerfile_findings: list[DockerfileFinding] = []
    packages: list[dict[str, Any]] = []

    try:
        data = json.loads(stdout)
    except Exception:
        return metadata, vulns, secrets, dockerfile_findings, None

    # metadata
    metadata.os_family = data.get("Metadata", {}).get("OS", {}).get("Family")
    metadata.os_name = data.get("Metadata", {}).get("OS", {}).get("Name")
    metadata.architecture = data.get("Metadata", {}).get("ImageConfig", {}).get("architecture")
    metadata.digest = data.get("ArtifactInfo", {}).get("Digest") or data.get("Metadata", {}).get("RepoDigests", [None])[0]

    for result in data.get("Results", []):
        target_name = result.get("Target")
        result_type = result.get("Type")

        # vulnerabilities
        for v in result.get("Vulnerabilities", []) or []:
            cvss = None
            cvss_data = v.get("CVSS", {})
            for _, score_obj in cvss_data.items():
                if isinstance(score_obj, dict) and score_obj.get("V3Score") is not None:
                    cvss = score_obj.get("V3Score")
                    break

            refs = v.get("References") or []
            vulns.append(PackageVuln(
                vulnerability_id=v.get("VulnerabilityID", "UNKNOWN"),
                pkg_name=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
                severity=(v.get("Severity") or "unknown").lower(),
                title=v.get("Title"),
                description=v.get("Description"),
                cvss=cvss,
                references=refs[:20],
                layer=target_name,
                path=v.get("PkgPath"),
                data_source=(v.get("PrimaryURL") or result_type),
            ))

        # secrets
        for s in result.get("Secrets", []) or []:
            secrets.append(EmbeddedSecret(
                rule_id=s.get("RuleID"),
                category="secret",
                severity=(s.get("Severity") or "high").lower(),
                title=s.get("Title") or s.get("Category") or "Embedded secret detected",
                file_path=s.get("Target"),
                line=s.get("StartLine"),
                match=s.get("Match"),
                recommendation="Remove embedded secrets and use a secure secret manager",
            ))

        # misconfig / Dockerfile
        for m in result.get("Misconfigurations", []) or []:
            dockerfile_findings.append(DockerfileFinding(
                check_id=m.get("ID"),
                title=m.get("Title") or "Dockerfile/config misconfiguration",
                severity=(m.get("Severity") or "medium").lower(),
                status="fail" if (m.get("Status") or "").lower() in {"failure", "fail"} else "warning",
                instruction=m.get("Query"),
                evidence=m.get("Message"),
                recommendation=m.get("Resolution"),
            ))

        # packages from sbom/package listing modes
        for p in result.get("Packages", []) or []:
            packages.append({
                "name": p.get("Name"),
                "version": p.get("Version"),
                "type": p.get("Type"),
                "licenses": p.get("Licenses"),
                "path": p.get("Path"),
            })

    if packages:
        metadata.total_packages = len(packages)

    return metadata, vulns, secrets, dockerfile_findings, (packages or None)


def parse_grype_json(stdout: str, target: str) -> tuple[Optional[ImageMetadata], list[PackageVuln]]:
    metadata = ImageMetadata(image=target)
    vulns: list[PackageVuln] = []

    try:
        data = json.loads(stdout)
    except Exception:
        return metadata, vulns

    source = data.get("source", {})
    metadata.image = source.get("target", {}).get("userInput") or target

    distro = data.get("distro", {})
    metadata.os_family = distro.get("name")
    metadata.os_name = distro.get("version")

    for match in data.get("matches", []) or []:
        artifact = match.get("artifact", {})
        vuln = match.get("vulnerability", {})
        related = vuln.get("urls") or []

        cvss = None
        for cv in vuln.get("cvss", []) or []:
            metrics = cv.get("metrics", {})
            if metrics.get("baseScore") is not None:
                cvss = metrics.get("baseScore")
                break

        vulns.append(PackageVuln(
            vulnerability_id=vuln.get("id", "UNKNOWN"),
            pkg_name=artifact.get("name"),
            installed_version=artifact.get("version"),
            fixed_version=", ".join(vuln.get("fix", {}).get("versions", [])[:5]) or None,
            severity=(vuln.get("severity") or "unknown").lower(),
            title=vuln.get("description"),
            description=vuln.get("description"),
            cvss=cvss,
            references=related[:20],
            layer=artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else None,
            path=artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else None,
            data_source=vuln.get("dataSource"),
        ))

    return metadata, vulns


def parse_syft_json(stdout: str, target: str) -> tuple[Optional[ImageMetadata], Optional[list[dict[str, Any]]]]:
    metadata = ImageMetadata(image=target)
    packages: list[dict[str, Any]] = []

    try:
        data = json.loads(stdout)
    except Exception:
        return metadata, None

    source = data.get("source", {})
    metadata.image = source.get("target", {}).get("userInput") or target

    distro = data.get("distro", {})
    metadata.os_family = distro.get("name")
    metadata.os_name = distro.get("version")

    artifacts = data.get("artifacts", []) or []
    for a in artifacts:
        packages.append({
            "name": a.get("name"),
            "version": a.get("version"),
            "type": a.get("type"),
            "locations": [x.get("path") for x in a.get("locations", [])[:5]],
            "licenses": a.get("licenses"),
            "cpes": a.get("cpes"),
            "purl": a.get("purl"),
        })

    metadata.total_packages = len(packages)
    return metadata, packages


def parse_trivy_table_fallback(output: str) -> list[PackageVuln]:
    vulns = []
    for line in output.splitlines():
        if "CVE-" in line or "GHSA-" in line:
            parts = re.split(r"\s{2,}|\t", line.strip())
            if len(parts) >= 4:
                vuln_id = parts[1] if len(parts) > 1 else "UNKNOWN"
                pkg = parts[0] if len(parts) > 0 else None
                severity = parts[-1].lower() if parts[-1] else "unknown"
                vulns.append(PackageVuln(
                    vulnerability_id=vuln_id,
                    pkg_name=pkg,
                    severity=severity,
                    title=line[:300],
                ))
    return vulns


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def container_image_scan(tool: str, target: str, scan_type: str = "vuln", args: list[str] = []) -> dict:
    """
    🐳 Agent Tool: Container Image Scanner

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  IMAGE CVES            OS/app package vulnerabilities       │
      │  VULNERABLE PACKAGES   package → version → fixed version    │
      │  EMBEDDED SECRETS      keys, tokens, credentials in image   │
      │  DOCKERFILE MISCONFIG  insecure base, root user, etc.       │
      │  SBOM / PACKAGE ENUM   inventory via syft/trivy             │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:      "trivy" | "grype" | "syft"
        target:    image ref, tar archive, OCI dir, or Dockerfile path
        scan_type: "vuln" | "secret" | "config" | "sbom" | "dockerfile" | "all" | "packages" | "licenses"
        args:      Raw tool arguments — agent decides

    Examples:
        container_image_scan("trivy", "nginx:latest", "vuln", ["--severity", "HIGH,CRITICAL"])
        container_image_scan("trivy", "myimage:latest", "secret", [])
        container_image_scan("trivy", "./Dockerfile", "dockerfile", [])
        container_image_scan("grype", "ubuntu:22.04", "vuln", [])
        container_image_scan("syft", "nginx:latest", "sbom", [])
    """

    start = time.time()

    try:
        req = ContainerImageScanRequest(tool=tool, target=target, scan_type=scan_type, args=args)
    except Exception as e:
        return ContainerImageScanResult(
            success=False,
            tool=tool,
            target=target,
            scan_type=scan_type,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if req.tool == "trivy":
        if req.scan_type in {"vuln", "all"}:
            cmd = ["trivy", "image", "--format", "json", req.target]
            if req.scan_type == "all":
                cmd.extend(["--scanners", "vuln,secret,misconfig"])
            else:
                cmd.extend(["--scanners", "vuln"])
        elif req.scan_type == "secret":
            cmd = ["trivy", "image", "--format", "json", "--scanners", "secret", req.target]
        elif req.scan_type in {"config", "dockerfile"}:
            # fs mode works for Dockerfile/repo paths
            cmd = ["trivy", "config", "--format", "json", req.target]
        elif req.scan_type in {"sbom", "packages", "licenses"}:
            cmd = ["trivy", "image", "--format", "json", "--list-all-pkgs", req.target]
        else:
            cmd = ["trivy", "image", "--format", "json", req.target]

        cmd.extend(list(req.args))

    elif req.tool == "grype":
        if req.scan_type not in {"vuln", "all"}:
            return ContainerImageScanResult(
                success=False,
                tool=tool,
                target=target,
                scan_type=scan_type,
                command="",
                error="Grype is primarily for vulnerability scanning; use scan_type='vuln' or 'all'",
            ).model_dump()

        cmd = ["grype", req.target, "-o", "json"]
        cmd.extend(list(req.args))

    elif req.tool == "syft":
        if req.scan_type not in {"sbom", "packages", "licenses", "all"}:
            return ContainerImageScanResult(
                success=False,
                tool=tool,
                target=target,
                scan_type=scan_type,
                command="",
                error="Syft is primarily for SBOM/package inventory; use scan_type='sbom', 'packages', 'licenses', or 'all'",
            ).model_dump()

        cmd = ["syft", req.target, "-o", "json"]
        cmd.extend(list(req.args))

    else:
        return ContainerImageScanResult(
            success=False,
            tool=tool,
            target=target,
            scan_type=scan_type,
            command="",
            error=f"Unknown tool: {tool}",
        ).model_dump()

    command_str = " ".join(cmd)

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    metadata = ImageMetadata(image=req.target)
    vulnerabilities: list[PackageVuln] = []
    secrets: list[EmbeddedSecret] = []
    dockerfile_findings: list[DockerfileFinding] = []
    packages: Optional[list[dict[str, Any]]] = None

    if req.tool == "trivy":
        metadata, vulnerabilities, secrets, dockerfile_findings, packages = parse_trivy_json(stdout, req.scan_type, req.target)
        if not vulnerabilities and not secrets and not dockerfile_findings and not packages and stdout:
            vulnerabilities = parse_trivy_table_fallback(stdout)

    elif req.tool == "grype":
        metadata, vulnerabilities = parse_grype_json(stdout, req.target)

    elif req.tool == "syft":
        metadata, packages = parse_syft_json(stdout, req.target)

    severity_summary: dict[str, int] = {}
    for v in vulnerabilities:
        severity_summary[v.severity] = severity_summary.get(v.severity, 0) + 1
    for s in secrets:
        severity_summary[s.severity] = severity_summary.get(s.severity, 0) + 1
    for d in dockerfile_findings:
        severity_summary[d.severity] = severity_summary.get(d.severity, 0) + 1

    return ContainerImageScanResult(
        success=(rc == 0 or len(vulnerabilities) > 0 or len(secrets) > 0 or len(dockerfile_findings) > 0 or (packages is not None)),
        tool=req.tool,
        target=req.target,
        scan_type=req.scan_type,
        command=command_str,
        metadata=metadata,
        total_vulnerabilities=len(vulnerabilities),
        severity_summary=severity_summary,
        vulnerabilities=vulnerabilities,
        secrets=secrets,
        dockerfile_findings=dockerfile_findings,
        packages=packages[:500] if packages else None,
        raw_output=(stdout or stderr)[:12000],
        error=stderr[:4000] if rc != 0 and not vulnerabilities and not secrets and not dockerfile_findings and not packages else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

CONTAINER_IMAGE_SCAN_TOOL_DEFINITION = {
    "name": "container_image_scan",
    "description": (
        "Scan Docker/OCI container images for CVEs, vulnerable packages, embedded secrets, "
        "and Dockerfile/configuration misconfigurations using Trivy, Grype, or Syft."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["trivy", "grype", "syft"],
                "description": (
                    "trivy = vulns + secrets + misconfig + packages | "
                    "grype = vulnerability scanning | "
                    "syft = SBOM and package inventory"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Container image reference, tarball, OCI layout, repo dir, or Dockerfile path. "
                    "Examples: 'nginx:latest', 'myrepo/app:1.2.3', './Dockerfile', './image.tar'"
                )
            },
            "scan_type": {
                "type": "string",
                "enum": ["vuln", "secret", "config", "sbom", "dockerfile", "all", "packages", "licenses"],
                "description": (
                    "vuln = CVEs | secret = embedded secrets | config/dockerfile = Dockerfile misconfig | "
                    "sbom/packages/licenses = package inventory | all = broad scan"
                ),
                "default": "vuln"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool args. Examples:\n"
                    "Trivy: ['--severity', 'HIGH,CRITICAL']\n"
                    "Trivy: ['--ignore-unfixed']\n"
                    "Grype: ['--only-fixed']\n"
                    "Syft: ['--scope', 'all-layers']"
                )
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 6. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Trivy vulnerability scan
    # ─────────────────────────────
    r = container_image_scan(
        tool="trivy",
        target="nginx:latest",
        scan_type="vuln",
        args=["--severity", "HIGH,CRITICAL"]
    )
    print("=== TRIVY VULN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Trivy full scan
    # ─────────────────────────────
    r = container_image_scan(
        tool="trivy",
        target="myapp:latest",
        scan_type="all",
        args=["--severity", "MEDIUM,HIGH,CRITICAL"]
    )
    print("=== TRIVY ALL ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Secret scan
    # ─────────────────────────────
    r = container_image_scan(
        tool="trivy",
        target="myapp:latest",
        scan_type="secret",
        args=[]
    )
    print("=== TRIVY SECRETS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Dockerfile config scan
    # ─────────────────────────────
    r = container_image_scan(
        tool="trivy",
        target="./Dockerfile",
        scan_type="dockerfile",
        args=[]
    )
    print("=== DOCKERFILE MISCONFIG ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Grype vuln scan
    # ─────────────────────────────
    r = container_image_scan(
        tool="grype",
        target="ubuntu:22.04",
        scan_type="vuln",
        args=["--only-fixed"]
    )
    print("=== GRYPE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Syft SBOM
    # ─────────────────────────────
    r = container_image_scan(
        tool="syft",
        target="nginx:latest",
        scan_type="sbom",
        args=[]
    )
    print("=== SYFT SBOM ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. Trivy package inventory
    # ─────────────────────────────
    r = container_image_scan(
        tool="trivy",
        target="python:3.11",
        scan_type="packages",
        args=[]
    )
    print("=== TRIVY PACKAGES ===")
    print(json.dumps(r, indent=2))