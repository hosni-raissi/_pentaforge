import subprocess
import json
import re
import time
import os
import shutil
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CloudMisconfigScanRequest(BaseModel):
    tool: str
    provider: str
    args: list[str] = []
    timeout: int = Field(default=3600, ge=60, le=14400)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"scoutsuite", "prowler", "cloudsploit", "pacu"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v):
        allowed = {"aws", "azure", "gcp", "multi"}
        if v not in allowed:
            raise ValueError(f"Provider '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = [
            "--output",
            "--output-file",
            "-o",
            "--report-dir",
            "--write",
            "--outdir",
        ]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")
        return v


class CloudFinding(BaseModel):
    category: str
    title: str
    severity: str = "info"   # critical, high, medium, low, info
    status: str = "info"     # fail, warning, pass, info
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    region: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    compliance: Optional[list[str]] = None
    extra: Optional[dict[str, Any]] = None


class CloudResourceSummary(BaseModel):
    resource_type: str
    count: int = 0


class CloudMisconfigScanResult(BaseModel):
    success: bool
    tool: str
    provider: str
    command: str
    total_findings: int = 0
    severity_summary: dict[str, int] = {}
    resource_summary: list[CloudResourceSummary] = []
    findings: list[CloudFinding] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 3600) -> tuple[str, str, int]:
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


def _resolve_scoutsuite_binary() -> str:
    """
    Resolve the ScoutSuite executable name.

    Priority:
    1) SCOUTSUITE_BIN env override
    2) common binary names in PATH
    3) default to 'scoutsuite' (so error message stays explicit if missing)
    """
    override = str(os.getenv("SCOUTSUITE_BIN", "")).strip()
    if override:
        return override

    for candidate in ("scoutsuite", "ScoutSuite", "scout"):
        if shutil.which(candidate):
            return candidate

    return "scoutsuite"


# ══════════════════════════════════════════════════════════════
# 3. GENERIC FINDING NORMALIZATION
# ══════════════════════════════════════════════════════════════

def normalize_severity(v: Optional[str]) -> str:
    if not v:
        return "info"
    s = str(v).strip().lower()
    if s in {"critical", "high", "medium", "low", "info"}:
        return s
    if s in {"warning", "warn"}:
        return "medium"
    if s in {"danger"}:
        return "high"
    if s in {"ok", "pass", "passed"}:
        return "info"
    return "info"


def safe_list(v) -> list:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_prowler_output(stdout: str, stderr: str) -> tuple[list[CloudFinding], list[CloudResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}

    raw = stdout.strip()
    if not raw:
        return findings, []

    # Try JSON lines first
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)

            status = str(data.get("Status", data.get("status", "info"))).lower()
            sev = normalize_severity(data.get("Severity", data.get("severity")))
            resource_type = data.get("ResourceType") or data.get("resource_type")
            resource_id = data.get("ResourceId") or data.get("resource_id")
            region = data.get("Region") or data.get("region")
            title = (
                data.get("CheckTitle")
                or data.get("CheckID")
                or data.get("check_id")
                or "Prowler finding"
            )
            evidence = data.get("StatusExtended") or data.get("status_extended") or data.get("Message")
            compliance = []
            comp = data.get("Compliance") or data.get("compliance")
            if isinstance(comp, dict):
                for k, val in comp.items():
                    if val:
                        compliance.append(f"{k}:{val}")
            elif isinstance(comp, list):
                compliance = [str(x) for x in comp]

            findings.append(CloudFinding(
                category="prowler",
                title=str(title),
                severity=sev,
                status="fail" if status in {"fail", "failed"} else ("pass" if status in {"pass", "passed"} else "warning"),
                resource_type=resource_type,
                resource_id=resource_id,
                region=region,
                evidence=str(evidence)[:2000] if evidence else None,
                recommendation=data.get("Recommendation") or data.get("recommendation"),
                compliance=compliance or None,
                extra={
                    "check_id": data.get("CheckID") or data.get("check_id"),
                    "service": data.get("ServiceName") or data.get("service"),
                }
            ))
            if resource_type:
                resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
        except json.JSONDecodeError:
            continue

    if findings:
        return findings, [CloudResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]

    # Fallback text parsing
    for line in raw.splitlines():
        if any(x in line.lower() for x in ["fail", "warning", "critical", "high", "medium", "low"]):
            findings.append(CloudFinding(
                category="prowler",
                title="Prowler text finding",
                severity="medium",
                status="warning",
                evidence=line[:2000],
            ))

    return findings, []


def parse_scoutsuite_output(stdout: str, stderr: str) -> tuple[list[CloudFinding], list[CloudResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}
    raw = stdout.strip() or stderr.strip()
    if not raw:
        return findings, []

    # Try full JSON
    try:
        data = json.loads(raw)

        # Common ScoutSuite-ish recursive extraction
        def walk(obj, path="root"):
            if isinstance(obj, dict):
                # Findings-like node
                if any(k in obj for k in ["severity", "level", "findings", "items", "flagged_items"]):
                    sev = normalize_severity(obj.get("severity") or obj.get("level"))
                    title = obj.get("description") or obj.get("title") or obj.get("name") or path
                    resource_type = obj.get("resource_type") or obj.get("service")
                    resource_id = obj.get("id") or obj.get("resource_id")
                    evidence = obj.get("rationale") or obj.get("description") or obj.get("message")
                    if title and sev != "info":
                        findings.append(CloudFinding(
                            category="scoutsuite",
                            title=str(title)[:300],
                            severity=sev,
                            status="warning",
                            resource_type=resource_type,
                            resource_id=resource_id,
                            evidence=str(evidence)[:2000] if evidence else None,
                            recommendation=obj.get("remediation"),
                            extra={"path": path},
                        ))
                        if resource_type:
                            resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1

                for k, v in obj.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, f"{path}[{i}]")

        walk(data)

        return findings, [CloudResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]
    except Exception:
        pass

    # Fallback text
    for line in raw.splitlines():
        if any(x in line.lower() for x in ["danger", "warning", "high", "medium", "low", "public", "exposed"]):
            findings.append(CloudFinding(
                category="scoutsuite",
                title="ScoutSuite text finding",
                severity="medium",
                status="warning",
                evidence=line[:2000],
            ))

    return findings, []


def parse_cloudsploit_output(stdout: str, stderr: str) -> tuple[list[CloudFinding], list[CloudResourceSummary]]:
    findings = []
    resource_counts: dict[str, int] = {}
    raw = stdout.strip() or stderr.strip()
    if not raw:
        return findings, []

    try:
        data = json.loads(raw)

        # cloudsploit often nests under scans/checks/results
        checks = []
        if isinstance(data, dict):
            for key in ["findings", "results", "checks", "scans"]:
                if isinstance(data.get(key), list):
                    checks.extend(data[key])

        for item in checks:
            if not isinstance(item, dict):
                continue
            sev = normalize_severity(item.get("severity"))
            status = str(item.get("status", "warning")).lower()
            resource_type = item.get("resource") or item.get("resourceType") or item.get("resource_type")
            resource_id = item.get("resourceId") or item.get("resource_id")
            region = item.get("region")
            title = item.get("title") or item.get("name") or item.get("plugin") or "CloudSploit finding"

            findings.append(CloudFinding(
                category="cloudsploit",
                title=str(title),
                severity=sev,
                status="fail" if status in {"fail", "failed"} else ("pass" if status in {"pass", "passed"} else "warning"),
                resource_type=str(resource_type) if resource_type else None,
                resource_id=str(resource_id) if resource_id else None,
                region=region,
                evidence=str(item.get("message") or item.get("description") or "")[:2000] or None,
                recommendation=item.get("remediation"),
                extra={"plugin": item.get("plugin")},
            ))
            if resource_type:
                resource_counts[str(resource_type)] = resource_counts.get(str(resource_type), 0) + 1

        return findings, [CloudResourceSummary(resource_type=k, count=v) for k, v in sorted(resource_counts.items())]
    except Exception:
        pass

    for line in raw.splitlines():
        if any(x in line.lower() for x in ["fail", "public", "over-permission", "metadata", "exposed"]):
            findings.append(CloudFinding(
                category="cloudsploit",
                title="CloudSploit text finding",
                severity="medium",
                status="warning",
                evidence=line[:2000],
            ))

    return findings, []


def parse_pacu_output(stdout: str, stderr: str) -> tuple[list[CloudFinding], list[CloudResourceSummary]]:
    findings = []
    raw = stdout.strip() or stderr.strip()
    if not raw:
        return findings, []

    patterns = [
        (r"Admin", "critical", "Potential admin-level permission or escalation path"),
        (r"Privilege Escalation", "critical", "Privilege escalation path found"),
        (r"Backdoor", "critical", "Persistence or backdoor-related issue"),
        (r"Public", "high", "Publicly accessible cloud resource"),
        (r"Metadata", "high", "Metadata exposure or abuse path"),
        (r"Role", "medium", "IAM role chaining or trust issue"),
        (r"Lambda", "medium", "Lambda configuration leak or env exposure"),
    ]

    for line in raw.splitlines():
        for pat, sev, title in patterns:
            if re.search(pat, line, re.IGNORECASE):
                findings.append(CloudFinding(
                    category="pacu",
                    title=title,
                    severity=sev,
                    status="warning",
                    evidence=line[:2000],
                ))
                break

    return findings, []


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def cloud_misconfig_scan(tool: str, provider: str, args: list[str] = []) -> dict:
    """
    ☁️ Agent Tool: Cloud Misconfiguration Scan

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  IAM OVER-PERMISSIONS   wildcard/admin/escalation paths    │
      │  PUBLIC EXPOSURE        public buckets, DBs, instances      │
      │  SECURITY GROUPS        0.0.0.0/0 risky ingress            │
      │  METADATA EXPOSURE      IMDS / instance metadata exposure   │
      │  ROLE CHAINING          assume-role trust path issues       │
      │  LAMBDA ENV LEAKS       secrets in function env vars        │
      │  CIS / BEST PRACTICE    provider benchmark checks           │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:     "scoutsuite" | "prowler" | "cloudsploit" | "pacu"
        provider: "aws" | "azure" | "gcp" | "multi"
        args:     Raw tool args — agent decides

    Typical usage:
        prowler      → benchmark/compliance + IAM/public exposure
        scoutsuite   → broad multi-cloud misconfig review
        cloudsploit  → config risk checks
        pacu         → AWS attack-path / privilege-escalation-oriented enum

    Examples:
        cloud_misconfig_scan("prowler", "aws", ["aws", "--compliance", "cis_1.5_aws"])
        cloud_misconfig_scan("scoutsuite", "aws", ["aws"])
        cloud_misconfig_scan("cloudsploit", "aws", [])
        cloud_misconfig_scan("pacu", "aws", ["--module", "iam__enum_permissions"])
    """

    start = time.time()

    try:
        req = CloudMisconfigScanRequest(tool=tool, provider=provider, args=args)
    except Exception as e:
        return CloudMisconfigScanResult(
            success=False,
            tool=tool,
            provider=provider,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if req.tool == "prowler":
        # Common modern prowler usage
        cmd = ["prowler", req.provider]
        cmd.extend(list(req.args))

    elif req.tool == "scoutsuite":
        # Resolve ScoutSuite binary robustly (scoutsuite/ScoutSuite/scout)
        cmd = [_resolve_scoutsuite_binary(), req.provider]
        cmd.extend(list(req.args))

    elif req.tool == "cloudsploit":
        # Wrapper assumes CLI available as "cloudsploit"
        cmd = ["cloudsploit", "--cloud", req.provider]
        cmd.extend(list(req.args))

    elif req.tool == "pacu":
        if req.provider != "aws":
            return CloudMisconfigScanResult(
                success=False,
                tool=tool,
                provider=provider,
                command="",
                error="Pacu is AWS-focused; provider must be 'aws'",
            ).model_dump()
        cmd = ["pacu"]
        cmd.extend(list(req.args))

    else:
        return CloudMisconfigScanResult(
            success=False,
            tool=tool,
            provider=provider,
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
    findings: list[CloudFinding] = []
    resource_summary: list[CloudResourceSummary] = []

    if req.tool == "prowler":
        findings, resource_summary = parse_prowler_output(stdout, stderr)
    elif req.tool == "scoutsuite":
        findings, resource_summary = parse_scoutsuite_output(stdout, stderr)
    elif req.tool == "cloudsploit":
        findings, resource_summary = parse_cloudsploit_output(stdout, stderr)
    elif req.tool == "pacu":
        findings, resource_summary = parse_pacu_output(stdout, stderr)

    severity_summary: dict[str, int] = {}
    for f in findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    return CloudMisconfigScanResult(
        success=(rc == 0 or len(findings) > 0),
        tool=req.tool,
        provider=req.provider,
        command=command_str,
        total_findings=len(findings),
        severity_summary=severity_summary,
        resource_summary=resource_summary,
        findings=findings,
        raw_output=(stdout or stderr)[:12000],
        error=stderr[:4000] if rc != 0 and not findings else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

CLOUD_MISCONFIG_SCAN_TOOL_DEFINITION = {
    "name": "cloud_misconfig_scan",
    "description": (
        "Scan cloud environments for IAM over-permissions, public exposure, insecure security groups, "
        "metadata exposure, role chaining risks, and Lambda environment leaks using ScoutSuite, "
        "Prowler, CloudSploit, or Pacu."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["scoutsuite", "prowler", "cloudsploit", "pacu"],
                "description": (
                    "scoutsuite = broad multi-cloud audit | "
                    "prowler = compliance and cloud security checks | "
                    "cloudsploit = cloud misconfig checks | "
                    "pacu = AWS attack-path and IAM-focused assessment"
                ),
            },
            "provider": {
                "type": "string",
                "enum": ["aws", "azure", "gcp", "multi"],
                "description": "Cloud provider to assess"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "Prowler:    ['--compliance', 'cis_1.5_aws']\n"
                    "ScoutSuite: ['--no-browser']\n"
                    "CloudSploit:['--json']\n"
                    "Pacu:       ['--module', 'iam__enum_permissions']"
                )
            }
        },
        "required": ["tool", "provider"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. AWS benchmark review with Prowler
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="prowler",
        provider="aws",
        args=["--compliance", "cis_1.5_aws"]
    )
    print("=== PROWLER AWS CIS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. ScoutSuite AWS review
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="scoutsuite",
        provider="aws",
        args=["--no-browser"]
    )
    print("=== SCOUTSUITE AWS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Azure review with ScoutSuite
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="scoutsuite",
        provider="azure",
        args=["--no-browser"]
    )
    print("=== SCOUTSUITE AZURE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. GCP review with ScoutSuite
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="scoutsuite",
        provider="gcp",
        args=["--no-browser"]
    )
    print("=== SCOUTSUITE GCP ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. CloudSploit AWS
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="cloudsploit",
        provider="aws",
        args=["--json"]
    )
    print("=== CLOUDSPLOIT AWS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Pacu IAM enumeration
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="pacu",
        provider="aws",
        args=["--module", "iam__enum_permissions"]
    )
    print("=== PACU IAM ENUM ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. Pacu role chain discovery
    # ─────────────────────────────
    r = cloud_misconfig_scan(
        tool="pacu",
        provider="aws",
        args=["--module", "iam__enum_role_trusts"]
    )
    print("=== PACU ROLE TRUSTS ===")
    print(json.dumps(r, indent=2))
