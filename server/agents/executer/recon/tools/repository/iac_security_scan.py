"""Infrastructure-as-Code Security Scanner - Terraform/CloudFormation/K8s/Docker."""

import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class IaCSecurityRequest(BaseModel):
    tool: str
    target: str
    include_secrets: bool = True
    timeout: int = Field(default=600, ge=30, le=3600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"tfsec", "checkov", "kubesec", "hadolint"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>"]
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")
        return v


class IaCIssue(BaseModel):
    issue_id: str
    title: str
    severity: str
    resource: str
    file_path: str
    line: Optional[int] = None
    rule: str
    description: str
    remediation: Optional[str] = None


class IaCSecurityResult(BaseModel):
    success: bool
    tool: str
    target: str

    # Findings
    issues: list[IaCIssue] = []
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    resource_scanned: int = 0

    # Files analyzed
    files_scanned: list[str] = []
    iac_types: list[str] = []

    error: Optional[str] = None
    execution_time: float = 0.0


def iac_security_scan(
    tool: str,
    target: str,
    include_secrets: bool = True,
    timeout: int = 600,
) -> dict:
    """Scan IaC files (Terraform, CloudFormation, K8s, Docker) for security issues."""
    start = time.time()

    try:
        req = IaCSecurityRequest(
            tool=tool,
            target=target,
            include_secrets=include_secrets,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "tool": tool,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = IaCSecurityResult(
        success=True,
        tool=tool,
        target=target,
    )

    try:
        # Detect IaC types
        iac_patterns = {
            "terraform": r"\.(tf|tfplan)$",
            "cloudformation": r"\.(yaml|yml|json)$",
            "kubernetes": r"(k8s|kube|deployment|service|pod)\.ya?ml$",
            "docker": r"Dockerfile$",
        }

        # Detect file types in target
        cmd = ["find", target, "-type", "f", "-name", "[^.]*"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            files = out.stdout.strip().split("\n")[:100]  # Limit to 100 files

            for file_path in files:
                for iac_type, pattern in iac_patterns.items():
                    if re.search(pattern, file_path, re.IGNORECASE):
                        if iac_type not in result.iac_types:
                            result.iac_types.append(iac_type)
                        result.files_scanned.append(file_path)
        except Exception:
            pass

        # Run scanner
        if tool == "tfsec":
            # Terraform security scanner
            cmd = [
                "tfsec", target,
                "--format", "json",
                "--exit-code", "0",
            ]
        elif tool == "checkov":
            # Multi-framework IaC scanner
            cmd = [
                "checkov",
                "-d", target,
                "--output", "json",
                "--quiet",
            ]
        elif tool == "kubesec":
            # Kubernetes manifest scanner
            cmd = [
                "kubesec", "scan", target,
                "-o", "json",
            ]
        elif tool == "hadolint":
            # Dockerfile scanner
            cmd = [
                "hadolint",
                "--format", "json",
                target,
            ]
        else:
            result.success = False
            result.error = f"Unknown tool: {tool}"
            return result.model_dump()

        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if out.stdout:
            try:
                parsed = json.loads(out.stdout)

                # Parse based on tool format
                issues_list = []

                if tool == "tfsec":
                    issues_list = parsed.get("results", [])
                elif tool == "checkov":
                    # Checkov returns check results
                    for check_type, checks in parsed.get("check_type_to_results", {}).items():
                        issues_list.extend(checks.get("failed_checks", []))
                elif tool == "kubesec":
                    issues_list = parsed if isinstance(parsed, list) else [parsed]
                elif tool == "hadolint":
                    issues_list = parsed if isinstance(parsed, list) else [parsed]

                # Normalize to IaCIssue format
                for issue in issues_list[:50]:  # Limit to 50 issues
                    severity = issue.get("severity", "medium").lower()

                    iac_issue = IaCIssue(
                        issue_id=issue.get("id", "unknown"),
                        title=issue.get("title", issue.get("name", "Unknown Issue")),
                        severity=severity,
                        resource=issue.get("resource", "unknown"),
                        file_path=issue.get("file_path", issue.get("file", target)),
                        line=issue.get("line", issue.get("line_number")),
                        rule=issue.get("rule", issue.get("code", "N/A")),
                        description=issue.get("description", ""),
                        remediation=issue.get("remediation", issue.get("message")),
                    )

                    result.issues.append(iac_issue)

                    # Count by severity
                    if severity == "critical":
                        result.critical_count += 1
                    elif severity == "high":
                        result.high_count += 1
                    elif severity == "medium":
                        result.medium_count += 1

                result.resource_scanned = len(result.files_scanned)

            except json.JSONDecodeError:
                result.success = False
                result.error = "Failed to parse scanner output"

    except subprocess.TimeoutExpired:
        result.success = False
        result.error = f"Scan timed out after {timeout}s"
    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


IaC_SECURITY_TOOL_DEFINITION = {
    "name": "iac_security_scan",
    "description": (
        "Scan Infrastructure-as-Code manifests (Terraform, CloudFormation, Kubernetes, Dockerfile) "
        "for misconfigurations, security issues, and best practice violations using tfsec, Checkov, Kubesec, or Hadolint."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["tfsec", "checkov", "kubesec", "hadolint"],
                "description": (
                    "tfsec=Terraform | checkov=Multi-IaC | kubesec=Kubernetes | hadolint=Docker"
                ),
            },
            "target": {
                "type": "string",
                "description": "Path to IaC file or directory containing manifests",
            },
            "include_secrets": {
                "type": "boolean",
                "description": "Include hardcoded secrets detection",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["tool", "target"],
    },
}
