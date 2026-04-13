"""CI/CD Pipeline Security Auditor - GitHub Actions, GitLab CI, Jenkins configs."""

import subprocess
import json
import re
import time
import yaml
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class CICDRequest(BaseModel):
    target: str
    platform: str = "auto"  # auto, github, gitlab, jenkins
    include_secrets: bool = True
    timeout: int = Field(default=600, ge=30, le=3600)

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

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v):
        allowed = {"auto", "github", "gitlab", "jenkins"}
        if v not in allowed:
            raise ValueError(f"platform must be one of: {allowed}")
        return v


class CICDIssue(BaseModel):
    issue_type: str
    severity: str
    location: str
    description: str
    risk: str
    recommendation: Optional[str] = None


class CICDPipelineResult(BaseModel):
    success: bool
    target: str
    platform: str

    # Findings
    security_issues: list[CICDIssue] = []
    exposed_secrets: list[dict] = []
    unsafe_commands: list[dict] = []
    third_party_actions: list[str] = []

    # Pipeline analysis
    workflows_found: list[str] = []
    total_workflows: int = 0
    high_risk_count: int = 0

    error: Optional[str] = None
    execution_time: float = 0.0


def ci_cd_pipeline_audit(
    target: str,
    platform: str = "auto",
    include_secrets: bool = True,
    timeout: int = 600,
) -> dict:
    """Audit CI/CD pipeline configurations for security issues."""
    start = time.time()

    try:
        req = CICDRequest(
            target=target,
            platform=platform,
            include_secrets=include_secrets,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = CICDPipelineResult(
        success=True,
        target=target,
        platform=platform,
    )

    try:
        # GitHub Actions
        github_actions_dir = f"{target}/.github/workflows"
        try:
            import os
            if os.path.isdir(github_actions_dir):
                result.platform = "github"
                for workflow_file in os.listdir(github_actions_dir):
                    if workflow_file.endswith((".yml", ".yaml")):
                        result.workflows_found.append(workflow_file)
                        workflow_path = os.path.join(github_actions_dir, workflow_file)

                        with open(workflow_path, "r") as f:
                            try:
                                workflow = yaml.safe_load(f)

                                # Analyze for issues
                                if workflow:
                                    # Check for dangerous permissions
                                    if workflow.get("permissions") == "write-all":
                                        result.security_issues.append(
                                            CICDIssue(
                                                issue_type="dangerous_permission",
                                                severity="high",
                                                location=workflow_file,
                                                description="Workflow has write-all permissions",
                                                risk="Could allow privilege escalation",
                                                recommendation="Use minimal required permissions",
                                            )
                                        )
                                        result.high_risk_count += 1

                                    # Check for secret exposure
                                    jobs = workflow.get("jobs", {})
                                    for job_name, job in jobs.items():
                                        env = job.get("env", {})
                                        for key, val in env.items():
                                            if any(
                                                secret in str(key).lower()
                                                for secret in ["secret", "token", "key", "password"]
                                            ):
                                                result.exposed_secrets.append(
                                                    {
                                                        "file": workflow_file,
                                                        "context": f"job.{job_name}.env",
                                                        "severity": "high",
                                                    }
                                                )

                                    # Check for third-party actions
                                    for job_name, job in jobs.items():
                                        steps = job.get("steps", [])
                                        for step in steps:
                                            uses = step.get("uses", "")
                                            if uses and "@" in uses:
                                                action = uses.split("@")[0]
                                                if not action.startswith("./"):
                                                    result.third_party_actions.append(action)

                                    # Check for unsafe commands
                                    for job_name, job in jobs.items():
                                        steps = job.get("steps", [])
                                        for step in steps:
                                            run = step.get("run", "")
                                            if isinstance(run, str):
                                                unsafe_patterns = [
                                                    r"curl.*\|.*bash",
                                                    r"eval\s+\$",
                                                    r"exec\s+\$",
                                                ]
                                                for pattern in unsafe_patterns:
                                                    if re.search(pattern, run):
                                                        result.unsafe_commands.append(
                                                            {
                                                                "file": workflow_file,
                                                                "pattern": pattern,
                                                                "severity": "high",
                                                            }
                                                        )

                            except yaml.YAMLError:
                                pass

        except ImportError:
            pass

        # GitLab CI
        gitlab_ci_file = f"{target}/.gitlab-ci.yml"
        try:
            import os
            if os.path.isfile(gitlab_ci_file):
                result.platform = "gitlab"
                result.workflows_found.append(".gitlab-ci.yml")

                with open(gitlab_ci_file, "r") as f:
                    try:
                        cicd = yaml.safe_load(f)
                        if cicd:
                            # Check for secret exposure in variables
                            variables = cicd.get("variables", {})
                            for var_name, var_val in variables.items():
                                if any(
                                    s in str(var_name).lower()
                                    for s in ["secret", "token", "key", "password"]
                                ):
                                    result.exposed_secrets.append(
                                        {
                                            "file": ".gitlab-ci.yml",
                                            "variable": var_name,
                                            "severity": "high",
                                        }
                                    )
                    except yaml.YAMLError:
                        pass

        except Exception:
            pass

        result.total_workflows = len(result.workflows_found)
        result.third_party_actions = list(set(result.third_party_actions))[:20]

    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


CICD_PIPELINE_TOOL_DEFINITION = {
    "name": "ci_cd_pipeline_audit",
    "description": (
        "Audit CI/CD pipeline configurations (GitHub Actions, GitLab CI, Jenkins) for security issues, "
        "exposed secrets, unsafe commands, dangerous permissions, and third-party action risks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Path to repository root or CI/CD config directory",
            },
            "platform": {
                "type": "string",
                "enum": ["auto", "github", "gitlab", "jenkins"],
                "description": "CI/CD platform: auto=detect, github=Actions, gitlab=CI, jenkins=Declarative",
            },
            "include_secrets": {
                "type": "boolean",
                "description": "Include exposed secrets detection",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
