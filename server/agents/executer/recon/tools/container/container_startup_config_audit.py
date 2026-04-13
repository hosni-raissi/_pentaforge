"""Container Startup Config Auditor - Entrypoint, CMD, environment, security configs."""

import subprocess
import json
import re
import time
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class StartupConfigRequest(BaseModel):
    target: str
    timeout: int = Field(default=300, ge=30, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        if not re.match(r"^[a-zA-Z0-9/._:@-]+$", v):
            raise ValueError("Invalid image reference format")
        return v


class SecurityConfig(BaseModel):
    parameter: str
    value: Optional[str] = None
    is_secure: bool
    risk: Optional[str] = None
    recommendation: Optional[str] = None


class StartupConfigResult(BaseModel):
    success: bool
    target: str

    # Findings
    security_issues: list[SecurityConfig] = []
    unsafe_commands: list[str] = []
    exposed_env_vars: list[dict] = []

    # Config details
    entrypoint: Optional[str] = None
    cmd: Optional[str] = None
    working_dir: Optional[str] = None
    user: Optional[str] = None
    volumes: list[str] = []
    exposed_ports: list[str] = []
    environment_vars: dict[str, str] = {}

    # Security metrics
    critical_issues: int = 0
    high_issues: int = 0

    error: Optional[str] = None
    execution_time: float = 0.0


def container_startup_config_audit(
    target: str,
    timeout: int = 300,
) -> dict:
    """Audit container image startup configuration for security issues."""
    start = time.time()

    try:
        req = StartupConfigRequest(
            target=target,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = StartupConfigResult(
        success=True,
        target=target,
    )

    try:
        cmd = ["docker", "inspect", target]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if out.returncode == 0 and out.stdout:
            try:
                inspect_data = json.loads(out.stdout)
                if not inspect_data:
                    result.success = False
                    result.error = "Image not found"
                    return result.model_dump()

                img_data = inspect_data[0]
                config = img_data.get("Config", {})

                # Entrypoint and CMD
                entrypoint = config.get("Entrypoint")
                cmd_config = config.get("Cmd")

                result.entrypoint = " ".join(entrypoint) if entrypoint else None
                result.cmd = " ".join(cmd_config) if cmd_config else None

                # User
                user = config.get("User", "")
                result.user = user if user else "root"

                if result.user == "root" or result.user == "":
                    result.security_issues.append(
                        SecurityConfig(
                            parameter="User",
                            value=result.user or "root",
                            is_secure=False,
                            risk="Container runs as root - arbitrary code execution = full system compromise",
                            recommendation="Use a non-root user (uid > 1000) in Dockerfile",
                        )
                    )
                    result.critical_issues += 1

                # Working directory
                result.working_dir = config.get("WorkingDir", "/")
                if result.working_dir == "/":
                    result.security_issues.append(
                        SecurityConfig(
                            parameter="WorkingDir",
                            value="/",
                            is_secure=False,
                            risk="Working directory is root filesystem",
                            recommendation="Use a specific application directory",
                        )
                    )
                    result.high_issues += 1

                # Volumes
                result.volumes = list(config.get("Volumes", {}).keys()) if config.get("Volumes") else []

                # Exposed ports
                result.exposed_ports = (
                    list(config.get("ExposedPorts", {}).keys())
                    if config.get("ExposedPorts")
                    else []
                )

                # Environment variables
                env_list = config.get("Env", [])
                for env_var in env_list:
                    if "=" in env_var:
                        key, val = env_var.split("=", 1)
                        result.environment_vars[key] = val[:100]

                        # Check for exposed secrets
                        if any(
                            secret in key.upper()
                            for secret in ["PASSWORD", "TOKEN", "SECRET", "KEY", "CREDENTIAL"]
                        ):
                            result.exposed_env_vars.append(
                                {
                                    "variable": key,
                                    "severity": "critical",
                                    "risk": "Sensitive data in environment variables",
                                }
                            )
                            result.critical_issues += 1

                # Check entrypoint/cmd for unsafe patterns
                unsafe_patterns = [
                    r"curl.*\|.*bash",
                    r"wget.*\|.*sh",
                    r"eval\s+\$",
                    r"exec\s+\$",
                    r"cat.*\|.*base64",
                    r"chmod.*777",
                ]

                combined_cmd = f"{result.entrypoint or ''} {result.cmd or ''}"
                for pattern in unsafe_patterns:
                    if re.search(pattern, combined_cmd):
                        result.unsafe_commands.append(pattern)
                        result.security_issues.append(
                            SecurityConfig(
                                parameter="Unsafe Pattern in CMD/Entrypoint",
                                value=pattern,
                                is_secure=False,
                                risk=f"Potentially unsafe command pattern detected",
                            )
                        )
                        result.high_issues += 1

                # Check for health checks
                health_check = config.get("Healthcheck")
                if not health_check:
                    result.security_issues.append(
                        SecurityConfig(
                            parameter="HealthCheck",
                            is_secure=False,
                            risk="No health check defined",
                            recommendation="Define a HEALTHCHECK instruction",
                        )
                    )

            except json.JSONDecodeError:
                result.success = False
                result.error = "Failed to parse image inspect output"

    except subprocess.TimeoutExpired:
        result.success = False
        result.error = f"Audit timed out after {timeout}s"
    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


STARTUP_CONFIG_TOOL_DEFINITION = {
    "name": "container_startup_config_audit",
    "description": (
        "Audit container image startup configuration for security issues: "
        "runs as root, exposed secrets in environment, unsafe commands in entrypoint/cmd, "
        "world-writable permissions, hardcoded credentials."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Container image reference (e.g., 'ubuntu:22.04', 'myapp:v1.0')",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
