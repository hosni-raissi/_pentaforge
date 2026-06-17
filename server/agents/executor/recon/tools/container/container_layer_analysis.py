"""Container Layer Analysis - Inspect layers, secrets, and history."""

import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class LayerAnalysisRequest(BaseModel):
    target: str
    include_secrets: bool = True
    timeout: int = Field(default=600, ge=30, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Allow docker image references: repo/image:tag
        if not re.match(r"^[a-zA-Z0-9/._:@-]+$", v):
            raise ValueError("Invalid image reference format")
        return v


class ContainerLayer(BaseModel):
    layer_index: int
    digest: str
    size: int
    cmd: Optional[str] = None
    created_by: Optional[str] = None
    created: Optional[str] = None
    empty_layer: bool = False


class ContainerLayerAnalysisResult(BaseModel):
    success: bool
    target: str

    # Findings
    layers: list[ContainerLayer] = []
    suspicious_layers: list[dict] = []
    secrets_found: list[dict] = []

    # Image metadata
    image_size: int = 0
    total_layers: int = 0
    base_image: Optional[str] = None
    OS: Optional[str] = None
    architecture: Optional[str] = None
    env_vars: dict[str, str] = {}

    # Security findings
    high_risk_issues: list[str] = []

    error: Optional[str] = None
    execution_time: float = 0.0


def container_layer_analysis(
    target: str,
    include_secrets: bool = True,
    timeout: int = 600,
) -> dict:
    """Analyze container image layers for secrets, suspicious commands, and metadata."""
    start = time.time()

    try:
        req = LayerAnalysisRequest(
            target=target,
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

    result = ContainerLayerAnalysisResult(
        success=True,
        target=target,
    )

    try:
        # Get image history
        cmd = ["docker", "history", "--human", "--no-trunc", target]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if out.returncode == 0 and out.stdout:
            lines = out.stdout.strip().split("\n")[1:]  # Skip header

            for idx, line in enumerate(lines):
                parts = line.split(None, 5)  # Split on whitespace, max 6 parts
                if len(parts) >= 2:
                    digest = parts[0][:12]  # Short digest
                    created_by = " ".join(parts[1:]) if len(parts) > 1 else "unknown"
                    size_str = parts[4] if len(parts) > 4 else "0B"

                    # Parse size
                    size = 0
                    if "kB" in size_str:
                        size = int(float(size_str.replace("kB", "")) * 1024)
                    elif "MB" in size_str:
                        size = int(float(size_str.replace("MB", "")) * 1024 * 1024)
                    elif "GB" in size_str:
                        size = int(float(size_str.replace("GB", "")) * 1024 * 1024 * 1024)

                    layer = ContainerLayer(
                        layer_index=idx,
                        digest=digest,
                        size=size,
                        created_by=created_by,
                        empty_layer="0B" in size_str,
                    )

                    result.layers.append(layer)
                    result.image_size += size

                    # Check for suspicious commands
                    unsafe_patterns = [
                        r"curl.*\|.*bash",
                        r"wget.*\|.*sh",
                        r"eval\s+\$",
                        r"exec\s+\$",
                        r"cat.*\|.*base64",
                    ]

                    for pattern in unsafe_patterns:
                        if re.search(pattern, created_by):
                            result.suspicious_layers.append(
                                {
                                    "layer": idx,
                                    "pattern": pattern,
                                    "command": created_by[:100],
                                    "severity": "high",
                                }
                            )
                            result.high_risk_issues.append(
                                f"Layer {idx} contains unsafe command pattern"
                            )

                    # Check for secret-like patterns
                    if include_secrets:
                        secret_patterns = [
                            r"password\s*=", r"token\s*=",
                            r"api[_-]?key\s*=", r"secret\s*=",
                            r"AWS_SECRET", r"GITHUB_TOKEN",
                        ]
                        for pattern in secret_patterns:
                            if re.search(pattern, created_by, re.IGNORECASE):
                                result.secrets_found.append(
                                    {
                                        "layer": idx,
                                        "pattern": pattern,
                                        "severity": "critical",
                                    }
                                )

        # Get image inspect data
        cmd = ["docker", "inspect", target]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if out.returncode == 0 and out.stdout:
            try:
                inspect_data = json.loads(out.stdout)
                if inspect_data and len(inspect_data) > 0:
                    img_data = inspect_data[0]

                    # Extract metadata
                    result.total_layers = len(img_data.get("RootFS", {}).get("Layers", []))
                    result.image_size = img_data.get("Size", 0)

                    # OS info
                    config = img_data.get("Config", {})
                    result.architecture = img_data.get("Architecture")
                    result.OS = img_data.get("Os")

                    # Environment variables
                    env_list = config.get("Env", [])
                    for env_var in env_list:
                        if "=" in env_var:
                            key, val = env_var.split("=", 1)
                            result.env_vars[key] = val[:50]  # Truncate values

            except json.JSONDecodeError:
                pass

    except subprocess.TimeoutExpired:
        result.success = False
        result.error = f"Analysis timed out after {timeout}s"
    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


LAYER_ANALYSIS_TOOL_DEFINITION = {
    "name": "container_layer_analysis",
    "description": (
        "Analyze container image layers for secrets, suspicious commands, metadata, "
        "and security issues. Inspects layer history, commands, and environment variables."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Container image reference (e.g., 'ubuntu:22.04', 'myrepo/app:v1.0')",
            },
            "include_secrets": {
                "type": "boolean",
                "description": "Scan layers for exposed secrets and sensitive patterns",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
