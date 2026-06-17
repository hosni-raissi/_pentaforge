"""Container Registry Enumeration - Docker Hub, ECR, GCR, ACR."""

import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class RegistryEnumRequest(BaseModel):
    target: str
    registry_type: str = "auto"  # auto, docker_hub, ecr, gcr, acr
    timeout: int = Field(default=300, ge=30, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")
        return v

    @field_validator("registry_type")
    @classmethod
    def validate_registry_type(cls, v):
        allowed = {"auto", "docker_hub", "ecr", "gcr", "acr"}
        if v not in allowed:
            raise ValueError(f"registry_type must be one of: {allowed}")
        return v


class ContainerImage(BaseModel):
    name: str
    tag: str = "latest"
    digest: Optional[str] = None
    size: Optional[int] = None
    created: Optional[str] = None
    pushed: Optional[str] = None
    pull_count: Optional[int] = None
    is_public: bool = False
    layers: int = 0


class RegistryEnumResult(BaseModel):
    success: bool
    target: str
    registry_type: str

    # Findings
    images_found: list[ContainerImage] = []
    total_images: int = 0
    public_images: int = 0
    untagged_images: int = 0

    # Repository info
    repository_name: Optional[str] = None
    repository_created: Optional[str] = None
    repository_stars: Optional[int] = None
    repository_pulls: Optional[int] = None

    # Risk indicators
    high_risk_images: list[dict] = []

    error: Optional[str] = None
    execution_time: float = 0.0


def container_registry_enum(
    target: str,
    registry_type: str = "auto",
    timeout: int = 300,
) -> dict:
    """Enumerate container images in registries (Docker Hub, ECR, GCR, ACR)."""
    start = time.time()

    try:
        req = RegistryEnumRequest(
            target=target,
            registry_type=registry_type,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = RegistryEnumResult(
        success=True,
        target=target,
        registry_type=registry_type,
    )

    try:
        # Detect registry type
        if registry_type == "auto":
            if "ecr." in target and ".amazonaws.com" in target:
                registry_type = "ecr"
            elif ".azurecr.io" in target:
                registry_type = "acr"
            elif any(x in target for x in ["gcr.io", "us-docker.pkg.dev", "europe-docker.pkg.dev"]):
                registry_type = "gcr"
            else:
                registry_type = "docker_hub"

        result.registry_type = registry_type
        result.repository_name = target

        # Docker Hub enumeration
        if registry_type == "docker_hub":
            # Parse username/repo
            parts = target.split("/")
            if len(parts) == 2:
                username, repo = parts
            elif len(parts) == 1:
                repo = parts[0]
                username = "library"
            else:
                result.success = False
                result.error = "Invalid Docker Hub target format"
                return result.model_dump()

            # Get tags via Docker Hub API
            cmd = [
                "curl", "-s",
                f"https://hub.docker.com/v2/repositories/{username}/{repo}/tags?page_size=100",
            ]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if out.stdout:
                    try:
                        data = json.loads(out.stdout)
                        for image_data in data.get("results", []):
                            img = ContainerImage(
                                name=f"{username}/{repo}",
                                tag=image_data.get("name", "latest"),
                                digest=image_data.get("image_id"),
                                size=image_data.get("full_size"),
                                pushed=image_data.get("last_updated"),
                                layers=image_data.get("images", [{}])[0].get("architecture", None),
                                is_public=True,
                            )
                            result.images_found.append(img)
                            result.public_images += 1

                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        # ECR enumeration (requires aws cli)
        elif registry_type == "ecr":
            # Extract region and account from ECR URL
            match = re.match(
                r"(\d+)\.dkr\.ecr\.([^.]+)\.amazonaws\.com",
                target,
            )
            if match:
                account, region = match.groups()
                cmd = [
                    "aws", "ecr", "describe-repositories",
                    "--region", region,
                    "--output", "json",
                ]
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                    if out.stdout:
                        try:
                            data = json.loads(out.stdout)
                            for repo in data.get("repositories", [])[:50]:
                                result.images_found.append(
                                    ContainerImage(
                                        name=repo.get("repositoryName"),
                                        pushed=repo.get("repositoryUri"),
                                        is_public=repo.get("encryptionConfiguration", {}).get(
                                            "encryptionType"
                                        )
                                        != "AES256",
                                    )
                                )
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

        # GCR enumeration
        elif registry_type == "gcr":
            # Try gcloud command
            cmd = ["gcloud", "container", "images", "list", "--repository-format=json"]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if out.stdout:
                    try:
                        images = json.loads(out.stdout)
                        for image_uri in images[:50]:
                            result.images_found.append(
                                ContainerImage(
                                    name=image_uri,
                                    tag="multiple",
                                    is_public=True,
                                )
                            )
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        result.total_images = len(result.images_found)

    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


REGISTRY_ENUM_TOOL_DEFINITION = {
    "name": "container_registry_enum",
    "description": (
        "Enumerate container images and repositories in Docker Hub, AWS ECR, Google GCR, or Azure ACR. "
        "Identifies accessible images, tags, and metadata for security assessment."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": (
                    "Registry target. Examples: 'username/repo' (Docker Hub), "
                    "'123456.dkr.ecr.us-east-1.amazonaws.com' (ECR), "
                    "'gcr.io/project-id' (GCR), 'myregistry.azurecr.io' (ACR)"
                ),
            },
            "registry_type": {
                "type": "string",
                "enum": ["auto", "docker_hub", "ecr", "gcr", "acr"],
                "description": "Registry type: auto=detect, docker_hub, ecr, gcr, acr",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
