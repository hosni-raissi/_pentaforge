"""Sensitive Files Scanner - .env, .key, .pem, backups, IDE configs."""

import subprocess
import os
import re
import time
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class SensitiveFileScanRequest(BaseModel):
    target: str
    include_backups: bool = True
    include_ide_config: bool = True
    timeout: int = Field(default=300, ge=30, le=3600)

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


class SensitiveFile(BaseModel):
    file_path: str
    file_type: str
    sensitivity: str
    size: int
    contains_sample: Optional[str] = None


class SensitiveFileResult(BaseModel):
    success: bool
    target: str

    # Findings
    sensitive_files: list[SensitiveFile] = []
    env_files: list[str] = []
    private_keys: list[str] = []
    certificates: list[str] = []
    backups: list[str] = []
    ide_configs: list[str] = []
    database_files: list[str] = []

    # Summary
    total_sensitive_files: int = 0
    critical_count: int = 0

    error: Optional[str] = None
    execution_time: float = 0.0


def sensitive_files_scan(
    target: str,
    include_backups: bool = True,
    include_ide_config: bool = True,
    timeout: int = 300,
) -> dict:
    """Scan for sensitive files (.env, .key, .pem, backups, IDE configs)."""
    start = time.time()

    try:
        req = SensitiveFileScanRequest(
            target=target,
            include_backups=include_backups,
            include_ide_config=include_ide_config,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = SensitiveFileResult(
        success=True,
        target=target,
    )

    try:
        patterns = {
            "env_files": [
                r"\.env$", r"\.env\.local$", r"\.env\.(dev|staging|prod|test)",
                r"config\.env", r"environment\.env",
            ],
            "private_keys": [
                r"\.key$", r"\.pem$", r"\.p12$", r"\.pfx$", r"\.pkcs12$",
                r"id_rsa$", r"id_dsa$", r"id_ecdsa$", r"id_ed25519$",
                r"\.privatekey$",
            ],
            "certificates": [
                r"\.crt$", r"\.cer$", r"\.cert$", r"\.pem$",
                r"certificate\.", r"\.csr$",
            ],
            "backups": [
                r"\.(bak|backup|old|swp|tmp|orig|original)$",
                r"~$",
                r"\.tar\.gz$", r"\.zip$", r"\.rar$",
            ],
            "ide_configs": [
                r"\.vscode/settings\.json",
                r"\.idea/",
                r"\.sublime-project",
                r"\.DS_Store",
                r"\.vscode/launch\.json",
            ],
            "database": [
                r"\.(sqlite|db|sql)$", r"database\.", r"\.mdb$",
                r"\.sqlite3$", r"dump\.",
            ],
        }

        # Find files
        for root, dirs, files in os.walk(target):
            # Skip common non-source directories
            skip_dirs = {".git", "node_modules", ".venv", ".env", "venv", "__pycache__"}
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file_name in files:
                file_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(file_path, target)

                # Check against patterns
                for pattern_type, patterns in patterns.items():
                    if pattern_type == "ide_configs" and not include_ide_config:
                        continue
                    if pattern_type == "backups" and not include_backups:
                        continue

                    for pattern in patterns:
                        if re.search(pattern, file_name, re.IGNORECASE) or re.search(
                            pattern, rel_path, re.IGNORECASE
                        ):
                            file_size = os.path.getsize(file_path)
                            sensitivity = "critical" if pattern_type in [
                                "private_keys", "env_files"
                            ] else "high"

                            # Get sample (max 100 chars for non-binary files)
                            sample = None
                            if file_size < 10000:
                                try:
                                    with open(file_path, "r", errors="ignore") as f:
                                        content = f.read(100)
                                        if len(content) > 0:
                                            sample = content[:50]
                                except Exception:
                                    pass

                            sensitive_file = SensitiveFile(
                                file_path=rel_path,
                                file_type=pattern_type,
                                sensitivity=sensitivity,
                                size=file_size,
                                contains_sample=sample,
                            )

                            result.sensitive_files.append(sensitive_file)

                            # Categorize
                            if pattern_type == "env_files":
                                result.env_files.append(rel_path)
                                result.critical_count += 1
                            elif pattern_type == "private_keys":
                                result.private_keys.append(rel_path)
                                result.critical_count += 1
                            elif pattern_type == "certificates":
                                result.certificates.append(rel_path)
                            elif pattern_type == "backups":
                                result.backups.append(rel_path)
                            elif pattern_type == "ide_configs":
                                result.ide_configs.append(rel_path)
                            elif pattern_type == "database":
                                result.database_files.append(rel_path)

                            break

            if len(result.sensitive_files) >= 100:  # Limit to 100 files
                break

        result.total_sensitive_files = len(result.sensitive_files)

    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


SENSITIVE_FILES_TOOL_DEFINITION = {
    "name": "sensitive_files_scan",
    "description": (
        "Scan repository for sensitive files (.env, private keys, certificates, "
        "backups, IDE configs, database files). Identifies files that should not be in version control."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Path to directory to scan",
            },
            "include_backups": {
                "type": "boolean",
                "description": "Include .bak, .backup, .old files",
            },
            "include_ide_config": {
                "type": "boolean",
                "description": "Include IDE configuration files",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
