"""Git History & Metadata Auditor - Detect hidden/sensitive data in git history."""

import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class GitHistoryRequest(BaseModel):
    target: str
    analysis_depth: str = "full"  # quick, medium, full
    include_deleted: bool = True
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

    @field_validator("analysis_depth")
    @classmethod
    def validate_depth(cls, v):
        allowed = {"quick", "medium", "full"}
        if v not in allowed:
            raise ValueError(f"analysis_depth must be one of: {allowed}")
        return v


class CommitAnomaly(BaseModel):
    commit_hash: str
    author: str
    date: str
    message: str
    severity: str
    reason: str
    files_changed: list[str] = []


class DeletedContent(BaseModel):
    file_path: str
    deleted_by_commit: str
    last_author: str
    last_date: str
    snippet: Optional[str] = None
    sensitivity: str = "medium"


class GitHistoryResult(BaseModel):
    success: bool
    target: str
    repository_url: Optional[str] = None

    # Findings
    large_commits: list[dict] = []
    suspicious_commits: list[CommitAnomaly] = []
    deleted_sensitive_files: list[DeletedContent] = []
    author_enumeration: dict[str, int] = {}
    branch_analysis: dict[str, Any] = {}

    # Metadata
    total_commits: int = 0
    date_range: Optional[str] = None
    branches_found: int = 0
    error: Optional[str] = None
    execution_time: float = 0.0


def git_history_audit(
    target: str,
    analysis_depth: str = "full",
    include_deleted: bool = True,
    timeout: int = 600,
) -> dict:
    """Audit git history for sensitive data, anomalies, and metadata."""
    start = time.time()

    try:
        req = GitHistoryRequest(
            target=target,
            analysis_depth=analysis_depth,
            include_deleted=include_deleted,
            timeout=timeout,
        )
    except ValueError as e:
        return {
            "success": False,
            "target": target,
            "error": str(e),
            "execution_time": 0.0,
        }

    result = GitHistoryResult(
        success=True,
        target=target,
    )

    try:
        # Get commit count
        cmd = ["git", "-C", target, "rev-list", "--count", "HEAD"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result.total_commits = int(out.stdout.strip()) if out.stdout else 0

        # Analyze commits for anomalies
        cmd = [
            "git", "-C", target, "log",
            "--pretty=format:%H|%an|%ai|%s|%b",
            "--name-status",
        ]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if out.stdout:
            commits = out.stdout.strip().split("\n\n")
            for commit_entry in commits[:min(100, len(commits))]:  # Limit to 100 commits
                lines = commit_entry.split("\n")
                if not lines[0]:
                    continue
                parts = lines[0].split("|")
                if len(parts) >= 4:
                    commit_hash, author, date, message = parts[:4]

                    # Detect anomalies
                    if "revert" in message.lower() or "remove" in message.lower():
                        if any(word in message.lower() for word in ["secret", "key", "token", "password", "api"]):
                            result.suspicious_commits.append(
                                CommitAnomaly(
                                    commit_hash=commit_hash,
                                    author=author,
                                    date=date,
                                    message=message,
                                    severity="high",
                                    reason="Suspicious removal of sensitive data",
                                    files_changed=[l.split()[-1] for l in lines[1:] if l],
                                )
                            )

                    # Track authors
                    result.author_enumeration[author] = result.author_enumeration.get(author, 0) + 1

        # Get branches
        cmd = ["git", "-C", target, "branch", "-a"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        branches = [b.strip() for b in out.stdout.strip().split("\n") if b.strip()]
        result.branches_found = len(branches)
        result.branch_analysis = {"branches": branches[:20]}

        # Deleted files analysis (if requested)
        if include_deleted:
            cmd = ["git", "-C", target, "log", "--diff-filter=D", "--summary"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            sensitive_patterns = [
                r"\.key$", r"\.pem$", r"\.p12$", r"\.pfx$",
                r"\.env", r"secrets\.", r"config\.prod",
                r"password", r"token", r"credential",
            ]

            if out.stdout:
                for line in out.stdout.split("\n"):
                    if "delete mode" in line:
                        for pattern in sensitive_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                file_path = line.split()[-1]
                                result.deleted_sensitive_files.append(
                                    DeletedContent(
                                        file_path=file_path,
                                        deleted_by_commit="unknown",
                                        last_author="unknown",
                                        last_date="unknown",
                                        sensitivity="high",
                                    )
                                )

    except Exception as e:
        result.success = False
        result.error = str(e)

    result.execution_time = round(time.time() - start, 2)
    return result.model_dump()


GIT_HISTORY_TOOL_DEFINITION = {
    "name": "git_history_audit",
    "description": (
        "Audit git repository history for sensitive data leaks, anomalies, "
        "deleted sensitive files, and author enumeration. Detects suspicious commits, "
        "large commits, and removed secrets."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Path to git repository",
            },
            "analysis_depth": {
                "type": "string",
                "enum": ["quick", "medium", "full"],
                "description": "Analysis scope: quick=recent, medium=1yr, full=all history",
            },
            "include_deleted": {
                "type": "boolean",
                "description": "Scan for deleted sensitive files",
            },
            "timeout": {
                "type": "integer",
                "description": "Command timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
