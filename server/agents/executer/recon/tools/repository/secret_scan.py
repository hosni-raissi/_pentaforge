import subprocess
import json
import re
import time
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SecretScanRequest(BaseModel):
    tool: str
    target: str
    scan_scope: str = "repo"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=30, le=7200)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"gitleaks", "trufflehog"}
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

        return v

    @field_validator("scan_scope")
    @classmethod
    def validate_scan_scope(cls, v):
        allowed = {"repo", "git", "history", "filesystem"}
        if v not in allowed:
            raise ValueError(f"Unknown scan_scope: {v}")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--report-path", "--report-format"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")

        return v


class SecretFinding(BaseModel):
    tool: str
    rule_id: Optional[str] = None
    title: str
    category: str = "secret"
    severity: str = "high"  # critical, high, medium, low, info
    secret_type: Optional[str] = None
    verified: Optional[bool] = None

    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None

    match: Optional[str] = None
    redacted: Optional[str] = None
    entropy: Optional[float] = None
    fingerprint: Optional[str] = None

    recommendation: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class SecretScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    scan_scope: str
    command: str
    total_findings: int = 0
    verified_findings: int = 0
    severity_summary: dict[str, int] = {}
    secret_type_summary: dict[str, int] = {}
    findings: list[SecretFinding] = []
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

def parse_gitleaks_json(stdout: str) -> list[SecretFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    if not isinstance(data, list):
        return findings

    for item in data:
        findings.append(SecretFinding(
            tool="gitleaks",
            rule_id=item.get("RuleID"),
            title=item.get("Description") or item.get("RuleID") or "Secret detected",
            category="secret",
            severity="high",
            secret_type=item.get("Tags", [None])[0] if isinstance(item.get("Tags"), list) and item.get("Tags") else item.get("RuleID"),
            verified=None,
            file_path=item.get("File"),
            start_line=item.get("StartLine"),
            end_line=item.get("EndLine"),
            commit=item.get("Commit"),
            author=item.get("Author"),
            date=item.get("Date"),
            match=item.get("Match"),
            redacted=item.get("Secret"),
            entropy=item.get("Entropy"),
            fingerprint=item.get("Fingerprint"),
            recommendation="Rotate the exposed secret, remove it from code/history, and move it to a secure secret manager",
            extra={
                "commit_message": item.get("Message"),
                "tags": item.get("Tags"),
            }
        ))

    return findings


def parse_trufflehog_json(stdout: str) -> list[SecretFinding]:
    findings = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            item = json.loads(line)
        except Exception:
            continue

        findings.append(SecretFinding(
            tool="trufflehog",
            rule_id=item.get("DetectorName"),
            title=item.get("DetectorName") or "Secret detected",
            category="secret",
            severity="critical" if item.get("Verified") else "high",
            secret_type=item.get("DetectorName"),
            verified=item.get("Verified"),
            file_path=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file")
                     or item.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file"),
            start_line=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line")
                      or item.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("line"),
            commit=item.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit"),
            author=item.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("email"),
            date=None,
            match=item.get("Raw"),
            redacted=item.get("Redacted"),
            entropy=None,
            fingerprint=item.get("Fingerprint"),
            recommendation="Immediately revoke/rotate verified secrets and purge them from repository history",
            extra={
                "source_name": item.get("SourceName"),
                "source_id": item.get("SourceID"),
                "rotation_guide": item.get("RotationGuide"),
                "verified": item.get("Verified"),
            }
        ))

    return findings


def fallback_secret_type(match: Optional[str], title: Optional[str]) -> str:
    text = f"{match or ''} {title or ''}".lower()

    if "aws" in text or re.search(r"akia[0-9a-z]{16}", text, re.I):
        return "aws"
    if "private key" in text or "-----begin" in text:
        return "private_key"
    if "github" in text or "ghp_" in text or "github_pat_" in text:
        return "github_token"
    if "slack" in text:
        return "slack_token"
    if "stripe" in text:
        return "stripe_key"
    if "password" in text:
        return "password"
    if "token" in text:
        return "token"
    return "unknown"


# ══════════════════════════════════════════════════════════════
# 4. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def secret_scan(tool: str, target: str, scan_scope: str = "repo", args: list[str] = []) -> dict:
    """
    🔐 Agent Tool: Secret Scanner

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  GIT HISTORY         search commits for leaked secrets      │
      │  REPOSITORY SCAN     current repo contents                  │
      │  FILESYSTEM SCAN     scan local directories                 │
      │  API KEYS            AWS, GitHub, Slack, Stripe, etc.      │
      │  TOKENS / PASSWORDS  tokens, passwords, credentials         │
      │  PRIVATE KEYS        SSH, RSA, EC, PEM blocks              │
      │  VERIFIED SECRETS    TruffleHog verification support       │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:       "gitleaks" | "trufflehog"
        target:     repo path, git URL, or filesystem path
        scan_scope: "repo" | "git" | "history" | "filesystem"
        args:       raw tool args — agent decides

    Examples:
        secret_scan("gitleaks", "/path/to/repo", "repo", [])
        secret_scan("gitleaks", "/path/to/repo", "history", ["--log-opts=--all"])
        secret_scan("trufflehog", "https://github.com/org/repo.git", "git", [])
        secret_scan("trufflehog", "/tmp/project", "filesystem", [])
    """

    start = time.time()

    try:
        req = SecretScanRequest(tool=tool, target=target, scan_scope=scan_scope, args=args)
    except Exception as e:
        return SecretScanResult(
            success=False,
            tool=tool,
            target=target,
            scan_scope=scan_scope,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if req.tool == "gitleaks":
        if req.scan_scope in {"repo", "history", "git"}:
            cmd = ["gitleaks", "detect", "--source", req.target, "--report-format", "json"]
            if req.scan_scope == "history":
                # gitleaks detect already inspects git history for git repos
                pass
        elif req.scan_scope == "filesystem":
            cmd = ["gitleaks", "dir", req.target, "--report-format", "json"]
        else:
            return SecretScanResult(
                success=False,
                tool=tool,
                target=target,
                scan_scope=scan_scope,
                command="",
                error=f"Unsupported gitleaks scope: {scan_scope}",
            ).model_dump()

        cmd.extend(list(req.args))

    elif req.tool == "trufflehog":
        if req.scan_scope in {"repo", "git", "history"}:
            cmd = ["trufflehog", "git", req.target, "--json"]
        elif req.scan_scope == "filesystem":
            cmd = ["trufflehog", "filesystem", req.target, "--json"]
        else:
            return SecretScanResult(
                success=False,
                tool=tool,
                target=target,
                scan_scope=scan_scope,
                command="",
                error=f"Unsupported trufflehog scope: {scan_scope}",
            ).model_dump()

        cmd.extend(list(req.args))

    else:
        return SecretScanResult(
            success=False,
            tool=tool,
            target=target,
            scan_scope=scan_scope,
            command="",
            error=f"Unknown tool: {tool}",
        ).model_dump()

    command_str = " ".join(cmd)

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)

    # Some secret scanners return non-zero when findings exist
    # so do not treat rc != 0 as immediate failure if parse succeeds.

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    findings: list[SecretFinding] = []

    if req.tool == "gitleaks":
        findings = parse_gitleaks_json(stdout)
    elif req.tool == "trufflehog":
        findings = parse_trufflehog_json(stdout)

    # fill fallback secret types
    for f in findings:
        if not f.secret_type:
            f.secret_type = fallback_secret_type(f.match, f.title)

    # summaries
    severity_summary: dict[str, int] = {}
    secret_type_summary: dict[str, int] = {}
    verified_findings = 0

    for f in findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1
        st = f.secret_type or "unknown"
        secret_type_summary[st] = secret_type_summary.get(st, 0) + 1
        if f.verified is True:
            verified_findings += 1

    return SecretScanResult(
        success=(rc == 0 or len(findings) > 0),
        tool=req.tool,
        target=req.target,
        scan_scope=req.scan_scope,
        command=command_str,
        total_findings=len(findings),
        verified_findings=verified_findings,
        severity_summary=severity_summary,
        secret_type_summary=secret_type_summary,
        findings=findings,
        raw_output=(stdout or stderr)[:12000],
        error=stderr[:4000] if rc != 0 and not findings else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

SECRET_SCAN_TOOL_DEFINITION = {
    "name": "secret_scan",
    "description": (
        "Scan repositories, git history, or filesystems for leaked secrets such as API keys, "
        "tokens, passwords, private keys, and cloud credentials using Gitleaks or TruffleHog."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["gitleaks", "trufflehog"],
                "description": (
                    "gitleaks = repo/filesystem secret scanning | "
                    "trufflehog = git/filesystem scanning with verification support"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Repository path, git URL, or filesystem path. "
                    "Examples: '/src/repo', 'https://github.com/org/repo.git', '/tmp/project'"
                )
            },
            "scan_scope": {
                "type": "string",
                "enum": ["repo", "git", "history", "filesystem"],
                "default": "repo",
                "description": (
                    "repo/history/git = scan git repository/history | "
                    "filesystem = scan directory contents"
                )
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool args. Examples:\n"
                    "Gitleaks: ['--no-git'] or ['--redact']\n"
                    "TruffleHog: ['--only-verified'] or ['--branch=main']"
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
    # 1. Scan local git repo with gitleaks
    # ─────────────────────────────
    r = secret_scan(
        tool="gitleaks",
        target="/path/to/repo",
        scan_scope="repo",
        args=[]
    )
    print("=== GITLEAKS REPO ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Scan repo history
    # ─────────────────────────────
    r = secret_scan(
        tool="gitleaks",
        target="/path/to/repo",
        scan_scope="history",
        args=["--redact"]
    )
    print("=== GITLEAKS HISTORY ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Scan remote git repo with trufflehog
    # ─────────────────────────────
    r = secret_scan(
        tool="trufflehog",
        target="https://github.com/org/repo.git",
        scan_scope="git",
        args=[]
    )
    print("=== TRUFFLEHOG GIT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Filesystem scan
    # ─────────────────────────────
    r = secret_scan(
        tool="trufflehog",
        target="/tmp/project",
        scan_scope="filesystem",
        args=["--only-verified"]
    )
    print("=== TRUFFLEHOG FILESYSTEM ===")
    print(json.dumps(r, indent=2))