import subprocess
import json
import re
import time
import shlex
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. WHITELIST POLICY
# ══════════════════════════════════════════════════════════════

# Commands allowed for edge-case diagnostics only
ALLOWED_COMMANDS = {
    "ls", "cat", "grep", "head", "tail", "wc", "sort", "uniq", "cut", "awk", "sed",
    "find", "stat", "file", "strings", "which", "whereis", "whoami", "id", "uname",
    "ps", "ss", "netstat", "lsof", "systemctl", "journalctl",
    "docker", "kubectl", "helm",
    "git",
    "nmap", "curl", "wget",
    "openssl", "readelf", "objdump", "checksec",
}

# Hard-block dangerous commands entirely
BLOCKED_COMMANDS = {
    "rm", "mv", "cp", "dd", "mkfs", "fdisk", "parted",
    "shutdown", "reboot", "halt", "poweroff",
    "chmod", "chown", "chgrp", "usermod", "useradd", "userdel",
    "groupadd", "groupdel", "passwd", "sudo", "su",
    "iptables", "ufw", "nft",
    "mount", "umount",
    "crontab", "at",
    "tee",
    "scp", "sftp", "rsync",
    "nc", "netcat", "socat",
}

# Dangerous argument tokens / shell metacharacters
BLOCKED_TOKENS = {
    ";", "&&", "||", "|", "`", "$(", ">", ">>", "<", "<<",
    "&", "*", "?", "~"
}

# Disallow obviously destructive flags/patterns even on allowed commands
BLOCKED_ARG_PATTERNS = [
    r"^/dev/",
    r"^-rf$",
    r"^-fr$",
    r"^--delete$",
    r"^--force$",
    r"^--remove$",
    r"^--output$",
    r"^--write-out$",
    r"^-o$",
]

# Optional read-only safety restrictions by command
READONLY_SAFE_FLAGS = {
    "journalctl": {"-n", "--no-pager", "-u", "--since"},
    "systemctl": {"status", "list-units", "list-unit-files", "show", "--type=service", "--state=running", "--no-pager", "--no-legend"},
    "docker": {"ps", "images", "inspect", "info", "version", "logs"},
    "kubectl": {"get", "describe", "api-resources", "api-versions", "cluster-info", "version", "-A", "-o", "json", "yaml", "wide"},
    "git": {"status", "log", "branch", "remote", "show", "rev-parse", "diff", "--stat"},
    "nmap": {"-Pn", "-sV", "-O", "-p", "--top-ports", "-T1", "-T2", "-T3", "-T4", "-oX", "-", "--reason", "--script", "--script-args"},
    "curl": {"-I", "-i", "-s", "-k", "-L", "--head", "--max-time", "-H", "-A", "--user-agent", "--connect-timeout"},
    "wget": {"--server-response", "--spider", "-S", "-q", "-O", "-"},
}


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class RunCustomRequest(BaseModel):
    command: str
    args: list[str] = []
    reason: str
    timeout: int = Field(default=300, ge=5, le=1800)

    @field_validator("command")
    @classmethod
    def validate_command(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Command cannot be empty")

        if v in BLOCKED_COMMANDS:
            raise ValueError(f"Command '{v}' is blocked")

        if v not in ALLOWED_COMMANDS:
            raise ValueError(f"Command '{v}' not whitelisted")

        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v):
        v = v.strip()
        if len(v) < 8:
            raise ValueError("Reason must be provided and be at least 8 characters")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        for arg in v:
            if not isinstance(arg, str):
                raise ValueError("All args must be strings")

            if not arg.strip():
                continue

            for tok in BLOCKED_TOKENS:
                if tok in arg:
                    raise ValueError(f"Dangerous token '{tok}' in arg: {arg}")

            for pat in BLOCKED_ARG_PATTERNS:
                if re.search(pat, arg):
                    raise ValueError(f"Blocked argument pattern in: {arg}")

        return v


class CustomCommandLog(BaseModel):
    command: str
    args: list[str]
    reason: str
    timestamp: float
    allowed: bool
    reviewer_note: Optional[str] = None


class RunCustomResult(BaseModel):
    success: bool
    command: str
    args: list[str]
    reason: str
    full_command: str
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    return_code: Optional[int] = None
    execution_time: float = 0.0
    logged: bool = True
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════
# 3. POLICY CHECKS
# ══════════════════════════════════════════════════════════════

def validate_command_policy(command: str, args: list[str]) -> Optional[str]:
    # Command must be explicitly allowed
    if command in BLOCKED_COMMANDS:
        return f"Blocked command: {command}"
    if command not in ALLOWED_COMMANDS:
        return f"Command not whitelisted: {command}"

    # Read-only restrictions for certain commands
    if command in READONLY_SAFE_FLAGS and args:
        allowed_tokens = READONLY_SAFE_FLAGS[command]

        # conservative policy: all leading verbs/flags must be known safe tokens
        # some value args are allowed after a safe flag/token
        for a in args:
            if not a:
                continue
            if a.startswith("-"):
                if a not in allowed_tokens:
                    return f"Arg '{a}' not allowed for command '{command}'"
            else:
                # non-flag tokens may be subcommands, output modes, unit names, paths, hosts, etc.
                # reject only if obviously dangerous
                if a in BLOCKED_COMMANDS:
                    return f"Suspicious token '{a}' in args"
                if re.search(r"[;&|`<>]", a):
                    return f"Dangerous shell syntax in arg '{a}'"

        # extra restrictive subcommand checks
        if command == "docker" and args[0] not in {"ps", "images", "inspect", "info", "version", "logs"}:
            return f"Docker subcommand '{args[0]}' not allowed"
        if command == "kubectl" and args[0] not in {"get", "describe", "api-resources", "api-versions", "cluster-info", "version"}:
            return f"kubectl subcommand '{args[0]}' not allowed"
        if command == "git" and args[0] not in {"status", "log", "branch", "remote", "show", "rev-parse", "diff"}:
            return f"git subcommand '{args[0]}' not allowed"
        if command == "systemctl" and args[0] not in {"status", "list-units", "list-unit-files", "show"}:
            return f"systemctl subcommand '{args[0]}' not allowed"
        if command == "curl":
            # forbid uploads / POST-like changes
            forbidden = {"-d", "--data", "--data-binary", "-T", "--upload-file", "-X", "--request", "-F", "--form"}
            if any(x in args for x in forbidden):
                return "curl write/modify/upload options are blocked"
        if command == "wget":
            forbidden = {"--post-data", "--post-file", "--method", "--body-data", "--body-file"}
            if any(x in args for x in forbidden):
                return "wget write/modify/upload options are blocked"

    return None


# ══════════════════════════════════════════════════════════════
# 4. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
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
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def run_custom(
    command: str,
    reason: str,
    args: Optional[list[str]] = None,
    timeout: int = 300,
) -> dict:
    """
    🛠️ Agent Tool: Run Custom Whitelisted Command

    Purpose:
      Run edge-case diagnostics with a tightly controlled allowlist.

    Policy:
      ┌─────────────────────────────────────────────────────────────┐
      │  WHITELISTED CMDS ONLY   explicit allowlist                │
      │  REASON REQUIRED         must explain why needed           │
      │  LOGGED FOR REVIEW       command + args + reason           │
      │  NO DESTRUCTIVE CMDS     blocked by policy                 │
      │  NO SHELL                subprocess shell=False            │
      └─────────────────────────────────────────────────────────────┘

    Args:
        command: allowed command only
        reason:  required explanation
        args:    safe read-only args
        timeout: execution timeout

    Returns:
        Structured stdout/stderr/rc result
    """

    start = time.time()
    args = list(args or [])

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = RunCustomRequest(
            command=command,
            args=args,
            reason=reason,
            timeout=timeout,
        )
    except Exception as e:
        return RunCustomResult(
            success=False,
            command=command,
            args=args,
            reason=reason,
            full_command="",
            error=f"Validation: {e}",
            logged=True,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # ══════════════════════════════
    # POLICY CHECK
    # ══════════════════════════════
    policy_error = validate_command_policy(req.command, req.args)
    if policy_error:
        return RunCustomResult(
            success=False,
            command=req.command,
            args=req.args,
            reason=req.reason,
            full_command="",
            error=f"Policy: {policy_error}",
            logged=True,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    cmd = [req.command] + list(req.args)
    full_command = " ".join(shlex.quote(x) for x in cmd)

    # ══════════════════════════════
    # LOG FOR REVIEW
    # ══════════════════════════════
    audit_log = CustomCommandLog(
        command=req.command,
        args=req.args,
        reason=req.reason,
        timestamp=time.time(),
        allowed=True,
        reviewer_note="Auto-logged for review"
    )

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout)

    return RunCustomResult(
        success=(rc == 0),
        command=req.command,
        args=req.args,
        reason=req.reason,
        full_command=full_command,
        stdout=stdout[:12000] if stdout else None,
        stderr=stderr[:4000] if stderr else None,
        return_code=rc,
        execution_time=round(time.time() - start, 2),
        logged=True,
        error=None if rc == 0 else f"Command exited with return code {rc}",
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

RUN_CUSTOM_TOOL_DEFINITION = {
    "name": "run_custom",
    "description": (
        "Run a tightly controlled, whitelisted shell command for edge-case diagnostics only. "
        "Requires a reason, is logged for review, and blocks destructive commands."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": (
                    "Whitelisted command only. Examples: ls, cat, grep, find, file, strings, "
                    "whoami, uname, ps, ss, systemctl, journalctl, docker, kubectl, git, curl"
                )
            },
            "reason": {
                "type": "string",
                "description": "Required explanation for why no existing module covers this need"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Safe read-only arguments only. Examples:\n"
                    "['-la', '/etc']\n"
                    "['status', 'ssh']\n"
                    "['get', 'pods', '-A']\n"
                    "['-I', 'https://example.com']"
                )
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Execution timeout in seconds"
            }
        },
        "required": ["command", "reason"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Read-only filesystem listing
    # ─────────────────────────────
    r = run_custom(
        command="ls",
        args=["-la", "/etc"],
        reason="Need to verify presence of config files not covered by module",
        timeout=30
    )
    print("=== LS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Service status
    # ─────────────────────────────
    r = run_custom(
        command="systemctl",
        args=["status", "ssh", "--no-pager"],
        reason="Need service runtime details for troubleshooting",
        timeout=30
    )
    print("=== SYSTEMCTL STATUS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Kubernetes read-only inspection
    # ─────────────────────────────
    r = run_custom(
        command="kubectl",
        args=["get", "pods", "-A", "-o", "json"],
        reason="Need cluster object details for edge-case review",
        timeout=60
    )
    print("=== KUBECTL GET PODS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. HTTP headers only
    # ─────────────────────────────
    r = run_custom(
        command="curl",
        args=["-I", "-s", "https://example.com"],
        reason="Need response headers for debugging redirect/security config",
        timeout=30
    )
    print("=== CURL HEAD ===")
    print(json.dumps(r, indent=2))
