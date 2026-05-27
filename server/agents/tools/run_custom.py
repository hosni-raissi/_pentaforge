#/+
"""
Safe Command Executor — Open security tool execution with hardened injection prevention.
No command whitelist: any tool can run. Destructive system commands remain blocked.
"""

import contextvars
import asyncio
import inspect
import os
import subprocess
import json
import re
import shlex
import time
import uuid
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from server.agents.executer.run_custom_guard import (
    append_audit_record,
    collect_artifact_paths,
    current_execution_context,
    detect_recon_role_violation,
    detect_scope_violation,
)
from server.agents.executer.sandbox import (
    SandboxExecutionPolicy,
    build_sandbox_env,
    build_sandbox_preexec,
    get_project_workspace_dir,
    get_sandbox_root,
    get_sandbox_share_dir,
    resolve_sandbox_cwd,
)
from server.agents.executer.sandbox_client import (
    execute_run_custom_remotely,
    sandbox_remote_enabled,
)
from server.agents.executer.tool_safety import get_run_custom_command_profile
from server.agents.tool_output_parsers import summarize_tool_output


# ══════════════════════════════════════════════════════════════
# 1. POLICY — Block only destructive/system-modifying commands
# ══════════════════════════════════════════════════════════════

# Hard-blocked: system-destructive or privilege-escalation commands only
BLOCKED_COMMANDS = {
    # Filesystem destruction
    "rm", "shred", "dd", "mkfs", "fdisk", "parted", "wipefs",
    # System control
    "shutdown", "reboot", "halt", "poweroff", "init",
    # Privilege / identity modification
    "chmod", "chown", "chgrp", "usermod", "useradd", "userdel",
    "groupadd", "groupdel", "passwd", "su", "newgrp",
    # Network firewall mutation
    "iptables", "ip6tables", "ufw", "nft", "firewall-cmd",
    # Disk / mount manipulation
    "mount", "umount", "losetup",
    # Scheduled task modification
    "crontab", "at", "batch",
    # Exfiltration / lateral movement helpers
    "tee", "scp", "rsync", "socat",
    # File mutation shortcuts
    "mv", "cp", "install",
}

# Shell metacharacters that enable injection / chaining
BLOCKED_TOKENS = {
    ";", "&&", "||", "|", "`", "$(", ">", ">>", "<", "<<",
    "\n", "\r",
}

# Argument-level patterns always rejected regardless of command
BLOCKED_ARG_PATTERNS = [
    r"^/dev/sd",          # raw block device writes
    r"^/dev/nvme",
    r"^-rf$", r"^-fr$",   # recursive force flags
    r"^--delete$",
    r"^--remove$",
    r"^--exec$",          # find --exec style escapes
]

# curl / wget write flags — blocked even though the binary itself is allowed
_CURL_BLOCKED_FLAGS  = {"-T", "--upload-file", "-F", "--form",
                        "--config",                          # could load arbitrary config
                        "-o", "--output"}                   # file write
_WGET_BLOCKED_FLAGS  = {"--post-file",
                        "--method", "--body-file",
                        "-O",                               # file write (use -O - to stdout)
                        "-P", "--directory-prefix",          # writes into chosen directory
                        "-r", "--recursive", "-m", "--mirror",
                        "-p", "--page-requisites",
                        "-k", "--convert-links",
                        "-E", "--adjust-extension",
                        "-K", "--backup-converted",
                        "--no-parent"}                       # mirroring/page save workflows

_RUN_CUSTOM_URL_VALUE_FLAGS = {
    "-u",
    "--url",
    "--target",
    "--uri",
    "-t",
}
_RUN_CUSTOM_HOST_VALUE_FLAGS = {
    "-h",
    "--host",
    "--hostname",
    "--connect",
    "-connect",
    "--server",
    "--domain",
}
_RUN_CUSTOM_DATA_VALUE_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-H",
    "--header",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-A",
    "--user-agent",
}


def _in_container_runtime() -> bool:
    flag = str(os.getenv("PENTAFORGE_CONTAINER_RUNTIME", "")).strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True
    return os.path.exists("/.dockerenv")


def _rewrite_loopback_target_value(value: str) -> str:
    raw = str(value or "").strip()
    if not raw or not _in_container_runtime():
        return raw
    if "://" in raw:
        parsed = urlsplit(raw)
        host = str(parsed.hostname or "").strip().lower()
        if host not in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            return raw
        port = f":{parsed.port}" if parsed.port is not None else ""
        netloc = f"host.docker.internal{port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    lowered = raw.lower()
    if lowered in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return "host.docker.internal"
    for prefix in ("localhost:", "127.0.0.1:", "0.0.0.0:"):
        if lowered.startswith(prefix):
            return f"host.docker.internal:{raw.split(':', 1)[1]}"
    return raw


def _rewrite_runtime_loopback_args(command: str, args: list[str]) -> list[str]:
    if not _in_container_runtime():
        return list(args)
    rewritten: list[str] = []
    skip_rewrite_for_next = False
    rewrite_next = False
    for raw_arg in args:
        arg = str(raw_arg or "")
        if rewrite_next:
            rewritten.append(_rewrite_loopback_target_value(arg))
            rewrite_next = False
            continue
        if skip_rewrite_for_next:
            rewritten.append(arg)
            skip_rewrite_for_next = False
            continue
        if arg in _RUN_CUSTOM_DATA_VALUE_FLAGS:
            rewritten.append(arg)
            skip_rewrite_for_next = True
            continue
        if arg in (_RUN_CUSTOM_URL_VALUE_FLAGS | _RUN_CUSTOM_HOST_VALUE_FLAGS):
            rewritten.append(arg)
            rewrite_next = True
            continue
        if arg.startswith(("http://", "https://", "ws://", "wss://")):
            rewritten.append(_rewrite_loopback_target_value(arg))
            continue
        rewritten.append(arg)
    return rewritten

def _arg_contains_blocked_shell_token(arg: str) -> str | None:
    text = str(arg or "")
    stripped = text.strip()
    if not stripped:
        return None

    for tok in ("\n", "\r"):
        if tok in text:
            return tok

    # Standalone shell operators are never allowed.
    for tok in (";", "&&", "||", "|", "`", "$(", ">", ">>", "<", "<<"):
        if stripped == tok:
            return tok

    # Reject obvious shell chaining, but allow regex alternation or literals inside a normal arg.
    shell_chain_patterns = (
        ("&&", r"(?:^|\s)&&(?=\s|$)"),
        ("||", r"(?:^|\s)\|\|(?=\s|$)"),
        ("|", r"(?:^|\s)\|(?=\s|$)"),
        (";", r";(?=\s|$)"),
        ("`", r"`"),
        ("$(", r"\$\("),
        (">>", r"(?:^|\s)>>(?=\s|$)"),
        (">", r"(?:^|\s)>(?=\s|$)"),
        ("<<", r"(?:^|\s)<<(?=\s|$)"),
        ("<", r"(?:^|\s)<(?=\s|$)"),
    )
    for tok, pattern in shell_chain_patterns:
        if re.search(pattern, text):
            return tok
    return None

# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class RunCustomRequest(BaseModel):
    command: str
    args: list[str] = []
    reason: str
    timeout: int = Field(default=300, ge=5, le=600)
    env: dict[str, str] = {}          # optional extra env vars (e.g. GOPATH, PYTHONPATH)
    cwd: Optional[str] = None         # working directory override

    @field_validator("args", mode="before")
    @classmethod
    def normalize_args(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list):
            return []
        
        import shlex
        normalized: list[str] = []
        for item in v:
            raw = str(item).strip()
            if not raw:
                continue
            # If an argument contains spaces and looks like multiple flags/URLs, split it.
            # This handles cases where the LLM puts " -u http://target -w wordlist" in a single arg string.
            if " " in raw and raw.startswith(("-", "http://", "https://", "ftp://")):
                try:
                    expanded = [part.strip() for part in shlex.split(raw) if str(part).strip()]
                    if expanded:
                        normalized.extend(expanded)
                        continue
                except ValueError:
                    pass
            normalized.append(raw)
        return normalized

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 8:
            raise ValueError("Reason must be at least 8 characters")
        return v

    @model_validator(mode="after")
    def validate_request(self) -> "RunCustomRequest":
        cmd = self.command.strip()
        if not cmd:
            raise ValueError("Command cannot be empty")
        
        # No path traversal in the binary name itself
        if "/" in cmd or "\\" in cmd:
            raise ValueError(
                "Specify the binary name only (e.g. 'nmap'), not a full path. "
                "Use cwd to set the working directory."
            )
        lowered_cmd = cmd.lower()
        if lowered_cmd in BLOCKED_COMMANDS:
            raise ValueError(
                f"Command '{cmd}' is blocked — it performs destructive system modifications."
            )
            
        # Special handling for curl/wget: they are allowed to send payloads containing shell tokens
        # to remote targets. Since we use shell=False, these tokens are safe on the local machine.
        allow_shell_tokens = lowered_cmd in {"curl", "wget"}

        for arg in self.args:
            if not isinstance(arg, str):
                raise ValueError("All args must be strings")
            
            if not allow_shell_tokens:
                tok = _arg_contains_blocked_shell_token(arg)
                if tok is not None:
                    raise ValueError(f"Dangerous shell token '{tok}' detected in arg: {repr(arg)}")
            
            for pat in BLOCKED_ARG_PATTERNS:
                if re.search(pat, arg):
                    raise ValueError(f"Blocked argument pattern matched in: {repr(arg)}")
        
        return self


class CustomCommandLog(BaseModel):
    command: str
    args: list[str]
    reason: str
    timestamp: float
    full_command: str


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
    execution_cwd: Optional[str] = None
    error: Optional[str] = None
    output_parser: Optional[str] = None
    observations: list[str] | None = None
    parsed_findings: list[dict[str, Any]] | None = None


# ══════════════════════════════════════════════════════════════
# 3. POLICY CHECKS (per-tool write-flag blocks)
# ══════════════════════════════════════════════════════════════

def validate_command_policy(command: str, args: list[str]) -> Optional[str]:
    """
    Returns an error string if the command+args violate policy, else None.
    No whitelist — only targeted blocks for write/destructive operations.
    """
    effective_cmd = str(command).strip().lower()
    effective_args = list(args)

    # Recursive check for sudo-wrapped commands
    if effective_cmd == "sudo" and effective_args:
        # Find the actual binary being called (skip sudo flags)
        inner_cmd = ""
        inner_args = []
        for i, arg in enumerate(effective_args):
            if not arg.startswith("-"):
                inner_cmd = arg
                inner_args = effective_args[i+1:]
                break
        if inner_cmd:
            # Check the inner command against the blocklist
            inner_error = validate_command_policy(inner_cmd, inner_args)
            if inner_error:
                return f"Privileged bypass detected: {inner_error}"

    if effective_cmd in BLOCKED_COMMANDS:
        return f"Blocked command: {effective_cmd}"

    # Per-tool write-flag enforcement
    arg_set = set(args)

    if command == "curl":
        # Block write flags except when pointing to a safe sink (stdout / dev/null)
        for i, arg in enumerate(args):
            if arg in {"-o", "--output"}:
                val = str(args[i+1]).strip() if i+1 < len(args) else ""
                if not val or _looks_like_file_sink(val):
                    return f"curl flag '{arg}' is blocked unless outputting to stdout or /dev/null"
            elif arg in (_CURL_BLOCKED_FLAGS - {"-o", "--output"}):
                 return f"curl flag '{arg}' is blocked (write/upload operations)"

    if command == "wget":
        bad = arg_set & _WGET_BLOCKED_FLAGS
        if bad:
            return f"wget flags {bad} are blocked (write/upload operations). Use '-O -' to stream to stdout."

    # Prevent find -exec / -execdir shell escapes
    if command == "find":
        if "-exec" in args or "-execdir" in args or "-delete" in args:
            return "find -exec / -execdir / -delete are blocked (command execution / deletion)"

    # Prevent git operations that modify the repo or contact remotes
    if command == "git":
        write_subcmds = {
            "push", "pull", "fetch", "commit", "merge",
            "rebase", "reset", "checkout", "switch", "restore",
            "stash", "tag", "apply", "am", "cherry-pick",
        }
        if args and args[0] in write_subcmds:
            return f"git subcommand '{args[0]}' is blocked (modifies repo or contacts remotes)"

    # Prevent docker run / exec / build / push / rm
    if command == "docker":
        write_subcmds = {"run", "exec", "build", "push", "rm", "rmi", "kill", "stop", "start", "restart"}
        if args and args[0] in write_subcmds:
            return f"docker subcommand '{args[0]}' is blocked (modifies containers/images)"

    # Prevent kubectl write operations
    if command == "kubectl":
        write_subcmds = {
            "apply", "create", "delete", "edit", "patch", "replace",
            "rollout", "scale", "set", "label", "annotate", "cordon",
            "drain", "taint", "exec", "cp", "port-forward",
        }
        if args and args[0] in write_subcmds:
            return f"kubectl subcommand '{args[0]}' is blocked (modifies cluster state)"

    return None


def _prepare_git_clone_destination(cmd: list[str], execution_cwd: str) -> None:
    if len(cmd) < 3:
        return
    if str(cmd[0]).strip().lower() != "git" or str(cmd[1]).strip().lower() != "clone":
        return

    destination: str | None = None
    positional: list[str] = []
    skip_next = False
    for token in cmd[2:]:
        value = str(token or "").strip()
        if not value:
            continue
        if skip_next:
            skip_next = False
            continue
        if value in {"-b", "--branch", "--depth", "--origin", "-c", "--config", "--reference"}:
            skip_next = True
            continue
        if value.startswith("-"):
            continue
        positional.append(value)

    if len(positional) >= 2:
        destination = positional[-1]
    elif positional:
        parsed = urlsplit(positional[0])
        repo_name = Path(parsed.path.rstrip("/")).name
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        if repo_name:
            destination = repo_name

    if not destination:
        return

    root = get_sandbox_root().resolve()
    destination_path = Path(destination).expanduser()
    if destination_path.is_absolute():
        try:
            resolved = destination_path.resolve()
        except Exception:
            return
    else:
        resolved = (Path(execution_cwd).resolve() / destination_path).resolve()

    try:
        resolved.relative_to(root)
    except ValueError:
        return

    resolved.parent.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# 3a. OUTPUT FILE FLAG STRIPPER
# ══════════════════════════════════════════════════════════════

_SHORT_OUTPUT_FLAGS_BY_COMMAND: dict[str, set[str]] = {
    "curl": {"-o"},
    "wget": {"-o", "-O"},
    "ffuf": {"-o", "-od"},
    "nuclei": {"-o", "-report-db"},
    "hydra": {"-o", "-O"},
    "nikto": {"-output"},
}
_COMBINED_OUTPUT_PREFIXES_BY_COMMAND: dict[str, tuple[str, ...]] = {
    "nmap": ("-oA", "-oN", "-oX", "-oG"),
}
_LONG_OUTPUT_FLAGS = {
    "--output",
    "--output-file",
    "--out",
    "--outfile",
    "--report",
    "--report-file",
    "--report-dir",
    "--outdir",
    "--jsonfile",
    "--json_out",
    "--log-json",
    "--xml",
    "--xml-output",
    "--save-report",
    "--write-report",
}
_LONG_OUTPUT_FLAG_PREFIXES = tuple(f"{flag}=" for flag in _LONG_OUTPUT_FLAGS)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _safe_tool_output_dir(tool_name: str) -> str:
    try:
        from server.agents.executer.base import _executer_tool_context

        context = _executer_tool_context.get({})
    except Exception:
        context = {}

    base = str(context.get("project_cache_dir", "")).strip() if isinstance(context, dict) else ""
    if base:
        path = Path(base) / "tool_outputs" / tool_name
    else:
        path = _project_root() / "server" / "cache" / "tool_outputs" / tool_name
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _looks_like_file_sink(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered in {"-", "stdout", "/dev/stdout", "/dev/fd/1", "/dev/null"}:
        return False
    if "=" in text and "/" not in text and "\\" not in text:
        left, _, right = text.partition("=")
        if left.strip() and right.strip():
            return False
    if text.startswith("-"):
        return False
    if lowered.startswith(("http://", "https://")):
        return False
    return True


def strip_output_file_flags(command: str, args: list[str]) -> tuple[list[str], list[str]]:
    """
    Remove command-aware output file flags from arguments.

    Only known file-output flags are stripped automatically. Ambiguous flags
    like `ssh -o BatchMode=yes` are preserved.

    Returns: (cleaned_args, stripped_flags)
    """
    normalized_command = str(command or "").strip().lower()
    short_flags = _SHORT_OUTPUT_FLAGS_BY_COMMAND.get(normalized_command, set())
    combined_prefixes = _COMBINED_OUTPUT_PREFIXES_BY_COMMAND.get(normalized_command, ())

    cleaned = []
    stripped = []
    i = 0
    while i < len(args):
        arg = str(args[i] or "").strip()

        if arg in short_flags or arg in _LONG_OUTPUT_FLAGS:
            next_value = str(args[i + 1]).strip() if i + 1 < len(args) else ""
            if next_value and _looks_like_file_sink(next_value):
                stripped.append(arg)
                stripped.append(next_value)
                i += 2
            elif next_value and (not _looks_like_file_sink(next_value) or next_value == "-"):
                # Safe sink (stdout, /dev/null, or explicit '-') - KEEP IT
                cleaned.append(arg)
                cleaned.append(next_value)
                i += 2
            else:
                # Ambiguous or no value - strip the flag to be safe
                stripped.append(arg)
                i += 1
        elif any(arg.startswith(prefix) for prefix in _LONG_OUTPUT_FLAG_PREFIXES):
            stripped.append(arg)
            i += 1
        else:
            matched_combined = False
            for prefix in combined_prefixes:
                if arg == prefix:
                    stripped.append(arg)
                    next_value = str(args[i + 1]).strip() if i + 1 < len(args) else ""
                    if next_value and _looks_like_file_sink(next_value):
                        stripped.append(next_value)
                        i += 2
                    else:
                        i += 1
                    matched_combined = True
                    break
                if arg.startswith(prefix):
                    suffix = arg[len(prefix) :].strip()
                    if _looks_like_file_sink(suffix):
                        stripped.append(arg)
                        i += 1
                        matched_combined = True
                        break
            if matched_combined:
                continue
            cleaned.append(args[i])
            i += 1

    return cleaned, stripped


def redirect_default_tool_outputs(command: str, args: list[str]) -> tuple[list[str], list[str]]:
    """
    Redirect tools with unavoidable default output folders into server/cache.

    Commix creates .output/<target>/ by default in the process cwd. That pollutes
    the project root, so force a cache-local output directory for every run.
    """
    normalized_command = str(command or "").strip().lower()
    if normalized_command != "commix":
        return list(args), []

    cleaned: list[str] = []
    removed: list[str] = []
    i = 0
    while i < len(args):
        arg = str(args[i] or "").strip()
        if arg == "--output-dir":
            removed.append(arg)
            if i + 1 < len(args):
                removed.append(str(args[i + 1]))
                i += 2
            else:
                i += 1
            continue
        if arg.startswith("--output-dir="):
            removed.append(arg)
            i += 1
            continue
        cleaned.append(args[i])
        i += 1

    safe_dir = _safe_tool_output_dir(normalized_command)
    cleaned.extend(["--output-dir", safe_dir])
    return cleaned, removed


def _sandbox_share_wordlists_dir() -> Path:
    return get_sandbox_share_dir() / "wordlists"


def _sandbox_share_seclists_dir() -> Path:
    return get_sandbox_share_dir() / "seclists"


def _sandbox_resource_exact_map() -> dict[str, str]:
    wordlists_dir = _sandbox_share_wordlists_dir()
    seclists_dir = _sandbox_share_seclists_dir()
    return {
        "wordlists": str(wordlists_dir),
        "seclists": str(seclists_dir),
        "server/share/wordlists": str(wordlists_dir),
        "server/share/seclists": str(seclists_dir),
        "/app/server/sandbox/share/wordlists": str(wordlists_dir),
        "/app/server/sandbox/share/seclists": str(seclists_dir),
        "wordlists/dns_fuzz_common.txt": str(wordlists_dir / "dns-fuzz-common.txt"),
        "/usr/share/wordlists/pentaforge/dns-fuzz-common.txt": str(wordlists_dir / "dns-fuzz-common.txt"),
    }


def _sandbox_resource_prefixes() -> tuple[tuple[str, str], ...]:
    wordlists_dir = _sandbox_share_wordlists_dir()
    seclists_dir = _sandbox_share_seclists_dir()
    return (
        ("wordlists/", f"{wordlists_dir}/"),
        ("seclists/", f"{seclists_dir}/"),
        ("share/wordlists/", f"{wordlists_dir}/"),
        ("share/seclists/", f"{seclists_dir}/"),
        ("../share/wordlists/", f"{wordlists_dir}/"),
        ("../share/seclists/", f"{seclists_dir}/"),
        ("server/share/wordlists/", f"{wordlists_dir}/"),
        ("server/share/seclists/", f"{seclists_dir}/"),
        ("/usr/share/wordlists/pentaforge/", f"{wordlists_dir}/"),
        ("/usr/share/seclists/pentaforge/", f"{seclists_dir}/"),
        ("/app/server/sandbox/share/wordlists/", f"{wordlists_dir}/"),
        ("/app/server/sandbox/share/seclists/", f"{seclists_dir}/"),
    )


def resolve_sandbox_resource_args(args: list[str]) -> list[str]:
    """Map friendly sandbox resource paths onto the shared sandbox bundle.

    This lets agents use compact catalog-style references such as
    `wordlists/short.txt` or `seclists/Passwords/...` while the sandbox executes
    against the same `server/sandbox/share` tree in both local and Docker modes.
    """
    exact_map = _sandbox_resource_exact_map()
    prefixes = _sandbox_resource_prefixes()
    resolved: list[str] = []
    for raw_arg in list(args or []):
        arg = str(raw_arg or "").strip()
        if not arg:
            continue
        exact = exact_map.get(arg)
        if exact is not None:
            resolved.append(exact)
            continue
        replaced = arg
        for prefix, target_prefix in prefixes:
            if replaced.startswith(prefix):
                replaced = f"{target_prefix}{replaced[len(prefix):]}"
                break
        resolved.append(replaced)
    return resolved


# ══════════════════════════════════════════════════════════════
# 3c. AUTO-INJECT SAFE TIMEOUT DEFAULTS FOR HTTP TOOLS
# ══════════════════════════════════════════════════════════════

# Default max-time for HTTP tools when the LLM omits a timeout flag.
_HTTP_TOOL_DEFAULT_TIMEOUT = "30"
_HTTP_TOOL_DEFAULT_CONNECT_TIMEOUT = "10"


def _inject_default_timeouts(command: str, args: list[str]) -> list[str]:
    """
    Auto-inject safe timeout flags for HTTP tools when the LLM omits them.

    Prevents curl/wget from hanging for the full subprocess timeout (300s)
    when the remote server is slow or unresponsive.

    Rules:
      - curl: inject  -m 30 --connect-timeout 10  if neither is present
      - wget: inject  -T 30  if not present
    """
    if command == "curl":
        has_max_time = any(
            a in ("-m", "--max-time") or a.startswith("-m") or a.startswith("--max-time=")
            for a in args
        )
        has_connect_timeout = any(
            a == "--connect-timeout" or a.startswith("--connect-timeout=")
            for a in args
        )
        injected = list(args)
        if not has_max_time:
            injected = ["-m", _HTTP_TOOL_DEFAULT_TIMEOUT] + injected
        if not has_connect_timeout:
            injected = ["--connect-timeout", _HTTP_TOOL_DEFAULT_CONNECT_TIMEOUT] + injected
        return injected

    if command == "wget":
        has_timeout = any(
            a in ("-T", "--timeout") or a.startswith("-T") or a.startswith("--timeout=")
            for a in args
        )
        if not has_timeout:
            return ["-T", _HTTP_TOOL_DEFAULT_TIMEOUT] + list(args)

    return args


# ══════════════════════════════════════════════════════════════
# 3b. PASSWORD REQUEST HANDLING
# ══════════════════════════════════════════════════════════════

def _command_needs_password(command: str, args: list[str]) -> tuple[bool, str]:
    """
    Detect if command needs password input.

    Returns: (needs_password, tool_name)
    """
    cmd_lower = str(command or "").lower().strip()
    password_commands = {
        "ssh": "SSH authentication",
        "sshpass": "SSH with password",
        "ssh-keyscan": "SSH key scanning",
        "sudo": "Privilege escalation",
        "mysql": "MySQL authentication",
        "psql": "PostgreSQL authentication",
        "sqlite3": "SQLite access",
        "ftp": "FTP login",
    }

    if cmd_lower in password_commands:
        return True, password_commands[cmd_lower]

    return False, ""


def _request_password_via_callback(
    command: str,
    tool_name: str,
    call_id: str,
) -> Optional[str]:
    """Request password from callback if available."""
    try:
        # Import here to avoid circular imports
        from server.agents.executer.base import _executer_callback_context

        callback = _executer_callback_context.get()
        if callback is None:
            return None

        # Check if callback has request_password method
        if not hasattr(callback, "request_password"):
            return None

        prompt = f"{command} password: "
        reason = f"Execute: {command}"
        # Use thread-safe version if available, otherwise fallback to async run
        if hasattr(callback, "request_password_threadsafe"):
            return callback.request_password_threadsafe(
                prompt=prompt,
                reason=reason,
                call_id=call_id,
            )

        password = callback.request_password(
            prompt=prompt,
            reason=reason,
            call_id=call_id,
        )
        if inspect.isawaitable(password):
            try:
                password = asyncio.run(password)
            except RuntimeError:
                return None
        return password
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# 4. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(
    cmd: list[str],
    timeout: int = 300,
    extra_env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
    password: Optional[str] = None,
) -> tuple[str, str, int]:
    """
    Execute command safely, optionally with password input.

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        extra_env: Extra environment variables
        cwd: Working directory
        password: Password to send via stdin (for ssh, sudo, etc.)
    """
    env = build_sandbox_env(extra_env)
    execution_cwd = resolve_sandbox_cwd(cwd)
    preexec_fn = build_sandbox_preexec(
        SandboxExecutionPolicy(
            cpu_seconds=max(10, min(int(timeout), 180)),
        )
    )

    try:
        _prepare_git_clone_destination(cmd, execution_cwd)
        proc = subprocess.run(
            cmd,
            input=password if password else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,       # CRITICAL: never use shell=True
            env=env,
            cwd=execution_cwd,
            preexec_fn=preexec_fn,
            start_new_session=True,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not found — is it installed and on PATH?", 127
    except PermissionError:
        return "", f"Permission denied running '{cmd[0]}'", 126
    except Exception as exc:
        return "", str(exc), -1


def _effective_command_cwd() -> str:
    context = current_execution_context()
    project_id = str(context.get("project_id", "")).strip() if isinstance(context, dict) else ""
    if project_id:
        return str(get_project_workspace_dir(project_id))
    return str(get_sandbox_root())


def _sandbox_service_local_execution_allowed() -> bool:
    return str(os.getenv("PENTAFORGE_SANDBOX_SERVICE", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def run_custom(
    command: str,
    reason: str,
    args: Optional[list[str]] = None,
    timeout: int = 300,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> dict:
    """
    Run any security/diagnostic tool with injection-safe subprocess execution.

    Policy (no whitelist — open tool execution):
    ┌──────────────────────────────────────────────────────────────┐
    │  ANY BINARY ALLOWED          no command whitelist            │
    │  DESTRUCTIVE CMDS BLOCKED    rm, dd, chmod, shutdown, etc.  │
    │  SHELL INJECTION PREVENTED   shell=False + token validation  │
    │  WRITE FLAGS BLOCKED         per-tool (curl -o, git push…)  │
    │  REASON REQUIRED             every call must be explained    │
    │  AUDIT LOGGED                command + args + reason         │
    └──────────────────────────────────────────────────────────────┘

    Args:
        command:  Binary name (no path). E.g. 'nmap', 'sqlmap', 'ffuf', 'nikto'.
        reason:   Why this command is needed (min 8 chars).
        args:     Argument list — no shell metacharacters.
        timeout:  Execution timeout in seconds (5–300).
        env:      Extra environment variables.
        cwd:      Ignored for safety. Commands always run from server/sandbox.

    Returns:
        Structured dict with stdout, stderr, return_code, execution_time.
    """
    start = time.time()
    args = list(args or [])

    # ── Validate ──────────────────────────────────────────────
    try:
        req = RunCustomRequest(
            command=command,
            args=args,
            reason=reason,
            timeout=timeout,
            env=env or {},
            cwd=cwd,
        )
    except Exception as exc:
        return RunCustomResult(
            success=False,
            command=command,
            args=args,
            reason=reason,
            full_command="",
            error=f"Validation error: {exc}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # ── Strip output file flags ────────────────────────────────
    # Remove -o, --output, --output-file and similar write flags
    # These are automatically stripped before execution
    cleaned_args, stripped_flags = strip_output_file_flags(req.command, req.args)
    if stripped_flags:
        # Update args with cleaned version (no -o flags)
        req.args = cleaned_args
        # Note: we silently remove them, as instructed in prompts

    # ── Redirect default tool output folders ──────────────────
    redirected_args, _redirected_flags = redirect_default_tool_outputs(req.command, req.args)
    req.args = redirected_args
    req.args = resolve_sandbox_resource_args(req.args)
    req.args = _inject_default_timeouts(req.command, req.args)
    command_profile = get_run_custom_command_profile(req.command, role=str(current_execution_context().get("role", "")))

    role_violation = detect_recon_role_violation(
        req.command,
        role=str(current_execution_context().get("role", "")),
    )
    if role_violation:
        append_audit_record(
            command=req.command,
            args=req.args,
            full_command=" ".join(shlex.quote(x) for x in [req.command, *req.args]),
            reason=req.reason,
            status="blocked",
            execution_cwd=_effective_command_cwd(),
            return_code=-1,
            execution_time=round(time.time() - start, 2),
            error=role_violation,
            stripped_args=stripped_flags,
            scope_target=str(current_execution_context().get("target_url", "")).strip(),
            profile=command_profile,
        )
        return RunCustomResult(
            success=False,
            command=req.command,
            args=req.args,
            reason=req.reason,
            full_command="",
            error=role_violation,
            return_code=-1,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    scope_violation = detect_scope_violation(
        req.command,
        req.args,
        active_target=str(current_execution_context().get("target_url", "")).strip(),
    )
    if scope_violation:
        append_audit_record(
            command=req.command,
            args=req.args,
            full_command=" ".join(shlex.quote(x) for x in [req.command, *req.args]),
            reason=req.reason,
            status="blocked",
            execution_cwd=_effective_command_cwd(),
            return_code=-1,
            execution_time=round(time.time() - start, 2),
            error=scope_violation,
            stripped_args=stripped_flags,
            scope_target=str(current_execution_context().get("target_url", "")).strip(),
            profile=command_profile,
        )
        return RunCustomResult(
            success=False,
            command=req.command,
            args=req.args,
            reason=req.reason,
            full_command="",
            error=f"Target scope violation: {scope_violation}",
            return_code=-1,
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # ── Policy check ──────────────────────────────────────────
    policy_error = validate_command_policy(req.command, req.args)
    if policy_error:
        append_audit_record(
            command=req.command,
            args=req.args,
            full_command=" ".join(shlex.quote(x) for x in [req.command, *req.args]),
            reason=req.reason,
            status="blocked",
            execution_cwd=_effective_command_cwd(),
            return_code=-1,
            execution_time=round(time.time() - start, 2),
            error=policy_error,
            stripped_args=stripped_flags,
            scope_target=str(current_execution_context().get("target_url", "")).strip(),
            profile=command_profile,
        )
        return RunCustomResult(
            success=False,
            command=req.command,
            args=req.args,
            reason=req.reason,
            full_command="",
            error=f"Policy violation: {policy_error}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    runtime_args = _rewrite_runtime_loopback_args(req.command, req.args)

    # ── Build & audit-log command ─────────────────────────────
    cmd = [req.command] + runtime_args
    full_command = " ".join(shlex.quote(x) for x in cmd)

    # ── Password handling ──────────────────────────────────────
    password: Optional[str] = None
    needs_password, password_reason = _command_needs_password(req.command, req.args)
    if needs_password:
        call_id = str(uuid.uuid4())
        password = _request_password_via_callback(
            command=req.command,
            tool_name=password_reason,
            call_id=call_id,
        )
        if password is None:
            # Password was denied or callback not available
            return RunCustomResult(
                success=False,
                command=req.command,
                args=req.args,
                reason=req.reason,
                full_command=full_command,
                error=f"Password required for {req.command} but not provided",
                return_code=-1,
                execution_time=round(time.time() - start, 2),
                logged=True,
            ).model_dump()

    # ── Execute ───────────────────────────────────────────────
    execution_cwd = _effective_command_cwd()
    if sandbox_remote_enabled():
        remote_result = execute_run_custom_remotely(
            command=req.command,
            args=req.args,
            timeout=req.timeout,
            env=req.env or {},
            cwd=execution_cwd,
            password=password,
        )
        stdout = str(remote_result.get("stdout") or "")
        stderr = str(remote_result.get("stderr") or "")
        rc = int(remote_result.get("return_code", -1))
        execution_cwd = str(remote_result.get("execution_cwd") or execution_cwd)
        artifact_paths = (
            list(remote_result.get("artifact_paths", []))
            if isinstance(remote_result.get("artifact_paths"), list)
            else collect_artifact_paths(req.args, execution_cwd=execution_cwd)
        )
    elif not _sandbox_service_local_execution_allowed():
        error = (
            "Sandbox executor unavailable: run_custom may only execute through the tool sandbox. "
            "Configure SANDBOX_EXECUTOR_URL for backend-side callers."
        )
        append_audit_record(
            command=req.command,
            args=req.args,
            full_command=full_command,
            reason=req.reason,
            status="blocked",
            execution_cwd=execution_cwd,
            return_code=-1,
            execution_time=round(time.time() - start, 2),
            error=error,
            stripped_args=stripped_flags,
            scope_target=str(current_execution_context().get("target_url", "")).strip(),
            profile=command_profile,
        )
        return RunCustomResult(
            success=False,
            command=req.command,
            args=req.args,
            reason=req.reason,
            full_command=full_command,
            return_code=-1,
            execution_time=round(time.time() - start, 2),
            logged=True,
            execution_cwd=execution_cwd,
            error=error,
        ).model_dump()
    else:
        stdout, stderr, rc = safe_execute(
            cmd,
            timeout=req.timeout,
            extra_env=req.env or None,
            cwd=execution_cwd,
            password=password,
        )
        artifact_paths = collect_artifact_paths(runtime_args, execution_cwd=execution_cwd)
    append_audit_record(
        command=req.command,
        args=req.args,
        full_command=full_command,
        reason=req.reason,
        status="completed" if rc == 0 else "failed",
        execution_cwd=execution_cwd,
        return_code=rc,
        execution_time=round(time.time() - start, 2),
        error=None if rc == 0 else stderr[:5000] if stderr else f"Exited with code {rc}",
        artifact_paths=artifact_paths,
        stripped_args=stripped_flags,
        scope_target=str(current_execution_context().get("target_url", "")).strip(),
        profile=command_profile,
    )

    structured_output = summarize_tool_output(
        {
            "command": req.command,
            "stdout": stdout[:100000] if stdout else "",
            "stderr": stderr[:10000] if stderr else "",
            "error": None if rc == 0 else f"Exited with code {rc}",
        }
    )

    return RunCustomResult(
        success=(rc == 0),
        command=req.command,
        args=req.args,
        reason=req.reason,
        full_command=full_command,
        stdout=stdout[:100000] if stdout else None,
        stderr=stderr[:10000]  if stderr else None,
        return_code=rc,
        execution_time=round(time.time() - start, 2),
        logged=True,
        execution_cwd=execution_cwd,
        error=None if rc == 0 else f"Exited with code {rc}",
        output_parser=str(structured_output.get("output_parser", "") or "").strip() or None,
        observations=structured_output.get("observations") or None,
        parsed_findings=structured_output.get("parsed_findings") or None,
    ).model_dump()



# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (LLM / agent integration)
# ══════════════════════════════════════════════════════════════

RUN_CUSTOM_TOOL_DEFINITION = {
    "name": "run_custom",
        "description": (
            "Execute any installed security or diagnostic tool safely. "
            "No command whitelist — nmap, sqlmap, ffuf, nikto, gobuster, hydra, metasploit, "
            "nuclei, trivy, semgrep, wfuzz, and others are all permitted. "
            "Destructive system commands (rm, chmod, shutdown…) and shell injection are blocked. "
            "Every call requires a reason and is audit-logged. "
            "Commands always execute from server/sandbox and may use compact bundled resource paths "
            "like wordlists/short.txt or seclists/Passwords/... which are resolved inside the sandbox."
        ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": (
                    "Binary name only — no full path. Examples: nmap, sqlmap, ffuf, nikto, "
                    "gobuster, hydra, nuclei, trivy, semgrep, openssl, curl, wget, git, "
                    "docker, kubectl, ps, ss, find, grep, strings, readelf."
                ),
            },
            "reason": {
                "type": "string",
                "description": "Required explanation for why this command is needed.",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Argument list — no shell metacharacters (; | & > < ` $()). Examples:\n"
                    "nmap:     ['-sV', '-p', '1-65535', '10.0.0.1']\n"
                    "sqlmap:   ['-u', 'http://target/page?id=1', '--dbs']\n"
                    "ffuf:     ['-u', 'http://target/FUZZ', '-w', 'wordlists/short.txt']\n"
                    "nuclei:   ['-u', 'http://target', '-t', 'cves/']\n"
                    "openssl:  ['s_client', '-connect', 'target:443']\n"
                    "curl:     ['-I', '-s', 'https://target.com']"
                ),
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Execution timeout in seconds (5–600).",
            },
            "env": {
                "type": "object",
                "description": "Optional extra environment variables (e.g. {'GOPATH': '/opt/go'}).",
            },
            "cwd": {
                "type": "string",
                "description": "Ignored for safety. Commands always execute from server/sandbox root.",
            },
        },
        "required": ["command", "reason"],
    },
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    examples = [
        # ── Network scanning ──────────────────────────────────
        dict(
            command="nmap",
            args=["-sV", "-p", "80,443,8080,8888", "--open", "127.0.0.1"],
            reason="Identify open ports and service versions on localhost",
            timeout=60,
        ),
        # ── Web fuzzing ───────────────────────────────────────
        dict(
            command="curl",
            args=["-I", "-s", "-k", "http://localhost:8888/api"],
            reason="Fetch HTTP headers from the API to inspect security headers",
            timeout=15,
        ),
        # ── SSL / TLS inspection ──────────────────────────────
        dict(
            command="openssl",
            args=["s_client", "-connect", "example.com:443", "-brief"],
            reason="Inspect TLS certificate chain and negotiated cipher suite",
            timeout=15,
        ),
        # ── Binary analysis ───────────────────────────────────
        dict(
            command="strings",
            args=["-n", "8", "/usr/bin/ls"],
            reason="Extract printable strings from binary for static analysis",
            timeout=10,
        ),
        # ── Process / socket enumeration ──────────────────────
        dict(
            command="ss",
            args=["-tlnp"],
            reason="List all TCP listening sockets and associated processes",
            timeout=10,
        ),
        # ── Blocked command demo ───────────────────────────────
        dict(
            command="rm",
            args=["-rf", "/tmp/test"],
            reason="Should be blocked by policy",
            timeout=5,
        ),
        # ── Injection attempt demo ────────────────────────────
        dict(
            command="curl",
            args=["-s", "http://localhost:8888/api; cat /etc/passwd"],
            reason="Should be blocked — injection attempt",
            timeout=5,
        ),
    ]

    for ex in examples:
        print(f"\n{'═'*60}")
        print(f"  CMD: {ex['command']} {' '.join(ex['args'])}")
        print(f"{'═'*60}")
        result = run_custom(**ex)
        print(json.dumps(result, indent=2))
