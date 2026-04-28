"""Assistant-safe wrapper around exploit run_custom."""

from __future__ import annotations

from typing import Any

from server.agents.executer.exploit.tools.all.run_custom import (
    RUN_CUSTOM_TOOL_DEFINITION,
    run_custom as exploit_run_custom,
)

_ASSISTANT_BLOCKED_COMMANDS = {
    "apt",
    "apt-get",
    "apk",
    "brew",
    "bun",
    "cargo",
    "composer",
    "dnf",
    "gem",
    "go",
    "make",
    "mkdir",
    "node",
    "npm",
    "npx",
    "patch",
    "perl",
    "php",
    "pip",
    "pip3",
    "poetry",
    "python",
    "python3",
    "ruby",
    "rustc",
    "sed",
    "sh",
    "tar",
    "touch",
    "unzip",
    "vi",
    "vim",
    "yarn",
    "zsh",
    "bash",
}

_ASSISTANT_BLOCKED_ARG_FLAGS = {
    "-i",
    "--in-place",
    "--write-out",
    "--create-dirs",
    "--output-dir",
}


def _assistant_policy_error(
    command: str,
    args: list[str],
    cwd: str | None,
) -> str | None:
    normalized_command = str(command or "").strip().lower()
    if normalized_command in _ASSISTANT_BLOCKED_COMMANDS:
        return (
            f"Assistant policy blocks '{normalized_command}' because it can modify the local machine, "
            "the project, or execute arbitrary local code."
        )

    normalized_args = [str(arg or "").strip() for arg in args]
    for arg in normalized_args:
        lowered = arg.lower()
        if lowered in _ASSISTANT_BLOCKED_ARG_FLAGS:
            return f"Assistant policy blocks argument '{arg}' because it can write locally."
        if lowered.startswith("--output=") or lowered.startswith("--output-file="):
            return f"Assistant policy blocks argument '{arg}' because it can write locally."
        if lowered.startswith("--directory-prefix=") or lowered.startswith("--output-dir="):
            return f"Assistant policy blocks argument '{arg}' because it can write locally."

    if cwd:
        return "Assistant policy blocks custom working directories. Commands must run without changing local workspace context."

    return None


def run_custom(
    command: str,
    reason: str,
    args: list[str] | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """
    Assistant-safe command execution wrapper.

    Reuses the hardened exploit run_custom implementation but adds stricter
    assistant-specific policy to keep the local machine and workspace read-only.
    """
    normalized_args = [str(item) for item in list(args or [])]
    policy_error = _assistant_policy_error(command, normalized_args, cwd)
    if policy_error:
        return {
            "success": False,
            "command": str(command or "").strip(),
            "args": normalized_args,
            "reason": str(reason or "").strip(),
            "full_command": "",
            "error": f"Policy violation: {policy_error}",
            "return_code": -1,
            "execution_time": 0.0,
            "logged": False,
        }

    return exploit_run_custom(
        command=command,
        reason=reason,
        args=normalized_args,
        timeout=max(5, min(int(timeout or 120), 180)),
        env=env if isinstance(env, dict) else {},
        cwd=None,
    )


ASSISTANT_RUN_CUSTOM_TOOL_DEFINITION = {
    **RUN_CUSTOM_TOOL_DEFINITION,
    "description": (
        "Execute a read-only diagnostic or pentest support command safely for the assistant chat. "
        "Blocks destructive commands, local code interpreters, package managers, repo-mutating workflows, "
        "custom working directories, and local write-style operations."
    ),
}
