"""Dedicated sandbox execution service for tool and Python runs."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from server.agents.executer.run_custom_guard import (
    collect_artifact_paths,
    detect_recon_role_violation,
    detect_scope_violation,
)
from server.agents.tools.run_custom import (
    _rewrite_runtime_loopback_args,
    RunCustomRequest,
    _effective_command_cwd,
    redirect_default_tool_outputs,
    resolve_sandbox_resource_args,
    safe_execute,
    validate_command_policy,
)
from server.agents.tools.run_python import run_python as local_run_python

try:
    from server.agents.executer.base import _executer_tool_context as executer_tool_context
except Exception:  # pragma: no cover - defensive import for minimal runtime
    executer_tool_context = None


app = FastAPI(
    title="PentaForge Sandbox Executor",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class SandboxExecutionContext(BaseModel):
    role: str = ""
    target_url: str = ""
    project_id: str = ""
    scan_id: str = ""
    project_cache_dir: str = ""


class RunCustomRemoteRequest(BaseModel):
    command: str
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=300, ge=5, le=600)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    password: str | None = None
    execution_context: SandboxExecutionContext = Field(default_factory=SandboxExecutionContext)


class RunPythonRemoteRequest(BaseModel):
    code: str
    reason: str
    which_file: str = ""
    script_filename: str = ""
    run_parallel: bool = False
    code_two: str = ""
    which_file_two: str = "two"
    install_deps: bool = True
    timeout: int = Field(default=120, ge=5, le=600)
    memory_limit_mb: int = Field(default=512, ge=64, le=4096)
    execution_context: SandboxExecutionContext = Field(default_factory=SandboxExecutionContext)


@contextmanager
def _execution_context_scope(context: SandboxExecutionContext) -> Iterator[None]:
    token = None
    if executer_tool_context is not None:
        payload = context.model_dump()
        token = executer_tool_context.set(payload)
    try:
        yield
    finally:
        if executer_tool_context is not None and token is not None:
            executer_tool_context.reset(token)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/execute/run-custom")
def execute_run_custom(req: RunCustomRemoteRequest) -> dict[str, Any]:
    with _execution_context_scope(req.execution_context):
        try:
            validated = RunCustomRequest(
                command=req.command,
                args=req.args,
                reason="Remote sandbox execution",
                timeout=req.timeout,
                env=req.env,
                cwd=req.cwd,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Validation error: {exc}") from exc

        redirected_args, _redirected_flags = redirect_default_tool_outputs(validated.command, validated.args)
        validated.args = resolve_sandbox_resource_args(redirected_args)

        role_violation = detect_recon_role_violation(validated.command, role=req.execution_context.role)
        if role_violation:
            raise HTTPException(status_code=403, detail=role_violation)

        scope_violation = detect_scope_violation(
            validated.command,
            validated.args,
            active_target=req.execution_context.target_url,
        )
        if scope_violation:
            raise HTTPException(status_code=403, detail=f"Target scope violation: {scope_violation}")

        policy_error = validate_command_policy(validated.command, validated.args)
        if policy_error:
            raise HTTPException(status_code=403, detail=f"Policy violation: {policy_error}")

        runtime_args = _rewrite_runtime_loopback_args(validated.command, validated.args)
        full_command = " ".join([validated.command, *runtime_args]).strip()
        execution_cwd = _effective_command_cwd()
        stdout, stderr, return_code = safe_execute(
            [validated.command, *runtime_args],
            timeout=validated.timeout,
            extra_env=validated.env,
            cwd=execution_cwd,
            password=req.password,
        )
        artifact_paths = collect_artifact_paths(runtime_args, execution_cwd=execution_cwd)
        return {
            "success": return_code == 0,
            "command": validated.command,
            "args": list(runtime_args),
            "full_command": full_command,
            "stdout": stdout[:20000] if stdout else None,
            "stderr": stderr[:5000] if stderr else None,
            "return_code": return_code,
            "execution_cwd": execution_cwd,
            "artifact_paths": artifact_paths,
            "error": None if return_code == 0 else f"Exited with code {return_code}",
        }


@app.post("/execute/run-python")
def execute_run_python(req: RunPythonRemoteRequest) -> dict[str, Any]:
    with _execution_context_scope(req.execution_context):
        return local_run_python(
            code=req.code,
            reason=req.reason,
            which_file=req.which_file,
            script_filename=req.script_filename,
            run_parallel=req.run_parallel,
            code_two=req.code_two,
            which_file_two=req.which_file_two,
            install_deps=req.install_deps,
            timeout=req.timeout,
            memory_limit_mb=req.memory_limit_mb,
        )
