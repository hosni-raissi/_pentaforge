from __future__ import annotations

import json
from pathlib import Path

from server.agents.executer.run_custom_guard import (
    detect_recon_role_violation,
    detect_scope_violation,
)
from server.agents.executer.sandbox import build_sandbox_env, get_sandbox_root, resolve_sandbox_cwd
from server.agents.executer.tool_safety import (
    get_run_custom_command_profile,
    get_tool_safety_profile,
    requires_approval_for_execution,
)
from server.db.projects.store import ProjectsStore


def test_run_custom_command_profiles_separate_scan_and_exploitation() -> None:
    sqlmap = get_run_custom_command_profile("sqlmap", role="recon")
    nmap = get_run_custom_command_profile("nmap", role="recon")

    assert sqlmap.category == "exploitation"
    assert sqlmap.risk_level == "critical"
    assert nmap.category == "active_scan"
    assert nmap.requires_human_approval is True


def test_recon_role_blocks_exploitation_commands() -> None:
    assert detect_recon_role_violation("sqlmap", role="recon") is not None
    assert detect_recon_role_violation("nmap", role="recon") is None


def test_scope_guard_blocks_mismatched_hosts_for_run_custom_targets() -> None:
    active_target = "https://example.com:443"

    assert detect_scope_violation("curl", ["https://example.com/login"], active_target=active_target) is None
    assert detect_scope_violation("nmap", ["-sV", "evil.com"], active_target=active_target) is not None


def test_tool_approval_policy_keeps_critical_execution_manual() -> None:
    passive = get_tool_safety_profile("http_probe", role="recon")
    critical = get_run_custom_command_profile("sqlmap", role="exploit")

    assert requires_approval_for_execution(
        profile=passive,
        approval_mode="auto",
        role="recon",
        tool_name="http_probe",
    ) is False
    assert requires_approval_for_execution(
        profile=critical,
        approval_mode="auto",
        role="exploit",
        tool_name="run_custom",
    ) is True


def test_sandbox_env_and_cwd_are_forced_inside_sandbox() -> None:
    env = build_sandbox_env({"SAFE_FLAG": "1", "bad-key": "2"})
    sandbox_root = get_sandbox_root().resolve()

    assert Path(env["HOME"]).resolve().is_relative_to(sandbox_root)
    assert Path(env["TMPDIR"]).resolve().is_relative_to(sandbox_root)
    assert "bad-key" not in env
    assert resolve_sandbox_cwd("/tmp") == str(sandbox_root)


def test_tool_audit_log_persists_exact_command(tmp_path: Path) -> None:
    store = ProjectsStore(db_path=str(tmp_path / "projects.db"))
    store.init_schema()
    store.append_tool_audit_log(
        {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "role": "recon",
            "tool_name": "run_custom",
            "command_name": "nmap",
            "safety_category": "active_scan",
            "risk_level": "high",
            "requires_human_approval": True,
            "full_command": "nmap -sV example.com",
            "args": ["-sV", "example.com"],
            "reason": "Enumerate the approved target.",
            "status": "completed",
            "execution_cwd": "/sandbox",
            "return_code": 0,
            "execution_time": 1.2,
            "artifact_paths": ["/sandbox/output.xml"],
            "scope_target": "https://example.com",
        }
    )

    with store._connect() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT full_command, args, risk_level, artifact_paths
            FROM project_tool_audit_logs
            WHERE project_id = 'proj-1'
            """
        )
        row = cur.fetchone()

    assert row is not None
    assert str(row["full_command"]) == "nmap -sV example.com"
    assert json.loads(str(row["args"])) == ["-sV", "example.com"]
    assert str(row["risk_level"]) == "high"
    assert json.loads(str(row["artifact_paths"])) == ["/sandbox/output.xml"]
