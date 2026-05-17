from __future__ import annotations

from importlib import import_module

import pytest
from fastapi import HTTPException

from server.agents.executer.sandbox_client import sandbox_remote_enabled
from server.agents.executer.sandbox import get_sandbox_share_dir
from server.agents.tools.run_custom import resolve_sandbox_resource_args, run_custom
from server.agents.tools.run_python import run_python
from server.agents.tool_output_parsers import parse_ffuf_findings
from server.sandbox_service.app import (
    RunCustomRemoteRequest,
    SandboxExecutionContext,
    execute_run_custom,
    health,
)

run_custom_module = import_module("server.agents.tools.run_custom")


def test_sandbox_remote_disabled_inside_service(monkeypatch):
    monkeypatch.setenv("SANDBOX_EXECUTOR_URL", "http://tool-sandbox:8010")
    monkeypatch.setenv("PENTAFORGE_SANDBOX_SERVICE", "1")
    assert sandbox_remote_enabled() is False


def test_sandbox_service_health():
    assert health() == {"status": "ok"}


def test_sandbox_service_blocks_out_of_scope_run_custom():
    with pytest.raises(HTTPException) as exc:
        execute_run_custom(
            RunCustomRemoteRequest(
                command="curl",
                args=["-I", "https://example.com"],
                timeout=30,
                env={},
                execution_context=SandboxExecutionContext(
                    role="recon",
                    target_url="https://pentest-ground.com:9000",
                ),
            )
        )
    assert exc.value.status_code == 403
    assert "scope" in str(exc.value.detail).lower()


def test_shared_run_custom_fails_closed_without_sandbox(monkeypatch):
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("PENTAFORGE_SANDBOX_SERVICE", raising=False)

    result = run_custom(
        command="echo",
        args=["hello"],
        reason="Check shared sandbox enforcement",
    )

    assert result["success"] is False
    assert "tool sandbox" in str(result.get("error", "")).lower()


def test_shared_run_python_fails_closed_without_sandbox(monkeypatch):
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("PENTAFORGE_SANDBOX_SERVICE", raising=False)

    result = run_python(
        code="print('hello')",
        reason="Check shared sandbox enforcement",
    )

    assert result["success"] is False
    assert "tool sandbox" in str(result.get("error", "")).lower()


def test_run_custom_resolves_compact_sandbox_wordlist_paths():
    share_dir = get_sandbox_share_dir()
    assert resolve_sandbox_resource_args(
        ["-w", "wordlists/short.txt", "-x", "seclists/Passwords/Common-Credentials/best1050.txt"]
    ) == [
        "-w",
        str(share_dir / "wordlists" / "short.txt"),
        "-x",
        str(share_dir / "seclists" / "Passwords" / "Common-Credentials" / "best1050.txt"),
    ]


def test_run_custom_resolves_dns_wordlist_underscore_alias():
    share_dir = get_sandbox_share_dir()
    assert resolve_sandbox_resource_args(
        ["-w", "wordlists/dns_fuzz_common.txt"]
    ) == [
        "-w",
        str(share_dir / "wordlists" / "dns-fuzz-common.txt"),
    ]


def test_sandbox_paths_can_be_overridden_by_environment(monkeypatch, tmp_path):
    root = tmp_path / "runtime-sandbox"
    share = tmp_path / "image-share"
    monkeypatch.setenv("PENTAFORGE_SANDBOX_ROOT", str(root))
    monkeypatch.setenv("PENTAFORGE_SANDBOX_SHARE_DIR", str(share))

    from server.agents.executer.sandbox import get_sandbox_root, get_sandbox_share_dir

    assert get_sandbox_root() == root
    assert get_sandbox_share_dir() == share
    assert resolve_sandbox_resource_args(["-w", "wordlists/short.txt"]) == [
        "-w",
        str(share / "wordlists" / "short.txt"),
    ]


def test_parse_ffuf_json_stream_extracts_exact_matches():
    findings = parse_ffuf_findings(
        {
            "stdout": (
                '{"input":{"FUZZ":"aW5kZXg="},"status":200,"length":6974,"words":495,"lines":153,'
                '"url":"http://scanme.nmap.org/index"} '
                '{"input":{"FUZZ":"aW1hZ2Vz"},"status":301,"length":318,"words":20,"lines":10,'
                '"redirectlocation":"http://scanme.nmap.org/images/","url":"http://scanme.nmap.org/images"}'
            )
        }
    )

    assert findings == [
        {"path": "index", "status": 200, "size": 6974, "words": 495, "lines": 153, "url": "http://scanme.nmap.org/index"},
        {
            "path": "images",
            "status": 301,
            "size": 318,
            "words": 20,
            "lines": 10,
            "url": "http://scanme.nmap.org/images",
            "redirectlocation": "http://scanme.nmap.org/images/",
        },
    ]


def test_run_custom_attaches_generic_observations(monkeypatch):
    monkeypatch.setenv("PENTAFORGE_SANDBOX_SERVICE", "1")
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.setattr(
        run_custom_module,
        "safe_execute",
        lambda *args, **kwargs: ("HTTP/1.1 200 OK\nServer: Apache/2.4.7", "", 0),
    )

    result = run_custom(
        command="echo",
        args=["probe"],
        reason="Capture generic command observations",
    )

    assert result["success"] is True
    assert result["output_parser"] == "generic_text"
    assert result["observations"][:2] == ["HTTP/1.1 200 OK", "Server: Apache/2.4.7"]


def test_run_custom_attaches_ffuf_observations_and_matches(monkeypatch):
    monkeypatch.setenv("PENTAFORGE_SANDBOX_SERVICE", "1")
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.setattr(
        run_custom_module,
        "safe_execute",
        lambda *args, **kwargs: (
            "index [Status: 200, Size: 6974, Words: 495, Lines: 153, Duration: 288ms] "
            "images [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 245ms]",
            "",
            0,
        ),
    )

    result = run_custom(
        command="ffuf",
        args=["-u", "http://scanme.nmap.org/FUZZ", "-w", "wordlists/short.txt", "-ic"],
        reason="Enumerate common content paths",
    )

    assert result["success"] is True
    assert result["output_parser"] == "ffuf"
    assert result["observations"][:2] == [
        "Matched index with HTTP 200 (size=6974, words=495)",
        "Matched images with HTTP 301 (size=318, words=20)",
    ]
    assert result["parsed_findings"][:2] == [
        {"path": "index", "status": 200, "size": 6974, "words": 495, "lines": 153},
        {"path": "images", "status": 301, "size": 318, "words": 20, "lines": 10},
    ]
