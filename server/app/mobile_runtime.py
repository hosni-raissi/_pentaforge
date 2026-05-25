from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from server.agents.executer.recon.tools.mobile.mobile_static_analysis import parse_android_manifest


def _project_target_config(project: dict[str, Any]) -> dict[str, Any]:
    target_config = project.get("targetConfig")
    return target_config if isinstance(target_config, dict) else {}


def _project_last_scan(project: dict[str, Any]) -> dict[str, Any]:
    last_scan = project.get("lastScan")
    return last_scan if isinstance(last_scan, dict) else {}


def _project_mobile_runtime_state(project: dict[str, Any]) -> dict[str, Any]:
    runtime = _project_last_scan(project).get("mobileRuntime")
    return runtime if isinstance(runtime, dict) else {}


def _mobile_remote_adb_endpoint(project: dict[str, Any] | None = None) -> str:
    target_config = _project_target_config(project or {}) if isinstance(project, dict) else {}
    explicit = str(
        target_config.get("runtime_adb_endpoint")
        or target_config.get("adb_endpoint")
        or os.environ.get("PENTAFORGE_MOBILE_REMOTE_ADB_ENDPOINT", "")
    ).strip()
    return explicit


def _mobile_runtime_mode(project: dict[str, Any] | None = None) -> str:
    target_config = _project_target_config(project or {}) if isinstance(project, dict) else {}
    configured = str(
        target_config.get("runtime_mode")
        or os.environ.get("PENTAFORGE_MOBILE_RUNTIME_MODE", "auto")
    ).strip().lower()
    if _mobile_remote_adb_endpoint(project):
        return "remote_adb"
    if configured in {"remote_adb", "local_emulator"}:
        return configured
    return "local_emulator"


def _mobile_android_device_id(project: dict[str, Any] | None = None) -> str:
    remote_endpoint = _mobile_remote_adb_endpoint(project)
    if remote_endpoint:
        return remote_endpoint
    host = str(os.environ.get("PENTAFORGE_MOBILE_ANDROID_HOST", "mobile-android")).strip() or "mobile-android"
    port = str(os.environ.get("PENTAFORGE_MOBILE_ANDROID_ADB_PORT", "5555")).strip() or "5555"
    return f"{host}:{port}"


def _run_mobile_command(args: list[str], *, timeout: int = 120, check: bool = True) -> tuple[int, str]:
    completed = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    combined = "\n".join(part for part in (stdout, stderr) if part).strip()
    if check and completed.returncode != 0:
        raise RuntimeError(combined or f"Command failed: {' '.join(args)}")
    return completed.returncode, combined


def _resolve_mobile_artifact_path(project: dict[str, Any]) -> Path | None:
    if not isinstance(project, dict):
        return None
    target_type = str(project.get("targetType", "")).strip().lower()
    if target_type != "mobile":
        return None
    target_config = project.get("targetConfig")
    if not isinstance(target_config, dict):
        target_config = {}
    target_path = str(target_config.get("file_path") or project.get("target") or "").strip()
    if not target_path:
        return None
    return Path(target_path)


def _extract_android_package_name(target_path: Path) -> str | None:
    if target_path.suffix.lower() != ".apk" or not target_path.is_file():
        return None
    with TemporaryDirectory(prefix="pf-mobile-apktool-") as temp_dir:
        output_dir = Path(temp_dir) / "decoded"
        _run_mobile_command(
            [
                "apktool",
                "d",
                "-f",
                "-s",
                str(target_path),
                "-o",
                str(output_dir),
            ],
            timeout=180,
        )
        manifest_path = output_dir / "AndroidManifest.xml"
        if not manifest_path.is_file():
            return None
        manifest_content = manifest_path.read_text(encoding="utf-8", errors="ignore")
        app_info, _, _ = parse_android_manifest(manifest_content)
        package_name = str(app_info.package_name or "").strip()
        return package_name or None


def _resolve_mobile_package_name(project: dict[str, Any], artifact_path: Path | None = None) -> str | None:
    if not isinstance(project, dict):
        return None
    target_config = project.get("targetConfig")
    if not isinstance(target_config, dict):
        target_config = {}
    package_name = str(target_config.get("package_name") or "").strip()
    if package_name:
        return package_name
    resolved_artifact = artifact_path or _resolve_mobile_artifact_path(project)
    if resolved_artifact is None:
        return None
    return _extract_android_package_name(resolved_artifact)


def _wait_for_android_boot_completed(device_id: str, *, timeout: int = 420) -> str:
    deadline = time.monotonic() + max(timeout, 30)
    last_output = ""
    while time.monotonic() < deadline:
        _, boot_output = _run_mobile_command(
            ["adb", "-s", device_id, "shell", "getprop", "sys.boot_completed"],
            timeout=30,
            check=False,
        )
        last_output = (boot_output or "").strip()
        if last_output == "1":
            return last_output
        time.sleep(5)
    raise RuntimeError(
        f"Android emulator did not finish booting on {device_id} within {timeout} seconds."
        + (f" Last boot status: {last_output}" if last_output else "")
    )


def _mobile_runtime_cleanup_required(project: dict[str, Any]) -> tuple[bool, str]:
    runtime = _project_mobile_runtime_state(project)
    execution_mode = str(runtime.get("executionMode") or "").strip().lower()
    runtime_available = runtime.get("runtimeAvailable")
    prepared = runtime.get("prepared")

    if execution_mode == "static_only":
        return False, "scan used static-only APK analysis"
    if runtime_available is False or prepared is False:
        return False, "mobile runtime was unavailable for this project"
    if execution_mode in {"live_local_emulator", "live_remote_adb"}:
        return True, ""
    return False, "no recorded live mobile runtime state"


def _connect_mobile_runtime_for_cleanup(device_id: str) -> tuple[str, str]:
    _, connect_output = _run_mobile_command(["adb", "connect", device_id], timeout=20)
    _run_mobile_command(["adb", "-s", device_id, "wait-for-device"], timeout=45)
    boot_status = _wait_for_android_boot_completed(device_id, timeout=45)
    return connect_output, boot_status


def prepare_mobile_runtime_for_project(project: dict[str, Any]) -> dict[str, Any]:
    artifact_path = _resolve_mobile_artifact_path(project)
    if artifact_path is None:
        return {"skipped": True, "reason": "project is not a mobile artifact target"}
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Mobile artifact not found: {artifact_path}")
    extension = artifact_path.suffix.lower()
    package_name = _resolve_mobile_package_name(project, artifact_path)

    return {
        "mode": "disabled",
        "execution_mode": "static_only",
        "runtime_available": False,
        "prepared": False,
        "warning": "Dynamic APK runtime is disabled in this deployment. Continuing with static APK analysis only.",
        "package_name": package_name,
        "artifact_path": str(artifact_path),
        "artifact_type": extension.lstrip("."),
    }


def stop_mobile_runtime_for_project(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "skipped": True,
        "reason": "dynamic mobile runtime is disabled; no live app process to stop",
    }


def uninstall_mobile_runtime_for_project(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "skipped": True,
        "reason": "dynamic mobile runtime is disabled; no live APK installation to uninstall",
    }
