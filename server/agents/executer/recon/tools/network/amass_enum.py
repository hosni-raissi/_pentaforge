#/*
from __future__ import annotations

__all__ = ["amass_enum", "AMASS_ENUM_TOOL_DEFINITION"]

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Optional

import requests
from pydantic import BaseModel, Field, field_validator

_ALLOWED_MODES = {"enum", "intel"}
_DANGEROUS = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_DOMAIN_FINDER_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_IP_FINDER_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RAW_LIMIT = 8_000
_ERR_LIMIT = 500
_MAX_FALLBACK_ASSETS = 200


class AmassEnumRequest(BaseModel):
    target: str
    mode: str = "enum"
    passive: bool = False
    timeout: int = Field(default=900, ge=30, le=7200)
    args: list[str] = []
    use_fallback: bool = True
    fallback_first: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("target must not be empty")
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"Invalid domain: {v!r}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in _ALLOWED_MODES:
            raise ValueError(f"mode must be one of: {sorted(_ALLOWED_MODES)}")
        return v

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        blocked = {"-o", "-dir", "-config"}
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            if arg.strip() in blocked:
                raise ValueError(f"Blocked arg: {arg!r}")
        return v


class AmassAsset(BaseModel):
    name: str
    addresses: list[str] = []
    sources: list[str] = []


class AmassEnumResult(BaseModel):
    success: bool
    target: str
    mode: str
    command: str
    assets: list[AmassAsset] = []
    total_assets: int = 0
    fallback_used: bool = False
    data_sources: list[str] = []
    coverage_note: str = ""
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    try:
        with tempfile.TemporaryDirectory(prefix="amass_home_") as temp_home:
            env = dict(os.environ)
            env["HOME"] = temp_home
            env["XDG_CONFIG_HOME"] = temp_home
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                env=env,
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                return stdout, stderr, proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                return stdout or "", (stderr or "") + f"\n[timeout] killed after {timeout}s", -1
    except FileNotFoundError:
        return "", "Tool 'amass' not installed", 127
    except Exception as exc:
        return "", str(exc), -1


def _parse(stdout: str, target: str, mode: str = "enum") -> list[AmassAsset]:
    assets: dict[str, AmassAsset] = {}
    target_l = target.lower()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            domains = [
                d.lower() for d in _DOMAIN_FINDER_RE.findall(line)
                if d.lower() == target_l or d.lower().endswith("." + target_l)
            ]
            ips = _IP_FINDER_RE.findall(line)
            for name in domains:
                asset = assets.setdefault(name, AmassAsset(name=name))
                for ip in ips:
                    if ip not in asset.addresses:
                        asset.addresses.append(ip)
            continue
        name = (data.get("name") or data.get("domain") or data.get("hostname") or "").lower()
        if not name:
            continue
        if mode == "enum" and not (name == target_l or name.endswith("." + target_l)):
            continue
        asset = assets.setdefault(name, AmassAsset(name=name))
        for address in data.get("addresses", []):
            ip = address.get("ip") if isinstance(address, dict) else None
            if ip and ip not in asset.addresses:
                asset.addresses.append(ip)
        src = data.get("source")
        if src and src not in asset.sources:
            asset.sources.append(src)

        if mode == "intel":
            ip = data.get("ip")
            if isinstance(ip, str) and ip:
                ip_asset = assets.setdefault(ip, AmassAsset(name=ip))
                if "amass_intel" not in ip_asset.sources:
                    ip_asset.sources.append("amass_intel")
    return sorted(assets.values(), key=lambda a: a.name)


def _resolve_ips_for_assets(assets: list[AmassAsset], max_hosts: int = 80) -> None:
    """Best-effort DNS enrichment for assets without resolved addresses."""
    checked = 0
    for asset in assets:
        if checked >= max_hosts:
            break
        if asset.addresses:
            continue
        checked += 1
        try:
            _, _, ips = socket.gethostbyname_ex(asset.name)
            for ip in ips:
                if ip not in asset.addresses:
                    asset.addresses.append(ip)
            if ips and "dns" not in asset.sources:
                asset.sources.append("dns")
        except Exception:
            continue


def _fallback_crtsh(target: str, timeout: int = 20) -> list[AmassAsset]:
    """
    Lightweight passive fallback source for subdomains when amass times out/returns empty.
    """
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        r = requests.get(url, timeout=min(timeout, 20))
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    assets: dict[str, AmassAsset] = {}
    target_l = target.lower()
    for row in data if isinstance(data, list) else []:
        val = (row.get("name_value") or "").strip()
        if not val:
            continue
        for part in val.split("\n"):
            name = part.strip().lower().lstrip("*.")
            if not name:
                continue
            if name == target_l or name.endswith("." + target_l):
                asset = assets.setdefault(name, AmassAsset(name=name))
                if "crt.sh" not in asset.sources:
                    asset.sources.append("crt.sh")
        if len(assets) >= _MAX_FALLBACK_ASSETS:
            break

    return list(assets.values())


def amass_enum(
    target: str,
    mode: str = "enum",
    passive: bool = False,
    timeout: int = 900,
    args: Optional[list[str]] = None,
    use_fallback: bool = True,
    fallback_first: bool = False,
) -> dict[str, Any]:
    start = time.monotonic()
    args = args or []

    try:
        req = AmassEnumRequest(
            target=target,
            mode=mode,
            passive=passive,
            timeout=timeout,
            args=args,
            use_fallback=use_fallback,
            fallback_first=fallback_first,
        )
    except Exception as exc:
        return AmassEnumResult(
            success=False, target=target, mode=mode, command="", error=str(exc),
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    cmd = ["amass", req.mode]
    if req.mode == "enum":
        cmd += ["-d", req.target]
        if "-silent" not in req.args:
            cmd.append("-silent")
        if req.passive:
            cmd.append("-passive")
    else:
        cmd += ["-whois", "-ip", "-d", req.target]
    cmd += req.args

    # Quick-path for smoke runs: prefer passive fallback if requested.
    if req.mode == "enum" and req.use_fallback and req.fallback_first:
        fb_assets = _fallback_crtsh(req.target, timeout=min(15, req.timeout))
        if fb_assets:
            _resolve_ips_for_assets(fb_assets, max_hosts=50)
            src_set = {"crt.sh"}
            if any("dns" in a.sources for a in fb_assets):
                src_set.add("dns")
            return AmassEnumResult(
                success=True,
                target=req.target,
                mode=req.mode,
                command=" ".join(cmd),
                assets=sorted(fb_assets, key=lambda a: a.name),
                total_assets=len(fb_assets),
                fallback_used=True,
                data_sources=sorted(src_set),
                coverage_note=(
                    "fallback-first mode: passive CT enumeration returned assets; "
                    "amass execution skipped for speed."
                ),
                raw_output=None,
                error=None,
                execution_time=round(time.monotonic() - start, 2),
            ).model_dump()

    stdout, stderr, rc = _safe_execute(cmd, req.timeout)
    assets = _parse(stdout, req.target, req.mode)
    fallback_used = False
    data_sources: set[str] = {"amass"}

    if req.use_fallback and req.mode == "enum" and not assets:
        fb_assets = _fallback_crtsh(req.target, timeout=min(req.timeout, 20))
        if fb_assets:
            assets = fb_assets
            fallback_used = True
            data_sources.add("crt.sh")

    if assets and req.mode == "enum":
        _resolve_ips_for_assets(assets, max_hosts=60 if req.passive else 100)

    raw = (stdout or stderr)[:_RAW_LIMIT] or None

    success = bool(assets)
    if success:
        error = None
    elif rc != 0:
        error = (stderr.strip()[:_ERR_LIMIT] or "amass failed without stderr output")
    else:
        error = "No assets discovered. Try larger timeout, passive=False, or provide additional amass args/sources."

    if req.mode == "intel":
        coverage_note = "intel mode focuses on WHOIS/IP intelligence and may return sparse host assets."
    elif req.passive:
        coverage_note = "passive mode only; fewer assets expected than active enumeration."
    else:
        coverage_note = "active enum mode; results depend on DNS/source availability and timeout budget."

    return AmassEnumResult(
        success=success,
        target=req.target,
        mode=req.mode,
        command=" ".join(cmd),
        assets=assets,
        total_assets=len(assets),
        fallback_used=fallback_used,
        data_sources=sorted(data_sources),
        coverage_note=coverage_note,
        raw_output=raw,
        error=error,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


AMASS_ENUM_TOOL_DEFINITION: dict[str, Any] = {
    "name": "amass_enum",
    "description": (
        "OSINT subdomain and asset discovery via Amass. "
        "Queries CT logs, WHOIS, passive DNS, and search engines. "
        "Use mode='enum' for subdomain enumeration, mode='intel' for org-level WHOIS recon. "
        "passive=True disables active DNS resolution (slower but stealthier)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target domain (e.g. 'example.com')"},
            "mode": {"type": "string", "enum": ["enum", "intel"], "default": "enum",
                     "description": "enum = subdomain discovery | intel = WHOIS org recon"},
            "passive": {"type": "boolean", "default": False,
                        "description": "Passive-only mode (no active DNS queries)"},
            "timeout": {"type": "integer", "default": 900, "minimum": 30, "maximum": 7200,
                        "description": "Max execution time in seconds"},
            "use_fallback": {"type": "boolean", "default": True,
                        "description": "Use crt.sh passive fallback when amass returns no assets"},
            "fallback_first": {"type": "boolean", "default": False,
                        "description": "Try fallback source before running amass for faster smoke scans"},
            "args": {"type": "array", "items": {"type": "string"},
                     "description": "Extra amass flags e.g. ['-rf', '/tmp/resolvers.txt']"},
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════
# MAIN — test runner
# ══════════════════════════════════════════════════════════════

def _print_result(label: str, result: dict) -> None:
    sep = "─" * 56
    print(f"\n{sep}")
    print(f"  {label}")
    print(sep)
    print(f"  success        : {result['success']}")
    print(f"  target         : {result['target']}")
    print(f"  mode           : {result['mode']}")
    print(f"  total_assets   : {result['total_assets']}")
    print(f"  fallback_used  : {result.get('fallback_used', False)}")
    print(f"  data_sources   : {', '.join(result.get('data_sources', [])) or '—'}")
    print(f"  execution_time : {result['execution_time']}s")
    print(f"  command        : {result['command']}")
    if result.get("coverage_note"):
        print(f"  coverage_note  : {result['coverage_note']}")
    if result.get("error"):
        print(f"  error          : {result['error']}")
    if result["assets"]:
        print(f"  assets (first 5):")
        for asset in result["assets"][:5]:
            ips = ", ".join(asset["addresses"]) or "—"
            srcs = ", ".join(asset["sources"]) or "—"
            print(f"    • {asset['name']}  ips=[{ips}]  sources=[{srcs}]")
    print(sep)


def main() -> None:
    full_main = os.getenv("PENTAFORGE_AMASS_MAIN_FULL", "0") == "1"

    # ── Validation tests (no amass needed) ────────────────────
    validation_cases: list[tuple[str, dict]] = [
        ("PASS — empty target",        dict(target="")),
        ("PASS — invalid domain",      dict(target="not a domain!!")),
        ("PASS — blocked arg -o",      dict(target="example.com", args=["-o"])),
        ("PASS — injection in arg",    dict(target="example.com", args=["valid", "bad;arg"])),
        ("PASS — invalid mode",        dict(target="example.com", mode="attack")),
        ("PASS — timeout out of range",dict(target="example.com", timeout=5)),
    ]

    print("\n══════════════════════════════════════════════════════")
    print("  VALIDATION TESTS  (all should fail with error)")
    print("══════════════════════════════════════════════════════")
    all_passed = True
    for label, kwargs in validation_cases:
        result = amass_enum(**kwargs)
        ok = not result["success"] and result["error"]
        status = "✅ PASS" if ok else "❌ FAIL"
        if not ok:
            all_passed = False
        print(f"  {status}  {label}")
        if not ok:
            print(f"         → unexpected result: {result}")

    print(f"\n  Validation suite: {'all passed ✅' if all_passed else 'FAILURES detected ❌'}")

    # ── Live tests (require amass installed) ──────────────────
    if full_main:
        live_cases: list[tuple[str, dict]] = [
            ("ENUM passive — google.com",  dict(target="google.com",      mode="enum",  passive=True,  timeout=120)),
            ("ENUM active  — hackerone.com", dict(target="hackerone.com", mode="enum",  passive=False, timeout=120)),
            ("INTEL        — google.com",  dict(target="google.com",      mode="intel",              timeout=90)),
        ]
    else:
        print("\nRunning quick smoke mode. Set PENTAFORGE_AMASS_MAIN_FULL=1 for full live tests.")
        live_cases = [
            ("ENUM passive — google.com",  dict(target="google.com", mode="enum", passive=True, timeout=30, use_fallback=True, fallback_first=True)),
        ]

    print("\n══════════════════════════════════════════════════════")
    print("  LIVE TESTS  (require amass in PATH)")
    print("══════════════════════════════════════════════════════")
    live_results: dict[str, dict] = {}
    for label, kwargs in live_cases:
        result = amass_enum(**kwargs)
        live_results[label] = result
        _print_result(label, result)

    # ── Full JSON dump of one result ──────────────────────────
    print("\n══════════════════════════════════════════════════════")
    print("  FULL JSON — passive enum google.com")
    print("══════════════════════════════════════════════════════")
    result = live_results.get(
        "ENUM passive — google.com",
        amass_enum(target="google.com", mode="enum", passive=True, timeout=45),
    )
    # Omit raw_output and trim very large asset arrays to keep print readable.
    display = {k: v for k, v in result.items() if k != "raw_output"}
    if len(display.get("assets", [])) > 20:
        display["assets"] = display["assets"][:20]
        display["assets_truncated"] = True
        display["assets_total_untruncated"] = result.get("total_assets", len(result.get("assets", [])))
    print(json.dumps(display, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)
