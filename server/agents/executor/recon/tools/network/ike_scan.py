#/+
"""
ike_scan_tool.py
~~~~~~~~~~~~~~~~
IPsec/IKE discovery and responder fingerprinting via ike-scan.

Usage (CLI test):
    python ike_scan_tool.py --target <IP> [--args "--sport=500"] [--timeout 30]
    python ike_scan_tool.py --demo          # offline parse demo (no ike-scan needed)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from server.agents.executor.recon.config import is_blocked_host

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ike_scan")

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# Shell-injection characters / sequences
_DANGEROUS: frozenset[str] = frozenset({
    ";", "&&", "||", "|", "`", "$(", ">>", "<<",
    ">", "<", "'", '"', "\n", "\r", "\x00",
})

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# Matches the first IPv4 address on a line (responder)
_HOST_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\b")

# IKE Vendor ID lines
_VENDOR_RE = re.compile(r"Vendor\s+ID:\s*(.+)", re.IGNORECASE)

# Real IKE transform proposal lines produced by ike-scan --multiline
# Example: "    Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK Life=28800"
_TRANSFORM_RE = re.compile(
    r"\b(?:Enc|Encryption)\s*=\s*\S+"
    r".*?\b(?:Hash|Integrity)\s*=\s*\S+",
    re.IGNORECASE,
)

# Hostname validation (RFC 1123)
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


# ---------------------------------------------------------------------------
# Target validation helpers
# ---------------------------------------------------------------------------

def _is_ip(value: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return parsed IP object, or None if value is not a bare IP address."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _validate_target(value: str) -> str:
    """
    Validate and normalise a scan target.

    Accepts:
        - IPv4 / IPv6 addresses (blocked ranges rejected)
        - RFC-1123 hostnames (length ≤ 253)

    Returns the stripped target string.
    Raises ValueError on any violation.
    """
    v = value.strip()
    if not v:
        raise ValueError("Target must not be empty")

    if is_blocked_host(v.lower()):
        raise ValueError(f"Target '{v}' is blocked")

    ip = _is_ip(v)
    if ip is not None:
        return v

    # Hostname path
    if len(v) > 253:
        raise ValueError(f"Hostname too long: {v!r}")
    # Strip trailing dot (FQDN)
    hostname = v.rstrip(".")
    if not _HOSTNAME_RE.match(hostname):
        raise ValueError(f"Invalid hostname or IP: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class IKEScanRequest(BaseModel):
    """Validated, sanitised scan request."""

    target: str
    args: list[str] = []
    timeout: int = Field(default=180, ge=10, le=1800)

    @field_validator("target")
    @classmethod
    def check_target(cls, v: str) -> str:
        return _validate_target(v)

    @field_validator("args")
    @classmethod
    def check_args(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in v:
            arg = raw.strip()
            # Every extra argument must be a real flag (--flag or --flag=value)
            if not arg.startswith("--"):
                raise ValueError(
                    f"Argument {arg!r} is not a valid ike-scan flag (must start with '--')"
                )
            # Reject shell-injection characters
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            cleaned.append(arg)
        return cleaned


class IKEFinding(BaseModel):
    """Parsed IKE response data."""

    responder: Optional[str] = None
    vendor_ids: list[str] = []
    transforms: list[str] = []
    aggressive_mode: bool = False
    handshake_seen: bool = False


class IKEScanResult(BaseModel):
    """Full scan result returned to callers."""

    success: bool          # tool executed without fatal error
    responded: bool        # target actually sent an IKE response
    target: str
    command: str
    finding: Optional[IKEFinding] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    """
    Run *cmd* without a shell.

    Returns (stdout, stderr, returncode).
    returncode is -1 on timeout or missing binary.
    """
    log.debug("Executing: %s", " ".join(cmd))
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
        log.warning("ike-scan timed out after %ds", timeout)
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        log.error("ike-scan is not installed or not in PATH")
        return "", "Tool 'ike-scan' not installed or not in PATH", -1
    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected subprocess error")
        return "", str(exc), -1


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse(stdout: str, target: str) -> Optional[IKEFinding]:
    """
    Parse ike-scan stdout into an :class:`IKEFinding`.

    Returns *None* when the output contains no IKE evidence.
    """
    finding = IKEFinding()

    for line in stdout.splitlines():
        stripped = line.strip()

        # Detect the responder IP on the first matching line
        if not finding.responder:
            m = _HOST_RE.match(stripped)
            if m:
                finding.responder = m.group(1)
                finding.handshake_seen = True

        # Vendor IDs
        vendor = _VENDOR_RE.search(line)
        if vendor:
            vid = vendor.group(1).strip()
            if vid not in finding.vendor_ids:
                finding.vendor_ids.append(vid)

        # Transform proposals (must match both Enc= and Hash= on the same line)
        if _TRANSFORM_RE.search(line):
            finding.transforms.append(stripped)

        # Aggressive-mode indicator
        if "aggressive mode" in stripped.lower():
            finding.aggressive_mode = True

    # Nothing interesting found → no finding
    if (
        not finding.handshake_seen
        and not finding.vendor_ids
        and not finding.transforms
        and not finding.aggressive_mode
    ):
        log.debug("No IKE evidence found in output")
        return None

    # Fallback: use target if we could not parse a responder IP
    if not finding.responder:
        finding.responder = target

    return finding


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ike_scan(
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 180,
) -> dict[str, Any]:
    """
    Perform an IKE scan against *target*.

    Parameters
    ----------
    target:
        IPv4/IPv6 address or hostname to scan.
    args:
        Extra ike-scan flags, e.g. ``["--sport=500", "--aggressive"]``.
        Every element must start with ``--``.
    timeout:
        Seconds to wait before aborting (10–1800).

    Returns
    -------
    dict
        Serialised :class:`IKEScanResult`.
    """
    start = time.time()
    args = args or []

    # --- Validate input -------------------------------------------------------
    try:
        req = IKEScanRequest(target=target, args=args, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return IKEScanResult(
            success=False,
            responded=False,
            target=target,
            command="",
            error=str(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Build command --------------------------------------------------------
    cmd = ["sudo", "ike-scan", "--showbackoff", "--multiline"] + req.args + [req.target]

    # --- Execute --------------------------------------------------------------
    stdout, stderr, rc = _safe_execute(cmd, req.timeout)

    # --- Parse ----------------------------------------------------------------
    finding = _parse(stdout, req.target)
    responded = finding is not None

    log.info(
        "Scan complete | target=%s responded=%s rc=%d time=%.2fs",
        req.target, responded, rc, time.time() - start,
    )

    return IKEScanResult(
        success=rc == 0 or responded,   # success if tool ran cleanly OR got a response
        responded=responded,
        target=req.target,
        command=" ".join(cmd),
        finding=finding,
        raw_output=(stdout or stderr)[:8000] or None,
        error=stderr[:500] if rc != 0 and not responded else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

IKE_SCAN_TOOL_DEFINITION: dict[str, Any] = {
    "name": "ike_scan",
    "description": (
        "IPsec/IKE discovery and responder fingerprinting via ike-scan. "
        "Probes a target host for IKE/IKEv1/IKEv2 daemons, returns vendor IDs, "
        "supported transforms, and aggressive-mode exposure."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IPv4/IPv6 address or hostname to scan (public addresses only).",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional ike-scan flags, e.g. ['--sport=500', '--aggressive']. "
                    "Each element must start with '--'."
                ),
                "default": [],
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds (10–1800).",
                "default": 180,
                "minimum": 10,
                "maximum": 1800,
            },
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Demo / offline parse test
# ---------------------------------------------------------------------------

_DEMO_OUTPUT = """\
1.2.3.4\tMain Mode Handshake returned
\tHDR=(CKY-R=abcdef1234567890)
\tSA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
\tVendor ID: Cisco Systems, Inc. PIX Security Appliance
\tVendor ID: draft-ietf-ipsra-isakmp-xauth-06.txt
"""

def _run_demo() -> None:
    """Offline demo: parse a synthetic ike-scan output without running ike-scan."""
    print("\n" + "=" * 60)
    print("  DEMO MODE  (no ike-scan binary required)")
    print("=" * 60)
    finding = _parse(_DEMO_OUTPUT, "1.2.3.4")
    if finding:
        print(json.dumps(finding.model_dump(), indent=2))
    else:
        print("No finding parsed.")


# ---------------------------------------------------------------------------
# Main / CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ike_scan_tool – IKE fingerprinting wrapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", nargs="?", help="Target IP or hostname")
    p.add_argument("--demo", action="store_true", help="Offline parse demo")
    p.add_argument(
        "--args",
        nargs="*",
        default=[],
        metavar="FLAG",
        help="Extra ike-scan flags, e.g. --args --sport=500 --aggressive",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECS",
        help="Scan timeout in seconds (default: 30)",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    return p


def main() -> None:
    target = "192.168.1.1"
    args = []
    timeout = 30
    demo = False
    verbose = True

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ---- Demo ---------------------------------------------------------------
    if demo:
        _run_demo()
        return

    # ---- Live scan ----------------------------------------------------------
    print(f"\nScanning target: {target}")
    print(f"Extra args     : {args or '(none)'}")
    print(f"Timeout        : {timeout}s")
    print("-" * 60)

    result = ike_scan(target=target, args=args, timeout=timeout)

    print(json.dumps(result, indent=2, default=str))

    # Quick summary
    print("\n" + "=" * 60)
    if result["responded"]:
        f = result["finding"]
        print(f"  ✅  Responded  — responder: {f['responder']}")
        print(f"  Vendor IDs  : {', '.join(f['vendor_ids']) or '(none)'}")
        print(f"  Transforms  : {len(f['transforms'])} found")
        print(f"  Aggressive  : {'YES ⚠️' if f['aggressive_mode'] else 'no'}")
    elif result["success"]:
        print("  ℹ️  Scan ran cleanly but no IKE response received.")
    else:
        print(f"  ❌  Scan failed: {result.get('error', 'unknown error')}")
    print(f"  Time        : {result['execution_time']}s")
    print("=" * 60)


if __name__ == "__main__":
    main()