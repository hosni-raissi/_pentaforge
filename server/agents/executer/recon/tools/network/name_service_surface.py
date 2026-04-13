#/+
"""
name_service_surface_tool.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Passive mDNS / LLMNR / NBNS poisoning-surface mapper via tshark.

Captures broadcast name-service traffic on the selected interface for a
configurable duration and returns structured events + per-protocol query lists.

Usage (CLI):
    sudo python name_service_surface_tool.py --interface eth0 --duration 10
    python name_service_surface_tool.py --demo          # offline parse demo
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("name_service_surface")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Extra seconds tshark is allowed beyond the capture duration before we
# forcibly terminate it (accounts for handshake / flush time).
_TSHARK_BUFFER_SECS = 8

# Shell-injection characters / sequences
_DANGEROUS: frozenset[str] = frozenset({
    ";", "&&", "||", "|", "`", "$(", ">>", "<<",
    ">", "<", "'", '"', "\n", "\r", "\x00",
})

# Supported protocol labels (normalised to these keys regardless of
# how tshark capitalises them in the _ws.col.Protocol field).
_PROTOCOL_KEYS: dict[str, str] = {
    "mdns":  "mDNS",
    "llmnr": "LLMNR",
    "nbns":  "NBNS",
}

# Valid Linux/macOS interface name pattern
# Allows: eth0, ens3, wlan0, en0, bond0.100, any, lo …
_IFACE_RE = re.compile(r"^[a-zA-Z0-9][\w.\-:]{0,31}$")
_NOISY_PSEUDO_IFACES = {
    "any", "lo", "lo0", "nflog", "nfqueue", "dbus-system", "dbus-session",
    "randpkt", "sdjournal", "ciscodump", "sshdump", "udpdump", "wifidump", "etwdump",
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class NameServiceSurfaceRequest(BaseModel):
    """Validated, sanitised capture request."""

    interface: str = "any"
    duration: int = Field(default=20, ge=5, le=300)
    args: list[str] = []
    use_sudo: bool = True
    auto_fallback_any: bool = True
    auto_retry_specific_interface: bool = True

    @field_validator("interface")
    @classmethod
    def check_interface(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Interface name must not be empty")
        if len(stripped) > 32:
            raise ValueError(f"Interface name too long: {stripped!r}")
        # Allow "any" as a special cross-platform keyword
        if stripped != "any" and not _IFACE_RE.match(stripped):
            raise ValueError(
                f"Invalid interface name {stripped!r}. "
                "Use alphanumeric names like 'eth0', 'wlan0', or 'any'."
            )
        return stripped

    @field_validator("args")
    @classmethod
    def check_args(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in v:
            arg = raw.strip()
            if not arg.startswith("--"):
                raise ValueError(
                    f"Argument {arg!r} is not a valid tshark flag (must start with '--')"
                )
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            cleaned.append(arg)
        return cleaned


class NameServiceEvent(BaseModel):
    """A single captured name-service query or response."""

    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    query: Optional[str] = None


class NameServiceSurfaceResult(BaseModel):
    """Full result returned to callers."""

    success: bool       # tool executed without fatal error
    captured: bool      # at least one name-service event was observed
    interface: str
    fallback_interface: Optional[str] = None
    interface_hints: list[str] = []
    command: str
    events: list[NameServiceEvent] = []
    queries_by_protocol: dict[str, list[str]] = {}
    packets_seen: int = 0
    note: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ---------------------------------------------------------------------------
# Safe execution
# ---------------------------------------------------------------------------

def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
    """
    Run *cmd* without a shell.

    The subprocess is given ``timeout + _TSHARK_BUFFER_SECS`` before we
    raise TimeoutExpired, giving tshark time to flush its buffers.

    Returns (stdout, stderr, returncode).  returncode is -1 on errors.
    """
    hard_timeout = timeout + _TSHARK_BUFFER_SECS
    log.debug("Executing (hard timeout=%ds): %s", hard_timeout, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=hard_timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log.warning("tshark hard-timeout (%ds) exceeded", hard_timeout)
        return "", f"Hard timeout after {hard_timeout}s", -1
    except FileNotFoundError:
        log.error("tshark not found. Install via: sudo apt install tshark")
        return "", "Tool 'tshark' not installed or not in PATH", -1
    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected subprocess error")
        return "", str(exc), -1


def _prefix_sudo(cmd: list[str], enabled: bool = True) -> list[str]:
    """
    Prefix command with sudo when not already root.
    Mirrors traffic_analyze privilege behavior for capture reliability.
    """
    if not enabled:
        return cmd
    try:
        if os.name != "nt" and os.geteuid() != 0:
            return ["sudo", *cmd]
    except AttributeError:
        pass
    return cmd


def _list_tshark_interfaces(use_sudo: bool = False) -> list[str]:
    """Return interface names from `tshark -D` best-effort."""
    try:
        cmd = _prefix_sudo(["tshark", "-D"], enabled=use_sudo)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8, shell=False)
        if r.returncode != 0:
            return []
        out: list[str] = []
        for line in r.stdout.splitlines():
            m = re.match(r"^\s*\d+\.\s+([^\s(]+)", line)
            if not m:
                continue
            name = m.group(1).strip()
            if name:
                out.append(name)
        return out
    except Exception:
        return []


def _preferred_interfaces(ifaces: list[str]) -> list[str]:
    """Filter and rank likely useful capture interfaces."""
    preferred = [i for i in ifaces if i not in _NOISY_PSEUDO_IFACES]
    wifi = [i for i in preferred if i.startswith(("wl", "wlan", "wifi"))]
    eth = [i for i in preferred if i.startswith(("en", "eth"))]
    other = [i for i in preferred if i not in wifi and i not in eth]
    return wifi + eth + other


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _normalise_proto(raw: str) -> str:
    """
    Normalise a tshark protocol label to a canonical key.

    tshark may emit 'MDNS', 'mDNS', 'LLMNR', 'NBNS', etc.
    Returns the canonical form or the uppercased raw value as fallback.
    """
    return _PROTOCOL_KEYS.get(raw.lower().strip(), raw.upper().strip() or "UNKNOWN")


def _extract_packets_captured(text: str) -> int:
    """Best-effort packet count extraction from tshark stderr/stdout."""
    if not text:
        return 0
    m = re.search(r"(\d+)\s+packets\s+captured", text, re.I)
    if not m:
        return 0
    try:
        return int(m.group(1))
    except Exception:
        return 0


def _parse(stdout: str) -> tuple[list[NameServiceEvent], dict[str, list[str]]]:
    """
    Parse tshark tab-separated output into structured events and a
    per-protocol query index.

    Expected tshark field order (set by the command builder):
        ip.src  ip.dst  _ws.col.Protocol  dns.qry.name  dns.resp.name
        ipv6.src  ipv6.dst

    The function handles both IPv4-only and dual-stack rows gracefully.
    """
    events: list[NameServiceEvent] = []
    # Initialise with the three known protocol buckets; others are added
    # dynamically so unexpected protocols are never silently dropped.
    queries: dict[str, list[str]] = {
        "mDNS": [],
        "LLMNR": [],
        "NBNS": [],
    }

    # Track (proto, src, dst, query) tuples to deduplicate noisy broadcasts
    seen: set[tuple[str, ...]] = set()

    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        # Unpack — IPv6 addresses land in slots 5/6 if present
        ipv4_src, ipv4_dst, raw_proto, qry_name, resp_name = parts[:5]
        ipv6_src = parts[5] if len(parts) > 5 else ""
        ipv6_dst = parts[6] if len(parts) > 6 else ""

        src_ip  = (ipv4_src or ipv6_src or None)
        dst_ip  = (ipv4_dst or ipv6_dst or None)
        proto   = _normalise_proto(raw_proto)
        query   = qry_name.strip() or resp_name.strip() or None

        key = (proto, src_ip or "", dst_ip or "", query or "")
        if key in seen:
            continue
        seen.add(key)

        events.append(NameServiceEvent(
            protocol=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            query=query,
        ))

        if query:
            bucket = queries.setdefault(proto, [])
            if query not in bucket:
                bucket.append(query)

    return events, queries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def name_service_surface(
    interface: str = "any",
    duration: int = 20,
    args: Optional[list[str]] = None,
    use_sudo: bool = True,
    auto_fallback_any: bool = True,
    auto_retry_specific_interface: bool = True,
) -> dict[str, Any]:
    """
    Passively capture mDNS / LLMNR / NBNS traffic on *interface*.

    Parameters
    ----------
    interface:
        Network interface to sniff (e.g. ``"eth0"``, ``"wlan0"``, ``"any"``).
        Requires tshark to have capture privileges (``sudo`` or ``CAP_NET_RAW``).
    duration:
        Seconds to capture (5–300).
    args:
        Extra tshark flags, e.g. ``["--display-filter=mdns"]``.
        Every element must start with ``--``.

    Returns
    -------
    dict
        Serialised :class:`NameServiceSurfaceResult`.
    """
    start = time.time()
    args = args or []

    # --- Validate input -------------------------------------------------------
    try:
        req = NameServiceSurfaceRequest(
            interface=interface,
            duration=duration,
            args=args,
            use_sudo=use_sudo,
            auto_fallback_any=auto_fallback_any,
            auto_retry_specific_interface=auto_retry_specific_interface,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Validation error: %s", exc)
        return NameServiceSurfaceResult(
            success=False,
            captured=False,
            interface=interface,
            command="",
            error=str(exc),
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    # --- Build command --------------------------------------------------------
    # Capture both IPv4 and IPv6 source/destination fields so dual-stack
    # hosts are correctly represented in the output.
    cmd = [
        "tshark",
        "-i", req.interface,
        "-a", f"duration:{req.duration}",
        "-Y", "mdns or llmnr or nbns",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "dns.qry.name",
        "-e", "dns.resp.name",
        "-e", "ipv6.src",   # populated only for IPv6 packets; empty otherwise
        "-e", "ipv6.dst",
    ] + req.args
    cmd = _prefix_sudo(cmd, enabled=req.use_sudo)

    # --- Execute --------------------------------------------------------------
    log.info("Capturing on '%s' for %ds …", req.interface, req.duration)
    stdout, stderr, rc = _safe_execute(cmd, req.duration)

    # Privilege hint: tshark exits non-zero and mentions permission/group errors
    error_msg: Optional[str] = None
    if rc != 0:
        hint = ""
        lower_err = stderr.lower()
        if (
            "permission" in lower_err
            or "group" in lower_err
            or "not in the sudoers" in lower_err
            or "a terminal is required" in lower_err
            or "password is required" in lower_err
        ):
            hint = " (Hint: run with sudo or add user to 'wireshark' group)"
        error_msg = stderr[:500] + hint

    # --- Parse ----------------------------------------------------------------
    events, queries = _parse(stdout)
    captured = len(events) > 0
    packets_seen = _extract_packets_captured(stderr or stdout)
    fallback_interface: Optional[str] = None
    interface_hints: list[str] = []
    note: Optional[str] = None

    # If a specific interface is quiet, retry briefly on `any` to avoid false negatives.
    if (
        not captured
        and req.auto_fallback_any
        and req.interface != "any"
        and rc == 0
    ):
        fb_duration = max(5, min(10, req.duration // 2 or 5))
        fb_cmd = cmd.copy()
        fb_cmd[fb_cmd.index("-i") + 1] = "any"
        fb_cmd[fb_cmd.index("-a") + 1] = f"duration:{fb_duration}"
        log.info("No events on '%s'; retrying quick fallback on 'any' for %ds", req.interface, fb_duration)
        fb_out, fb_err, fb_rc = _safe_execute(fb_cmd, fb_duration)
        fb_events, fb_queries = _parse(fb_out)
        fb_packets = _extract_packets_captured(fb_err or fb_out)
        packets_seen += fb_packets
        if fb_events:
            events = fb_events
            queries = fb_queries
            captured = True
            fallback_interface = "any"
            note = "No events on selected interface; events observed on fallback interface 'any'."
            cmd_str = " ".join(cmd) + " || fallback:any"
            combined_raw = "\n".join([p for p in [stdout, stderr, fb_out, fb_err] if p]).strip()
            stdout = combined_raw
            stderr = ""
            rc = 0 if fb_rc == 0 or captured else fb_rc
        else:
            if packets_seen == 0:
                note = "No packets captured on selected interface or fallback 'any'."
            else:
                note = "Packets captured, but none matched mDNS/LLMNR/NBNS on selected interface or fallback 'any'."

    if not captured and note is None:
        if packets_seen == 0:
            note = "No packets captured; verify interface name, link activity, or capture privileges."
        else:
            note = "Packets were captured but none matched mDNS/LLMNR/NBNS filters."

    # If `any` is quiet, try one concrete interface briefly (where available).
    if (
        not captured
        and req.interface == "any"
        and req.auto_retry_specific_interface
        and rc == 0
    ):
        ranked_ifaces = _preferred_interfaces(_list_tshark_interfaces(use_sudo=req.use_sudo))
        interface_hints = ranked_ifaces[:5]
        if ranked_ifaces:
            pick = ranked_ifaces[0]
            fb_duration = max(5, min(10, req.duration // 2 or 5))
            fb_cmd = cmd.copy()
            fb_cmd[fb_cmd.index("-i") + 1] = pick
            fb_cmd[fb_cmd.index("-a") + 1] = f"duration:{fb_duration}"
            log.info("No packets on 'any'; retrying quick capture on '%s' for %ds", pick, fb_duration)
            fb_out, fb_err, fb_rc = _safe_execute(fb_cmd, fb_duration)
            fb_events, fb_queries = _parse(fb_out)
            packets_seen += _extract_packets_captured(fb_err or fb_out)
            if fb_events:
                events = fb_events
                queries = fb_queries
                captured = True
                fallback_interface = pick
                note = f"No events on 'any'; events observed on retry interface '{pick}'."
                cmd_str = " ".join(cmd) + f" || retry:{pick}"
                combined_raw = "\n".join([p for p in [stdout, stderr, fb_out, fb_err] if p]).strip()
                stdout = combined_raw
                stderr = ""
                rc = 0 if fb_rc == 0 or captured else fb_rc
            elif note:
                note = note + f" Suggested interface(s): {', '.join(interface_hints[:3])}."
        elif note:
            note = note + " Could not enumerate capture interfaces via tshark -D."

    if fallback_interface is None:
        cmd_str = " ".join(cmd)

    log.info(
        "Capture done | iface=%s events=%d rc=%d time=%.2fs",
        req.interface, len(events), rc, time.time() - start,
    )

    return NameServiceSurfaceResult(
        success=rc == 0 or captured,
        captured=captured,
        interface=req.interface,
        fallback_interface=fallback_interface,
        interface_hints=interface_hints,
        command=cmd_str,
        events=events,
        queries_by_protocol={k: v for k, v in queries.items() if v},  # omit empty
        packets_seen=packets_seen,
        note=note,
        raw_output=(stdout or stderr)[:8000] or None,
        error=error_msg if rc != 0 and not captured else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool definition (Anthropic / OpenAI tool-use schema)
# ---------------------------------------------------------------------------

NAME_SERVICE_SURFACE_TOOL_DEFINITION: dict[str, Any] = {
    "name": "name_service_surface",
    "description": (
        "Passive mDNS / LLMNR / NBNS poisoning-surface mapper using tshark. "
        "Captures broadcast name-service traffic on a network interface for a "
        "configurable duration and returns structured events and per-protocol "
        "query lists that reveal potential poisoning targets."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "interface": {
                "type": "string",
                "description": (
                    "Network interface to capture on (e.g. 'eth0', 'wlan0', 'any'). "
                    "Requires tshark capture privileges."
                ),
                "default": "any",
            },
            "duration": {
                "type": "integer",
                "description": "Capture duration in seconds (5–300).",
                "default": 20,
                "minimum": 5,
                "maximum": 300,
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional extra tshark flags, e.g. ['--log-level=debug']. "
                    "Each element must start with '--'."
                ),
                "default": [],
            },
            "use_sudo": {
                "type": "boolean",
                "description": "Prefix tshark commands with sudo when not root.",
                "default": True,
            },
            "auto_fallback_any": {
                "type": "boolean",
                "description": "If selected interface has no events, retry briefly on interface 'any'.",
                "default": True,
            },
            "auto_retry_specific_interface": {
                "type": "boolean",
                "description": "If interface='any' has no packets, retry briefly on a concrete interface.",
                "default": True,
            },
        },
        "required": [],
    },
}


# ---------------------------------------------------------------------------
# Demo / offline parse test
# ---------------------------------------------------------------------------

_DEMO_OUTPUT = "\n".join([
    # ipv4_src          ipv4_dst        proto   qry_name                resp_name  ipv6_src  ipv6_dst
    "192.168.1.10\t224.0.0.251\tmDNS\t_http._tcp.local\t\t\t",
    "192.168.1.11\t224.0.0.251\tmDNS\t_smb._tcp.local\t\t\t",
    "192.168.1.12\t224.0.0.252\tLLMNR\tworkstation\t\t\t",
    "192.168.1.13\t192.168.1.255\tNBNS\t\tFILESERVER\t\t",
    # duplicate — should be deduplicated
    "192.168.1.10\t224.0.0.251\tmDNS\t_http._tcp.local\t\t\t",
    # IPv6 mDNS
    "\t\tmDNS\t_printer._tcp.local\t\tfe80::1\tff02::fb",
])


# ---------------------------------------------------------------------------
# Main — hardcoded test cases
# ---------------------------------------------------------------------------

def main() -> None:
    # ── Edit these to match your test environment ────────────────────────────
    iface_env = os.getenv("PENTAFORGE_NSS_IFACE")
    USE_SUDO = os.getenv("PENTAFORGE_NSS_USE_SUDO", "1") == "1"
    DURATION  = int(os.getenv("PENTAFORGE_NSS_DURATION", "12"))
    ARGS      = []                   # extra tshark flags (each must start with --)
    # ─────────────────────────────────────────────────────────────────────────

    # 1. Offline parser smoke-test (no tshark binary needed)
    print("=" * 60)
    print("  [1] Parser smoke-test (synthetic output)")
    print("=" * 60)
    events, queries = _parse(_DEMO_OUTPUT)
    print(json.dumps({
        "event_count": len(events),
        "events": [e.model_dump() for e in events],
        "queries_by_protocol": queries,
    }, indent=2))

    # 2. Validation tests — every call below should fail with a clear error
    print("\n" + "=" * 60)
    print("  [2] Validation tests (all expected to fail)")
    print("=" * 60)
    bad_cases = [
        ("eth0;reboot",  20, [],                        "shell injection in interface"),
        ("a" * 40,       20, [],                        "interface name too long"),
        ("any",          20, ["display-filter=mdns"],   "arg missing -- prefix"),
        ("any",          20, ["--filter=mdns;id"],      "shell injection in arg"),
        ("any",           3, [],                        "duration below minimum"),
    ]
    for iface, dur, args, label in bad_cases:
        r = name_service_surface(iface, dur, args)
        status = "✅ rejected" if not r["success"] else "❌ PASSED (unexpected)"
        print(f"  {status}  [{label}]  error: {str(r.get('error',''))[:55]!r}")

    # 3. Live capture on the configured interface
    if iface_env:
        INTERFACE = iface_env
    else:
        # Resolve interface lazily so parser/validation tests run before any sudo prompt.
        ranked = _preferred_interfaces(_list_tshark_interfaces(use_sudo=False))
        INTERFACE = ranked[0] if ranked else "any"
        print(f"Auto-selected interface: {INTERFACE}")

    print("\n" + "=" * 60)
    print(f"  [3] Live capture → {INTERFACE}  ({DURATION}s)")
    print("=" * 60)
    result = name_service_surface(
        interface=INTERFACE,
        duration=DURATION,
        args=ARGS,
        use_sudo=USE_SUDO,
        auto_fallback_any=True,
        auto_retry_specific_interface=True,
    )
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 60)
    if result["captured"]:
        print(f"  ✅  Captured {len(result['events'])} event(s)")
        for proto, qs in result["queries_by_protocol"].items():
            print(f"      {proto:<8}: {', '.join(qs[:5])}" + (" …" if len(qs) > 5 else ""))
    elif result["success"]:
        print("  ℹ️  Capture completed — no name-service traffic observed.")
    else:
        print(f"  ❌  Failed: {result.get('error', 'unknown error')}")
    if result.get("note"):
        print(f"      Note    : {result['note']}")
    if result.get("fallback_interface"):
        print(f"      Fallback: {result['fallback_interface']}")
    if result.get("interface_hints"):
        print(f"      Hints   : {', '.join(result['interface_hints'][:3])}")
    print(f"      Packets : {result.get('packets_seen', 0)}")
    print(f"      Time    : {result['execution_time']}s")
    print("=" * 60)


if __name__ == "__main__":
    main()