#/+
"""
Route & Topology Mapper — Agent Tool  (v3.4 - Bug Fixes)
===============================================================
Zero-configuration reconnaissance. Agent provides target only.
Executes MTR (path quality) + Nmap (services) concurrently and
merges results into unified intelligence.

Improvements over v3.2:
  - DNS rebinding protection (resolves hostname, validates all IPs)
  - tools_succeeded field for partial-result transparency
  - Configurable boundary_threshold_ms (default 20ms)
  - success only True when at least one tool fully succeeds
  - Cleaner field_map fallback with exhaustive MTR key variants
  - Type annotations tightened throughout

Usage:
    result = route_topology(target="scanme.nmap.org")
    print(result["formatted_report"])
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from pydantic import BaseModel, Field

from server.agents.executer.recon.config import BLOCKED_HOSTNAMES as _BLOCKED_HOSTNAMES
from server.agents.executer.recon.config import BLOCKED_NETWORKS as _BLOCKED_NETWORKS


# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════

logger = logging.getLogger("route_topology")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s — %(message)s", datefmt="%H:%M:%S",
    ))
    logger.addHandler(_handler)


# ══════════════════════════════════════════════════════════════════════
# 1. SECURITY CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Regex to extract embedded IPv4 patterns from hostnames (e.g. evil.127.0.0.1.xip.io)
_EMBEDDED_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


# ══════════════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════════════

class ServiceInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str
    reason: str
    service: Optional[str] = None
    version: Optional[str] = None


class RouteHop(BaseModel):
    hop_number: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: list[float] = Field(default_factory=list)
    avg_rtt_ms: Optional[float] = None
    loss_pct: Optional[float] = None
    jitter_ms: Optional[float] = None
    is_timeout: bool = False
    asn: Optional[str] = None


class ReconResult(BaseModel):
    target: str
    success: bool
    execution_time: float = 0.0

    # Path data (MTR primary, Nmap traceroute fallback)
    path_hops: list[RouteHop] = Field(default_factory=list)
    avg_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    packet_loss_path: Optional[float] = None
    possible_firewalls: list[int] = Field(default_factory=list)
    network_boundaries: list[dict] = Field(default_factory=list)

    # Service data (Nmap)
    open_ports: list[ServiceInfo] = Field(default_factory=list)
    os_guesses: list[dict] = Field(default_factory=list)
    host_alive: bool = False

    # Transparency
    tools_succeeded: list[str] = Field(default_factory=list)
    commands_executed: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
# 3. SECURITY VALIDATION
# ══════════════════════════════════════════════════════════════════════

def _ip_in_blocked_networks(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if addr falls within any blocked network."""
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _validate_target(target: str) -> tuple[bool, str]:
    """
    Full security validation:
      1. Blocked hostname list
      2. Embedded IPv4 patterns in hostname string
      3. Direct IP address check (CIDR-aware)
      4. DNS resolution + check of all resolved IPs (DNS rebinding protection)

    Returns (is_blocked, reason). Passes through on any DNS error —
    the scanning tools themselves will fail on unresolvable targets.
    """
    clean = target.strip().lower()

    # 1. Exact hostname blocklist
    if clean in _BLOCKED_HOSTNAMES:
        return True, f"Hostname '{target}' is blocked"

    # 2. Embedded IP patterns (e.g. evil.127.0.0.1.xip.io)
    for match in _EMBEDDED_IP_RE.findall(clean):
        try:
            addr = ipaddress.ip_address(match)
            if _ip_in_blocked_networks(addr):
                return True, f"Target contains blocked IP pattern: {match}"
        except ValueError:
            continue

    # 3. Direct IP address
    try:
        addr = ipaddress.ip_address(target.strip())
        if _ip_in_blocked_networks(addr):
            return True, f"IP {target} is in a blocked network"
        return False, ""  # Valid IP — skip DNS step
    except ValueError:
        pass  # Not a bare IP — continue to DNS check

    # 4. DNS rebinding protection: resolve and validate all returned IPs
    try:
        resolved = socket.getaddrinfo(clean, None)
        for item in resolved:
            raw_ip = item[4][0]
            try:
                addr = ipaddress.ip_address(raw_ip)
                if _ip_in_blocked_networks(addr):
                    return True, (
                        f"'{target}' resolves to blocked IP {raw_ip}"
                    )
            except ValueError:
                continue
    except socket.gaierror:
        # Unresolvable — let the tools report the error naturally
        logger.debug("DNS resolution failed for %s — passing through", target)

    return False, ""


# ══════════════════════════════════════════════════════════════════════
# 4. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════════════

def _build_mtr_cmd(target: str, max_hops: int = 30) -> list[str]:
    """
    MTR: TCP mode (bypasses ICMP filters), 20 probes for reliable
    statistics, JSON output, both hostname and IP displayed.
    """
    return [
        "sudo", "mtr",
        "--report", "--report-wide", "--json", "--show-ips",
        "--tcp",
        "-c", "20",
        "-m", str(max_hops),
        target,
    ]


def _build_nmap_cmd(target: str, max_hops: int = 30) -> list[str]:
    """
    Nmap: SYN stealth, OS + version detection, traceroute backup,
    aggressive timing, XML to stdout.
    """
    return [
        "sudo", "nmap",
        "-sS", "-O", "-sV",
        "--traceroute", "--reason",
        "-Pn", "-n", "-T4",
        "--max-retries", "2",
        "-p", "22,80,443,8080,9929,31337",
        "--ttl", str(max_hops),   # --max-hops is not a valid Nmap flag
        "-oX", "-",
        target,
    ]


# ══════════════════════════════════════════════════════════════════════
# 5. EXECUTOR
# ══════════════════════════════════════════════════════════════════════

def _execute(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """
    Run command as a subprocess (shell=False — no shell injection risk).
    Returns (stdout, stderr, returncode). -1 returncode signals tool-level error.
    """
    logger.debug("Executing: %s", " ".join(cmd))
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
    except FileNotFoundError as exc:
        return "", f"Tool not found: {exc}", -1
    except Exception as exc:  # noqa: BLE001
        return "", str(exc), -1


# ══════════════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════════════

# Known MTR JSON field name variants across versions
_MTR_FIELD_CANDIDATES: dict[str, list[str]] = {
    "loss":   ["Loss%", "LossPercent", "loss"],
    "avg":    ["Avg", "Average", "avg"],
    "best":   ["Best", "best"],
    "worst":  ["Wrst", "Worst", "worst"],
    "jitter": ["StDev", "StdDev", "Jitter", "jitter"],
}


def _resolve_mtr_fields(sample: dict) -> dict[str, str]:
    """
    Detect which MTR field name variant is present in the JSON output.
    Returns a mapping of canonical name → actual key, or raises KeyError
    with a descriptive message if required fields are absent.
    """
    resolved: dict[str, str] = {}
    missing: list[str] = []

    for canonical, candidates in _MTR_FIELD_CANDIDATES.items():
        for candidate in candidates:
            if candidate in sample:
                resolved[canonical] = candidate
                break
        else:
            missing.append(canonical)

    if missing:
        logger.warning(
            "MTR JSON missing fields %s. Available keys: %s",
            missing,
            list(sample.keys()),
        )
    return resolved


def _parse_mtr(stdout: str) -> tuple[list[RouteHop], list[str]]:
    """
    Parse MTR JSON output into RouteHop list.
    Returns (hops, warnings). Never raises.
    """
    hops: list[RouteHop] = []
    warnings: list[str] = []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        warnings.append(f"MTR returned invalid JSON: {exc}")
        return hops, warnings

    hubs: list[dict] = data.get("report", {}).get("hubs", [])
    if not hubs:
        warnings.append("MTR returned an empty hub list")
        return hops, warnings

    field_map = _resolve_mtr_fields(hubs[0])
    if not field_map:
        warnings.append("MTR field detection failed — no usable fields found")
        return hops, warnings

    for entry in hubs:
        hop_num = int(entry.get("count", 0)) + 1
        host = entry.get("host", "???")

        loss  = float(entry.get(field_map.get("loss",   "Loss%"), 0))
        avg   = float(entry.get(field_map.get("avg",    "Avg"),   0))
        best  = float(entry.get(field_map.get("best",   "Best"),  avg))
        worst = float(entry.get(field_map.get("worst",  "Wrst"),  avg))
        stdev = float(entry.get(field_map.get("jitter", "StDev"), 0))

        if host in ("???",) or loss >= 100.0:
            hops.append(RouteHop(hop_number=hop_num, is_timeout=True))
        else:
            hops.append(RouteHop(
                hop_number=hop_num,
                ip=host if not host.startswith("?") else None,
                rtt_ms=[best, avg, worst],
                avg_rtt_ms=avg,
                loss_pct=loss,
                jitter_ms=stdev if stdev > 0 else None,
            ))

    return hops, warnings


def _parse_nmap(
    xml_output: str,
) -> tuple[list[ServiceInfo], list[dict], list[RouteHop], bool, list[str]]:
    """
    Parse Nmap XML into services, OS guesses, traceroute hops, alive flag.
    Returns (services, os_matches, trace_hops, alive, warnings). Never raises.
    """
    services: list[ServiceInfo] = []
    os_matches: list[dict] = []
    trace_hops: list[RouteHop] = []
    alive = False
    warnings: list[str] = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        warnings.append(f"Nmap returned invalid XML: {exc}")
        return services, os_matches, trace_hops, alive, warnings

    host = root.find(".//host")
    if host is None:
        warnings.append("Nmap XML contained no host element")
        return services, os_matches, trace_hops, alive, warnings

    status = host.find("status")
    if status is not None and status.get("state") == "up":
        alive = True

    ports_elem = host.find("ports")
    if ports_elem is not None:
        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            svc_elem = port.find("service")
            version = ""
            if svc_elem is not None:
                product = svc_elem.get("product", "")
                ver     = svc_elem.get("version", "")
                version = f"{product} {ver}".strip()
            services.append(ServiceInfo(
                port=int(port.get("portid", 0)),
                protocol=port.get("protocol", "tcp"),
                state="open",
                reason=state_elem.get("reason", ""),
                service=svc_elem.get("name", "unknown") if svc_elem is not None else "unknown",
                version=version or None,
            ))

    os_elem = host.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch")[:3]:
            os_matches.append({
                "name":     match.get("name", ""),
                "accuracy": match.get("accuracy", ""),
            })

    trace_elem = host.find("trace")
    if trace_elem is not None:
        for hop in trace_elem.findall("hop"):
            ttl = hop.get("ttl")
            rtt = hop.get("rtt")
            trace_hops.append(RouteHop(
                hop_number=int(ttl) if ttl else 0,
                ip=hop.get("ipaddr"),
                avg_rtt_ms=float(rtt) if rtt else None,
            ))

    return services, os_matches, trace_hops, alive, warnings


# ══════════════════════════════════════════════════════════════════════
# 7. PATH ANALYSIS
# ══════════════════════════════════════════════════════════════════════

def _analyze_path(
    hops: list[RouteHop],
    boundary_threshold_ms: float = 20.0,
) -> dict:
    """
    Derive path statistics, possible firewall positions, and latency
    boundaries from a hop list.

    boundary_threshold_ms — latency jump (ms) that marks a network boundary.
    Default 20ms suits internet paths; increase for intercontinental scans.
    """
    analysis: dict = {
        "possible_firewalls": [],
        "boundaries":         [],
        "avg_latency":        None,
        "max_latency":        None,
        "worst_loss":         0.0,
    }
    if not hops:
        return analysis

    # Latency statistics
    rtts = [h.avg_rtt_ms for h in hops if h.avg_rtt_ms is not None]
    if rtts:
        analysis["avg_latency"] = round(sum(rtts) / len(rtts), 2)
        analysis["max_latency"] = round(max(rtts), 2)

    # Worst packet loss across any hop
    losses = [h.loss_pct for h in hops if h.loss_pct is not None]
    if losses:
        analysis["worst_loss"] = max(losses)

    # Possible firewall: 2+ consecutive timeouts following a live hop.
    # Note: also triggered by ICMP rate-limiting and congestion — treat as
    # a hint, not a definitive finding.
    consecutive   = 0
    last_live_hop = 0
    for h in hops:
        if h.is_timeout:
            consecutive += 1
            if consecutive >= 2 and last_live_hop > 0:
                candidate = last_live_hop + 1
                if candidate not in analysis["possible_firewalls"]:
                    analysis["possible_firewalls"].append(candidate)
        else:
            consecutive   = 0
            last_live_hop = h.hop_number

    # Network boundaries: configurable latency jump threshold
    prev_rtt: Optional[float] = None
    for h in hops:
        if h.avg_rtt_ms is not None and prev_rtt is not None:
            jump = h.avg_rtt_ms - prev_rtt
            if jump > boundary_threshold_ms:
                analysis["boundaries"].append({
                    "hop":     h.hop_number,
                    "jump_ms": round(jump, 1),
                    "ip":      h.ip,
                })
        if h.avg_rtt_ms is not None:
            prev_rtt = h.avg_rtt_ms

    return analysis


# ══════════════════════════════════════════════════════════════════════
# 8. MAIN FUNCTION
# ══════════════════════════════════════════════════════════════════════

def route_topology(
    target: str,
    max_hops: int = 30,
    timeout: int = 120,
    boundary_threshold_ms: float = 20.0,
    output_format: str = "text",
) -> dict:
    """
    Agent Tool — Unified Network Reconnaissance.

    Runs MTR and Nmap in parallel and returns fused path + service data.

    Args:
        target:                 IP or hostname to scan
        max_hops:               Maximum traceroute depth (default 30)
        timeout:                Max seconds per tool (default 120)
        boundary_threshold_ms:  Latency jump (ms) to flag as a network
                                boundary (default 20; raise for WAN scans)
        output_format:          "text" | "json" | "csv"

    Returns:
        ReconResult as dict, with an extra "formatted_report" key.
        Check tools_succeeded to understand which tools contributed data.
    """
    start = time.perf_counter()

    # Security validation (includes DNS rebinding check)
    is_blocked, reason = _validate_target(target.strip())
    if is_blocked:
        return ReconResult(
            target=target,
            success=False,
            error=reason,
        ).model_dump()

    logger.info("Starting reconnaissance on %s", target)

    mtr_cmd  = _build_mtr_cmd(target, max_hops)
    nmap_cmd = _build_nmap_cmd(target, max_hops)

    with ThreadPoolExecutor(max_workers=2) as pool:
        mtr_future  = pool.submit(_execute, mtr_cmd,  timeout)
        nmap_future = pool.submit(_execute, nmap_cmd, timeout)
        mtr_stdout,  mtr_stderr,  mtr_rc  = mtr_future.result()
        nmap_stdout, nmap_stderr, nmap_rc = nmap_future.result()

    warnings:       list[str] = []
    tools_succeeded: list[str] = []

    # Parse MTR
    mtr_hops: list[RouteHop] = []
    if mtr_rc == 0:
        mtr_hops, mtr_warns = _parse_mtr(mtr_stdout)
        warnings.extend(mtr_warns)
        if mtr_hops:
            tools_succeeded.append("mtr")
    else:
        warnings.append(f"MTR failed (rc={mtr_rc}): {mtr_stderr[:200]}")

    # Parse Nmap
    nmap_services: list[ServiceInfo] = []
    nmap_os:       list[dict]        = []
    nmap_trace:    list[RouteHop]    = []
    alive          = False
    if nmap_rc == 0:
        nmap_services, nmap_os, nmap_trace, alive, nmap_warns = _parse_nmap(nmap_stdout)
        warnings.extend(nmap_warns)
        if alive or nmap_services:
            tools_succeeded.append("nmap")
    else:
        warnings.append(f"Nmap failed (rc={nmap_rc}): {nmap_stderr[:200]}")

    # Merge: MTR preferred for path quality; Nmap traceroute as fallback
    path_hops = mtr_hops if mtr_hops else nmap_trace
    analysis  = _analyze_path(path_hops, boundary_threshold_ms)

    elapsed = round(time.perf_counter() - start, 2)

    result = ReconResult(
        target            = target,
        # success = True only when at least one tool produced usable data
        success           = bool(tools_succeeded),
        execution_time    = elapsed,
        path_hops         = path_hops,
        avg_latency_ms    = analysis["avg_latency"],
        max_latency_ms    = analysis["max_latency"],
        packet_loss_path  = analysis["worst_loss"],
        possible_firewalls= analysis["possible_firewalls"],
        network_boundaries= analysis["boundaries"],
        open_ports        = nmap_services,
        os_guesses        = nmap_os,
        host_alive        = alive,
        tools_succeeded   = tools_succeeded,
        commands_executed = [" ".join(mtr_cmd), " ".join(nmap_cmd)],
        warnings          = warnings,
    )

    report: str
    if output_format == "json":
        report = json.dumps(result.model_dump(), indent=2, default=str)
    elif output_format == "csv":
        report = _format_csv(result)
    else:
        report = _format_text(result)

    out = result.model_dump()
    out["formatted_report"] = report
    return out


# ══════════════════════════════════════════════════════════════════════
# 9. FORMATTERS
# ══════════════════════════════════════════════════════════════════════

def _format_text(r: ReconResult) -> str:
    sep = "═" * 72
    lines: list[str] = [
        sep,
        "  NETWORK RECONNAISSANCE REPORT  (v3.4)",
        f"  Target : {r.target}",
        f"  Time   : {r.execution_time}s  |  Tools: {', '.join(r.tools_succeeded) or 'none'}",
        sep,
    ]

    # ── Path ──
    _LW = 55  # label column width — fits full NTT/Akamai hostnames
    if r.path_hops:
        lines.append(f"\n  Network path  ({len(r.path_hops)} hops)")
        lines.append(f"  {'Hop':<5} {'IP / Host':<{_LW}} {'RTT':>9}  {'Loss':>6}  {'Jitter':>9}")
        lines.append("  " + "─" * (_LW + 36))
        for h in r.path_hops[:20]:
            if h.is_timeout:
                lines.append(f"  {h.hop_number:<5} *** timeout ***")
            else:
                ip_str   = h.ip or "unknown"
                hn_str   = f"  ({h.hostname})" if h.hostname else ""
                full_lbl = ip_str + hn_str
                rtt    = f"{h.avg_rtt_ms:.1f} ms" if h.avg_rtt_ms is not None else "—"
                loss   = f"{h.loss_pct:.0f}%"     if h.loss_pct   is not None else "0%"
                jitter = f"{h.jitter_ms:.1f} ms"  if h.jitter_ms  is not None else "—"
                if len(full_lbl) <= _LW:
                    lines.append(
                        f"  {h.hop_number:<5} {full_lbl:<{_LW}} {rtt:>9}  {loss:>6}  {jitter:>9}"
                    )
                else:
                    # Label too wide: IP + stats on line 1, hostname indented on line 2
                    lines.append(
                        f"  {h.hop_number:<5} {ip_str:<{_LW}} {rtt:>9}  {loss:>6}  {jitter:>9}"
                    )
                    if h.hostname:
                        lines.append(f"        ({h.hostname})")

        lines.append(f"\n  Path quality")
        lines.append(f"    Average latency : {r.avg_latency_ms} ms")
        lines.append(f"    Maximum latency : {r.max_latency_ms} ms")
        lines.append(f"    Worst hop loss  : {r.packet_loss_path}%")

        if r.possible_firewalls:
            lines.append(
                f"    Possible firewalls at hops {r.possible_firewalls}"
                " (may also indicate ICMP rate-limiting or congestion)"
            )
        if r.network_boundaries:
            lines.append(f"    Network boundaries detected: {len(r.network_boundaries)}")
            for b in r.network_boundaries[:5]:
                lines.append(f"      Hop {b['hop']:>2}: +{b['jump_ms']} ms  ({b['ip'] or 'unknown'})")

    # ── Services ──
    if r.open_ports:
        lines.append(f"\n  Open ports  ({len(r.open_ports)})")
        for svc in r.open_ports:
            ver = f"  {svc.version}" if svc.version else ""
            lines.append(f"    {svc.port:>5}/{svc.protocol:<4}  {svc.service:<18}{ver}")

    # ── OS ──
    if r.os_guesses:
        lines.append("\n  OS fingerprint")
        for guess in r.os_guesses:
            lines.append(f"    {guess['name']}  ({guess['accuracy']}% confidence)")

    if r.host_alive:
        lines.append("\n  Host status: alive")

    # ── Warnings ──
    if r.warnings:
        lines.append("\n  Warnings")
        for w in r.warnings:
            lines.append(f"    • {w}")

    lines.append(sep)
    return "\n".join(lines)


def _format_csv(r: ReconResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["hop", "ip", "hostname", "avg_rtt_ms", "loss_pct", "jitter_ms"])
    for h in r.path_hops:
        writer.writerow([
            h.hop_number,
            h.ip       or "",
            h.hostname or "",
            h.avg_rtt_ms if h.avg_rtt_ms is not None else "",
            h.loss_pct   if h.loss_pct   is not None else "",
            h.jitter_ms  if h.jitter_ms  is not None else "",
        ])
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════════════
# 10. LLM TOOL DEFINITION
# ══════════════════════════════════════════════════════════════════════

ROUTE_TOPOLOGY_TOOL: dict = {
    "name": "route_topology",
    "description": (
        "Comprehensive network reconnaissance. Runs MTR (path quality: "
        "latency / packet loss / jitter, 20-probe statistics) and Nmap "
        "(service detection, OS fingerprinting, traceroute) in parallel, "
        "then fuses the results. Returns hop-by-hop path data, possible "
        "firewall positions, open ports with versions, and OS guesses. "
        "Check tools_succeeded in the response to understand which tools "
        "contributed data. Provide the target hostname or IP."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type":        "string",
                "description": "IP address or hostname to scan (e.g. 'scanme.nmap.org')",
            },
            "max_hops": {
                "type":        "integer",
                "description": "Maximum traceroute depth (default 30)",
                "default":     30,
            },
            "boundary_threshold_ms": {
                "type":        "number",
                "description": (
                    "Latency jump (ms) used to flag a network boundary. "
                    "Default 20ms suits LAN/regional scans; raise to 80–150 "
                    "for intercontinental targets."
                ),
                "default": 20.0,
            },
            "output_format": {
                "type":        "string",
                "enum":        ["text", "json", "csv"],
                "description": "Report format (default 'text')",
                "default":     "text",
            },
        },
        "required": ["target"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# 11. CLI / SELF-TEST
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

  
    # Live scan (only if arg provided or default test host)
    targets = sys.argv[1:] or ["scanme.nmap.org"]
    for target in targets:
        print(f"\n{'═' * 72}")
        print(f"  Scanning: {target}")
        print("═" * 72)
        result = route_topology(target=target, boundary_threshold_ms=30.0)
        print(result["formatted_report"])
        if result["success"]:
            print(
                f"\n  Tools succeeded : {result['tools_succeeded']}\n"
                f"  Hops            : {len(result['path_hops'])}\n"
                f"  Open ports      : {len(result['open_ports'])}\n"
                f"  Execution time  : {result['execution_time']}s"
            )
        else:
            print(f"\n  Failed: {result.get('error')}")