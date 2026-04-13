#/+
from __future__ import annotations

__all__ = ["linux_config_audit", "LINUX_CONFIG_AUDIT_TOOL_DEFINITION"]

import glob
import grp
import ipaddress
import argparse
import getpass
import json
import os
import pwd
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Optional

import paramiko
from pydantic import BaseModel, Field, field_validator, model_validator

from server.agents.executer.recon.config import BLOCKED_HOSTNAMES as _BLOCKED_HOSTNAMES
from server.agents.executer.recon.config import BLOCKED_NETWORKS as _BLOCKED_NETWORKS

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_ALLOWED_MODES  = frozenset({"quick", "standard", "deep", "lynis"})
_DANGEROUS      = frozenset({";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"', "\n", "\r"})
_BLOCKED_FLAGS  = frozenset({"-o", "--output", "--report-file"})
_ERR_LIMIT      = 1_000
_RAW_LIMIT      = 8_000
_DOMAIN_RE      = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_LOCAL_TARGETS  = frozenset({"local", "self", "localhost", "127.0.0.1", "::1"})

_RISKY_PORTS: dict[int, tuple[str, str]] = {
    21:    ("high",   "FTP transmits credentials in cleartext"),
    23:    ("high",   "Telnet transmits credentials in cleartext"),
    25:    ("medium", "SMTP may expose relay/auth if misconfigured"),
    111:   ("medium", "rpcbind broadens attack surface"),
    445:   ("high",   "SMB exposed — common ransomware vector"),
    3306:  ("high",   "MySQL exposed without host restriction"),
    5432:  ("high",   "PostgreSQL exposed without host restriction"),
    6379:  ("high",   "Redis has no auth by default"),
    27017: ("high",   "MongoDB has no auth by default"),
}


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class LinuxConfigAuditRequest(BaseModel):
    mode:      str       = "standard"
    target:    str       = "local"
    username:  Optional[str] = None
    password:  Optional[str] = None
    ssh_key:   Optional[str] = None
    ssh_port:  int       = Field(default=22, ge=1, le=65535)
    use_sudo:  bool      = False
    aggressive: bool     = False
    args:      list[str] = Field(default_factory=list)
    timeout:   int       = Field(default=900, ge=10, le=3600)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in _ALLOWED_MODES:
            raise ValueError(f"mode must be one of: {sorted(_ALLOWED_MODES)}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("target must not be empty")

        if clean.lower() in _LOCAL_TARGETS:
            return "local"

        if len(clean) > 253:
            raise ValueError(f"Hostname too long: {clean!r}")

        v_lower = clean.lower()
        for b_host in _BLOCKED_HOSTNAMES:
            if v_lower == b_host or v_lower.endswith(f".{b_host}"):
                raise ValueError(f"Target '{clean}' matches blocked hostname '{b_host}'")

        try:
            ip = ipaddress.ip_address(clean)
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    raise ValueError(f"Target '{clean}' is in a blocked range ({net})")
            return clean
        except ValueError as exc:
            if "blocked range" in str(exc) or "blocked hostname" in str(exc):
                raise

        if not _DOMAIN_RE.match(clean.lower()):
            raise ValueError(f"{clean!r} is neither a valid IP nor a valid domain")
        return clean

    @field_validator("username", "password", "ssh_key", mode="before")
    @classmethod
    def validate_credential_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        s = str(v).strip()
        if not s:
            return None
        for ch in _DANGEROUS:
            if ch in s:
                raise ValueError(f"Dangerous character {ch!r} in credential field")
        return s

    @field_validator("args", mode="before")
    @classmethod
    def validate_args(cls, v: list[str]) -> list[str]:
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            if arg.strip() in _BLOCKED_FLAGS:
                raise ValueError(f"Blocked flag: {arg!r}")
        return v

    @model_validator(mode="after")
    def validate_remote_requirements(self) -> "LinuxConfigAuditRequest":
        if self.target != "local" and not self.username:
            raise ValueError("username is required for remote target auditing")
        return self


class AuditFinding(BaseModel):
    category:       str
    title:          str
    severity:       str           = "info"   # critical high medium low info
    status:         str           = "info"   # pass fail warning info
    evidence:       Optional[str] = None
    recommendation: Optional[str] = None
    file_path:      Optional[str] = None
    extra:          Optional[dict[str, Any]] = None


class AuditSection(BaseModel):
    name:     str
    findings: list[AuditFinding] = []


class LinuxConfigAuditResult(BaseModel):
    success:          bool
    mode:             str
    target:           str                   = "local"
    remote:           bool                  = False
    command:          str
    hostname:         Optional[str]           = None
    os_info:          Optional[dict[str, Any]] = None
    total_findings:   int                     = 0
    severity_summary: dict[str, int]          = {}
    sections:         list[AuditSection]      = []
    error:            Optional[str]           = None
    execution_time:   float                   = 0.0


# ══════════════════════════════════════════════════════════════
# 3. EXECUTOR + FILE HELPERS
# ══════════════════════════════════════════════════════════════

def _safe_execute(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout, stderr, proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return (
                stdout or "",
                (stderr or "") + f"\n[timeout] killed after {timeout}s",
                -1,
            )
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", 127
    except Exception as exc:
        return "", str(exc), -1


def _read_file(path: str, max_bytes: int = 200_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_bytes)
    except Exception:
        return None


def _file_stat(path: str) -> Optional[dict[str, Any]]:
    try:
        st = os.stat(path)
        return {
            "mode_octal": oct(stat.S_IMODE(st.st_mode)),
            "uid":        st.st_uid,
            "gid":        st.st_gid,
            "owner":      pwd.getpwuid(st.st_uid).pw_name,
            "group":      grp.getgrgid(st.st_gid).gr_name,
        }
    except Exception:
        return None


def _get_os_info() -> dict[str, Any]:
    info: dict[str, Any] = {}
    data = _read_file("/etc/os-release")
    if data:
        for line in data.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')
    uname, _, _ = _safe_execute(["uname", "-a"], timeout=10)
    if uname:
        info["uname"] = uname.strip()
    return info


def _cmd_exists(name: str) -> bool:
    _, _, rc = _safe_execute(["which", name], timeout=5)
    return rc == 0


def _is_remote(req: LinuxConfigAuditRequest) -> bool:
    return req.target != "local"


def _with_sudo_prefix(req: LinuxConfigAuditRequest, cmd: str) -> str:
    if req.use_sudo:
        return f"sudo -n {cmd}"
    return cmd


def _safe_remote_execute(
    req: LinuxConfigAuditRequest,
    remote_cmd: str,
    timeout: int = 30,
) -> tuple[str, str, int]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=req.target,
            port=req.ssh_port,
            username=req.username,
            password=req.password,
            key_filename=req.ssh_key,
            timeout=10,
        )
        stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:
        return "", f"SSH Execution error: {e}", -1
    finally:
        client.close()


def _run_cmd(req: LinuxConfigAuditRequest, cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    if _is_remote(req):
        remote = " ".join(shlex.quote(part) for part in cmd)
        remote = _with_sudo_prefix(req, remote)
        return _safe_remote_execute(req, remote, timeout=timeout)
    return _safe_execute(cmd, timeout=timeout)


def _read_path(req: LinuxConfigAuditRequest, path: str, max_bytes: int = 200_000) -> Optional[str]:
    if _is_remote(req):
        # Use cat with truncation to keep transport bounded.
        remote_cmd = _with_sudo_prefix(req, f"head -c {max_bytes} {shlex.quote(path)}")
        stdout, _, rc = _safe_remote_execute(req, remote_cmd, timeout=30)
        return stdout if rc == 0 else None
    return _read_file(path, max_bytes=max_bytes)


def _path_exists(req: LinuxConfigAuditRequest, path: str) -> bool:
    if _is_remote(req):
        remote_cmd = _with_sudo_prefix(req, f"test -e {shlex.quote(path)}")
        _, _, rc = _safe_remote_execute(req, remote_cmd, timeout=15)
        return rc == 0
    return os.path.exists(path)


def _stat_path(req: LinuxConfigAuditRequest, path: str) -> Optional[dict[str, Any]]:
    if _is_remote(req):
        remote_cmd = _with_sudo_prefix(
            req,
            f"stat -c '%a|%u|%g|%U|%G' {shlex.quote(path)}",
        )
        stdout, _, rc = _safe_remote_execute(req, remote_cmd, timeout=20)
        if rc != 0 or not stdout.strip():
            return None
        parts = stdout.strip().split("|", 4)
        if len(parts) != 5:
            return None
        mode_dec, uid, gid, owner, group = parts
        try:
            return {
                "mode_octal": oct(int(mode_dec, 10) & 0o7777),
                "uid": int(uid),
                "gid": int(gid),
                "owner": owner,
                "group": group,
            }
        except Exception:
            return None
    return _file_stat(path)


def _list_glob_paths(req: LinuxConfigAuditRequest, pattern: str) -> list[str]:
    if _is_remote(req):
        remote_cmd = _with_sudo_prefix(
            req,
            f"for f in {pattern}; do [ -e \"$f\" ] && printf '%s\\n' \"$f\"; done",
        )
        stdout, _, rc = _safe_remote_execute(req, remote_cmd, timeout=20)
        if rc != 0:
            return []
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    return sorted(glob.glob(pattern))


def _get_os_info_for(req: LinuxConfigAuditRequest) -> dict[str, Any]:
    info: dict[str, Any] = {}
    data = _read_path(req, "/etc/os-release")
    if data:
        for line in data.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')

    uname_cmd = ["uname", "-a"]
    if _is_remote(req):
        out, _, _ = _run_cmd(req, uname_cmd, timeout=10)
    else:
        out, _, _ = _safe_execute(uname_cmd, timeout=10)
    if out:
        info["uname"] = out.strip()
    return info


def _parse_ssh_config(text: str) -> dict[str, str]:
    """
    Parse SSH config key→value pairs.
    Handles multi-word values (e.g. AllowUsers alice bob).
    Last-wins semantics to match sshd Include order.
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)   # split on FIRST whitespace only
        if len(parts) == 2:
            result[parts[0]] = parts[1].strip()
        elif len(parts) == 1:
            result[parts[0]] = ""
    return result


# ══════════════════════════════════════════════════════════════
# 4. AUDIT SECTIONS
# ══════════════════════════════════════════════════════════════

def _audit_ssh(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []
    paths = ["/etc/ssh/sshd_config"] + _list_glob_paths(req, "/etc/ssh/sshd_config.d/*.conf")

    merged = ""
    for p in paths:
        data = _read_path(req, p)
        if data:
            merged += "\n" + data

    if not merged:
        findings.append(AuditFinding(
            category="ssh", title="SSH configuration not readable",
            severity="medium", status="warning",
            recommendation="Ensure /etc/ssh/sshd_config is present and readable",
        ))
        return AuditSection(name="SSH Hardening", findings=findings)

    cfg = _parse_ssh_config(merged)

    checks: list[tuple[str, list[str], str, str]] = [
        # (key, good_values, severity, recommendation)
        ("PermitRootLogin",       ["no"],          "high",   "Disable direct root SSH login"),
        ("PasswordAuthentication",["no"],          "high",   "Disable password auth — use keys only"),
        ("PubkeyAuthentication",  ["yes"],         "medium", "Enable public key authentication"),
        ("PermitEmptyPasswords",  ["no"],          "high",   "Disallow empty SSH passwords"),
        ("X11Forwarding",         ["no"],          "low",    "Disable X11 forwarding if not needed"),
        ("MaxAuthTries",          ["3", "4"],      "medium", "Reduce brute-force surface"),
        ("ClientAliveInterval",   ["300", "600"],  "low",    "Set idle session timeout"),
        ("LoginGraceTime",        ["30", "60"],    "low",    "Reduce login grace time"),
    ]

    for key, good, severity, rec in checks:
        val = cfg.get(key)
        if val is None:
            findings.append(AuditFinding(
                category="ssh",
                title=f"SSH '{key}' not explicitly configured",
                severity=severity, status="warning",
                evidence="Not found in sshd_config",
                recommendation=f"Set {key} {' or '.join(good)} explicitly",
                file_path=paths[0] if paths else "/etc/ssh/sshd_config",
            ))
        elif val not in good:
            findings.append(AuditFinding(
                category="ssh",
                title=f"Weak SSH setting: {key}={val}",
                severity=severity, status="fail",
                evidence=f"{key} {val}",
                recommendation=rec,
                file_path=paths[0] if paths else "/etc/ssh/sshd_config",
            ))
        else:
            findings.append(AuditFinding(
                category="ssh",
                title=f"SSH OK: {key}={val}",
                severity="info", status="pass",
                evidence=f"{key} {val}",
                file_path=paths[0] if paths else "/etc/ssh/sshd_config",
            ))

    return AuditSection(name="SSH Hardening", findings=findings)


def _audit_firewall(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []

    # ufw
    ufw_out, _, ufw_rc = _run_cmd(req, ["ufw", "status", "verbose"], timeout=20)
    if ufw_rc == 0:
        active = "Status: active" in ufw_out
        findings.append(AuditFinding(
            category="firewall",
            title="UFW is active" if active else "UFW installed but inactive",
            severity="info" if active else "high",
            status="pass" if active else "fail",
            evidence=ufw_out[:1_000],
            recommendation=None if active else "Enable UFW and define least-privilege rules",
        ))
        return AuditSection(name="Firewall Rules", findings=findings)

    # nftables
    nft_out, _, nft_rc = _run_cmd(req, ["nft", "list", "ruleset"], timeout=20)
    if nft_rc == 0:
        has_rules = bool(nft_out.strip())
        findings.append(AuditFinding(
            category="firewall",
            title="nftables ruleset present" if has_rules else "nftables — no ruleset loaded",
            severity="info" if has_rules else "high",
            status="pass" if has_rules else "fail",
            evidence=nft_out[:1_200] if has_rules else None,
            recommendation=None if has_rules else "Load a restrictive nftables ruleset",
        ))
        return AuditSection(name="Firewall Rules", findings=findings)

    # iptables
    ipt_out, _, ipt_rc = _run_cmd(req, ["iptables", "-S"], timeout=20)
    if ipt_rc == 0:
        has_rules = bool(ipt_out.strip())
        findings.append(AuditFinding(
            category="firewall",
            title="iptables rules present" if has_rules else "iptables — no rules returned",
            severity="info" if has_rules else "high",
            status="pass" if has_rules else "fail",
            evidence=ipt_out[:1_200] if has_rules else None,
            recommendation=None if has_rules else "Add default-deny with explicit allowlist",
        ))
        return AuditSection(name="Firewall Rules", findings=findings)

    findings.append(AuditFinding(
        category="firewall",
        title="No supported firewall tool detected (ufw/nftables/iptables)",
        severity="high", status="fail",
        recommendation="Install and configure ufw, nftables, or iptables",
    ))
    return AuditSection(name="Firewall Rules", findings=findings)


def _audit_users_sudoers(req: LinuxConfigAuditRequest) -> AuditSection:
    """
    Users, UID-0 check, interactive shells, sudoers permissions.
    NOTE: /etc/shadow permission check is intentionally in _audit_file_permissions
    to avoid duplicate findings.
    """
    findings: list[AuditFinding] = []

    # ── /etc/passwd ────────────────────────────────────────────
    passwd_data = _read_path(req, "/etc/passwd")
    if passwd_data:
        uid0: list[str] = []
        shell_users: list[str] = []
        nologin = {"/usr/sbin/nologin", "/bin/false", ""}
        for line in passwd_data.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, _, _, _, shell = parts
            if uid == "0":
                uid0.append(user)
            if shell.strip() not in nologin:
                shell_users.append(user)

        if len(uid0) > 1:
            findings.append(AuditFinding(
                category="users", title="Multiple UID-0 accounts detected",
                severity="critical", status="fail",
                evidence=", ".join(uid0),
                recommendation="Restrict UID 0 to root only",
                file_path="/etc/passwd",
            ))
        else:
            findings.append(AuditFinding(
                category="users", title="Only root has UID 0",
                severity="info", status="pass",
                evidence=", ".join(uid0) or "root",
            ))

        findings.append(AuditFinding(
            category="users", title="Interactive shell users enumerated",
            severity="info", status="info",
            evidence=", ".join(shell_users[:50]),
            file_path="/etc/passwd",
            extra={"count": len(shell_users)},
        ))

    # ── /etc/sudoers ───────────────────────────────────────────
    sudoers_stat = _stat_path(req, "/etc/sudoers")
    if sudoers_stat:
        ok = sudoers_stat["mode_octal"] == "0o440"
        findings.append(AuditFinding(
            category="sudoers",
            title="/etc/sudoers permissions correct (0440)" if ok
                  else "Unexpected /etc/sudoers permissions",
            severity="info" if ok else "high",
            status="pass" if ok else "fail",
            evidence=json.dumps(sudoers_stat),
            recommendation=None if ok else "chmod 0440 /etc/sudoers",
            file_path="/etc/sudoers",
        ))

    sudoers_data = _read_path(req, "/etc/sudoers")
    if sudoers_data and re.search(r"NOPASSWD", sudoers_data):
        findings.append(AuditFinding(
            category="sudoers", title="NOPASSWD entries in /etc/sudoers",
            severity="high", status="warning",
            evidence="NOPASSWD present",
            recommendation="Review and minimise passwordless sudo access",
            file_path="/etc/sudoers",
        ))

    for inc in _list_glob_paths(req, "/etc/sudoers.d/*"):
        st = _stat_path(req, inc)
        if st and st["mode_octal"] != "0o440":
            findings.append(AuditFinding(
                category="sudoers",
                title=f"Unexpected sudoers.d permissions: {inc}",
                severity="medium", status="warning",
                evidence=json.dumps(st),
                recommendation="chmod 0440 " + inc,
                file_path=inc,
            ))
        data = _read_path(req, inc)
        if data and "NOPASSWD" in data:
            findings.append(AuditFinding(
                category="sudoers", title=f"NOPASSWD in {inc}",
                severity="high", status="warning",
                recommendation="Restrict passwordless sudo entries",
                file_path=inc,
            ))

    return AuditSection(name="Users / Sudoers", findings=findings)


def _audit_ports_services(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []

    # prefer ss, fall back to netstat
    ss_out, _, ss_rc = _run_cmd(req, ["ss", "-tulpn"], timeout=30)
    if ss_rc != 0:
        ss_out, _, _ = _run_cmd(req, ["netstat", "-tulpn"], timeout=30)

    if not ss_out.strip():
        findings.append(AuditFinding(
            category="services", title="Could not enumerate listening services",
            severity="medium", status="warning",
            recommendation="Run with sufficient privileges or install ss/netstat",
        ))
        return AuditSection(name="Open Ports / Services", findings=findings)

    listening = [l for l in ss_out.splitlines() if re.search(r"LISTEN|UNCONN", l)]
    findings.append(AuditFinding(
        category="services", title="Listening sockets enumerated",
        severity="info", status="info",
        evidence="\n".join(listening[:50]),
        extra={"count": len(listening)},
    ))

    # FIX: IPv4 :port AND IPv6 :::port AND *:port patterns
    for line in listening:
        m = re.search(r"[:\*](\d+)\s", line)
        if not m:
            continue
        port = int(m.group(1))
        if port in _RISKY_PORTS:
            severity, rec = _RISKY_PORTS[port]
            findings.append(AuditFinding(
                category="services",
                title=f"Risky listening port: {port}",
                severity=severity, status="warning",
                evidence=line.strip(),
                recommendation=rec,
            ))

    # running systemd services
    svc_out, _, svc_rc = _run_cmd(
        req,
        ["systemctl", "list-units", "--type=service", "--state=running",
         "--no-pager", "--no-legend"],
        timeout=30,
    )
    if svc_rc == 0 and svc_out.strip():
        findings.append(AuditFinding(
            category="services", title="Running systemd services",
            severity="info", status="info",
            evidence="\n".join(svc_out.splitlines()[:40]),
        ))

    return AuditSection(name="Open Ports / Services", findings=findings)


def _audit_file_permissions(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []

    # ── Critical file permission checks ───────────────────────
    file_checks: list[tuple[str, list[str], str, str]] = [
        # (path, allowed_modes, severity, recommendation)
        ("/etc/passwd",         ["0o644", "0o640"],    "medium",   "chmod 644 /etc/passwd"),
        ("/etc/shadow",         ["0o600", "0o640"],    "critical", "chmod 600 /etc/shadow"),
        ("/etc/group",          ["0o644", "0o640"],    "medium",   "chmod 644 /etc/group"),
        ("/etc/gshadow",        ["0o600", "0o640"],    "high",     "chmod 600 /etc/gshadow"),
        ("/etc/ssh/sshd_config",["0o600", "0o644"],   "medium",   "chmod 600 /etc/ssh/sshd_config"),
    ]

    for path, allowed, severity, rec in file_checks:
        if not _path_exists(req, path):
            continue
        st = _stat_path(req, path)
        if not st:
            continue
        ok = st["mode_octal"] in allowed
        findings.append(AuditFinding(
            category="permissions",
            title=f"{path} permissions OK ({st['mode_octal']})" if ok
                  else f"Weak permissions on {path}: {st['mode_octal']}",
            severity="info" if ok else severity,
            status="pass" if ok else "fail",
            evidence=json.dumps(st),
            recommendation=None if ok else rec,
            file_path=path,
        ))

    # ── /tmp sticky bit ────────────────────────────────────────
    if _path_exists(req, "/tmp"):
        st_tmp = _stat_path(req, "/tmp")
        mode_int = int(st_tmp["mode_octal"], 8) if st_tmp else 0
        sticky = bool(mode_int & stat.S_ISVTX)
        findings.append(AuditFinding(
            category="permissions",
            title="/tmp sticky bit present" if sticky else "/tmp missing sticky bit",
            severity="info" if sticky else "high",
            status="pass" if sticky else "fail",
            evidence=oct(mode_int),
            recommendation=None if sticky else "chmod 1777 /tmp",
            file_path="/tmp",
        ))

    # ── World-writable files in sensitive dirs (aggressive only) ─────────────
    if req.aggressive:
        if _is_remote(req):
            ww_cmd = _with_sudo_prefix(
                req,
                "find /etc /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 2>/dev/null | head -n 200",
            )
            ww_out, _, ww_rc = _safe_remote_execute(req, ww_cmd, timeout=min(120, req.timeout))
            if ww_rc == 0:
                for fp in [l.strip() for l in ww_out.splitlines() if l.strip()][:200]:
                    findings.append(AuditFinding(
                        category="permissions",
                        title=f"World-writable file: {fp}",
                        severity="high", status="warning",
                        recommendation="chmod o-w " + fp,
                        file_path=fp,
                    ))
        else:
            for root_path in ["/etc", "/usr/local/bin", "/usr/local/sbin"]:
                if not os.path.isdir(root_path):
                    continue
                try:
                    for dirpath, _, filenames in os.walk(root_path):
                        for fn in filenames:
                            fp = os.path.join(dirpath, fn)
                            try:
                                mode = stat.S_IMODE(os.stat(fp).st_mode)
                                if mode & 0o002:
                                    findings.append(AuditFinding(
                                        category="permissions",
                                        title=f"World-writable file: {fp}",
                                        severity="high", status="warning",
                                        evidence=oct(mode),
                                        recommendation="chmod o-w " + fp,
                                        file_path=fp,
                                    ))
                            except OSError:
                                continue
                except OSError:
                    continue

    return AuditSection(name="File Permissions", findings=findings)


def _audit_pam(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []
    pam_paths = [
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/login.defs",
    ]

    combined = ""
    found: list[str] = []
    for p in pam_paths:
        data = _read_path(req, p)
        if data:
            combined += "\n" + data
            found.append(p)

    if not combined:
        findings.append(AuditFinding(
            category="pam", title="PAM configuration not readable",
            severity="medium", status="warning",
            recommendation="Review PAM stack for password policy and lockout controls",
        ))
        return AuditSection(name="PAM / Authentication", findings=findings)

    # password quality module
    has_quality = bool(re.search(r"pam_pwquality\.so|pam_cracklib\.so", combined))
    findings.append(AuditFinding(
        category="pam",
        title="Password quality module configured" if has_quality
              else "No password quality PAM module detected",
        severity="info" if has_quality else "high",
        status="pass" if has_quality else "warning",
        evidence=", ".join(found),
        recommendation=None if has_quality
                       else "Enable pam_pwquality or pam_cracklib",
    ))

    # account lockout module
    has_lockout = bool(re.search(r"pam_faillock\.so|pam_tally2\.so", combined))
    findings.append(AuditFinding(
        category="pam",
        title="Account lockout module configured" if has_lockout
              else "No PAM account lockout module detected",
        severity="info" if has_lockout else "high",
        status="pass" if has_lockout else "warning",
        evidence=", ".join(found),
        recommendation=None if has_lockout
                       else "Enable pam_faillock or pam_tally2",
    ))

    # /etc/login.defs password aging
    login_defs = _read_path(req, "/etc/login.defs")
    if login_defs:
        for key, desired in [
            ("PASS_MAX_DAYS", "90"),
            ("PASS_MIN_DAYS", "1"),
            ("PASS_WARN_AGE", "7"),
        ]:
            m = re.search(rf"^\s*{re.escape(key)}\s+(\S+)", login_defs, re.MULTILINE)
            if not m:
                findings.append(AuditFinding(
                    category="pam",
                    title=f"{key} not configured in /etc/login.defs",
                    severity="medium", status="warning",
                    recommendation=f"Set {key} {desired}",
                    file_path="/etc/login.defs",
                ))
            else:
                findings.append(AuditFinding(
                    category="pam", title=f"{key} configured ({m.group(1)})",
                    severity="info", status="pass",
                    evidence=f"{key} {m.group(1)}",
                    file_path="/etc/login.defs",
                ))

    return AuditSection(name="PAM / Authentication", findings=findings)


def _audit_lynis(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []

    if _is_remote(req):
        check_cmd = _with_sudo_prefix(req, "command -v lynis >/dev/null 2>&1")
        _, _, exists_rc = _safe_remote_execute(req, check_cmd, timeout=15)
        has_lynis = exists_rc == 0
    else:
        has_lynis = _cmd_exists("lynis")

    if not has_lynis:
        findings.append(AuditFinding(
            category="lynis", title="Lynis not installed",
            severity="medium", status="warning",
            recommendation="Install lynis for deep CIS-benchmark auditing",
        ))
        return AuditSection(name="Lynis", findings=findings)

    cmd = ["lynis", "audit", "system", "--quick", "--no-colors"] + req.args
    stdout, stderr, rc = _run_cmd(req, cmd, timeout=req.timeout)

    if rc != 0 and not stdout:
        findings.append(AuditFinding(
            category="lynis", title="Lynis execution failed",
            severity="medium", status="warning",
            evidence=stderr[:_ERR_LIMIT],
        ))
        return AuditSection(name="Lynis", findings=findings)

    for w in re.findall(r"\[WARNING\]\s+(.*)", stdout)[:100]:
        findings.append(AuditFinding(
            category="lynis", title="Lynis warning",
            severity="medium", status="warning", evidence=w,
        ))
    for s in re.findall(r"\[SUGGESTION\]\s+(.*)", stdout)[:100]:
        findings.append(AuditFinding(
            category="lynis", title="Lynis suggestion",
            severity="low", status="info", evidence=s,
        ))

    hi = re.search(r"Hardening index\s*:\s*(\d+)", stdout)
    if hi:
        findings.append(AuditFinding(
            category="lynis", title=f"Lynis hardening index: {hi.group(1)}",
            severity="info", status="info", evidence=hi.group(1),
        ))

    if not findings:
        findings.append(AuditFinding(
            category="lynis", title="Lynis completed — no warnings parsed",
            severity="info", status="info", evidence=stdout[:1_000],
        ))

    return AuditSection(name="Lynis", findings=findings)


def _audit_aggressive_probe(req: LinuxConfigAuditRequest) -> AuditSection:
    findings: list[AuditFinding] = []

    suid_cmd = ["find", "/", "-xdev", "-perm", "-4000", "-type", "f"]
    suid_out, suid_err, suid_rc = _run_cmd(req, suid_cmd, timeout=min(req.timeout, 180))
    if suid_rc == 0 and suid_out.strip():
        lines = [l.strip() for l in suid_out.splitlines() if l.strip()]
        findings.append(AuditFinding(
            category="aggressive",
            title="SUID binaries discovered (aggressive)",
            severity="medium",
            status="warning",
            evidence="\n".join(lines[:80]),
            recommendation="Review SUID binaries for privilege escalation paths",
            extra={"count": len(lines)},
        ))
    elif suid_err.strip():
        findings.append(AuditFinding(
            category="aggressive",
            title="SUID discovery incomplete",
            severity="low",
            status="info",
            evidence=suid_err[:_ERR_LIMIT],
        ))

    cron_cmd = ["find", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "-xdev", "-type", "f", "-perm", "-0002"]
    cron_out, _, cron_rc = _run_cmd(req, cron_cmd, timeout=min(req.timeout, 120))
    if cron_rc == 0 and cron_out.strip():
        files = [l.strip() for l in cron_out.splitlines() if l.strip()]
        findings.append(AuditFinding(
            category="aggressive",
            title="World-writable cron files detected",
            severity="critical",
            status="fail",
            evidence="\n".join(files[:50]),
            recommendation="Remove world-write permissions from cron paths",
            extra={"count": len(files)},
        ))
    else:
        findings.append(AuditFinding(
            category="aggressive",
            title="No world-writable cron files found",
            severity="info",
            status="pass",
        ))

    return AuditSection(name="Aggressive Checks", findings=findings)


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

_MODE_SECTIONS: dict[str, list[str]] = {
    "quick":    ["ssh", "firewall", "ports"],
    "standard": ["ssh", "firewall", "users", "ports", "files", "pam"],
    "deep":     ["ssh", "firewall", "users", "ports", "files", "pam", "lynis"],
    "lynis":    ["lynis"],
}

_SECTION_BUILDERS = {
    "ssh":      _audit_ssh,
    "firewall": _audit_firewall,
    "users":    _audit_users_sudoers,
    "ports":    _audit_ports_services,
    "files":    _audit_file_permissions,
    "pam":      _audit_pam,
}


def linux_config_audit(
    mode: str = "standard",
    target: str = "local",
    username: Optional[str] = None,
    password: Optional[str] = None,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
    use_sudo: bool = False,
    aggressive: bool = False,
    args: Optional[list[str]] = None,
    timeout: int = 900,
) -> dict[str, Any]:
    """
    Linux security configuration audit — returns structured dict, never writes to disk.

    Args:
        mode    : quick | standard | deep | lynis
        target  : 'local' or remote IP/domain
        username: SSH username for remote target
        password: SSH password (requires sshpass)
        ssh_key : SSH private key path for remote auth
        ssh_port: SSH TCP port (default 22)
        use_sudo: Run remote commands with sudo -n prefix
        aggressive: Enable additional aggressive privilege-escalation checks
        args    : extra Lynis flags when mode=deep/lynis
        timeout : max seconds for the entire run (10–3600)

    Returns:
        LinuxConfigAuditResult as dict with keys:
        success, mode, target, remote, command, hostname, os_info, total_findings,
        severity_summary, sections, error, execution_time
    """
    start = time.monotonic()
    args  = args or []

    def _fail(msg: str) -> dict[str, Any]:
        return LinuxConfigAuditResult(
            success=False, mode=mode, command="", error=msg,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    try:
        req = LinuxConfigAuditRequest(
            mode=mode,
            target=target,
            username=username,
            password=password,
            ssh_key=ssh_key,
            ssh_port=ssh_port,
            use_sudo=use_sudo,
            aggressive=aggressive,
            args=args,
            timeout=timeout,
        )
    except Exception as exc:
        return _fail(f"Validation: {exc}")

    sections: list[AuditSection] = []
    section_keys = _MODE_SECTIONS[req.mode]

    for key in section_keys:
        if key == "lynis":
            sections.append(_audit_lynis(req))
        else:
            sections.append(_SECTION_BUILDERS[key](req))

    if req.aggressive:
        sections.append(_audit_aggressive_probe(req))

    # ── Aggregate severity summary ─────────────────────────────
    severity_summary: dict[str, int] = {}
    total = 0
    for section in sections:
        for f in section.findings:
            total += 1
            severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    command = f"linux_config_audit mode={req.mode} target={req.target}"
    if req.target != "local":
        command += f" ssh={req.username}@{req.target}:{req.ssh_port}"
    if req.use_sudo:
        command += " sudo=true"
    if req.aggressive:
        command += " aggressive=true"
    if req.mode in ("deep", "lynis") and req.args:
        command += " args=" + " ".join(req.args)

    return LinuxConfigAuditResult(
        success=True,
        mode=req.mode,
        target=req.target,
        remote=_is_remote(req),
        command=command,
        hostname=(
            (_run_cmd(req, ["hostname"], timeout=10)[0].strip() if _is_remote(req) else socket.gethostname())
            or None
        ),
        os_info=_get_os_info_for(req),
        total_findings=total,
        severity_summary=severity_summary,
        sections=sections,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

LINUX_CONFIG_AUDIT_TOOL_DEFINITION: dict[str, Any] = {
    "name": "linux_config_audit",
    "description": (
        "Audit Linux host/server security configuration locally or over SSH by IP/hostname: "
        "SSH hardening, firewall rules, "
        "users/UID-0/sudoers, open ports, file permissions, and PAM policy. "
        "Optionally runs Lynis for deep CIS-benchmark auditing and aggressive checks. "
        "Returns structured findings by section with severity and remediation guidance. "
        "Never writes to disk."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": sorted(_ALLOWED_MODES),
                "default": "standard",
                "description": (
                    "quick    = SSH + firewall + ports only |\n"
                    "standard = full baseline audit (default) |\n"
                    "deep     = standard + Lynis |\n"
                    "lynis    = Lynis only"
                ),
            },
            "target": {
                "type": "string",
                "default": "local",
                "description": "Target host for audit. Use 'local' for current machine or provide remote IP/domain.",
            },
            "username": {
                "type": "string",
                "description": "SSH username for remote target audit.",
            },
            "password": {
                "type": "string",
                "description": "SSH password for remote target (requires sshpass installed).",
            },
            "ssh_key": {
                "type": "string",
                "description": "Path to SSH private key for remote target authentication.",
            },
            "ssh_port": {
                "type": "integer",
                "default": 22,
                "minimum": 1,
                "maximum": 65535,
                "description": "SSH port for remote target.",
            },
            "use_sudo": {
                "type": "boolean",
                "default": False,
                "description": "Run remote commands with sudo -n for deeper audit visibility.",
            },
            "aggressive": {
                "type": "boolean",
                "default": False,
                "description": "Enable aggressive checks (e.g., SUID sweep and writable cron search).",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Extra Lynis flags for deep/lynis mode. "
                    "e.g. ['--tests-from-group', 'authentication,networking']"
                ),
            },
            "timeout": {
                "type": "integer",
                "default": 900,
                "minimum": 10,
                "maximum": 3600,
                "description": "Max execution time in seconds.",
            },
        },
        "required": [],
    },
}


# ══════════════════════════════════════════════════════════════
# 7. HELPERS
# ══════════════════════════════════════════════════════════════

def _sep(char: str = "─", width: int = 64) -> str:
    return char * width


def _print_result(label: str, r: dict) -> None:
    print(f"\n{_sep()}\n  {label}\n{_sep()}")
    print(f"  success        : {r['success']}")
    print(f"  mode           : {r['mode']}")
    print(f"  target         : {r.get('target', 'local')}")
    print(f"  remote         : {r.get('remote', False)}")
    print(f"  hostname       : {r.get('hostname')}")
    print(f"  total_findings : {r['total_findings']}")
    print(f"  execution_time : {r['execution_time']}s")
    print(f"  severity       : {r['severity_summary']}")
    if r.get("error"):
        print(f"  error          : {r['error'][:200]}")
    for section in r.get("sections", []):
        fails = [f for f in section["findings"] if f["status"] in ("fail", "warning")]
        passes = [f for f in section["findings"] if f["status"] == "pass"]
        print(f"\n  [{section['name']}]  {len(passes)} pass  {len(fails)} fail/warn")
        for f in fails[:5]:
            sev = f["severity"].upper()
            print(f"    [{sev:8s}] {f['title']}")
            if f.get("recommendation"):
                print(f"             → {f['recommendation']}")
    print(_sep())


# ══════════════════════════════════════════════════════════════
# 8. MAIN — validation + live tests
# ══════════════════════════════════════════════════════════════

_MAIN_TEST_TARGET = "10.129.22.137"
_MAIN_TEST_USER_ENV = "PENTAFORGE_LINUX_AUDIT_USERNAME"
_MAIN_TEST_PASS_ENV = "PENTAFORGE_LINUX_AUDIT_PASSWORD"
_MAIN_TEST_KEY_ENV = "PENTAFORGE_LINUX_AUDIT_SSH_KEY"


def _prompt_live_auth(target: str) -> Optional[dict[str, Any]]:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None

    print(f"  Interactive auth for remote target {target}")
    username = input("  SSH username (leave blank to skip): ").strip()
    if not username:
        return None

    method = input("  Auth method [password/key] (default: password): ").strip().lower() or "password"
    password: Optional[str] = None
    ssh_key: Optional[str] = None

    if method == "key":
        ssh_key = input("  SSH private key path: ").strip() or None
        if not ssh_key:
            print("  No key path provided; skipping live tests.")
            return None
    else:
        password = getpass.getpass("  SSH password: ").strip() or None
        if password is None:
            print("  Empty password provided; skipping live tests.")
            return None

    use_sudo_in = input("  Use sudo for remote commands? [y/N]: ").strip().lower()
    use_sudo = use_sudo_in in {"y", "yes", "1", "true"}

    return {
        "username": username,
        "password": password,
        "ssh_key": ssh_key,
        "use_sudo": use_sudo,
    }

def _run_validation_tests() -> bool:
    cases: list[tuple[str, dict]] = [
        ("PASS — invalid mode",         dict(mode="hack")),
        ("PASS — remote without username", dict(target=_MAIN_TEST_TARGET)),
        ("PASS — dangerous username", dict(target=_MAIN_TEST_TARGET, username="root;id")),
        ("PASS — injection in arg ;",   dict(mode="lynis", args=["bad;arg"])),
        ("PASS — injection in arg |",   dict(mode="lynis", args=["bad|arg"])),
        ("PASS — injection in arg >",   dict(mode="lynis", args=[">evil"])),
        ("PASS — blocked flag --output",dict(mode="lynis", args=["--output"])),
        ("PASS — timeout out of range", dict(mode="standard", timeout=5)),
    ]

    print(f"\n{_sep('═')}")
    print("  VALIDATION TESTS  (all should fail with error)")
    print(_sep("═"))

    all_ok = True
    for label, kwargs in cases:
        result = linux_config_audit(**kwargs)
        ok     = not result["success"] and bool(result["error"])
        if not ok:
            all_ok = False
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}  {label}")
        if not ok:
            print(f"         → unexpected: {result['error']}")

    print(f"\n  Validation suite: {'all passed ✅' if all_ok else 'FAILURES ❌'}")
    return all_ok


def _run_live_tests(
    target_override: Optional[str] = None,
    username_override: Optional[str] = None,
    password_override: Optional[str] = None,
    ssh_key_override: Optional[str] = None,
    ssh_port_override: Optional[int] = None,
    use_sudo_override: Optional[bool] = None,
) -> None:
    target = target_override or _MAIN_TEST_TARGET
    username = username_override or os.getenv(_MAIN_TEST_USER_ENV)
    password = password_override if password_override is not None else os.getenv(_MAIN_TEST_PASS_ENV)
    ssh_key = ssh_key_override if ssh_key_override is not None else os.getenv(_MAIN_TEST_KEY_ENV)

    if ssh_port_override is not None:
        ssh_port = ssh_port_override
    else:
        try:
            ssh_port = int(os.getenv("PENTAFORGE_LINUX_AUDIT_SSH_PORT", "22"))
        except Exception:
            ssh_port = 22

    if use_sudo_override is not None:
        use_sudo = use_sudo_override
    else:
        use_sudo = os.getenv("PENTAFORGE_LINUX_AUDIT_USE_SUDO", "0") == "1"

    print(f"\n{_sep('═')}")
    print(f"  LIVE TESTS — remote target {target}")
    print(_sep("═"))

    if not username:
        prompted = _prompt_live_auth(target)
        if prompted:
            username = prompted.get("username")
            password = prompted.get("password")
            ssh_key = prompted.get("ssh_key")
            use_sudo = bool(prompted.get("use_sudo"))

    if not username:
        print(
            "  Skipping live remote tests: provide --username (plus --password or --ssh-key), "
            f"or set {_MAIN_TEST_USER_ENV} (and optionally {_MAIN_TEST_PASS_ENV}/{_MAIN_TEST_KEY_ENV}) "
            f"to run against {target}."
        )
        return

    base_kwargs: dict[str, Any] = {
        "target": target,
        "username": username,
        "password": password,
        "ssh_key": ssh_key,
        "ssh_port": ssh_port,
        "use_sudo": use_sudo,
    }

    _print_result("quick — SSH + firewall + ports",
                  linux_config_audit(mode="quick", timeout=60, **base_kwargs))

    _print_result("standard — full baseline audit",
                  linux_config_audit(mode="standard", timeout=120, **base_kwargs))

    _print_result("lynis — Lynis only (reports not installed if missing)",
                  linux_config_audit(mode="lynis", timeout=300, **base_kwargs))

    _print_result("aggressive — remote deep checks",
                  linux_config_audit(mode="standard", aggressive=True, timeout=180, **base_kwargs))

    # Full JSON of standard
    print(f"\n{_sep('═')}")
    print(f"  FULL JSON — standard mode ({target})")
    print(_sep("═"))
    result = linux_config_audit(mode="standard", timeout=120, **base_kwargs)
    print(json.dumps(result, indent=2))


def _parse_main_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run linux_config_audit validation suite and remote live tests.",
    )
    parser.add_argument(
        "--target",
        default=_MAIN_TEST_TARGET,
        help=f"Remote target IP/domain for live tests (default: {_MAIN_TEST_TARGET}).",
    )
    parser.add_argument("--username", help="SSH username for remote live tests.")
    parser.add_argument("--password", help="SSH password for remote live tests.")
    parser.add_argument("--ssh-key", dest="ssh_key", help="Path to SSH private key.")
    parser.add_argument("--ssh-port", dest="ssh_port", type=int, help="SSH port (default: 22).")
    parser.add_argument(
        "--use-sudo",
        dest="use_sudo",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Use sudo for remote commands (use --no-use-sudo to disable).",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip validation tests and run live tests only.",
    )
    return parser.parse_args()


def main() -> None:
    ns = _parse_main_args()
    if not ns.skip_validation:
        _run_validation_tests()
    _run_live_tests(
        target_override=ns.target,
        username_override=ns.username,
        password_override=ns.password,
        ssh_key_override=ns.ssh_key,
        ssh_port_override=ns.ssh_port,
        use_sudo_override=ns.use_sudo,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)