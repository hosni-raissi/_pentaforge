import subprocess
import json
import re
import time
import os
import stat
import pwd
import grp
import glob
import socket
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class LinuxConfigAuditRequest(BaseModel):
    mode: str = "standard"
    args: list[str] = []
    timeout: int = Field(default=900, ge=30, le=3600)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        allowed = {"quick", "standard", "deep", "lynis"}
        if v not in allowed:
            raise ValueError(f"Mode '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--report-file"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")
        return v


class AuditFinding(BaseModel):
    category: str
    title: str
    severity: str = "info"   # critical, high, medium, low, info
    status: str = "info"     # pass, fail, warning, info
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    file_path: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class AuditSection(BaseModel):
    name: str
    findings: list[AuditFinding] = []


class LinuxConfigAuditResult(BaseModel):
    success: bool
    mode: str
    command: str
    hostname: Optional[str] = None
    os_info: Optional[dict[str, Any]] = None
    total_findings: int = 0
    severity_summary: dict[str, int] = {}
    sections: list[AuditSection] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 900) -> tuple[str, str, int]:
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
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

def read_file_safe(path: str, max_bytes: int = 200000) -> tuple[Optional[str], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_bytes), None
    except Exception as e:
        return None, str(e)


def file_stat_info(path: str) -> Optional[dict[str, Any]]:
    try:
        st = os.stat(path)
        return {
            "mode_octal": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": pwd.getpwuid(st.st_uid).pw_name if st.st_uid is not None else None,
            "group": grp.getgrgid(st.st_gid).gr_name if st.st_gid is not None else None,
        }
    except Exception:
        return None


def get_os_info() -> dict[str, Any]:
    info = {}
    data, _ = read_file_safe("/etc/os-release")
    if data:
        for line in data.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip().strip('"')
    uname_out, _, _ = safe_execute(["uname", "-a"], timeout=10)
    if uname_out:
        info["uname"] = uname_out.strip()
    return info


def command_exists(name: str) -> bool:
    _, _, rc = safe_execute(["which", name], timeout=10)
    return rc == 0


def parse_key_value_config(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if " " in line:
            k, v = line.split(None, 1)
            result[k.strip()] = v.strip()
    return result


# ══════════════════════════════════════════════════════════════
# 4. AUDIT CHECKS
# ══════════════════════════════════════════════════════════════

def audit_ssh() -> AuditSection:
    findings = []
    sshd_paths = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))

    merged = ""
    for p in sshd_paths:
        content, err = read_file_safe(p)
        if content:
            merged += "\n" + content

    if not merged:
        findings.append(AuditFinding(
            category="ssh",
            title="SSH configuration not readable",
            severity="medium",
            status="warning",
            recommendation="Ensure /etc/ssh/sshd_config is present and readable",
        ))
        return AuditSection(name="SSH Hardening", findings=findings)

    cfg = parse_key_value_config(merged)

    def check_setting(key: str, expected: list[str], severity="medium", recommendation=None):
        val = cfg.get(key)
        if val is None:
            findings.append(AuditFinding(
                category="ssh",
                title=f"SSH setting '{key}' not explicitly configured",
                severity=severity,
                status="warning",
                evidence="Not found in sshd_config",
                recommendation=recommendation or f"Set {key} {' or '.join(expected)} explicitly",
                file_path="/etc/ssh/sshd_config",
            ))
        elif val not in expected:
            findings.append(AuditFinding(
                category="ssh",
                title=f"Weak SSH setting: {key}={val}",
                severity=severity,
                status="fail",
                evidence=f"{key} {val}",
                recommendation=recommendation or f"Set {key} {' or '.join(expected)}",
                file_path="/etc/ssh/sshd_config",
            ))
        else:
            findings.append(AuditFinding(
                category="ssh",
                title=f"SSH setting OK: {key}={val}",
                severity="info",
                status="pass",
                evidence=f"{key} {val}",
                file_path="/etc/ssh/sshd_config",
            ))

    check_setting("PermitRootLogin", ["no"], "high", "Disable direct root SSH login")
    check_setting("PasswordAuthentication", ["no"], "high", "Disable password auth and use keys")
    check_setting("PubkeyAuthentication", ["yes"], "medium", "Enable public key authentication")
    check_setting("PermitEmptyPasswords", ["no"], "high", "Disallow empty SSH passwords")
    check_setting("X11Forwarding", ["no"], "low", "Disable X11 forwarding if not needed")
    check_setting("MaxAuthTries", ["3", "4"], "medium", "Reduce brute-force surface with low MaxAuthTries")
    check_setting("ClientAliveInterval", ["300", "600"], "low", "Set idle timeout")
    check_setting("LoginGraceTime", ["30", "60"], "low", "Reduce login grace time")

    return AuditSection(name="SSH Hardening", findings=findings)


def audit_firewall() -> AuditSection:
    findings = []

    ufw_out, ufw_err, ufw_rc = safe_execute(["ufw", "status", "verbose"], timeout=20)
    if ufw_rc == 0:
        if "Status: active" in ufw_out:
            findings.append(AuditFinding(
                category="firewall",
                title="UFW is active",
                severity="info",
                status="pass",
                evidence=ufw_out[:1000],
            ))
        else:
            findings.append(AuditFinding(
                category="firewall",
                title="UFW is installed but inactive",
                severity="high",
                status="fail",
                evidence=ufw_out[:500],
                recommendation="Enable UFW and define least-privilege rules",
            ))
        return AuditSection(name="Firewall Rules", findings=findings)

    nft_out, _, nft_rc = safe_execute(["nft", "list", "ruleset"], timeout=20)
    if nft_rc == 0:
        if nft_out.strip():
            findings.append(AuditFinding(
                category="firewall",
                title="nftables ruleset present",
                severity="info",
                status="pass",
                evidence=nft_out[:1200],
            ))
        else:
            findings.append(AuditFinding(
                category="firewall",
                title="nftables installed but no ruleset loaded",
                severity="high",
                status="fail",
                recommendation="Load a restrictive nftables ruleset",
            ))
        return AuditSection(name="Firewall Rules", findings=findings)

    ipt_out, _, ipt_rc = safe_execute(["iptables", "-S"], timeout=20)
    if ipt_rc == 0:
        if ipt_out.strip():
            findings.append(AuditFinding(
                category="firewall",
                title="iptables rules present",
                severity="info",
                status="pass",
                evidence=ipt_out[:1200],
            ))
        else:
            findings.append(AuditFinding(
                category="firewall",
                title="iptables installed but no rules returned",
                severity="high",
                status="fail",
                recommendation="Add default-deny rules with explicit allowlist",
            ))
        return AuditSection(name="Firewall Rules", findings=findings)

    findings.append(AuditFinding(
        category="firewall",
        title="No supported firewall tool detected",
        severity="high",
        status="fail",
        recommendation="Install and configure ufw, nftables, or iptables",
    ))
    return AuditSection(name="Firewall Rules", findings=findings)


def audit_users_groups_sudoers() -> AuditSection:
    findings = []

    passwd_data, passwd_err = read_file_safe("/etc/passwd")
    shadow_stat = file_stat_info("/etc/shadow")
    sudoers_stat = file_stat_info("/etc/sudoers")

    if passwd_data:
        system_uid_0 = []
        shell_users = []
        for line in passwd_data.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, gid, gecos, home, shell = parts
            if uid == "0":
                system_uid_0.append(user)
            if shell and shell not in ["/usr/sbin/nologin", "/bin/false", ""]:
                shell_users.append(user)

        if len(system_uid_0) > 1:
            findings.append(AuditFinding(
                category="users",
                title="Multiple UID 0 accounts detected",
                severity="critical",
                status="fail",
                evidence=", ".join(system_uid_0),
                recommendation="Restrict UID 0 to root only",
                file_path="/etc/passwd",
            ))
        else:
            findings.append(AuditFinding(
                category="users",
                title="Only root has UID 0",
                severity="info",
                status="pass",
                evidence=", ".join(system_uid_0) if system_uid_0 else "No UID 0 account parsed",
            ))

        findings.append(AuditFinding(
            category="users",
            title="Interactive shell users enumerated",
            severity="info",
            status="info",
            evidence=", ".join(shell_users[:50]),
            file_path="/etc/passwd",
            extra={"count": len(shell_users)},
        ))

    if shadow_stat:
        if shadow_stat["mode_octal"] != "0o640" and shadow_stat["mode_octal"] != "0o600":
            findings.append(AuditFinding(
                category="permissions",
                title="Weak /etc/shadow permissions",
                severity="critical",
                status="fail",
                evidence=json.dumps(shadow_stat),
                recommendation="Set /etc/shadow to 600 or distro-approved restrictive mode",
                file_path="/etc/shadow",
            ))
        else:
            findings.append(AuditFinding(
                category="permissions",
                title="/etc/shadow permissions are restrictive",
                severity="info",
                status="pass",
                evidence=json.dumps(shadow_stat),
                file_path="/etc/shadow",
            ))

    if sudoers_stat:
        if sudoers_stat["mode_octal"] != "0o440":
            findings.append(AuditFinding(
                category="sudoers",
                title="Unexpected /etc/sudoers permissions",
                severity="high",
                status="fail",
                evidence=json.dumps(sudoers_stat),
                recommendation="Set /etc/sudoers permissions to 0440",
                file_path="/etc/sudoers",
            ))
        else:
            findings.append(AuditFinding(
                category="sudoers",
                title="/etc/sudoers permissions are correct",
                severity="info",
                status="pass",
                evidence=json.dumps(sudoers_stat),
                file_path="/etc/sudoers",
            ))

    sudoers_data, _ = read_file_safe("/etc/sudoers")
    if sudoers_data:
        if re.search(r"NOPASSWD", sudoers_data):
            findings.append(AuditFinding(
                category="sudoers",
                title="NOPASSWD entries found in /etc/sudoers",
                severity="high",
                status="warning",
                evidence="NOPASSWD present",
                recommendation="Review and minimize passwordless sudo access",
                file_path="/etc/sudoers",
            ))

    for inc in sorted(glob.glob("/etc/sudoers.d/*")):
        st = file_stat_info(inc)
        if st and st["mode_octal"] != "0o440":
            findings.append(AuditFinding(
                category="sudoers",
                title=f"Unexpected sudoers include permissions: {inc}",
                severity="medium",
                status="warning",
                evidence=json.dumps(st),
                recommendation="Set include file permissions to 0440",
                file_path=inc,
            ))
        data, _ = read_file_safe(inc)
        if data and "NOPASSWD" in data:
            findings.append(AuditFinding(
                category="sudoers",
                title=f"NOPASSWD found in {inc}",
                severity="high",
                status="warning",
                evidence="NOPASSWD present",
                recommendation="Restrict passwordless sudo entries",
                file_path=inc,
            ))

    return AuditSection(name="Users / Groups / Sudoers", findings=findings)


def audit_open_ports_services() -> AuditSection:
    findings = []

    ss_out, _, ss_rc = safe_execute(["ss", "-tulpn"], timeout=30)
    if ss_rc != 0:
        netstat_out, _, netstat_rc = safe_execute(["netstat", "-tulpn"], timeout=30)
        ss_out = netstat_out if netstat_rc == 0 else ""

    if not ss_out.strip():
        findings.append(AuditFinding(
            category="services",
            title="Could not enumerate listening services",
            severity="medium",
            status="warning",
            recommendation="Install ss/netstat or run with sufficient privileges",
        ))
        return AuditSection(name="Open Ports / Running Services", findings=findings)

    listening = []
    for line in ss_out.splitlines():
        if re.search(r"LISTEN|UNCONN", line):
            listening.append(line)

    findings.append(AuditFinding(
        category="services",
        title="Listening sockets enumerated",
        severity="info",
        status="info",
        evidence="\n".join(listening[:50]),
        extra={"count": len(listening)},
    ))

    risky_ports = {
        21: "FTP is insecure in cleartext",
        23: "Telnet is insecure in cleartext",
        25: "SMTP may expose relay/auth paths if misconfigured",
        111: "rpcbind expands attack surface",
        445: "SMB exposed",
        3306: "MySQL exposed",
        5432: "PostgreSQL exposed",
        6379: "Redis exposed",
        27017: "MongoDB exposed",
    }

    for line in listening:
        m = re.search(r":(\d+)\s", line)
        if not m:
            continue
        port = int(m.group(1))
        if port in risky_ports:
            findings.append(AuditFinding(
                category="services",
                title=f"Potentially risky listening port: {port}",
                severity="high" if port in [21, 23, 445, 6379, 27017] else "medium",
                status="warning",
                evidence=line,
                recommendation=risky_ports[port],
            ))

    systemctl_out, _, systemctl_rc = safe_execute(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"], timeout=30)
    if systemctl_rc == 0 and systemctl_out.strip():
        findings.append(AuditFinding(
            category="services",
            title="Running systemd services enumerated",
            severity="info",
            status="info",
            evidence="\n".join(systemctl_out.splitlines()[:40]),
        ))

    return AuditSection(name="Open Ports / Running Services", findings=findings)


def audit_file_permissions() -> AuditSection:
    findings = []

    critical_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/ssh/sshd_config",
        "/root",
        "/tmp",
    ]

    for path in critical_paths:
        if not os.path.exists(path):
            continue
        st = file_stat_info(path)
        if not st:
            continue

        if path == "/etc/passwd" and st["mode_octal"] not in ["0o644", "0o640"]:
            findings.append(AuditFinding(
                category="permissions",
                title="Unexpected /etc/passwd permissions",
                severity="medium",
                status="warning",
                evidence=json.dumps(st),
                recommendation="Set /etc/passwd to distro-approved permissions, typically 0644",
                file_path=path,
            ))

        if path == "/etc/shadow" and st["mode_octal"] not in ["0o600", "0o640"]:
            findings.append(AuditFinding(
                category="permissions",
                title="Weak /etc/shadow permissions",
                severity="critical",
                status="fail",
                evidence=json.dumps(st),
                recommendation="Restrict /etc/shadow permissions",
                file_path=path,
            ))

        if path == "/etc/ssh/sshd_config" and st["mode_octal"] not in ["0o600", "0o644"]:
            findings.append(AuditFinding(
                category="permissions",
                title="Unexpected sshd_config permissions",
                severity="medium",
                status="warning",
                evidence=json.dumps(st),
                recommendation="Set sshd_config to a secure readable mode",
                file_path=path,
            ))

        if path == "/tmp":
            mode = stat.S_IMODE(os.stat(path).st_mode)
            sticky = bool(mode & stat.S_ISVTX)
            if not sticky:
                findings.append(AuditFinding(
                    category="permissions",
                    title="/tmp missing sticky bit",
                    severity="high",
                    status="fail",
                    evidence=oct(mode),
                    recommendation="Set sticky bit on /tmp (chmod 1777 /tmp)",
                    file_path=path,
                ))
            else:
                findings.append(AuditFinding(
                    category="permissions",
                    title="/tmp sticky bit present",
                    severity="info",
                    status="pass",
                    evidence=oct(mode),
                    file_path=path,
                ))

    # world writable files in sensitive paths
    for root_path in ["/etc", "/usr/local/bin", "/usr/local/sbin"]:
        if not os.path.exists(root_path):
            continue
        try:
            for dirpath, _, filenames in os.walk(root_path):
                for fn in filenames[:]:
                    fp = os.path.join(dirpath, fn)
                    try:
                        mode = stat.S_IMODE(os.stat(fp).st_mode)
                        if mode & 0o002:
                            findings.append(AuditFinding(
                                category="permissions",
                                title="World-writable file detected",
                                severity="high",
                                status="warning",
                                evidence=oct(mode),
                                recommendation="Remove world-write permission unless absolutely required",
                                file_path=fp,
                            ))
                    except Exception:
                        continue
        except Exception:
            continue

    return AuditSection(name="File Permissions", findings=findings)


def audit_pam() -> AuditSection:
    findings = []
    pam_files = [
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/login.defs",
    ]

    combined = ""
    found_files = []
    for p in pam_files:
        data, _ = read_file_safe(p)
        if data:
            combined += "\n" + data
            found_files.append(p)

    if not combined:
        findings.append(AuditFinding(
            category="pam",
            title="PAM configuration not readable",
            severity="medium",
            status="warning",
            recommendation="Review PAM stack for password policy and lockout controls",
        ))
        return AuditSection(name="PAM / Authentication", findings=findings)

    if re.search(r"pam_pwquality\.so|pam_cracklib\.so", combined):
        findings.append(AuditFinding(
            category="pam",
            title="Password quality module configured",
            severity="info",
            status="pass",
            evidence=", ".join(found_files),
        ))
    else:
        findings.append(AuditFinding(
            category="pam",
            title="No password quality PAM module detected",
            severity="high",
            status="warning",
            recommendation="Enable pam_pwquality or equivalent password complexity control",
            evidence=", ".join(found_files),
        ))

    if re.search(r"pam_faillock\.so|pam_tally2\.so", combined):
        findings.append(AuditFinding(
            category="pam",
            title="Account lockout module configured",
            severity="info",
            status="pass",
            evidence=", ".join(found_files),
        ))
    else:
        findings.append(AuditFinding(
            category="pam",
            title="No PAM account lockout module detected",
            severity="high",
            status="warning",
            recommendation="Enable pam_faillock or equivalent brute-force protection",
            evidence=", ".join(found_files),
        ))

    login_defs, _ = read_file_safe("/etc/login.defs")
    if login_defs:
        for key, desired in {
            "PASS_MAX_DAYS": "90",
            "PASS_MIN_DAYS": "1",
            "PASS_WARN_AGE": "7",
        }.items():
            m = re.search(rf"^\s*{re.escape(key)}\s+(\S+)", login_defs, re.MULTILINE)
            if not m:
                findings.append(AuditFinding(
                    category="pam",
                    title=f"{key} not configured in /etc/login.defs",
                    severity="medium",
                    status="warning",
                    recommendation=f"Set {key} to an appropriate value such as {desired}",
                    file_path="/etc/login.defs",
                ))
            else:
                findings.append(AuditFinding(
                    category="pam",
                    title=f"{key} configured",
                    severity="info",
                    status="pass",
                    evidence=f"{key} {m.group(1)}",
                    file_path="/etc/login.defs",
                ))

    return AuditSection(name="PAM / Authentication", findings=findings)


def audit_lynis(args: list[str], timeout: int) -> AuditSection:
    findings = []
    if not command_exists("lynis"):
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis not installed",
            severity="medium",
            status="warning",
            recommendation="Install Lynis for deeper host auditing",
        ))
        return AuditSection(name="Lynis", findings=findings)

    cmd = ["lynis", "audit", "system", "--quick", "--no-colors"] + list(args)
    stdout, stderr, rc = safe_execute(cmd, timeout=timeout)

    if rc != 0 and not stdout:
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis execution failed",
            severity="medium",
            status="warning",
            evidence=stderr[:1000],
        ))
        return AuditSection(name="Lynis", findings=findings)

    # Minimal parser
    warnings = re.findall(r"\[WARNING\]\s+(.*)", stdout)
    suggestions = re.findall(r"\[SUGGESTION\]\s+(.*)", stdout)
    hardening_index = re.search(r"Hardening index\s*:\s*(\d+)", stdout)

    for w in warnings[:100]:
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis warning",
            severity="medium",
            status="warning",
            evidence=w,
        ))

    for s in suggestions[:100]:
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis suggestion",
            severity="low",
            status="info",
            evidence=s,
        ))

    if hardening_index:
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis hardening index",
            severity="info",
            status="info",
            evidence=hardening_index.group(1),
        ))

    if not findings:
        findings.append(AuditFinding(
            category="lynis",
            title="Lynis completed with no parsed warnings/suggestions",
            severity="info",
            status="info",
            evidence=stdout[:1000],
        ))

    return AuditSection(name="Lynis", findings=findings)


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def linux_config_audit(mode: str = "standard", args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: Linux Configuration Audit

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  SSH HARDENING       sshd_config review                     │
      │  FIREWALL RULES      ufw / nftables / iptables             │
      │  USERS / GROUPS      UID 0, interactive users              │
      │  SUDOERS REVIEW      sudoers perms, NOPASSWD checks        │
      │  OPEN PORTS          listening sockets, risky services     │
      │  RUNNING SERVICES    systemd running units                 │
      │  FILE PERMISSIONS    sensitive paths, world-writable files │
      │  PAM CONFIG          password policy, faillock             │
      │  LYNIS               optional deep audit                   │
      └─────────────────────────────────────────────────────────────┘

    Args:
        mode: "quick" | "standard" | "deep" | "lynis"
        args: Additional Lynis args when mode="lynis" or "deep"

    Returns:
        Structured JSON audit findings by section
    """

    start = time.time()

    try:
        req = LinuxConfigAuditRequest(mode=mode, args=args)
    except Exception as e:
        return LinuxConfigAuditResult(
            success=False,
            mode=mode,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    sections = []
    commands = []

    # common baseline
    hostname = socket.gethostname()
    os_info = get_os_info()

    if req.mode == "quick":
        sections.append(audit_ssh())
        sections.append(audit_firewall())
        sections.append(audit_open_ports_services())
        commands.append("custom: quick baseline checks")

    elif req.mode == "standard":
        sections.append(audit_ssh())
        sections.append(audit_firewall())
        sections.append(audit_users_groups_sudoers())
        sections.append(audit_open_ports_services())
        sections.append(audit_file_permissions())
        sections.append(audit_pam())
        commands.append("custom: standard baseline checks")

    elif req.mode == "deep":
        sections.append(audit_ssh())
        sections.append(audit_firewall())
        sections.append(audit_users_groups_sudoers())
        sections.append(audit_open_ports_services())
        sections.append(audit_file_permissions())
        sections.append(audit_pam())
        sections.append(audit_lynis(req.args, req.timeout))
        commands.append("custom + lynis deep audit")

    elif req.mode == "lynis":
        sections.append(audit_lynis(req.args, req.timeout))
        commands.append("lynis audit system --quick --no-colors")

    severity_summary: dict[str, int] = {}
    total_findings = 0
    for section in sections:
        for f in section.findings:
            total_findings += 1
            severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1

    return LinuxConfigAuditResult(
        success=True,
        mode=req.mode,
        command=" | ".join(commands),
        hostname=hostname,
        os_info=os_info,
        total_findings=total_findings,
        severity_summary=severity_summary,
        sections=sections,
        raw_output=None,
        error=None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

LINUX_CONFIG_AUDIT_TOOL_DEFINITION = {
    "name": "linux_config_audit",
    "description": (
        "Audit Linux host configuration for SSH hardening, firewall rules, users/groups, "
        "sudoers, open ports, running services, file permissions, and PAM configuration. "
        "Can optionally run Lynis for deeper host auditing."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["quick", "standard", "deep", "lynis"],
                "description": (
                    "quick = SSH/firewall/ports only | "
                    "standard = baseline config audit | "
                    "deep = baseline + Lynis | "
                    "lynis = run Lynis only"
                ),
                "default": "standard"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional extra args for Lynis in deep/lynis mode. "
                    "Example: ['--tests-from-group', 'authentication,networking']"
                )
            }
        },
        "required": []
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=== QUICK ===")
    print(json.dumps(linux_config_audit(mode="quick"), indent=2))

    print("=== STANDARD ===")
    print(json.dumps(linux_config_audit(mode="standard"), indent=2))

    print("=== DEEP ===")
    print(json.dumps(
        linux_config_audit(mode="deep", args=["--tests-from-group", "authentication,networking"]),
        indent=2
    ))

    print("=== LYNIS ONLY ===")
    print(json.dumps(linux_config_audit(mode="lynis"), indent=2))