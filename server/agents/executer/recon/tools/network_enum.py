import subprocess
import json
import re
import os
import time
import tempfile
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
    OUTPUT_DIR = "output"
    TEMP_DIR   = "tmp"
    LOGS_DIR   = "logs"

    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir
        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir
        current = Path(__file__).resolve().parent
        markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt"]
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in markers):
                cls._project_dir = parent
                return cls._project_dir
        cls._project_dir = Path.cwd()
        return cls._project_dir

    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


def safe_execute(
    cmd: list[str],
    timeout: int = 120,
    cwd: Optional[str] = None,
    input_data: Optional[str] = None,
) -> tuple[str, str, int, str]:
    """Run a command safely, return (stdout, stderr, returncode, cwd)"""
    work_dir = Path(cwd) if cwd else ProjectConfig.get_project_dir()
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(work_dir),
            input=input_data,
        )
        return result.stdout, result.stderr, result.returncode, str(work_dir)
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1, str(work_dir)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed or not in PATH", -1, str(work_dir)
    except Exception as e:
        return "", str(e), -1, str(work_dir)


# ══════════════════════════════════════════════════════════════
# 2. CONSTANTS & PATTERNS
# ══════════════════════════════════════════════════════════════

# Well-known SNMP OIDs for targeted walking
SNMP_OIDS = {
    "system_description": "1.3.6.1.2.1.1.1.0",
    "system_name":        "1.3.6.1.2.1.1.5.0",
    "system_uptime":      "1.3.6.1.2.1.1.3.0",
    "interfaces":         "1.3.6.1.2.1.2.2",
    "ip_addresses":       "1.3.6.1.2.1.4.20",
    "running_software":   "1.3.6.1.2.1.25.4.2",
    "installed_software": "1.3.6.1.2.1.25.6.3",
    "users":              "1.3.6.1.4.1.77.1.2.25",
    "shares":             "1.3.6.1.4.1.77.1.2.27",
    "tcp_connections":    "1.3.6.1.2.1.6.13",
}

# SNMP community strings to try (in order)
DEFAULT_COMMUNITIES = ["public", "private", "manager", "community", "admin", "snmp"]

# AD / LDAP attribute sets
LDAP_USER_ATTRS  = [
    "sAMAccountName", "userPrincipalName", "displayName",
    "mail", "memberOf", "lastLogon", "pwdLastSet",
    "userAccountControl", "description", "telephoneNumber",
]
LDAP_GROUP_ATTRS = [
    "cn", "member", "description", "groupType",
    "managedBy", "distinguishedName",
]
LDAP_POLICY_ATTRS = [
    "maxPwdAge", "minPwdAge", "minPwdLength",
    "lockoutThreshold", "lockoutDuration",
    "pwdHistoryLength", "ms-DS-MachineAccountQuota",
]

# Sensitive findings patterns
SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"passw(or)?d",
        r"secret",
        r"admin",
        r"root",
        r"hash",
        r"ntlm",
        r"kerberos",
        r"ticket",
        r"credential",
        r"writable",
        r"everyone",
        r"anonymous",
        r"guest",
        r"no authentication",
        r"world[- ]readable",
    ]
]


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class EnumType(str, Enum):
    smb        = "smb"        # SMB shares via enum4linux / rpcclient / smbclient
    snmp       = "snmp"       # SNMP walk via snmpwalk
    netbios    = "netbios"    # NetBIOS via nbtscan
    ldap       = "ldap"       # LDAP enum via ldapsearch
    nfs        = "nfs"        # NFS shares via nfs-ls / showmount
    ad         = "ad"         # AD users/groups/policies via rpcclient + ldapsearch
    all        = "all"        # Run everything


class NetworkEnumRequest(BaseModel):
    target:      str
    checks:      list[EnumType]   = [EnumType.all]
    # Credentials (optional — enables authenticated enumeration)
    username:    Optional[str]    = None
    password:    Optional[str]    = None
    domain:      Optional[str]    = None
    # SNMP
    communities: list[str]        = []        # override default community strings
    snmp_version:str              = "2c"      # 1 | 2c | 3
    # LDAP / AD
    ldap_base_dn:Optional[str]    = None      # e.g. "DC=corp,DC=local"
    ldap_port:   int              = 389
    ldap_ssl:    bool             = False
    # NFS
    nfs_mount:   bool             = False     # attempt to mount shares
    # Output
    timeout:     int              = Field(default=120, ge=10, le=600)
    # Extra raw args forwarded to tools
    extra_args:  dict[str, list[str]] = {}    # {"enum4linux": ["-a"], ...}

    @validator("target")
    def validate_target(cls, v):
        blocked = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
        clean   = re.sub(r"^\w+://", "", v.strip()).split("/")[0]
        if clean in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()

    @validator("checks", always=True)
    def expand_all(cls, v):
        if EnumType.all in v:
            return [c for c in EnumType if c != EnumType.all]
        return v

    @validator("snmp_version")
    def validate_snmp_version(cls, v):
        if v not in {"1", "2c", "3"}:
            raise ValueError("snmp_version must be '1', '2c', or '3'")
        return v

    @validator("extra_args")
    def validate_extra_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"', ">"]
        for tool_args in v.values():
            for arg in tool_args:
                for char in dangerous:
                    if char in str(arg):
                        raise ValueError(
                            f"Dangerous character '{char}' in extra_args: {arg}"
                        )
        return v


class NetworkFinding(BaseModel):
    """A single enumeration finding"""
    check_type:  str
    severity:    str              # critical | high | medium | low | info
    host:        str
    category:    str              # share | user | group | policy | oid | netbios | nfs …
    name:        Optional[str]   = None
    value:       Optional[str]   = None
    description: str
    raw:         Optional[str]   = None   # snippet of raw tool output


class NetworkEnumResult(BaseModel):
    success:        bool
    target:         str
    checks_run:     list[str]
    findings:       list[NetworkFinding] = []
    summary:        dict[str, int]       = {}   # category → count
    tool_outputs:   dict[str, str]       = {}   # tool → raw stdout (trimmed)
    errors:         list[str]            = []
    execution_time: float                = 0.0


# ══════════════════════════════════════════════════════════════
# 4. HELPERS
# ══════════════════════════════════════════════════════════════

def _redact(s: str, max_len: int = 120) -> str:
    if len(s) > max_len:
        return s[:max_len] + "…[truncated]"
    return s


def _is_sensitive(text: str) -> bool:
    return any(p.search(text) for p in SENSITIVE_PATTERNS)


def _severity(text: str) -> str:
    text_l = text.lower()
    if any(k in text_l for k in [
        "writable", "everyone", "anonymous", "guest",
        "no auth", "world-readable", "password", "hash", "ntlm"
    ]):
        return "critical"
    if any(k in text_l for k in ["admin", "root", "credential", "kerberos", "ticket"]):
        return "high"
    if any(k in text_l for k in ["share", "user", "group", "member"]):
        return "medium"
    return "info"


def _build_auth_args(req: NetworkEnumRequest) -> dict[str, list[str]]:
    """Build per-tool authentication argument lists"""
    auth: dict[str, list[str]] = {
        "rpcclient":   [],
        "smbclient":   [],
        "ldapsearch":  [],
        "enum4linux":  [],
        "nfs_ls":      [],
    }

    if req.username and req.password:
        up = f"{req.username}%{req.password}"
        dom_up = f"{req.domain}\\{up}" if req.domain else up

        auth["rpcclient"]  = ["-U", dom_up]
        auth["smbclient"]  = ["-U", dom_up]
        auth["enum4linux"] = ["-u", req.username, "-p", req.password]
        if req.domain:
            auth["enum4linux"] += ["-w", req.domain]

        # ldapsearch: simple bind
        bind_dn = (
            f"CN={req.username},DC="
            + ",DC=".join(req.domain.split("."))
            if req.domain else req.username
        )
        auth["ldapsearch"] = ["-D", bind_dn, "-w", req.password]
    else:
        # Anonymous / null session
        auth["rpcclient"]  = ["-U", "''%''", "-N"]
        auth["smbclient"]  = ["-U", "''%''", "-N"]
        auth["enum4linux"] = []
        auth["ldapsearch"] = ["-x"]          # simple anonymous bind

    return auth


# ══════════════════════════════════════════════════════════════
# 5. CHECK IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════

# ─────────────────────────────────────────
# 5A. SMB — enum4linux + rpcclient
# ─────────────────────────────────────────

def _check_smb(req: NetworkEnumRequest,
               auth: dict) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    # ── enum4linux ───────────────────────────────────────────────
    cmd = ["enum4linux", "-a"]          # -a = all simple enumeration
    cmd += auth["enum4linux"]
    cmd += req.extra_args.get("enum4linux", [])
    cmd.append(req.target)

    raw_log.append(f"[SMB/enum4linux] {' '.join(cmd)}")
    stdout, stderr, rc, _ = safe_execute(cmd, req.timeout)
    raw_log.append(stdout[:4000] or f"(no output; rc={rc})")

    if stderr and rc != 0:
        raw_log.append(f"STDERR: {stderr[:400]}")

    # Parse enum4linux output ─────────────────────────────────────
    # Shares section
    for m in re.finditer(
        r"//\S+/(\S+)\s+Disk\s+(.*)", stdout, re.IGNORECASE
    ):
        share, comment = m.group(1), m.group(2).strip()
        sev = _severity(share + " " + comment)
        findings.append(NetworkFinding(
            check_type  = "smb",
            severity    = sev,
            host        = req.target,
            category    = "share",
            name        = share,
            value       = comment or "(no comment)",
            description = f"SMB share '{share}' found — comment: {comment or 'none'}",
            raw         = _redact(m.group(0)),
        ))

    # Users section  (enum4linux -U)
    for m in re.finditer(
        r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE
    ):
        user, rid = m.group(1), m.group(2)
        findings.append(NetworkFinding(
            check_type  = "smb",
            severity    = "info",
            host        = req.target,
            category    = "user",
            name        = user,
            value       = f"RID={rid}",
            description = f"Local/domain user enumerated via SMB: {user} (RID {rid})",
            raw         = _redact(m.group(0)),
        ))

    # Groups section
    for m in re.finditer(
        r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE
    ):
        group, rid = m.group(1), m.group(2)
        findings.append(NetworkFinding(
            check_type  = "smb",
            severity    = "info",
            host        = req.target,
            category    = "group",
            name        = group,
            value       = f"RID={rid}",
            description = f"Local/domain group enumerated via SMB: {group} (RID {rid})",
            raw         = _redact(m.group(0)),
        ))

    # Password policy
    for m in re.finditer(
        r"(Minimum password length|Password history length|"
        r"Maximum password age|Account lockout threshold)[:\s]+(\S+)",
        stdout, re.IGNORECASE
    ):
        policy_key, policy_val = m.group(1), m.group(2)
        sev = "high" if "lockout threshold" in policy_key.lower() \
              and policy_val in ("0", "None") else "info"
        findings.append(NetworkFinding(
            check_type  = "smb",
            severity    = sev,
            host        = req.target,
            category    = "policy",
            name        = policy_key,
            value       = policy_val,
            description = f"Password policy: {policy_key} = {policy_val}",
            raw         = _redact(m.group(0)),
        ))

    # OS / workgroup info
    for m in re.finditer(
        r"OS=\[([^\]]+)\].*Server=\[([^\]]+)\]", stdout, re.IGNORECASE
    ):
        findings.append(NetworkFinding(
            check_type  = "smb",
            severity    = "info",
            host        = req.target,
            category    = "os_info",
            name        = "OS",
            value       = f"{m.group(1)} / Server: {m.group(2)}",
            description = f"SMB OS banner: {m.group(1)}, Server: {m.group(2)}",
            raw         = _redact(m.group(0)),
        ))

    # ── rpcclient additional enumeration ─────────────────────────
    rpc_commands = [
        ("srvinfo",       "server_info"),
        ("enumdomusers",  "users"),
        ("enumdomgroups", "groups"),
        ("getdompwinfo",  "password_policy"),
        ("lsaquery",      "lsa_info"),
        ("enumprinters",  "printers"),
    ]

    for rpc_cmd, category in rpc_commands:
        cmd = ["rpcclient"] + auth["rpcclient"]
        cmd += req.extra_args.get("rpcclient", [])
        cmd += ["-c", rpc_cmd, req.target]

        raw_log.append(f"[SMB/rpcclient] {' '.join(cmd)}")
        stdout_rpc, stderr_rpc, rc_rpc, _ = safe_execute(cmd, timeout=30)
        raw_log.append(stdout_rpc[:1000] or f"  (no output; rc={rc_rpc})")

        if not stdout_rpc:
            continue

        # Generic finding for each non-empty rpcclient response
        for line in stdout_rpc.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sev = _severity(line)
            findings.append(NetworkFinding(
                check_type  = "smb",
                severity    = sev,
                host        = req.target,
                category    = category,
                value       = _redact(line),
                description = f"rpcclient {rpc_cmd}: {_redact(line)}",
                raw         = _redact(line),
            ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5B. SNMP — snmpwalk
# ─────────────────────────────────────────

def _check_snmp(req: NetworkEnumRequest) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    communities = req.communities or DEFAULT_COMMUNITIES

    for community in communities:
        raw_log.append(f"\n[SNMP] Trying community='{community}' version={req.snmp_version}")

        # Full tree walk first
        cmd = [
            "snmpwalk",
            f"-v{req.snmp_version}",
            "-c", community,
            "-t", "3",           # 3 s timeout per request
            "-r", "1",           # 1 retry
        ]
        cmd += req.extra_args.get("snmpwalk", [])
        cmd += [req.target]

        raw_log.append(f"  CMD: {' '.join(cmd)}")
        stdout, stderr, rc, _ = safe_execute(cmd, timeout=req.timeout)

        if rc != 0 or not stdout.strip():
            raw_log.append(f"  No response (community '{community}' failed or closed)")
            continue

        raw_log.append(stdout[:3000])

        # Community string worked — flag it
        findings.append(NetworkFinding(
            check_type  = "snmp",
            severity    = "critical" if community in ("public", "private") else "high",
            host        = req.target,
            category    = "community_string",
            name        = community,
            description = f"SNMP community string '{community}' accepted — "
                          f"information disclosure risk.",
            raw         = f"snmpwalk responded with {len(stdout.splitlines())} lines",
        ))

        # Parse OID → value lines
        oid_pattern = re.compile(
            r"([\w.]+)\s*=\s*([\w\s]+):\s*(.*)", re.IGNORECASE
        )
        for line in stdout.splitlines():
            m = oid_pattern.match(line.strip())
            if not m:
                continue
            oid, oid_type, value = m.group(1), m.group(2).strip(), m.group(3).strip()
            if not value or value in ("", '""', "No Such Instance"):
                continue

            # Map OID prefix to human category
            category = "oid"
            for label, prefix in SNMP_OIDS.items():
                if oid.startswith(prefix.rsplit(".", 1)[0]):
                    category = label
                    break

            sev = "high" if _is_sensitive(value + oid) else "info"
            findings.append(NetworkFinding(
                check_type  = "snmp",
                severity    = sev,
                host        = req.target,
                category    = category,
                name        = oid,
                value       = _redact(value),
                description = f"SNMP OID {oid} ({category}): {_redact(value)}",
                raw         = _redact(line),
            ))

        # Targeted OID queries for high-value data
        for label, oid in SNMP_OIDS.items():
            cmd_get = [
                "snmpget",
                f"-v{req.snmp_version}",
                "-c", community,
                "-t", "3",
                req.target,
                oid,
            ]
            out_g, _, rc_g, _ = safe_execute(cmd_get, timeout=15)
            if rc_g == 0 and out_g.strip():
                raw_log.append(f"  [OID/{label}] {out_g.strip()[:200]}")
        
        # Only use the first working community
        break

    if not findings:
        findings.append(NetworkFinding(
            check_type  = "snmp",
            severity    = "info",
            host        = req.target,
            category    = "community_string",
            description = "No SNMP community strings accepted — host may be hardened "
                          "or SNMP is not running.",
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5C. NetBIOS — nbtscan
# ─────────────────────────────────────────

def _check_netbios(req: NetworkEnumRequest) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    # nbtscan works on IPs and CIDR ranges
    cmd = ["nbtscan", "-r"]
    cmd += req.extra_args.get("nbtscan", [])
    cmd.append(req.target)

    raw_log.append(f"[NetBIOS/nbtscan] {' '.join(cmd)}")
    stdout, stderr, rc, _ = safe_execute(cmd, timeout=req.timeout)
    raw_log.append(stdout[:3000] or f"(no output; rc={rc})")

    # Parse nbtscan output
    # Format: IP   NetBIOS_Name   Server   User
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("IP") or line.startswith("-"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip       = parts[0]
        nb_name  = parts[1] if len(parts) > 1 else "?"
        nb_user  = parts[3] if len(parts) > 3 else ""
        nb_mac   = parts[-1] if len(parts) > 4 else ""

        findings.append(NetworkFinding(
            check_type  = "netbios",
            severity    = "info",
            host        = ip,
            category    = "netbios_name",
            name        = nb_name,
            value       = f"User={nb_user} MAC={nb_mac}",
            description = f"NetBIOS name '{nb_name}' resolved for {ip}",
            raw         = _redact(line),
        ))

    # Also run nmblookup for richer name table
    cmd_nml = ["nmblookup", "-A", req.target]
    raw_log.append(f"[NetBIOS/nmblookup] {' '.join(cmd_nml)}")
    stdout_nml, _, rc_nml, _ = safe_execute(cmd_nml, timeout=30)
    raw_log.append(stdout_nml[:2000] or f"(no output; rc={rc_nml})")

    # Parse nmblookup name table
    # Format:   <name>           <00> -         B <ACTIVE>
    for m in re.finditer(
        r"(\S+)\s+<([0-9a-fA-F]{2})>\s+-?\s+(\w)\s+<(\w+)>",
        stdout_nml
    ):
        nb_name, nb_type, node_type, status = (
            m.group(1), m.group(2), m.group(3), m.group(4)
        )

        # Decode known NetBIOS service codes
        nb_service = {
            "00": "Workstation/Hostname",
            "03": "Messenger Service",
            "06": "RAS Server",
            "20": "File Server (SMB)",
            "1B": "Domain Master Browser",
            "1C": "Domain Controller",
            "1D": "Master Browser",
            "1E": "Browser Election",
        }.get(nb_type.upper(), f"Type 0x{nb_type}")

        sev = "high" if nb_type.upper() in ("20", "1B", "1C") else "info"
        findings.append(NetworkFinding(
            check_type  = "netbios",
            severity    = sev,
            host        = req.target,
            category    = "netbios_service",
            name        = nb_name,
            value       = f"{nb_service} [{status}]",
            description = f"NetBIOS service: {nb_name} ({nb_service}) — "
                          f"Node={node_type} Status={status}",
            raw         = _redact(m.group(0)),
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5D. LDAP — ldapsearch
# ─────────────────────────────────────────

def _check_ldap(req: NetworkEnumRequest,
                auth: dict) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    port   = req.ldap_port
    scheme = "ldaps" if req.ldap_ssl else "ldap"
    uri    = f"{scheme}://{req.target}:{port}"

    # Auto-detect base DN if not provided
    base_dn = req.ldap_base_dn
    if not base_dn:
        # Query rootDSE to discover naming context
        cmd_rootdse = [
            "ldapsearch", "-H", uri,
            "-x", "-s", "base",
            "-b", "",
            "namingContexts",
        ]
        raw_log.append(f"[LDAP/rootDSE] {' '.join(cmd_rootdse)}")
        stdout_r, _, rc_r, _ = safe_execute(cmd_rootdse, timeout=20)
        raw_log.append(stdout_r[:500])
        m = re.search(r"namingContexts:\s*(.+)", stdout_r, re.IGNORECASE)
        if m:
            base_dn = m.group(1).strip()
            raw_log.append(f"  Auto-detected base DN: {base_dn}")
        else:
            # Fallback: derive from target hostname
            parts  = req.target.replace("-", "").split(".")
            base_dn = ",".join(f"DC={p}" for p in parts if p)
            raw_log.append(f"  Fallback base DN: {base_dn}")

    # Generic base arguments
    base_args = ["-H", uri, "-b", base_dn] + auth["ldapsearch"]

    # ── Query 1: All users ────────────────────────────────────────
    user_filter = "(objectClass=user)"
    cmd_users   = (
        ["ldapsearch"] + base_args
        + ["-s", "sub", user_filter]
        + LDAP_USER_ATTRS
        + req.extra_args.get("ldapsearch", [])
    )
    raw_log.append(f"[LDAP/users] {' '.join(cmd_users)}")
    stdout_u, stderr_u, rc_u, _ = safe_execute(cmd_users, timeout=req.timeout)
    raw_log.append(stdout_u[:3000] or f"(no output; rc={rc_u})")

    for block in re.split(r"\n\n+", stdout_u):
        sam = re.search(r"sAMAccountName:\s*(.+)", block, re.I)
        upn = re.search(r"userPrincipalName:\s*(.+)", block, re.I)
        uac = re.search(r"userAccountControl:\s*(\d+)", block, re.I)
        if not sam:
            continue
        username = sam.group(1).strip()
        # Decode UAC flags
        uac_flags = []
        if uac:
            uac_val = int(uac.group(1))
            if uac_val & 0x0002: uac_flags.append("DISABLED")
            if uac_val & 0x0010: uac_flags.append("LOCKOUT")
            if uac_val & 0x0040: uac_flags.append("PASSWORD_NOT_REQUIRED")
            if uac_val & 0x10000: uac_flags.append("NO_PASSWORD_EXPIRY")
            if uac_val & 0x80000: uac_flags.append("TRUSTED_FOR_DELEGATION")

        sev = "critical" if "PASSWORD_NOT_REQUIRED" in uac_flags else \
              "high"     if "TRUSTED_FOR_DELEGATION" in uac_flags else \
              "info"

        findings.append(NetworkFinding(
            check_type  = "ldap",
            severity    = sev,
            host        = req.target,
            category    = "user",
            name        = username,
            value       = upn.group(1).strip() if upn else "",
            description = f"AD user '{username}'"
                          + (f" — flags: {', '.join(uac_flags)}" if uac_flags else ""),
            raw         = _redact(block[:300]),
        ))

    # ── Query 2: All groups ───────────────────────────────────────
    grp_filter = "(objectClass=group)"
    cmd_groups  = (
        ["ldapsearch"] + base_args
        + ["-s", "sub", grp_filter]
        + LDAP_GROUP_ATTRS
    )
    raw_log.append(f"[LDAP/groups] {' '.join(cmd_groups)}")
    stdout_g, _, rc_g, _ = safe_execute(cmd_groups, timeout=req.timeout)
    raw_log.append(stdout_g[:2000] or f"(no output; rc={rc_g})")

    for block in re.split(r"\n\n+", stdout_g):
        cn     = re.search(r"^cn:\s*(.+)",          block, re.I | re.M)
        desc   = re.search(r"description:\s*(.+)",  block, re.I)
        mcount = len(re.findall(r"^member:\s",       block, re.M))
        if not cn:
            continue
        group_name = cn.group(1).strip()
        findings.append(NetworkFinding(
            check_type  = "ldap",
            severity    = "high" if any(
                k in group_name.lower()
                for k in ["admin", "domain admin", "enterprise", "schema"]
            ) else "info",
            host        = req.target,
            category    = "group",
            name        = group_name,
            value       = f"{mcount} member(s) | {desc.group(1).strip() if desc else ''}",
            description = f"AD group '{group_name}' with {mcount} member(s)",
            raw         = _redact(block[:300]),
        ))

    # ── Query 3: Domain password policy ──────────────────────────
    policy_filter = "(objectClass=domainDNS)"
    cmd_policy    = (
        ["ldapsearch"] + base_args
        + ["-s", "base", policy_filter]
        + LDAP_POLICY_ATTRS
    )
    raw_log.append(f"[LDAP/policy] {' '.join(cmd_policy)}")
    stdout_p, _, rc_p, _ = safe_execute(cmd_policy, timeout=30)
    raw_log.append(stdout_p[:1000] or f"(no output; rc={rc_p})")

    for attr in LDAP_POLICY_ATTRS:
        m = re.search(rf"{attr}:\s*(.+)", stdout_p, re.I)
        if m:
            val = m.group(1).strip()
            # lockoutThreshold of 0 means no lockout
            sev = "critical" if attr == "lockoutThreshold" and val == "0" else \
                  "high"     if attr == "minPwdLength"     and int(re.sub(r"\D","",val) or "8") < 8 else \
                  "info"
            findings.append(NetworkFinding(
                check_type  = "ldap",
                severity    = sev,
                host        = req.target,
                category    = "password_policy",
                name        = attr,
                value       = val,
                description = f"Domain policy attribute '{attr}' = {val}",
                raw         = _redact(m.group(0)),
            ))

    # ── Query 4: Computers ────────────────────────────────────────
    cmd_comp = (
        ["ldapsearch"] + base_args
        + ["-s", "sub", "(objectClass=computer)"]
        + ["cn", "operatingSystem", "operatingSystemVersion", "dNSHostName"]
    )
    raw_log.append(f"[LDAP/computers] {' '.join(cmd_comp)}")
    stdout_c, _, rc_c, _ = safe_execute(cmd_comp, timeout=req.timeout)
    raw_log.append(stdout_c[:2000] or f"(no output; rc={rc_c})")

    for block in re.split(r"\n\n+", stdout_c):
        cn_m  = re.search(r"^cn:\s*(.+)",                    block, re.I | re.M)
        os_m  = re.search(r"operatingSystem:\s*(.+)",        block, re.I)
        osv_m = re.search(r"operatingSystemVersion:\s*(.+)", block, re.I)
        dns_m = re.search(r"dNSHostName:\s*(.+)",            block, re.I)
        if not cn_m:
            continue
        comp_name = cn_m.group(1).strip()
        os_str    = os_m.group(1).strip() if os_m else "?"
        osv_str   = osv_m.group(1).strip() if osv_m else ""
        dns_str   = dns_m.group(1).strip() if dns_m else ""

        # Flag end-of-life OS versions
        eol_os = ["2003", "2008", "xp", "vista", "windows 7"]
        sev    = "critical" if any(e in os_str.lower() for e in eol_os) else "info"
        findings.append(NetworkFinding(
            check_type  = "ldap",
            severity    = sev,
            host        = req.target,
            category    = "computer",
            name        = comp_name,
            value       = f"{os_str} {osv_str} ({dns_str})",
            description = f"AD computer '{comp_name}' — OS: {os_str} {osv_str}"
                          + (" [EOL!]" if sev == "critical" else ""),
            raw         = _redact(block[:300]),
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5E. NFS — showmount + nfs-ls
# ─────────────────────────────────────────

def _check_nfs(req: NetworkEnumRequest) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    # ── showmount: list exports ───────────────────────────────────
    cmd = ["showmount", "-e", req.target]
    cmd += req.extra_args.get("showmount", [])

    raw_log.append(f"[NFS/showmount] {' '.join(cmd)}")
    stdout, stderr, rc, _ = safe_execute(cmd, timeout=req.timeout)
    raw_log.append(stdout[:2000] or f"(no output; rc={rc})")

    exports: list[str] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Export"):
            continue
        # showmount format:  /share   *  or  /share  10.0.0.0/8
        parts      = line.split()
        export     = parts[0]
        allow_list = " ".join(parts[1:]) if len(parts) > 1 else "*"
        exports.append(export)

        sev = "critical" if allow_list.strip() in ("*", "everyone", "0.0.0.0/0") else "high"
        findings.append(NetworkFinding(
            check_type  = "nfs",
            severity    = sev,
            host        = req.target,
            category    = "nfs_export",
            name        = export,
            value       = f"allowed={allow_list}",
            description = f"NFS export '{export}' accessible from: {allow_list}"
                          + (" [world-accessible!]" if sev == "critical" else ""),
            raw         = _redact(line),
        ))

    # ── nfs-ls: list files in each export ────────────────────────
    for export in exports:
        nfs_url = f"nfs://{req.target}{export}"
        cmd_ls  = ["nfs-ls"]
        cmd_ls += req.extra_args.get("nfs-ls", [])
        cmd_ls.append(nfs_url)

        raw_log.append(f"[NFS/nfs-ls] {' '.join(cmd_ls)}")
        stdout_ls, stderr_ls, rc_ls, _ = safe_execute(cmd_ls, timeout=60)
        raw_log.append(stdout_ls[:2000] or f"(no output; rc={rc_ls})")

        for line in stdout_ls.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect world-writable permissions (rwxrwxrwx or -------rw-)
            perm_m = re.match(r"^([d\-lrwxsStT]{10})\s+", line)
            if perm_m:
                perms = perm_m.group(1)
                # Other-write bit
                world_write = len(perms) >= 10 and perms[8] == "w"
                world_read  = len(perms) >= 10 and perms[7] == "r"
                sev = "critical" if world_write else \
                      "high"     if world_read  else "info"
                if sev != "info":
                    findings.append(NetworkFinding(
                        check_type  = "nfs",
                        severity    = sev,
                        host        = req.target,
                        category    = "nfs_file",
                        name        = export,
                        value       = _redact(line),
                        description = f"NFS file/dir with insecure permissions ({perms}) "
                                      f"in export '{export}'",
                        raw         = _redact(line),
                    ))
            elif _is_sensitive(line):
                findings.append(NetworkFinding(
                    check_type  = "nfs",
                    severity    = "high",
                    host        = req.target,
                    category    = "nfs_file",
                    name        = export,
                    value       = _redact(line),
                    description = f"Potentially sensitive file found in NFS export '{export}'",
                    raw         = _redact(line),
                ))

        # Optional: attempt mount
        if req.nfs_mount and exports:
            tmp_mount = ProjectConfig.get_temp_dir() / "nfs_mount"
            tmp_mount.mkdir(exist_ok=True)
            cmd_mount = [
                "mount", "-t", "nfs",
                "-o", "ro,nolock",
                f"{req.target}:{export}",
                str(tmp_mount),
            ]
            raw_log.append(f"[NFS/mount] {' '.join(cmd_mount)}")
            _, stderr_m, rc_m, _ = safe_execute(cmd_mount, timeout=30)
            if rc_m == 0:
                findings.append(NetworkFinding(
                    check_type  = "nfs",
                    severity    = "critical",
                    host        = req.target,
                    category    = "nfs_mount",
                    name        = export,
                    value       = str(tmp_mount),
                    description = f"NFS share '{export}' mounted successfully at "
                                  f"{tmp_mount} — no authentication required!",
                ))
                # Unmount immediately
                safe_execute(["umount", str(tmp_mount)], timeout=10)
            else:
                raw_log.append(f"  Mount failed (expected if no root): {stderr_m[:200]}")

    if not exports:
        findings.append(NetworkFinding(
            check_type  = "nfs",
            severity    = "info",
            host        = req.target,
            category    = "nfs_export",
            description = "No NFS exports found or NFS is not running on this host.",
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5F. Active Directory — rpcclient deep dive
# ─────────────────────────────────────────

def _check_ad(req: NetworkEnumRequest,
              auth: dict) -> tuple[list[NetworkFinding], str]:
    findings: list[NetworkFinding] = []
    raw_log:  list[str]            = []

    # Extended rpcclient commands for AD
    ad_commands = [
        ("enumdomains",           "domains"),
        ("enumtrusts",            "trust_relationships"),
        ("enumdomusers",          "ad_users"),
        ("enumdomgroups",         "ad_groups"),
        ("enumprivs",             "privileges"),
        ("getdompwinfo",          "password_policy"),
        ("lsaenumsid",            "sids"),
        ("dsroledominfo",         "domain_role"),
        ("netconnenum",           "connections"),
        ("netsessenum",           "sessions"),
        ("netdiskenum",           "disks"),
        ("querydominfo",          "domain_info"),
    ]

    for rpc_cmd, category in ad_commands:
        cmd = ["rpcclient"] + auth["rpcclient"]
        cmd += req.extra_args.get("rpcclient", [])
        cmd += ["-c", rpc_cmd, req.target]

        raw_log.append(f"[AD/rpcclient] {rpc_cmd}: {' '.join(cmd)}")
        stdout, stderr, rc, _ = safe_execute(cmd, timeout=30)
        raw_log.append(stdout[:1500] or f"  (no output; rc={rc})")

        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sev = _severity(line)
            findings.append(NetworkFinding(
                check_type  = "ad",
                severity    = sev,
                host        = req.target,
                category    = category,
                value       = _redact(line),
                description = f"AD rpcclient [{rpc_cmd}]: {_redact(line)}",
                raw         = _redact(line),
            ))

    # ── Kerberoastable accounts (SPN query via ldapsearch) ───────
    if req.ldap_base_dn or req.domain:
        base_dn = req.ldap_base_dn or ",".join(
            f"DC={p}" for p in (req.domain or "").split(".")
        )
        uri = f"ldap://{req.target}:{req.ldap_port}"
        cmd_spn = (
            ["ldapsearch"] + auth["ldapsearch"]
            + ["-H", uri, "-b", base_dn, "-s", "sub"]
            + ["(&(objectClass=user)(servicePrincipalName=*)"
               "(!(objectClass=computer))(!(cn=krbtgt)))"]
            + ["sAMAccountName", "servicePrincipalName", "memberOf"]
        )
        raw_log.append(f"[AD/Kerberoast] {' '.join(cmd_spn)}")
        stdout_spn, _, rc_spn, _ = safe_execute(cmd_spn, timeout=req.timeout)
        raw_log.append(stdout_spn[:2000] or f"(no output; rc={rc_spn})")

        for block in re.split(r"\n\n+", stdout_spn):
            sam = re.search(r"sAMAccountName:\s*(.+)", block, re.I)
            spn = re.findall(r"servicePrincipalName:\s*(.+)", block, re.I)
            if sam and spn:
                username = sam.group(1).strip()
                findings.append(NetworkFinding(
                    check_type  = "ad",
                    severity    = "critical",
                    host        = req.target,
                    category    = "kerberoastable",
                    name        = username,
                    value       = ", ".join(s.strip() for s in spn),
                    description = f"Kerberoastable account '{username}' has SPN(s): "
                                  f"{', '.join(s.strip() for s in spn)}",
                    raw         = _redact(block[:300]),
                ))

        # ── ASREPRoastable accounts (no pre-auth required) ───────
        cmd_asrep = (
            ["ldapsearch"] + auth["ldapsearch"]
            + ["-H", uri, "-b", base_dn, "-s", "sub"]
            + ["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"]
            + ["sAMAccountName", "userAccountControl"]
        )
        raw_log.append(f"[AD/ASREProast] {' '.join(cmd_asrep)}")
        stdout_ar, _, rc_ar, _ = safe_execute(cmd_asrep, timeout=req.timeout)
        raw_log.append(stdout_ar[:1000] or f"(no output; rc={rc_ar})")

        for block in re.split(r"\n\n+", stdout_ar):
            sam = re.search(r"sAMAccountName:\s*(.+)", block, re.I)
            if sam:
                username = sam.group(1).strip()
                findings.append(NetworkFinding(
                    check_type  = "ad",
                    severity    = "critical",
                    host        = req.target,
                    category    = "asreproastable",
                    name        = username,
                    description = f"ASREPRoastable account '{username}' — "
                                  f"Kerberos pre-authentication NOT required.",
                    raw         = _redact(block[:200]),
                ))

    return findings, "\n".join(raw_log)


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def network_enum(
    target:        str,
    checks:        list[str]       = ["all"],
    username:      Optional[str]   = None,
    password:      Optional[str]   = None,
    domain:        Optional[str]   = None,
    communities:   list[str]       = [],
    snmp_version:  str             = "2c",
    ldap_base_dn:  Optional[str]   = None,
    ldap_port:     int             = 389,
    ldap_ssl:      bool            = False,
    nfs_mount:     bool            = False,
    timeout:       int             = 120,
    extra_args:    dict            = {},
) -> dict:
    """
    🔧 Agent Tool: Network Enumeration

    Enumerate network services across SMB, SNMP, NetBIOS, LDAP, NFS,
    and Active Directory. Supports both null/anonymous and authenticated
    sessions. Returns structured findings with severity ratings.

    Args:
        target:       IP address, hostname, or CIDR range
        checks:       ["all"] or subset of:
                      smb | snmp | netbios | ldap | nfs | ad
        username:     Username for authenticated enumeration
        password:     Password for authenticated enumeration
        domain:       Windows domain name (e.g. "corp.local")
        communities:  SNMP community strings to try (default: common list)
        snmp_version: SNMP version — "1" | "2c" | "3"
        ldap_base_dn: LDAP base DN (e.g. "DC=corp,DC=local")
        ldap_port:    LDAP port (default 389; use 636 for LDAPS)
        ldap_ssl:     Use LDAPS (SSL/TLS)
        nfs_mount:    Attempt to mount discovered NFS shares (requires root)
        timeout:      Per-tool timeout in seconds
        extra_args:   Raw extra args per tool:
                      {"enum4linux": ["-v"], "snmpwalk": ["-On"], ...}

    Returns:
        Structured dict with all findings, severity summary, and raw tool output.

    Tools required:
        enum4linux, rpcclient, smbclient  — apt install samba-common-bin enum4linux
        snmpwalk, snmpget                 — apt install snmp
        nbtscan, nmblookup                — apt install nbtscan samba-common-bin
        ldapsearch                        — apt install ldap-utils
        showmount, nfs-ls                 — apt install nfs-common libnfs-utils
    """
    start = time.time()

    # ── VALIDATE ──────────────────────────────────────────────────
    try:
        req = NetworkEnumRequest(
            target       = target,
            checks       = checks,
            username     = username,
            password     = password,
            domain       = domain,
            communities  = communities,
            snmp_version = snmp_version,
            ldap_base_dn = ldap_base_dn,
            ldap_port    = ldap_port,
            ldap_ssl     = ldap_ssl,
            nfs_mount    = nfs_mount,
            timeout      = timeout,
            extra_args   = extra_args,
        )
    except Exception as e:
        return NetworkEnumResult(
            success     = False,
            target      = target,
            checks_run  = [],
            errors      = [f"Validation error: {e}"],
        ).model_dump()

    # Build per-tool auth argument lists
    auth = _build_auth_args(req)

    all_findings:     list[NetworkFinding] = []
    all_tool_outputs: dict[str, str]       = {}
    all_errors:       list[str]            = []
    checks_run:       list[str]            = []

    # ══════════════════════════════════════
    # DISPATCH CHECKS
    # ══════════════════════════════════════

    if EnumType.smb in req.checks:
        checks_run.append("smb")
        try:
            f, log = _check_smb(req, auth)
            all_findings.extend(f)
            all_tool_outputs["smb"] = log
        except Exception as e:
            all_errors.append(f"smb: {e}")

    if EnumType.snmp in req.checks:
        checks_run.append("snmp")
        try:
            f, log = _check_snmp(req)
            all_findings.extend(f)
            all_tool_outputs["snmp"] = log
        except Exception as e:
            all_errors.append(f"snmp: {e}")

    if EnumType.netbios in req.checks:
        checks_run.append("netbios")
        try:
            f, log = _check_netbios(req)
            all_findings.extend(f)
            all_tool_outputs["netbios"] = log
        except Exception as e:
            all_errors.append(f"netbios: {e}")

    if EnumType.ldap in req.checks:
        checks_run.append("ldap")
        try:
            f, log = _check_ldap(req, auth)
            all_findings.extend(f)
            all_tool_outputs["ldap"] = log
        except Exception as e:
            all_errors.append(f"ldap: {e}")

    if EnumType.nfs in req.checks:
        checks_run.append("nfs")
        try:
            f, log = _check_nfs(req)
            all_findings.extend(f)
            all_tool_outputs["nfs"] = log
        except Exception as e:
            all_errors.append(f"nfs: {e}")

    if EnumType.ad in req.checks:
        checks_run.append("ad")
        try:
            f, log = _check_ad(req, auth)
            all_findings.extend(f)
            all_tool_outputs["ad"] = log
        except Exception as e:
            all_errors.append(f"ad: {e}")

    # ══════════════════════════════════════
    # DEDUPLICATE & SORT
    # ══════════════════════════════════════

    seen: set[str] = set()
    unique: list[NetworkFinding] = []
    for f in all_findings:
        sig = f"{f.check_type}:{f.category}:{f.name}:{f.value}"
        if sig not in seen:
            seen.add(sig)
            unique.append(f)

    sev_order = ["critical", "high", "medium", "low", "info"]
    unique.sort(key=lambda f: sev_order.index(f.severity)
                if f.severity in sev_order else 99)

    # Summary by category
    summary: dict[str, int] = {}
    for f in unique:
        summary[f.category] = summary.get(f.category, 0) + 1

    sev_summary: dict[str, int] = {s: 0 for s in sev_order}
    for f in unique:
        sev_summary[f.severity] = sev_summary.get(f.severity, 0) + 1

    return NetworkEnumResult(
        success        = True,
        target         = req.target,
        checks_run     = checks_run,
        findings       = unique,
        summary        = {**summary, "by_severity": sev_summary},
        tool_outputs   = all_tool_outputs,
        errors         = all_errors,
        execution_time = round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

NETWORK_ENUM_TOOL_DEFINITION = {
    "name": "network_enum",
    "description": (
        "Enumerate network services on a target host or range. "
        "Covers SMB shares (enum4linux, rpcclient), SNMP walks (snmpwalk), "
        "NetBIOS names (nbtscan, nmblookup), LDAP directory (ldapsearch), "
        "NFS exports (showmount, nfs-ls), and Active Directory objects "
        "(users, groups, policies, Kerberoastable/ASREPRoastable accounts). "
        "Supports null sessions and authenticated enumeration."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address, hostname, or CIDR range to enumerate."
            },
            "checks": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["all", "smb", "snmp", "netbios", "ldap", "nfs", "ad"]
                },
                "description": (
                    "Enumeration modules to run:\n"
                    " smb     — SMB shares, users, groups, policy (enum4linux + rpcclient)\n"
                    " snmp    — SNMP community brute + OID walk (snmpwalk)\n"
                    " netbios — NetBIOS name table (nbtscan + nmblookup)\n"
                    " ldap    — LDAP users, groups, computers, policy (ldapsearch)\n"
                    " nfs     — NFS exports + file listing (showmount + nfs-ls)\n"
                    " ad      — AD deep dive: trusts, SPNs, Kerberoast, ASREProast\n"
                    " all     — Run everything above"
                )
            },
            "username":     {"type": "string",  "description": "Username for authenticated enumeration."},
            "password":     {"type": "string",  "description": "Password for authenticated enumeration."},
            "domain":       {"type": "string",  "description": "Windows domain (e.g. 'corp.local')."},
            "communities":  {"type": "array", "items": {"type": "string"},
                             "description": "SNMP community strings. Default: common wordlist."},
            "snmp_version": {"type": "string", "enum": ["1", "2c", "3"],
                             "description": "SNMP version (default '2c')."},
            "ldap_base_dn": {"type": "string",  "description": "LDAP base DN (e.g. 'DC=corp,DC=local')."},
            "ldap_port":    {"type": "integer", "description": "LDAP port (default 389)."},
            "ldap_ssl":     {"type": "boolean", "description": "Use LDAPS/TLS (default false)."},
            "nfs_mount":    {"type": "boolean", "description": "Attempt to mount NFS shares (needs root)."},
            "timeout":      {"type": "integer", "description": "Per-tool timeout in seconds (default 120)."},
            "extra_args":   {
                "type": "object",
                "description": (
                    "Extra raw CLI args per tool. Example:\n"
                    '{"enum4linux": ["-v"], "snmpwalk": ["-On"], '
                    '"ldapsearch": ["-E", "pr=1000/noprompt"]}'
                )
            }
        },
        "required": ["target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 8. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 65)
    print("NETWORK ENUMERATION — EXAMPLES")
    print("=" * 65)

    # ── Example 1: Full unauthenticated scan ─────────────────────
    print("\n=== 1. Full Null-Session Scan ===")
    result = network_enum(
        target  = "192.168.1.100",
        checks  = ["all"],
        timeout = 60,
    )
    print(f"Checks run : {result['checks_run']}")
    print(f"Summary    : {result['summary']}")
    for f in result["findings"]:
        sev = f["severity"].upper()
        print(f"  [{sev:8s}] {f['check_type']:8s} | {f['category']:20s} | "
              f"{f['name'] or ''} {f['value'] or ''}")

    # ── Example 2: Authenticated AD enum ─────────────────────────
    print("\n=== 2. Authenticated Active Directory Enum ===")
    result = network_enum(
        target       = "dc01.corp.local",
        checks       = ["smb", "ldap", "ad"],
        username     = "jdoe",
        password     = "Password123!",
        domain       = "corp.local",
        ldap_base_dn = "DC=corp,DC=local",
        timeout      = 180,
    )
    print(f"Total findings : {len(result['findings'])}")
    for f in result["findings"]:
        if f["severity"] in ("critical", "high"):
            print(f"  [{f['severity'].upper():8s}] {f['description'][:90]}")

    # ── Example 3: SNMP walk with custom communities ──────────────
    print("\n=== 3. SNMP Walk — Custom Community Strings ===")
    result = network_enum(
        target       = "192.168.1.1",
        checks       = ["snmp"],
        communities  = ["public", "private", "network", "cisco"],
        snmp_version = "2c",
        timeout      = 60,
    )
    for f in result["findings"]:
        print(f"  [{f['severity'].upper():8s}] {f['category']:25s} "
              f"{f['name'] or ''}: {f['value'] or ''}")

    # ── Example 4: NFS export hunting ────────────────────────────
    print("\n=== 4. NFS Export Discovery ===")
    result = network_enum(
        target    = "10.10.10.5",
        checks    = ["nfs"],
        nfs_mount = False,
        timeout   = 60,
    )
    for f in result["findings"]:
        print(f"  [{f['severity'].upper():8s}] {f['name']} → {f['value']}")
        print(f"             {f['description']}")

    # ── Example 5: Full JSON output ───────────────────────────────
    print("\n=== 5. Full JSON Payload ===")
    print(json.dumps(result, indent=2, default=str))