

from __future__ import annotations

from enum import Enum
from typing import Optional, List

from pydantic import BaseModel, Field
from .credentials import Credential


# ═══════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════


class LinuxDistro(str, Enum):
    """Known distributions — helps select kernel exploits and paths."""
    ubuntu      = "ubuntu"
    debian      = "debian"
    centos      = "centos"
    rhel        = "rhel"
    fedora      = "fedora"
    arch        = "arch"
    alpine      = "alpine"
    kali        = "kali"
    suse        = "suse"
    opensuse    = "opensuse"
    amazon      = "amazon_linux"
    oracle      = "oracle_linux"
    rocky       = "rocky"
    alma        = "alma"
    gentoo      = "gentoo"
    freebsd     = "freebsd"
    openbsd     = "openbsd"
    unknown     = "unknown"


class ServerRole(str, Enum):
    """Server role — determines which service checks to prioritize."""
    web_server      = "web_server"          # Apache, Nginx, Caddy
    database        = "database"            # MySQL, PostgreSQL, MongoDB, Redis
    mail_server     = "mail_server"         # Postfix, Dovecot, Exim
    dns_server      = "dns_server"          # BIND, Unbound, dnsmasq
    file_server     = "file_server"         # NFS, Samba, SFTP
    application     = "application"         # Custom app server
    proxy           = "proxy"               # HAProxy, Nginx reverse proxy, Squid
    ci_cd           = "ci_cd"               # Jenkins, GitLab Runner, GitHub Actions
    monitoring      = "monitoring"          # Prometheus, Grafana, Nagios, Zabbix
    logging         = "logging"             # ELK, Graylog, syslog
    container_host  = "container_host"      # Docker host, Podman
    virtualization  = "virtualization"      # KVM, Proxmox, VMware ESXi
    jump_box        = "jump_box"            # Bastion / SSH gateway
    backup          = "backup"              # Backup server, rsync target
    ldap            = "ldap"                # OpenLDAP, FreeIPA
    vpn_server      = "vpn_server"          # OpenVPN, WireGuard
    generic         = "generic"


class PrivEscVector(str, Enum):
    """Specific privilege escalation vectors to prioritize."""
    suid_sgid       = "suid_sgid"           # SUID/SGID binaries
    sudo_misconfig  = "sudo_misconfig"      # sudo -l abuse
    cron_jobs       = "cron_jobs"            # Writable cron scripts
    capabilities    = "capabilities"        # Linux capabilities abuse
    kernel_exploit  = "kernel_exploit"      # Dirty Pipe, Dirty COW, etc.
    path_hijack     = "path_hijack"         # PATH injection
    ld_preload      = "ld_preload"          # LD_PRELOAD / LD_LIBRARY_PATH
    docker_escape   = "docker_escape"       # Docker socket, privileged container
    nfs_root_squash = "nfs_root_squash"     # NFS no_root_squash
    writable_passwd = "writable_passwd"     # /etc/passwd or /etc/shadow writable
    service_exploit = "service_exploit"     # Exploit running service for root
    lxd_group       = "lxd_group"           # LXD/LXC group membership
    python_library  = "python_library"      # Python library hijacking
    systemd_abuse   = "systemd_abuse"       # Writable unit files / timers
    dbus_abuse      = "dbus_abuse"          # D-Bus policy misconfig
    polkit_bypass   = "polkit_bypass"       # PolicyKit CVEs


# ═══════════════════════════════════════════════════════════════════
# SUB-CONFIGS
# ═══════════════════════════════════════════════════════════════════


class LinuxTargetInfo(BaseModel):
    """Information about the target server. More detail = better plan."""
    ip_address:         str                             # Primary IP
    hostname:           Optional[str] = None            # FQDN
    additional_ips:     Optional[List[str]] = None      # Secondary interfaces
    distro:             Optional[LinuxDistro] = None
    distro_version:     Optional[str] = None            # "22.04", "9.3"
    kernel_version:     Optional[str] = None            # "5.15.0-91-generic"
    architecture:       Optional[str] = None            # "x86_64", "aarch64"
    server_roles:       Optional[List[ServerRole]] = None
    open_ports_known:   Optional[List[int]] = None      # Already known open ports
    notes:              Optional[str] = None


class ServiceConfig(BaseModel):
    """Configuration for service-specific testing."""
    # ── Web servers ────────────────────────────────────────────
    test_web_server:    Optional[bool] = True
    web_ports:          Optional[List[int]] = None      # [80, 443, 8080, 8443]
    web_root_path:      Optional[str] = None            # "/var/www/html"
    web_config_path:    Optional[str] = None            # "/etc/nginx/nginx.conf"

    # ── Databases ──────────────────────────────────────────────
    test_databases:     Optional[bool] = True
    db_type:            Optional[str] = None            # "mysql", "postgresql", "mongodb", "redis"
    db_port:            Optional[int] = None
    db_credentials:     Optional[Credential] = None

    # ── Mail ───────────────────────────────────────────────────
    test_mail:          Optional[bool] = False
    smtp_port:          Optional[int] = 25
    test_open_relay:    Optional[bool] = True
    test_user_enum:     Optional[bool] = True           # VRFY / RCPT TO enumeration

    # ── File sharing ───────────────────────────────────────────
    test_nfs:           Optional[bool] = True
    test_smb:           Optional[bool] = True
    test_ftp:           Optional[bool] = True

    # ── Other ──────────────────────────────────────────────────
    test_snmp:          Optional[bool] = True           # SNMP community strings
    test_ldap:          Optional[bool] = False
    test_dns_zone:      Optional[bool] = True           # DNS zone transfer
    test_rpc:           Optional[bool] = True           # RPC / NFS enumeration


# ═══════════════════════════════════════════════════════════════════
# MAIN LINUX SERVER SCAN REQUEST
# ═══════════════════════════════════════════════════════════════════


class LinuxServerScanRequest(BaseModel):
    # ── Target information ─────────────────────────────────────
    targets:            LinuxTargetInfo
    excluded_hosts:     Optional[List[str]] = None      # IPs to never touch
    port_range:         Optional[str] = "1-65535"       # Port range to scan
    stealth_mode:       Optional[bool] = False          # Slow/quiet scanning

    credentials:        Optional[List[Credential]] = None
    initial_access:     Optional[str] = "none"          # "none", "user", "root"
