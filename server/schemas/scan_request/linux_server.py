

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


# ═══════════════════════════════════════════════════════════════════
# MAIN LINUX SERVER SCAN REQUEST
# ═══════════════════════════════════════════════════════════════════


class LinuxServerScanRequest(BaseModel):
    # ── Target information ─────────────────────────────────────
    
    ip_address:         str                             # Primary IP
    hostname:           Optional[str] = None            # FQDN
    additional_ips:     Optional[List[str]] = None      # Secondary interfaces
    distro:             Optional[LinuxDistro] = None          # "5.15.0-91-generic"
    architecture:       Optional[str] = None            # "x86_64", "aarch64"
    server_roles:       Optional[List[ServerRole]] = None
    open_ports_known:   Optional[List[int]] = None  
    credentials:        Optional[List[Credential]] = None 
    description:        Optional[str] = None        # "none", "user", "root"
