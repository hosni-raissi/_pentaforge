"""Curated network recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_NETWORK_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PORT & HOST DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "masscan": {
        "t": "scan",
        "c": "port_discovery",
        "u": "masscan TARGET/24 -p1-65535 --rate 10000 --output-format json 2>/dev/null | jq -c '.[]?'",
        "d": ["10Gbps async scanning", "full port range", "JSON output for chaining"],
        "tgt": ["subnets", "large_ranges", "external_perimeter"],
        "note": "--output-format json streams to stdout; pipe to jq for filtering"
    },
    
    "naabu": {
        "t": "scan",
        "c": "port_discovery",
        "u": "echo '(WORDLIST:hosts)' | naabu -list - -p - -rate 5000 -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["hybrid TCP/SYN scan", "CDN-aware", "pipe-friendly JSON output"],
        "tgt": ["hosts", "api_gateways", "cloud_assets"],
        "note": "(WORDLIST:hosts) piped via stdin; -list - reads from stdin"
    },
    
    "fping": {
        "t": "discovery",
        "c": "icmp_sweep",
        "u": "fping -a -g TARGET/24 2>/dev/null | grep alive",
        "d": ["fast ICMP enumeration", "parallel probing", "scriptable output"],
        "tgt": ["internal_network", "dmz", "vlan_ranges"]
    },
    
    "arp-scan": {
        "t": "discovery",
        "c": "layer2_enum",
        "u": "arp-scan --interface=eth0 --localnet 2>/dev/null | grep -v '^$'",
        "d": ["ARP-based host discovery", "MAC vendor lookup", "VLAN hopping prep"],
        "tgt": ["internal_lan", "switched_networks", "arp_spoofing_prep"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 SERVICE ENUMERATION & BANNER GRABBING
    # ─────────────────────────────────────────────────────────────
    "nmap": {
        "t": "scan",
        "c": "service_enum",
        "u": "nmap -sS -sV -sC -Pn -T4 --open -oG - TARGET 2>/dev/null | grep -E '^[0-9]+\\.|Host:'",
        "d": ["version detection", "NSE scripting", "OS fingerprint", "firewall evasion"],
        "tgt": ["hosts", "services", "vuln_correlation"],
        "note": "-oG - outputs grepable format to stdout; avoid -oA for fileless mode"
    },
    
    "rustscan": {
        "t": "scan",
        "c": "fast_port_discovery",
        "u": "rustscan -a TARGET/24 -p 1-65535 -b 2000 -- -sV -sC --open -oG - 2>/dev/null | grep -E '^[0-9]+\\.|Ports:'",
        "d": ["ultra-fast port scan", "auto-pipe to nmap", "adaptive timing"],
        "tgt": ["large_ranges", "time_sensitive_engagements"],
        "note": "RustScan pipes to nmap; -oG - ensures stdout output"
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "banner_grab",
        "u": "echo TARGET | zgrab2 ssh --port 22 --output-file=- 2>/dev/null | jq -c '.[]?.result?'",
        "d": ["application-layer probing", "TLS/SSH/HTTP banners", "cert metadata"],
        "tgt": ["services", "cloud_endpoints", "iot_devices"],
        "note": "--output-file=- streams JSON to stdout for jq filtering"
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 DNS & SUBDOMAIN RECON
    # ─────────────────────────────────────────────────────────────
    "amass": {
        "t": "recon",
        "c": "asset_discovery",
        "u": "amass enum -active -brute -min-for-recursive 2 -d TARGET.com -silent 2>/dev/null | sort -u",
        "d": ["DNS enumeration", "ASN mapping", "cert transparency", "brute subdomains"],
        "tgt": ["external_recon", "cloud_assets", "attack_surface"],
        "note": "Removed -o assets.txt; output to stdout for piping"
    },
    
    "dnsx": {
        "t": "dns",
        "c": "resolution_probe",
        "u": "echo '(WORDLIST:subs)' | dnsx -list - -resp -rcode -cdn -silent -json 2>/dev/null | jq -c '.[]?'",
        "d": ["fast DNS resolution", "CDN/WAF detection", "multiple record types", "JSON to stdout"],
        "tgt": ["subdomains", "external_recon", "cdn_bypass"],
        "note": "(WORDLIST:subs) piped via stdin; -list - reads from stdin"
    },
    
    "subfinder": {
        "t": "dns",
        "c": "passive_enum",
        "u": "subfinder -d TARGET.com -all -silent -nW 2>/dev/null | grep -v '^$'",
        "d": ["30+ passive sources", "recursive discovery", "API key integration"],
        "tgt": ["subdomains", "asset_inventory", "bug_bounty"],
        "note": "Removed -o subs.txt; output to stdout for chaining"
    },
    
    "knockpy": {
        "t": "dns",
        "c": "brute_enum",
        "u": "knockpy TARGET.com -w (WORDLIST:subdomains) --output - 2>/dev/null | grep -E '^[A-Za-z]'",
        "d": ["subdomain brute-forcing", "wildcard detection", "CSV to stdout"],
        "tgt": ["subdomains", "internal_dns", "zone_transfer_prep"],
        "note": "(WORDLIST:subdomains) resolved at runtime; --output - for stdout"
    },
    
    "dnsrecon": {
        "t": "dns",
        "c": "advanced_enum",
        "u": "dnsrecon -d TARGET.com -t std,axfr,brt,goo -j - 2>/dev/null | jq -r '.[]?.target?'",
        "d": ["zone transfer", "SRV records", "Google enum", "reverse lookup"],
        "tgt": ["dns_misconfigs", "internal_enum", "ad_recon"],
        "note": "-j - outputs JSON to stdout instead of file"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 PROTOCOL ENUMERATION & AUTH TESTING
    # ─────────────────────────────────────────────────────────────
    "crackmapexec": {
        "t": "protocol",
        "c": "auth_spray_enum",
        "u": "crackmapexec smb TARGET/24 -u (WORDLIST:users) -p (WORDLIST:passwords) --shares --no-progress 2>/dev/null | grep -E '^\\S+\\s+\\S+\\s+\\S+'",
        "d": ["SMB/WinRM/SSH/LDAP spraying", "share enum", "lateral movement prep"],
        "tgt": ["active_directory", "windows_networks", "credential_testing"],
        "note": "(WORDLIST:users) and (WORDLIST:passwords) resolved at runtime"
    },
    
    "impacket-suite": {
        "t": "protocol",
        "c": "protocol_abuse",
        "u": "python3 secretsdump.py DOMAIN/(SECRET:user):(SECRET:pass)@TARGET -just-dc -no-pass 2>/dev/null | grep -E '^[A-Za-z]'",
        "d": ["DCSync", "secretsdump", "wmiexec", "smbexec", "kerberoasting prep"],
        "tgt": ["active_directory", "windows", "kerberos"],
        "note": "(SECRET:user) and (SECRET:pass) injected at runtime"
    },
    
    "enum4linux-ng": {
        "t": "protocol",
        "c": "smb_ldap_enum",
        "u": "enum4linux-ng -A TARGET 2>/dev/null | grep -E '^\\[\\+\\]|^\\[\\*\\]'",
        "d": ["SMB user/share enum", "RID cycling", "LDAP query", "policy extraction"],
        "tgt": ["smb", "ldap", "windows_enum"]
    },
    
    "snmp-enum": {
        "t": "protocol",
        "c": "snmp_enum",
        "u": "echo '(WORDLIST:communities)' | xargs -I{} onesixtyone -c {} TARGET 2>/dev/null | grep -E '^\\[\\+\\]'; snmpwalk -v2c -c (SECRET:snmp_community) TARGET 1.3.6.1.2.1.1 2>/dev/null | grep -E 'sysName|sysDescr'",
        "d": ["community string brute", "MIB traversal", "device config leak"],
        "tgt": ["network_devices", "iot", "legacy_infrastructure"],
        "note": "(WORDLIST:communities) piped via stdin; (SECRET:snmp_community) defaults to 'public'"
    },
    
    "showmount": {
        "t": "protocol",
        "c": "nfs_enum",
        "u": "showmount -e TARGET 2>/dev/null | grep -v '^$'",
        "d": ["NFS export listing", "permission mapping", "mount point discovery"],
        "tgt": ["nfs", "unix_networks", "file_shares"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔒 VPN & REMOTE ACCESS RECON
    # ─────────────────────────────────────────────────────────────
    "ike-scan": {
        "t": "vpn",
        "c": "ipsec_discovery",
        "u": "ike-scan -M TARGET --retry=3 2>/dev/null | grep -E '^TARGET|transform'",
        "d": ["IPSec gateway detection", "transform enumeration", "aggressive mode prep"],
        "tgt": ["vpn_gateways", "site_to_site", "remote_access"]
    },
    
    "rdp-sec-check": {
        "t": "protocol",
        "c": "rdp_enum",
        "u": "rdp-sec-check.pl TARGET 2>/dev/null | grep -E '^\\[\\+\\]|^\\[\\*\\]|^\\[\\-\\]'",
        "d": ["RDP encryption check", "NLA detection", "CVE correlation"],
        "tgt": ["rdp", "windows_remote", "bluekeep_prep"]
    },
    
    "ssh-audit": {
        "t": "protocol",
        "c": "ssh_hardening_check",
        "u": "ssh-audit TARGET -p 22 2>/dev/null | grep -E '^\\+|^-|algorithm'",
        "d": ["algorithm strength", "CVE mapping", "config hardening advice"],
        "tgt": ["ssh", "linux_servers", "key_management"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌍 PASSIVE OSINT & INTERNET-WIDE RECON
    # ─────────────────────────────────────────────────────────────
    "shodan-cli": {
        "t": "passive",
        "c": "internet_scan_query",
        "u": "shodan host TARGET_IP --fields ip,port,org,hostnames 2>/dev/null",
        "d": ["internet-wide scan data", "historical banners", "vuln tags"],
        "tgt": ["external_assets", "cloud_exposure", "leak_detection"],
        "note": "Requires SHODAN_API_KEY env var"
    },
    
    "censys-cli": {
        "t": "passive",
        "c": "cert_host_query",
        "u": "censys search 'services.port:443 and ip:TARGET/24' --fields ip,services.tls.certificate 2>/dev/null | jq -c '.[]?'",
        "d": ["certificate transparency", "service fingerprinting", "ASN mapping"],
        "tgt": ["tls_assets", "cloud_infra", "cert_misconfigs"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars"
    },
    
    "theHarvester": {
        "t": "passive",
        "c": "osint_enum",
        "u": "theHarvester -d TARGET.com -b google,linkedin,github -f - 2>/dev/null | grep -E '^[A-Za-z0-9]'",
        "d": ["email harvesting", "subdomain discovery", "employee enumeration"],
        "tgt": ["osint", "phishing_prep", "social_engineering"],
        "note": "-f - outputs to stdout instead of HTML file"
    },
    
    # ─────────────────────────────────────────────────────────────
    # 🗺️ NETWORK TOPOLOGY & PATH ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "mtr": {
        "t": "topology",
        "c": "path_analysis",
        "u": "mtr -rw TARGET --report --csv 2>/dev/null | head -20",
        "d": ["hop-by-hop latency", "packet loss mapping", "routing anomalies", "CSV to stdout"],
        "tgt": ["network_mapping", "cdn_detection", "egress_points"],
        "note": "--csv outputs structured data; head limits verbose output"
    },
    
    "besttrace": {
        "t": "topology",
        "c": "geo_path_trace",
        "u": "besttrace -q 1 TARGET 2>/dev/null | grep -E 'ms|AS'",
        "d": ["ISP-level path visualization", "geo-IP mapping", "ASN detection"],
        "tgt": ["cloud_routing", "multi_region", "egress_analysis"]
    },
    
    "netdiscover": {
        "t": "topology",
        "c": "arp_recon",
        "u": "netdiscover -r TARGET/24 -i eth0 -p 2>/dev/null | grep -E '^[0-9a-f]'",
        "d": ["active/passive ARP scan", "device fingerprinting", "vlan mapping"],
        "tgt": ["internal_lan", "wireless", "iot_networks"],
        "note": "-p for passive mode; output filtered for relevant lines"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔄 PIVOTING & TUNNELING
    # ─────────────────────────────────────────────────────────────
    "chisel": {
        "t": "pivot",
        "c": "tcp_tunnel",
        "u": "# Server: chisel server -p 8080 --reverse; Client: chisel client TARGET:8080 R:socks",
        "d": ["encrypted TCP tunneling", "SOCKS5 proxy", "reverse/forward modes"],
        "tgt": ["internal_pivot", "cloud_breach", "egress_bypass"],
        "note": "Interactive setup; use systemd/socket activation for persistent tunnels"
    },
    
    "proxychains-ng": {
        "t": "pivot",
        "c": "proxy_chain",
        "u": "proxychains -q -f (CONFIG:proxychains) nmap -sT -Pn TARGET 2>/dev/null | grep -E '^[0-9]+\\.|PORT'",
        "d": ["chain multiple proxies", "TCP-only support", "tool compatibility"],
        "tgt": ["internal_scan", "tor_routing", "multi_hop"],
        "note": "(CONFIG:proxychains) resolves to /etc/proxychains.conf or injected path"
    },
    
    "ligolo-ng": {
        "t": "pivot",
        "c": "tunnel_interface",
        "u": "# Agent: ligolo-ng-agent -listen 0.0.0.0:443; Controller: ligolo-ng-controller -connect TARGET:443",
        "d": ["TUN/TAP interface tunneling", "full network stack", "no port forwarding needed"],
        "tgt": ["advanced_pivot", "internal_enum", "red_team_ops"],
        "note": "Interactive; use tmux/screen for background execution"
    },
    
    "sshuttle": {
        "t": "pivot",
        "c": "transparent_proxy",
        "u": "sshuttle -r (SECRET:ssh_user)@TARGET 10.0.0.0/8 192.168.0.0/16 --dns -v 2>&1 | grep -E 'connected|route'",
        "d": ["transparent VPN over SSH", "no root on remote", "subnet routing"],
        "tgt": ["ssh_pivot", "internal_network", "quick_access"],
        "note": "(SECRET:ssh_user) injected at runtime; -v for verbose connection logs"
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 TRAFFIC ANALYSIS & PACKET INSPECTION
    # ─────────────────────────────────────────────────────────────
    "tshark": {
        "t": "analysis",
        "c": "cli_packet_capture",
        "u": "tshark -i eth0 -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri 2>/dev/null | head -50",
        "d": ["Wireshark CLI", "powerful display filters", "field extraction"],
        "tgt": ["traffic_analysis", "credential_capture", "protocol_debug"],
        "note": "Requires cap_net_raw; use timeout to prevent hanging"
    },
    
    "tcpdump": {
        "t": "analysis",
        "c": "raw_capture",
        "u": "timeout 30 tcpdump -i any -nn -l 'port 80 or port 443' 2>/dev/null | grep -E 'IP|TCP'",
        "d": ["lightweight packet capture", "BPF filtering", "line-buffered stdout"],
        "tgt": ["network_debug", "evidence_collection", "trigger_based_capture"],
        "note": "-l for line buffering; timeout prevents indefinite capture; avoid -w for fileless mode"
    },
    
    "ja3-fingerprint": {
        "t": "analysis",
        "c": "tls_client_fingerprint",
        "u": "# Query ja3er.com API: curl -s 'https://ja3er.com/search?hash=JA3_HASH' | jq",
        "d": ["client TLS fingerprinting", "malware C2 detection", "tool identification"],
        "tgt": ["threat_hunting", "beacon_detection", "anomaly_analysis"],
        "note": "Use custom script or API call; no local file I/O"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "nuclei-network": {
        "t": "automation",
        "c": "network_vuln_scan",
        "u": "echo '(WORDLIST:hosts)' | nuclei -list - -t network/ -severity critical,high -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["CVE checks", "misconfig detection", "protocol-specific templates", "JSON to stdout"],
        "tgt": ["network_services", "iot", "infrastructure"],
        "note": "(WORDLIST:hosts) piped via stdin; -list - reads from stdin"
    },
    
    "custom-python-recon": {
        "t": "automation",
        "c": "logic_orchestration",
        "u": "# Your repo: subnet_chainer.py, cred_spray_orchestrator.py — output JSON to stdout",
        "d": ["multi-tool chaining", "custom auth flows", "engagement-specific logic"],
        "tgt": ["advanced_ops", "red_team", "client_pipelines"]
    },
    
    "docker-recon-toolchain": {
        "t": "automation",
        "c": "isolated_envs",
        "u": "echo '(WORDLIST:targets)' | docker run --rm -i ghcr.io/projectdiscovery/naabu:latest -list - -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["reproducible tooling", "version pinning", "clean engagement envs", "JSON to stdout"],
        "tgt": ["all", "lab", "client_deliverables"],
        "note": "(WORDLIST:targets) piped via stdin; -list - reads from stdin"
    },
    "john": {
    "t": "password_crack",
    "c": "offline_hash_cracking",
    "u": "echo '(MANIFEST:hashes)' | john --format=auto --wordlist=(WORDLIST:passwords) --stdout --pot=none - 2>/dev/null | grep -v '^Using'",
    "d": [
        "offline password hash cracking",
        "auto-format detection (NTLM, SHA, bcrypt, etc.)",
        "wordlist + rule-based attacks",
        "cracked passwords to stdout",
        "no .pot file writes (--pot=none)"
    ],
    "tgt": [
        "ntlm", "kerberos", "sha1", "sha256", "sha512", "bcrypt", 
        "md5", "ssh_keys", "zip", "pdf", "local_accounts", 
        "dumped_credentials", "hash_cracking", "post_exploitation"
    ],
    "note": "(MANIFEST:hashes) piped via stdin in John format (user:hash); (WORDLIST:passwords) resolved at runtime; --stdout outputs cracked creds; --pot=none avoids file writes",
    "alt": "john --format=nt --wordlist=(WORDLIST:passwords) --stdout --pot=none - 2>/dev/null"
    },
    "hydra": {
    "t": "auth_bruteforce",
    "c": "online_password_spray",
    "u": "echo '(WORDLIST:userpass)' | hydra -L - -P - -t 4 -f -o - TARGET SERVICE 2>/dev/null | grep -E '^\\[\\+\\]|password'",
    "d": [
        "online credential brute-forcing",
        "protocol-aware authentication testing",
        "parallel connection handling",
        "early exit on first success",
        "stdout results for chaining"
    ],
    "tgt": [
        "ssh", "ftp", "http", "https", "smb", "rdp", 
        "mysql", "postgres", "ldap", "smtp", "pop3", 
        "active_directory", "network_services", "auth_testing"
    ],
    "note": "(WORDLIST:userpass) piped via stdin as 'user:pass' pairs; -o - outputs to stdout; SERVICE = ssh/ftp/http/etc.",
    "alt": "hydra -l user -P (WORDLIST:passwords) -t 4 -f TARGET SERVICE 2>/dev/null | grep -E '^\\[\\+\\]'"
    },
}

NETWORK_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_NETWORK_RECON_TOOLS)

# ✅ Alias is already correct and consistent
network_tools = NETWORK_RECON_TOOLS
