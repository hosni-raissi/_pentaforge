"""Curated network recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_NETWORK_RECON_TOOLS: dict[str, dict[str, object]] = {
    "masscan": {
        "t": "scan",
        "c": "port_discovery",
        "u": "masscan TARGET/24 -p1-65535 --rate 10000 -oJ output.json",
        "d": ["10Gbps async scanning", "full port range", "JSON output for chaining"],
        "tgt": ["subnets", "large_ranges", "external_perimeter"]
    },
    
    "naabu": {
        "t": "scan",
        "c": "port_discovery",
        "u": "naabu -host TARGET_LIST -p - -rate 5000 -json -o ports.json",
        "d": ["hybrid TCP/SYN scan", "CDN-aware", "pipe-friendly output"],
        "tgt": ["hosts", "api_gateways", "cloud_assets"]
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
        "u": "arp-scan --interface=eth0 --localnet",
        "d": ["ARP-based host discovery", "MAC vendor lookup", "VLAN hopping prep"],
        "tgt": ["internal_lan", "switched_networks", "arp_spoofing_prep"]
    },
    "nmap": {
        "t": "scan",
        "c": "service_enum",
        "u": "nmap -sS -sV -sC -Pn -T4 -oA scan TARGET",
        "d": ["version detection", "NSE scripting", "OS fingerprint", "firewall evasion"],
        "tgt": ["hosts", "services", "vuln_correlation"]
    },
    
    "rustscan": {
        "t": "scan",
        "c": "fast_port_discovery",
        "u": "rustscan -a TARGET/24 -p 1-65535 -b 2000 -- -sV -sC",
        "d": ["ultra-fast port scan", "auto-pipe to nmap", "adaptive timing"],
        "tgt": ["large_ranges", "time_sensitive_engagements"]
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "banner_grab",
        "u": "zgrab2 ssh --port 22 TARGET_LIST --output-file ssh.json",
        "d": ["application-layer probing", "TLS/SSH/HTTP banners", "cert metadata"],
        "tgt": ["services", "cloud_endpoints", "iot_devices"]
    },
    
    "amass": {
        "t": "recon",
        "c": "asset_discovery",
        "u": "amass enum -active -brute -min-for-recursive 2 -d TARGET.com -o assets.txt",
        "d": ["DNS enumeration", "ASN mapping", "cert transparency", "brute subdomains"],
        "tgt": ["external_recon", "cloud_assets", "attack_surface"]
    },
    "dnsx": {
        "t": "dns",
        "c": "resolution_probe",
        "u": "dnsx -l subdomains.txt -resp -rcode -cdn -o resolved.txt",
        "d": ["fast DNS resolution", "CDN/WAF detection", "multiple record types"],
        "tgt": ["subdomains", "external_recon", "cdn_bypass"]
    },
    
    "subfinder": {
        "t": "dns",
        "c": "passive_enum",
        "u": "subfinder -d TARGET.com -all -o subs.txt -silent",
        "d": ["30+ passive sources", "recursive discovery", "API key integration"],
        "tgt": ["subdomains", "asset_inventory", "bug_bounty"]
    },
    
    "knockpy": {
        "t": "dns",
        "c": "brute_enum",
        "u": "knockpy TARGET.com -w wordlist.txt -o output.csv",
        "d": ["subdomain brute-forcing", "wildcard detection", "CSV export"],
        "tgt": ["subdomains", "internal_dns", "zone_transfer_prep"]
    },
    
    "dnsrecon": {
        "t": "dns",
        "c": "advanced_enum",
        "u": "dnsrecon -d TARGET.com -t std,axfr,brt,goo",
        "d": ["zone transfer", "SRV records", "Google enum", "reverse lookup"],
        "tgt": ["dns_misconfigs", "internal_enum", "ad_recon"]
    },
    "crackmapexec": {
        "t": "protocol",
        "c": "auth_spray_enum",
        "u": "crackmapexec smb TARGET/24 -u users.txt -p passwords.txt --shares",
        "d": ["SMB/WinRM/SSH/LDAP spraying", "share enum", "lateral movement prep"],
        "tgt": ["active_directory", "windows_networks", "credential_testing"]
    },
    
    "impacket-suite": {
        "t": "protocol",
        "c": "protocol_abuse",
        "u": "python3 secretsdump.py DOMAIN/user:pass@TARGET -just-dc",
        "d": ["DCSync", "secretsdump", "wmiexec", "smbexec", "kerberoasting prep"],
        "tgt": ["active_directory", "windows", "kerberos"]
    },
    
    "enum4linux-ng": {
        "t": "protocol",
        "c": "smb_ldap_enum",
        "u": "enum4linux-ng -A TARGET",
        "d": ["SMB user/share enum", "RID cycling", "LDAP query", "policy extraction"],
        "tgt": ["smb", "ldap", "windows_enum"]
    },
    
    "snmpwalk + onesixtyone": {
        "t": "protocol",
        "c": "snmp_enum",
        "u": "onesixtyone -c communities.txt TARGET && snmpwalk -v2c -c public TARGET",
        "d": ["community string brute", "MIB traversal", "device config leak"],
        "tgt": ["network_devices", "iot", "legacy_infrastructure"]
    },
    
    "showmount": {
        "t": "protocol",
        "c": "nfs_enum",
        "u": "showmount -e TARGET",
        "d": ["NFS export listing", "permission mapping", "mount point discovery"],
        "tgt": ["nfs", "unix_networks", "file_shares"]
    },
    "ike-scan": {
        "t": "vpn",
        "c": "ipsec_discovery",
        "u": "ike-scan -M TARGET --retry=3",
        "d": ["IPSec gateway detection", "transform enumeration", "aggressive mode prep"],
        "tgt": ["vpn_gateways", "site_to_site", "remote_access"]
    },
    
    "rdp-sec-check": {
        "t": "protocol",
        "c": "rdp_enum",
        "u": "rdp-sec-check.pl TARGET",
        "d": ["RDP encryption check", "NLA detection", "CVE correlation"],
        "tgt": ["rdp", "windows_remote", "bluekeep_prep"]
    },
    
    "ssh-audit": {
        "t": "protocol",
        "c": "ssh_hardening_check",
        "u": "ssh-audit TARGET -p 22",
        "d": ["algorithm strength", "CVE mapping", "config hardening advice"],
        "tgt": ["ssh", "linux_servers", "key_management"]
    },
    "shodan-cli": {
        "t": "passive",
        "c": "internet_scan_query",
        "u": "shodan host TARGET_IP --fields ip,port,org,hostnames",
        "d": ["internet-wide scan data", "historical banners", "vuln tags"],
        "tgt": ["external_assets", "cloud_exposure", "leak_detection"]
    },
    
    "censys-cli": {
        "t": "passive",
        "c": "cert_host_query",
        "u": "censys search 'services.port:443 and ip:TARGET/24' --fields ip,services.tls.certificate",
        "d": ["certificate transparency", "service fingerprinting", "ASN mapping"],
        "tgt": ["tls_assets", "cloud_infra", "cert_misconfigs"]
    },
    
    "theHarvester": {
        "t": "passive",
        "c": "osint_enum",
        "u": "theHarvester -d TARGET.com -b google,linkedin,github",
        "d": ["email harvesting", "subdomain discovery", "employee enumeration"],
        "tgt": ["osint", "phishing_prep", "social_engineering"]
    },
    
    "assetfinder + httpx": {
        "t": "passive",
        "c": "pipeline_discovery",
        "u": "assetfinder TARGET.com | httpx -silent -status-code -title -o live.txt",
        "d": ["fast domain resolution", "HTTP probing", "pipeline-friendly"],
        "tgt": ["external_recon", "bug_bounty", "attack_surface"]
    },
    "traceroute + mtr": {
        "t": "topology",
        "c": "path_analysis",
        "u": "mtr -rw TARGET --report",
        "d": ["hop-by-hop latency", "packet loss mapping", "routing anomalies"],
        "tgt": ["network_mapping", "cdn_detection", "egress_points"]
    },
    
    "besttrace": {
        "t": "topology",
        "c": "geo_path_trace",
        "u": "besttrace -q 1 TARGET",
        "d": ["ISP-level path visualization", "geo-IP mapping", "ASN detection"],
        "tgt": ["cloud_routing", "multi_region", "egress_analysis"]
    },
    
    "netdiscover": {
        "t": "topology",
        "c": "arp_recon",
        "u": "netdiscover -r TARGET/24 -i eth0",
        "d": ["active/passive ARP scan", "device fingerprinting", "vlan mapping"],
        "tgt": ["internal_lan", "wireless", "iot_networks"]
    },
    "chisel": {
        "t": "pivot",
        "c": "tcp_tunnel",
        "u": "chisel server -p 8080 --reverse && chisel client TARGET:8080 R:socks",
        "d": ["encrypted TCP tunneling", "SOCKS5 proxy", "reverse/forward modes"],
        "tgt": ["internal_pivot", "cloud_breach", "egress_bypass"]
    },
    
    "proxychains-ng": {
        "t": "pivot",
        "c": "proxy_chain",
        "u": "proxychains -q nmap -sT -Pn TARGET",
        "d": ["chain multiple proxies", "TCP-only support", "tool compatibility"],
        "tgt": ["internal_scan", "tor_routing", "multi_hop"]
    },
    
    "ligolo-ng": {
        "t": "pivot",
        "c": "tunnel_interface",
        "u": "ligolo-ng-agent -listen 0.0.0.0:443 && ligolo-ng-controller -connect TARGET:443",
        "d": ["TUN/TAP interface tunneling", "full network stack", "no port forwarding needed"],
        "tgt": ["advanced_pivot", "internal_enum", "red_team_ops"]
    },
    
    "sshuttle": {
        "t": "pivot",
        "c": "transparent_proxy",
        "u": "sshuttle -r user@TARGET 10.0.0.0/8 192.168.0.0/16",
        "d": ["transparent VPN over SSH", "no root on remote", "subnet routing"],
        "tgt": ["ssh_pivot", "internal_network", "quick_access"]
    },
    "tshark": {
        "t": "analysis",
        "c": "cli_packet_capture",
        "u": "tshark -i eth0 -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri",
        "d": ["Wireshark CLI", "powerful display filters", "field extraction"],
        "tgt": ["traffic_analysis", "credential_capture", "protocol_debug"]
    },
    
    "tcpdump": {
        "t": "analysis",
        "c": "raw_capture",
        "u": "tcpdump -i any -w capture.pcap 'port 80 or port 443'",
        "d": ["lightweight packet capture", "BPF filtering", "forensic export"],
        "tgt": ["network_debug", "evidence_collection", "trigger_based_capture"]
    },
    
    "ja3er + tls-fingerprint": {
        "t": "analysis",
        "c": "tls_client_fingerprint",
        "u": "# Use ja3er.com API or custom script to match JA3 hashes",
        "d": ["client TLS fingerprinting", "malware C2 detection", "tool identification"],
        "tgt": ["threat_hunting", "beacon_detection", "anomaly_analysis"]
    },
    "nuclei + network-templates": {
        "t": "automation",
        "c": "network_vuln_scan",
        "u": "nuclei -l hosts.txt -t network/ -severity critical,high -o net_vulns.txt",
        "d": ["CVE checks", "misconfig detection", "protocol-specific templates"],
        "tgt": ["network_services", "iot", "infrastructure"]
    },
    
    "custom-python-recon": {
        "t": "automation",
        "c": "logic_orchestration",
        "u": "# Your repo: subnet_chainer.py, cred_spray_orchestrator.py",
        "d": ["multi-tool chaining", "custom auth flows", "engagement-specific logic"],
        "tgt": ["advanced_ops", "red_team", "client_pipelines"]
    },
    
    "docker + recon-toolchains": {
        "t": "automation",
        "c": "isolated_envs",
        "u": "docker run -v $(pwd):/data ghcr.io/projectdiscovery/naabu -list targets.txt",
        "d": ["reproducible tooling", "version pinning", "clean engagement envs"],
        "tgt": ["all", "lab", "client_deliverables"]
    }
}

NETWORK_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_NETWORK_RECON_TOOLS)

network_tools = NETWORK_RECON_TOOLS
