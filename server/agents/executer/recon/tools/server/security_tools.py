"""Curated server recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_SERVER_RECON_TOOLS: dict[str, dict[str, object]] = {
    "shodan-cli": {
        "t": "passive",
        "c": "internet_scan_query",
        "u": "shodan host TARGET_IP --fields ip,port,org,hostnames,vulns",
        "d": ["Internet-wide scan data", "Historical banners", "CVE tags", "Geo-location"],
        "tgt": ["external_server", "cloud_asset", "infrastructure_intel"]
    },
    
    "censys-cli": {
        "t": "passive",
        "c": "cert_service_query",
        "u": "censys search 'services.port:443 and ip:TARGET_IP' --fields services.tls.certificate",
        "d": ["Certificate transparency logs", "TLS fingerprinting", "Service metadata"],
        "tgt": ["tls_server", "cloud_infra", "cert_analysis"]
    },
    
    "theHarvester": {
        "t": "passive",
        "c": "osint_enum",
        "u": "theHarvester -d TARGET_DOMAIN -b google,linkedin,github,shodan",
        "d": ["Email harvesting", "Subdomain discovery", "Employee enumeration", "Metadata leaks"],
        "tgt": ["domain_recon", "social_engineering_prep", "asset_inventory"]
    },
    
    "waybackurls + gau": {
        "t": "passive",
        "c": "historical_url_enum",
        "u": "gau TARGET_DOMAIN | grep -iE 'admin|api|backup|config'",
        "d": ["Wayback Machine harvesting", "Hidden endpoint discovery", "Parameter mining"],
        "tgt": ["web_server", "api_recon", "js_analysis"]
    },

    "dnsx": {
        "t": "dns",
        "c": "resolution_probe",
        "u": "dnsx -l subdomains.txt -a -aaaa -cname -mx -ns -resp -cdn -o resolved.txt",
        "d": ["Fast DNS resolution", "Multiple record types", "CDN/WAF detection", "Response codes"],
        "tgt": ["subdomains", "external_recon", "dns_mapping"]
    },
    
    "subfinder": {
        "t": "dns",
        "c": "passive_subdomain_enum",
        "u": "subfinder -d TARGET_DOMAIN -all -recursive -o subs.txt -silent",
        "d": ["30+ passive sources", "Recursive discovery", "API key integration", "Deduplication"],
        "tgt": ["subdomains", "asset_discovery", "attack_surface"]
    },
    
    "amass": {
        "t": "dns",
        "c": "comprehensive_asset_enum",
        "u": "amass enum -passive -d TARGET_DOMAIN -o assets.txt",
        "d": ["DNS enumeration", "ASN mapping", "Cert transparency", "Brute subdomains (optional)"],
        "tgt": ["external_recon", "cloud_assets", "org_mapping"]
    },
    
    "dnsrecon": {
        "t": "dns",
        "c": "advanced_dns_enum",
        "u": "dnsrecon -d TARGET_DOMAIN -t std,axfr,brt,goo,mname",
        "d": ["Zone transfer checks", "SRV records", "Google enum", "Reverse lookups"],
        "tgt": ["dns_misconfigs", "internal_enum", "ad_recon"]
    },
    "nmap": {
        "t": "scan",
        "c": "service_version_enum",
        "u": "nmap -sS -sV -sC -Pn -T4 -oA scan TARGET_IP",
        "d": ["SYN scan", "Version detection", "NSE scripts (safe)", "OS fingerprint (optional)"],
        "tgt": ["any_server", "service_inventory", "port_mapping"]
    },
    
    "masscan": {
        "t": "scan",
        "c": "rapid_port_discovery",
        "u": "masscan TARGET_IP/24 -p1-65535 --rate 10000 -oJ ports.json",
        "d": ["10Gbps async scanning", "Full port range", "JSON output for chaining"],
        "tgt": ["large_ranges", "external_perimeter", "quick_inventory"]
    },
    
    "naabu": {
        "t": "scan",
        "c": "hybrid_port_enum",
        "u": "naabu -host TARGET_IP -p - -rate 5000 -json -o ports.json",
        "d": ["TCP/SYN hybrid scan", "CDN-aware", "Pipe-friendly output", "Service probe optional"],
        "tgt": ["cloud_assets", "api_gateways", "fast_enum"]
    },
    
    "rustscan": {
        "t": "scan",
        "c": "ultra_fast_discovery",
        "u": "rustscan -a TARGET_IP -p 1-65535 -b 2000 -- -sV",
        "d": ["Sub-second port scan", "Auto-pipe to nmap for versioning", "Adaptive timing"],
        "tgt": ["time_sensitive", "large_ranges", "pre_exploit_recon"]
    },
    "httpx": {
        "t": "http",
        "c": "web_probe_enrich",
        "u": "httpx -u TARGET_LIST -status-code -title -tech-detect -cdn -jitter 3 -o live.txt",
        "d": ["Fast HTTP probing", "Tech stack detection", "CDN/WAF identification", "Response headers"],
        "tgt": ["web_server", "api_endpoints", "subdomain_validation"]
    },
    
    "curl": {
        "t": "http",
        "c": "manual_service_probe",
        "u": "curl -i -k -H 'User-Agent: Mozilla/5.0' http://TARGET_IP/ -o response.txt",
        "d": ["Raw HTTP inspection", "Header analysis", "Redirect following", "Manual validation"],
        "tgt": ["web_server", "api_probe", "auth_flow_enum"]
    },
    
    "gobuster": {
        "t": "fuzz",
        "c": "directory_discovery",
        "u": "gobuster dir -u http://TARGET_IP -w common.txt -x php,js,json --timeout 10s",
        "d": ["Directory brute-forcing", "Extension filtering", "Status code filtering", "DNS mode available"],
        "tgt": ["web_server", "hidden_paths", "config_file_discovery"]
    },
    
    "ffuf": {
        "t": "fuzz",
        "c": "parameter_vhost_discovery",
        "u": "ffuf -u http://TARGET_IP/FUZZ -w wordlist.txt -mc 200,301,403 -H 'Host: FUZZ.TARGET_IP'",
        "d": ["Parameter fuzzing", "Vhost discovery", "Header injection testing", "Rate limiting aware"],
        "tgt": ["web_server", "api_recon", "virtual_host_enum"]
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "application_banner_grab",
        "u": "zgrab2 http --port 443 --use-https --max-redirects 3 TARGET_IP",
        "d": ["TLS handshake analysis", "HTTP banner grabbing", "Certificate metadata", "Redirect following"],
        "tgt": ["https_server", "api_gateways", "service_fingerprint"]
    },
    "smbclient": {
        "t": "protocol",
        "c": "smb_share_enum",
        "u": "smbclient -L //TARGET_IP -N 2>/dev/null | grep -i 'disk\\|share'",
        "d": ["List SMB shares", "Null session testing", "Share permission enumeration", "No auth required option"],
        "tgt": ["windows_server", "file_shares", "smb_recon"]
    },
    
    "rpcclient": {
        "t": "protocol",
        "c": "rpc_user_enum",
        "u": "rpcclient -U '' -N TARGET_IP -c 'enumdomusers' 2>/dev/null",
        "d": ["RPC user enumeration", "Null session queries", "Domain info extraction", "SID resolution"],
        "tgt": ["windows_domain", "user_enum", "ad_recon"]
    },
    
    "ldapsearch": {
        "t": "protocol",
        "c": "ldap_directory_enum",
        "u": "ldapsearch -x -H ldap://TARGET_IP -b 'DC=domain,DC=com' '(objectClass=*)' 2>/dev/null | head -100",
        "d": ["LDAP directory queries", "Anonymous bind testing", "Object class enumeration", "Attribute discovery"],
        "tgt": ["active_directory", "ldap_server", "user_group_enum"]
    },
    
    "enum4linux-ng": {
        "t": "protocol",
        "c": "windows_smb_ldap_enum",
        "u": "enum4linux-ng -A TARGET_IP 2>/dev/null | grep -Ei 'user|share|policy'",
        "d": ["SMB user/share enumeration", "RID cycling (safe mode)", "LDAP queries", "Policy extraction"],
        "tgt": ["windows_server", "smb_enum", "ad_recon"]
    },
    
    "nbtscan": {
        "t": "protocol",
        "c": "netbios_enum",
        "u": "nbtscan -r TARGET_IP/24 2>/dev/null | grep -i 'server\\|workstation'",
        "d": ["NetBIOS name resolution", "OS detection via NetBIOS", "Workgroup/domain identification"],
        "tgt": ["windows_network", "internal_enum", "legacy_systems"]
    },
    "snmpwalk": {
        "t": "protocol",
        "c": "snmp_public_enum",
        "u": "snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.1.5 2>/dev/null",
        "d": ["SNMP v2c public community query", "System name retrieval", "Interface enumeration", "Read-only OID walk"],
        "tgt": ["network_devices", "linux_server", "iot_enum"]
    },
    
    "nmap-nse-safe": {
        "t": "scan",
        "c": "safe_script_enum",
        "u": "nmap -sV --script=safe,discovery -Pn TARGET_IP -oA nse_scan",
        "d": ["NSE scripts: banner, http-title, ssl-cert, ssh-hostkey", "No exploitation scripts", "Service metadata"],
        "tgt": ["any_server", "service_enrichment", "safe_enum"]
    },
    
    "whatweb": {
        "t": "http",
        "c": "web_tech_fingerprint",
        "u": "whatweb -a 3 http://TARGET_IP --color=never",
        "d": ["Web framework detection", "CMS identification", "JS library enumeration", "Header analysis"],
        "tgt": ["web_server", "cms_enum", "tech_stack_mapping"]
    },
    
    "wappalyzer-cli": {
        "t": "http",
        "c": "application_stack_enum",
        "u": "wappalyzer http://TARGET_IP --output-json",
        "d": ["Technology profiling", "Framework/version detection", "Analytics/CDN identification"],
        "tgt": ["web_app", "spa_enum", "supply_chain_recon"]
    },
    "traceroute": {
        "t": "topology",
        "c": "path_discovery",
        "u": "traceroute -n TARGET_IP",
        "d": ["Hop-by-hop path mapping", "Latency measurement", "AS path inference", "ICMP/UDP modes"],
        "tgt": ["network_mapping", "cdn_detection", "egress_analysis"]
    },
    
    "mtr": {
        "t": "topology",
        "c": "continuous_path_analysis",
        "u": "mtr -rw -c 100 TARGET_IP --report",
        "d": ["Combined traceroute + ping", "Packet loss per hop", "Jitter analysis", "Report mode"],
        "tgt": ["network_debug", "performance_recon", "routing_anomalies"]
    },
    
    "besttrace": {
        "t": "topology",
        "c": "geo_path_visualization",
        "u": "besttrace -q 1 -g cn TARGET_IP",
        "d": ["ISP-level path visualization", "Geo-IP mapping per hop", "ASN detection", "Multi-region support"],
        "tgt": ["cloud_routing", "multi_region", "cdn_bypass_recon"]
    },

    "tshark": {
        "t": "analysis",
        "c": "protocol_metadata_extraction",
        "u": "tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri 2>/dev/null",
        "d": ["Wireshark CLI", "Display filter queries", "Field extraction", "Protocol statistics"],
        "tgt": ["traffic_analysis", "protocol_enum", "credential_discovery_passive"]
    },
    
    "ja3-fingerprint": {
        "t": "analysis",
        "c": "tls_client_identification",
        "u": "# Use ja3er.com API or local script to match JA3 hashes from captured TLS handshakes",
        "d": ["Client TLS fingerprinting", "Tool/malware identification", "Anomaly detection", "No active probing"],
        "tgt": ["threat_intel", "beacon_detection", "client_profiling"]
    },

    "recon-ng": {
        "t": "automation",
        "c": "modular_osint_framework",
        "u": "recon-ng -r recon_workspace.rc  # Pre-built modules: dnsbrute, shodan, http/recon",
        "d": ["Modular OSINT framework", "Database-backed results", "API key integration", "Report generation"],
        "tgt": ["comprehensive_recon", "bug_bounty", "enterprise_asset_discovery"]
    },
    
    "custom-recon-pipeline": {
        "t": "automation",
        "c": "toolchain_orchestration",
        "u": "# Your script: subfinder | dnsx | httpx | nuclei (safe templates) -o results.json",
        "d": ["Multi-tool chaining", "Deduplication", "JSON output for reporting", "Engagement-specific logic"],
        "tgt": ["scalable_recon", "ci_cd_integration", "client_deliverables"]
    },
    
    "docker-recon-stack": {
        "t": "automation",
        "c": "isolated_toolchain_env",
        "u": "docker run -v $(pwd):/data ghcr.io/projectdiscovery/httpx -list targets.txt -o live.txt",
        "d": ["Reproducible tooling", "Version pinning", "Clean engagement environments", "No host pollution"],
        "tgt": ["all", "lab", "client_workspaces"]
    }
}

SERVER_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_SERVER_RECON_TOOLS)

network_tools = SERVER_RECON_TOOLS
