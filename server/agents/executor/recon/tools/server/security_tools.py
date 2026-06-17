"""Curated server recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_SERVER_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 PASSIVE OSINT & EXTERNAL RECON
    # ─────────────────────────────────────────────────────────────
    "shodan-cli": {
        "t": "passive",
        "c": "internet_scan_query",
        "u": "shodan host TARGET_IP --fields ip,port,org,hostnames,vulns 2>/dev/null",
        "d": ["Internet-wide scan data", "Historical banners", "CVE tags", "Geo-location"],
        "tgt": ["external_server", "cloud_asset", "infrastructure_intel"],
        "note": "Requires SHODAN_API_KEY env var"
    },
    
    "censys-cli": {
        "t": "passive",
        "c": "cert_service_query",
        "u": "censys search 'services.port:443 and ip:TARGET_IP' --fields services.tls.certificate 2>/dev/null | jq -c '.[]?'",
        "d": ["Certificate transparency logs", "TLS fingerprinting", "Service metadata"],
        "tgt": ["tls_server", "cloud_infra", "cert_analysis"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars"
    },
    
    "theHarvester": {
        "t": "passive",
        "c": "osint_enum",
        "u": "theHarvester -d TARGET_DOMAIN -b google,linkedin,github,shodan -f - 2>/dev/null | grep -E '^[A-Za-z0-9]'",
        "d": ["Email harvesting", "Subdomain discovery", "Employee enumeration", "Metadata leaks"],
        "tgt": ["domain_recon", "social_engineering_prep", "asset_inventory"],
        "note": "-f - outputs to stdout instead of HTML file"
    },
    
    "gau-historical": {
        "t": "passive",
        "c": "historical_url_enum",
        "u": "gau TARGET_DOMAIN 2>/dev/null | grep -iE 'admin|api|backup|config' | sort -u",
        "d": ["Wayback Machine harvesting", "Hidden endpoint discovery", "Parameter mining"],
        "tgt": ["web_server", "api_recon", "js_analysis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 DNS ENUMERATION & SUBDOMAIN DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "dnsx": {
        "t": "dns",
        "c": "resolution_probe",
        "u": "echo '(WORDLIST:subdomains)' | dnsx -list - -a -aaaa -cname -mx -ns -resp -cdn -silent -json 2>/dev/null | jq -c '.[]?'",
        "d": ["Fast DNS resolution", "Multiple record types", "CDN/WAF detection", "JSON to stdout"],
        "tgt": ["subdomains", "external_recon", "dns_mapping"],
        "note": "(WORDLIST:subdomains) piped via stdin; -list - reads from stdin"
    },
    
    "subfinder": {
        "t": "dns",
        "c": "passive_subdomain_enum",
        "u": "subfinder -d TARGET_DOMAIN -all -recursive -silent -nW 2>/dev/null | grep -v '^$'",
        "d": ["30+ passive sources", "Recursive discovery", "API key integration", "Deduplication"],
        "tgt": ["subdomains", "asset_discovery", "attack_surface"],
        "note": "Removed -o subs.txt; output to stdout for chaining"
    },
    
    "amass": {
        "t": "dns",
        "c": "comprehensive_asset_enum",
        "u": "amass enum -passive -d TARGET_DOMAIN -silent 2>/dev/null | sort -u",
        "d": ["DNS enumeration", "ASN mapping", "Cert transparency", "Brute subdomains (optional)"],
        "tgt": ["external_recon", "cloud_assets", "org_mapping"],
        "note": "Removed -o assets.txt; output to stdout for piping"
    },
    
    "dnsrecon": {
        "t": "dns",
        "c": "advanced_dns_enum",
        "u": "dnsrecon -d TARGET_DOMAIN -t std,axfr,brt,goo,mname -j - 2>/dev/null | jq -r '.[]?.target?'",
        "d": ["Zone transfer checks", "SRV records", "Google enum", "Reverse lookups"],
        "tgt": ["dns_misconfigs", "internal_enum", "ad_recon"],
        "note": "-j - outputs JSON to stdout instead of file"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔍 PORT & SERVICE SCANNING
    # ─────────────────────────────────────────────────────────────
    "nmap": {
        "t": "scan",
        "c": "service_version_enum",
        "u": "nmap -sS -sV -sC -Pn -T4 --open -oG - TARGET_IP 2>/dev/null | grep -E '^[0-9]+\\.|Host:'",
        "d": ["SYN scan", "Version detection", "NSE scripts (safe)", "OS fingerprint (optional)"],
        "tgt": ["any_server", "service_inventory", "port_mapping"],
        "note": "-oG - outputs grepable format to stdout; avoid -oA for fileless mode"
    },
    
    "masscan": {
        "t": "scan",
        "c": "rapid_port_discovery",
        "u": "masscan TARGET_IP/24 -p1-65535 --rate 10000 --output-format json 2>/dev/null | jq -c '.[]?'",
        "d": ["10Gbps async scanning", "Full port range", "JSON output for chaining"],
        "tgt": ["large_ranges", "external_perimeter", "quick_inventory"],
        "note": "--output-format json streams to stdout; pipe to jq for filtering"
    },
    
    "naabu": {
        "t": "scan",
        "c": "hybrid_port_enum",
        "u": "echo '(WORDLIST:hosts)' | naabu -list - -p - -rate 5000 -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["TCP/SYN hybrid scan", "CDN-aware", "Pipe-friendly JSON output", "Service probe optional"],
        "tgt": ["cloud_assets", "api_gateways", "fast_enum"],
        "note": "(WORDLIST:hosts) piped via stdin; -list - reads from stdin"
    },
    
    "rustscan": {
        "t": "scan",
        "c": "ultra_fast_discovery",
        "u": "rustscan -a TARGET_IP -p 1-65535 -b 2000 -- -sV --open -oG - 2>/dev/null | grep -E '^[0-9]+\\.|Ports:'",
        "d": ["Sub-second port scan", "Auto-pipe to nmap for versioning", "Adaptive timing"],
        "tgt": ["time_sensitive", "large_ranges", "pre_exploit_recon"],
        "note": "RustScan pipes to nmap; -oG - ensures stdout output"
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 HTTP/Web Probing & Fuzzing
    # ─────────────────────────────────────────────────────────────
    "httpx": {
        "t": "http",
        "c": "web_probe_enrich",
        "u": "echo '(WORDLIST:targets)' | httpx -silent -status-code -title -tech-detect -cdn -jitter 3 -json 2>/dev/null | jq -c '.[]?'",
        "d": ["Fast HTTP probing", "Tech stack detection", "CDN/WAF identification", "JSON to stdout"],
        "tgt": ["web_server", "api_endpoints", "subdomain_validation"],
        "note": "(WORDLIST:targets) piped via stdin; -json outputs structured data"
    },
    
    "curl": {
        "t": "http",
        "c": "manual_service_probe",
        "u": "curl -i -k -s -H 'User-Agent: Mozilla/5.0' http://TARGET_IP/ 2>/dev/null",
        "d": ["Raw HTTP inspection", "Header analysis", "Redirect following", "Manual validation"],
        "tgt": ["web_server", "api_probe", "auth_flow_enum"],
        "note": "Default output to stdout; removed -o response.txt"
    },
    
    "gobuster": {
        "t": "fuzz",
        "c": "directory_discovery",
        "u": "gobuster dir -u http://TARGET_IP -w (WORDLIST:common) -x php,js,json --timeout 10s --quiet 2>/dev/null",
        "d": ["Directory brute-forcing", "Extension filtering", "Status code filtering", "DNS mode available"],
        "tgt": ["web_server", "hidden_paths", "config_file_discovery"],
        "note": "(WORDLIST:common) resolved at runtime; --quiet for stdout-only"
    },
    
    "ffuf": {
        "t": "fuzz",
        "c": "parameter_vhost_discovery",
        "u": "ffuf -u http://TARGET_IP/FUZZ -w (WORDLIST:paths) -mc 200,301,403 -H 'Host: FUZZ.TARGET_IP' -s 2>/dev/null",
        "d": ["Parameter fuzzing", "Vhost discovery", "Header injection testing", "Rate limiting aware"],
        "tgt": ["web_server", "api_recon", "virtual_host_enum"],
        "note": "(WORDLIST:paths) resolved at runtime; -silent for clean stdout"
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "application_banner_grab",
        "u": "echo TARGET_IP | zgrab2 http --port 443 --use-https --max-redirects 3 --output-file=- 2>/dev/null | jq -c '.[]?.result?'",
        "d": ["TLS handshake analysis", "HTTP banner grabbing", "Certificate metadata", "Redirect following"],
        "tgt": ["https_server", "api_gateways", "service_fingerprint"],
        "note": "--output-file=- streams JSON to stdout for jq filtering"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 PROTOCOL ENUMERATION (SMB/RPC/LDAP/NetBIOS)
    # ─────────────────────────────────────────────────────────────
    "smbclient": {
        "t": "protocol",
        "c": "smb_share_enum",
        "u": "smbclient -L //TARGET_IP -N 2>/dev/null | grep -iE 'disk|share'",
        "d": ["List SMB shares", "Null session testing", "Share permission enumeration", "No auth required option"],
        "tgt": ["windows_server", "file_shares", "smb_recon"]
    },
    
    "rpcclient": {
        "t": "protocol",
        "c": "rpc_user_enum",
        "u": "rpcclient -U '' -N TARGET_IP -c 'enumdomusers' 2>/dev/null | grep -v '^$'",
        "d": ["RPC user enumeration", "Null session queries", "Domain info extraction", "SID resolution"],
        "tgt": ["windows_domain", "user_enum", "ad_recon"]
    },
    
    "ldapsearch": {
        "t": "protocol",
        "c": "ldap_directory_enum",
        "u": "ldapsearch -x -H ldap://TARGET_IP -b 'DC=domain,DC=com' '(objectClass=*)' 2>/dev/null | head -100",
        "d": ["LDAP directory queries", "Anonymous bind testing", "Object class enumeration", "Attribute discovery"],
        "tgt": ["active_directory", "ldap_server", "user_group_enum"],
        "note": "head limits verbose output for streaming"
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
        "u": "nbtscan -r TARGET_IP/24 2>/dev/null | grep -iE 'server|workstation'",
        "d": ["NetBIOS name resolution", "OS detection via NetBIOS", "Workgroup/domain identification"],
        "tgt": ["windows_network", "internal_enum", "legacy_systems"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📡 SNMP & SAFE NSE SCRIPTING
    # ─────────────────────────────────────────────────────────────
    "snmpwalk": {
        "t": "protocol",
        "c": "snmp_public_enum",
        "u": "snmpwalk -v2c -c (SECRET:snmp_community) TARGET_IP 1.3.6.1.2.1.1.5 2>/dev/null",
        "d": ["SNMP v2c public community query", "System name retrieval", "Interface enumeration", "Read-only OID walk"],
        "tgt": ["network_devices", "linux_server", "iot_enum"],
        "note": "(SECRET:snmp_community) defaults to 'public' if not injected"
    },
    
    "nmap-nse-safe": {
        "t": "scan",
        "c": "safe_script_enum",
        "u": "nmap -sV --script=safe,discovery -Pn TARGET_IP -oG - 2>/dev/null | grep -E '^[0-9]+\\.|PORT'",
        "d": ["NSE scripts: banner, http-title, ssl-cert, ssh-hostkey", "No exploitation scripts", "Service metadata"],
        "tgt": ["any_server", "service_enrichment", "safe_enum"],
        "note": "-oG - outputs grepable format to stdout"
    },
    
    "whatweb": {
        "t": "http",
        "c": "web_tech_fingerprint",
        "u": "whatweb -a 3 http://TARGET_IP --color=never 2>/dev/null | grep -v '^$'",
        "d": ["Web framework detection", "CMS identification", "JS library enumeration", "Header analysis"],
        "tgt": ["web_server", "cms_enum", "tech_stack_mapping"]
    },
    
    "wappalyzer-cli": {
        "t": "http",
        "c": "application_stack_enum",
        "u": "wappalyzer http://TARGET_IP --output-json 2>/dev/null | jq -r '.technologies[]?.name?'",
        "d": ["Technology profiling", "Framework/version detection", "Analytics/CDN identification"],
        "tgt": ["web_app", "spa_enum", "supply_chain_recon"],
        "note": "--output-json streams to stdout for jq filtering"
    },

    # ─────────────────────────────────────────────────────────────
    # 🗺️ NETWORK TOPOLOGY & PATH ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "traceroute": {
        "t": "topology",
        "c": "path_discovery",
        "u": "traceroute -n TARGET_IP 2>/dev/null | head -30",
        "d": ["Hop-by-hop path mapping", "Latency measurement", "AS path inference", "ICMP/UDP modes"],
        "tgt": ["network_mapping", "cdn_detection", "egress_analysis"],
        "note": "head limits verbose output for streaming"
    },
    
    "mtr": {
        "t": "topology",
        "c": "continuous_path_analysis",
        "u": "mtr -rw -c 50 TARGET_IP --report --csv 2>/dev/null | head -20",
        "d": ["Combined traceroute + ping", "Packet loss per hop", "Jitter analysis", "CSV to stdout"],
        "tgt": ["network_debug", "performance_recon", "routing_anomalies"],
        "note": "--csv outputs structured data; head limits verbose output"
    },
    
    "besttrace": {
        "t": "topology",
        "c": "geo_path_visualization",
        "u": "besttrace -q 1 -g cn TARGET_IP 2>/dev/null | grep -E 'ms|AS'",
        "d": ["ISP-level path visualization", "Geo-IP mapping per hop", "ASN detection", "Multi-region support"],
        "tgt": ["cloud_routing", "multi_region", "cdn_bypass_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 TRAFFIC ANALYSIS & TLS FINGERPRINTING
    # ─────────────────────────────────────────────────────────────
    "tshark": {
        "t": "analysis",
        "c": "protocol_metadata_extraction",
        "u": "timeout 30 tshark -i eth0 -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri 2>/dev/null | head -50",
        "d": ["Wireshark CLI", "Display filter queries", "Field extraction", "Protocol statistics"],
        "tgt": ["traffic_analysis", "protocol_enum", "credential_discovery_passive"],
        "note": "timeout prevents hanging; head limits output for streaming"
    },
    
    "ja3-fingerprint": {
        "t": "analysis",
        "c": "tls_client_identification",
        "u": "curl -s 'https://ja3er.com/search?hash=(SECRET:ja3_hash)' 2>/dev/null | jq -r '.matches[]?.description?'",
        "d": ["Client TLS fingerprinting", "Tool/malware identification", "Anomaly detection", "No active probing"],
        "tgt": ["threat_intel", "beacon_detection", "client_profiling"],
        "note": "(SECRET:ja3_hash) injected at runtime; API-based lookup"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    "recon-ng": {
        "t": "automation",
        "c": "modular_osint_framework",
        "u": "recon-ng -r (CONFIG:recon_script) 2>&1 | grep -E '^\\[\\*\\]|^\\[\\+\\]'",
        "d": ["Modular OSINT framework", "Database-backed results", "API key integration", "Report generation"],
        "tgt": ["comprehensive_recon", "bug_bounty", "enterprise_asset_discovery"],
        "note": "(CONFIG:recon_script) resolves to pre-built workspace RC file"
    },
    
    "custom-recon-pipeline": {
        "t": "automation",
        "c": "toolchain_orchestration",
        "u": "# Chain via pipes: subfinder -d TARGET -silent | dnsx -silent -json | httpx -silent -json | jq -s 'add'",
        "d": ["Multi-tool chaining", "Deduplication", "JSON output for reporting", "Engagement-specific logic"],
        "tgt": ["scalable_recon", "ci_cd_integration", "client_deliverables"]
    },
    
    "docker-recon-stack": {
        "t": "automation",
        "c": "isolated_toolchain_env",
        "u": "echo '(WORDLIST:targets)' | docker run --rm -i ghcr.io/projectdiscovery/httpx:latest -silent -json 2>/dev/null | jq -c '.[]?'",
        "d": ["Reproducible tooling", "Version pinning", "Clean engagement environments", "JSON to stdout"],
        "tgt": ["all", "lab", "client_workspaces"],
        "note": "(WORDLIST:targets) piped via stdin; -json outputs structured data"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 AUTH TESTING & PASSWORD CRACKING (Stream-Only)
    # ─────────────────────────────────────────────────────────────
    "zap-cli": {
        "t": "scanner",
        "c": "api_security_scan",
        "u": "zap-cli openapi-scan -t http://TARGET/swagger.json --format json 2>/dev/null | jq -r '.alerts[]?.name?'",
        "d": ["OpenAPI/Swagger import", "API-specific rule scanning", "auth flow testing", "JSON output to stdout"],
        "tgt": ["api", "openapi", "soap", "auth_testing", "misconfigs"],
        "note": "Requires ZAP daemon running: zap-cli start --daemon; --format json for stdout"
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
        "note": "(MANIFEST:hashes) piped via stdin in John format; (WORDLIST:passwords) resolved at runtime",
        "alt": "john --format=nt --wordlist=(WORDLIST:passwords) --stdout --pot=none - 2>/dev/null"
    },
    
    "hydra": {
        "t": "auth_bruteforce",
        "c": "online_password_spray",
        "u": "hydra -L (WORDLIST:users) -P (WORDLIST:passwords) -t 4 -f TARGET SERVICE 2>/dev/null",
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
        "note": "(WORDLIST:users) and (WORDLIST:passwords) resolved at runtime; SERVICE = ssh/ftp/http/etc.",
        "alt": "hydra -l user -P (WORDLIST:passwords) -t 4 -f TARGET SERVICE 2>/dev/null"
    }
}

SERVER_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_SERVER_RECON_TOOLS)

# ✅ Correct alias for consistency with other catalogs
server_tools = SERVER_RECON_TOOLS
