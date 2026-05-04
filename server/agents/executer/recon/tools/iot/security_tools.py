"""Curated IoT recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_IOT_RECON_TOOLS: dict[str, dict[str, object]] = {
    "curl": {
        "t": "http",
        "c": "probe",
        "u": "curl -i -k -H 'X-Debug: 1' http://TARGET/endpoint",
        "d": ["manual validation", "header injection", "raw HTTP control"],
        "tgt": ["http", "api", "auth_flows"]
    },
    "httpx": {
        "t": "http",
        "c": "probe_enrich",
        "u": "httpx -u TARGET_LIST -status-code -title -tech-detect -jitter 3",
        "d": ["fast HTTP probing", "tech stack detection", "CDN/WAF identification"],
        "tgt": ["web", "api", "subdomains"]
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "banner_grab",
        "u": "zgrab2 http --port 443 --use-https TARGET",
        "d": ["TLS fingerprinting", "HTTP banner", "cert metadata"],
        "tgt": ["services", "api_gateways"]
    },
    "ffuf": {
        "t": "fuzz",
        "c": "dir_param_fuzz",
        "u": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200,302,403 -H 'Authorization: Bearer TOKEN'",
        "d": ["directory brute", "parameter fuzzing", "vhost discovery"],
        "tgt": ["web", "api", "auth_endpoints"]
    },
    
    "gobuster": {
        "t": "fuzz",
        "c": "dir_dns_enum",
        "u": "gobuster dir -u http://TARGET -w wordlist.txt -x php,js,json --timeout 10s",
        "d": ["fast dir brute", "DNS subdomain enum", "extension filtering"],
        "tgt": ["web", "subdomains"]
    },
    
    "waybackurls + gau": {
        "t": "recon",
        "c": "historical_enum",
        "u": "gau TARGET | grep -i api | unfurl -u keys",
        "d": ["Wayback Machine harvesting", "hidden endpoint discovery", "parameter mining"],
        "tgt": ["web", "api", "js_analysis"]
    },
    
    "paramminer": {
        "t": "fuzz",
        "c": "header_param_discovery",
        "u": "paramminer headers -u http://TARGET -w headers.txt",
        "d": ["hidden header discovery", "parameter brute", "cache poisoning vectors"],
        "tgt": ["api", "web", "cdn_bypass"]
    },
    "burp-suite-pro": {
        "t": "proxy",
        "c": "manual_exploit",
        "u": "burpsuite --project-file=engagement.burp",
        "d": ["Repeater/Intruder", "BApp extensions", "Collaborator OOB", "OpenAPI import"],
        "tgt": ["web", "api", "auth", "business_logic"]
    },
    
    "owasp-zap": {
        "t": "proxy",
        "c": "auto_manual_hybrid",
        "u": "zap-cli quick-scan --spider -r http://TARGET",
        "d": ["open-source baseline", "API scanning", "scriptable auth", "CI/CD ready"],
        "tgt": ["web", "api", "regression_tests"]
    },
    
    "mitmproxy": {
        "t": "proxy",
        "c": "scriptable_intercept",
        "u": "mitmproxy -s custom_flow_modifier.py --mode reverse:http://backend",
        "d": ["Python scripting", "WebSocket inspection", "reverse proxy mode"],
        "tgt": ["api", "mobile_backends", "grpc_http2"]
    },
    "postman + newman": {
        "t": "api_orchestration",
        "c": "workflow_testing",
        "u": "newman run collection.json -e env.json --folder 'Auth Tests'",
        "d": ["collection runners", "pre-request scripts", "CI/CD integration"],
        "tgt": ["rest", "graphql", "auth_flows"]
    },
    
    "inql": {
        "t": "graphql",
        "c": "schema_attack",
        "u": "# Burp extension: auto-generates GraphQL fuzzing queries",
        "d": ["introspection abuse", "batched query attacks", "alias flooding"],
        "tgt": ["graphql", "api"]
    },
    
    "graphql-voyager": {
        "t": "graphql",
        "c": "schema_visualization",
        "u": "voyager --introspection http://TARGET/graphql",
        "d": ["interactive schema map", "hidden resolver discovery"],
        "tgt": ["graphql", "api_recon"]
    },
    
    "grpcurl": {
        "t": "grpc",
        "c": "proto_enum",
        "u": "grpcurl -plaintext TARGET:50051 list",
        "d": ["service reflection", "method enumeration", "payload crafting"],
        "tgt": ["grpc", "microservices"]
    },
    "nuclei": {
        "t": "scanner",
        "c": "template_driven",
        "u": "nuclei -u http://TARGET -t http/cves/ -t http/exposures/ -severity critical,high",
        "d": ["5000+ community templates", "CVSS filtering", "CI/CD native"],
        "tgt": ["web", "api", "misconfigs"]
    },
    
    "dalfox": {
        "t": "scanner",
        "c": "xss_specialist",
        "u": "dalfox url http://TARGET/page?param=value --skip-bav --deep-domxss",
        "d": ["advanced XSS detection", "DOM sink analysis", "WAF bypass payloads"],
        "tgt": ["web", "xss", "client_side"]
    },
    
    "sqlmap": {
        "t": "scanner",
        "c": "sqli_exploitation",
        "u": "sqlmap -u 'http://TARGET/page?id=1' --batch --level=3 --risk=2 --tamper=space2comment",
        "d": ["advanced SQLi", "WAF evasion", "OS shell via DB"],
        "tgt": ["web", "sqli", "auth_bypass"]
    },
    "jwt-tool": {
        "t": "auth",
        "c": "token_abuse",
        "u": "jwt-tool TOKEN -C -p wordlist.txt -S hs256 -k secret",
        "d": ["JWT cracking", "algorithm confusion", "replay + injection"],
        "tgt": ["api", "auth", "oauth"]
    },
    
    "autorize": {
        "t": "auth",
        "c": "privilege_escalation",
        "u": "# Burp extension: auto-test IDOR/BOLA across roles",
        "d": ["automated authz testing", "role comparison", "IDOR detection"],
        "tgt": ["api", "web", "business_logic"]
    },
    
    "oauth-scanner": {
        "t": "auth",
        "c": "oauth_enum",
        "u": "python3 oauth-scanner.py -u http://TARGET -c client_id",
        "d": ["OAuth misconfig detection", "redirect_uri abuse", "token leakage"],
        "tgt": ["oauth", "api", "sso"]
    },

    "jsfinder": {
        "t": "js_analysis",
        "c": "secret_endpoint_enum",
        "u": "jsfinder -u http://TARGET/app.js -o results.txt",
        "d": ["JS file parsing", "API key extraction", "hidden endpoint discovery"],
        "tgt": ["web", "spa", "api_recon"]
    },
    
    "subjs": {
        "t": "js_analysis",
        "c": "domain_extraction",
        "u": "subjs -u http://TARGET | httpx -silent",
        "d": ["JS-sourced subdomain mining", "CSP bypass vectors"],
        "tgt": ["web", "recon", "cdn_bypass"]
    },
    
    "retire.js": {
        "t": "js_analysis",
        "c": "vuln_lib_detection",
        "u": "retire --js --path /path/to/webapp",
        "d": ["known vulnerable JS lib detection", "CVE mapping"],
        "tgt": ["web", "spa", "supply_chain"]
    },
    "wafw00f": {
        "t": "waf",
        "c": "detection",
        "u": "wafw00f http://TARGET",
        "d": ["WAF fingerprinting", "bypass strategy selection"],
        "tgt": ["web", "api", "cdn"]
    },
    
    "bypass-firewalls-by-DNS-history": {
        "t": "waf",
        "c": "origin_ip_discovery",
        "u": "# Manual: check SecurityTrails, Censys, Shodan for pre-WAF IPs",
        "d": ["origin server discovery", "DNS history abuse"],
        "tgt": ["waf_bypass", "infrastructure"]
    },
    
    "turbo-intruder": {
        "t": "fuzz",
        "c": "rate_limit_bypass",
        "u": "# Burp extension: send 1000s of requests with micro-timing",
        "d": ["race condition testing", "rate limit bypass", "TOCTOU attacks"],
        "tgt": ["api", "auth", "business_logic"]
    },
    "nuclei + github-actions": {
        "t": "automation",
        "c": "continuous_scanning",
        "u": "# .github/workflows/security.yml: nuclei scan on PR",
        "d": ["shift-left security", "auto-fail on critical", "slack alerts"],
        "tgt": ["ci_cd", "devsecops", "regression"]
    },
    
    "custom-python-scripts": {
        "t": "automation",
        "c": "logic_flaw_orchestration",
        "u": "# Your repo: idor_chainer.py, mass_assignment_fuzzer.py",
        "d": ["business logic automation", "custom auth flows", "exploit chaining"],
        "tgt": ["api", "web", "advanced_logic"]
    },
    
    "docker + toolchains": {
        "t": "automation",
        "c": "isolated_envs",
        "u": "docker run -v $(pwd):/data ghcr.io/projectdiscovery/nuclei -u http://TARGET",
        "d": ["reproducible tooling", "engagement isolation", "version pinning"],
        "tgt": ["all", "lab", "client_envs"]
    }
}

IOT_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_IOT_RECON_TOOLS)
WEB_RECON_TOOLS = IOT_RECON_TOOLS

network_tools = IOT_RECON_TOOLS
