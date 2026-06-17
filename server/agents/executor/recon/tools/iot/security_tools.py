"""Curated IoT recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_IOT_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 HTTP/API PROBING (IoT Device Interfaces)
    # ─────────────────────────────────────────────────────────────
    "curl": {
        "t": "http",
        "c": "manual_probe",
        "u": "curl -i -k -s -H 'X-Debug: 1' http://TARGET/endpoint 2>/dev/null",
        "d": ["manual validation", "header injection", "raw HTTP control", "auth flow testing"],
        "tgt": ["http", "api", "auth_flows", "iot_web_ui"]
    },
    
    "httpx": {
        "t": "http",
        "c": "probe_enrich",
        "u": "echo '(WORDLIST:iot_targets)' | httpx -silent -status-code -title -tech-detect -cdn -waf -json 2>/dev/null | jq -c '.[]?'",
        "d": ["fast HTTP probing", "tech stack detection", "CDN/WAF identification", "JSON to stdout"],
        "tgt": ["web", "api", "subdomains", "iot_gateways"],
        "note": "(WORDLIST:iot_targets) piped via stdin; -l flag removed"
    },
    
    "zgrab2": {
        "t": "enrichment",
        "c": "banner_grab",
        "u": "echo TARGET | zgrab2 http --port 443 --use-https --output-file=- 2>/dev/null | jq -c '.[]?.result?'",
        "d": ["TLS fingerprinting", "HTTP banner", "cert metadata", "IoT device fingerprinting"],
        "tgt": ["services", "api_gateways", "iot_tls"],
        "note": "--output-file=- streams JSON to stdout"
    },
    
    "ffuf": {
        "t": "fuzz",
        "c": "dir_param_fuzz",
        "u": "ffuf -u http://TARGET/FUZZ -w (WORDLIST:iot_paths) -mc 200,302,403 -H 'Authorization: Bearer (SECRET:iot_token)' -s 2>/dev/null",
        "d": ["directory brute", "parameter fuzzing", "vhost discovery", "auth endpoint testing"],
        "tgt": ["web", "api", "auth_endpoints", "iot_admin"],
        "note": "(WORDLIST:iot_paths) and (SECRET:iot_token) resolved at runtime"
    },
    
    "gobuster": {
        "t": "fuzz",
        "c": "dir_dns_enum",
        "u": "gobuster dir -u http://TARGET -w (WORDLIST:iot_dirs) -x php,js,json --timeout 10s --quiet 2>/dev/null",
        "d": ["fast dir brute", "DNS subdomain enum", "extension filtering", "IoT panel discovery"],
        "tgt": ["web", "subdomains", "iot_ui"],
        "note": "(WORDLIST:iot_dirs) resolved at runtime; --quiet for stdout-only"
    },

    # ─────────────────────────────────────────────────────────────
    # 📡 PASSIVE RECON & HISTORICAL ENUM (IoT Asset Discovery)
    # ─────────────────────────────────────────────────────────────
    "gau": {
        "t": "recon",
        "c": "historical_enum",
        "u": "gau TARGET 2>/dev/null | grep -iE 'api|admin|config|device' | unfurl -u keys 2>/dev/null | sort -u",
        "d": ["Wayback Machine harvesting", "hidden endpoint discovery", "parameter mining", "IoT API paths"],
        "tgt": ["web", "api", "js_analysis", "iot_endpoints"]
    },

    "paramminer": {
        "t": "fuzz",
        "c": "header_param_discovery",
        "u": "paramminer headers -u http://TARGET -w (WORDLIST:headers) --quiet 2>/dev/null | grep -E '^\\[\\+\\]'",
        "d": ["hidden header discovery", "parameter brute", "cache poisoning vectors", "IoT auth bypass"],
        "tgt": ["api", "web", "cdn_bypass", "iot_auth"],
        "note": "(WORDLIST:headers) resolved at runtime"
    },
    
    "shodan-iot": {
        "t": "passive",
        "c": "iot_device_discovery",
        "u": "shodan search 'product:\"IP Camera\" org:\"TARGET\"' --fields ip,port,hostnames,product 2>/dev/null",
        "d": ["IoT device enumeration", "firmware version mapping", "exposed service discovery", "geolocation correlation"],
        "tgt": ["iot_devices", "cameras", "sensors", "industrial_iot"],
        "note": "Requires SHODAN_API_KEY env var"
    },
    
    "censys-iot": {
        "t": "passive",
        "c": "cert_service_iot_recon",
        "u": "censys search 'services.software.product: \"IoT\" AND ip:TARGET_NET' --fields ip,services.port,services.software 2>/dev/null | jq -c '.[]?'",
        "d": ["Certificate-based IoT discovery", "service fingerprinting", "firmware metadata", "exposed API detection"],
        "tgt": ["iot_tls", "cert_recon", "service_discovery"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 PROXY & MANUAL TESTING (IoT Protocol Analysis)
    # ─────────────────────────────────────────────────────────────
    "burp-suite-pro": {
        "t": "proxy",
        "c": "manual_exploit",
        "u": "# Interactive: burpsuite --project-file=engagement.burp",
        "d": ["Repeater/Intruder", "BApp extensions", "Collaborator OOB", "OpenAPI import", "IoT protocol plugins"],
        "tgt": ["web", "api", "auth", "business_logic", "iot_protocols"],
        "note": "Interactive GUI; use Project Import for batch replay if headless mode available"
    },
    
    "owasp-zap": {
        "t": "proxy",
        "c": "auto_manual_hybrid",
        "u": "zap-cli quick-scan --spider -r -o - http://TARGET 2>/dev/null | grep -E 'ALERT|INFO'",
        "d": ["open-source baseline", "API scanning", "scriptable auth", "CI/CD ready", "IoT template support"],
        "tgt": ["web", "api", "regression_tests", "iot_web_ui"],
        "note": "-o - outputs to stdout; use -s for silent mode"
    },
    
    "mitmproxy": {
        "t": "proxy",
        "c": "scriptable_intercept",
        "u": "mitmproxy -p 8080 --set block_global=false --mode reverse:http://iot_backend 2>/dev/null",
        "d": ["Python scripting", "WebSocket inspection", "reverse proxy mode", "MQTT/CoAP plugin support"],
        "tgt": ["api", "mobile_backends", "grpc_http2", "iot_protocols"],
        "note": "Interactive TUI; use --set console=false for headless mode"
    },
    
    "postman-cli": {
        "t": "api_orchestration",
        "c": "workflow_testing",
        "u": "newman run (CONFIG:iot_collection) -e (CONFIG:iot_env) --folder 'Auth Tests' --reporters cli 2>/dev/null",
        "d": ["collection runners", "pre-request scripts", "CI/CD integration", "IoT API workflow testing"],
        "tgt": ["rest", "graphql", "auth_flows", "iot_apis"],
        "note": "(CONFIG:iot_collection) and (CONFIG:iot_env) resolved at runtime"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔗 GRAPHQL/gRPC RECON (IoT Management APIs)
    # ─────────────────────────────────────────────────────────────
    "inql": {
        "t": "graphql",
        "c": "schema_attack",
        "u": "# Burp extension: auto-generates GraphQL fuzzing queries for IoT schemas",
        "d": ["introspection abuse", "batched query attacks", "alias flooding", "IoT GraphQL endpoint testing"],
        "tgt": ["graphql", "api", "iot_management"]
    },
    
    "graphql-voyager": {
        "t": "graphql",
        "c": "schema_visualization",
        "u": "# Web tool: https://graphql-voyager.now.sh/ — paste introspection JSON from IoT endpoint",
        "d": ["interactive schema map", "hidden resolver discovery", "IoT type enumeration"],
        "tgt": ["graphql", "api_recon", "iot_schema"]
    },
    
    "grpcurl": {
        "t": "grpc",
        "c": "proto_enum",
        "u": "grpcurl -plaintext TARGET:50051 list 2>/dev/null | grep -v '^$'",
        "d": ["service reflection", "method enumeration", "payload crafting", "IoT gRPC service discovery"],
        "tgt": ["grpc", "microservices", "iot_protocols"]
    },
    
    "protoc-decode": {
        "t": "grpc",
        "c": "protobuf_analysis",
        "u": "echo '(MANIFEST:proto_bin)' | protoc --decode_raw 2>/dev/null | head -30",
        "d": ["Protocol buffer message decoding", "IoT payload structure analysis", "field enumeration"],
        "tgt": ["grpc", "protobuf", "iot_binary_protocols"],
        "note": "(MANIFEST:proto_bin) piped via stdin"
    },

    # ─────────────────────────────────────────────────────────────
    # 🛡️ VULNERABILITY SCANNING (IoT-Specific Templates)
    # ─────────────────────────────────────────────────────────────
    "nuclei": {
        "t": "scanner",
        "c": "template_driven",
        "u": "nuclei -u http://TARGET -t http/cves/,http/exposures/iot/ -severity critical,high -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["5000+ community templates", "IoT-specific CVEs", "CVSS filtering", "CI/CD native", "JSON to stdout"],
        "tgt": ["web", "api", "misconfigs", "iot_devices"],
        "note": "Add -t http/exposures/iot/ for IoT-focused templates"
    },
    
    "dalfox": {
        "t": "scanner",
        "c": "xss_specialist",
        "u": "dalfox url http://TARGET/page?param=value --skip-bav --deep-domxss --format json 2>/dev/null | jq -r '.[]?.issue?.name?'",
        "d": ["advanced XSS detection", "DOM sink analysis", "WAF bypass payloads", "IoT web UI testing"],
        "tgt": ["web", "xss", "client_side", "iot_ui"],
        "note": "--format json outputs to stdout for filtering"
    },
    
    "sqlmap": {
        "t": "scanner",
        "c": "sqli_exploitation",
        "u": "sqlmap -u 'http://TARGET/page?id=1' --batch --level=3 --risk=2 --tamper=space2comment --output-dir=/dev/null --csv 2>/dev/null",
        "d": ["advanced SQLi", "WAF evasion", "OS shell via DB", "IoT admin panel testing"],
        "tgt": ["web", "sqli", "auth_bypass", "iot_admin"],
        "note": "--output-dir=/dev/null avoids file writes; use --csv for stdout parsing"
    },
    
    "firmware-analyzer": {
        "t": "scanner",
        "c": "firmware_recon",
        "u": "echo '(MANIFEST:firmware_bin)' | binwalk -e -q - 2>/dev/null | grep -E 'extracted|signature'",
        "d": ["firmware extraction", "embedded file discovery", "credential harvesting", "IoT binary analysis"],
        "tgt": ["firmware", "embedded", "iot_devices", "supply_chain"],
        "note": "(MANIFEST:firmware_bin) piped via stdin; binwalk reads from -"
    },

    # ─────────────────────────────────────────────────────────────
    # 🔑 AUTH & TOKEN TESTING (IoT Auth Flows)
    # ─────────────────────────────────────────────────────────────
    "jwt-tool": {
        "t": "auth",
        "c": "token_abuse",
        "u": "echo '(SECRET:iot_jwt)' | jwt-tool - -C -p (WORDLIST:secrets) -S hs256 --quiet 2>/dev/null | grep -E '^\\[\\+\\]'",
        "d": ["JWT cracking", "algorithm confusion", "replay + injection", "IoT token testing"],
        "tgt": ["api", "auth", "oauth", "iot_auth"],
        "note": "(SECRET:iot_jwt) and (WORDLIST:secrets) resolved at runtime; token via stdin"
    },
    
    "autorize": {
        "t": "auth",
        "c": "privilege_escalation",
        "u": "# Burp extension: auto-test IDOR/BOLA across IoT device roles",
        "d": ["automated authz testing", "role comparison", "IDOR detection", "IoT multi-tenant testing"],
        "tgt": ["api", "web", "business_logic", "iot_iam"]
    },
    
    "oauth-scanner": {
        "t": "auth",
        "c": "oauth_enum",
        "u": "python3 oauth-scanner.py -u http://TARGET -c (SECRET:iot_client_id) --json 2>/dev/null | jq -r '.findings[]?.type?'",
        "d": ["OAuth misconfig detection", "redirect_uri abuse", "token leakage", "IoT SSO testing"],
        "tgt": ["oauth", "api", "sso", "iot_auth"],
        "note": "(SECRET:iot_client_id) injected at runtime; --json for stdout parsing"
    },

    # ─────────────────────────────────────────────────────────────
    # 📜 JAVASCRIPT ANALYSIS (IoT Web UI Recon)
    # ─────────────────────────────────────────────────────────────
    "jsfinder": {
        "t": "js_analysis",
        "c": "secret_endpoint_enum",
        "u": "curl -s http://TARGET/app.js 2>/dev/null | jsfinder -i - -o - 2>/dev/null | grep -E 'api|key|secret|endpoint'",
        "d": ["JS file parsing", "API key extraction", "hidden endpoint discovery", "IoT config leakage"],
        "tgt": ["web", "spa", "api_recon", "iot_web_ui"],
        "note": "-i - reads JS from stdin; -o - outputs to stdout"
    },
    
    "subjs": {
        "t": "js_analysis",
        "c": "domain_extraction",
        "u": "curl -s http://TARGET 2>/dev/null | subjs -i - 2>/dev/null | httpx -silent -json | jq -r '.url?'",
        "d": ["JS-sourced subdomain mining", "CSP bypass vectors", "IoT CDN discovery"],
        "tgt": ["web", "recon", "cdn_bypass", "iot_infra"],
        "note": "Pipes HTML via stdin to subjs; httpx outputs JSON for filtering"
    },
    
    "retire.js": {
        "t": "js_analysis",
        "c": "vuln_lib_detection",
        "u": "curl -s http://TARGET/app.js 2>/dev/null | retire --js --stdin --outputformat json 2>/dev/null | jq -r '.results[]?.component?'",
        "d": ["known vulnerable JS lib detection", "CVE mapping", "IoT supply chain audit"],
        "tgt": ["web", "spa", "supply_chain", "iot_dependencies"],
        "note": "--stdin reads JS content; --outputformat json for stdout parsing"
    },

    # ─────────────────────────────────────────────────────────────
    # 🧱 WAF/BYPASS RECON (IoT Edge Protection)
    # ─────────────────────────────────────────────────────────────
    "wafw00f": {
        "t": "waf",
        "c": "detection",
        "u": "wafw00f http://TARGET 2>/dev/null | grep -E '^\\[\\*\\]|^\\[\\+\\]'",
        "d": ["WAF fingerprinting", "bypass strategy selection", "IoT edge protection audit"],
        "tgt": ["web", "api", "cdn", "iot_waf"]
    },
    
    "bypass-firewalls-by-DNS-history": {
        "t": "waf",
        "c": "origin_ip_discovery",
        "u": "# Manual: query SecurityTrails/Censys/Shodan APIs for pre-WAF IoT device IPs",
        "d": ["origin server discovery", "DNS history abuse", "IoT device IP enumeration"],
        "tgt": ["waf_bypass", "infrastructure", "iot_exposure"]
    },
    
    "turbo-intruder": {
        "t": "fuzz",
        "c": "rate_limit_bypass",
        "u": "# Burp extension: send 1000s of requests with micro-timing for IoT auth bypass",
        "d": ["race condition testing", "rate limit bypass", "TOCTOU attacks", "IoT auth flooding"],
        "tgt": ["api", "auth", "business_logic", "iot_auth"],
        "note": "Interactive Burp extension; use Python scripting for headless execution"
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION (IoT Recon Pipelines)
    # ─────────────────────────────────────────────────────────────
    "nuclei-iot-ci": {
        "t": "automation",
        "c": "continuous_scanning",
        "u": "# GitHub Actions: nuclei scan with IoT templates on PR/commit",
        "d": ["shift-left security", "auto-fail on critical", "slack alerts", "IoT template filtering"],
        "tgt": ["ci_cd", "devsecops", "regression", "iot_supply_chain"]
    },
    
    "custom-iot-scripts": {
        "t": "automation",
        "c": "logic_flaw_orchestration",
        "u": "# Your repo: iot_idor_chainer.py, firmware_secret_extractor.py — output JSON to stdout",
        "d": ["business logic automation", "custom auth flows", "exploit chaining", "IoT protocol fuzzing"],
        "tgt": ["api", "web", "advanced_logic", "iot_protocols"]
    },
    
    "docker-iot-recon": {
        "t": "automation",
        "c": "isolated_envs",
        "u": "echo '(WORDLIST:iot_targets)' | docker run --rm -i ghcr.io/projectdiscovery/nuclei:latest -l - -t http/exposures/iot/ -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["reproducible tooling", "engagement isolation", "version pinning", "IoT template support"],
        "tgt": ["all", "lab", "client_envs", "iot_devices"],
        "note": "(WORDLIST:iot_targets) piped via stdin; -l - reads from stdin"
    },
    
    "iot-protocol-fuzzer": {
        "t": "automation",
        "c": "protocol_abuse_testing",
        "u": "echo '(MANIFEST:iot_proto_spec)' | boofuzz -t TARGET -p 1883 -f - 2>/dev/null | grep -E 'crash|timeout|response'",
        "d": ["MQTT/CoAP/Modbus fuzzing", "protocol state machine testing", "IoT device crash detection"],
        "tgt": ["mqtt", "coap", "modbus", "iot_protocols"],
        "note": "(MANIFEST:iot_proto_spec) piped via stdin; boofuzz reads spec from -"
    }
}

IOT_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_IOT_RECON_TOOLS)

iot_tools = IOT_RECON_TOOLS
