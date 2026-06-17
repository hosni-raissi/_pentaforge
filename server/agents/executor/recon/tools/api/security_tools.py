"""Curated API recon security tool catalog for `run_custom` usage."""
from __future__ import annotations

from server.agents.executor.recon.tools.security_catalog import normalize_security_catalog

_RAW_API_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 API ENDPOINT DISCOVERY (Find the Surface)
    # ─────────────────────────────────────────────────────────────
    "gau": {
        "t": "discovery",
        "c": "historical_api_enum",
        "u": "gau TARGET | grep -iE 'api|v[0-9]+|graphql|rest' | sort -u",
        "d": ["Wayback Machine API harvesting", "Historical endpoint discovery", "Version path detection"],
        "tgt": ["rest_api", "graphql", "public_apis", "legacy_versions"]
    },
    
    "httpx": {
        "t": "discovery",
        "c": "api_probe_validation",
        "u": "httpx -silent -status-code -content-length -title -tech-detect -json",
        "d": ["Fast HTTP probing", "API endpoint validation", "Tech stack detection", "JSON output to stdout"],
        "tgt": ["rest_api", "graphql", "soap", "api_gateway"],
        "note": "Pipes endpoints via stdin: echo TARGET | httpx ..."
    },
    
    "subfinder": {
        "t": "discovery",
        "c": "api_subdomain_enum",
        "u": "subfinder -d TARGET -silent -nW | grep -iE 'api|dev|staging|prod'",
        "d": ["API-specific subdomain discovery", "Environment enumeration", "DNS-ready output"],
        "tgt": ["api_subdomains", "microservices", "cloud_apis"],
        "alt": "subfinder -d TARGET -silent | dnsx -silent -resp"
    },
    
    "kiterunner": {
        "t": "discovery",
        "c": "api_route_bruteforce",
        "u": "kr scan TARGET -w (WORDLIST:routes-large.kite)",
        "d": ["High-performance API route discovery", "Content-type aware probing", "System wordlist support"],
        "tgt": ["rest_api", "hidden_routes", "api_endpoints"]
    },

    "amap": {
        "t": "discovery",
        "c": "api_mapping_analysis",
        "u": "amap -b TARGET",
        "d": ["Application mapping", "Service detection", "Protocol identification"],
        "tgt": ["api_services", "exposed_interfaces"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📚 API DOCUMENTATION & SCHEMA ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "swagger-ui-enum": {
        "t": "enum",
        "c": "openapi_doc_discovery",
        "u": "ffuf -u TARGET/FUZZ -w (WORDLIST:swagger) -mc 200 -mr 'swagger|openapi' -s",
        "d": ["Swagger/OpenAPI UI discovery", "API documentation enumeration", "Spec file location"],
        "tgt": ["openapi", "swagger", "api_docs", "developer_portal"]
    },
    
    "openapi-spec-downloader": {
        "t": "enum",
        "c": "schema_retrieval",
        "u": "curl -s TARGET/swagger.json | jq -r '.paths | keys[]' 2>/dev/null | head -50",
        "d": ["OpenAPI/Swagger spec download", "Endpoint enumeration from spec", "Parameter discovery"],
        "tgt": ["openapi_2", "openapi_3", "swagger", "api_spec"]
    },
    
    "postman-api-network": {
        "t": "enum",
        "c": "public_api_collection_enum",
        "u": "# Manual: Search https://www.postman.com/explore for TARGET APIs",
        "d": ["Public Postman API collections", "Pre-built request examples", "Auth flow documentation"],
        "tgt": ["public_apis", "developer_resources", "api_marketplace"]
    },
    
    "rapidapi-enum": {
        "t": "enum",
        "c": "api_marketplace_discovery",
        "u": "# Manual: Search https://rapidapi.com/hub for TARGET APIs",
        "d": ["RapidAPI marketplace enumeration", "Third-party API discovery", "Usage examples"],
        "tgt": ["third_party_apis", "api_aggregators", "saas_integrations"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🎯 GRAPHQL-SPECIFIC RECON
    # ─────────────────────────────────────────────────────────────
    "graphql-introspection": {
        "t": "enum",
        "c": "schema_introspection_query",
        "u": "curl -s -X POST -H 'Content-Type: application/json' -d '{\"query\":\"query{__schema{types{name}}}\"}' TARGET/graphql | jq -r '.data.__schema.types[].name' 2>/dev/null | sort -u",
        "d": ["GraphQL introspection query", "Full schema enumeration", "Type/field discovery"],
        "tgt": ["graphql", "api_schema", "type_enumeration"]
    },
    
    "inql": {
        "t": "enum",
        "c": "graphql_automation_recon",
        "u": "# Burp extension: Auto-generates GraphQL introspection queries",
        "d": ["Automated GraphQL schema mapping", "Field enumeration", "Burp integration"],
        "tgt": ["graphql", "burp_suite", "api_recon"]
    },
    
    "graphql-voyager": {
        "t": "enum",
        "c": "graphql_schema_visualization",
        "u": "# Web tool: https://graphql-voyager.now.sh/ — paste introspection JSON",
        "d": ["Interactive GraphQL schema visualization", "Type relationship mapping"],
        "tgt": ["graphql", "schema_analysis", "visual_recon"]
    },
    
    "graphw00f": {
        "t": "enum",
        "c": "graphql_engine_fingerprint",
        "u": "graphw00f -t TARGET/graphql -v",
        "d": ["GraphQL engine fingerprinting", "Version detection", "Security setting enumeration"],
        "tgt": ["graphql", "engine_detection", "version_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔌 gRPC-SPECIFIC RECON
    # ─────────────────────────────────────────────────────────────
    "grpcurl": {
        "t": "enum",
        "c": "grpc_service_discovery",
        "u": "grpcurl -plaintext TARGET:50051 list",
        "d": ["gRPC service enumeration", "Method listing via reflection", "Protocol buffer discovery"],
        "tgt": ["grpc", "microservices", "protobuf_apis"]
    },
    
    
    "protoc": {
        "t": "enum",
        "c": "protobuf_schema_analysis",
        "u": "protoc --decode_raw",
        "d": ["Protocol buffer message decoding", "Schema reverse engineering", "Binary proto analysis"],
        "tgt": ["grpc", "protobuf", "binary_apis"],
        "note": "Pipes binary response via stdin: echo DATA | protoc --decode_raw"
    },

    # ─────────────────────────────────────────────────────────────
    # 📡 SOAP & XML-RPC RECON
    # ─────────────────────────────────────────────────────────────
    "wsdl-enumerator": {
        "t": "enum",
        "c": "soap_wsdl_discovery",
        "u": "curl -s TARGET/service?wsdl | grep -oE '<(operation|message|portType)[^>]+' | sort -u",
        "d": ["WSDL file discovery", "SOAP operation enumeration", "Method/parameter mapping"],
        "tgt": ["soap", "wsdl", "xml_rpc", "legacy_apis"]
    },
    


    # ─────────────────────────────────────────────────────────────
    # 🔐 AUTHENTICATION & RATE LIMITING DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "api-auth-enum": {
        "t": "enum",
        "c": "auth_mechanism_discovery",
        "u": "curl -si -X OPTIONS TARGET/api/v1/resource 2>&1 | grep -iE 'www-authenticate|access-control|authorization|allow'",
        "d": ["CORS policy enumeration", "WWW-Authenticate header analysis", "OAuth/OpenID discovery"],
        "tgt": ["auth_recon", "cors_policy", "oauth_discovery"]
    },
    
    "jwt-inspector": {
        "t": "enum",
        "c": "jwt_token_analysis",
        "u": "echo TOKEN | cut -d'.' -f1,2 | base64 -d 2>/dev/null | jq . 2>/dev/null",
        "d": ["JWT structure inspection", "Algorithm detection", "Claim enumeration"],
        "tgt": ["jwt", "token_analysis", "auth_recon"],
        "note": "Replace TOKEN with actual JWT; --no-verify implied for recon"
    },
    
    "rate-limit-detector": {
        "t": "enum",
        "c": "rate_limiting_discovery",
        "u": "for i in {1..10}; do curl -s -o /dev/null -w '%{http_code}\\n' TARGET/api/endpoint; done | sort | uniq -c",
        "d": ["Rate limit header detection", "429 response monitoring", "Request threshold mapping"],
        "tgt": ["rate_limits", "api_throttling", "dos_protection"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 API TRAFFIC & BEHAVIOR ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "mitmproxy": {
        "t": "analysis",
        "c": "api_traffic_interception",
        "u": "mitmproxy -p 8080 --set block_global=false",
        "d": ["HTTP/HTTPS API traffic interception", "Request/response inspection", "Scriptable filtering"],
        "tgt": ["mobile_apis", "spa_apis", "traffic_analysis"]
    },
    
    "postman-proxy": {
        "t": "analysis",
        "c": "api_workflow_capture",
        "u": "# Postman Proxy: Configure system proxy → Capture → Inspect",
        "d": ["API request capture from browser/mobile", "Workflow documentation", "Collection auto-generation"],
        "tgt": ["api_workflows", "mobile_apps", "spa_recon"]
    },
    
    "wireshark-api-filters": {
        "t": "analysis",
        "c": "packet_level_api_enum",
        "u": "tshark -Y 'http.request.uri contains \"api\"' -T fields -e http.request.uri -e http.request.method 2>/dev/null",
        "d": ["Packet-level API endpoint extraction", "HTTP method enumeration", "Query parameter analysis"],
        "tgt": ["network_capture", "api_discovery", "protocol_analysis"],
        "note": "Reads from live interface or pipe: tshark -r - ..."
    },
    "zap-cli": {
        "t": "scanner",
        "c": "api_security_scan",
        "u": "zap-cli openapi-scan -o - -t http://TARGET/swagger.json 2>/dev/null | jq -r '.alerts[]?.name?'",
        "d": ["OpenAPI/Swagger import", "API-specific rule scanning", "auth flow testing", "JSON output to stdout"],
        "tgt": ["api", "openapi", "soap", "auth_testing", "misconfigs"],
        "note": "Requires ZAP daemon running: zap-cli start --daemon"
    },
    # ─────────────────────────────────────────────────────────────
    # 🧩 PARAMETER & ENDPOINT FUZZING (Discovery Only)
    # ─────────────────────────────────────────────────────────────
    "ffuf-api-fuzz": {
        "t": "fuzz",
        "c": "api_endpoint_discovery",
        "u": "ffuf -u TARGET/api/FUZZ -w (WORDLIST:api-endpoints) -mc 200,201,401,403,500 -t 50 -s",
        "d": ["API endpoint brute-forcing", "Version path discovery", "Status code filtering"],
        "tgt": ["rest_api", "api_versions", "hidden_endpoints"]
    },
    
    "paramminer": {
        "t": "fuzz",
        "c": "api_parameter_discovery",
        "u": "paramminer params -u TARGET/api/v1/resource -w (WORDLIST:params) -H 'Authorization: Bearer (TOKEN)' -q",
        "d": ["Hidden parameter discovery", "Header brute-forcing", "JSON body parameter testing"],
        "tgt": ["api_params", "header_enum", "input_discovery"],
        "note": "Replace (TOKEN) with actual auth token or omit for unauthed testing"
    },
    
    "arjun": {
        "t": "fuzz",
        "c": "http_parameter_enum",
        "u": "arjun -u TARGET/api/endpoint -oT - -t 10 --quiet",
        "d": ["GET/POST parameter discovery", "JSON parameter testing", "Header enumeration"],
        "tgt": ["api_parameters", "input_vectors", "query_enum"],
        "note": "-oT - outputs to stdout instead of file"
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 API GATEWAY & VERSION ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "api-version-scanner": {
        "t": "enum",
        "c": "version_path_discovery",
        "u": "for v in v1 v2 v3 api api/v1 api/v2; do curl -s -o /dev/null -w \"$v: %{http_code}\\n\" TARGET/$v/; done",
        "d": ["API version enumeration", "Legacy version detection", "Path structure analysis"],
        "tgt": ["api_versions", "legacy_apis", "migration_recon"]
    },
    
    "kong-admin-enum": {
        "t": "enum",
        "c": "gateway_admin_discovery",
        "u": "curl -s TARGET:8001/services 2>/dev/null | jq -r '.data[].name' 2>/dev/null",
        "d": ["Kong API Gateway admin API enumeration", "Service/Route discovery", "Plugin configuration leak"],
        "tgt": ["kong_gateway", "api_gateway", "admin_apis"]
    },
    
    "aws-api-gateway-enum": {
        "t": "enum",
        "c": "cloud_api_discovery",
        "u": "# Requires AWS CLI + creds: aws apigateway get-rest-apis --region us-east-1 --query 'items[].name' --output text",
        "d": ["AWS API Gateway enumeration", "Stage/Resource mapping", "Authorizer configuration"],
        "tgt": ["aws_apis", "cloud_gateway", "serverless_apis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📱 MOBILE API RECON (Backend Discovery)
    # ─────────────────────────────────────────────────────────────
    "mobsf": {
        "t": "enum",
        "c": "mobile_api_extraction",
        "u": "# MobSF CLI/Web: Upload APK/IPA → Auto-extracts API endpoints to stdout/report",
        "d": ["Static analysis of mobile apps", "Hardcoded API endpoint extraction", "Certificate pinning detection"],
        "tgt": ["mobile_backends", "ios_apis", "android_apis"]
    },
    
    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION (API Recon Pipelines)
    # ─────────────────────────────────────────────────────────────
    "nuclei-api-templates": {
        "t": "automation",
        "c": "api_vuln_recon",
        "u": "nuclei -u TARGET -t http/exposures/apis/,http/misconfiguration/ -severity info,low -silent",
        "d": ["API misconfiguration detection", "Exposed admin panels", "CORS misconfig enumeration"],
        "tgt": ["api_misconfigs", "exposed_endpoints", "safe_scanning"]
    },
    
    "custom-api-recon-pipeline": {
        "t": "automation",
        "c": "multi_tool_orchestration",
        "u": "# Chain via pipes: subfinder -d TARGET -silent | httpx -silent | nuclei -silent -t api",
        "d": ["Tool chaining for API surface mapping", "Deduplication via sort -u", "JSON output to stdout"],
        "tgt": ["scalable_api_recon", "bug_bounty", "enterprise_discovery"]
    },
    

    "pynt": {
        "t": "automation",
        "c": "api_security_testing",
        "u": "pynt scan --target TARGET --format json 2>/dev/null",
        "d": ["Modern API security scanner", "Automated functional & security testing", "JSON output to stdout"],
        "tgt": ["rest_api", "swagger", "security_testing"]
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
    },


   
}

API_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_API_RECON_TOOLS)

api_tools = API_RECON_TOOLS
