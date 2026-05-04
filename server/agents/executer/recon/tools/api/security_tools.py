"""Curated API recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_API_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 🔍 API ENDPOINT DISCOVERY (Find the Surface)
    # ─────────────────────────────────────────────────────────────
    "gau + waybackurls": {
        "t": "discovery",
        "c": "historical_api_enum",
        "u": "gau TARGET_DOMAIN | grep -iE 'api|v[0-9]+|graphql|rest' | sort -u",
        "d": ["Wayback Machine API harvesting", "Historical endpoint discovery", "Version path detection", "Parameter mining"],
        "tgt": ["rest_api", "graphql", "public_apis", "legacy_versions"]
    },
    
    "httpx": {
        "t": "discovery",
        "c": "api_probe_validation",
        "u": "httpx -l api_endpoints.txt -status-code -content-length -title -tech-detect -json -o live_apis.json",
        "d": ["Fast HTTP probing", "API endpoint validation", "Tech stack detection", "Response code filtering", "JSON output"],
        "tgt": ["rest_api", "graphql", "soap", "api_gateway"]
    },
    
    "subfinder + dnsx": {
        "t": "discovery",
        "c": "api_subdomain_enum",
        "u": "subfinder -d TARGET_DOMAIN -silent | grep -iE 'api|dev|staging|prod' | dnsx -resp -o api_subs.txt",
        "d": ["API-specific subdomain discovery", "Environment enumeration (dev/staging/prod)", "DNS resolution validation"],
        "tgt": ["api_subdomains", "microservices", "cloud_apis"]
    },
    
    "assetfinder": {
        "t": "discovery",
        "c": "passive_api_asset_enum",
        "u": "assetfinder TARGET_DOMAIN | grep -iE 'api|graphql|swagger'",
        "d": ["Passive subdomain enumeration", "API-related domain discovery", "Certificate transparency sources"],
        "tgt": ["external_apis", "api_gateways", "third_party_integrations"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📚 API DOCUMENTATION & SCHEMA ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "swagger-ui-enum": {
        "t": "enum",
        "c": "openapi_doc_discovery",
        "u": "ffuf -u http://TARGET_DOMAIN/FUZZ -w swagger-wordlist.txt -mc 200 -mr 'swagger|openapi'",
        "d": ["Swagger/OpenAPI UI discovery", "API documentation enumeration", "Interactive console detection", "Spec file location"],
        "tgt": ["openapi", "swagger", "api_docs", "developer_portal"]
    },
    
    "openapi-spec-downloader": {
        "t": "enum",
        "c": "schema_retrieval",
        "u": "curl -s http://TARGET_DOMAIN/swagger.json | jq '.paths' | head -50",
        "d": ["OpenAPI/Swagger spec download", "Endpoint enumeration from spec", "Parameter discovery", "Auth requirement mapping"],
        "tgt": ["openapi_2", "openapi_3", "swagger", "api_spec"]
    },
    
    "postman-api-network": {
        "t": "enum",
        "c": "public_api_collection_enum",
        "u": "# Search: https://www.postman.com/explore for TARGET_DOMAIN APIs",
        "d": ["Public Postman API collections", "Pre-built request examples", "Auth flow documentation", "Endpoint samples"],
        "tgt": ["public_apis", "developer_resources", "api_marketplace"]
    },
    
    "rapidapi-enum": {
        "t": "enum",
        "c": "api_marketplace_discovery",
        "u": "# Search: https://rapidapi.com/hub for TARGET_DOMAIN or related APIs",
        "d": ["RapidAPI marketplace enumeration", "Third-party API discovery", "Pricing/auth models", "Usage examples"],
        "tgt": ["third_party_apis", "api_aggregators", "saas_integrations"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🎯 GRAPHQL-SPECIFIC RECON
    # ─────────────────────────────────────────────────────────────
    "graphql-introspection": {
        "t": "enum",
        "c": "schema_introspection_query",
        "u": "curl -X POST -H 'Content-Type: application/json' --data '{\"query\":\"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }\"}' http://TARGET_DOMAIN/graphql | jq",
        "d": ["GraphQL introspection query", "Full schema enumeration", "Type/field discovery", "Mutation/query mapping", "No auth required check"],
        "tgt": ["graphql", "api_schema", "type_enumeration"]
    },
    
    "inql": {
        "t": "enum",
        "c": "graphql_automation_recon",
        "u": "# Burp Suite extension: Auto-generates GraphQL introspection queries and maps schema",
        "d": ["Automated GraphQL schema mapping", "Introspection query generation", "Field enumeration", "Burp integration", "Visual schema browser"],
        "tgt": ["graphql", "burp_suite", "api_recon"]
    },
    
    "graphql-voyager": {
        "t": "enum",
        "c": "graphql_schema_visualization",
        "u": "# Web tool: https://graphql-voyager.now.sh/ - Paste introspection result",
        "d": ["Interactive GraphQL schema visualization", "Type relationship mapping", "Field dependency graph", "Schema exploration UI"],
        "tgt": ["graphql", "schema_analysis", "visual_recon"]
    },
    
    "graphw00f": {
        "t": "enum",
        "c": "graphql_engine_fingerprint",
        "u": "python3 graphw00f.py -t http://TARGET_DOMAIN/graphql -v",
        "d": ["GraphQL engine fingerprinting", "Version detection (Apollo, Relay, etc.)", "Security setting enumeration", "Error-based detection"],
        "tgt": ["graphql", "engine_detection", "version_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔌 gRPC-SPECIFIC RECON
    # ─────────────────────────────────────────────────────────────
    "grpcurl": {
        "t": "enum",
        "c": "grpc_service_discovery",
        "u": "grpcurl -plaintext TARGET_DOMAIN:50051 list",
        "d": ["gRPC service enumeration", "Method listing via reflection", "Protocol buffer discovery", "Server reflection check", "Plain/text TLS modes"],
        "tgt": ["grpc", "microservices", "protobuf_apis"]
    },
    
    "grpc-health-probe": {
        "t": "enum",
        "c": "grpc_health_check",
        "u": "grpc_health_probe -addr=TARGET_DOMAIN:50051",
        "d": ["gRPC health check endpoint testing", "Service availability validation", "Health status enumeration"],
        "tgt": ["grpc", "health_checks", "service_mesh"]
    },
    
    "protoc": {
        "t": "enum",
        "c": "protobuf_schema_analysis",
        "u": "protoc --decode_raw < service_response.bin",
        "d": ["Protocol buffer message decoding", "Schema reverse engineering", "Field type enumeration", "Binary proto analysis"],
        "tgt": ["grpc", "protobuf", "binary_apis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📡 SOAP & XML-RPC RECON
    # ─────────────────────────────────────────────────────────────
    "wsdl-enumerator": {
        "t": "enum",
        "c": "soap_wsdl_discovery",
        "u": "curl -s http://TARGET_DOMAIN/service?wsdl | grep -E 'operation|message|portType'",
        "d": ["WSDL file discovery", "SOAP operation enumeration", "Method/parameter mapping", "XML schema extraction"],
        "tgt": ["soap", "wsdl", "xml_rpc", "legacy_apis"]
    },
    
    "soapui": {
        "t": "enum",
        "c": "soap_project_recon",
        "u": "# GUI tool: Import WSDL → Auto-generates request templates",
        "d": ["SOAP project creation from WSDL", "Request/response inspection", "XML structure analysis", "Auth configuration testing"],
        "tgt": ["soap", "wsdl", "enterprise_apis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 AUTHENTICATION & RATE LIMITING DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "api-auth-enum": {
        "t": "enum",
        "c": "auth_mechanism_discovery",
        "u": "curl -i -X OPTIONS http://TARGET_DOMAIN/api/v1/resource 2>&1 | grep -iE 'www-authenticate|access-control|authorization'",
        "d": ["CORS policy enumeration", "WWW-Authenticate header analysis", "OAuth/OpenID discovery", "API key requirement detection", "OPTIONS preflight inspection"],
        "tgt": ["auth_recon", "cors_policy", "oauth_discovery"]
    },
    
    "jwt-inspector": {
        "t": "enum",
        "c": "jwt_token_analysis",
        "u": "echo TOKEN | jwt decode --no-verify 2>/dev/null | jq '.header, .payload'",
        "d": ["JWT structure inspection", "Algorithm detection", "Claim enumeration", "Expiration/issuer analysis", "No verification (read-only)"],
        "tgt": ["jwt", "token_analysis", "auth_recon"]
    },
    
    "rate-limit-detector": {
        "t": "enum",
        "c": "rate_limiting_discovery",
        "u": "for i in {1..20}; do curl -s -o /dev/null -w \"%{http_code}\\n\" http://TARGET_DOMAIN/api/endpoint; done | sort | uniq -c",
        "d": ["Rate limit header detection (X-RateLimit-*)", "429 response monitoring", "Request threshold mapping", "Cooldown period estimation"],
        "tgt": ["rate_limits", "api_throttling", "dos_protection"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📊 API TRAFFIC & BEHAVIOR ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "mitmproxy": {
        "t": "analysis",
        "c": "api_traffic_interception",
        "u": "mitmproxy -p 8080 --set block_global=false | grep -iE 'api|graphql|rest'",
        "d": ["HTTP/HTTPS API traffic interception", "Request/response inspection", "Header analysis", "WebSocket support", "Scriptable filtering"],
        "tgt": ["mobile_apis", "spa_apis", "traffic_analysis"]
    },
    
    "postman-proxy": {
        "t": "analysis",
        "c": "api_workflow_capture",
        "u": "# Postman Proxy: Capture → Inspect → Save as collection",
        "d": ["API request capture from browser/mobile", "Workflow documentation", "Collection auto-generation", "Environment variable detection"],
        "tgt": ["api_workflows", "mobile_apps", "spa_recon"]
    },
    
    "wireshark-api-filters": {
        "t": "analysis",
        "c": "packet_level_api_enum",
        "u": "tshark -r capture.pcap -Y 'http.request.uri contains \"api\"' -T fields -e http.request.uri -e http.request.method",
        "d": ["Packet-level API endpoint extraction", "HTTP method enumeration", "Query parameter analysis", "TLS decryption (with keys)"],
        "tgt": ["network_capture", "api_discovery", "protocol_analysis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🧩 PARAMETER & ENDPOINT FUZZING (Discovery Only)
    # ─────────────────────────────────────────────────────────────
    "ffuf-api-fuzz": {
        "t": "fuzz",
        "c": "api_endpoint_discovery",
        "u": "ffuf -u http://TARGET_DOMAIN/api/FUZZ -w api-wordlist.txt -mc 200,201,401,403,500 -t 50 -H 'Authorization: Bearer TOKEN'",
        "d": ["API endpoint brute-forcing", "Version path discovery", "Resource enumeration", "Status code filtering", "Auth header support"],
        "tgt": ["rest_api", "api_versions", "hidden_endpoints"]
    },
    
    "paramminer": {
        "t": "fuzz",
        "c": "api_parameter_discovery",
        "u": "paramminer params -u http://TARGET_DOMAIN/api/v1/resource -w params.txt -H 'Authorization: Bearer TOKEN'",
        "d": ["Hidden parameter discovery", "Header brute-forcing", "Cookie enumeration", "JSON body parameter testing"],
        "tgt": ["api_params", "header_enum", "input_discovery"]
    },
    
    "arjun": {
        "t": "fuzz",
        "c": "http_parameter_enum",
        "u": "arjun -u http://TARGET_DOMAIN/api/endpoint -oT params.txt -t 10",
        "d": ["GET/POST parameter discovery", "JSON parameter testing", "Header enumeration", "Wordlist-based + heuristic"],
        "tgt": ["api_parameters", "input_vectors", "query_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 API GATEWAY & VERSION ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "api-version-scanner": {
        "t": "enum",
        "c": "version_path_discovery",
        "u": "for v in v1 v2 v3 api api/v1 api/v2; do curl -s -o /dev/null -w \"$v: %{http_code}\\n\" http://TARGET_DOMAIN/$v/; done",
        "d": ["API version enumeration", "Legacy version detection", "Deprecation mapping", "Path structure analysis"],
        "tgt": ["api_versions", "legacy_apis", "migration_recon"]
    },
    
    "kong-admin-enum": {
        "t": "enum",
        "c": "gateway_admin_discovery",
        "u": "curl -s http://TARGET_DOMAIN:8001/services | jq '.data[].name' 2>/dev/null",
        "d": ["Kong API Gateway admin API enumeration", "Service/Route discovery", "Plugin configuration leak", "Upstream mapping"],
        "tgt": ["kong_gateway", "api_gateway", "admin_apis"]
    },
    
    "aws-api-gateway-enum": {
        "t": "enum",
        "c": "cloud_api_discovery",
        "u": "# Use: aws apigateway get-rest-apis --region us-east-1 (if creds available)",
        "d": ["AWS API Gateway enumeration", "Stage/Resource mapping", "Authorizer configuration", "CloudFormation stack discovery"],
        "tgt": ["aws_apis", "cloud_gateway", "serverless_apis"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📱 MOBILE API RECON (Backend Discovery)
    # ─────────────────────────────────────────────────────────────
    "mobsf": {
        "t": "enum",
        "c": "mobile_api_extraction",
        "u": "# Mobile Security Framework: Upload APK/IPA → Auto-extracts API endpoints",
        "d": ["Static analysis of mobile apps", "Hardcoded API endpoint extraction", "Certificate pinning detection", "API key discovery"],
        "tgt": ["mobile_backends", "ios_apis", "android_apis"]
    },
    
    "frida-api-tracer": {
        "t": "analysis",
        "c": "runtime_api_monitoring",
        "u": "frida -U -f com.app -l api-tracer.js --no-pause",
        "d": ["Runtime API call tracing", "SSL pinning bypass (for recon)", "Request/response logging", "Dynamic endpoint discovery"],
        "tgt": ["mobile_apis", "encrypted_traffic", "runtime_enum"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🤖 AUTOMATION & ORCHESTRATION (API Recon Pipelines)
    # ─────────────────────────────────────────────────────────────
    "nuclei-api-templates": {
        "t": "automation",
        "c": "api_vuln_recon",
        "u": "nuclei -u http://TARGET_DOMAIN -t http/exposures/apis/ -t http/misconfiguration/ -severity info,low -o api_recon.txt",
        "d": ["API misconfiguration detection", "Exposed admin panels", "Debug endpoint discovery", "CORS misconfig enumeration", "Info-only templates"],
        "tgt": ["api_misconfigs", "exposed_endpoints", "safe_scanning"]
    },
    
    "custom-api-recon-pipeline": {
        "t": "automation",
        "c": "multi_tool_orchestration",
        "u": "# Your script: subfinder | httpx | nuclei (api templates) | graphql-introspection | swagger-enum",
        "d": ["Tool chaining for API surface mapping", "Deduplication", "JSON output for reporting", "Engagement-specific workflows"],
        "tgt": ["scalable_api_recon", "bug_bounty", "enterprise_discovery"]
    },
    
    "docker-api-recon-stack": {
        "t": "automation",
        "c": "isolated_api_toolchain",
        "u": "docker run -v $(pwd):/data ghcr.io/projectdiscovery/httpx -list api_targets.txt -json -o api_live.json",
        "d": ["Reproducible API recon environments", "Version-pinned tools", "Clean workspaces", "CI/CD integration"],
        "tgt": ["all", "lab", "client_deliverables"]
    }
}

API_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_API_RECON_TOOLS)

network_tools = API_RECON_TOOLS
