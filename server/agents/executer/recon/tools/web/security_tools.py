"""Curated web recon security tool catalog for `run_custom` usage.

This catalog supplements the live web recon runtime. Smart Python tools remain
active until each wrapper has a real alias-backed or router-backed replacement.
"""

from __future__ import annotations

WEB_RECON_TOOLS: dict[str, dict[str, object]] = {

    # ── PHASE 1: PASSIVE OSINT ─────────────────────────────────────────────
    "subfinder": {
        "t": "subdomain_enum",
        "c": "passive_discovery",
        "u": "subfinder -d TARGET -all -silent -nW 2>/dev/null",
        "d": ["find subdomains passively", "initial domain asset discovery", "feed subdomain list to other tools"],
        "tgt": ["domain"],
        "note": "Output to stdout; no -o flag",
        "pipe_into": ["dnsx", "httpx", "nuclei"]
    },
    "amass": {
        "t": "subdomain_enum",
        "c": "deep_discovery",
        "u": "amass enum -passive -d TARGET -config (CONFIG:amass) -silent 2>/dev/null",
        "d": ["deep passive+active subdomain enum", "ASN and CIDR mapping", "relationship graph across assets", "when subfinder misses subdomains"],
        "tgt": ["domain", "org"],
        "note": "(CONFIG:amass) resolves to config path; output to stdout",
        "pipe_into": ["dnsx", "httpx"]
    },
    "assetfinder": {
        "t": "subdomain_enum",
        "c": "lightweight_sweep",
        "u": "assetfinder --subs-only TARGET 2>/dev/null",
        "d": ["fast lightweight passive subdomain sweep", "quick pipeline input"],
        "tgt": ["domain"],
        "pipe_into": ["dnsx", "httpx"]
    },
    "theHarvester": {
        "t": "osint_harvest",
        "c": "email_host_enum",
        "u": "theHarvester -d TARGET -b all -f - 2>/dev/null | grep -E '^[A-Za-z0-9]'",
        "d": ["harvest emails and employee names", "find IPs and hostnames from search engines", "OSINT before active scanning"],
        "tgt": ["domain", "org"],
        "note": "-f - outputs to stdout instead of HTML file"
    },
    "shodan": {
        "t": "internet_search",
        "c": "banner_query",
        "u": "shodan search 'hostname:TARGET' --fields ip_str,port,org,os 2>/dev/null",
        "d": ["find exposed services without touching target", "banner grabbing at scale", "locate IPs running specific products or CVEs"],
        "tgt": ["ip", "org", "product"],
        "note": "Requires SHODAN_API_KEY env var",
        "pipe_into": ["nmap", "nuclei"]
    },
    "censys": {
        "t": "internet_search",
        "c": "cert_query",
        "u": "censys search 'parsed.names: TARGET' --index-type certificates 2>/dev/null | jq -c '.[]?'",
        "d": ["SSL cert and TLS config analysis", "discover assets via certificate transparency", "alternative to shodan for cert-heavy recon"],
        "tgt": ["domain", "ip", "cert"],
        "note": "Requires CENSYS_API_ID and CENSYS_API_SECRET env vars",
        "pipe_into": ["nmap"]
    },
    "crt_sh": {
        "t": "cert_transparency",
        "c": "subdomain_from_certs",
        "u": "curl -s 'https://crt.sh/?q=%25.TARGET&output=json' 2>/dev/null | jq -r '.[].name_value' | sort -u",
        "d": ["enumerate subdomains from SSL certificates", "zero-noise passive recon", "no API key needed"],
        "tgt": ["domain"],
        "pipe_into": ["dnsx", "httpx"]
    },
    "gau": {
        "t": "url_harvest",
        "c": "historical_mining",
        "u": "gau TARGET --threads 5 2>/dev/null | grep -v '^$'",
        "d": ["mine historical URLs from Wayback and Common Crawl", "find old endpoints and parameters", "discover forgotten paths"],
        "tgt": ["domain"],
        "pipe_into": ["ffuf", "nuclei"]
    },
    "waybackurls": {
        "t": "url_harvest",
        "c": "archive_mining",
        "u": "echo TARGET | waybackurls 2>/dev/null",
        "d": ["pull URLs from Wayback Machine specifically", "simpler alternative to gau for archive mining"],
        "tgt": ["domain"],
        "pipe_into": ["ffuf"]
    },
    "paramspider": {
        "t": "param_harvest",
        "c": "url_param_extract",
        "u": "paramspider -d TARGET 2>/dev/null | grep -v '^$'",
        "d": ["extract parameters from archived URLs", "seed parameter lists for fuzzing and injection testing"],
        "tgt": ["domain"],
        "pipe_into": ["ffuf", "dalfox"]
    },
    "trufflehog": {
        "t": "secret_scan",
        "c": "git_secret_detect",
        "u": "trufflehog git https://github.com/ORG/REPO --only-verified --json --no-update 2>/dev/null | jq -c '.[]?'",
        "d": ["scan git repos for leaked API keys and secrets", "find hardcoded credentials in source code", "check public repos of target org"],
        "tgt": ["github_repo", "git_url"],
        "note": "--no-update avoids local cache writes; --json for stdout parsing"
    },
    "github_dork": {
        "t": "osint_harvest",
        "c": "github_search",
        "u": "# Search GitHub: org:TARGET password OR secret OR api_key OR internal",
        "d": ["find secrets and internal references in public GitHub", "look for config files, tokens, internal URLs"],
        "tgt": ["org", "domain"]
    },
    "cloudbrute": {
        "t": "cloud_enum",
        "c": "bucket_discovery",
        "u": "cloudbrute -d TARGET -k keyword -m storage 2>/dev/null | grep -E '^\\[\\+\\]|found'",
        "d": ["discover exposed cloud storage buckets", "find open S3, GCS, Azure blobs for target org", "cloud asset enumeration before active scanning"],
        "tgt": ["org", "keyword"]
    },
    "s3scanner": {
        "t": "cloud_enum",
        "c": "s3_permission_check",
        "u": "s3scanner scan --bucket TARGET --output-format json 2>/dev/null | jq -c '.[]?'",
        "d": ["scan for misconfigured S3 buckets specifically", "check bucket permissions and public read/write access"],
        "tgt": ["bucket_name", "domain"],
        "note": "--output-format json streams to stdout"
    },

    # ── PHASE 2: DNS & ASSET VALIDATION ───────────────────────────────────
    "dnsx": {
        "t": "dns_resolve",
        "c": "record_validation",
        "u": "echo '(WORDLIST:subdomains)' | dnsx -list - -a -resp -silent -json 2>/dev/null | jq -c '.[]?'",
        "d": ["validate which subdomains resolve", "A/CNAME/MX/TXT record lookup at scale", "filter dead subdomains before active scanning"],
        "tgt": ["subdomain_list"],
        "note": "(WORDLIST:subdomains) piped via stdin; -list - reads from stdin; -json for structured output",
        "pipe_into": ["httpx", "nmap"]
    },
    "massdns": {
        "t": "dns_bruteforce",
        "c": "high_speed_resolve",
        "u": "echo '(WORDLIST:massdns_subs)' | massdns -r (CONFIG:resolvers) -t A -o F - 2>/dev/null | grep -E '^[A-Za-z]'",
        "d": ["high-speed DNS brute forcing", "resolve massive wordlists fast", "when dnsx is too slow for large lists"],
        "tgt": ["domain", "wordlist"],
        "note": "(WORDLIST:massdns_subs) piped via stdin; -o F outputs flat format to stdout; (CONFIG:resolvers) for resolver list",
        "pipe_into": ["httpx"]
    },
    "alterx": {
        "t": "subdomain_permutation",
        "c": "variant_generation",
        "u": "echo '(WORDLIST:resolved)' | alterx -l - -silent 2>/dev/null | dnsx -silent -json | jq -c '.[]?'",
        "d": ["generate subdomain permutations from known subs", "find staging/dev/internal variants"],
        "tgt": ["subdomain_list"],
        "note": "(WORDLIST:resolved) piped via stdin; -l - reads from stdin",
        "pipe_into": ["httpx"]
    },
    "subjack": {
        "t": "takeover_detection",
        "c": "dangling_cname_check",
        "u": "echo '(WORDLIST:resolved)' | subjack -w - -t 100 -timeout 30 -ssl -v 2>/dev/null | grep -E '^\\[\\+\\]|vulnerable'",
        "d": ["detect subdomain takeover vulnerabilities", "check dangling CNAME records pointing to unclaimed services"],
        "tgt": ["subdomain_list"],
        "note": "(WORDLIST:resolved) piped via stdin; -w - reads from stdin"
    },

    # ── PHASE 3: HTTP PROBING & FINGERPRINTING ─────────────────────────────
    "httpx": {
        "t": "http_probe",
        "c": "live_host_validation",
        "u": "echo '(WORDLIST:hosts)' | httpx -silent -title -tech-detect -status-code -cl -ct -json 2>/dev/null | jq -c '.[]?'",
        "d": ["check which hosts are live HTTP/S", "fingerprint tech stack, status codes, titles", "validate before deeper scanning"],
        "tgt": ["subdomain_list", "ip_list"],
        "note": "(WORDLIST:hosts) piped via stdin; -json outputs structured data for jq filtering",
        "pipe_into": ["nuclei", "katana", "ffuf"]
    },
    "whatweb": {
        "t": "fingerprint",
        "c": "cms_framework_detect",
        "u": "whatweb -a 3 TARGET --color=never 2>/dev/null | grep -v '^$'",
        "d": ["detailed framework and CMS fingerprinting on single target", "when httpx tech-detect is insufficient"],
        "tgt": ["url"],
        "pipe_into": ["wpscan", "cmseek"]
    },
    "wafw00f": {
        "t": "waf_detect",
        "c": "filter_identification",
        "u": "wafw00f TARGET 2>/dev/null | grep -E '^\\[\\*\\]|^\\[\\+\\]'",
        "d": ["detect WAF before fuzzing to plan bypass", "identify filtering layer"],
        "tgt": ["url"]
    },
    "masscan": {
        "t": "port_scan",
        "c": "ultra_fast_sweep",
        "u": "masscan TARGET -p0-65535 --rate 10000 --output-format json 2>/dev/null | jq -c '.[]?'",
        "d": ["ultra-fast port scan across large IP ranges", "initial open port sweep before nmap deep scan", "when nmap is too slow for wide scope"],
        "tgt": ["ip_range", "cidr"],
        "note": "--output-format json streams to stdout; pipe to jq for filtering",
        "pipe_into": ["nmap"]
    },
    "testssl.sh": {
        "t": "ssl_tls_analysis",
        "c": "comprehensive_tls_audit",
        "u": "testssl.sh --format json TARGET 2>/dev/null | jq -c '.[]?'",
        "d": ["comprehensive TLS/SSL analysis", "check for Heartbleed, ROBOT, POODLE", "evaluate cipher strength and certificates"],
        "tgt": ["url", "ip:port"],
        "note": "--format json outputs to stdout; no file writes"
    },
    "sslyze": {
        "t": "ssl_tls_analysis",
        "c": "programmatic_tls_scan",
        "u": "sslyze --json_out=- TARGET 2>/dev/null | jq -c '.[]?'",
        "d": ["fast programmatic SSL/TLS scanning", "validate certificate trust stores", "check modern TLS configurations"],
        "tgt": ["url", "ip:port"],
        "note": "--json_out=- streams JSON to stdout instead of file"
    },
    "nmap": {
        "t": "port_scan",
        "c": "service_version_enum",
        "u": "nmap -sV -sC -p- --open -T4 -oG - TARGET 2>/dev/null | grep -E '^[0-9]+\\.|Host:'",
        "d": ["discover open ports and running services", "service version detection", "run NSE scripts for vuln detection", "deep scan after masscan sweep"],
        "tgt": ["ip", "host"],
        "note": "-oG - outputs grepable format to stdout; avoid -oA for fileless mode",
        "pipe_into": ["nuclei"]
    },

    # ── PHASE 4: CONTENT DISCOVERY ─────────────────────────────────────────
    "ffuf": {
        "t": "fuzzer",
        "c": "dir_param_vhost_fuzz",
        "u": "ffuf -u TARGET/FUZZ -w (WORDLIST:folders) -mc 200,204,301,302,307,401,403 -silent 2>/dev/null",
        "d": ["directory and file brute force", "parameter fuzzing", "vhost discovery", "fastest fuzz option"],
        "tgt": ["url"],
        "note": "(WORDLIST:folders) resolved at runtime; -silent for clean stdout"
    },
    "feroxbuster": {
        "t": "fuzzer",
        "c": "recursive_content_discovery",
        "u": "feroxbuster -u TARGET -w (WORDLIST:folders) --silent 2>/dev/null",
        "d": ["recursive content discovery", "find nested hidden paths", "when ffuf misses deep structure"],
        "tgt": ["url"],
        "note": "(WORDLIST:folders) resolved at runtime; --silent for stdout-only"
    },
    "gobuster": {
        "t": "fuzzer",
        "c": "extension_aware_fuzz",
        "u": "gobuster dir -u TARGET -w (WORDLIST:folders) -x php,js,json,bak --quiet 2>/dev/null",
        "d": ["extension-aware path discovery", "DNS subdomain brute force mode", "simple fast alternative to ffuf"],
        "tgt": ["url", "domain"],
        "note": "(WORDLIST:folders) resolved at runtime; --quiet for stdout-only"
    },
    "katana": {
        "t": "crawler",
        "c": "spa_endpoint_mapping",
        "u": "katana -u TARGET -jc -js -d 5 -silent -json 2>/dev/null | jq -c '.[]?'",
        "d": ["crawl live web app for routes and endpoints", "parse JS for client-side paths and APIs", "map SPA surfaces"],
        "tgt": ["url"],
        "note": "-json outputs structured data to stdout for jq filtering",
        "pipe_into": ["ffuf", "nuclei"]
    },

    # ── PHASE 5: VULNERABILITY SCANNING ───────────────────────────────────
    "nuclei": {
        "t": "vuln_scanner",
        "c": "template_driven_detection",
        "u": "nuclei -u TARGET -severity critical,high,medium -json -silent 2>/dev/null | jq -c '.[]?'",
        "d": ["template-driven vuln detection across all live hosts", "check misconfigs, exposed panels, CVEs", "automate known-exposure checks"],
        "tgt": ["url_list", "url"],
        "note": "-json outputs structured data to stdout for jq filtering"
    },
    "nikto": {
        "t": "vuln_scanner",
        "c": "misconfig_quick_scan",
        "u": "nikto -h TARGET -Format csv 2>/dev/null | grep -v '^#'",
        "d": ["classic web server misconfiguration scan", "quick check for outdated software and default files"],
        "tgt": ["url"],
        "note": "-Format csv outputs to stdout; avoid -output file flag"
    },
    "zap-cli": {
        "t": "scanner",
        "c": "api_security_scan",
        "u": "zap-cli openapi-scan -t http://TARGET/swagger.json --format json 2>/dev/null | jq -r '.alerts[]?.name?'",
        "d": ["API security scanning via OpenAPI/Swagger", "automated auth flow testing", "misconfiguration detection"],
        "tgt": ["api", "openapi", "soap", "auth_testing", "misconfigs"],
        "note": "Requires ZAP daemon running: zap-cli start --daemon; --format json for stdout"
    },

    # ── PHASE 6: SPECIALIZED RECON ─────────────────────────────────────────
    "curl": {
        "t": "http_manual",
        "c": "header_auth_probe",
        "u": "curl -i -sS -A 'Mozilla/5.0' TARGET 2>/dev/null",
        "d": ["manual header inspection", "validate specific endpoints", "cookie and auth flow probing"],
        "tgt": ["url"],
        "note": "Default output to stdout; no -o flag"
    },
    "wpscan": {
        "t": "cms_scan",
        "c": "wordpress_enum",
        "u": "wpscan --url TARGET --no-update -e vp,vt,tt,cb,dbe,u,m --api-token (SECRET:wpscan) --format json 2>/dev/null | jq -c '.[]?'",
        "d": ["target is WordPress", "enumerate plugins, themes, users, and known CVEs"],
        "tgt": ["wordpress_url"],
        "note": "(SECRET:wpscan) injected at runtime; --format json for stdout parsing"
    },
    "cmseek": {
        "t": "cms_scan",
        "c": "cms_family_detect",
        "u": "cmseek --batch --random-agent -u TARGET 2>/dev/null | grep -E '^\\[\\+\\]|^\\[\\*\\]|CMS:'",
        "d": ["unknown CMS — detect and fingerprint first", "initial CMS family identification"],
        "tgt": ["url"],
        "pipe_into": ["wpscan", "joomscan", "droopescan"]
    },
    "joomscan": {
        "t": "cms_scan",
        "c": "joomla_enum",
        "u": "joomscan -u TARGET 2>/dev/null | grep -v '^$'",
        "d": ["target is Joomla", "enumerate components and known misconfigs"],
        "tgt": ["joomla_url"]
    },
    "droopescan": {
        "t": "cms_scan",
        "c": "drupal_enum",
        "u": "droopescan scan drupal -u TARGET 2>/dev/null | grep -E '^\\[\\+\\]|found'",
        "d": ["target is Drupal", "module and version discovery"],
        "tgt": ["drupal_url"]
    },
    "retire_js": {
        "t": "js_analysis",
        "c": "vuln_lib_detect",
        "u": "retire --js --path TARGET --outputformat json 2>/dev/null | jq -r '.results[]?.component?'",
        "d": ["detect vulnerable client-side JS libraries", "CVE mapping on frontend dependencies"],
        "tgt": ["url", "js_path"],
        "note": "--outputformat json outputs to stdout for jq filtering"
    },
    "subjs": {
        "t": "js_analysis",
        "c": "js_url_harvest",
        "u": "subjs -u TARGET 2>/dev/null | grep -v '^$'",
        "d": ["harvest all JS file URLs from a target", "feed JS files to secret scanners or retire.js"],
        "tgt": ["url"],
        "pipe_into": ["retire_js", "trufflehog"]
    },
    "gowitness": {
        "t": "screenshot",
        "c": "visual_triage",
        "u": "echo '(WORDLIST:live_urls)' | gowitness scan stdin --threads 10 --no-db 2>/dev/null | grep -E '^\\[\\+\\]|screenshot'",
        "d": ["visually inspect and triage large lists of live hosts", "prioritize targets by rendered content", "actively maintained alternative to aquatone"],
        "tgt": ["url_list"],
        "note": "(WORDLIST:live_urls) piped via stdin; --no-db avoids SQLite file; stdin mode for streaming"
    },
    "jwt_tool": {
        "t": "auth_analysis",
        "c": "token_abuse_test",
        "u": "echo '(SECRET:jwt_token)' | jwt-tool - -C -d (WORDLIST:jwt_secrets) --quiet 2>/dev/null | grep -E '^\\[\\+\\]|valid|cracked'",
        "d": ["inspect and abuse JWT tokens", "test alg confusion, none attack, weak secrets"],
        "tgt": ["jwt_token"],
        "note": "(SECRET:jwt_token) and (WORDLIST:jwt_secrets) resolved at runtime; token via stdin"
    },
    "inql": {
        "t": "graphql_recon",
        "c": "schema_introspect",
        "u": "inql -t TARGET/graphql 2>/dev/null | grep -v '^$'",
        "d": ["target exposes a GraphQL endpoint", "introspect schema, map queries and mutations"],
        "tgt": ["graphql_url"]
    },
    "grpcurl": {
        "t": "grpc_recon",
        "c": "service_reflection_enum",
        "u": "grpcurl -plaintext TARGET:50051 list 2>/dev/null | grep -v '^$'",
        "d": ["target uses gRPC", "enumerate services and methods via reflection"],
        "tgt": ["grpc_host"]
    },
    "mitmproxy": {
        "t": "proxy",
        "c": "traffic_intercept_script",
        "u": "mitmproxy -p 8080 --set block_global=false 2>/dev/null",
        "d": ["intercept and modify traffic programmatically", "capture WebSocket or gRPC/HTTP2 flows", "replay and tamper requests with scripts"],
        "tgt": ["http_traffic", "websocket", "mobile_backend"],
        "note": "Interactive TUI; use --set console=false for headless mode if supported"
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
        "note": "(MANIFEST:hashes) piped via stdin in John format; (WORDLIST:passwords) resolved at runtime; --stdout outputs cracked creds; --pot=none avoids file writes",
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
    }
}

web_recon_tools = WEB_RECON_TOOLS