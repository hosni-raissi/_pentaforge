"""Curated retest command catalog for PoC proof gathering via `run_custom`."""

from __future__ import annotations

RETEST_TOOLS: dict[str, dict[str, object]] = {
    "curl": {
        "t": "http",
        "c": "poc_proof",
        "u": "curl -i -sS -X POST TARGET -d 'payload=data' --max-time 10",
        "d": ["Execute PoC payload", "Capture request/response timing", "Proof of exploitation"],
        "tgt": ["http", "api", "web"],
    },
    "curl_verbose": {
        "t": "http_detailed",
        "c": "poc_response_capture",
        "u": "curl -v -i TARGET/endpoint?vulnerable_param=PAYLOAD 2>&1",
        "d": ["Detailed request/response capture", "Header analysis", "Response body proof"],
        "tgt": ["http", "api", "web"],
    },
    "wget": {
        "t": "http_download",
        "c": "poc_download_proof",
        "u": "wget -q --save-headers -O - TARGET/sensitive/file.txt",
        "d": ["Download restricted files", "Proof of unauthorized access"],
        "tgt": ["http", "web"],
    },
    "telnet": {
        "t": "network_connect",
        "c": "poc_connection_proof",
        "u": "echo 'GET / HTTP/1.1\\r\\nHost: TARGET\\r\\n\\r\\n' | telnet TARGET 80",
        "d": ["Raw protocol connection", "Banner grabbing", "Service behavior proof"],
        "tgt": ["network", "service"],
    },
    "mysql_client": {
        "t": "database",
        "c": "sqli_result_extraction",
        "u": "mysql -h TARGET -u user -p pass -e 'SELECT * FROM users LIMIT 1'",
        "d": ["SQL injection data extraction", "Database access proof"],
        "tgt": ["database", "api"],
    },
    "sqlmap_quick": {
        "t": "injection_poc",
        "c": "sqli_poc",
        "u": "sqlmap -u 'TARGET' --data='param=PAYLOAD' --batch --risk=1 --level=1 --dbs",
        "d": ["Quick SQLi POC", "Extract database names", "Proof of SQLi exploitation"],
        "tgt": ["web", "api"],
    },
}
