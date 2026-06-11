"""Global wordlist catalog for all agents (Planner, Analyzer, Assistant, Executer)."""

GLOBAL_SANDBOX_WORDLISTS: dict[str, dict[str, object]] = {
    "dns_subdomains": {
        "t": "wordlist",
        "c": "dns",
        "p": [
            "wordlists/dns/subdomains_short.txt",
            "wordlists/dns/subdomains_medium.txt",
            "wordlists/dns/subdomains_large.txt"
        ],
        "d": ["brute force hidden dns and subdomains", "use short for fast checks, large for deep scans"],
        "use_with": ["subfinder", "gobuster dns", "dnsrecon"],
    },
    "web_files": {
        "t": "wordlist",
        "c": "web",
        "p": [
            "wordlists/web/files_short.txt",
            "wordlists/web/files_medium.txt",
            "wordlists/web/files_large.txt"
        ],
        "d": ["file discovery", "extension fuzzing", "finding hidden files like .env or .bak"],
        "use_with": ["ffuf", "gobuster"],
    },
    "web_folders": {
        "t": "wordlist",
        "c": "web",
        "p": [
            "wordlists/web/folders_short.txt",
            "wordlists/web/folders_medium.txt",
            "wordlists/web/folders_large.txt"
        ],
        "d": ["directory enumeration", "finding hidden paths and admin panels"],
        "use_with": ["ffuf", "gobuster", "feroxbuster"],
    },
    "passwords": {
        "t": "wordlist",
        "c": "passwords",
        "p": [
            "seclists/Passwords/Common-Credentials/passwords_short.txt",
            "seclists/Passwords/Common-Credentials/passwords_medium.txt",
            "seclists/Passwords/Common-Credentials/passwords_large.txt"
        ],
        "d": ["password audits", "credential brute forcing", "checking default/weak passwords"],
        "use_with": ["hydra", "john"],
    },
    "usernames": {
        "t": "wordlist",
        "c": "usernames",
        "p": [
            "seclists/Usernames/usernames_short.txt",
            "seclists/Usernames/usernames_medium.txt",
            "seclists/Usernames/usernames_large.txt"
        ],
        "d": ["username enumeration", "login audits"],
        "use_with": ["hydra", "ffuf"],
    },
    "common_web_content": {
        "t": "wordlist",
        "c": "web",
        "p": [
            "seclists/Discovery/Web-Content/common_short.txt",
            "seclists/Discovery/Web-Content/common_medium.txt",
            "seclists/Discovery/Web-Content/common_large.txt"
        ],
        "d": ["common web content discovery (mix of paths, files, and directories)"],
        "use_with": ["ffuf", "gobuster"],
    },
    "parameters": {
        "t": "wordlist",
        "c": "web",
        "p": [
            "seclists/Discovery/Web-Parameters/burp-parameter-names-short.txt",
            "seclists/Discovery/Web-Parameters/burp-parameter-names-medium.txt",
            "seclists/Discovery/Web-Parameters/burp-parameter-names-large.txt"
        ],
        "d": ["parameter fuzzing", "discovering hidden query or body parameters"],
        "use_with": ["ffuf", "arjun"],
    },
    "seclists_root": {
        "t": "wordlist_bundle",
        "c": "seclists",
        "p": ["seclists/"],
        "d": ["bundled SecLists mirror in sandbox", "use for highly targeted lists not covered above"],
        "use_with": ["ffuf", "gobuster", "custom recon"],
    },
    "wordlists_root": {
        "t": "wordlist_bundle",
        "c": "wordlists",
        "p": ["wordlists/"],
        "d": ["curated PentaForge wordlists directory", "use if you know a specific custom list path"],
        "use_with": ["ffuf", "gobuster", "custom recon"],
    },
}
