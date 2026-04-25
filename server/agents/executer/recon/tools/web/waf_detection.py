#/+
import subprocess
import json
import re
import time
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Dict
from urllib.parse import quote_plus
from pydantic import BaseModel, Field, field_validator
from server.agents.executer.recon.config import is_blocked_host


# ═══════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════

SERVER_DIR = Path(__file__).resolve().parents[5]
WHATWAF_PATH = SERVER_DIR / "tools" / "whatwaf" / "whatwaf"
# Balanced profile: still faster than default but less likely to miss detections.
WHATWAF_FAST_ARGS = ["--skip", "-t", "3", "--verify-num", "3"]
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
KNOWN_WAF_KEYWORDS = [
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "fastly",
    "f5",
    "barracuda",
    "fortiweb",
    "netscaler",
    "citrix",
    "radware",
    "cloud armor",
    "reblaze",
    "signal sciences",
    "denyall",
    "safeline",
    "wallarm",
    "silverline",
]

KNOWN_CDN_KEYWORDS = [
    "cloudflare",
    "cloudfront",
    "stackpath",
    "edgecast",
    "azure front door",
    "fastly",
]

DEFAULT_ACTIVE_PAYLOADS = [
    "'",
    "1 OR 1=1",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "' OR 'x'='x",
]


def strip_ansi(value: str) -> str:

    return ANSI_ESCAPE_RE.sub("", value or "")


def resolve_whatwaf_cmd(url: str) -> list[str]:

    if WHATWAF_PATH.exists():
        # Run the launcher directly so WhatWaf resolves bundled content paths.
        if os.access(WHATWAF_PATH, os.X_OK):
            return [str(WHATWAF_PATH), "-u", url, *WHATWAF_FAST_ARGS]
        return ["python3", str(WHATWAF_PATH), "-u", url, *WHATWAF_FAST_ARGS]

    return ["whatwaf", "-u", url, *WHATWAF_FAST_ARGS]


def run_whatwaf_detection(url: str, timeout: int) -> tuple[list[str], str, str, int]:

    primary_cmd = resolve_whatwaf_cmd(url)
    out, err, rc = safe_execute(primary_cmd, timeout)
    text = f"{out}\n{err}"

    # Some environments run the launcher with a Python that lacks gitpython.
    if "No module named 'git'" in text and WHATWAF_PATH.exists():
        fallback_cmds = [["python3", str(WHATWAF_PATH), "-u", url, *WHATWAF_FAST_ARGS]]
        if Path("/usr/bin/python3").exists():
            fallback_cmds.append(["/usr/bin/python3", str(WHATWAF_PATH), "-u", url, *WHATWAF_FAST_ARGS])

        for cmd in fallback_cmds:
            out2, err2, rc2 = safe_execute(cmd, timeout)
            text2 = f"{out2}\n{err2}"
            if "No module named 'git'" not in text2:
                return cmd, out2, err2, rc2

    return primary_cmd, out, err, rc


def dedupe_waf_names(names: list[str]) -> list[str]:

    best_by_key: dict[str, str] = {}
    canonical_keywords = [
        "cloudflare",
        "akamai",
        "imperva",
        "incapsula",
        "sucuri",
        "fastly",
        "f5",
        "barracuda",
        "fortiweb",
        "netscaler",
        "citrix",
        "radware",
        "cloud armor",
    ]

    for raw_name in names:
        clean = strip_ansi(raw_name).strip()
        if not clean:
            continue

        lower_clean = clean.lower()
        key = clean.lower().split(" (", 1)[0].strip()
        for keyword in canonical_keywords:
            if keyword in lower_clean:
                key = keyword
                break

        existing = best_by_key.get(key)

        # Keep the richer form (for example: "Cloudflare (Cloudflare Inc.)").
        if existing is None or len(clean) > len(existing):
            best_by_key[key] = clean

    return list(best_by_key.values())


def dedupe_cdn_names(names: list[str]) -> list[str]:

    best_by_key: dict[str, str] = {}

    for raw_name in names:
        clean = strip_ansi(raw_name).strip()
        if not clean:
            continue

        lower_clean = clean.lower()
        key = lower_clean
        for keyword in KNOWN_CDN_KEYWORDS:
            if keyword in lower_clean:
                key = keyword
                break

        existing = best_by_key.get(key)
        if existing is None or len(clean) > len(existing):
            best_by_key[key] = clean

    return list(best_by_key.values())


def canonicalize_waf_name(name: str) -> str:

    clean = strip_ansi(name).strip()
    lower = clean.lower()
    mapping = [
        ("cloudflare", "Cloudflare"),
        ("akamai", "Akamai"),
        ("imperva", "Imperva"),
        ("incapsula", "Imperva"),
        ("sucuri", "Sucuri"),
        ("fastly", "Fastly"),
        ("f5 silverline", "F5 Silverline"),
        ("f5", "F5"),
        ("barracuda", "Barracuda"),
        ("fortiweb", "FortiWeb"),
        ("netscaler", "Citrix NetScaler"),
        ("citrix", "Citrix NetScaler"),
        ("radware", "Radware"),
        ("cloud armor", "Google Cloud Armor"),
        ("reblaze", "Reblaze"),
        ("signal sciences", "Signal Sciences"),
        ("denyall", "DenyAll"),
        ("safeline", "SafeLine"),
        ("wallarm", "Wallarm"),
        ("silverline", "F5 Silverline"),
    ]
    for needle, canonical in mapping:
        if needle in lower:
            return canonical
    return clean


def build_vendor_details(raw_names: list[str]) -> Dict[str, str]:

    details: Dict[str, str] = {}
    for raw in raw_names:
        clean = strip_ansi(raw).strip()
        if not clean:
            continue
        canonical = canonicalize_waf_name(clean)
        existing = details.get(canonical)
        if existing is None or len(clean) > len(existing):
            details[canonical] = clean
    return details


# ═══════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════

class WafDetectRequest(BaseModel):

    target: str
    passive_mode: bool = False
    active_payloads: Optional[list[str]] = None
    timeout: int = Field(default=300, ge=10, le=900)

    @field_validator("target")
    def validate_target(cls, v):

        clean = re.sub(r"^\w+://", "", v).split("/")[0]

        if is_blocked_host(clean):
            raise ValueError("Local targets are blocked")

        return v.strip()

    @field_validator("active_payloads")
    def validate_active_payloads(cls, v):

        if v is None:
            return None

        cleaned = []
        seen = set()

        for payload in v:
            if not isinstance(payload, str):
                raise ValueError("active_payloads must contain only strings")

            item = payload.strip()
            if not item:
                continue

            if len(item) > 200:
                raise ValueError("Each payload must be 200 characters or fewer")

            if item not in seen:
                seen.add(item)
                cleaned.append(item)

        if not cleaned:
            return None

        if len(cleaned) > 20:
            raise ValueError("At most 20 payloads are allowed")

        return cleaned


class WafResult(BaseModel):

    success: bool
    target: str

    waf_detected: bool = False
    detected_wafs: list[str] = Field(default_factory=list)
    vendor_details: Dict[str, str] = Field(default_factory=dict)
    cdn_detected: bool = False
    detected_cdns: list[str] = Field(default_factory=list)

    wafw00f: Optional[str] = None
    whatwaf: Optional[str] = None
    httpx_tech: Optional[list[str]] = None
    headers: Optional[dict] = None

    confidence: int = 0
    signals: int = 0
    confidence_reasons: list[str] = Field(default_factory=list)
    active_probe_triggered: bool = False
    active_probe_reasons: list[str] = Field(default_factory=list)

    command_log: list[str] = Field(default_factory=list)
    raw_outputs: Dict[str, str] = Field(default_factory=dict)

    error: Optional[str] = None
    execution_time: float = 0.0


# ═══════════════════════════════════════════════════════
# SAFE EXECUTION
# ═══════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int):

    try:

        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return r.stdout, r.stderr, r.returncode

    except subprocess.TimeoutExpired:

        return "", "Timeout", -1

    except FileNotFoundError:

        return "", f"Tool not installed: {cmd[0]}", -1

    except Exception as e:

        return "", str(e), -1


# ═══════════════════════════════════════════════════════
# PARSERS
# ═══════════════════════════════════════════════════════

def parse_wafw00f(out: str):

    out = strip_ansi(out)

    m = re.search(r"is behind (.*?) WAF", out, re.I)

    if m:
        return m.group(1).strip()

    return None


def parse_whatwaf(out: str):

    out = strip_ansi(out)

    m = re.search(r"Detected WAF:\s*(.*)", out)

    if not m:
        m = re.search(
            r"detected website protection identified as\s+['\"](.+?)['\"]",
            out,
            re.I,
        )

    if not m:
        m = re.search(r'"identified firewall"\s*:\s*"(.+?)"', out, re.I)

    if not m:
        keyword_map = {
            "cloudflare": "CloudFlare Web Application Firewall (CloudFlare)",
            "akamai": "AkamaiGHost Website Protection (Akamai Global Host)",
            "imperva": "Incapsula Web Application Firewall (Incapsula/Imperva)",
            "sucuri": "Sucuri Firewall (Sucuri Cloudproxy)",
            "fastly": "Fastly",
            "fortiweb": "FortiWeb (Fortinet)",
            "netscaler": "Citrix NetScaler AppFirewall",
            "citrix": "Citrix NetScaler AppFirewall",
            "radware": "Radware AppWall",
            "cloud armor": "Google Cloud Armor",
        }
        lower_out = out.lower()
        for k, label in keyword_map.items():
            if k in lower_out:
                return label

    if m:
        return m.group(1).strip()

    return None


def parse_httpx(out: str):

    try:
        data = None
        for line in (out or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                data = json.loads(line)
                break

        if data is None:
            return []

        if isinstance(data, dict):

            return data.get("tech", [])

    except:
        pass

    return []


def parse_headers(out: str):

    headers = {}

    for line in out.splitlines():

        if ":" in line:

            k, v = line.split(":", 1)

            headers[k.lower().strip()] = v.strip()

    return headers


def parse_status_code(out: str) -> int:

    matches = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out or "")
    return int(matches[-1]) if matches else 0


def detect_waf_from_headers(headers):

    wafs = []

    server = headers.get("server", "").lower()
    all_headers = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()

    if "akamai" in server:
        wafs.append("Akamai")

    if "imperva" in server:
        wafs.append("Imperva")

    if "sucuri" in server:
        wafs.append("Sucuri")

    if "akamai" in all_headers or any(k.startswith("x-akamai") for k in headers.keys()):
        wafs.append("Akamai")

    if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
        wafs.append("Sucuri")

    if "x-iinfo" in headers or "incap_ses" in headers.get("set-cookie", "").lower():
        wafs.append("Imperva")

    if any("barracuda" in k for k in headers.keys()) or "x-barracuda" in all_headers:
        wafs.append("Barracuda")

    # Avoid loose substring matches ("f5") across large headers/CSP values.
    if "bigipserver" in headers.get("set-cookie", "").lower() or "x-waf-event-info" in headers:
        wafs.append("F5")

    if "fortiwafsid" in headers.get("set-cookie", "").lower() or "fortiweb" in all_headers:
        wafs.append("FortiWeb")

    if "citrix_ns_id" in headers.get("set-cookie", "").lower() or "ns_af" in headers.get("set-cookie", "").lower() or "netscaler" in all_headers:
        wafs.append("Citrix NetScaler")

    if "x-sl-compstate" in headers or "radware" in all_headers:
        wafs.append("Radware")

    if ("x-goog" in all_headers or "google" in all_headers) and "armor" in all_headers:
        wafs.append("Google Cloud Armor")

    if "reblaze" in all_headers:
        wafs.append("Reblaze")

    if "signal sciences" in all_headers or "x-sigsci" in all_headers:
        wafs.append("Signal Sciences")

    if "denyall" in all_headers:
        wafs.append("DenyAll")

    if "safeline" in all_headers:
        wafs.append("SafeLine")

    if "wallarm" in all_headers:
        wafs.append("Wallarm")

    if "silverline" in all_headers:
        wafs.append("F5 Silverline")

    return wafs


def detect_cdn_from_headers(headers):

    cdns = []
    all_headers = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
    server = headers.get("server", "").lower()

    if "cloudflare" in server or "cf-ray" in headers or "cf-request-id" in headers:
        cdns.append("Cloudflare CDN")

    if "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
        cdns.append("Amazon CloudFront")

    if "stackpath" in all_headers:
        cdns.append("StackPath")

    if "edgecast" in all_headers:
        cdns.append("Edgecast")

    if "x-azure-ref" in headers or "x-azure-fdid" in headers:
        cdns.append("Azure Front Door")

    if "fastly" in all_headers:
        cdns.append("Fastly")

    return cdns


def detect_behavioral_waf_vendors(headers) -> list[str]:

    vendors = []
    set_cookie = headers.get("set-cookie", "").lower()
    all_headers = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()

    if "cf-ray" in headers or "cf-request-id" in headers or "cloudflare" in all_headers:
        vendors.append("Cloudflare")
    if "x-akamai" in all_headers or "akamai" in all_headers:
        vendors.append("Akamai")
    if "x-iinfo" in headers or "incap_ses" in set_cookie:
        vendors.append("Imperva")
    if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
        vendors.append("Sucuri")
    if "bigipserver" in set_cookie or "x-waf-event-info" in headers:
        vendors.append("F5")
    if "fortiwafsid" in set_cookie or "fortiweb" in all_headers:
        vendors.append("FortiWeb")
    if "citrix_ns_id" in set_cookie or "ns_af" in set_cookie or "netscaler" in all_headers:
        vendors.append("Citrix NetScaler")
    if "x-sl-compstate" in headers or "radware" in all_headers:
        vendors.append("Radware")
    if ("x-goog" in all_headers or "google" in all_headers) and "armor" in all_headers:
        vendors.append("Google Cloud Armor")

    return dedupe_waf_names(vendors)


def run_active_waf_behavior_probe(url: str, timeout: int, active_payloads: Optional[list[str]] = None) -> dict:

    def probe(one_url: str) -> tuple[int, dict]:
        cmd = [
            "curl",
            "-s",
            "-L",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "--max-time",
            str(min(6, max(3, timeout // 80))),
            one_url,
        ]
        out, err, _ = safe_execute(cmd, timeout=min(10, max(6, timeout // 30)))
        text = out or err
        return parse_status_code(text), parse_headers(text)

    baseline_status, baseline_headers = probe(url)

    payload_values = active_payloads or DEFAULT_ACTIVE_PAYLOADS

    blocked_statuses = {403, 406, 429, 503}
    reasons = []
    vendors = []
    blocking_hits = 0

    query_keys = ["id", "q", "search", "input", "query"]
    payloads = [
        (query_keys[i % len(query_keys)], payload)
        for i, payload in enumerate(payload_values)
    ]

    for k, v in payloads:
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{k}={quote_plus(v)}"
        status, headers = probe(test_url)

        if baseline_status in {200, 301, 302, 307, 308} and status in blocked_statuses:
            blocking_hits += 1
            reasons.append(f"Payload {k} triggered status transition {baseline_status}->{status}")
            vendors.extend(detect_behavioral_waf_vendors(headers))
            continue

        if status in blocked_statuses and detect_behavioral_waf_vendors(headers):
            blocking_hits += 1
            reasons.append(f"Payload {k} received blocking status {status} with WAF markers")
            vendors.extend(detect_behavioral_waf_vendors(headers))

        elif status in blocked_statuses:
            blocking_hits += 1
            reasons.append(f"Payload {k} received blocking status {status}")

    vendors = dedupe_waf_names(vendors)
    heuristic_unknown = False
    if not vendors and blocking_hits >= 2:
        generic_header_signals = [
            "x-waf",
            "x-firewall",
            "x-protected-by",
            "x-security",
            "mod_security",
            "request blocked",
            "access denied",
            "forbidden",
            "challenge",
            "captcha",
        ]
        combined_baseline = " ".join(
            f"{k}:{v}" for k, v in (baseline_headers or {}).items()
        ).lower()
        if any(signal in combined_baseline for signal in generic_header_signals) or baseline_status in blocked_statuses:
            heuristic_unknown = True
        else:
            # Even without known vendor/header signatures, repeated payload blocking is still suspicious.
            heuristic_unknown = True

        reasons.append("Multiple payloads triggered blocking behavior without known vendor fingerprint")

    return {
        "triggered": len(reasons) > 0,
        "reasons": reasons,
        "vendors": vendors,
        "heuristic_unknown": heuristic_unknown,
        "used_payloads": payload_values,
    }


def compute_confidence(
    wafw00f_res: Optional[str],
    whatwaf_res: Optional[str],
    header_wafs: list[str],
    httpx_tech: list[str],
    detected: list[str],
    behavior_triggered: bool,
) -> tuple[int, int, list[str]]:

    score = 0
    signals = 0
    reasons = []

    if wafw00f_res:
        score += 45
        signals += 1
        reasons.append("wafw00f identified WAF")

    if whatwaf_res:
        score += 30
        signals += 1
        reasons.append("whatwaf identified WAF")

    if header_wafs:
        score += 15
        signals += 1
        reasons.append("WAF-like HTTP headers detected")

    if behavior_triggered:
        score += 20
        signals += 1
        reasons.append("active payload probe triggered WAF-like blocking behavior")

    tech_l = [t.lower() for t in (httpx_tech or [])]
    waf_tech_keywords = [
        "waf",
        "firewall",
        "imperva",
        "incapsula",
        "sucuri",
        "fortiweb",
        "netscaler",
        "citrix",
        "radware",
        "cloud armor",
        "barracuda",
        "signal sciences",
        "reblaze",
        "wallarm",
        "denyall",
        "safeline",
        "silverline",
        "f5",
    ]
    if any(any(k in t for k in waf_tech_keywords) for t in tech_l):
        score += 10
        signals += 1
        reasons.append("httpx tech fingerprint supports WAF presence")

    if len(detected) >= 2:
        score += 10
        reasons.append("multiple engines agree on WAF family")

    return min(100, score), signals, reasons


def probe_wafw00f(url: str, timeout: int) -> dict:

    cmd = ["wafw00f", url]
    out, err, rc = safe_execute(cmd, timeout)
    return {
        "command": " ".join(cmd),
        "output": (out or err)[:1500],
        "parsed": parse_wafw00f(out),
        "rc": rc,
    }


def probe_whatwaf(url: str, timeout: int) -> dict:

    cmd, out, err, rc = run_whatwaf_detection(url, timeout)
    text = f"{out}\n{err}".strip()
    return {
        "command": " ".join(cmd),
        "output": text[:1500],
        "parsed": parse_whatwaf(text),
        "rc": rc,
    }


def probe_httpx(url: str, timeout: int) -> dict:

    cmd, out, err, rc = run_httpx_detection(url, timeout)
    return {
        "command": " ".join(cmd),
        "output": (out or err)[:1500],
        "parsed": parse_httpx(out),
        "rc": rc,
    }


def probe_curl_headers(url: str, timeout: int) -> dict:

    cmd = ["curl", "-I", "-s", url]
    out, err, rc = safe_execute(cmd, timeout)
    headers = parse_headers(out)
    return {
        "command": " ".join(cmd),
        "output": (out or err)[:1500],
        "parsed": headers,
        "header_wafs": detect_waf_from_headers(headers),
        "header_cdns": detect_cdn_from_headers(headers),
        "rc": rc,
    }


def run_httpx_detection(url: str, timeout: int) -> tuple[list[str], str, str, int]:

    # Prefer ProjectDiscovery httpx if available; avoid Python httpx CLI collisions.
    candidates = ["/usr/local/bin/httpx", "httpx"]
    pd_flags = ["-u", url, "-title", "-web-server", "-tech-detect", "-json", "-silent"]

    for bin_path in candidates:
        cmd = [bin_path, *pd_flags]
        out, err, rc = safe_execute(cmd, timeout)
        err_l = (err or "").lower()

        if rc == 0:
            return cmd, out, err, rc

        if "required dependencies were not installed" in err_l:
            continue
        if "no such option: -u" in err_l:
            continue
        if "tool not installed" in err_l:
            continue

        return cmd, out, err, rc

    # Final fallback for environments where only Python HTTPX CLI exists.
    fallback_cmd = ["httpx", url]
    out, err, rc = safe_execute(fallback_cmd, timeout)
    return fallback_cmd, out, err, rc


# ═══════════════════════════════════════════════════════
# MAIN TOOL
# ═══════════════════════════════════════════════════════

def waf_detection(target: str, passive_mode: bool = False, active_payloads: Optional[list[str]] = None):

    """
    🔧 Agent Tool: Multi Engine WAF Detection

    Runs:

    • wafw00f
    • whatwaf
    • httpx tech detection
    • curl header analysis

    Agent only provides target.
    """

    start = time.time()

    try:

        req = WafDetectRequest(
            target=target,
            passive_mode=passive_mode,
            active_payloads=active_payloads,
        )

    except Exception as e:

        return WafResult(
            success=False,
            target=target,
            error=str(e)
        ).model_dump()

    if not target.startswith("http"):
        url = f"https://{target}"
    else:
        url = target

    commands = []
    raw_outputs = {}

    max_workers = 4 if req.passive_mode else 5
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        f_wafw00f = executor.submit(probe_wafw00f, url, req.timeout)
        f_whatwaf = executor.submit(probe_whatwaf, url, req.timeout)
        f_httpx = executor.submit(probe_httpx, url, req.timeout)
        f_curl = executor.submit(probe_curl_headers, url, req.timeout)
        f_behavior = None if req.passive_mode else executor.submit(
            run_active_waf_behavior_probe,
            url,
            req.timeout,
            req.active_payloads,
        )

        wafw00f_data = f_wafw00f.result()
        whatwaf_data = f_whatwaf.result()
        httpx_data = f_httpx.result()
        curl_data = f_curl.result()
        behavior_data = f_behavior.result() if f_behavior else {
            "triggered": False,
            "reasons": ["Passive mode enabled: active payload probe skipped"],
            "vendors": [],
            "heuristic_unknown": False,
            "used_payloads": [],
        }

    # Keep deterministic ordering in the command log.
    for probe in [wafw00f_data, whatwaf_data, httpx_data, curl_data]:
        commands.append(probe["command"])

    raw_outputs["wafw00f"] = wafw00f_data["output"]
    raw_outputs["whatwaf"] = whatwaf_data["output"]
    raw_outputs["httpx"] = httpx_data["output"]
    raw_outputs["curl"] = curl_data["output"]

    wafw00f_res = wafw00f_data["parsed"]
    whatwaf_res = whatwaf_data["parsed"]
    httpx_tech = httpx_data["parsed"]
    headers = curl_data["parsed"]
    header_wafs = curl_data["header_wafs"]
    header_cdns = curl_data.get("header_cdns", [])


    # ─────────────────────────────
    # Aggregate
    # ─────────────────────────────

    detected = []
    detected_cdns = []

    if wafw00f_res:
        detected.append(strip_ansi(wafw00f_res).strip())

    if whatwaf_res:
        detected.append(strip_ansi(whatwaf_res).strip())

    detected.extend(behavior_data.get("vendors", []))
    if behavior_data.get("heuristic_unknown"):
        detected.append("Unknown WAF (Heuristic)")

    for tech in httpx_tech or []:
        tech_l = tech.lower()
        if "akamai" in tech_l and ("waf" in tech_l or "firewall" in tech_l):
            detected.append("Akamai")
        if "imperva" in tech_l or "incapsula" in tech_l:
            detected.append("Imperva")
        if "f5" in tech_l and ("waf" in tech_l or "firewall" in tech_l or "asm" in tech_l):
            detected.append("F5")
        if "barracuda" in tech_l:
            detected.append("Barracuda")
        if "sucuri" in tech_l:
            detected.append("Sucuri")
        if "fortiweb" in tech_l:
            detected.append("FortiWeb")
        if ("netscaler" in tech_l or "citrix" in tech_l) and ("waf" in tech_l or "firewall" in tech_l):
            detected.append("Citrix NetScaler")
        if "radware" in tech_l and ("waf" in tech_l or "appwall" in tech_l or "firewall" in tech_l):
            detected.append("Radware")
        if "cloud armor" in tech_l:
            detected.append("Google Cloud Armor")

        if "cloudflare" in tech_l:
            detected_cdns.append("Cloudflare CDN")
        if "cloudfront" in tech_l or "amazon cloudfront" in tech_l:
            detected_cdns.append("Amazon CloudFront")
        if "stackpath" in tech_l:
            detected_cdns.append("StackPath")
        if "edgecast" in tech_l:
            detected_cdns.append("Edgecast")
        if "azure front door" in tech_l:
            detected_cdns.append("Azure Front Door")
        if "fastly" in tech_l:
            detected_cdns.append("Fastly")

    detected.extend(strip_ansi(w).strip() for w in header_wafs)
    vendor_details = build_vendor_details(detected)
    detected = list(vendor_details.keys())
    detected_cdns.extend(strip_ansi(c).strip() for c in header_cdns)
    detected_cdns = dedupe_cdn_names(detected_cdns)

    confidence, signals, confidence_reasons = compute_confidence(
        wafw00f_res=wafw00f_res,
        whatwaf_res=whatwaf_res,
        header_wafs=header_wafs,
        httpx_tech=httpx_tech,
        detected=detected,
        behavior_triggered=bool(behavior_data.get("triggered")),
    )


    return WafResult(

        success=True,
        target=target,

        waf_detected=len(detected) > 0,
        detected_wafs=detected,
        vendor_details=vendor_details,
        cdn_detected=len(detected_cdns) > 0,
        detected_cdns=detected_cdns,

        wafw00f=strip_ansi(wafw00f_res).strip() if wafw00f_res else None,
        whatwaf=strip_ansi(whatwaf_res).strip() if whatwaf_res else None,
        httpx_tech=httpx_tech,
        headers=headers,
        confidence=confidence,
        signals=signals,
        confidence_reasons=confidence_reasons,
        active_probe_triggered=bool(behavior_data.get("triggered")),
        active_probe_reasons=behavior_data.get("reasons", []),

        command_log=commands,
        raw_outputs=raw_outputs,

        execution_time=round(time.time() - start, 2)

    ).model_dump()


# ═══════════════════════════════════════════════════════
# TOOL DEFINITION
# ═══════════════════════════════════════════════════════

WAF_DETECTION_TOOL = {

    "name": "waf_detection",

    "description": (
        "Detect Web Application Firewall using multiple techniques. "
        "Runs wafw00f, WhatWaf, httpx tech detection and curl header analysis in parallel, "
        "then returns confidence scoring from multi-engine signals. Supports passive mode to skip active probes."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "target": {

                "type": "string",
                "description": "Target domain or URL"

            },
            "passive_mode": {

                "type": "boolean",
                "description": "If true, skip active payload probes and run passively."

            },
            "active_payloads": {

                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Optional custom payloads for active probe heuristics (max 20)."

            }

        },

        "required": ["target"]

    }

}


# ═══════════════════════════════════════════════════════
# EXAMPLE
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":

    result = waf_detection("scanme.nmap.org")

    print(json.dumps(result, indent=2))