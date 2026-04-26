#/+
import argparse
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from server.agents.executer.recon.config import is_blocked_host


ALLOWED_SOURCES = {"crtsh", "wayback", "otx", "urlscan"}
DEFAULT_SOURCES = ["crtsh", "wayback", "otx", "urlscan"]
DEFAULT_UA = "Mozilla/5.0 (PassiveWebRecon/1.0)"
SSL_CONTEXT = ssl.create_default_context()
MAX_FETCH_RETRIES = 3
RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}
MAX_URL_LEN = 350
MAX_URL_PATH_LEN = 180
MAX_URL_QUERY_LEN = 220
MAX_PERCENT_ENCODED_BYTES = 12
CONTROL_ENCODED_PATTERN = re.compile(r"%(?:00|09|0a|0d)", re.IGNORECASE)
DISALLOWED_URL_TEXT_PATTERN = re.compile(r"[\"'`<>\\]")

SENSITIVE_URL_PATTERNS = [
    re.compile(r"/(?:admin|administrator|manage|panel|backup|internal|private)\b", re.IGNORECASE),
    re.compile(r"\.(?:env|sql|bak|old|zip|tar|gz|7z|log|pem|key|crt|db|sqlite)\b", re.IGNORECASE),
]
API_URL_PATTERN = re.compile(r"/(?:api|graphql|swagger|openapi|v\d+)\b", re.IGNORECASE)


class PassiveWebReconRequest(BaseModel):
    target: str
    sources: list[str] = Field(default_factory=lambda: list(DEFAULT_SOURCES))
    include_subdomains: bool = True
    include_historical_urls: bool = True
    include_ip_history: bool = True
    max_urls: int = Field(default=400, ge=20, le=5000)
    timeout: int = Field(default=20, ge=5, le=120)
    threads: int = Field(default=4, ge=1, le=8)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("target is required")
        domain = _normalize_domain(v)
        if not domain:
            raise ValueError("target must be a domain or URL")
        if _is_blocked_target(domain):
            raise ValueError("target is blocked by recon config")
        return v.strip()

    @field_validator("sources")
    @classmethod
    def validate_sources(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one source is required")
        cleaned: list[str] = []
        seen: set[str] = set()
        for entry in v:
            source = str(entry or "").strip().lower()
            if source not in ALLOWED_SOURCES:
                raise ValueError(f"unknown source '{source}'. Allowed: {sorted(ALLOWED_SOURCES)}")
            if source not in seen:
                seen.add(source)
                cleaned.append(source)
        return cleaned

    @model_validator(mode="after")
    def validate_modes(self) -> "PassiveWebReconRequest":
        if not self.include_subdomains and not self.include_historical_urls and not self.include_ip_history:
            raise ValueError("at least one collection mode must be enabled")
        return self


class PassiveSourceStatus(BaseModel):
    source: str
    success: bool
    subdomains: int = 0
    urls: int = 0
    ips: int = 0
    error: Optional[str] = None


class PassiveWebReconResult(BaseModel):
    success: bool
    tool: str = "passive_web_recon"
    target: str
    normalized_domain: str
    command: str
    working_dir: str = ""
    sources_used: list[str] = Field(default_factory=list)
    source_status: list[PassiveSourceStatus] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    total_subdomains: int = 0
    historical_urls: list[str] = Field(default_factory=list)
    total_historical_urls: int = 0
    ip_history: list[str] = Field(default_factory=list)
    total_ip_history: int = 0
    parameterized_urls: list[str] = Field(default_factory=list)
    sensitive_urls: list[str] = Field(default_factory=list)
    api_candidates: list[str] = Field(default_factory=list)
    insights: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class _SourceData:
    source: str
    subdomains: list[str]
    urls: list[str]
    ips: list[str]
    error: Optional[str] = None


def _normalize_domain(value: str) -> str:
    clean = str(value or "").strip().lower()
    if not clean:
        return ""
    if "://" in clean:
        parsed = urllib.parse.urlparse(clean)
        host = parsed.netloc or parsed.path
    else:
        host = clean
    return host.split("/")[0].split(":")[0].strip(".")


def _is_blocked_target(host: str) -> bool:
    return is_blocked_host(host)


def _is_retryable_exception(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRYABLE_HTTP_CODES
    if isinstance(exc, urllib.error.URLError):
        reason = str(exc.reason).lower()
        retry_tokens = [
            "timed out",
            "temporary failure in name resolution",
            "name or service not known",
            "try again",
            "connection reset",
            "connection refused",
            "network is unreachable",
        ]
        return any(token in reason for token in retry_tokens)
    return isinstance(exc, (TimeoutError, socket.timeout))


def _fetch_url(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    last_error: Optional[Exception] = None
    for attempt in range(MAX_FETCH_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = exc
            if attempt == MAX_FETCH_RETRIES - 1 or not _is_retryable_exception(exc):
                raise
            time.sleep(0.7 * (2 ** attempt))
    if last_error is not None:  # pragma: no cover
        raise last_error
    raise RuntimeError("unknown fetch failure")


def _unique_sorted(items: list[str], limit: Optional[int] = None) -> list[str]:
    cleaned = sorted({item.strip() for item in items if item and item.strip()})
    return cleaned[:limit] if limit is not None else cleaned


def _extract_registered_subdomains(names: list[str], domain: str) -> list[str]:
    out: list[str] = []
    suffix = f".{domain}"
    for name in names:
        lowered = name.strip().lower().strip(".")
        if lowered and (lowered == domain or lowered.endswith(suffix)):
            out.append(lowered)
    return _unique_sorted(out)


def _is_domain_allowed(host: str, domain: str, include_subdomains: bool) -> bool:
    host = (host or "").lower().strip(".")
    if host == domain:
        return True
    return include_subdomains and host.endswith("." + domain)


def _is_noisy_decoded_url_text(text: str) -> bool:
    if not text:
        return False
    if any(ch in text for ch in ("\r", "\n", "\t", "\x00")):
        return True
    if any(ch.isspace() for ch in text):
        return True
    if DISALLOWED_URL_TEXT_PATTERN.search(text):
        return True
    return False


def _normalize_one_url(raw_url: str, domain: str, include_subdomains: bool) -> Optional[str]:
    candidate = (raw_url or "").strip()
    if not candidate or len(candidate) > MAX_URL_LEN:
        return None
    if any(ord(ch) < 32 for ch in candidate):
        return None
    if not (candidate.startswith("http://") or candidate.startswith("https://")):
        return None

    try:
        parsed = urllib.parse.urlparse(candidate)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None

    host = (parsed.hostname or "").lower().strip(".")
    if not host or not _is_domain_allowed(host, domain, include_subdomains):
        return None

    if parsed.path and ("http://" in parsed.path or "https://" in parsed.path):
        return None

    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parsed.path or "/"
    query = parsed.query or ""

    if len(path) > MAX_URL_PATH_LEN or len(query) > MAX_URL_QUERY_LEN:
        return None
    if "&quot" in path.lower():
        return None
    if CONTROL_ENCODED_PATTERN.search(path) or CONTROL_ENCODED_PATTERN.search(query):
        return None
    if len(re.findall(r"%[0-9a-fA-F]{2}", path)) > MAX_PERCENT_ENCODED_BYTES:
        return None

    decoded_path = urllib.parse.unquote(path)
    decoded_query = urllib.parse.unquote(query)
    if _is_noisy_decoded_url_text(decoded_path) or _is_noisy_decoded_url_text(decoded_query):
        return None
    if decoded_path.startswith("/:") and decoded_path[2:].isdigit():
        return None
    if len(decoded_path) >= 25:
        non_ascii = sum(1 for ch in decoded_path if ord(ch) > 127)
        if non_ascii / len(decoded_path) > 0.30:
            return None

    if path != "/" and path.endswith("/"):
        path = path[:-1]

    fragment = ""
    normalized = urllib.parse.urlunparse((scheme, netloc, path, "", query, fragment))
    if len(normalized) > MAX_URL_LEN:
        return None
    return normalized


def _canonical_url_key(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_sorted = urllib.parse.urlencode(sorted(query_pairs))
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urllib.parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query_sorted, ""))


def _normalize_filter_dedupe_urls(
    urls: list[str],
    domain: str,
    include_subdomains: bool,
    limit: int,
) -> tuple[list[str], int]:
    kept: list[str] = []
    seen: set[str] = set()
    dropped = 0
    for raw in urls:
        normalized = _normalize_one_url(raw, domain, include_subdomains)
        if not normalized:
            dropped += 1
            continue
        key = _canonical_url_key(normalized)
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        kept.append(normalized)
        if len(kept) >= limit:
            break
    return kept, dropped


def _fetch_crtsh(domain: str, timeout: int) -> _SourceData:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    subdomains: list[str] = []
    try:
        raw = _fetch_url(url, timeout=timeout)
        data = json.loads(raw or "[]")
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                for key in ("name_value", "common_name"):
                    value = str(entry.get(key) or "").strip()
                    if value:
                        subdomains.extend(part.strip() for part in value.splitlines())
    except Exception as exc:
        return _SourceData(source="crtsh", subdomains=[], urls=[], ips=[], error=str(exc))
    return _SourceData(source="crtsh", subdomains=_extract_registered_subdomains(subdomains, domain), urls=[], ips=[])


def _fetch_wayback(domain: str, timeout: int, max_urls: int) -> _SourceData:
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{urllib.parse.quote(domain)}/*"
        "&output=json&fl=original,timestamp,statuscode,mimetype"
        "&collapse=urlkey"
        f"&limit={max_urls}"
    )
    urls: list[str] = []
    subdomains: list[str] = []
    try:
        raw = _fetch_url(url, timeout=timeout)
        data = json.loads(raw or "[]")
        if isinstance(data, list):
            for row in data[1:]:
                if isinstance(row, list) and row:
                    original = str(row[0]).strip()
                    if original:
                        urls.append(original)
                        host = _normalize_domain(original)
                        if host:
                            subdomains.append(host)
    except Exception as exc:
        return _SourceData(source="wayback", subdomains=[], urls=[], ips=[], error=str(exc))
    return _SourceData(
        source="wayback",
        subdomains=_extract_registered_subdomains(subdomains, domain),
        urls=_unique_sorted(urls, limit=max_urls),
        ips=[],
    )


def _fetch_otx(domain: str, timeout: int) -> _SourceData:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
    subdomains: list[str] = []
    ips: list[str] = []
    try:
        raw = _fetch_url(url, timeout=timeout)
        data = json.loads(raw or "{}")
        records = data.get("passive_dns", []) if isinstance(data, dict) else []
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, dict):
                    continue
                hostname = str(record.get("hostname") or "").strip()
                address = str(record.get("address") or "").strip()
                if hostname:
                    subdomains.append(hostname)
                if address:
                    ips.append(address)
    except Exception as exc:
        return _SourceData(source="otx", subdomains=[], urls=[], ips=[], error=str(exc))
    return _SourceData(
        source="otx",
        subdomains=_extract_registered_subdomains(subdomains, domain),
        urls=[],
        ips=_unique_sorted(ips),
    )


def _fetch_urlscan(domain: str, timeout: int, max_urls: int) -> _SourceData:
    query = urllib.parse.quote(f"domain:{domain}")
    url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
    urls: list[str] = []
    subdomains: list[str] = []
    try:
        raw = _fetch_url(url, timeout=timeout)
        data = json.loads(raw or "{}")
        results = data.get("results", []) if isinstance(data, dict) else []
        if isinstance(results, list):
            for row in results:
                if not isinstance(row, dict):
                    continue
                page = row.get("page", {})
                task = row.get("task", {})
                page_url = str(page.get("url") or "").strip()
                task_domain = str(task.get("domain") or "").strip()
                if page_url:
                    urls.append(page_url)
                if task_domain:
                    subdomains.append(task_domain)
    except Exception as exc:
        return _SourceData(source="urlscan", subdomains=[], urls=[], ips=[], error=str(exc))
    return _SourceData(
        source="urlscan",
        subdomains=_extract_registered_subdomains(subdomains, domain),
        urls=_unique_sorted(urls, limit=max_urls),
        ips=[],
    )


def _source_worker(source: str, domain: str, timeout: int, max_urls: int) -> _SourceData:
    if source == "crtsh":
        return _fetch_crtsh(domain, timeout)
    if source == "wayback":
        return _fetch_wayback(domain, timeout, max_urls)
    if source == "otx":
        return _fetch_otx(domain, timeout)
    if source == "urlscan":
        return _fetch_urlscan(domain, timeout, max_urls)
    return _SourceData(source=source, subdomains=[], urls=[], ips=[], error="unsupported source")


def _build_url_insights(urls: list[str], max_urls: int) -> tuple[list[str], list[str], list[str]]:
    limited_urls = _unique_sorted(urls, limit=max_urls)
    parameterized = [u for u in limited_urls if "?" in u]
    sensitive = [u for u in limited_urls if any(pattern.search(u) for pattern in SENSITIVE_URL_PATTERNS)]
    api_candidates = [u for u in limited_urls if API_URL_PATTERN.search(u)]
    return (
        _unique_sorted(parameterized, limit=150),
        _unique_sorted(sensitive, limit=150),
        _unique_sorted(api_candidates, limit=150),
    )


def passive_web_recon(
    target: str,
    sources: Optional[list[str]] = None,
    include_subdomains: bool = True,
    include_historical_urls: bool = True,
    include_ip_history: bool = True,
    max_urls: int = 400,
    timeout: int = 20,
    threads: int = 4,
) -> dict:
    start = time.time()
    try:
        req = PassiveWebReconRequest(
            target=target,
            sources=sources if sources is not None else list(DEFAULT_SOURCES),
            include_subdomains=include_subdomains,
            include_historical_urls=include_historical_urls,
            include_ip_history=include_ip_history,
            max_urls=max_urls,
            timeout=timeout,
            threads=threads,
        )
    except Exception as exc:
        return PassiveWebReconResult(
            success=False,
            target=target,
            normalized_domain="",
            command="",
            error=f"Validation error: {exc}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    domain = _normalize_domain(req.target)
    command = (
        "passive_web_recon("
        f"{domain}, sources={req.sources}, "
        f"include_subdomains={req.include_subdomains}, "
        f"include_historical_urls={req.include_historical_urls}, "
        f"include_ip_history={req.include_ip_history})"
    )

    source_results: list[_SourceData] = []
    with ThreadPoolExecutor(max_workers=req.threads) as executor:
        future_map = {
            executor.submit(_source_worker, source, domain, req.timeout, req.max_urls): source
            for source in req.sources
        }
        for future in as_completed(future_map):
            try:
                source_results.append(future.result())
            except Exception as exc:
                source = future_map[future]
                source_results.append(_SourceData(source=source, subdomains=[], urls=[], ips=[], error=str(exc)))

    all_subdomains: list[str] = []
    all_urls: list[str] = []
    all_ips: list[str] = []
    status_entries: list[PassiveSourceStatus] = []
    warnings: list[str] = []

    for result in sorted(source_results, key=lambda item: item.source):
        if req.include_subdomains:
            all_subdomains.extend(result.subdomains)
        if req.include_historical_urls:
            all_urls.extend(result.urls)
        if req.include_ip_history:
            all_ips.extend(result.ips)

        status_entries.append(
            PassiveSourceStatus(
                source=result.source,
                success=result.error is None,
                subdomains=len(result.subdomains),
                urls=len(result.urls),
                ips=len(result.ips),
                error=result.error,
            )
        )

    subdomains = _unique_sorted(all_subdomains, limit=5000)
    historical_urls, dropped_urls = _normalize_filter_dedupe_urls(
        all_urls,
        domain=domain,
        include_subdomains=req.include_subdomains,
        limit=req.max_urls,
    )
    ip_history = _unique_sorted(all_ips, limit=2000)
    parameterized_urls, sensitive_urls, api_candidates = _build_url_insights(historical_urls, req.max_urls)

    success_count = sum(1 for item in status_entries if item.success)
    failed_sources = [item for item in status_entries if not item.success]

    insights: list[str] = []
    if subdomains:
        insights.append(f"Discovered {len(subdomains)} passive subdomains")
    if historical_urls:
        insights.append(f"Collected {len(historical_urls)} historical URLs")
    if parameterized_urls:
        insights.append(f"Found {len(parameterized_urls)} parameterized URLs for testing")
    if sensitive_urls:
        insights.append(f"Flagged {len(sensitive_urls)} potentially sensitive URLs")
    if api_candidates:
        insights.append(f"Identified {len(api_candidates)} API-like endpoints")
    if ip_history:
        insights.append(f"Observed {len(ip_history)} historical IP addresses")

    if dropped_urls > 0:
        warnings.append(f"Filtered out {dropped_urls} noisy/malformed/out-of-scope URLs")

    for item in failed_sources:
        warnings.append(f"{item.source} failed: {item.error}")

    if success_count > 0 and failed_sources:
        warnings.append(
            f"Partial passive coverage: {len(failed_sources)}/{len(status_entries)} sources failed"
        )

    error_text = None
    if success_count == 0:
        errors = [item.error for item in status_entries if item.error]
        error_text = "; ".join(errors)[:1000] if errors else "No passive source succeeded"

    result = PassiveWebReconResult(
        success=success_count > 0,
        target=req.target,
        normalized_domain=domain,
        command=command,
        working_dir="",
        sources_used=req.sources,
        source_status=status_entries,
        subdomains=subdomains,
        total_subdomains=len(subdomains),
        historical_urls=historical_urls,
        total_historical_urls=len(historical_urls),
        ip_history=ip_history,
        total_ip_history=len(ip_history),
        parameterized_urls=parameterized_urls,
        sensitive_urls=sensitive_urls,
        api_candidates=api_candidates,
        insights=insights,
        warnings=warnings,
        raw_output=None,
        error=error_text,
        execution_time=round(time.time() - start, 2),
    )
    return result.model_dump()


PASSIVE_WEB_RECON_TOOL_DEFINITION = {
    "name": "passive_web_recon",
    "description": (
        "Powerful passive web intelligence collector. "
        "Aggregates certificate transparency, Wayback historical URLs, OTX passive DNS, and urlscan data "
        "without actively fuzzing the target. Produces subdomains, URL intelligence, IP history, and prioritized leads."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target domain or URL (e.g. example.com or https://app.example.com).",
            },
            "sources": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": sorted(ALLOWED_SOURCES),
                },
                "description": "Passive intelligence sources to query. Default: all.",
            },
            "include_subdomains": {
                "type": "boolean",
                "description": "Include discovered subdomains in output.",
                "default": True,
            },
            "include_historical_urls": {
                "type": "boolean",
                "description": "Include historical URLs from passive archives.",
                "default": True,
            },
            "include_ip_history": {
                "type": "boolean",
                "description": "Include historical passive DNS IPs.",
                "default": True,
            },
            "max_urls": {
                "type": "integer",
                "minimum": 20,
                "maximum": 5000,
                "default": 400,
                "description": "Maximum historical URLs returned after cleaning and dedupe.",
            },
            "timeout": {
                "type": "integer",
                "minimum": 5,
                "maximum": 120,
                "default": 20,
                "description": "Per-source timeout in seconds.",
            },
            "threads": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "default": 4,
                "description": "Parallel source workers.",
            },
        },
        "required": ["target"],
    },
}


def _print_run_summary(label: str, result: dict) -> None:
    status = "ok" if result.get("success") else "failed"
    print(f"\n=== {label} ===")
    print(
        f"status={status} target={result.get('normalized_domain')} "
        f"subs={result.get('total_subdomains', 0)} "
        f"urls={result.get('total_historical_urls', 0)} "
        f"ips={result.get('total_ip_history', 0)} "
        f"time={result.get('execution_time', 0.0)}s"
    )
    source_status = result.get("source_status", []) or []
    if source_status:
        compact = []
        for item in source_status:
            source = item.get("source", "unknown")
            success = "ok" if item.get("success") else "err"
            compact.append(f"{source}:{success}")
        print("sources=" + ", ".join(compact))

    if result.get("insights"):
        print("insights=" + " | ".join(result["insights"][:4]))
    if result.get("warnings"):
        print("warnings=" + " | ".join(result["warnings"][:3]))
    if result.get("error"):
        print("error=" + str(result["error"]))


def _parse_sources_arg(value: str) -> list[str]:
    parsed = [part.strip().lower() for part in str(value).split(",") if part.strip()]
    return parsed or list(DEFAULT_SOURCES)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive web recon (CT logs, Wayback, OTX, urlscan)")
    parser.add_argument("--target", default="scanme.nmap.org", help="Target domain or URL")
    parser.add_argument(
        "--sources",
        default="crtsh,wayback,otx,urlscan",
        help="Comma-separated sources (crtsh,wayback,otx,urlscan)",
    )
    parser.add_argument("--timeout", type=int, default=20, help="Per-source timeout in seconds")
    parser.add_argument("--threads", type=int, default=4, help="Parallel source workers")
    parser.add_argument("--max-urls", type=int, default=150, help="Maximum historical URLs to keep")
    parser.add_argument("--no-subdomains", action="store_true", help="Disable subdomain collection")
    parser.add_argument("--no-urls", action="store_true", help="Disable historical URL collection")
    parser.add_argument("--no-ip-history", action="store_true", help="Disable passive DNS IP history")
    parser.add_argument("--json-only", action="store_true", help="Print only JSON result")
    args = parser.parse_args()

    if not args.json_only:
        print("=" * 70)
        print("PASSIVE WEB RECON — v1.2")
        print("CT Logs | Wayback | OTX | urlscan (Passive Only)")
        print("=" * 70)

    run = passive_web_recon(
        target=args.target,
        sources=_parse_sources_arg(args.sources),
        include_subdomains=not args.no_subdomains,
        include_historical_urls=not args.no_urls,
        include_ip_history=not args.no_ip_history,
        max_urls=args.max_urls,
        timeout=args.timeout,
        threads=args.threads,
    )

    if not args.json_only:
        _print_run_summary("PASSIVE RUN", run)
    print(json.dumps(run, indent=2))
