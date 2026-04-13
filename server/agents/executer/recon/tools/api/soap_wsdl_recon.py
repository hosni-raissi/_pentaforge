#/+
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from server.agents.executer.recon.tools.api._common import (
    build_url,
    extract_host,
    response_snippet,
    safe_request,
    summarize_validation_error,
    validate_headers,
    validate_http_target,
)

WSDL_PATHS = [
    "/service?wsdl",
    "/soap?wsdl",
    "/api?wsdl",
    "/wsdl",
    "/service.wsdl",
    "/soap",
    "/soap/v1?wsdl",
    "/api/wsdl",
    "/webservice?wsdl",
    "/xmlrpc.php",
]

SENSITIVE_OPERATION_PATTERNS = [
    "admin",
    "debug",
    "delete",
    "execute",
    "token",
    "secret",
    "password",
    "upload",
    "reset",
]

INTERNAL_HOST_PATTERNS = [".internal", ".local", ".corp", ".lan"]

NS = {
    "wsdl":   "http://schemas.xmlsoap.org/wsdl/",
    "soap":   "http://schemas.xmlsoap.org/wsdl/soap/",
    "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
    "http":   "http://schemas.xmlsoap.org/wsdl/http/",
    "xsd":    "http://www.w3.org/2001/XMLSchema",
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class SOAPWSDLReconRequest(BaseModel):
    target: str
    endpoints: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=5, le=180)
    verify_tls: bool = True
    include_404_probes: bool = False

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return validate_http_target(value, allow_paths=True)

    @field_validator("headers")
    @classmethod
    def validate_custom_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return validate_headers(value)


class SOAPOperation(BaseModel):
    name: str
    soap_action: str | None = None
    input_message: str | None = None
    output_message: str | None = None
    sensitive: bool = False


class WSDLService(BaseModel):
    name: str
    ports: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)


class WSDLDocument(BaseModel):
    url: str
    service_names: list[str] = Field(default_factory=list)
    target_namespace: str | None = None
    soap_versions: list[str] = Field(default_factory=list)
    operations: list[SOAPOperation] = Field(default_factory=list)
    services: list[WSDLService] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    internal_hosts: list[str] = Field(default_factory=list)
    response_snippet: str | None = None
    issues: list[str] = Field(default_factory=list)


class SOAPFinding(BaseModel):
    title: str
    severity: str = "info"
    description: str
    evidence: list[str] = Field(default_factory=list)


class SOAPProbe(BaseModel):
    url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    reachable: bool = False
    looks_like_wsdl: bool = False
    error: str | None = None
    response_snippet: str | None = None


class SOAPWSDLReconResult(BaseModel):
    success: bool
    target: str
    endpoints_probed: int = 0
    probes: list[SOAPProbe] = Field(default_factory=list)
    ignored_404_probes: int = 0
    wsdl_documents: list[WSDLDocument] = Field(default_factory=list)
    findings: list[SOAPFinding] = Field(default_factory=list)
    raw_output: str | None = None
    error: str | None = None
    execution_time: float = 0.0
    techniques_used: list[str] = Field(default_factory=lambda: ["wsdl_probe", "xml_parse"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _candidate_urls(target: str, endpoints: list[str]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for item in [*WSDL_PATHS, *endpoints]:
        url = build_url(target, item)
        if url not in seen:
            seen.add(url)
            candidates.append(url)

    parsed = urlparse(target)
    if parsed.path and parsed.path != "/" and parsed.scheme and parsed.netloc:
        # If the target is scoped to a base path (e.g. /api), also probe host-root
        # WSDL conventions to avoid missing SOAP services mounted outside that path.
        host_root = f"{parsed.scheme}://{parsed.netloc}"
        for item in [*WSDL_PATHS, *endpoints]:
            root_url = build_url(host_root, item)
            if root_url not in seen:
                seen.add(root_url)
                candidates.append(root_url)

    if parsed.query.lower() == "wsdl" and target not in seen:
        candidates.insert(0, target)
    elif parsed.path and target + "?wsdl" not in seen:
        candidates.append(target.rstrip("/") + "?wsdl")
    return candidates


def _looks_like_wsdl(content_type: str, body: str) -> bool:
    lowered = f"{content_type}\n{body[:1000]}".lower()
    return (
        "<definitions" in lowered
        or "wsdl:" in lowered
        or "http://schemas.xmlsoap.org/wsdl/" in lowered
    )


def _internal_hosts(values: list[str]) -> list[str]:
    findings: set[str] = set()
    for value in values:
        host = extract_host(value)
        if not host:
            continue
        if any(marker in host for marker in INTERNAL_HOST_PATTERNS):
            findings.add(host)
            continue
        if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)", host):
            findings.add(host)
    return sorted(findings)


def _parse_wsdl(url: str, body: str) -> WSDLDocument:
    document = WSDLDocument(url=url, response_snippet=response_snippet(body, limit=1500))
    if "<!entity" in body.lower() or "<!doctype" in body.lower():
        document.issues.append("DTD or ENTITY declaration present in WSDL/XML response")

    root = ET.fromstring(body)
    document.target_namespace = root.attrib.get("targetNamespace")

    imports: list[str] = []
    for tag in ("wsdl:import", "xsd:import", "xsd:include"):
        for node in root.findall(f".//{tag}", NS):
            location = node.attrib.get("location") or node.attrib.get("schemaLocation")
            if location:
                imports.append(location)
    document.imports = sorted(set(imports))

    soap_versions: set[str] = set()
    services: list[WSDLService] = []
    service_names: list[str] = []
    addresses: list[str] = []
    for service in root.findall(".//wsdl:service", NS):
        service_name = service.attrib.get("name", "unknown")
        service_names.append(service_name)
        ports: list[str] = []
        service_addresses: list[str] = []
        for port in service.findall("wsdl:port", NS):
            ports.append(port.attrib.get("name", "unknown"))
            soap_address = port.find("soap:address", NS)
            soap12_address = port.find("soap12:address", NS)
            if soap_address is not None and soap_address.attrib.get("location"):
                soap_versions.add("SOAP 1.1")
                service_addresses.append(soap_address.attrib["location"])
            if soap12_address is not None and soap12_address.attrib.get("location"):
                soap_versions.add("SOAP 1.2")
                service_addresses.append(soap12_address.attrib["location"])
        addresses.extend(service_addresses)
        services.append(WSDLService(name=service_name, ports=ports, addresses=service_addresses))
    document.services = services
    document.service_names = sorted(set(service_names))
    document.soap_versions = sorted(soap_versions)

    operation_meta: dict[str, SOAPOperation] = {}
    for port_type in root.findall(".//wsdl:portType", NS):
        for operation in port_type.findall("wsdl:operation", NS):
            name = operation.attrib.get("name", "unknown")
            input_node = operation.find("wsdl:input", NS)
            output_node = operation.find("wsdl:output", NS)
            operation_meta[name] = SOAPOperation(
                name=name,
                input_message=input_node.attrib.get("message") if input_node is not None else None,
                output_message=output_node.attrib.get("message") if output_node is not None else None,
                sensitive=any(pattern in name.lower() for pattern in SENSITIVE_OPERATION_PATTERNS),
            )

    for binding in root.findall(".//wsdl:binding", NS):
        for operation in binding.findall("wsdl:operation", NS):
            name = operation.attrib.get("name", "unknown")
            op = operation_meta.setdefault(name, SOAPOperation(name=name))
            soap_op = operation.find("soap:operation", NS) or operation.find("soap12:operation", NS)
            if soap_op is not None:
                op.soap_action = soap_op.attrib.get("soapAction")

    document.operations = sorted(operation_meta.values(), key=lambda op: op.name)
    document.internal_hosts = _internal_hosts([*document.imports, *addresses])

    if document.service_names:
        document.issues.append("Public WSDL/service definition exposed")
    if document.internal_hosts:
        document.issues.append("Internal hostnames or private addresses disclosed in WSDL")
    if any(op.sensitive for op in document.operations):
        document.issues.append("Potentially sensitive SOAP operations discovered")
    return document


def _build_findings(documents: list[WSDLDocument]) -> list[SOAPFinding]:
    findings: list[SOAPFinding] = []
    exposed = [doc.url for doc in documents if doc.service_names]
    if exposed:
        findings.append(SOAPFinding(
            title="Public WSDL exposed",
            severity="medium",
            description="WSDL or service definitions were accessible without prior authentication.",
            evidence=exposed[:10],
        ))
    internal = sorted({host for doc in documents for host in doc.internal_hosts})
    if internal:
        findings.append(SOAPFinding(
            title="Internal endpoint disclosure",
            severity="medium",
            description="WSDL content disclosed internal hostnames or private network addresses.",
            evidence=internal[:15],
        ))
    sensitive_ops = sorted({op.name for doc in documents for op in doc.operations if op.sensitive})
    if sensitive_ops:
        findings.append(SOAPFinding(
            title="Sensitive SOAP operations discovered",
            severity="medium",
            description="Operation names suggest administrative or high-impact actions worth deeper testing.",
            evidence=sensitive_ops[:15],
        ))
    dtd_urls = [doc.url for doc in documents if any("DTD" in i or "ENTITY" in i for i in doc.issues)]
    if dtd_urls:
        findings.append(SOAPFinding(
            title="DTD or ENTITY markup present",
            severity="low",
            description=(
                "XML definitions included DTD/ENTITY declarations. "
                "That does not prove XXE, but it is worth reviewing parser hardening."
            ),
            evidence=dtd_urls[:10],
        ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def soap_wsdl_recon(
    target: str,
    endpoints: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    verify_tls: bool = True,
    include_404_probes: bool = False,
) -> dict:
    """
    Discover SOAP and WSDL surfaces. Probes common WSDL paths, parses services,
    ports, operations, imports, and flags internal disclosure or sensitive actions.
    """
    start = time.monotonic()
    endpoints = endpoints or []
    headers = headers or {}
    try:
        req = SOAPWSDLReconRequest(
            target=target,
            endpoints=endpoints,
            headers=headers,
            timeout=timeout,
            verify_tls=verify_tls,
            include_404_probes=include_404_probes,
        )
    except Exception as exc:
        return SOAPWSDLReconResult(
            success=False,
            target=target,
            error=summarize_validation_error(exc),
        ).model_dump()

    documents: list[WSDLDocument] = []
    raw_bodies: list[str] = []
    probes: list[SOAPProbe] = []
    candidates = _candidate_urls(req.target, req.endpoints)

    for url in candidates:
        probe = SOAPProbe(url=url)
        response = safe_request(
            "GET",
            url,
            headers=req.headers,
            timeout=req.timeout,
            verify_tls=req.verify_tls,
            allow_redirects=True,
        )
        if response is None:
            probe.error = "safe_request returned None"
            probes.append(probe)
            continue

        if not response.ok:
            failure = getattr(response, "failure", None)
            if failure is not None:
                probe.error = f"{failure.reason}: {failure.detail}"
            else:
                probe.error = "request failed before receiving HTTP response"
            probes.append(probe)
            continue

        status_code = response.status_code
        if status_code is None:
            probe.error = "missing HTTP status code"
            probes.append(probe)
            continue

        body = response.text or ""
        content_type = response.headers.get("content-type", "") if response.headers else ""

        probe.reachable = True
        probe.final_url = str(response.url or url)
        probe.status_code = status_code
        probe.content_type = content_type or None
        probe.response_snippet = response_snippet(body, limit=220)
        probe.looks_like_wsdl = _looks_like_wsdl(content_type, body)

        if status_code >= 400 or not probe.looks_like_wsdl:
            probes.append(probe)
            continue

        try:
            documents.append(_parse_wsdl(str(response.url or url), body))
            raw_bodies.append(body)
        except ET.ParseError:
            probe.error = "WSDL candidate parse error"
        probes.append(probe)

    findings = _build_findings(documents)
    ignored_404_probes = sum(1 for p in probes if p.status_code == 404)
    raw_output = response_snippet("\n\n".join(raw_bodies), limit=5000)

    error: str | None
    if documents:
        error = None
    else:
        reachable = [p for p in probes if p.reachable]
        wsdl_like = [p for p in reachable if p.looks_like_wsdl]
        if not reachable:
            error = "No WSDL/SOAP definitions discovered; target appears unreachable for probed endpoints"
        elif not wsdl_like:
            reachable_count = len(reachable)
            status_404_count = sum(1 for p in reachable if p.status_code == 404)
            if reachable_count > 0 and status_404_count == reachable_count:
                parsed_target = urlparse(req.target)
                target_path = parsed_target.path or "/"
                if target_path != "/":
                    error = (
                        "No WSDL/SOAP definitions discovered; target is reachable but all probed endpoints "
                        f"returned HTTP 404 for base path '{target_path}' and host-root fallback paths. "
                        "Likely no SOAP/WSDL routes are exposed on this host/port; provide explicit SOAP endpoints if known."
                    )
                else:
                    error = (
                        "No WSDL/SOAP definitions discovered; target is reachable but all probed endpoints "
                        "returned HTTP 404 at host root. Likely no SOAP/WSDL routes are exposed there; "
                        "provide explicit SOAP endpoints if known."
                    )
            else:
                error = (
                    "No WSDL/SOAP definitions discovered; target is reachable but responses looked non-WSDL "
                    "(likely REST/JSON API)"
                )
        else:
            error = "No WSDL/SOAP definitions discovered"

        if not raw_output:
            diagnostic_probes = probes if req.include_404_probes else [p for p in probes if p.status_code != 404]
            probe_lines = []
            for p in diagnostic_probes[:20]:
                code = str(p.status_code) if p.status_code is not None else "ERR"
                ct = p.content_type or "-"
                mark = "wsdl-like" if p.looks_like_wsdl else "non-wsdl"
                err = p.error or "-"
                snip = (p.response_snippet or "").replace("\n", " ")[:120]
                probe_lines.append(f"[{code}] {p.url} ct={ct} {mark} err={err} snip={snip}")
            if probe_lines:
                raw_output = response_snippet("\n".join(probe_lines), limit=5000)
            elif ignored_404_probes:
                raw_output = f"Filtered {ignored_404_probes} HTTP 404 probe responses from diagnostics output."

    output_probes = probes if req.include_404_probes else [p for p in probes if p.status_code != 404]

    return SOAPWSDLReconResult(
        success=bool(documents),
        target=req.target,
        endpoints_probed=len(candidates),
        probes=output_probes,
        ignored_404_probes=0 if req.include_404_probes else ignored_404_probes,
        wsdl_documents=documents,
        findings=findings,
        raw_output=raw_output,
        error=error,
        execution_time=round(time.monotonic() - start, 2),
    ).model_dump()


SOAP_WSDL_RECON_TOOL_DEFINITION = {
    "name": "soap_wsdl_recon",
    "description": (
        "Discover SOAP and WSDL endpoints. Parses services, bindings, operations, imports, "
        "and highlights internal host disclosure plus sensitive SOAP actions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base SOAP or application URL such as https://example.com",
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional custom SOAP/WSDL paths to probe in addition to defaults.",
            },
            "headers": {
                "type": "object",
                "description": "Optional custom HTTP headers.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout per request in seconds (default: 30)",
            },
            "verify_tls": {
                "type": "boolean",
                "description": "Verify TLS certificates (default: true)",
            },
            "include_404_probes": {
                "type": "boolean",
                "description": "Include HTTP 404 probes in output payload (default: false)",
            },
        },
        "required": ["target"],
    },
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ── Configure your scan here ─────────────────────────────────────────────────
TARGET      = "http://localhost:8888/api"   # base URL of the SOAP/WSDL target
ENDPOINTS   = []                      # extra paths, e.g. ["/legacy/service?wsdl"]
HEADERS     = {}                      # custom headers, e.g. {"Authorization": "Bearer ..."}
TIMEOUT     = 30                      # per-request timeout in seconds (5–180)
VERIFY_TLS  = True                    # set False to skip TLS certificate validation
INCLUDE_404_PROBES = False            # include 404 probes in output payload
EMIT_JSON   = False                   # True → raw JSON output, False → human-readable
SHOW_FULL_RESULT = True               # True → also print full result payload after summary output
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    import json

    result = soap_wsdl_recon(
        target=TARGET,
        endpoints=ENDPOINTS,
        headers=HEADERS,
        timeout=TIMEOUT,
        verify_tls=VERIFY_TLS,
        include_404_probes=INCLUDE_404_PROBES,
    )

    if EMIT_JSON:
        print(json.dumps(result, indent=2))
        return

    status = "OK" if result["success"] else "FAILED"
    print(f"\n[{status}] {result['target']}  ({result['execution_time']}s)")
    print(f"  Endpoints probed : {result['endpoints_probed']}")
    print(f"  WSDL documents   : {len(result['wsdl_documents'])}\n")

    probes = result.get("probes") or []
    ignored_404 = result.get("ignored_404_probes") or 0
    if probes:
        reachable = sum(1 for p in probes if p.get("reachable"))
        wsdl_like = sum(1 for p in probes if p.get("looks_like_wsdl"))
        print(f"  Probe diagnostics: reachable={reachable}/{len(probes)}, wsdl_like={wsdl_like}")
        for p in probes[:8]:
            code = p.get("status_code") if p.get("status_code") is not None else "ERR"
            ctype = p.get("content_type") or "-"
            marker = "WSDL" if p.get("looks_like_wsdl") else "NON-WSDL"
            print(f"    [{code}] {p.get('url')}  ({ctype})  {marker}")
            if p.get("error"):
                print(f"           error: {p['error']}")
        print()
    elif ignored_404:
        print(f"  Probe diagnostics: no non-404 probes to display (filtered 404 probes: {ignored_404})\n")

    if result.get("error") and not result["wsdl_documents"]:
        print(f"  {result['error']}\n")
        if SHOW_FULL_RESULT:
            print("  Full result:")
            print(json.dumps(result, indent=2))
        return

    for doc in result["wsdl_documents"]:
        print(f"  [WSDL] {doc['url']}")
        if doc["service_names"]:
            print(f"    Services    : {', '.join(doc['service_names'])}")
        if doc["soap_versions"]:
            print(f"    SOAP        : {', '.join(doc['soap_versions'])}")
        if doc["operations"]:
            op_names = [op["name"] for op in doc["operations"]]
            sensitive = [op["name"] for op in doc["operations"] if op["sensitive"]]
            print(f"    Operations  : {len(op_names)}  (sensitive: {len(sensitive)})")
        if doc["internal_hosts"]:
            print(f"    Internal IPs: {', '.join(doc['internal_hosts'])}")
        for issue in doc["issues"]:
            print(f"    [!] {issue}")
        print()

    if result["findings"]:
        print("  Findings:")
        for finding in result["findings"]:
            sev = finding["severity"].upper()
            print(f"    [{sev:6}] {finding['title']}")
            for evidence in finding["evidence"][:5]:
                print(f"             - {evidence}")
        print()

    if SHOW_FULL_RESULT:
        print("  Full result:")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()