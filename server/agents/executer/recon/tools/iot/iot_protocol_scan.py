import subprocess
import re
import time
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# ═══════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════

class IoTScanRequest(BaseModel):

    target: str
    protocols: List[str] = ["mqtt", "coap"]
    timeout: int = Field(default=300, ge=30, le=3600)

    @field_validator("protocols")
    @classmethod
    def validate_protocols(cls, v):

        allowed = {
            "mqtt",
            "coap",
            "upnp",
            "ble",
            "modbus",
            "bacnet"
        }

        for p in v:
            if p not in allowed:
                raise ValueError(f"Unsupported protocol: {p}")

        return v


class IoTService(BaseModel):

    protocol: str
    endpoint: str
    info: Optional[str] = None


class IoTFinding(BaseModel):

    type: str
    value: str


class IoTScanResult(BaseModel):

    success: bool
    target: str
    services: List[IoTService] = []
    findings: List[IoTFinding] = []
    raw_output: Optional[str] = None
    execution_time: float


# ═══════════════════════════════════════════════════════
# 2. SAFE EXECUTION
# ═══════════════════════════════════════════════════════

def safe_execute(cmd, timeout):

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", "Timeout", -1

    except Exception as e:
        return "", str(e), -1


# ═══════════════════════════════════════════════════════
# 3. OUTPUT PARSER
# ═══════════════════════════════════════════════════════

def parse_iot_output(output):

    services = []
    findings = []

    # MQTT detection
    if "MQTT" in output:

        services.append(
            IoTService(
                protocol="mqtt",
                endpoint="broker"
            )
        )

    # CoAP endpoints
    for uri in re.findall(r"coap://[^\s]+", output):

        services.append(
            IoTService(
                protocol="coap",
                endpoint=uri
            )
        )

    # UPnP devices
    if "UPnP" in output:

        services.append(
            IoTService(
                protocol="upnp",
                endpoint="device"
            )
        )

    # Anonymous MQTT
    if "anonymous login allowed" in output.lower():

        findings.append(
            IoTFinding(
                type="mqtt_anonymous_access",
                value="MQTT broker allows anonymous connections"
            )
        )

    # Modbus
    if "modbus" in output.lower():

        findings.append(
            IoTFinding(
                type="modbus_service",
                value="Modbus service detected"
            )
        )

    return services, findings


# ═══════════════════════════════════════════════════════
# 4. MAIN TOOL
# ═══════════════════════════════════════════════════════

def iot_protocol_scan(
    target: str,
    protocols: Optional[List[str]] = None
):

    start = time.time()
    protocols = list(protocols or ["mqtt", "coap"])

    try:
        req = IoTScanRequest(target=target, protocols=protocols)
    except Exception as e:
        return IoTScanResult(
            success=False,
            target=target,
            services=[],
            findings=[],
            raw_output=None,
            execution_time=round(time.time() - start, 2),
        ).model_dump() | {"error": f"Validation: {e}"}

    raw = ""
    services = []
    findings = []

    # ─────────────────────────
    # MQTT
    # ─────────────────────────

    if "mqtt" in protocols:

        cmd = [
            "mqtt-pwn",
            "scan",
            "-h",
            req.target
        ]

        stdout, stderr, rc = safe_execute(cmd, 120)

        raw += stdout

    # ─────────────────────────
    # COAP
    # ─────────────────────────

    if "coap" in protocols:

        cmd = [
            "coap-client",
            "-m",
            "get",
            f"coap://{req.target}/.well-known/core"
        ]

        stdout, stderr, rc = safe_execute(cmd, 120)

        raw += stdout

    # ─────────────────────────
    # NMAP IoT SCRIPTS
    # ─────────────────────────

    if any(p in protocols for p in ["upnp","modbus","bacnet"]):

        scripts = [
            "upnp-info",
            "modbus-discover",
            "bacnet-info"
        ]

        cmd = [
            "nmap",
            "-sU",
            "--script=" + ",".join(scripts),
            req.target
        ]

        stdout, stderr, rc = safe_execute(cmd, 300)

        raw += stdout

    # ─────────────────────────
    # BLE SCAN
    # ─────────────────────────

    if "ble" in protocols:

        cmd = [
            "bettercap",
            "-eval",
            "ble.recon on"
        ]

        stdout, stderr, rc = safe_execute(cmd, 120)

        raw += stdout

    # ─────────────────────────
    # PARSE RESULTS
    # ─────────────────────────

    s, f = parse_iot_output(raw)

    services.extend(s)
    findings.extend(f)

    return IoTScanResult(
        success=True,
        target=req.target,
        services=services,
        findings=findings,
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ═══════════════════════════════════════════════════════

IOT_PROTOCOL_SCAN_TOOL = {

    "name": "iot_protocol_scan",

    "description": (
        "Scan IoT devices for protocol services including MQTT, CoAP, "
        "UPnP, BLE, Modbus, and BACnet. Detect insecure configurations "
        "like anonymous MQTT access and exposed IoT services."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "target": {
                "type": "string",
                "description": "Target IP or hostname"
            },

            "protocols": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Protocols to scan: mqtt, coap, upnp, ble, modbus, bacnet"
            }

        },

        "required": ["target"]

    }

}
