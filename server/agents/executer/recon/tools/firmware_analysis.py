import subprocess
import os
import re
import time
from typing import Optional, List
from pydantic import BaseModel, Field, validator


# ═══════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════

class FirmwareAnalysisRequest(BaseModel):

    firmware_path: str
    extract_dir: str = "./fw_extract"
    tools: List[str] = ["binwalk", "firmwalker"]
    timeout: int = Field(default=1200, ge=60, le=7200)

    @validator("firmware_path")
    def validate_path(cls, v):

        if not os.path.exists(v):
            raise ValueError("Firmware file not found")

        if os.path.getsize(v) > 1024 * 1024 * 1024:
            raise ValueError("Firmware too large (>1GB)")

        return v

    @validator("tools")
    def validate_tools(cls, v):

        allowed = {
            "binwalk",
            "firmwalker",
            "jefferson",
            "ubi_reader",
            "strings"
        }

        for t in v:
            if t not in allowed:
                raise ValueError(f"Tool not allowed: {t}")

        return v


class FirmwareFinding(BaseModel):

    type: str
    value: str


class FirmwareAnalysisResult(BaseModel):

    success: bool
    firmware: str
    extracted_filesystem: Optional[str] = None
    findings: List[FirmwareFinding] = []
    files_found: List[str] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float


# ═══════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
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
# 3. FINDING PARSER
# ═══════════════════════════════════════════════════════

def analyze_strings(output):

    findings = []

    cred_patterns = [
        r"password\s*=\s*(\S+)",
        r"passwd\s*=\s*(\S+)",
        r"root:.*",
        r"admin:.*"
    ]

    key_patterns = [
        r"BEGIN RSA PRIVATE KEY",
        r"BEGIN OPENSSH PRIVATE KEY",
        r"BEGIN CERTIFICATE"
    ]

    debug_patterns = [
        "telnetd",
        "dropbear",
        "debug",
        "uart",
        "console"
    ]

    for line in output.splitlines():

        for p in cred_patterns:

            if re.search(p, line, re.IGNORECASE):
                findings.append(
                    FirmwareFinding(
                        type="hardcoded_credentials",
                        value=line.strip()
                    )
                )

        for p in key_patterns:

            if p in line:
                findings.append(
                    FirmwareFinding(
                        type="crypto_material",
                        value=line.strip()
                    )
                )

        for p in debug_patterns:

            if p in line.lower():
                findings.append(
                    FirmwareFinding(
                        type="debug_interface",
                        value=line.strip()
                    )
                )

    return findings


# ═══════════════════════════════════════════════════════
# 4. FILESYSTEM SCAN
# ═══════════════════════════════════════════════════════

def scan_filesystem(path):

    interesting = []

    suspicious_ext = [
        ".conf",
        ".sh",
        ".pem",
        ".key",
        ".crt",
        ".cgi",
        ".php"
    ]

    for root, dirs, files in os.walk(path):

        for f in files:

            for ext in suspicious_ext:

                if f.endswith(ext):

                    interesting.append(
                        os.path.join(root, f)
                    )

    return interesting[:100]


# ═══════════════════════════════════════════════════════
# 5. MAIN TOOL
# ═══════════════════════════════════════════════════════

def firmware_analysis(
    firmware_path: str,
    extract_dir: str = "./fw_extract",
    tools: Optional[List[str]] = None
):

    start = time.time()
    tools = list(tools or ["binwalk", "firmwalker"])

    try:
        req = FirmwareAnalysisRequest(
            firmware_path=firmware_path,
            extract_dir=extract_dir,
            tools=tools,
        )
    except Exception as e:
        return FirmwareAnalysisResult(
            success=False,
            firmware=firmware_path,
            extracted_filesystem=None,
            findings=[],
            files_found=[],
            raw_output=None,
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    raw = ""
    findings = []
    files_found = []

    # ─────────────────────────
    # BINWALK EXTRACTION
    # ─────────────────────────

    if "binwalk" in tools:

        cmd = [
            "binwalk",
            "-e",
            req.firmware_path,
            "-C",
            req.extract_dir
        ]

        stdout, stderr, rc = safe_execute(cmd, 600)

        raw += stdout

    # ─────────────────────────
    # STRINGS ANALYSIS
    # ─────────────────────────

    if "strings" in tools:

        cmd = [
            "strings",
            req.firmware_path
        ]

        stdout, stderr, rc = safe_execute(cmd, 300)

        raw += stdout

        findings.extend(
            analyze_strings(stdout)
        )

    # ─────────────────────────
    # FIRM WALKER
    # ─────────────────────────

    if "firmwalker" in tools:

        cmd = [
            "firmwalker",
            req.extract_dir
        ]

        stdout, stderr, rc = safe_execute(cmd, 600)

        raw += stdout

    # ─────────────────────────
    # FILESYSTEM SCAN
    # ─────────────────────────

    if os.path.exists(req.extract_dir):

        files_found = scan_filesystem(req.extract_dir)

    return FirmwareAnalysisResult(
        success=True,
        firmware=req.firmware_path,
        extracted_filesystem=req.extract_dir,
        findings=findings,
        files_found=files_found,
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ═══════════════════════════════════════════════════════

FIRMWARE_ANALYSIS_TOOL_DEFINITION = {

    "name": "firmware_analysis",

    "description": (
        "Extract and analyze firmware images for embedded devices. "
        "Detect hardcoded credentials, private keys, debug interfaces, "
        "backdoors, and configuration files."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "firmware_path": {
                "type": "string",
                "description": "Path to firmware image file"
            },

            "extract_dir": {
                "type": "string",
                "description": "Directory to extract firmware filesystem"
            },

            "tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tools to use: binwalk, firmwalker, strings"
            }

        },

        "required": ["firmware_path"]

    }

}
