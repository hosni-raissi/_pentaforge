import subprocess
import re
import time
import os
from typing import Optional, List
from pydantic import BaseModel, Field, validator


# ═══════════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════════

class BinaryAnalysisRequest(BaseModel):
    file_path: str
    tools: List[str] = ["strings", "checksec", "radare2"]
    timeout: int = Field(default=600, ge=30, le=3600)

    @validator("file_path")
    def validate_path(cls, v):
        if not os.path.exists(v):
            raise ValueError(f"Binary not found: {v}")

        if os.path.getsize(v) > 200 * 1024 * 1024:
            raise ValueError("Binary too large (>200MB)")

        return v

    @validator("tools")
    def validate_tools(cls, v):
        allowed = {
            "strings",
            "checksec",
            "radare2",
            "readelf",
            "objdump"
        }

        for t in v:
            if t not in allowed:
                raise ValueError(f"Tool not allowed: {t}")

        return v


class BinaryProtection(BaseModel):
    nx: Optional[bool] = None
    pie: Optional[bool] = None
    relro: Optional[str] = None
    canary: Optional[bool] = None
    fortify: Optional[bool] = None


class BinaryFinding(BaseModel):
    type: str
    value: str


class BinaryAnalysisResult(BaseModel):
    success: bool
    file: str
    protections: Optional[BinaryProtection] = None
    findings: List[BinaryFinding] = []
    interesting_strings: List[str] = []
    imported_functions: List[str] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float


# ═══════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ═══════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════
# 3. STRINGS ANALYSIS
# ═══════════════════════════════════════════════════════════

def analyze_strings(output):

    interesting = []
    findings = []

    password_patterns = [
        r"password\s*=\s*(\S+)",
        r"passwd\s*=\s*(\S+)",
        r"api[_-]?key\s*=\s*(\S+)",
        r"token\s*=\s*(\S+)"
    ]

    url_pattern = r"https?://[^\s]+"

    for line in output.splitlines():

        if len(line) < 6:
            continue

        if re.search(url_pattern, line):
            interesting.append(line)

        for p in password_patterns:
            if re.search(p, line, re.IGNORECASE):
                findings.append(
                    BinaryFinding(
                        type="hardcoded_credential",
                        value=line
                    )
                )

        if "dll" in line.lower():
            findings.append(
                BinaryFinding(
                    type="dll_reference",
                    value=line
                )
            )

    return interesting[:50], findings


# ═══════════════════════════════════════════════════════════
# 4. CHECKSEC PARSER
# ═══════════════════════════════════════════════════════════

def parse_checksec(output):

    prot = BinaryProtection()

    if "NX enabled" in output:
        prot.nx = True
    if "NX disabled" in output:
        prot.nx = False

    if "PIE enabled" in output:
        prot.pie = True
    if "PIE disabled" in output:
        prot.pie = False

    if "Canary found" in output:
        prot.canary = True
    if "No canary found" in output:
        prot.canary = False

    if "Full RELRO" in output:
        prot.relro = "Full"
    elif "Partial RELRO" in output:
        prot.relro = "Partial"
    else:
        prot.relro = "None"

    return prot


# ═══════════════════════════════════════════════════════════
# 5. RADARE2 IMPORT ANALYSIS
# ═══════════════════════════════════════════════════════════

def parse_imports(output):

    dangerous_funcs = [
        "strcpy",
        "gets",
        "scanf",
        "sprintf",
        "strcat"
    ]

    imports = []
    findings = []

    for line in output.splitlines():

        func = line.strip()

        if func:
            imports.append(func)

        if func in dangerous_funcs:
            findings.append(
                BinaryFinding(
                    type="dangerous_function",
                    value=func
                )
            )

    return imports[:100], findings


# ═══════════════════════════════════════════════════════════
# 6. MAIN TOOL
# ═══════════════════════════════════════════════════════════

def binary_analysis(file_path: str, tools: List[str] = ["strings", "checksec", "radare2"]):

    start = time.time()

    findings = []
    interesting_strings = []
    imports = []
    protections = None
    raw = ""

    # ─────────────────────────
    # STRINGS
    # ─────────────────────────

    if "strings" in tools:

        stdout, stderr, rc = safe_execute(
            ["strings", file_path],
            300
        )

        raw += stdout

        strs, f = analyze_strings(stdout)

        interesting_strings.extend(strs)
        findings.extend(f)

    # ─────────────────────────
    # CHECKSEC
    # ─────────────────────────

    if "checksec" in tools:

        stdout, stderr, rc = safe_execute(
            ["checksec", "--file", file_path],
            60
        )

        raw += stdout

        protections = parse_checksec(stdout)

    # ─────────────────────────
    # RADARE2 IMPORTS
    # ─────────────────────────

    if "radare2" in tools:

        stdout, stderr, rc = safe_execute(
            ["r2", "-A", "-q", "-c", "ii", file_path],
            300
        )

        raw += stdout

        imps, f = parse_imports(stdout)

        imports.extend(imps)
        findings.extend(f)

    return BinaryAnalysisResult(
        success=True,
        file=file_path,
        protections=protections,
        findings=findings,
        interesting_strings=interesting_strings,
        imported_functions=imports,
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════════
# 7. TOOL DEFINITION
# ═══════════════════════════════════════════════════════════

BINARY_ANALYSIS_TOOL_DEFINITION = {

    "name": "binary_analysis",

    "description": (
        "Reverse engineer binaries (.exe, .dll, .elf). "
        "Detect hardcoded credentials, DLL hijacking, dangerous functions, "
        "and binary security protections like ASLR/NX/DEP/RELRO."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "file_path": {
                "type": "string",
                "description": "Path to binary file"
            },

            "tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tools to use: strings, checksec, radare2"
            }

        },

        "required": ["file_path"]

    }

}