import subprocess
import re
import time
from typing import Optional, List
from pydantic import BaseModel, Field, validator


# ═══════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════

class CloudEnumRequest(BaseModel):

    target: str
    tools: List[str] = ["cloud_enum"]
    timeout: int = Field(default=600, ge=30, le=3600)

    @validator("tools")
    def validate_tools(cls, v):

        allowed = {
            "cloud_enum",
            "s3scanner",
            "lazys3",
            "awscli",
            "gsutil"
        }

        for t in v:
            if t not in allowed:
                raise ValueError(f"Tool not allowed: {t}")

        return v


class CloudAsset(BaseModel):

    provider: str
    resource: str
    access: Optional[str] = None
    files: List[str] = []


class CloudFinding(BaseModel):

    type: str
    value: str


class CloudEnumResult(BaseModel):

    success: bool
    target: str
    assets: List[CloudAsset] = []
    findings: List[CloudFinding] = []
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
# 3. PARSER
# ═══════════════════════════════════════════════════════

def parse_cloud_output(output):

    assets = []
    findings = []

    s3_pattern = r"s3://([a-zA-Z0-9\-\._]+)"
    azure_pattern = r"https://([a-zA-Z0-9\-]+)\.blob\.core\.windows\.net"
    gcp_pattern = r"gs://([a-zA-Z0-9\-\._]+)"

    # ───────────────
    # S3 Buckets
    # ───────────────

    for bucket in re.findall(s3_pattern, output):

        assets.append(
            CloudAsset(
                provider="aws",
                resource=bucket
            )
        )

        findings.append(
            CloudFinding(
                type="public_s3_bucket",
                value=bucket
            )
        )

    # ───────────────
    # Azure Blobs
    # ───────────────

    for blob in re.findall(azure_pattern, output):

        assets.append(
            CloudAsset(
                provider="azure",
                resource=blob
            )
        )

        findings.append(
            CloudFinding(
                type="public_blob_storage",
                value=blob
            )
        )

    # ───────────────
    # GCP Buckets
    # ───────────────

    for bucket in re.findall(gcp_pattern, output):

        assets.append(
            CloudAsset(
                provider="gcp",
                resource=bucket
            )
        )

        findings.append(
            CloudFinding(
                type="public_gcp_bucket",
                value=bucket
            )
        )

    # ───────────────
    # Backup files
    # ───────────────

    backup_patterns = [
        r"\.bak",
        r"\.sql",
        r"\.zip",
        r"\.tar",
        r"\.gz"
    ]

    for line in output.splitlines():

        for p in backup_patterns:

            if re.search(p, line):

                findings.append(
                    CloudFinding(
                        type="exposed_backup",
                        value=line.strip()
                    )
                )

    return assets, findings


# ═══════════════════════════════════════════════════════
# 4. MAIN TOOL
# ═══════════════════════════════════════════════════════

def cloud_storage_enum(
    target: str,
    tools: Optional[List[str]] = None
):

    start = time.time()
    tools = list(tools or ["cloud_enum"])

    try:
        req = CloudEnumRequest(target=target, tools=tools)
    except Exception as e:
        return CloudEnumResult(
            success=False,
            target=target,
            assets=[],
            findings=[],
            raw_output=None,
            execution_time=round(time.time() - start, 2),
        ).model_dump() | {"error": f"Validation: {e}"}

    raw = ""
    assets = []
    findings = []

    # ─────────────────────────
    # CLOUD ENUM
    # ─────────────────────────

    if "cloud_enum" in tools:

        cmd = [
            "cloud_enum",
            "-k",
            req.target
        ]

        stdout, stderr, rc = safe_execute(cmd, 600)

        raw += stdout

    # ─────────────────────────
    # S3SCANNER
    # ─────────────────────────

    if "s3scanner" in tools:

        cmd = [
            "s3scanner",
            "--bucket",
            req.target
        ]

        stdout, stderr, rc = safe_execute(cmd, 300)

        raw += stdout

    # ─────────────────────────
    # LAZYS3
    # ─────────────────────────

    if "lazys3" in tools:

        cmd = [
            "lazys3",
            req.target
        ]

        stdout, stderr, rc = safe_execute(cmd, 300)

        raw += stdout

    # ─────────────────────────
    # PARSE RESULTS
    # ─────────────────────────

    a, f = parse_cloud_output(raw)

    assets.extend(a)
    findings.extend(f)

    return CloudEnumResult(
        success=True,
        target=req.target,
        assets=assets,
        findings=findings,
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ═══════════════════════════════════════════════════════

CLOUD_ENUM_TOOL_DEFINITION = {

    "name": "cloud_storage_enum",

    "description": (
        "Enumerate cloud storage misconfigurations including AWS S3, "
        "Azure Blob Storage, and Google Cloud Storage. Detect public "
        "buckets, exposed backups, and leaked data."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "target": {
                "type": "string",
                "description": "Company name, domain, or keyword used for bucket discovery"
            },

            "tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tools to use: cloud_enum, s3scanner, lazys3"
            }

        },

        "required": ["target"]

    }

}
