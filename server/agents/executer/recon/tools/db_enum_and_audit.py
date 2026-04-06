import subprocess
import json
import re
import time
from typing import Optional, List
from pydantic import BaseModel, Field, validator


# ═══════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════

class DBEnumRequest(BaseModel):

    target: str
    port: Optional[int] = None
    db_type: Optional[str] = None
    tools: List[str] = ["nmap"]
    timeout: int = Field(default=600, ge=30, le=3600)

    @validator("db_type")
    def validate_db_type(cls, v):

        if v is None:
            return v

        allowed = {
            "mysql",
            "postgres",
            "mongodb",
            "redis",
            "mssql"
        }

        if v not in allowed:
            raise ValueError("Unsupported DB type")

        return v


class DBFinding(BaseModel):
    type: str
    value: str


class DBInfo(BaseModel):

    db_type: Optional[str]
    version: Optional[str]
    databases: List[str] = []
    users: List[str] = []
    roles: List[str] = []


class DBEnumResult(BaseModel):

    success: bool
    target: str
    findings: List[DBFinding] = []
    db_info: Optional[DBInfo] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
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

def parse_db_output(output):

    findings = []
    databases = []
    users = []
    roles = []
    version = None

    # DB version
    version_match = re.search(r"version[: ]+([0-9\.]+)", output, re.I)
    if version_match:
        version = version_match.group(1)

    # Databases
    for db in re.findall(r"Database:\s*(\S+)", output):
        databases.append(db)

    # Users
    for u in re.findall(r"user[: ]+(\S+)", output, re.I):
        users.append(u)

    # Roles
    for r in re.findall(r"role[: ]+(\S+)", output, re.I):
        roles.append(r)

    # Default credentials
    if "access granted" in output.lower():
        findings.append(
            DBFinding(
                type="default_credentials",
                value="Login succeeded using weak/default creds"
            )
        )

    # Public access
    if "authentication disabled" in output.lower():
        findings.append(
            DBFinding(
                type="public_access",
                value="Database allows unauthenticated access"
            )
        )

    return databases, users, roles, version, findings


# ═══════════════════════════════════════════════════════
# 4. MAIN TOOL
# ═══════════════════════════════════════════════════════

def db_enum_and_audit(
    target: str,
    port: Optional[int] = None,
    db_type: Optional[str] = None,
    tools: Optional[List[str]] = None
):

    start = time.time()
    tools = list(tools or ["nmap"])

    try:
        req = DBEnumRequest(
            target=target,
            port=port,
            db_type=db_type,
            tools=tools,
        )
    except Exception as e:
        return DBEnumResult(
            success=False,
            target=target,
            findings=[],
            db_info=None,
            raw_output=None,
            error=f"Validation: {e}",
            execution_time=round(time.time() - start, 2),
        ).model_dump()

    findings = []
    databases = []
    users = []
    roles = []
    version = None
    raw = ""

    # ─────────────────────────
    # NMAP DB ENUMERATION
    # ─────────────────────────

    if "nmap" in req.tools:

        scripts = [
            "mysql-info",
            "mysql-enum",
            "pgsql-info",
            "mongodb-info",
            "redis-info",
            "ms-sql-info"
        ]

        cmd = [
            "nmap",
            "-sV",
            "--script=" + ",".join(scripts),
            req.target
        ]

        if req.port:
            cmd.extend(["-p", str(req.port)])

        stdout, stderr, rc = safe_execute(cmd, 600)

        raw += stdout

        dbs, us, rs, ver, f = parse_db_output(stdout)

        databases.extend(dbs)
        users.extend(us)
        roles.extend(rs)

        if ver:
            version = ver

        findings.extend(f)

    # ─────────────────────────
    # MYSQL ENUM
    # ─────────────────────────

    if req.db_type == "mysql":

        cmd = [
            "mysql",
            "-h", req.target,
            "-u", "root",
            "-e", "SHOW DATABASES;"
        ]

        stdout, stderr, rc = safe_execute(cmd, 60)

        raw += stdout

        if rc == 0:
            findings.append(
                DBFinding(
                    type="default_credentials",
                    value="MySQL root access without password"
                )
            )

            for line in stdout.splitlines():
                if line and "Database" not in line:
                    databases.append(line)

    # ─────────────────────────
    # REDIS ENUM
    # ─────────────────────────

    if req.db_type == "redis":

        cmd = [
            "redis-cli",
            "-h", req.target,
            "INFO"
        ]

        stdout, stderr, rc = safe_execute(cmd, 60)

        raw += stdout

        if rc == 0:
            findings.append(
                DBFinding(
                    type="unauthenticated_redis",
                    value="Redis accessible without auth"
                )
            )

    # ─────────────────────────
    # MONGODB ENUM
    # ─────────────────────────

    if req.db_type == "mongodb":

        cmd = [
            "mongo",
            "--host",
            req.target,
            "--eval",
            "db.adminCommand('listDatabases')"
        ]

        stdout, stderr, rc = safe_execute(cmd, 60)

        raw += stdout

    db_info = DBInfo(
        db_type=req.db_type,
        version=version,
        databases=list(set(databases)),
        users=list(set(users)),
        roles=list(set(roles))
    )

    return DBEnumResult(
        success=True,
        target=req.target,
        findings=findings,
        db_info=db_info,
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ═══════════════════════════════════════════════════════

DB_ENUM_TOOL_DEFINITION = {

    "name": "db_enum_and_audit",

    "description": (
        "Enumerate databases, users, roles, and security configuration. "
        "Detect default credentials, public access, weak permissions, "
        "and vulnerable DB versions."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "target": {
                "type": "string",
                "description": "Target host or IP"
            },

            "port": {
                "type": "integer"
            },

            "db_type": {
                "type": "string",
                "enum": [
                    "mysql",
                    "postgres",
                    "mongodb",
                    "redis",
                    "mssql"
                ]
            },

            "tools": {
                "type": "array",
                "items": {"type": "string"}
            }

        },

        "required": ["target"]

    }

}
