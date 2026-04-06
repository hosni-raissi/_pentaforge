import subprocess
import json
import re
import time
import os
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SASTScanRequest(BaseModel):
    tool: str
    target: str
    language: str = "auto"
    scan_type: str = "security"
    args: list[str] = []
    timeout: int = Field(default=1800, ge=30, le=7200)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"semgrep", "bandit", "gosec", "brakeman", "eslint-security"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        for d in dangerous:
            if d in v:
                raise ValueError(f"Dangerous character '{d}' in target")

        return v

    @validator("language")
    def validate_language(cls, v):
        allowed = {
            "auto", "python", "javascript", "typescript",
            "go", "ruby", "java", "php", "c", "csharp"
        }
        if v not in allowed:
            raise ValueError(f"Language '{v}' not allowed. Use: {allowed}")
        return v

    @validator("scan_type")
    def validate_scan_type(cls, v):
        allowed = {
            "security", "sqli", "xss", "rce",
            "deserialization", "secrets", "all"
        }
        if v not in allowed:
            raise ValueError(f"scan_type '{v}' not allowed. Use: {allowed}")
        return v

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", ">", "<", "'", '"']
        blocked_flags = ["-o", "--output", "--out", "--report", "--json-output"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked file output flag: {arg}")

        return v


class CodeFinding(BaseModel):
    tool: str
    rule_id: Optional[str] = None
    title: str
    category: str = "security"
    severity: str = "medium"    # critical, high, medium, low, info
    confidence: Optional[str] = None

    file_path: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    column: Optional[int] = None

    code_snippet: Optional[str] = None
    message: Optional[str] = None
    cwe: list[str] = []
    owasp: list[str] = []
    references: list[str] = []

    recommendation: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


class SASTScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    language: str
    scan_type: str
    command: str
    total_findings: int = 0
    severity_summary: dict[str, int] = {}
    category_summary: dict[str, int] = {}
    findings: list[CodeFinding] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. SAFE EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 1800, cwd: Optional[str] = None) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 3. HELPERS
# ══════════════════════════════════════════════════════════════

def detect_language(target: str) -> str:
    if os.path.isfile(target):
        ext = os.path.splitext(target)[1].lower()
        return {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".rb": "ruby",
            ".java": "java",
            ".php": "php",
            ".c": "c",
            ".cs": "csharp",
        }.get(ext, "auto")

    if os.path.isdir(target):
        exts = set()
        try:
            for root, _, files in os.walk(target):
                for f in files[:2000]:
                    exts.add(os.path.splitext(f)[1].lower())
        except Exception:
            return "auto"

        if ".py" in exts:
            return "python"
        if ".js" in exts:
            return "javascript"
        if ".ts" in exts:
            return "typescript"
        if ".go" in exts:
            return "go"
        if ".rb" in exts:
            return "ruby"
        if ".java" in exts:
            return "java"
        if ".php" in exts:
            return "php"
        if ".c" in exts:
            return "c"
        if ".cs" in exts:
            return "csharp"

    return "auto"


def normalize_severity(sev: Optional[str]) -> str:
    if not sev:
        return "medium"
    s = str(sev).lower().strip()
    mapping = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "info": "low",
        "note": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    return mapping.get(s, s if s in {"critical", "high", "medium", "low", "info"} else "medium")


def categorize_title(rule_id: Optional[str], title: Optional[str], message: Optional[str]) -> str:
    text = f"{rule_id or ''} {title or ''} {message or ''}".lower()

    if any(x in text for x in ["sql", "injection", "sqli"]):
        return "sqli"
    if any(x in text for x in ["xss", "cross-site scripting"]):
        return "xss"
    if any(x in text for x in ["command injection", "subprocess", "os.system", "rce", "exec"]):
        return "rce"
    if any(x in text for x in ["deserialize", "deserialization", "pickle", "yaml.load", "marshal"]):
        return "deserialization"
    if any(x in text for x in ["secret", "password", "token", "apikey", "api key"]):
        return "secrets"
    return "security"


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_semgrep_json(stdout: str) -> list[CodeFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    for item in data.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}

        cwe = metadata.get("cwe")
        if isinstance(cwe, str):
            cwe = [cwe]
        elif not isinstance(cwe, list):
            cwe = []

        owasp = metadata.get("owasp")
        if isinstance(owasp, str):
            owasp = [owasp]
        elif not isinstance(owasp, list):
            owasp = []

        title = extra.get("message") or item.get("check_id") or "Semgrep finding"
        category = categorize_title(item.get("check_id"), title, extra.get("message"))

        findings.append(CodeFinding(
            tool="semgrep",
            rule_id=item.get("check_id"),
            title=title,
            category=category,
            severity=normalize_severity(extra.get("severity")),
            confidence=metadata.get("confidence"),
            file_path=item.get("path"),
            line=start.get("line"),
            end_line=end.get("line"),
            column=start.get("col"),
            code_snippet=extra.get("lines"),
            message=extra.get("message"),
            cwe=[str(x) for x in cwe],
            owasp=[str(x) for x in owasp],
            references=metadata.get("references", [])[:20] if isinstance(metadata.get("references"), list) else [],
            recommendation=metadata.get("fix"),
            extra={
                "technology": metadata.get("technology"),
                "impact": metadata.get("impact"),
                "likelihood": metadata.get("likelihood"),
            }
        ))

    return findings


def parse_bandit_json(stdout: str) -> list[CodeFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    for item in data.get("results", []) or []:
        title = item.get("issue_text") or item.get("test_name") or "Bandit finding"
        category = categorize_title(item.get("test_id"), title, item.get("issue_text"))

        findings.append(CodeFinding(
            tool="bandit",
            rule_id=item.get("test_id"),
            title=title,
            category=category,
            severity=normalize_severity(item.get("issue_severity")),
            confidence=(item.get("issue_confidence") or "").lower() if item.get("issue_confidence") else None,
            file_path=item.get("filename"),
            line=item.get("line_number"),
            end_line=item.get("line_range", [None])[-1] if item.get("line_range") else None,
            code_snippet=item.get("code"),
            message=item.get("issue_text"),
            cwe=[f"CWE-{item.get('issue_cwe', {}).get('id')}"] if isinstance(item.get("issue_cwe"), dict) and item.get("issue_cwe", {}).get("id") else [],
            references=[item.get("more_info")] if item.get("more_info") else [],
            recommendation="Review the insecure Python pattern and replace it with a safe equivalent",
            extra={
                "test_name": item.get("test_name"),
            }
        ))

    return findings


def parse_gosec_json(stdout: str) -> list[CodeFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    items = data.get("Issues", []) or data.get("issues", []) or []
    for item in items:
        title = item.get("details") or item.get("rule_id") or "Gosec finding"
        category = categorize_title(item.get("rule_id"), title, item.get("details"))

        references = []
        if item.get("cwe"):
            references.append(str(item.get("cwe")))

        findings.append(CodeFinding(
            tool="gosec",
            rule_id=item.get("rule_id"),
            title=title,
            category=category,
            severity=normalize_severity(item.get("severity")),
            confidence=(item.get("confidence") or "").lower() if item.get("confidence") else None,
            file_path=item.get("file"),
            line=item.get("line"),
            end_line=item.get("line"),
            column=item.get("column"),
            code_snippet=item.get("code"),
            message=item.get("details"),
            cwe=[str(item.get("cwe"))] if item.get("cwe") else [],
            references=references,
            recommendation="Refactor the Go code to remove the insecure pattern identified by gosec",
        ))

    return findings


def parse_brakeman_json(stdout: str) -> list[CodeFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    warnings = data.get("warnings", []) or []
    for item in warnings:
        title = item.get("warning_type") or item.get("message") or "Brakeman finding"
        category = categorize_title(item.get("check_name"), title, item.get("message"))

        confidence = item.get("confidence")
        if isinstance(confidence, int):
            confidence_map = {0: "high", 1: "medium", 2: "low"}
            confidence = confidence_map.get(confidence, None)

        findings.append(CodeFinding(
            tool="brakeman",
            rule_id=item.get("check_name"),
            title=title,
            category=category,
            severity=normalize_severity(item.get("warning_code") and "medium" or "medium"),
            confidence=confidence,
            file_path=item.get("file"),
            line=item.get("line"),
            end_line=item.get("line"),
            code_snippet=item.get("code"),
            message=item.get("message"),
            cwe=[str(x) for x in item.get("cwe_id", [])] if isinstance(item.get("cwe_id"), list) else ([f"CWE-{item.get('cwe_id')}"] if item.get("cwe_id") else []),
            references=item.get("link", []) if isinstance(item.get("link"), list) else ([item.get("link")] if item.get("link") else []),
            recommendation="Apply Rails-specific input validation, escaping, or safe query APIs",
            extra={
                "user_input": item.get("user_input"),
                "confidence": confidence,
            }
        ))

    return findings


def parse_eslint_security_json(stdout: str) -> list[CodeFinding]:
    findings = []

    try:
        data = json.loads(stdout)
    except Exception:
        return findings

    if not isinstance(data, list):
        return findings

    for file_result in data:
        file_path = file_result.get("filePath")
        for msg in file_result.get("messages", []) or []:
            title = msg.get("message") or msg.get("ruleId") or "ESLint security finding"
            category = categorize_title(msg.get("ruleId"), title, msg.get("message"))

            severity = "medium"
            if msg.get("severity") == 2:
                severity = "high"
            elif msg.get("severity") == 1:
                severity = "medium"

            findings.append(CodeFinding(
                tool="eslint-security",
                rule_id=msg.get("ruleId"),
                title=title,
                category=category,
                severity=severity,
                confidence=None,
                file_path=file_path,
                line=msg.get("line"),
                end_line=msg.get("endLine"),
                column=msg.get("column"),
                message=msg.get("message"),
                recommendation="Refactor the JavaScript code to remove insecure usage patterns",
                extra={
                    "node_type": msg.get("nodeType"),
                }
            ))

    return findings


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def sast_scan(tool: str, target: str, language: str = "auto", scan_type: str = "security", args: list[str] = []) -> dict:
    """
    🧪 Agent Tool: Static Application Security Testing (SAST)

    Capabilities:
      ┌─────────────────────────────────────────────────────────────┐
      │  SQLi                 unsafe query construction             │
      │  XSS                  unsanitized rendering/output          │
      │  RCE                  dangerous exec/system patterns        │
      │  DESERIALIZATION      insecure object parsing/loading       │
      │  CODE SECURITY        language-specific static analysis     │
      │  MULTI-TOOL SUPPORT   semgrep, bandit, gosec, etc.         │
      └─────────────────────────────────────────────────────────────┘

    Args:
        tool:      "semgrep" | "bandit" | "gosec" | "brakeman" | "eslint-security"
        target:    source file or project directory
        language:  "auto" | "python" | "javascript" | "typescript" | "go" | "ruby" | ...
        scan_type: "security" | "sqli" | "xss" | "rce" | "deserialization" | "secrets" | "all"
        args:      raw tool args — agent decides

    Examples:
        sast_scan("semgrep", "/src/app", "auto", "security", ["--config=auto"])
        sast_scan("bandit", "/src/pythonapp", "python", "security", ["-r"])
        sast_scan("gosec", "/src/goapp", "go", "security", ["-fmt=json"])
        sast_scan("brakeman", "/src/railsapp", "ruby", "security", [])
        sast_scan("eslint-security", "/src/nodeapp", "javascript", "security", [])
    """

    start = time.time()

    try:
        req = SASTScanRequest(
            tool=tool,
            target=target,
            language=language,
            scan_type=scan_type,
            args=args,
        )
    except Exception as e:
        return SASTScanResult(
            success=False,
            tool=tool,
            target=target,
            language=language,
            scan_type=scan_type,
            command="",
            error=f"Validation: {e}",
        ).model_dump()

    resolved_language = req.language if req.language != "auto" else detect_language(req.target)
    cwd = req.target if os.path.isdir(req.target) else os.path.dirname(req.target) or None

    # ══════════════════════════════
    # BUILD COMMAND
    # ══════════════════════════════
    if req.tool == "semgrep":
        cmd = ["semgrep", "--json"]
        if "--config" not in " ".join(req.args):
            cmd.append("--config=auto")
        cmd.append(req.target)
        cmd.extend(list(req.args))

    elif req.tool == "bandit":
        cmd = ["bandit", "-f", "json"]
        if os.path.isdir(req.target) and "-r" not in req.args:
            cmd.append("-r")
        cmd.append(req.target)
        cmd.extend(list(req.args))

    elif req.tool == "gosec":
        cmd = ["gosec", "-fmt", "json"]
        cmd.extend(list(req.args))
        cmd.append(req.target)

    elif req.tool == "brakeman":
        cmd = ["brakeman", "-f", "json", "-p", req.target]
        cmd.extend(list(req.args))

    elif req.tool == "eslint-security":
        cmd = ["eslint", "-f", "json", req.target]
        cmd.extend(list(req.args))

    else:
        return SASTScanResult(
            success=False,
            tool=tool,
            target=target,
            language=resolved_language,
            scan_type=scan_type,
            command="",
            error=f"Unknown tool: {tool}",
        ).model_dump()

    command_str = " ".join(cmd)

    # ══════════════════════════════
    # EXECUTE
    # ══════════════════════════════
    stdout, stderr, rc = safe_execute(cmd, timeout=req.timeout, cwd=cwd)

    # Many SAST tools return non-zero when findings exist, so parse first.

    # ══════════════════════════════
    # PARSE
    # ══════════════════════════════
    findings: list[CodeFinding] = []

    if req.tool == "semgrep":
        findings = parse_semgrep_json(stdout)
    elif req.tool == "bandit":
        findings = parse_bandit_json(stdout)
    elif req.tool == "gosec":
        findings = parse_gosec_json(stdout)
    elif req.tool == "brakeman":
        findings = parse_brakeman_json(stdout)
    elif req.tool == "eslint-security":
        findings = parse_eslint_security_json(stdout)

    # Optional filtering by requested scan_type
    if req.scan_type != "all" and req.scan_type != "security":
        findings = [f for f in findings if f.category == req.scan_type]

    severity_summary: dict[str, int] = {}
    category_summary: dict[str, int] = {}

    for f in findings:
        severity_summary[f.severity] = severity_summary.get(f.severity, 0) + 1
        category_summary[f.category] = category_summary.get(f.category, 0) + 1

    return SASTScanResult(
        success=(rc == 0 or len(findings) > 0),
        tool=req.tool,
        target=req.target,
        language=resolved_language,
        scan_type=req.scan_type,
        command=command_str,
        total_findings=len(findings),
        severity_summary=severity_summary,
        category_summary=category_summary,
        findings=findings,
        raw_output=(stdout or stderr)[:12000],
        error=stderr[:4000] if rc != 0 and not findings else None,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION
# ══════════════════════════════════════════════════════════════

SAST_SCAN_TOOL_DEFINITION = {
    "name": "sast_scan",
    "description": (
        "Run Static Application Security Testing (SAST) against source code to find SQL injection, "
        "XSS, RCE, insecure deserialization, and other insecure coding patterns using Semgrep, "
        "Bandit, Gosec, Brakeman, or ESLint security rules."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["semgrep", "bandit", "gosec", "brakeman", "eslint-security"],
                "description": (
                    "semgrep = multi-language SAST | "
                    "bandit = Python | "
                    "gosec = Go | "
                    "brakeman = Ruby on Rails | "
                    "eslint-security = JavaScript security linting"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "Source file or project directory. "
                    "Examples: '/src/app', '/src/app/main.py', '/src/railsapp'"
                )
            },
            "language": {
                "type": "string",
                "enum": ["auto", "python", "javascript", "typescript", "go", "ruby", "java", "php", "c", "csharp"],
                "default": "auto",
                "description": "Programming language"
            },
            "scan_type": {
                "type": "string",
                "enum": ["security", "sqli", "xss", "rce", "deserialization", "secrets", "all"],
                "default": "security",
                "description": "Type of security issue focus"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "Semgrep: ['--config=auto'] or ['--config', 'p/security-audit']\n"
                    "Bandit: ['-r']\n"
                    "Gosec: ['-nosec=true']\n"
                    "Brakeman: ['--no-exit-on-warn']\n"
                    "ESLint: ['--ext', '.js,.ts']"
                )
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Semgrep full scan
    # ─────────────────────────────
    r = sast_scan(
        tool="semgrep",
        target="/src/app",
        language="auto",
        scan_type="security",
        args=["--config=auto"]
    )
    print("=== SEMGREP ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Python Bandit
    # ─────────────────────────────
    r = sast_scan(
        tool="bandit",
        target="/src/pythonapp",
        language="python",
        scan_type="security",
        args=["-r"]
    )
    print("=== BANDIT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Go SAST
    # ─────────────────────────────
    r = sast_scan(
        tool="gosec",
        target="/src/goapp",
        language="go",
        scan_type="security",
        args=[]
    )
    print("=== GOSEC ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Rails Brakeman
    # ─────────────────────────────
    r = sast_scan(
        tool="brakeman",
        target="/src/railsapp",
        language="ruby",
        scan_type="security",
        args=[]
    )
    print("=== BRAKEMAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. JS security linting
    # ─────────────────────────────
    r = sast_scan(
        tool="eslint-security",
        target="/src/nodeapp",
        language="javascript",
        scan_type="security",
        args=["--ext", ".js,.ts"]
    )
    print("=== ESLINT SECURITY ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. SQLi-focused semgrep filter
    # ─────────────────────────────
    r = sast_scan(
        tool="semgrep",
        target="/src/app",
        language="auto",
        scan_type="sqli",
        args=["--config=auto"]
    )
    print("=== SQLI FOCUS ===")
    print(json.dumps(r, indent=2))