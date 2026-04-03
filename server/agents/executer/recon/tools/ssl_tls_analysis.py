import subprocess
import json
import re
import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
    OUTPUT_DIR = "output"
    TEMP_DIR = "tmp"
    
    @classmethod
    def get_project_dir(cls) -> Path:
        if cls._project_dir:
            return cls._project_dir
        
        env_dir = os.environ.get("AGENT_PROJECT_DIR")
        if env_dir and os.path.isdir(env_dir):
            cls._project_dir = Path(env_dir)
            return cls._project_dir
        
        current = Path(__file__).resolve().parent
        markers = ["pyproject.toml", "setup.py", ".git", "requirements.txt"]
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in markers):
                cls._project_dir = parent
                return cls._project_dir
                
        cls._project_dir = Path.cwd()
        return cls._project_dir
    
    @classmethod
    def get_temp_dir(cls) -> Path:
        path = cls.get_project_dir() / cls.TEMP_DIR
        path.mkdir(parents=True, exist_ok=True)
        return path


def _target_in_args(target: str, args: list[str]) -> bool:
    """Universal check for target duplication"""
    if not args: return False
    target_clean = target.strip().lower()
    target_stripped = re.sub(r"^\w+://", "", target_clean).split('/')[0]
    
    for i, arg in enumerate(args):
        arg_lower = arg.strip().lower()
        arg_stripped = re.sub(r"^\w+://", "", arg_lower).split('/')[0]
        
        if arg_lower == target_clean or arg_stripped == target_stripped: return True
        if target_stripped in arg_lower: return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int, str]:
    """Execute safely in project dir"""
    cwd = ProjectConfig.get_project_dir()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False, cwd=str(cwd))
        return res.stdout, res.stderr, res.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        return "", f"Timeout ({timeout}s)", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 2. SCHEMAS
# ══════════════════════════════════════════════════════════════

class SslTlsRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=10, le=3600)

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"testssl", "testssl.sh", "sslscan", "sslyze"}
        if v not in allowed: 
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        clean_v = re.sub(r"^\w+://", "", v.strip()).split('/')[0].split(':')[0]
        if clean_v in blocked:
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        for arg in v:
            for char in [";", "&&", "||", "|", "`", "$(", ">"]:
                if char in arg: raise ValueError(f"Dangerous char '{char}' in arg: {arg}")
        return v


class CertificateInfo(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    signature_algorithm: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    expired: bool = False
    hostname_matches: Optional[bool] = None


class ProtocolSupport(BaseModel):
    version: str
    supported: bool


class CipherSuite(BaseModel):
    protocol: str
    name: str
    key_size: Optional[int] = None
    strength: Optional[str] = None  # e.g. "strong", "weak", "insecure"


class Vulnerability(BaseModel):
    name: str
    severity: str
    description: Optional[str] = None


class SslTlsResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    
    certificate: Optional[CertificateInfo] = None
    protocols: list[ProtocolSupport] = []
    ciphers: list[CipherSuite] = []
    vulnerabilities: list[Vulnerability] = []
    hsts_enabled: Optional[bool] = None
    
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 3. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_testssl_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    """Build testssl.sh command, force JSON output"""
    # Use whichever alias the agent passed (testssl or testssl.sh)
    tool_bin = "testssl.sh" if "testssl.sh" in args or "testssl.sh" == args[0] else "testssl"
    if tool_bin in args: args.remove(tool_bin)
    
    cmd = [tool_bin]
    final_args = list(args)
    
    tmp_file = ProjectConfig.get_temp_dir() / f"testssl_{int(time.time())}.json"
    
    if not _has_flag(final_args, ["--jsonfile", "--json"]):
        final_args.extend(["--jsonfile", str(tmp_file)])
    
    if not _target_in_args(target, final_args):
        final_args.append(target)
        
    cmd.extend(final_args)
    return cmd, tmp_file


def _build_sslscan_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    """Build sslscan command, force XML output"""
    cmd = ["sslscan"]
    final_args = list(args)
    
    tmp_file = ProjectConfig.get_temp_dir() / f"sslscan_{int(time.time())}.xml"
    
    if not any(arg.startswith("--xml=") for arg in final_args):
        final_args.append(f"--xml={tmp_file}")
        
    if not _target_in_args(target, final_args):
        final_args.append(target)
        
    cmd.extend(final_args)
    return cmd, tmp_file


def _build_sslyze_cmd(args: list[str], target: str) -> tuple[list[str], Path]:
    """Build sslyze command, force JSON output"""
    cmd = ["sslyze"]
    final_args = list(args)
    
    tmp_file = ProjectConfig.get_temp_dir() / f"sslyze_{int(time.time())}.json"
    
    if not any(arg.startswith("--json_out=") for arg in final_args):
        final_args.append(f"--json_out={tmp_file}")
        
    if not _target_in_args(target, final_args):
        final_args.append(target)
        
    cmd.extend(final_args)
    return cmd, tmp_file


# ══════════════════════════════════════════════════════════════
# 4. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_testssl(tmp_file: Path) -> tuple[Optional[CertificateInfo], list, list, list, Optional[bool]]:
    """Parse testssl.sh JSON output"""
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    vulns = []
    hsts = None

    if not tmp_file.exists():
        return None, protocols, ciphers, vulns, hsts

    try:
        data = json.loads(tmp_file.read_text())
        if isinstance(data, list):
            for item in data:
                id_ = item.get("id", "")
                sev = item.get("severity", "")
                finding = item.get("finding", "")
                
                # 1. Protocols
                if id_ in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]:
                    supported = "offered" in finding.lower() or "not offered" not in finding.lower() and sev != "OK"
                    if "not offered" in finding.lower(): supported = False
                    protocols.append(ProtocolSupport(version=id_, supported=supported))
                
                # 2. Certificate Info
                elif id_ == "cert_subject": cert.subject = finding
                elif id_ == "cert_issuer": cert.issuer = finding
                elif id_ == "cert_signatureAlgorithm": cert.signature_algorithm = finding
                elif id_ == "cert_notBefore": cert.valid_from = finding
                elif id_ == "cert_notAfter": cert.valid_until = finding
                elif id_ == "cert_expirationStatus": 
                    cert.expired = "expired" in finding.lower()
                elif id_ == "cert_trust":
                    cert.hostname_matches = "ok" in finding.lower()
                
                # 3. Vulnerabilities
                elif id_ in ["heartbleed", "CCS", "ticketbleed", "ROBOT", "poodle", "logjam", "freak", "sweet32"]:
                    if sev not in ["OK", "INFO"]:
                        vulns.append(Vulnerability(name=id_, severity=sev, description=finding))
                
                # 4. HSTS
                elif id_ == "HSTS":
                    hsts = "offered" in finding.lower()
                    
                # 5. Ciphers (Sample a few if explicit cipher test run)
                elif id_.startswith("cipher_"):
                    ciphers.append(CipherSuite(
                        protocol="Unknown", name=finding.split()[0], strength=sev
                    ))

    except Exception:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return cert if cert.subject else None, protocols, ciphers, vulns, hsts


def parse_sslscan(tmp_file: Path) -> tuple[Optional[CertificateInfo], list, list, list, Optional[bool]]:
    """Parse sslscan XML output"""
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    
    if not tmp_file.exists():
        return None, protocols, [], [], None

    try:
        tree = ET.parse(tmp_file)
        root = tree.getroot()
        
        for host in root.findall(".//host"):
            # 1. Protocols and Ciphers
            for sslver in host.findall("sslversion"):
                proto_name = sslver.get("protocol", "Unknown")
                is_supported = False
                
                for cipher in sslver.findall("cipher"):
                    if cipher.get("status") == "accepted":
                        is_supported = True
                        ciphers.append(CipherSuite(
                            protocol=proto_name,
                            name=cipher.get("cipher", ""),
                            key_size=int(cipher.get("bits", 0)),
                            strength=cipher.get("strength", "unknown")
                        ))
                
                protocols.append(ProtocolSupport(version=proto_name, supported=is_supported))
            
            # 2. Certificate
            cert_node = host.find("certificate")
            if cert_node is not None:
                subj = cert_node.find("subject")
                iss = cert_node.find("issuer")
                sig = cert_node.find("signature-algorithm")
                start = cert_node.find("not-valid-before")
                end = cert_node.find("not-valid-after")
                exp = cert_node.find("expired")
                
                if subj is not None: cert.subject = subj.text
                if iss is not None: cert.issuer = iss.text
                if sig is not None: cert.signature_algorithm = sig.text
                if start is not None: cert.valid_from = start.text
                if end is not None: cert.valid_until = end.text
                if exp is not None: cert.expired = exp.text.lower() == "true"

    except ET.ParseError:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return cert if cert.subject else None, protocols, ciphers, [], None


def parse_sslyze(tmp_file: Path) -> tuple[Optional[CertificateInfo], list, list, list, Optional[bool]]:
    """Parse sslyze JSON output"""
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    vulns = []
    hsts = None

    if not tmp_file.exists():
        return None, protocols, ciphers, vulns, hsts

    try:
        data = json.loads(tmp_file.read_text())
        
        # sslyze JSON structure varies by version, making a best effort extraction
        # v5 structure: server_scan_results -> scan_result -> <plugins>
        results = data.get("server_scan_results", [])
        if results:
            res = results[0].get("scan_result", {})
            
            # Certs
            cert_info = res.get("certificate_info", {}).get("result", {})
            if cert_info:
                deployments = cert_info.get("certificate_deployments", [])
                if deployments:
                    leaf = deployments[0].get("received_certificate_chain", [])[0]
                    cert.subject = leaf.get("subject", {}).get("rfc4514_string")
                    cert.issuer = leaf.get("issuer", {}).get("rfc4514_string")
                    cert.signature_algorithm = leaf.get("signature_hash_algorithm")
                    cert.valid_from = leaf.get("not_valid_before")
                    cert.valid_until = leaf.get("not_valid_after")

            # Protocols / Ciphers
            for proto in ["ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites", "tls_1_3_cipher_suites"]:
                proto_res = res.get(proto, {}).get("result", {})
                if proto_res:
                    is_supported = proto_res.get("is_tls_version_supported", False)
                    name = proto.replace("_cipher_suites", "").replace("_", ".").upper()
                    protocols.append(ProtocolSupport(version=name, supported=is_supported))
                    
                    for c in proto_res.get("accepted_cipher_suites", []):
                        suite = c.get("cipher_suite", {})
                        ciphers.append(CipherSuite(
                            protocol=name,
                            name=suite.get("name", "Unknown"),
                            key_size=suite.get("key_size", 0)
                        ))

            # Vulns
            heartbleed = res.get("heartbleed", {}).get("result", {}).get("is_vulnerable_to_heartbleed")
            if heartbleed: vulns.append(Vulnerability(name="Heartbleed", severity="HIGH"))
            
            robot = res.get("robot", {}).get("result", {}).get("robot_result")
            if robot and "VULNERABLE" in robot: vulns.append(Vulnerability(name="ROBOT", severity="HIGH"))

    except Exception:
        pass
    finally:
        try: tmp_file.unlink()
        except OSError: pass

    return cert if cert.subject else None, protocols, ciphers, vulns, hsts


# ══════════════════════════════════════════════════════════════
# 5. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def ssl_tls_analysis(tool: str, target: str, args: list[str] = []) -> dict:
    """
    🔧 Agent Tool: SSL/TLS Analysis
    
    Inspects a target's SSL/TLS configuration to extract certificate info, 
    supported protocols (TLSv1.2, TLSv1.3, etc), cipher suites, and vulnerabilities (Heartbleed, etc).
    """
    start = time.time()
    
    # ── VALIDATE ──
    try:
        req = SslTlsRequest(tool=tool, target=target, args=args)
    except Exception as e:
        return SslTlsResult(
            success=False, tool=tool, target=target, command="", error=f"Validation: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    tmp_file = None
    if tool in ["testssl", "testssl.sh"]:
        cmd, tmp_file = _build_testssl_cmd(args, target)
    elif tool == "sslscan":
        cmd, tmp_file = _build_sslscan_cmd(args, target)
    elif tool == "sslyze":
        cmd, tmp_file = _build_sslyze_cmd(args, target)

    # ── EXECUTE ──
    command_str = " ".join(cmd)
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    
    # ── PARSE ──
    cert = None
    protocols = []
    ciphers = []
    vulns = []
    hsts = None

    if tool in ["testssl", "testssl.sh"]:
        cert, protocols, ciphers, vulns, hsts = parse_testssl(tmp_file)
    elif tool == "sslscan":
        cert, protocols, ciphers, vulns, hsts = parse_sslscan(tmp_file)
    elif tool == "sslyze":
        cert, protocols, ciphers, vulns, hsts = parse_sslyze(tmp_file)

    # Check if we parsed anything useful
    has_data = cert is not None or len(protocols) > 0 or len(ciphers) > 0

    # ── RETURN ──
    return SslTlsResult(
        success=rc == 0 or has_data,
        tool=tool,
        target=target,
        command=command_str,
        working_dir=cwd,
        certificate=cert,
        protocols=protocols,
        ciphers=ciphers,
        vulnerabilities=vulns,
        hsts_enabled=hsts,
        raw_output=(stdout or stderr)[:5000] if not has_data else None, # Give LLM raw output if parsing failed
        error=stderr if rc != 0 and not has_data else None,
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 6. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

SSL_TLS_TOOL_DEFINITION = {
    "name": "ssl_tls_analysis",
    "description": (
        "Analyze a target's SSL/TLS configuration. Extracts certificate validity, "
        "supported protocols (TLSv1.2, SSLv3, etc.), cipher suites, HSTS status, and vulns (Heartbleed, POODLE). "
        "Supports testssl.sh (most thorough), sslscan (fast C-based), and sslyze (Python)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["testssl.sh", "sslscan", "sslyze"],
                "description": "testssl.sh (thorough, slow) | sslscan (fast, reliable) | sslyze"
            },
            "target": {
                "type": "string",
                "description": "Target domain or IP:PORT (e.g. 'example.com' or '10.10.10.1:8443')"
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Raw args. Example: testssl.sh: ['-U', '-S'] | sslscan: ['--no-failed']"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 7. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 60)
    print("SSL/TLS ANALYSIS — EXAMPLES")
    print("=" * 60)
    
    # ─────────────────────────────
    # Example 1: SSLScan (Fast and solid for protocols/ciphers)
    # ─────────────────────────────
    r1 = ssl_tls_analysis(
        tool="sslscan",
        target="hackerone.com",
        args=["--no-failed"]
    )
    print("\n=== SSLSCAN ===")
    print(f"Command: {r1['command']}")
    if r1['certificate']:
        print(f"Cert Subject: {r1['certificate']['subject']}")
        print(f"Cert Issuer:  {r1['certificate']['issuer']}")
        print(f"Expired:      {r1['certificate']['expired']}")
    print("Protocols:")
    for p in r1['protocols']:
        print(f"  - {p['version']}: {'Supported' if p['supported'] else 'Not Supported'}")

    # ─────────────────────────────
    # Example 2: TestSSL.sh (Deep vulnerability check)
    # ─────────────────────────────
    r2 = ssl_tls_analysis(
        tool="testssl.sh",
        target="hackerone.com",
        args=["--fast", "-U"]  # fast mode, checking vulnerabilities
    )
    print("\n=== TESTSSL.SH ===")
    print(f"Command: {r2['command']}")
    print("Vulnerabilities Found:")
    if not r2['vulnerabilities']:
        print("  None detected.")
    for v in r2['vulnerabilities']:
        print(f"  - {v['name']} (Severity: {v['severity']})")
        
    print(f"HSTS Enabled: {r2['hsts_enabled']}")

    # ─────────────────────────────
    # Example 3: Full JSON Payload
    # ─────────────────────────────
    print("\n=== FULL JSON PAYLOAD (SSLScan) ===")
    print(json.dumps(r1, indent=2))