#/+
import subprocess
import json
import re
import os
import time
import logging
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Any
from functools import lru_cache
from pydantic import BaseModel, Field, field_validator
from server.agents.executer.recon.config import is_blocked_host


# ══════════════════════════════════════════════════════════════
# 1. LOGGING CONFIGURATION
# ══════════════════════════════════════════════════════════════

logger = logging.getLogger("ssl_tls_analysis")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(handler)


# ══════════════════════════════════════════════════════════════
# 2. RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm"""
    
    def __init__(self, calls_per_second: float = 2.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self.lock = threading.Lock()
    
    def acquire(self):
        """Block until rate limit allows next call"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call = time.time()
    
    def reset(self):
        with self.lock:
            self.last_call = 0.0


# Global rate limiter (SSL scans are heavy, limit to 2/sec)
SSL_RATE_LIMITER = RateLimiter(calls_per_second=2.0)


# ══════════════════════════════════════════════════════════════
# 3. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Project directory resolver (no result file writes)."""
    _project_dir: Optional[Path] = None
    
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
    
def _target_in_args(target: str, args: list[str]) -> bool:
    """Universal check for target duplication"""
    if not args:
        return False
    target_clean = target.strip().lower()
    target_stripped = re.sub(r"^\w+://", "", target_clean).split('/')[0]
    
    for arg in args:
        arg_lower = arg.strip().lower()
        arg_stripped = re.sub(r"^\w+://", "", arg_lower).split('/')[0]
        
        if arg_lower == target_clean or arg_stripped == target_stripped:
            return True
        if target_stripped in arg_lower:
            return True
    return False


def _has_flag(args: list[str], flags: list[str]) -> bool:
    return any(arg in args for arg in flags)


def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int, str]:
    """Execute command safely in project directory"""
    cwd = ProjectConfig.get_project_dir()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            cwd=str(cwd)
        )
        return result.stdout, result.stderr, result.returncode, str(cwd)
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1, str(cwd)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1, str(cwd)
    except Exception as e:
        return "", str(e), -1, str(cwd)


# ══════════════════════════════════════════════════════════════
# 4. SECURITY CONSTANTS
# ══════════════════════════════════════════════════════════════

# Comprehensive vulnerability detection
VULNERABILITY_IDS = {
    # Critical/High severity
    "heartbleed", "CCS", "ticketbleed", "ROBOT", "poodle", "poodle_ssl",
    "logjam", "freak", "sweet32", "DROWN", "BEAST", "CRIME", "BREACH",
    "SLOTH", "lucky13", "rc4", "RC4",
    
    # Renegotiation
    "secure_renego", "secure_client_renego", "RENEGOTIATION",
    
    # Protocol-specific
    "fallback_SCSV", "TLS_FALLBACK_SCSV",
    
    # Cipher-related
    "NULL", "aNULL", "EXPORT", "DES", "3DES", "IDEA",
    
    # Certificate-related
    "cert_chain_incomplete", "cert_expired", "cert_revoked",
    "cert_selfsigned", "cert_sha1",
}

# Insecure cipher patterns
INSECURE_CIPHER_PATTERNS = [
    r"NULL",
    r"ANON",
    r"EXPORT",
    r"DES-CBC-",
    r"RC4",
    r"RC2",
    r"MD5",
    r"ADH-",
    r"AECDH-",
]

# Weak cipher patterns
WEAK_CIPHER_PATTERNS = [
    r"3DES",
    r"IDEA",
    r"SEED",
    r"CAMELLIA.*CBC",
    r"AES.*CBC(?!.*SHA256|.*SHA384)",
]

# Strong cipher patterns
STRONG_CIPHER_PATTERNS = [
    r"AES.*GCM",
    r"CHACHA20",
    r"POLY1305",
    r"ECDHE.*AES",
    r"DHE.*AES.*GCM",
]

# Deprecated signature algorithms
DEPRECATED_SIGNATURE_ALGORITHMS = [
    "sha1WithRSAEncryption",
    "sha1WithRSA",
    "md5WithRSAEncryption",
    "md5WithRSA",
    "md2WithRSAEncryption",
]


# ══════════════════════════════════════════════════════════════
# 5. SCHEMAS (Enhanced Pydantic Models)
# ══════════════════════════════════════════════════════════════

class SslTlsRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=10, le=3600)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"testssl", "sslscan", "sslyze"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        clean_v = re.sub(r"^\w+://", "", v.strip()).split('/')[0].split(':')[0]
        if is_blocked_host(clean_v):
            raise ValueError(f"Target '{v}' is blocked")
        return v.strip()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        # Enhanced dangerous character list (includes newlines for injection)
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">", "\n", "\r", "'", '"']
        # Blocked flags that might leak info or write files
        blocked_flags = ["--debug", "-d", "--verbose", "-v", "--log", "--outfile"]
        
        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{repr(char)}' in arg: {arg}")
            
            arg_lower = arg.lower().strip()
            for flag in blocked_flags:
                if arg_lower.startswith(flag):
                    raise ValueError(f"Blocked flag: {flag}")
        return v


class CertificateInfo(BaseModel):
    """Enhanced certificate information"""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    signature_algorithm: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    expired: bool = False
    days_until_expiry: Optional[int] = None
    hostname_matches: Optional[bool] = None
    
    # Enhanced fields
    self_signed: bool = False
    key_algorithm: Optional[str] = None      # RSA, ECDSA, Ed25519
    key_size: Optional[int] = None           # 2048, 4096, 256 (for ECDSA)
    sha1_signature: bool = False             # Deprecated
    sha256_fingerprint: Optional[str] = None
    revoked: Optional[bool] = None           # OCSP/CRL check
    chain_valid: Optional[bool] = None
    chain_length: Optional[int] = None
    sans: list[str] = []                     # Subject Alternative Names
    is_wildcard: bool = False
    is_ev: bool = False                      # Extended Validation
    ct_sct_present: bool = False             # Certificate Transparency


class ProtocolSupport(BaseModel):
    """Protocol support with TLS 1.3 features"""
    version: str
    supported: bool
    server_preference: Optional[int] = None  # Order (1 = most preferred)
    
    # TLS 1.3 specific
    zero_rtt_enabled: Optional[bool] = None
    early_data: Optional[bool] = None


class CipherSuite(BaseModel):
    """Enhanced cipher suite with strength classification"""
    protocol: str
    name: str
    key_size: Optional[int] = None
    strength: str = "unknown"  # insecure, weak, acceptable, strong
    key_exchange: Optional[str] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    mac: Optional[str] = None
    pfs: bool = False  # Perfect Forward Secrecy


class Vulnerability(BaseModel):
    """Vulnerability with detailed info"""
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cve: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None


class SessionResumption(BaseModel):
    """Session resumption analysis"""
    session_id_supported: bool = False
    session_ticket_supported: bool = False
    session_ticket_lifetime: Optional[int] = None


class OCSPInfo(BaseModel):
    """OCSP stapling information"""
    stapling_enabled: bool = False
    response_status: Optional[str] = None  # "valid", "invalid", "revoked", "unknown"
    responder_url: Optional[str] = None
    must_staple: bool = False


class SslTlsResult(BaseModel):
    """Comprehensive SSL/TLS analysis result"""
    success: bool
    tool: str
    target: str
    command: str
    working_dir: str = ""
    
    # Core results
    certificate: Optional[CertificateInfo] = None
    protocols: list[ProtocolSupport] = []
    ciphers: list[CipherSuite] = []
    vulnerabilities: list[Vulnerability] = []
    
    # Enhanced results
    hsts_enabled: Optional[bool] = None
    hsts_max_age: Optional[int] = None
    hsts_preload: bool = False
    hsts_include_subdomains: bool = False
    
    ocsp: Optional[OCSPInfo] = None
    session_resumption: Optional[SessionResumption] = None
    
    # Summary stats
    insecure_cipher_count: int = 0
    weak_cipher_count: int = 0
    strong_cipher_count: int = 0
    
    # Meta
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    
    # Overall grade (A-F)
    grade: Optional[str] = None
    grade_reasons: list[str] = []


# ══════════════════════════════════════════════════════════════
# 6. CIPHER STRENGTH CLASSIFICATION
# ══════════════════════════════════════════════════════════════

def classify_cipher_strength(cipher_name: str, key_size: Optional[int] = None) -> str:
    """
    Classify cipher strength based on NIST/OWASP/Mozilla guidelines.
    
    Returns: "insecure", "weak", "acceptable", "strong"
    """
    if not cipher_name:
        return "unknown"
    
    name_upper = cipher_name.upper()
    
    # INSECURE - Must be disabled immediately
    for pattern in INSECURE_CIPHER_PATTERNS:
        if re.search(pattern, name_upper):
            return "insecure"
    
    # Check key size for insecurity
    if key_size is not None:
        if key_size < 112:  # NIST minimum
            return "insecure"
        if key_size < 128:
            return "weak"
    
    # WEAK - Should be disabled
    for pattern in WEAK_CIPHER_PATTERNS:
        if re.search(pattern, name_upper):
            return "weak"
    
    # STRONG - Recommended
    for pattern in STRONG_CIPHER_PATTERNS:
        if re.search(pattern, name_upper):
            return "strong"
    
    # ACCEPTABLE - Modern but not optimal
    if "AES" in name_upper and (key_size is None or key_size >= 128):
        return "acceptable"
    
    if "CHACHA" in name_upper or "POLY1305" in name_upper:
        return "strong"
    
    return "acceptable"  # Default for unrecognized modern ciphers


def has_perfect_forward_secrecy(cipher_name: str) -> bool:
    """Check if cipher suite supports Perfect Forward Secrecy"""
    if not cipher_name:
        return False
    name_upper = cipher_name.upper()
    # ECDHE and DHE provide PFS
    return "ECDHE" in name_upper or "DHE" in name_upper or "EECDH" in name_upper


def parse_cipher_components(cipher_name: str) -> dict:
    """Parse cipher suite into components"""
    components = {
        "key_exchange": None,
        "authentication": None,
        "encryption": None,
        "mac": None
    }
    
    if not cipher_name:
        return components
    
    # Common patterns
    if "ECDHE" in cipher_name:
        components["key_exchange"] = "ECDHE"
    elif "DHE" in cipher_name or "EDH" in cipher_name:
        components["key_exchange"] = "DHE"
    elif "ECDH" in cipher_name:
        components["key_exchange"] = "ECDH"
    elif "RSA" in cipher_name:
        components["key_exchange"] = "RSA"
    
    if "RSA" in cipher_name:
        components["authentication"] = "RSA"
    elif "ECDSA" in cipher_name:
        components["authentication"] = "ECDSA"
    elif "DSS" in cipher_name:
        components["authentication"] = "DSS"
    
    if "AES256" in cipher_name or "AES-256" in cipher_name:
        components["encryption"] = "AES-256"
    elif "AES128" in cipher_name or "AES-128" in cipher_name:
        components["encryption"] = "AES-128"
    elif "CHACHA20" in cipher_name:
        components["encryption"] = "ChaCha20"
    elif "3DES" in cipher_name:
        components["encryption"] = "3DES"
    elif "DES" in cipher_name:
        components["encryption"] = "DES"
    elif "RC4" in cipher_name:
        components["encryption"] = "RC4"
    
    if "SHA384" in cipher_name:
        components["mac"] = "SHA384"
    elif "SHA256" in cipher_name:
        components["mac"] = "SHA256"
    elif "SHA" in cipher_name:
        components["mac"] = "SHA1"
    elif "MD5" in cipher_name:
        components["mac"] = "MD5"
    elif "POLY1305" in cipher_name:
        components["mac"] = "Poly1305"
    
    return components


# ══════════════════════════════════════════════════════════════
# 7. GRADING SYSTEM
# ══════════════════════════════════════════════════════════════

def calculate_grade(result: dict) -> tuple[str, list[str]]:
    """
    Calculate overall SSL/TLS grade (A+ to F) based on configuration.
    
    Returns: (grade, list of reasons)
    """
    score = 100
    reasons = []
    
    cert = result.get("certificate")
    protocols = result.get("protocols", [])
    ciphers = result.get("ciphers", [])
    vulns = result.get("vulnerabilities", [])
    
    # ═══════════════════════════════════════════
    # Certificate Issues (-5 to -50 points)
    # ═══════════════════════════════════════════
    if cert:
        if cert.get("expired"):
            score -= 50
            reasons.append("Certificate expired")
        
        if cert.get("self_signed"):
            score -= 30
            reasons.append("Self-signed certificate")
        
        if cert.get("sha1_signature"):
            score -= 20
            reasons.append("SHA-1 signature (deprecated)")
        
        if cert.get("hostname_matches") is False:
            score -= 30
            reasons.append("Hostname mismatch")
        
        key_size = cert.get("key_size")
        if key_size:
            if key_size < 2048:
                score -= 20
                reasons.append(f"Weak key size ({key_size} bits)")
            elif key_size < 1024:
                score -= 40
                reasons.append(f"Critically weak key ({key_size} bits)")
        
        if cert.get("chain_valid") is False:
            score -= 15
            reasons.append("Incomplete certificate chain")
    else:
        score -= 30
        reasons.append("Certificate information unavailable")
    
    # ═══════════════════════════════════════════
    # Protocol Issues (-5 to -40 points)
    # ═══════════════════════════════════════════
    supported_protocols = [p.get("version", "").upper() for p in protocols if p.get("supported")]
    
    if any("SSL" in p for p in supported_protocols):
        score -= 40
        reasons.append("SSLv2/SSLv3 supported (critical)")
    
    if "TLS1" in supported_protocols or "TLS1_0" in supported_protocols or "TLS.1.0" in supported_protocols:
        score -= 15
        reasons.append("TLS 1.0 supported (deprecated)")
    
    if "TLS1_1" in supported_protocols or "TLS.1.1" in supported_protocols:
        score -= 10
        reasons.append("TLS 1.1 supported (deprecated)")
    
    has_tls12 = any("1.2" in p or "1_2" in p for p in supported_protocols)
    has_tls13 = any("1.3" in p or "1_3" in p for p in supported_protocols)
    
    if not has_tls12 and not has_tls13:
        score -= 30
        reasons.append("No TLS 1.2 or 1.3 support")
    elif has_tls13:
        score += 5  # Bonus for TLS 1.3
    
    # ═══════════════════════════════════════════
    # Cipher Issues (-5 to -30 points)
    # ═══════════════════════════════════════════
    insecure_count = sum(1 for c in ciphers if c.get("strength") == "insecure")
    weak_count = sum(1 for c in ciphers if c.get("strength") == "weak")
    
    if insecure_count > 0:
        score -= min(30, insecure_count * 10)
        reasons.append(f"{insecure_count} insecure cipher(s)")
    
    if weak_count > 0:
        score -= min(15, weak_count * 5)
        reasons.append(f"{weak_count} weak cipher(s)")
    
    # Check for PFS
    pfs_ciphers = sum(1 for c in ciphers if c.get("pfs"))
    if len(ciphers) > 0 and pfs_ciphers == 0:
        score -= 10
        reasons.append("No Perfect Forward Secrecy")
    
    # ═══════════════════════════════════════════
    # Vulnerability Issues (-10 to -50 points)
    # ═══════════════════════════════════════════
    critical_vulns = [v for v in vulns if v.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
    medium_vulns = [v for v in vulns if v.get("severity", "").upper() == "MEDIUM"]
    
    for vuln in critical_vulns:
        score -= 25
        reasons.append(f"Vulnerability: {vuln.get('name')} ({vuln.get('severity')})")
    
    for vuln in medium_vulns:
        score -= 10
        reasons.append(f"Vulnerability: {vuln.get('name')} ({vuln.get('severity')})")
    
    # ═══════════════════════════════════════════
    # HSTS Bonus/Penalty
    # ═══════════════════════════════════════════
    if result.get("hsts_enabled"):
        score += 5
        if result.get("hsts_preload"):
            score += 3
    else:
        score -= 5
        reasons.append("HSTS not enabled")
    
    # ═══════════════════════════════════════════
    # OCSP Stapling Bonus
    # ═══════════════════════════════════════════
    ocsp = result.get("ocsp")
    if ocsp and ocsp.get("stapling_enabled"):
        score += 3
    
    # ═══════════════════════════════════════════
    # Calculate Final Grade
    # ═══════════════════════════════════════════
    score = max(0, min(100, score))  # Clamp to 0-100
    
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 85:
        grade = "A-"
    elif score >= 80:
        grade = "B+"
    elif score >= 75:
        grade = "B"
    elif score >= 70:
        grade = "B-"
    elif score >= 65:
        grade = "C+"
    elif score >= 60:
        grade = "C"
    elif score >= 55:
        grade = "C-"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"
    
    return grade, reasons


# ══════════════════════════════════════════════════════════════
# 8. ROBUST JSON/XML EXTRACTION
# ══════════════════════════════════════════════════════════════

def _extract_json_value(raw: str) -> Optional[Any]:
    """
    Robustly extract JSON from potentially noisy output.
    
    Handles:
    - Clean JSON input
    - JSON embedded in log output
    - Multiple JSON objects (takes first complete one)
    - ANSI color codes in output
    """
    if not raw:
        return None
    
    # Remove ANSI color codes
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    text = text.strip()
    
    if not text:
        return None
    
    # Try parsing entire output first (clean case)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Find valid JSON objects/arrays using regex
    decoder = json.JSONDecoder()
    
    # Look for JSON starting markers
    for match in re.finditer(r'[\[\{]', text):
        idx = match.start()
        
        # Skip if this looks like a log timestamp [2024-01-15...]
        if idx > 0 and text[idx] == '[':
            # Check if it's a timestamp pattern
            slice_after = text[idx:idx+20]
            if re.match(r'\[\d{4}-\d{2}-\d{2}', slice_after):
                continue
            # Check if it's a log level [INFO], [WARN], etc.
            if re.match(r'\[(INFO|WARN|ERROR|DEBUG|OK|CRITICAL)\]', slice_after, re.IGNORECASE):
                continue
        
        try:
            value, end_idx = decoder.raw_decode(text, idx=idx)
            # Validate it's a complete JSON value
            if isinstance(value, (dict, list)):
                # Additional validation: must have some content
                if isinstance(value, list) and len(value) > 0:
                    return value
                if isinstance(value, dict) and len(value) > 0:
                    return value
        except json.JSONDecodeError:
            continue
        except ValueError:
            continue
    
    return None


def _extract_xml_blob(raw: str) -> str:
    """
    Robustly extract XML from potentially noisy output.
    
    Handles:
    - Clean XML input
    - XML embedded in log output
    - HTML errors (filters them out)
    """
    if not raw:
        return ""
    
    # Remove ANSI color codes
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    text = text.strip()
    
    if not text:
        return ""
    
    # Priority 1: XML declaration
    xml_decl_match = re.search(r'<\?xml[^?]*\?>', text)
    if xml_decl_match:
        start = xml_decl_match.start()
        candidate = text[start:].strip()
        # Trim trailing non-XML text often printed by tools after XML output.
        root_match = re.search(r'<\?xml[^>]*\?>\s*<([a-zA-Z_][\w\-\.:]*)', candidate)
        if root_match:
            root_name = root_match.group(1)
            end_tag = f"</{root_name}>"
            end_idx = candidate.rfind(end_tag)
            if end_idx != -1:
                return candidate[:end_idx + len(end_tag)].strip()
        return candidate
    
    # Priority 2: Known root elements (sslscan specific)
    known_roots = ["<document", "<ssltest", "<results", "<target", "<host"]
    for root in known_roots:
        idx = text.find(root)
        if idx != -1:
            candidate = text[idx:].strip()
            # Best effort trim to closing root tag if present.
            root_name_match = re.match(r'<([a-zA-Z_][\w\-\.:]*)', candidate)
            if root_name_match:
                root_name = root_name_match.group(1)
                end_tag = f"</{root_name}>"
                end_idx = candidate.rfind(end_tag)
                if end_idx != -1:
                    return candidate[:end_idx + len(end_tag)].strip()
            return candidate
    
    # Priority 3: First < that looks like valid XML (not HTML error)
    for match in re.finditer(r'<[a-zA-Z]', text):
        idx = match.start()
        candidate = text[idx:].strip()
        
        # Filter out HTML error pages
        if any(html in candidate.lower()[:500] for html in ['<html', '<!doctype', '<body', '<head']):
            continue
        
        # Basic XML structure validation
        if '</' in candidate and '>' in candidate:
            return candidate
    
    return ""


def _extract_sslscan_errors(raw_xml: str) -> list[str]:
    """Extract sslscan XML error nodes."""
    errors: list[str] = []
    xml_blob = _extract_xml_blob(raw_xml)
    if not xml_blob:
        return errors
    try:
        root = ET.fromstring(xml_blob)
        for err_node in root.findall(".//error"):
            text = (err_node.text or "").strip()
            if text:
                errors.append(text)
    except ET.ParseError:
        pass
    return errors


# ══════════════════════════════════════════════════════════════
# 9. COMMAND BUILDERS
# ══════════════════════════════════════════════════════════════

def _build_testssl_cmd(args: list[str], target: str) -> list[str]:
    """Build testssl command with stdout-only JSON output"""
    user_args = list(args)
    user_args = [a for a in user_args if a not in {"testssl", "testssl.sh"}]
    
    cmd = ["testssl"]
    final_args = user_args

    # Block file output flags
    for arg in final_args:
        if arg in {"--jsonfile", "--json", "--htmlfile", "--logfile", "--csvfile"}:
            raise ValueError(f"Output file flag '{arg}' blocked. Use stdout only.")
        if any(arg.startswith(f"{flag}=") for flag in ["--jsonfile", "--htmlfile", "--logfile", "--csvfile"]):
            raise ValueError(f"Output file flag blocked. Use stdout only.")

    # Force JSON to stdout
    final_args.extend(["--jsonfile", "/dev/stdout"])
    
    # Add severity warnings for better parsing
    if "--warnings" not in " ".join(final_args):
        final_args.append("--warnings=batch")
    
    if not _target_in_args(target, final_args):
        final_args.append(target)
        
    cmd.extend(final_args)
    return cmd


def _build_sslscan_cmd(args: list[str], target: str) -> list[str]:
    """Build sslscan command with stdout-only XML output"""
    cmd = ["sslscan"]
    final_args = list(args)

    # Block file output
    for arg in final_args:
        if arg.startswith("--xml=") and arg != "--xml=/dev/stdout":
            raise ValueError("Output file flags blocked. Use stdout only.")

    if "--xml=/dev/stdout" not in final_args:
        final_args.append("--xml=/dev/stdout")

    # Clean target (sslscan needs hostname:port, not URL)
    clean_target = re.sub(r"^\w+://", "", target.strip()).split('/')[0]

    if not _target_in_args(clean_target, final_args):
        final_args.append(clean_target)

    cmd.extend(final_args)
    return cmd


def _build_sslyze_cmd(args: list[str], target: str) -> list[str]:
    """Build sslyze command with stdout-only JSON output"""
    cmd = ["sslyze"]
    final_args = list(args)

    # Block file output
    for arg in final_args:
        if arg.startswith("--json_out=") and arg != "--json_out=/dev/stdout":
            raise ValueError("Output file flags blocked. Use stdout only.")

    if "--json_out=/dev/stdout" not in final_args:
        final_args.append("--json_out=/dev/stdout")

    # Clean target
    clean_target = re.sub(r"^\w+://", "", target.strip()).split('/')[0]

    if not _target_in_args(clean_target, final_args):
        final_args.append(clean_target)

    cmd.extend(final_args)
    return cmd


# ══════════════════════════════════════════════════════════════
# 10. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_testssl(raw_json: str) -> dict:
    """
    Parse testssl JSON output with comprehensive extraction.
    
    Returns dict with all extracted data.
    """
    result = {
        "certificate": None,
        "protocols": [],
        "ciphers": [],
        "vulnerabilities": [],
        "hsts_enabled": None,
        "hsts_max_age": None,
        "hsts_preload": False,
        "hsts_include_subdomains": False,
        "ocsp": OCSPInfo(),
        "session_resumption": SessionResumption(),
    }
    
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    vulns = []
    
    data = _extract_json_value(raw_json)
    if data is None:
        logger.warning("testssl: Failed to extract JSON from output")
        return result

    try:
        if isinstance(data, list):
            for item in data:
                id_ = item.get("id", "")
                sev = item.get("severity", "")
                finding = item.get("finding", "")
                id_upper = id_.upper()
                
                # ═══════════════════════════════════════════
                # Protocols
                # ═══════════════════════════════════════════
                if id_ in ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]:
                    supported = "not offered" not in finding.lower()
                    protocols.append(ProtocolSupport(version=id_, supported=supported))
                
                # TLS 1.3 specific features
                elif id_ == "TLS1_3_early_data" or id_ == "early_data":
                    # Find the TLS 1.3 protocol entry and update it
                    for p in protocols:
                        if "1.3" in p.version or "1_3" in p.version:
                            p.early_data = "enabled" in finding.lower() or "offered" in finding.lower()
                            p.zero_rtt_enabled = p.early_data
                
                # ═══════════════════════════════════════════
                # Certificate Info
                # ═══════════════════════════════════════════
                elif id_ == "cert_subject" or id_ == "cert_commonName":
                    cert.subject = finding
                    if "*." in finding:
                        cert.is_wildcard = True
                
                elif id_ == "cert_issuer":
                    cert.issuer = finding
                    # Self-signed check
                    if cert.subject and cert.subject == cert.issuer:
                        cert.self_signed = True
                
                elif id_ == "cert_signatureAlgorithm":
                    cert.signature_algorithm = finding
                    if any(deprecated in finding.lower() for deprecated in ["sha1", "md5", "md2"]):
                        cert.sha1_signature = True
                
                elif id_ == "cert_notBefore":
                    cert.valid_from = finding
                
                elif id_ == "cert_notAfter":
                    cert.valid_until = finding
                
                elif id_ == "cert_expirationStatus":
                    cert.expired = "expired" in finding.lower()
                    # Try to extract days until expiry
                    days_match = re.search(r'(\d+)\s*days?', finding)
                    if days_match:
                        cert.days_until_expiry = int(days_match.group(1))
                
                elif id_ == "cert_trust":
                    cert.hostname_matches = sev in ["OK", "INFO"]
                
                elif id_ == "cert_chain_of_trust":
                    cert.chain_valid = "ok" in finding.lower() or sev == "OK"
                
                elif id_ == "cert_keySize":
                    # Extract key size and algorithm
                    size_match = re.search(r'(\d+)\s*bit', finding)
                    if size_match:
                        cert.key_size = int(size_match.group(1))
                    if "RSA" in finding.upper():
                        cert.key_algorithm = "RSA"
                    elif "EC" in finding.upper() or "ECDSA" in finding.upper():
                        cert.key_algorithm = "ECDSA"
                    elif "ED25519" in finding.upper():
                        cert.key_algorithm = "Ed25519"
                
                elif id_ == "cert_subjectAltName":
                    # Parse SANs
                    sans = re.findall(r'DNS:([^\s,]+)', finding)
                    cert.sans = sans
                
                elif id_ == "cert_extendedValidation":
                    cert.is_ev = "yes" in finding.lower()
                
                elif id_ == "cert_certificateTransparency":
                    cert.ct_sct_present = "yes" in finding.lower() or "present" in finding.lower()
                
                elif id_ == "cert_fingerprintSHA256":
                    cert.sha256_fingerprint = finding
                
                elif id_ == "cert_chainCount":
                    count_match = re.search(r'(\d+)', finding)
                    if count_match:
                        cert.chain_length = int(count_match.group(1))
                
                # ═══════════════════════════════════════════
                # Vulnerabilities (comprehensive list)
                # ═══════════════════════════════════════════
                elif id_upper in [v.upper() for v in VULNERABILITY_IDS]:
                    if sev.upper() not in ["OK", "INFO"]:
                        vuln = Vulnerability(
                            name=id_,
                            severity=sev.upper(),
                            description=finding
                        )
                        # Add CVE if known
                        cve_map = {
                            "heartbleed": "CVE-2014-0160",
                            "CCS": "CVE-2014-0224",
                            "ticketbleed": "CVE-2016-9244",
                            "ROBOT": "CVE-2017-13099",
                            "poodle": "CVE-2014-3566",
                            "DROWN": "CVE-2016-0800",
                            "BEAST": "CVE-2011-3389",
                            "logjam": "CVE-2015-4000",
                            "freak": "CVE-2015-0204",
                            "sweet32": "CVE-2016-2183",
                        }
                        if id_.lower() in cve_map:
                            vuln.cve = cve_map[id_.lower()]
                        vulns.append(vuln)
                
                # Check for generic vulnerability indicators
                elif sev.upper() in ["CRITICAL", "HIGH", "MEDIUM"] and "vuln" in id_.lower():
                    vulns.append(Vulnerability(
                        name=id_,
                        severity=sev.upper(),
                        description=finding
                    ))
                
                # ═══════════════════════════════════════════
                # HSTS
                # ═══════════════════════════════════════════
                elif id_ == "HSTS":
                    result["hsts_enabled"] = "offered" in finding.lower()
                    # Extract max-age
                    age_match = re.search(r'max-age\s*=\s*(\d+)', finding, re.IGNORECASE)
                    if age_match:
                        result["hsts_max_age"] = int(age_match.group(1))
                    result["hsts_preload"] = "preload" in finding.lower()
                    result["hsts_include_subdomains"] = "includesubdomains" in finding.lower()
                
                # ═══════════════════════════════════════════
                # OCSP Stapling
                # ═══════════════════════════════════════════
                elif id_ == "OCSP_stapling":
                    result["ocsp"].stapling_enabled = "offered" in finding.lower()
                
                elif id_ == "OCSP_must_staple":
                    result["ocsp"].must_staple = "yes" in finding.lower()
                
                elif id_ == "OCSP_URI":
                    result["ocsp"].responder_url = finding
                
                # ═══════════════════════════════════════════
                # Session Resumption
                # ═══════════════════════════════════════════
                elif id_ == "sessionresumption_ID":
                    result["session_resumption"].session_id_supported = "supported" in finding.lower()
                
                elif id_ == "sessionresumption_ticket":
                    result["session_resumption"].session_ticket_supported = "supported" in finding.lower()
                    # Extract lifetime
                    lifetime_match = re.search(r'(\d+)', finding)
                    if lifetime_match:
                        result["session_resumption"].session_ticket_lifetime = int(lifetime_match.group(1))
                
                # ═══════════════════════════════════════════
                # Ciphers
                # ═══════════════════════════════════════════
                elif id_.startswith("cipher_") or "cipher" in id_.lower():
                    cipher_name = finding.split()[0] if finding else id_
                    if cipher_name and len(cipher_name) > 3:
                        components = parse_cipher_components(cipher_name)
                        key_size = None
                        size_match = re.search(r'(\d+)\s*bit', finding)
                        if size_match:
                            key_size = int(size_match.group(1))
                        
                        ciphers.append(CipherSuite(
                            protocol="Unknown",
                            name=cipher_name,
                            key_size=key_size,
                            strength=classify_cipher_strength(cipher_name, key_size),
                            pfs=has_perfect_forward_secrecy(cipher_name),
                            **components
                        ))

    except Exception as e:
        logger.error(f"testssl parser error: {e}")

    result["certificate"] = cert if cert.subject else None
    result["protocols"] = protocols
    result["ciphers"] = ciphers
    result["vulnerabilities"] = vulns
    
    return result


def parse_sslscan(raw_xml: str) -> dict:
    """
    Parse sslscan XML output with comprehensive extraction.
    """
    result = {
        "certificate": None,
        "protocols": [],
        "ciphers": [],
        "vulnerabilities": [],
        "hsts_enabled": None,
        "ocsp": OCSPInfo(),
        "session_resumption": SessionResumption(),
        "scan_errors": [],
    }
    
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    vulns = []
    
    xml_blob = _extract_xml_blob(raw_xml)
    if not xml_blob:
        logger.warning("sslscan: Failed to extract XML from output")
        return result

    try:
        root = ET.fromstring(xml_blob)

        # Capture scan-level errors from sslscan XML.
        for err_node in root.findall(".//error"):
            text = (err_node.text or "").strip()
            if text:
                result["scan_errors"].append(text)

        ssltests = root.findall(".//ssltest")
        if not ssltests:
            # Sometimes root can directly be an ssltest node.
            if root.tag.lower().endswith("ssltest"):
                ssltests = [root]
            else:
                # No usable scan result nodes.
                return result

        for ssltest in ssltests:
            # ═══════════════════════════════════════════
            # Protocols and Ciphers
            # ═══════════════════════════════════════════
            protocol_supported = {}
            
            for cipher in ssltest.findall(".//cipher"):
                status = cipher.get("status", "")
                if status == "accepted":
                    proto_name = cipher.get("sslversion", "Unknown")
                    cipher_name = cipher.get("cipher", "")
                    key_bits = cipher.get("bits", "0")
                    
                    try:
                        key_size = int(key_bits)
                    except ValueError:
                        key_size = None
                    
                    protocol_supported[proto_name] = True
                    
                    components = parse_cipher_components(cipher_name)
                    strength = classify_cipher_strength(cipher_name, key_size)
                    
                    ciphers.append(CipherSuite(
                        protocol=proto_name,
                        name=cipher_name,
                        key_size=key_size,
                        strength=strength,
                        pfs=has_perfect_forward_secrecy(cipher_name),
                        **components
                    ))
                    
                    # Flag weak/insecure ciphers as vulnerabilities
                    if strength == "insecure":
                        vulns.append(Vulnerability(
                            name=f"Insecure Cipher: {cipher_name}",
                            severity="HIGH",
                            description=f"Insecure cipher {cipher_name} accepted on {proto_name}"
                        ))
                    elif strength == "weak":
                        vulns.append(Vulnerability(
                            name=f"Weak Cipher: {cipher_name}",
                            severity="MEDIUM",
                            description=f"Weak cipher {cipher_name} accepted on {proto_name}"
                        ))
            
            # Add protocol entries only when we have protocol evidence.
            if protocol_supported:
                all_protos = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
                for proto in all_protos:
                    supported = protocol_supported.get(proto, False)
                    protocols.append(ProtocolSupport(version=proto, supported=supported))
                
                    # Flag deprecated protocols as vulnerabilities
                    if supported and proto in ["SSLv2", "SSLv3"]:
                        vulns.append(Vulnerability(
                            name=f"Deprecated Protocol: {proto}",
                            severity="CRITICAL",
                            description=f"{proto} is supported but critically insecure"
                        ))
                    elif supported and proto in ["TLSv1.0", "TLSv1.1"]:
                        vulns.append(Vulnerability(
                            name=f"Deprecated Protocol: {proto}",
                            severity="MEDIUM",
                            description=f"{proto} is supported but deprecated"
                        ))
            
            # ═══════════════════════════════════════════
            # Certificate
            # ═══════════════════════════════════════════
            cert_node = ssltest.find(".//certificate") or ssltest.find("certificate")
            if cert_node is not None:
                # Subject
                for tag in ["subject", "certificate-subject"]:
                    elem = cert_node.find(tag)
                    if elem is not None and elem.text:
                        cert.subject = elem.text
                        if "*." in elem.text:
                            cert.is_wildcard = True
                        break
                
                # Issuer
                for tag in ["issuer", "certificate-issuer"]:
                    elem = cert_node.find(tag)
                    if elem is not None and elem.text:
                        cert.issuer = elem.text
                        if cert.subject and cert.subject == cert.issuer:
                            cert.self_signed = True
                        break
                
                # Signature algorithm
                sig_elem = cert_node.find("signature-algorithm")
                if sig_elem is not None and sig_elem.text:
                    cert.signature_algorithm = sig_elem.text
                    if any(deprecated in sig_elem.text.lower() for deprecated in ["sha1", "md5"]):
                        cert.sha1_signature = True
                        vulns.append(Vulnerability(
                            name="Deprecated Signature Algorithm",
                            severity="MEDIUM",
                            description=f"Certificate uses deprecated signature: {sig_elem.text}"
                        ))
                
                # Validity dates
                for start_tag in ["not-valid-before", "notBefore"]:
                    elem = cert_node.find(start_tag)
                    if elem is not None and elem.text:
                        cert.valid_from = elem.text
                        break
                
                for end_tag in ["not-valid-after", "notAfter"]:
                    elem = cert_node.find(end_tag)
                    if elem is not None and elem.text:
                        cert.valid_until = elem.text
                        break
                
                # Expiry
                exp_elem = cert_node.find("expired")
                if exp_elem is not None:
                    cert.expired = exp_elem.text and exp_elem.text.lower() == "true"
                
                # Key info
                pk_elem = cert_node.find(".//pk")
                if pk_elem is not None:
                    cert.key_algorithm = pk_elem.get("type")
                    try:
                        cert.key_size = int(pk_elem.get("bits", 0))
                    except ValueError:
                        pass
                    
                    # Flag weak keys
                    if cert.key_size and cert.key_size < 2048:
                        vulns.append(Vulnerability(
                            name="Weak Key Size",
                            severity="HIGH" if cert.key_size < 1024 else "MEDIUM",
                            description=f"Certificate key size is only {cert.key_size} bits"
                        ))
                
                # Self-signed check
                self_signed_elem = cert_node.find("self-signed")
                if self_signed_elem is not None:
                    cert.self_signed = self_signed_elem.text and self_signed_elem.text.lower() == "true"
                
                # SANs
                san_elem = cert_node.find(".//altnames")
                if san_elem is not None and san_elem.text:
                    cert.sans = [s.strip() for s in san_elem.text.split(",") if s.strip()]
            
            # ═══════════════════════════════════════════
            # Heartbleed check (sslscan specific)
            # ═══════════════════════════════════════════
            heartbleed = ssltest.find(".//heartbleed")
            if heartbleed is not None:
                vuln_attr = heartbleed.get("vulnerable", "0")
                if vuln_attr == "1" or "vulnerable" in (heartbleed.text or "").lower():
                    vulns.append(Vulnerability(
                        name="Heartbleed",
                        severity="CRITICAL",
                        cve="CVE-2014-0160",
                        description="Server is vulnerable to Heartbleed attack"
                    ))
            
            # ═══════════════════════════════════════════
            # Session Resumption
            # ═══════════════════════════════════════════
            session_elem = ssltest.find(".//session-resumption") or ssltest.find("sessionresumption")
            if session_elem is not None:
                result["session_resumption"].session_id_supported = session_elem.get("supported", "0") == "1"

    except ET.ParseError as e:
        logger.error(f"sslscan XML parse error: {e}")
    except Exception as e:
        logger.error(f"sslscan parser error: {e}")

    result["certificate"] = cert if cert.subject else None
    result["protocols"] = protocols
    result["ciphers"] = ciphers
    result["vulnerabilities"] = vulns
    
    return result


def parse_sslyze(raw_json: str) -> dict:
    """
    Parse sslyze JSON output with comprehensive extraction.
    """
    result = {
        "certificate": None,
        "protocols": [],
        "ciphers": [],
        "vulnerabilities": [],
        "hsts_enabled": None,
        "ocsp": OCSPInfo(),
        "session_resumption": SessionResumption(),
    }
    
    cert = CertificateInfo()
    protocols = []
    ciphers = []
    vulns = []

    data = _extract_json_value(raw_json)
    if data is None:
        logger.warning("sslyze: Failed to extract JSON from output")
        return result

    try:
        results_list = data.get("server_scan_results", [])
        if not results_list:
            return result
        
        scan_result = results_list[0].get("scan_result", {})
        
        # ═══════════════════════════════════════════
        # Certificate
        # ═══════════════════════════════════════════
        cert_info = scan_result.get("certificate_info", {}).get("result", {})
        if cert_info:
            deployments = cert_info.get("certificate_deployments", [])
            if deployments:
                deployment = deployments[0]
                chain = deployment.get("received_certificate_chain", [])
                
                if chain:
                    leaf = chain[0]
                    
                    # Subject/Issuer
                    subject = leaf.get("subject", {})
                    issuer = leaf.get("issuer", {})
                    cert.subject = subject.get("rfc4514_string")
                    cert.issuer = issuer.get("rfc4514_string")
                    
                    if cert.subject and cert.issuer and cert.subject == cert.issuer:
                        cert.self_signed = True
                    
                    # Signature algorithm
                    cert.signature_algorithm = leaf.get("signature_hash_algorithm", {}).get("name")
                    if cert.signature_algorithm and "sha1" in cert.signature_algorithm.lower():
                        cert.sha1_signature = True
                    
                    # Validity
                    cert.valid_from = leaf.get("not_valid_before")
                    cert.valid_until = leaf.get("not_valid_after")
                    
                    # Key info
                    public_key = leaf.get("public_key", {})
                    cert.key_algorithm = public_key.get("algorithm")
                    cert.key_size = public_key.get("key_size")
                    
                    # SANs
                    san_ext = leaf.get("subject_alternative_name", {})
                    cert.sans = san_ext.get("dns", [])
                    
                    # Wildcard check
                    if cert.sans:
                        cert.is_wildcard = any(s.startswith("*.") for s in cert.sans)
                    
                    # Fingerprint
                    cert.sha256_fingerprint = leaf.get("fingerprint_sha256")
                    
                    # Chain info
                    cert.chain_length = len(chain)
                
                # Chain validation
                path_validation = deployment.get("path_validation_results", [])
                if path_validation:
                    # Check if any validation passed
                    cert.chain_valid = any(
                        v.get("verified_certificate_chain") is not None
                        for v in path_validation
                    )
                
                # OCSP stapling
                ocsp_response = deployment.get("ocsp_response")
                if ocsp_response:
                    result["ocsp"].stapling_enabled = True
                    status = ocsp_response.get("response_status")
                    result["ocsp"].response_status = status
        
        # ═══════════════════════════════════════════
        # Protocols / Ciphers
        # ═══════════════════════════════════════════
        protocol_mapping = {
            "ssl_2_0_cipher_suites": "SSLv2",
            "ssl_3_0_cipher_suites": "SSLv3",
            "tls_1_0_cipher_suites": "TLSv1.0",
            "tls_1_1_cipher_suites": "TLSv1.1",
            "tls_1_2_cipher_suites": "TLSv1.2",
            "tls_1_3_cipher_suites": "TLSv1.3",
        }
        
        for proto_key, proto_name in protocol_mapping.items():
            proto_result = scan_result.get(proto_key, {}).get("result", {})
            if proto_result:
                is_supported = proto_result.get("is_tls_version_supported", False)
                
                proto = ProtocolSupport(version=proto_name, supported=is_supported)
                
                # TLS 1.3 features
                if proto_name == "TLSv1.3":
                    early_data = scan_result.get("tls_1_3_early_data", {}).get("result", {})
                    proto.early_data = early_data.get("supports_early_data", False)
                    proto.zero_rtt_enabled = proto.early_data
                
                protocols.append(proto)
                
                # Flag deprecated protocols
                if is_supported and proto_name in ["SSLv2", "SSLv3"]:
                    vulns.append(Vulnerability(
                        name=f"Deprecated Protocol: {proto_name}",
                        severity="CRITICAL",
                        description=f"{proto_name} is supported but critically insecure"
                    ))
                elif is_supported and proto_name in ["TLSv1.0", "TLSv1.1"]:
                    vulns.append(Vulnerability(
                        name=f"Deprecated Protocol: {proto_name}",
                        severity="MEDIUM",
                        description=f"{proto_name} is supported but deprecated"
                    ))
                
                # Extract ciphers
                for cipher_entry in proto_result.get("accepted_cipher_suites", []):
                    suite = cipher_entry.get("cipher_suite", {})
                    cipher_name = suite.get("name", "Unknown")
                    key_size = suite.get("key_size")
                    
                    components = parse_cipher_components(cipher_name)
                    strength = classify_cipher_strength(cipher_name, key_size)
                    
                    ciphers.append(CipherSuite(
                        protocol=proto_name,
                        name=cipher_name,
                        key_size=key_size,
                        strength=strength,
                        pfs=has_perfect_forward_secrecy(cipher_name),
                        **components
                    ))
                    
                    # Flag weak/insecure ciphers
                    if strength == "insecure":
                        vulns.append(Vulnerability(
                            name=f"Insecure Cipher: {cipher_name}",
                            severity="HIGH",
                            description=f"Insecure cipher accepted on {proto_name}"
                        ))
        
        # ═══════════════════════════════════════════
        # Vulnerabilities
        # ═══════════════════════════════════════════
        # Heartbleed
        heartbleed = scan_result.get("heartbleed", {}).get("result", {})
        if heartbleed.get("is_vulnerable_to_heartbleed"):
            vulns.append(Vulnerability(
                name="Heartbleed",
                severity="CRITICAL",
                cve="CVE-2014-0160",
                description="Server is vulnerable to Heartbleed attack"
            ))
        
        # ROBOT
        robot = scan_result.get("robot", {}).get("result", {})
        robot_result = robot.get("robot_result")
        if robot_result and "VULNERABLE" in str(robot_result).upper():
            vulns.append(Vulnerability(
                name="ROBOT",
                severity="HIGH",
                cve="CVE-2017-13099",
                description="Server is vulnerable to ROBOT attack"
            ))
        
        # OpenSSL CCS Injection
        ccs = scan_result.get("openssl_ccs_injection", {}).get("result", {})
        if ccs.get("is_vulnerable_to_ccs_injection"):
            vulns.append(Vulnerability(
                name="CCS Injection",
                severity="HIGH",
                cve="CVE-2014-0224",
                description="Server is vulnerable to OpenSSL CCS Injection"
            ))
        
        # Session Renegotiation
        reneg = scan_result.get("session_renegotiation", {}).get("result", {})
        if reneg.get("is_vulnerable_to_client_renegotiation_dos"):
            vulns.append(Vulnerability(
                name="Client Renegotiation DoS",
                severity="MEDIUM",
                description="Server is vulnerable to client-initiated renegotiation DoS"
            ))
        
        # ═══════════════════════════════════════════
        # Session Resumption
        # ═══════════════════════════════════════════
        resumption = scan_result.get("session_resumption", {}).get("result", {})
        if resumption:
            result["session_resumption"].session_id_supported = (
                resumption.get("session_id_resumption_result") == "FULLY_SUPPORTED"
            )
            result["session_resumption"].session_ticket_supported = (
                resumption.get("tls_ticket_resumption_result") == "FULLY_SUPPORTED"
            )

    except Exception as e:
        logger.error(f"sslyze parser error: {e}")

    result["certificate"] = cert if cert.subject else None
    result["protocols"] = protocols
    result["ciphers"] = ciphers
    result["vulnerabilities"] = vulns
    
    return result


# ══════════════════════════════════════════════════════════════
# 11. CACHING
# ══════════════════════════════════════════════════════════════

@lru_cache(maxsize=128)
def _cached_ssl_analysis(tool: str, target: str, args_tuple: tuple, timeout: int) -> str:
    """Cached internal implementation. Returns JSON string."""
    args = list(args_tuple)
    result = _ssl_tls_analysis_impl(tool, target, args, timeout)
    return json.dumps(result)


def clear_cache():
    """Clear the result cache"""
    _cached_ssl_analysis.cache_clear()


def get_cache_info():
    """Get cache statistics"""
    return _cached_ssl_analysis.cache_info()


# ══════════════════════════════════════════════════════════════
# 12. MAIN IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

def _ssl_tls_analysis_impl(tool: str, target: str, args: list[str], timeout: int) -> dict:
    """Core implementation"""
    start = time.time()
    
    # Rate limit
    SSL_RATE_LIMITER.acquire()
    
    # ── VALIDATE ──
    try:
        req = SslTlsRequest(tool=tool, target=target, args=args, timeout=timeout)
    except Exception as e:
        return SslTlsResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Validation error: {e}"
        ).model_dump()

    # ── BUILD COMMAND ──
    try:
        if tool == "testssl":
            cmd = _build_testssl_cmd(args, target)
        elif tool == "sslscan":
            cmd = _build_sslscan_cmd(args, target)
        elif tool == "sslyze":
            cmd = _build_sslyze_cmd(args, target)
        else:
            raise ValueError(f"Unknown tool: {tool}")
    except Exception as e:
        return SslTlsResult(
            success=False,
            tool=tool,
            target=target,
            command="",
            error=f"Command build error: {e}"
        ).model_dump()

    # ── EXECUTE ──
    command_str = " ".join(cmd)
    logger.info(f"Executing: {command_str}")
    
    stdout, stderr, rc, cwd = safe_execute(cmd, req.timeout)
    
    # ── PARSE ──
    parsed = {}
    if tool == "testssl":
        parsed = parse_testssl(stdout)
    elif tool == "sslscan":
        parsed = parse_sslscan(stdout)
    elif tool == "sslyze":
        parsed = parse_sslyze(stdout)

    # Check if we got meaningful data
    cert = parsed.get("certificate")
    protocols = parsed.get("protocols", [])
    ciphers = parsed.get("ciphers", [])
    vulns = parsed.get("vulnerabilities", [])
    
    supported_protocol_found = False
    for p in protocols:
        if hasattr(p, "supported") and bool(getattr(p, "supported")):
            supported_protocol_found = True
            break
        if isinstance(p, dict) and bool(p.get("supported")):
            supported_protocol_found = True
            break

    has_data = (
        cert is not None
        or len(ciphers) > 0
        or len(vulns) > 0
        or supported_protocol_found
    )
    clean_stderr = re.sub(r"\x1b\[[0-9;]*m", "", (stderr or "")).strip()
    runtime_error = None

    # Prefer explicit stderr errors first.
    if clean_stderr:
        runtime_error = clean_stderr[:1000]

    # sslscan often returns XML <error> with rc=0 and no stderr.
    if tool == "sslscan" and not runtime_error:
        xml_errors = parsed.get("scan_errors") or _extract_sslscan_errors(stdout)
        if xml_errors:
            runtime_error = " | ".join(xml_errors)[:1000]

    # Generic no-data fallback.
    if not has_data and not runtime_error:
        combined = re.sub(r"\x1b\[[0-9;]*m", "", (stdout or "") + "\n" + (stderr or ""))
        if re.search(
            r"could not open a connection|could not resolve hostname|network is unreachable|connection refused|timed out|name or service not known",
            combined,
            flags=re.IGNORECASE,
        ):
            runtime_error = combined.strip()[:1000]
        else:
            runtime_error = "No parsable SSL/TLS data returned."

    success = has_data and runtime_error is None

    # ── COUNT CIPHER STRENGTHS ──
    insecure_count = sum(1 for c in ciphers if c.strength == "insecure")
    weak_count = sum(1 for c in ciphers if c.strength == "weak")
    strong_count = sum(1 for c in ciphers if c.strength == "strong")

    # ── BUILD RESULT ──
    result_data = {
        "success": success,
        "tool": tool,
        "target": target,
        "command": command_str,
        "working_dir": cwd,
        "certificate": cert.model_dump() if cert else None,
        "protocols": [p.model_dump() if hasattr(p, 'model_dump') else p for p in protocols],
        "ciphers": [c.model_dump() if hasattr(c, 'model_dump') else c for c in ciphers],
        "vulnerabilities": [v.model_dump() if hasattr(v, 'model_dump') else v for v in vulns],
        "hsts_enabled": parsed.get("hsts_enabled"),
        "hsts_max_age": parsed.get("hsts_max_age"),
        "hsts_preload": parsed.get("hsts_preload", False),
        "hsts_include_subdomains": parsed.get("hsts_include_subdomains", False),
        "ocsp": parsed.get("ocsp").model_dump() if parsed.get("ocsp") else None,
        "session_resumption": parsed.get("session_resumption").model_dump() if parsed.get("session_resumption") else None,
        "insecure_cipher_count": insecure_count,
        "weak_cipher_count": weak_count,
        "strong_cipher_count": strong_count,
        "raw_output": (stdout or stderr)[:8000] if not has_data else None,
        "error": runtime_error,
        "execution_time": round(time.time() - start, 2),
    }

    # ── CALCULATE GRADE ──
    grade, grade_reasons = calculate_grade(result_data)
    result_data["grade"] = grade
    result_data["grade_reasons"] = grade_reasons

    return result_data


# ══════════════════════════════════════════════════════════════
# 13. PUBLIC API
# ══════════════════════════════════════════════════════════════

def ssl_tls_analysis(
    tool: str,
    target: str,
    args: Optional[list[str]] = None,
    timeout: int = 600,
    use_cache: bool = True
) -> dict:
    """
    🔧 Agent Tool: Comprehensive SSL/TLS Analysis
    
    Analyzes a target's SSL/TLS configuration to extract:
    - Certificate information (validity, chain, SANs, key strength)
    - Supported protocols (SSLv2/3, TLS 1.0-1.3)
    - Cipher suites with strength classification
    - Vulnerabilities (Heartbleed, POODLE, ROBOT, BEAST, etc.)
    - HSTS status and configuration
    - OCSP stapling status
    - Session resumption support
    - Overall security grade (A+ to F)

    ┌──────────────────────────────────────────────────────────────────┐
    │  CAPABILITIES                                                    │
    ├──────────────────────────────────────────────────────────────────┤
    │  • Certificate Validation    Subject, issuer, expiry, chain     │
    │  • Protocol Detection        SSLv2/3, TLS 1.0-1.3, 0-RTT       │
    │  • Cipher Classification     insecure/weak/acceptable/strong    │
    │  • Vulnerability Scanning    20+ CVEs (Heartbleed, ROBOT, etc)  │
    │  • HSTS Analysis             Enabled, max-age, preload          │
    │  • OCSP Stapling             Enabled, response status           │
    │  • Security Grading          A+ to F with reasons               │
    │  • Rate Limiting             2 scans/second (configurable)      │
    │  • Result Caching            LRU cache (128 entries)            │
    └──────────────────────────────────────────────────────────────────┘

    Args:
        tool: Scanner to use
            - "testssl"  : Most thorough (bash script, 2-5 min)
            - "sslscan"  : Fast C-based (10-30 sec)
            - "sslyze"   : Python-based (30-60 sec)

        target: Target domain or IP:port
            - "example.com" (defaults to port 443)
            - "example.com:8443" (custom port)
            - "10.10.10.1:443"

        args: Tool-specific arguments
            testssl: ["-U", "-S", "--fast"]
            sslscan: ["--no-failed", "--show-times"]
            sslyze: ["--regular"]

        timeout: Execution timeout in seconds (default: 600)

        use_cache: Enable LRU caching (default: True)

    Returns:
        dict: Comprehensive SSL/TLS analysis including:
            - certificate: Subject, issuer, expiry, key info, SANs
            - protocols: List with support status and TLS 1.3 features
            - ciphers: List with strength classification
            - vulnerabilities: List with CVEs and severity
            - grade: Overall security grade (A+ to F)
            - grade_reasons: Explanations for deductions

    Example:
        >>> result = ssl_tls_analysis("sslscan", "example.com")
        >>> print(f"Grade: {result['grade']}")
        >>> print(f"Vulnerabilities: {len(result['vulnerabilities'])}")
    """
    args = list(args or [])
    
    if use_cache:
        cached_json = _cached_ssl_analysis(tool, target, tuple(args), timeout)
        return json.loads(cached_json)
    else:
        return _ssl_tls_analysis_impl(tool, target, args, timeout)


# ══════════════════════════════════════════════════════════════
# 14. TOOL DEFINITION (LLM Function Calling)
# ══════════════════════════════════════════════════════════════

SSL_TLS_TOOL_DEFINITION = {
    "name": "ssl_tls_analysis",
    "description": (
        "Comprehensive SSL/TLS security analysis. Extracts certificate info "
        "(validity, chain, SANs, key strength), supported protocols (SSLv2-TLS1.3), "
        "cipher suites with strength classification (insecure/weak/acceptable/strong), "
        "vulnerabilities (Heartbleed, POODLE, ROBOT, BEAST, DROWN, etc. with CVEs), "
        "HSTS status, OCSP stapling, and calculates overall security grade (A+ to F). "
        "Supports testssl (most thorough, 2-5 min), sslscan (fast, 10-30 sec), "
        "and sslyze (Python-based, 30-60 sec). Includes rate limiting and caching."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["testssl", "sslscan", "sslyze"],
                "description": (
                    "Scanner tool:\n"
                    "• testssl = Most thorough, checks 20+ vulnerabilities (2-5 min)\n"
                    "• sslscan = Fast C-based scanner, good for ciphers (10-30 sec)\n"
                    "• sslyze = Python-based, good balance of speed/features (30-60 sec)"
                )
            },
            "target": {
                "type": "string",
                "description": (
                    "Target domain or IP with optional port. Examples:\n"
                    "• 'example.com' (defaults to port 443)\n"
                    "• 'example.com:8443' (custom port)\n"
                    "• '10.10.10.1:443' (IP address)"
                )
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Tool-specific arguments:\n"
                    "• testssl: ['-U'] (vulns), ['-S'] (server defaults), ['--fast']\n"
                    "• sslscan: ['--no-failed'] (hide rejected ciphers), ['--show-times']\n"
                    "• sslyze: ['--regular'] (standard scan)"
                )
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default: 600, min: 10, max: 3600)"
            },
            "use_cache": {
                "type": "boolean",
                "description": "Enable result caching to avoid re-scanning (default: true)"
            }
        },
        "required": ["tool", "target"]
    }
}


# ══════════════════════════════════════════════════════════════
# 15. UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_rate_limiter_stats() -> dict:
    """Get rate limiter configuration"""
    return {
        "calls_per_second": SSL_RATE_LIMITER.calls_per_second,
        "min_interval": SSL_RATE_LIMITER.min_interval
    }


def set_rate_limit(calls_per_second: float):
    """Adjust rate limit"""
    global SSL_RATE_LIMITER
    SSL_RATE_LIMITER = RateLimiter(calls_per_second=calls_per_second)


def list_detected_vulnerabilities() -> list[str]:
    """Return list of vulnerabilities we detect"""
    return sorted(list(VULNERABILITY_IDS))


def get_cipher_strength_rules() -> dict:
    """Return cipher classification rules"""
    return {
        "insecure_patterns": INSECURE_CIPHER_PATTERNS,
        "weak_patterns": WEAK_CIPHER_PATTERNS,
        "strong_patterns": STRONG_CIPHER_PATTERNS,
    }


# ══════════════════════════════════════════════════════════════
# 16. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    clear_cache()

    print("=" * 70)
    print("SSL/TLS ANALYSIS — v2.0")
    print("Cipher Classification | Vulnerability Detection | Security Grading")
    print("=" * 70)
    
    # ─────────────────────────────────────────
    # Example 1: SSLScan (Fast)
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 1: SSLScan (Fast Scanner)")
    print("─" * 50)
    
    r1 = ssl_tls_analysis(
        tool="sslscan",
        target="scanme.nmap.org",
        args=["--no-failed"],
        use_cache=False
    )
    
    print(f"Command:   {r1['command']}")
    print(f"Success:   {r1['success']}")
    print(f"Grade:     {r1['grade']}")
    print(f"Exec Time: {r1['execution_time']}s")
    if r1.get("error"):
        print(f"Error:     {r1['error']}")
    
    if r1['certificate']:
        print(f"\nCertificate:")
        print(f"  Subject:     {r1['certificate'].get('subject', 'N/A')}")
        print(f"  Issuer:      {r1['certificate'].get('issuer', 'N/A')}")
        print(f"  Key:         {r1['certificate'].get('key_algorithm', 'N/A')} {r1['certificate'].get('key_size', '')} bit")
        print(f"  Expired:     {r1['certificate'].get('expired', False)}")
        print(f"  Self-Signed: {r1['certificate'].get('self_signed', False)}")
        print(f"  Wildcard:    {r1['certificate'].get('is_wildcard', False)}")
        if r1['certificate'].get('sans'):
            print(f"  SANs:        {', '.join(r1['certificate']['sans'][:5])}")
    
    print(f"\nProtocols:")
    for p in r1['protocols']:
        status = "✅ Supported" if p['supported'] else "❌ Not Supported"
        print(f"  {p['version']}: {status}")
    
    print(f"\nCipher Summary:")
    print(f"  Strong:   {r1['strong_cipher_count']}")
    print(f"  Weak:     {r1['weak_cipher_count']}")
    print(f"  Insecure: {r1['insecure_cipher_count']}")
    
    if r1['vulnerabilities']:
        print(f"\nVulnerabilities ({len(r1['vulnerabilities'])}):")
        for v in r1['vulnerabilities'][:5]:
            cve = f" ({v.get('cve')})" if v.get('cve') else ""
            print(f"  🔴 {v['name']}{cve} - {v['severity']}")
    
    if r1['grade_reasons']:
        print(f"\nGrade Reasons:")
        for reason in r1['grade_reasons'][:5]:
            print(f"  • {reason}")
    
    # ─────────────────────────────────────────
    # Example 2: TestSSL (Thorough)
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 2: TestSSL (Thorough Scanner)")
    print("─" * 50)
    
    r2 = ssl_tls_analysis(
        tool="testssl",
        target="scanme.nmap.org",
        args=["--fast", "-U"],  # Fast mode + vulnerability checks
        use_cache=False
    )
    
    print(f"Command:   {r2['command']}")
    print(f"Grade:     {r2['grade']}")
    print(f"Exec Time: {r2['execution_time']}s")
    
    print(f"\nHSTS: {'✅ Enabled' if r2['hsts_enabled'] else '❌ Disabled'}")
    if r2['hsts_enabled']:
        print(f"  Max-Age:           {r2.get('hsts_max_age', 'N/A')}")
        print(f"  Include Subdomains: {r2.get('hsts_include_subdomains', False)}")
        print(f"  Preload:           {r2.get('hsts_preload', False)}")
    
    if r2.get('ocsp'):
        print(f"\nOCSP Stapling: {'✅ Enabled' if r2['ocsp'].get('stapling_enabled') else '❌ Disabled'}")
    
    if r2.get('session_resumption'):
        sr = r2['session_resumption']
        print(f"\nSession Resumption:")
        print(f"  Session ID:     {'✅' if sr.get('session_id_supported') else '❌'}")
        print(f"  Session Ticket: {'✅' if sr.get('session_ticket_supported') else '❌'}")
    
    # ─────────────────────────────────────────
    # Example 3: Cache Test
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 3: Cache Performance")
    print("─" * 50)

    # First cacheable call (miss)
    start_miss = time.time()
    _ = ssl_tls_analysis(
        tool="sslscan",
        target="scanme.nmap.org",
        args=["--no-failed"],
        use_cache=True
    )
    miss_time = time.time() - start_miss

    # Second identical call (hit)
    start_hit = time.time()
    r_cached = ssl_tls_analysis(
        tool="sslscan",
        target="scanme.nmap.org",
        args=["--no-failed"],
        use_cache=True
    )
    hit_time = time.time() - start_hit

    print(f"No-cache run:   {r1['execution_time']}s")
    print(f"Cache miss run: {miss_time:.4f}s")
    print(f"Cache hit run:  {hit_time:.4f}s")
    print(f"Speedup:        {miss_time / hit_time:.0f}x" if hit_time > 0 else "Instant")
    
    info = get_cache_info()
    print(f"Cache stats: hits={info.hits}, misses={info.misses}, size={info.currsize}/{info.maxsize}")
    
    # ─────────────────────────────────────────
    # Example 4: Cipher Strength Details
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 4: Cipher Strength Analysis")
    print("─" * 50)
    
    if r1['ciphers']:
        print(f"Total Ciphers: {len(r1['ciphers'])}")
        print("\nSample Ciphers:")
        for c in r1['ciphers'][:10]:
            strength_emoji = {
                "strong": "🟢",
                "acceptable": "🟡",
                "weak": "🟠",
                "insecure": "🔴",
                "unknown": "⚪"
            }.get(c['strength'], "⚪")
            pfs = "✓PFS" if c.get('pfs') else ""
            print(f"  {strength_emoji} {c['name'][:40]:<40} {c['strength']:<10} {pfs}")
    
    # ─────────────────────────────────────────
    # Example 5: Full JSON Output
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("TEST 5: Full JSON Output (truncated)")
    print("─" * 50)
    
    # Create a summary version for display
    summary = {
        "success": r1['success'],
        "tool": r1['tool'],
        "target": r1['target'],
        "grade": r1['grade'],
        "certificate": {
            "subject": r1['certificate'].get('subject') if r1['certificate'] else None,
            "expired": r1['certificate'].get('expired') if r1['certificate'] else None,
        } if r1['certificate'] else None,
        "protocol_count": len(r1['protocols']),
        "cipher_count": len(r1['ciphers']),
        "vulnerability_count": len(r1['vulnerabilities']),
        "grade_reasons": r1['grade_reasons'][:3],
    }
    print(json.dumps(summary, indent=2))
    
    # ─────────────────────────────────────────
    # Example 6: LLM Tool Definition
    # ─────────────────────────────────────────
    print("\n" + "─" * 50)
    print("LLM TOOL DEFINITION")
    print("─" * 50)
    print(json.dumps(SSL_TLS_TOOL_DEFINITION, indent=2))
    
    print("\n" + "=" * 70)
    print("All tests completed!")
    print("=" * 70)
