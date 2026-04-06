import subprocess
import json
import re
import time
import os
import zipfile
import concurrent.futures
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class MobileStaticRequest(BaseModel):
    tool: str
    target: str                         # path to APK / IPA file
    args: list[str] = []
    timeout: int = Field(default=1200, ge=60, le=7200)
    platform: str = "auto"             # android / ios / auto
    output_dir: Optional[str] = None   # decompiled output dir
    api_key: Optional[str] = None      # MobSF API key

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"mobsf", "apktool", "jadx", "class_dump", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        v = v.strip()
        # Must be a file path ending in .apk or .ipa
        if not (v.endswith(".apk") or v.endswith(".ipa")
                or v.endswith(".aab") or v.endswith(".zip")):
            raise ValueError(
                f"Target must be an APK/IPA/AAB file: {v}"
            )
        if not os.path.isfile(v):
            raise ValueError(f"File not found: {v}")
        return v

    @validator("platform")
    def validate_platform(cls, v):
        allowed = {"android", "ios", "auto"}
        if v.lower() not in allowed:
            raise ValueError(f"Platform must be: {allowed}")
        return v.lower()

    @validator("args")
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked   = ["--rm", "-rf", "--delete"]
        for arg in v:
            for c in dangerous:
                if c in arg:
                    raise ValueError(f"Dangerous char '{c}' in: {arg}")
            for f in blocked:
                if arg.strip() == f:
                    raise ValueError(f"Blocked flag: {f}")
        return v


# ── Hardcoded secret finding ──
class SecretFinding(BaseModel):
    file_path: str
    line_number: Optional[int] = None
    secret_type: str                    # AWS key / API key / JWT / password etc.
    value_snippet: str                  # first 12 chars + ...
    full_match: Optional[str] = None    # full matched string (capped 80 chars)
    severity: str = "high"
    confidence: str = "medium"          # low / medium / high
    evidence: list[str] = []


# ── Permission finding ──
class PermissionFinding(BaseModel):
    permission: str
    description: str = ""
    dangerous: bool = False
    protection_level: str = "normal"   # normal / dangerous / signature / privileged
    reason: str = ""
    severity: str = "info"


# ── Exported component ──
class ExportedComponent(BaseModel):
    component_type: str                 # activity / service / receiver / provider
    name: str
    exported: bool = True
    intent_filters: list[str] = []
    permissions_required: list[str] = []
    vulnerable: bool = False
    issues: list[str] = []
    severity: str = "info"


# ── Insecure code finding ──
class CodeFinding(BaseModel):
    file_path: str
    line_number: Optional[int] = None
    rule_id: str
    category: str                       # crypto / network / storage / logging /
                                        # intent / webview / authentication
    title: str
    description: str
    code_snippet: Optional[str] = None
    severity: str = "medium"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: list[str] = []


# ── Network security finding ──
class NetworkFinding(BaseModel):
    finding_type: str                   # cleartext / pinning / nsc / backup
    description: str
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    severity: str = "medium"
    evidence: list[str] = []


# ── App metadata ──
class AppInfo(BaseModel):
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    platform: str = "unknown"
    file_size: Optional[int] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None
    signed: bool = False
    signature_info: Optional[str] = None
    debuggable: bool = False
    allow_backup: bool = False
    network_security_config: bool = False
    uses_cleartext: bool = False
    main_activity: Optional[str] = None
    activities_count: int = 0
    services_count: int = 0
    receivers_count: int = 0
    providers_count: int = 0
    native_libs: list[str] = []
    third_party_libs: list[str] = []


# ── Final result ──
class MobileStaticResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    platform: str = "unknown"
    app_info: Optional[AppInfo] = None
    secrets: list[SecretFinding] = []
    permissions: list[PermissionFinding] = []
    exported_components: list[ExportedComponent] = []
    code_findings: list[CodeFinding] = []
    network_findings: list[NetworkFinding] = []
    total_secrets: int = 0
    total_dangerous_permissions: int = 0
    total_exported: int = 0
    total_code_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    risk_score: int = 0                 # 0-100
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = []


# ══════════════════════════════════════════════════════════════
# 2. SECRET PATTERNS
# ══════════════════════════════════════════════════════════════

SECRET_PATTERNS: list[dict] = [
    # ── Cloud Providers ──
    {"type": "AWS Access Key",
     "pattern": r"AKIA[0-9A-Z]{16}",
     "severity": "critical", "confidence": "high"},
    {"type": "AWS Secret Key",
     "pattern": r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key"
                r"[\s=:\"']+([A-Za-z0-9+/]{40})",
     "severity": "critical", "confidence": "high"},
    {"type": "AWS Session Token",
     "pattern": r"(?i)aws[_\-]?session[_\-]?token[\s=:\"']+([A-Za-z0-9+/=]{100,})",
     "severity": "critical", "confidence": "medium"},
    {"type": "GCP API Key",
     "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "severity": "critical", "confidence": "high"},
    {"type": "GCP Service Account",
     "pattern": r'"type"\s*:\s*"service_account"',
     "severity": "critical", "confidence": "high"},
    {"type": "Azure Storage Key",
     "pattern": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;"
                r"AccountKey=[A-Za-z0-9+/=]{86,}==",
     "severity": "critical", "confidence": "high"},

    # ── Source Control / CI ──
    {"type": "GitHub Token",
     "pattern": r"gh[pousr]_[A-Za-z0-9]{36,255}",
     "severity": "critical", "confidence": "high"},
    {"type": "GitHub OAuth",
     "pattern": r"gho_[A-Za-z0-9]{36}",
     "severity": "critical", "confidence": "high"},
    {"type": "GitLab Token",
     "pattern": r"glpat-[A-Za-z0-9\-_]{20}",
     "severity": "critical", "confidence": "high"},

    # ── Payment ──
    {"type": "Stripe Live Key",
     "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
     "severity": "critical", "confidence": "high"},
    {"type": "Stripe Publishable Key",
     "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
     "severity": "high", "confidence": "high"},
    {"type": "Stripe Test Key",
     "pattern": r"sk_test_[0-9a-zA-Z]{24,}",
     "severity": "medium", "confidence": "high"},
    {"type": "PayPal Client ID",
     "pattern": r"(?i)paypal[_\-\s]?client[_\-\s]?id[\s=:\"']+([A-Za-z0-9\-_]{10,})",
     "severity": "high", "confidence": "medium"},

    # ── Messaging / Communication ──
    {"type": "Slack Token",
     "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
     "severity": "high", "confidence": "high"},
    {"type": "Slack Webhook",
     "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     "severity": "high", "confidence": "high"},
    {"type": "Twilio Account SID",
     "pattern": r"AC[a-fA-F0-9]{32}",
     "severity": "high", "confidence": "medium"},
    {"type": "Twilio Auth Token",
     "pattern": r"(?i)twilio[_\-\s]?auth[_\-\s]?token[\s=:\"']+([a-fA-F0-9]{32})",
     "severity": "critical", "confidence": "high"},
    {"type": "SendGrid API Key",
     "pattern": r"SG\.[a-zA-Z0-9\-_\.]{22,}\.[a-zA-Z0-9\-_\.]{43,}",
     "severity": "critical", "confidence": "high"},
    {"type": "Mailgun API Key",
     "pattern": r"key-[0-9a-zA-Z]{32}",
     "severity": "high", "confidence": "medium"},

    # ── Firebase ──
    {"type": "Firebase API Key",
     "pattern": r"(?i)firebase[_\-\s]?api[_\-\s]?key[\s=:\"']+([A-Za-z0-9\-_]{30,})",
     "severity": "high", "confidence": "high"},
    {"type": "Firebase URL",
     "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com",
     "severity": "medium", "confidence": "high"},
    {"type": "Firebase Project ID",
     "pattern": r"(?i)firebase[_\-\s]?project[_\-\s]?id[\s=:\"']+([A-Za-z0-9\-]+)",
     "severity": "low", "confidence": "medium"},

    # ── Google ──
    {"type": "Google Maps API Key",
     "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "severity": "high", "confidence": "high"},
    {"type": "Google OAuth Client ID",
     "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
     "severity": "medium", "confidence": "high"},
    {"type": "Google OAuth Secret",
     "pattern": r"(?i)google[_\-\s]?client[_\-\s]?secret[\s=:\"']+([A-Za-z0-9\-_]{24,})",
     "severity": "high", "confidence": "medium"},

    # ── Social Media ──
    {"type": "Facebook App Secret",
     "pattern": r"(?i)facebook[_\-\s]?app[_\-\s]?secret[\s=:\"']+([A-Za-z0-9]{32})",
     "severity": "critical", "confidence": "high"},
    {"type": "Twitter API Secret",
     "pattern": r"(?i)twitter[_\-\s]?(?:api[_\-\s]?)?secret[\s=:\"']+([A-Za-z0-9]{35,44})",
     "severity": "high", "confidence": "medium"},

    # ── Mobile Specific ──
    {"type": "Apple App Store Connect API Key",
     "pattern": r"AuthKey_[A-Z0-9]{10}\.p8",
     "severity": "critical", "confidence": "high"},
    {"type": "Apple Team ID",
     "pattern": r"(?i)team[_\-\s]?id[\s=:\"']+([A-Z0-9]{10})",
     "severity": "low", "confidence": "medium"},
    {"type": "Android Keystore Password",
     "pattern": r"(?i)keystore[_\-\s]?pass(?:word)?[\s=:\"']+(\S{4,})",
     "severity": "critical", "confidence": "medium"},
    {"type": "Android Key Alias",
     "pattern": r"(?i)key[_\-\s]?alias[\s=:\"']+(\S{3,})",
     "severity": "medium", "confidence": "low"},

    # ── Crypto / JWT ──
    {"type": "JWT Token",
     "pattern": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*",
     "severity": "high", "confidence": "high"},
    {"type": "JWT Secret",
     "pattern": r"(?i)jwt[_\-\s]?secret[\s=:\"']+(\S{8,})",
     "severity": "critical", "confidence": "high"},
    {"type": "RSA Private Key",
     "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
     "severity": "critical", "confidence": "high"},
    {"type": "Private Key",
     "pattern": r"-----BEGIN (?:EC|DSA|OPENSSH) PRIVATE KEY-----",
     "severity": "critical", "confidence": "high"},
    {"type": "Certificate",
     "pattern": r"-----BEGIN CERTIFICATE-----",
     "severity": "low", "confidence": "high"},

    # ── Database ──
    {"type": "Database Connection String",
     "pattern": r"(?i)(mysql|postgresql|mongodb|mssql|redis|sqlite)"
                r"://[^:\s]+:[^@\s]+@[^\s\"']+",
     "severity": "critical", "confidence": "high"},
    {"type": "MongoDB URI",
     "pattern": r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s\"']+",
     "severity": "critical", "confidence": "high"},

    # ── Generic Secrets ──
    {"type": "Generic API Key",
     "pattern": r"(?i)api[_\-\s]?key[\s=:\"']+([A-Za-z0-9\-_\.]{16,})",
     "severity": "high", "confidence": "medium"},
    {"type": "Generic Secret",
     "pattern": r"(?i)(?:secret|api_secret|client_secret|app_secret)"
                r"[\s=:\"']+([A-Za-z0-9\-_\.!@#$%]{8,})",
     "severity": "high", "confidence": "medium"},
    {"type": "Generic Password",
     "pattern": r"(?i)(?:password|passwd|pwd|pass)"
                r"[\s=:\"']+([^\s\"']{6,})",
     "severity": "high", "confidence": "low"},
    {"type": "Basic Auth in URL",
     "pattern": r"https?://[^:\s]+:[^@\s]+@",
     "severity": "high", "confidence": "high"},
    {"type": "Bearer Token",
     "pattern": r"(?i)bearer[\s]+([A-Za-z0-9\-_\.]{20,})",
     "severity": "high", "confidence": "medium"},
    {"type": "Private IP Address",
     "pattern": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3})",
     "severity": "low", "confidence": "medium"},
]


# ══════════════════════════════════════════════════════════════
# 3. ANDROID DANGEROUS PERMISSIONS
# ══════════════════════════════════════════════════════════════

DANGEROUS_PERMISSIONS: dict[str, dict] = {
    # Location
    "android.permission.ACCESS_FINE_LOCATION": {
        "desc": "Access precise GPS location",
        "severity": "high", "group": "LOCATION",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "desc": "Access approximate location",
        "severity": "medium", "group": "LOCATION",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "desc": "Access location in background",
        "severity": "high", "group": "LOCATION",
    },
    # Contacts
    "android.permission.READ_CONTACTS": {
        "desc": "Read device contacts",
        "severity": "high", "group": "CONTACTS",
    },
    "android.permission.WRITE_CONTACTS": {
        "desc": "Modify device contacts",
        "severity": "high", "group": "CONTACTS",
    },
    # Phone
    "android.permission.READ_PHONE_STATE": {
        "desc": "Access phone state / IMEI",
        "severity": "high", "group": "PHONE",
    },
    "android.permission.CALL_PHONE": {
        "desc": "Make phone calls",
        "severity": "high", "group": "PHONE",
    },
    "android.permission.READ_CALL_LOG": {
        "desc": "Read call history",
        "severity": "high", "group": "CALL_LOG",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "desc": "Intercept outgoing calls",
        "severity": "critical", "group": "PHONE",
    },
    # SMS
    "android.permission.SEND_SMS": {
        "desc": "Send SMS messages",
        "severity": "high", "group": "SMS",
    },
    "android.permission.RECEIVE_SMS": {
        "desc": "Receive SMS messages",
        "severity": "high", "group": "SMS",
    },
    "android.permission.READ_SMS": {
        "desc": "Read SMS messages",
        "severity": "high", "group": "SMS",
    },
    # Camera / Media
    "android.permission.CAMERA": {
        "desc": "Access device camera",
        "severity": "high", "group": "CAMERA",
    },
    "android.permission.RECORD_AUDIO": {
        "desc": "Record audio / use microphone",
        "severity": "high", "group": "MICROPHONE",
    },
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": {
        "desc": "Read files from external storage",
        "severity": "medium", "group": "STORAGE",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "desc": "Write files to external storage",
        "severity": "medium", "group": "STORAGE",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "desc": "Access all files (broad storage access)",
        "severity": "high", "group": "STORAGE",
    },
    # Biometric / Authentication
    "android.permission.USE_BIOMETRIC": {
        "desc": "Use biometric authentication",
        "severity": "medium", "group": "BIOMETRIC",
    },
    "android.permission.USE_FINGERPRINT": {
        "desc": "Use fingerprint authentication (deprecated)",
        "severity": "medium", "group": "BIOMETRIC",
    },
    # System
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "desc": "Draw over other apps",
        "severity": "high", "group": "SYSTEM",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "desc": "Install unknown apps",
        "severity": "critical", "group": "SYSTEM",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "desc": "Run at device startup",
        "severity": "medium", "group": "SYSTEM",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "desc": "Accessibility service (can read screen)",
        "severity": "critical", "group": "SYSTEM",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "desc": "Device administrator access",
        "severity": "critical", "group": "ADMIN",
    },
    "android.permission.MASTER_CLEAR": {
        "desc": "Factory reset device",
        "severity": "critical", "group": "ADMIN",
    },
    # Network
    "android.permission.CHANGE_NETWORK_STATE": {
        "desc": "Change network connectivity",
        "severity": "low", "group": "NETWORK",
    },
    "android.permission.NFC": {
        "desc": "Access NFC hardware",
        "severity": "medium", "group": "NFC",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "desc": "Connect to Bluetooth devices",
        "severity": "medium", "group": "BLUETOOTH",
    },
    # Accounts
    "android.permission.GET_ACCOUNTS": {
        "desc": "Access accounts configured on device",
        "severity": "medium", "group": "ACCOUNTS",
    },
    "android.permission.AUTHENTICATE_ACCOUNTS": {
        "desc": "Create accounts and set passwords",
        "severity": "high", "group": "ACCOUNTS",
    },
    # Calendar
    "android.permission.READ_CALENDAR": {
        "desc": "Read calendar events",
        "severity": "medium", "group": "CALENDAR",
    },
    "android.permission.WRITE_CALENDAR": {
        "desc": "Add/modify calendar events",
        "severity": "medium", "group": "CALENDAR",
    },
}

# iOS permissions (Privacy keys in Info.plist)
IOS_PRIVACY_PERMISSIONS: dict[str, dict] = {
    "NSCameraUsageDescription": {
        "desc": "Camera access", "severity": "high",
    },
    "NSMicrophoneUsageDescription": {
        "desc": "Microphone access", "severity": "high",
    },
    "NSLocationAlwaysUsageDescription": {
        "desc": "Location always (background)", "severity": "high",
    },
    "NSLocationWhenInUseUsageDescription": {
        "desc": "Location when in use", "severity": "medium",
    },
    "NSContactsUsageDescription": {
        "desc": "Contacts access", "severity": "high",
    },
    "NSPhotoLibraryUsageDescription": {
        "desc": "Photo library access", "severity": "medium",
    },
    "NSHealthShareUsageDescription": {
        "desc": "Health data access", "severity": "high",
    },
    "NSFaceIDUsageDescription": {
        "desc": "Face ID biometric", "severity": "medium",
    },
    "NSMotionUsageDescription": {
        "desc": "Motion sensors", "severity": "low",
    },
    "NSBluetoothAlwaysUsageDescription": {
        "desc": "Bluetooth always", "severity": "medium",
    },
    "NSLocalNetworkUsageDescription": {
        "desc": "Local network scanning", "severity": "medium",
    },
    "NSSpeechRecognitionUsageDescription": {
        "desc": "Speech recognition", "severity": "medium",
    },
    "NSTrackingUsageDescription": {
        "desc": "App tracking / ATT", "severity": "high",
    },
    "NSUserTrackingUsageDescription": {
        "desc": "User tracking across apps", "severity": "high",
    },
}


# ══════════════════════════════════════════════════════════════
# 4. INSECURE CODE RULES
# ══════════════════════════════════════════════════════════════

CODE_RULES: list[dict] = [

    # ── Cryptography ──
    {"id": "CRYPTO001",
     "category": "crypto",
     "title": "Weak Cipher — DES/3DES",
     "pattern": r"(?i)(DES|DESedeKeySpec|TripleDES|DESede)"
                r"(?!/\*|DESEDE_CBC)",
     "severity": "high",
     "cwe": "CWE-327",
     "owasp": "M5",
     "desc": "DES/3DES are deprecated weak ciphers. Use AES-256-GCM.",
     "fix": ["Replace DES/3DES with AES-256-GCM",
             "Use javax.crypto.Cipher with AES/GCM/NoPadding"]},
    {"id": "CRYPTO002",
     "category": "crypto",
     "title": "Weak Cipher — RC4/RC2",
     "pattern": r'(?i)"(RC4|RC2|ARCFOUR)"',
     "severity": "high",
     "cwe": "CWE-327",
     "owasp": "M5",
     "desc": "RC4/RC2 are broken stream ciphers.",
     "fix": ["Use AES-256-GCM instead"]},
    {"id": "CRYPTO003",
     "category": "crypto",
     "title": "ECB Mode Encryption",
     "pattern": r'(?i)(AES/ECB|Cipher\.getInstance\("AES"\))',
     "severity": "high",
     "cwe": "CWE-327",
     "owasp": "M5",
     "desc": "AES in ECB mode reveals patterns in plaintext.",
     "fix": ["Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with random IV"]},
    {"id": "CRYPTO004",
     "category": "crypto",
     "title": "Weak Hashing — MD5",
     "pattern": r"(?i)(MessageDigest\.getInstance\(\"MD5\"\)"
                r"|md5\(|\.md5)",
     "severity": "high",
     "cwe": "CWE-328",
     "owasp": "M5",
     "desc": "MD5 is cryptographically broken.",
     "fix": ["Use SHA-256 or SHA-3 for hashing",
             "Use Argon2/bcrypt/scrypt for passwords"]},
    {"id": "CRYPTO005",
     "category": "crypto",
     "title": "Weak Hashing — SHA-1",
     "pattern": r'(?i)MessageDigest\.getInstance\("SHA-1"\)',
     "severity": "medium",
     "cwe": "CWE-328",
     "owasp": "M5",
     "desc": "SHA-1 is deprecated and collision-vulnerable.",
     "fix": ["Use SHA-256 or SHA-3"]},
    {"id": "CRYPTO006",
     "category": "crypto",
     "title": "Hardcoded IV / Salt",
     "pattern": r"(?i)(new IvParameterSpec\(new byte\[\]\{"
                r"|IvParameterSpec\(\"[^\"]+\"\."
                r"|static.*iv\s*=\s*new byte\[\]"
                r"|final.*salt\s*=\s*\"[^\"]+\")",
     "severity": "high",
     "cwe": "CWE-329",
     "owasp": "M5",
     "desc": "Hardcoded IV or salt defeats the purpose of encryption.",
     "fix": ["Generate random IV using SecureRandom for each encryption",
             "Never reuse IV with the same key"]},
    {"id": "CRYPTO007",
     "category": "crypto",
     "title": "Insecure Random — java.util.Random",
     "pattern": r"(?i)(new Random\(\)|Math\.random\(\)"
                r"|java\.util\.Random)",
     "severity": "medium",
     "cwe": "CWE-338",
     "owasp": "M5",
     "desc": "java.util.Random is not cryptographically secure.",
     "fix": ["Use java.security.SecureRandom for security-sensitive operations"]},
    {"id": "CRYPTO008",
     "category": "crypto",
     "title": "Insecure Key Size",
     "pattern": r"(?i)KeyGenerator\.getInstance.*\b(512|768|1024)\b",
     "severity": "high",
     "cwe": "CWE-326",
     "owasp": "M5",
     "desc": "RSA/DH key size below 2048 bits is insecure.",
     "fix": ["Use RSA >= 2048 bits", "Use EC P-256 or P-384 as alternative"]},

    # ── Network / SSL ──
    {"id": "NET001",
     "category": "network",
     "title": "TrustAllCerts — Disabled SSL Validation",
     "pattern": r"(?i)(TrustAllCerts|X509TrustManager\(\)|"
                r"checkServerTrusted.*\{\s*\}|"
                r"setHostnameVerifier.*ALLOW_ALL|"
                r"ALLOW_ALL_HOSTNAME_VERIFIER|"
                r"NullHostnameVerifier|"
                r"AllowAllHostnameVerifier)",
     "severity": "critical",
     "cwe": "CWE-295",
     "owasp": "M3",
     "desc": "SSL/TLS certificate validation disabled. "
             "Allows MITM attacks.",
     "fix": ["Remove TrustAllCerts implementation",
             "Use the default TrustManager",
             "Implement proper certificate pinning"]},
    {"id": "NET002",
     "category": "network",
     "title": "HTTP URL (Cleartext Traffic)",
     "pattern": r'(?i)(http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.)[a-zA-Z])',
     "severity": "high",
     "cwe": "CWE-319",
     "owasp": "M3",
     "desc": "Cleartext HTTP traffic transmits data without encryption.",
     "fix": ["Use HTTPS for all network communication",
             "Set android:usesCleartextTraffic=false in manifest"]},
    {"id": "NET003",
     "category": "network",
     "title": "Certificate Pinning Disabled",
     "pattern": r"(?i)(setCertificateChainValidator.*null"
                r"|sslSocketFactory.*null"
                r"|hostnameVerifier.*null"
                r"|setSSLSocketFactory.*null)",
     "severity": "high",
     "cwe": "CWE-295",
     "owasp": "M3",
     "desc": "SSL pinning explicitly disabled.",
     "fix": ["Implement certificate pinning via OkHttp CertificatePinner",
             "Use TrustKit for iOS"]},
    {"id": "NET004",
     "category": "network",
     "title": "WebSocket Insecure (ws://)",
     "pattern": r'ws://[a-zA-Z]',
     "severity": "high",
     "cwe": "CWE-319",
     "owasp": "M3",
     "desc": "Unencrypted WebSocket connection.",
     "fix": ["Use wss:// (WebSocket Secure) instead of ws://"]},
    {"id": "NET005",
     "category": "network",
     "title": "Debug Proxy / Fiddler/Burp",
     "pattern": r"(?i)(Fiddler|BurpSuite|HttpCanary|Charles|"
                r"Packet Capture|Wireshark|proxy.*debug)",
     "severity": "low",
     "cwe": "CWE-319",
     "owasp": "M3",
     "desc": "Debug proxy configuration found in code.",
     "fix": ["Remove all proxy/debug network configs before release"]},

    # ── Storage ──
    {"id": "STORE001",
     "category": "storage",
     "title": "SharedPreferences — Sensitive Data",
     "pattern": r"(?i)getSharedPreferences.*(?:password|secret|token|key|pin|auth)",
     "severity": "high",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Sensitive data stored in SharedPreferences (plaintext).",
     "fix": ["Use EncryptedSharedPreferences from Jetpack Security",
             "Use Android Keystore for key management"]},
    {"id": "STORE002",
     "category": "storage",
     "title": "World-Readable/Writable File",
     "pattern": r"(?i)(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
                r"|openFileOutput.*MODE_WORLD)",
     "severity": "high",
     "cwe": "CWE-732",
     "owasp": "M2",
     "desc": "File created with world-readable or world-writable permissions.",
     "fix": ["Use MODE_PRIVATE for file creation",
             "Never use MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE"]},
    {"id": "STORE003",
     "category": "storage",
     "title": "External Storage — Sensitive Data",
     "pattern": r"(?i)(getExternalStorage|Environment\.getExternal"
                r"|externalFilesDir.*(?:password|secret|token|key|pin))",
     "severity": "high",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Sensitive data written to external storage (SD card) — "
             "accessible by other apps.",
     "fix": ["Use internal storage for sensitive data",
             "Encrypt data before writing to external storage"]},
    {"id": "STORE004",
     "category": "storage",
     "title": "SQLite Database — No Encryption",
     "pattern": r"(?i)(openOrCreate(?:Database)|SQLiteDatabase\.open"
                r"(?!.*cipher|.*encrypt))",
     "severity": "medium",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "SQLite database opened without encryption.",
     "fix": ["Use SQLCipher for database encryption",
             "Use Room with SQLCipher integration"]},
    {"id": "STORE005",
     "category": "storage",
     "title": "Clipboard Sensitive Data",
     "pattern": r"(?i)(ClipboardManager.*(?:password|token|key|secret|pin)"
                r"|setPrimaryClip.*(?:password|token))",
     "severity": "medium",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Sensitive data written to clipboard — accessible by other apps.",
     "fix": ["Avoid copying sensitive data to clipboard",
             "Clear clipboard after use"]},
    {"id": "STORE006",
     "category": "storage",
     "title": "Realm Database — No Encryption",
     "pattern": r"(?i)RealmConfiguration\.Builder\(\)"
                r"(?!.*encryptionKey)",
     "severity": "medium",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Realm database configured without encryption.",
     "fix": ["Set encryptionKey in RealmConfiguration.Builder"]},

    # ── Logging ──
    {"id": "LOG001",
     "category": "logging",
     "title": "Sensitive Data in Logs",
     "pattern": r"(?i)(Log\.[dveiw]\(.*(?:password|passwd|secret|token|"
                r"key|pin|auth|credit|ssn|dob|email)|"
                r"System\.out\.print.*(?:password|token|secret))",
     "severity": "high",
     "cwe": "CWE-532",
     "owasp": "M2",
     "desc": "Sensitive data written to application logs.",
     "fix": ["Remove all sensitive data from log statements",
             "Use ProGuard to strip Log calls in release builds",
             "Implement a log wrapper that strips sensitive fields"]},
    {"id": "LOG002",
     "category": "logging",
     "title": "Debug Logging Enabled",
     "pattern": r"(?i)(BuildConfig\.DEBUG.*Log\.|"
                r"if.*debug.*Log\.|"
                r"Log\.d\(|android\.util\.Log\.d)",
     "severity": "low",
     "cwe": "CWE-532",
     "owasp": "M2",
     "desc": "Debug logging present — may leak info in production.",
     "fix": ["Strip debug logs in release build using ProGuard/R8",
             "Use Timber with a release tree that disables logging"]},

    # ── WebView ──
    {"id": "WEB001",
     "category": "webview",
     "title": "WebView — JavaScript Enabled",
     "pattern": r"(?i)setJavaScriptEnabled\(true\)",
     "severity": "medium",
     "cwe": "CWE-749",
     "owasp": "M1",
     "desc": "JavaScript enabled in WebView. "
             "XSS in loaded content can access native bridges.",
     "fix": ["Disable JavaScript if not required",
             "Validate and sanitize all content loaded in WebView",
             "Use addJavascriptInterface with @JavascriptInterface only on safe methods"]},
    {"id": "WEB002",
     "category": "webview",
     "title": "WebView — addJavascriptInterface",
     "pattern": r"(?i)addJavascriptInterface\(",
     "severity": "high",
     "cwe": "CWE-749",
     "owasp": "M1",
     "desc": "JavaScript interface exposes native Java methods to WebView. "
             "XSS leads to RCE on API < 17.",
     "fix": ["Only expose @JavascriptInterface annotated methods",
             "Validate all data received from JavaScript",
             "Target API >= 17"]},
    {"id": "WEB003",
     "category": "webview",
     "title": "WebView — File Access",
     "pattern": r"(?i)(setAllowFileAccess\(true\)"
                r"|setAllowFileAccessFromFileURLs\(true\)"
                r"|setAllowUniversalAccessFromFileURLs\(true\))",
     "severity": "high",
     "cwe": "CWE-200",
     "owasp": "M1",
     "desc": "WebView file access enabled — local file theft via XSS.",
     "fix": ["Set setAllowFileAccess(false)",
             "Set setAllowFileAccessFromFileURLs(false)",
             "Set setAllowUniversalAccessFromFileURLs(false)"]},
    {"id": "WEB004",
     "category": "webview",
     "title": "WebView — Ignoring SSL Errors",
     "pattern": r"(?i)(onReceivedSslError.*handler\.proceed"
                r"|proceed\(\).*ssl)",
     "severity": "critical",
     "cwe": "CWE-295",
     "owasp": "M3",
     "desc": "WebView ignores SSL errors — full MITM vulnerability.",
     "fix": ["Call handler.cancel() in onReceivedSslError",
             "Never call handler.proceed() on SSL errors in production"]},
    {"id": "WEB005",
     "category": "webview",
     "title": "WebView — setPluginState Enabled",
     "pattern": r"(?i)setPluginState\(PluginState\.ON\)",
     "severity": "medium",
     "cwe": "CWE-749",
     "owasp": "M1",
     "desc": "WebView plugins (Flash etc.) enabled — unnecessary attack surface.",
     "fix": ["Remove setPluginState or set to OFF"]},

    # ── Intent / IPC ──
    {"id": "INTENT001",
     "category": "intent",
     "title": "Implicit Intent with Sensitive Data",
     "pattern": r"(?i)(new Intent\(\)(?!.*setPackage)"
                r".*(?:putExtra.*(?:password|token|key|secret)"
                r"|setData.*(?:password|token)))",
     "severity": "high",
     "cwe": "CWE-927",
     "owasp": "M1",
     "desc": "Implicit intent carrying sensitive data — "
             "any app can intercept.",
     "fix": ["Use explicit intents (setPackage/setComponent)",
             "Never put sensitive data in intents",
             "Use LocalBroadcastManager for local broadcasts"]},
    {"id": "INTENT002",
     "category": "intent",
     "title": "Pending Intent — Mutable",
     "pattern": r"(?i)PendingIntent\.(getActivity|getBroadcast|getService)"
                r"\(.*FLAG_MUTABLE",
     "severity": "medium",
     "cwe": "CWE-927",
     "owasp": "M1",
     "desc": "Mutable PendingIntent can be hijacked by malicious apps.",
     "fix": ["Use FLAG_IMMUTABLE for PendingIntents (API 23+)",
             "Only use FLAG_MUTABLE when absolutely necessary (AlarmManager, etc.)"]},
    {"id": "INTENT003",
     "category": "intent",
     "title": "Dynamic Broadcast Receiver",
     "pattern": r"(?i)registerReceiver\((?!.*RECEIVER_NOT_EXPORTED)",
     "severity": "medium",
     "cwe": "CWE-927",
     "owasp": "M1",
     "desc": "Dynamic BroadcastReceiver without export restriction.",
     "fix": ["Use RECEIVER_NOT_EXPORTED flag (API 33+)",
             "Validate intent data before processing"]},

    # ── Authentication ──
    {"id": "AUTH001",
     "category": "authentication",
     "title": "Biometric Authentication — Weak Fallback",
     "pattern": r"(?i)(BiometricManager|BiometricPrompt)"
                r".*BIOMETRIC_STRONG",
     "severity": "low",
     "cwe": "CWE-287",
     "owasp": "M4",
     "desc": "Biometric auth configured — verify fallback is also secure.",
     "fix": ["Use BiometricManager.Authenticators.BIOMETRIC_STRONG",
             "Do not allow device credential (PIN/pattern) as fallback "
             "for high-security operations"]},
    {"id": "AUTH002",
     "category": "authentication",
     "title": "Root Detection Bypass",
     "pattern": r"(?i)(isRooted|checkRoot|detectRoot|RootBeer"
                r"|SuFile|su binary|superuser)",
     "severity": "medium",
     "cwe": "CWE-919",
     "owasp": "M8",
     "desc": "Root detection implementation found — verify it cannot be bypassed.",
     "fix": ["Use multiple root detection methods",
             "Use SafetyNet/Play Integrity API",
             "Combine with runtime application self-protection (RASP)"]},
    {"id": "AUTH003",
     "category": "authentication",
     "title": "Emulator Detection",
     "pattern": r"(?i)(isEmulator|Build\.FINGERPRINT.*generic"
                r"|Build\.MODEL.*sdk|EMULATOR|goldfish)",
     "severity": "low",
     "cwe": "CWE-919",
     "owasp": "M8",
     "desc": "Emulator detection found — verify robustness.",
     "fix": ["Combine multiple emulator signals",
             "Use Play Integrity API for device attestation"]},
    {"id": "AUTH004",
     "category": "authentication",
     "title": "Insecure Token Storage",
     "pattern": r"(?i)(SharedPreferences.*(?:token|jwt|bearer|auth)"
                r"|getDefaultSharedPreferences.*token)",
     "severity": "high",
     "cwe": "CWE-312",
     "owasp": "M4",
     "desc": "Authentication tokens stored in insecure SharedPreferences.",
     "fix": ["Store tokens in Android Keystore",
             "Use EncryptedSharedPreferences",
             "For iOS: use Keychain"]},

    # ── iOS Specific ──
    {"id": "IOS001",
     "category": "ios",
     "title": "NSLog — Sensitive Data",
     "pattern": r"NSLog\(@.*(?:password|token|secret|key|pin|auth)",
     "severity": "high",
     "cwe": "CWE-532",
     "owasp": "M2",
     "desc": "Sensitive data logged via NSLog.",
     "fix": ["Remove sensitive data from NSLog calls",
             "Use os_log with privacy annotations: %{private}@"]},
    {"id": "IOS002",
     "category": "ios",
     "title": "Keychain — kSecAttrAccessibleAlways",
     "pattern": r"kSecAttrAccessibleAlways(?!WhenPasscodeSet)",
     "severity": "high",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Keychain item accessible even when device is locked.",
     "fix": ["Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
             "Use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly "
             "for maximum security"]},
    {"id": "IOS003",
     "category": "ios",
     "title": "UIPasteboard — Sensitive Data",
     "pattern": r"UIPasteboard.*(?:password|token|secret|key|pin)",
     "severity": "medium",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Sensitive data written to clipboard.",
     "fix": ["Avoid writing sensitive data to UIPasteboard",
             "Clear clipboard contents after use"]},
    {"id": "IOS004",
     "category": "ios",
     "title": "AllowArbitraryLoads — ATS Disabled",
     "pattern": r"NSAllowsArbitraryLoads.*true|NSExceptionDomains",
     "severity": "high",
     "cwe": "CWE-319",
     "owasp": "M3",
     "desc": "App Transport Security disabled — allows HTTP traffic.",
     "fix": ["Remove NSAllowsArbitraryLoads",
             "Use specific NSExceptionDomains only for required domains",
             "Require HTTPS for all connections"]},
    {"id": "IOS005",
     "category": "ios",
     "title": "WKWebView — evaluateJavaScript",
     "pattern": r"evaluateJavaScript\(",
     "severity": "medium",
     "cwe": "CWE-749",
     "owasp": "M1",
     "desc": "JavaScript evaluated in WKWebView — "
             "potential for XSS and data injection.",
     "fix": ["Validate and sanitize all JS evaluated in WebView",
             "Use message handlers instead of evaluateJavaScript where possible"]},
    {"id": "IOS006",
     "category": "ios",
     "title": "UserDefaults — Sensitive Data",
     "pattern": r"UserDefaults\.standard\.(set|string|integer).*"
                r"(?:password|token|secret|key|pin|auth)",
     "severity": "high",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "Sensitive data stored in NSUserDefaults (plaintext).",
     "fix": ["Store sensitive data in iOS Keychain",
             "Use CryptoKit to encrypt before storing in UserDefaults"]},
    {"id": "IOS007",
     "category": "ios",
     "title": "Jailbreak Detection Missing or Weak",
     "pattern": r"(?i)(fileExists.*cydia|fileExists.*substrate"
                r"|canOpenURL.*cydia|jailbreak|jailbroken)",
     "severity": "medium",
     "cwe": "CWE-919",
     "owasp": "M8",
     "desc": "Jailbreak detection implementation found — verify robustness.",
     "fix": ["Use multiple jailbreak detection vectors",
             "Use Apple DeviceCheck / App Attest",
             "Implement RASP solutions"]},

    # ── General Android ──
    {"id": "ANDROID001",
     "category": "android",
     "title": "android:debuggable=true",
     "pattern": r'android:debuggable="true"',
     "severity": "critical",
     "cwe": "CWE-489",
     "owasp": "M7",
     "desc": "Application is debuggable — allows attaching debugger, "
             "ADB backup, extracting data.",
     "fix": ["Set android:debuggable=false in production manifest",
             "Let build system manage this via buildType release config"]},
    {"id": "ANDROID002",
     "category": "android",
     "title": "android:allowBackup=true",
     "pattern": r'android:allowBackup="true"',
     "severity": "medium",
     "cwe": "CWE-312",
     "owasp": "M2",
     "desc": "ADB backup enabled — allows extraction of app data.",
     "fix": ["Set android:allowBackup=false",
             "If backup needed, use fullBackupContent with exclude rules"]},
    {"id": "ANDROID003",
     "category": "android",
     "title": "Exported Activity Without Permission",
     "pattern": r'(?:<activity[^>]*android:exported="true"[^>]*(?!android:permission))',
     "severity": "high",
     "cwe": "CWE-926",
     "owasp": "M1",
     "desc": "Activity exported without permission restriction — "
             "any app can launch it.",
     "fix": ["Add android:permission to exported components",
             "Set android:exported=false if external access not needed"]},
    {"id": "ANDROID004",
     "category": "android",
     "title": "Content Provider — No Permission",
     "pattern": r'(?:<provider[^>]*android:exported="true"'
                r'(?:(?!android:(?:read|write)Permission)[^>])*>)',
     "severity": "high",
     "cwe": "CWE-926",
     "owasp": "M1",
     "desc": "Content provider exported without read/writePermission.",
     "fix": ["Add android:readPermission and android:writePermission",
             "Set android:exported=false if external access not required",
             "Validate all SQL query inputs in ContentProvider"]},
    {"id": "ANDROID005",
     "category": "android",
     "title": "StrictMode in Production",
     "pattern": r"(?i)StrictMode\.(setThread|setVm)Policy",
     "severity": "low",
     "cwe": "CWE-200",
     "owasp": "M7",
     "desc": "StrictMode enabled — should be debug-only.",
     "fix": ["Wrap StrictMode in BuildConfig.DEBUG check"]},
    {"id": "ANDROID006",
     "category": "android",
     "title": "Reflection — Class Loading",
     "pattern": r"(?i)(DexClassLoader|PathClassLoader|InMemoryDex"
                r"|loadClass|forName\(.*getClass)",
     "severity": "medium",
     "cwe": "CWE-470",
     "owasp": "M7",
     "desc": "Dynamic class loading — potential code injection vector.",
     "fix": ["Validate class names before loading",
             "Use signatures to verify loaded classes",
             "Avoid loading code from external/untrusted sources"]},
    {"id": "ANDROID007",
     "category": "android",
     "title": "Runtime.exec() — Command Execution",
     "pattern": r"(?i)(Runtime\.getRuntime\(\)\.exec"
                r"|ProcessBuilder\(|exec\(new String\[)",
     "severity": "high",
     "cwe": "CWE-78",
     "owasp": "M1",
     "desc": "Shell command execution from app code.",
     "fix": ["Avoid Runtime.exec() with user-controlled input",
             "Use ProcessBuilder with explicit argument array",
             "Never concatenate user input into shell commands"]},
]


# ══════════════════════════════════════════════════════════════
# 5. APK ANALYZER (Android)
# ══════════════════════════════════════════════════════════════

def parse_android_manifest(manifest_content: str) -> tuple[AppInfo, list[PermissionFinding],
                                                            list[ExportedComponent]]:
    """
    Parse AndroidManifest.xml content.
    Extract: package, permissions, exported components, security flags.
    """
    app_info   = AppInfo(platform="android")
    perms:     list[PermissionFinding]  = []
    exported:  list[ExportedComponent]  = []

    # Package name
    pkg = re.search(r'package="([^"]+)"', manifest_content)
    if pkg:
        app_info.package_name = pkg.group(1)

    # Version
    vn = re.search(r'android:versionName="([^"]+)"', manifest_content)
    vc = re.search(r'android:versionCode="([^"]+)"', manifest_content)
    if vn:
        app_info.version_name = vn.group(1)
    if vc:
        app_info.version_code = vc.group(1)

    # SDK versions
    min_sdk  = re.search(r'android:minSdkVersion="([^"]+)"', manifest_content)
    tgt_sdk  = re.search(r'android:targetSdkVersion="([^"]+)"', manifest_content)
    if min_sdk:
        app_info.min_sdk = min_sdk.group(1)
    if tgt_sdk:
        app_info.target_sdk = tgt_sdk.group(1)

    # Security flags
    app_info.debuggable   = bool(re.search(
        r'android:debuggable="true"', manifest_content))
    app_info.allow_backup = bool(re.search(
        r'android:allowBackup="true"', manifest_content))
    app_info.uses_cleartext = bool(re.search(
        r'android:usesCleartextTraffic="true"', manifest_content))
    app_info.network_security_config = bool(re.search(
        r'android:networkSecurityConfig', manifest_content))

    # Main activity
    ma = re.search(r'<activity[^>]+android:name="([^"]+)"[^>]*>'
                   r'.*?MAIN.*?</activity>', manifest_content, re.DOTALL)
    if ma:
        app_info.main_activity = ma.group(1)

    # Permissions
    for m in re.finditer(
        r'<uses-permission(?:\s+android:maxSdkVersion="[^"]*")?'
        r'\s+android:name="([^"]+)"',
        manifest_content
    ):
        perm_name = m.group(1)
        perm_info = DANGEROUS_PERMISSIONS.get(perm_name, {})
        pf = PermissionFinding(
            permission=perm_name,
            description=perm_info.get("desc", ""),
            dangerous=bool(perm_info),
            protection_level="dangerous" if perm_info else "normal",
            reason=perm_info.get("group", ""),
            severity=perm_info.get("severity", "info"),
        )
        perms.append(pf)

    # Components
    component_map = {
        "activity": r'<activity([^>]+)>(.*?)</activity>',
        "service":  r'<service([^>]+)>(.*?)</service>',
        "receiver": r'<receiver([^>]+)>(.*?)</receiver>',
        "provider": r'<provider([^>]+)>(.*?)</provider>',
    }

    for comp_type, pattern in component_map.items():
        for m in re.finditer(pattern, manifest_content, re.DOTALL):
            attrs     = m.group(1)
            body      = m.group(2)
            name_m    = re.search(r'android:name="([^"]+)"', attrs)
            name      = name_m.group(1) if name_m else "unknown"

            # Determine exported status
            exp_m = re.search(r'android:exported="(true|false)"', attrs)
            if exp_m:
                is_exported = exp_m.group(1) == "true"
            else:
                # Implicit export if intent-filter present
                is_exported = "<intent-filter>" in body

            # Permission required
            perm_m = re.search(r'android:permission="([^"]+)"', attrs)
            req_perm = [perm_m.group(1)] if perm_m else []

            # Intent filters
            intent_filters = re.findall(
                r'<action[^>]+android:name="([^"]+)"', body
            )

            comp = ExportedComponent(
                component_type=comp_type,
                name=name,
                exported=is_exported,
                intent_filters=intent_filters,
                permissions_required=req_perm,
            )

            # Security checks
            if is_exported and not req_perm:
                comp.vulnerable = True
                comp.issues.append(
                    f"Exported {comp_type} '{name}' has no permission restriction"
                )
                comp.severity = "high"

                if comp_type == "provider":
                    comp.issues.append(
                        "Exported ContentProvider without readPermission/"
                        "writePermission — data may be accessible to other apps"
                    )
                    comp.severity = "critical"

                if comp_type == "activity" and any(
                    "MAIN" in f or "LAUNCHER" in f
                    for f in intent_filters
                ):
                    comp.severity = "info"    # main activity is expected to export

            if is_exported:
                exported.append(comp)

            # Count
            if comp_type == "activity":
                app_info.activities_count += 1
            elif comp_type == "service":
                app_info.services_count += 1
            elif comp_type == "receiver":
                app_info.receivers_count += 1
            elif comp_type == "provider":
                app_info.providers_count += 1

    return app_info, perms, exported


def extract_apk(apk_path: str, output_dir: str) -> dict[str, str]:
    """
    Extract APK (it's a ZIP) and return {filename: content} for text files.
    Reads: AndroidManifest.xml (binary decoded), classes.dex references,
    res/values/strings.xml, assets/*, shared_prefs/*, lib/.
    """
    extracted: dict[str, str] = {}

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                # Skip large binaries
                info = zf.getinfo(name)
                if info.file_size > 5 * 1024 * 1024:  # 5MB limit per file
                    continue

                # Only extract text-like files
                text_exts = {".xml", ".json", ".txt", ".yml", ".yaml",
                             ".properties", ".gradle", ".java", ".kt",
                             ".py", ".js", ".html", ".plist", ".strings",
                             ".cfg", ".ini", ".conf", ".smali"}
                _, ext = os.path.splitext(name.lower())

                if ext in text_exts or name in (
                    "AndroidManifest.xml", "resources.arsc"
                ):
                    try:
                        data = zf.read(name)
                        try:
                            extracted[name] = data.decode("utf-8", errors="ignore")
                        except Exception:
                            extracted[name] = data.decode("latin-1", errors="ignore")
                    except Exception:
                        pass

                # Track native libs
                if name.startswith("lib/") and name.endswith(".so"):
                    extracted.setdefault("__native_libs__", "")
                    extracted["__native_libs__"] += name + "\n"

    except zipfile.BadZipFile as e:
        extracted["__error__"] = str(e)

    return extracted


def scan_secrets_in_files(
    files: dict[str, str],
) -> list[SecretFinding]:
    """
    Scan extracted file contents for hardcoded secrets.
    """
    findings: list[SecretFinding] = []
    seen: set[str] = set()

    for file_path, content in files.items():
        if file_path.startswith("__"):
            continue

        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            for sp in SECRET_PATTERNS:
                for m in re.finditer(sp["pattern"], line, re.IGNORECASE):
                    val     = m.group(0)
                    dedup   = f"{file_path}:{sp['type']}:{val[:20]}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)

                    findings.append(SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=sp["type"],
                        value_snippet=val[:12] + "..." if len(val) > 12 else val,
                        full_match=(val[:80] + "..." if len(val) > 80 else val),
                        severity=sp["severity"],
                        confidence=sp["confidence"],
                        evidence=[
                            f"File: {file_path}:{line_num}",
                            f"Pattern: {sp['type']}",
                            f"Value: {val[:20]}...",
                        ],
                    ))

    return findings


def scan_code_rules(
    files: dict[str, str],
    platform: str = "android",
) -> list[CodeFinding]:
    """
    Scan extracted/decompiled code against insecure code rules.
    """
    findings: list[CodeFinding] = []
    seen: set[str] = set()

    # Filter rules by platform
    active_rules = [
        r for r in CODE_RULES
        if r["category"] not in ("ios",) or platform == "ios"
    ]
    if platform == "ios":
        active_rules = [
            r for r in CODE_RULES
            if r["category"] not in ("android",)
        ]

    for file_path, content in files.items():
        if file_path.startswith("__"):
            continue

        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            for rule in active_rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    dedup = f"{file_path}:{rule['id']}:{line_num}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)

                    findings.append(CodeFinding(
                        file_path=file_path,
                        line_number=line_num,
                        rule_id=rule["id"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["desc"],
                        code_snippet=line.strip()[:200],
                        severity=rule["severity"],
                        cwe=rule.get("cwe"),
                        owasp=rule.get("owasp"),
                        remediation=rule.get("fix", []),
                    ))

    return findings


def analyze_network_security(
    files: dict[str, str],
    manifest_content: str,
    platform: str,
) -> list[NetworkFinding]:
    """
    Analyze network security configuration:
    - Network Security Config (Android)
    - ATS (iOS)
    - Certificate pinning implementation
    - Cleartext traffic
    """
    findings: list[NetworkFinding] = []

    if platform == "android":
        # Cleartext traffic
        if 'android:usesCleartextTraffic="true"' in manifest_content:
            findings.append(NetworkFinding(
                finding_type="cleartext_traffic",
                description="usesCleartextTraffic=true allows HTTP connections",
                file_path="AndroidManifest.xml",
                severity="high",
                evidence=["android:usesCleartextTraffic=\"true\" in manifest"],
            ))

        # Network Security Config analysis
        nsc_content = files.get("res/xml/network_security_config.xml", "")
        if nsc_content:
            if "<trust-anchors>" in nsc_content:
                if "user" in nsc_content:
                    findings.append(NetworkFinding(
                        finding_type="user_ca_trusted",
                        description="Network Security Config trusts user-installed CAs — "
                                    "allows MITM with custom certificates",
                        file_path="res/xml/network_security_config.xml",
                        severity="high",
                        evidence=["<certificates src=\"user\"/> found in NSC"],
                    ))
            if "<debug-overrides>" in nsc_content:
                findings.append(NetworkFinding(
                    finding_type="debug_overrides",
                    description="NSC debug-overrides present — "
                                "verify not in production build",
                    file_path="res/xml/network_security_config.xml",
                    severity="medium",
                    evidence=["<debug-overrides> in network_security_config.xml"],
                ))
            if "<pin-set>" in nsc_content:
                # Good — pinning configured
                findings.append(NetworkFinding(
                    finding_type="cert_pinning_configured",
                    description="Certificate pinning configured via Network Security Config",
                    file_path="res/xml/network_security_config.xml",
                    severity="info",
                    evidence=["<pin-set> found in NSC"],
                ))
        else:
            findings.append(NetworkFinding(
                finding_type="no_nsc",
                description="No Network Security Config found — "
                            "default trust anchors and no pinning",
                severity="medium",
                evidence=["network_security_config.xml not found"],
            ))

        # Check for cleartext in code
        for path, content in files.items():
            if "http://" in content and not path.endswith((".xml", ".gradle")):
                http_urls = re.findall(
                    r'http://(?!localhost|127\.|10\.|192\.168\.)[^\s"\'<>]+',
                    content
                )
                if http_urls:
                    findings.append(NetworkFinding(
                        finding_type="cleartext_url",
                        description=f"HTTP URL(s) found in {path}",
                        file_path=path,
                        severity="high",
                        evidence=[f"HTTP URL: {u[:80]}" for u in http_urls[:3]],
                    ))

    elif platform == "ios":
        # Check Info.plist for ATS
        plist_content = files.get("Info.plist", "")
        if not plist_content:
            for k, v in files.items():
                if k.endswith("Info.plist"):
                    plist_content = v
                    break

        if plist_content:
            if "NSAllowsArbitraryLoads" in plist_content:
                if "<true/>" in plist_content[
                    plist_content.find("NSAllowsArbitraryLoads"):
                    plist_content.find("NSAllowsArbitraryLoads") + 200
                ]:
                    findings.append(NetworkFinding(
                        finding_type="ats_disabled",
                        description="App Transport Security disabled "
                                    "(NSAllowsArbitraryLoads=true)",
                        file_path="Info.plist",
                        severity="high",
                        evidence=["NSAllowsArbitraryLoads set to true"],
                    ))

            if "NSExceptionDomains" in plist_content:
                findings.append(NetworkFinding(
                    finding_type="ats_exceptions",
                    description="ATS exception domains defined — "
                                "verify these are necessary",
                    file_path="Info.plist",
                    severity="medium",
                    evidence=["NSExceptionDomains found in Info.plist"],
                ))

    return findings


def compute_risk_score(
    secrets: list[SecretFinding],
    perms: list[PermissionFinding],
    exported: list[ExportedComponent],
    code_findings: list[CodeFinding],
    net_findings: list[NetworkFinding],
    app_info: Optional[AppInfo],
) -> int:
    """
    Compute a 0-100 risk score based on all findings.
    """
    score = 0
    severity_weights = {
        "critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0
    }

    # Secrets (high weight)
    for s in secrets:
        score += severity_weights.get(s.severity, 0)

    # Code findings
    for cf in code_findings:
        score += severity_weights.get(cf.severity, 0) // 2

    # Exported components
    for ec in exported:
        if ec.vulnerable:
            score += severity_weights.get(ec.severity, 0)

    # Network findings
    for nf in net_findings:
        score += severity_weights.get(nf.severity, 0) // 2

    # App info flags
    if app_info:
        if app_info.debuggable:
            score += 20
        if app_info.allow_backup:
            score += 8
        if app_info.uses_cleartext:
            score += 10

    # Dangerous permissions
    for p in perms:
        if p.severity == "critical":
            score += 5
        elif p.severity == "high":
            score += 2

    return min(100, score)


# ══════════════════════════════════════════════════════════════
# 6. IOS ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_ipa(ipa_path: str) -> dict[str, str]:
    """
    Extract IPA (it's also a ZIP).
    Returns {filename: content} for text files.
    Handles Payload/<AppName>.app/ structure.
    """
    extracted: dict[str, str] = {}

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            for name in zf.namelist():
                info = zf.getinfo(name)
                if info.file_size > 5 * 1024 * 1024:
                    continue

                text_exts = {".plist", ".json", ".strings", ".xml",
                             ".html", ".js", ".txt", ".yml", ".yaml",
                             ".conf", ".cfg", ".ini", ".swift", ".m", ".h"}
                _, ext = os.path.splitext(name.lower())

                if ext in text_exts or "Info.plist" in name:
                    try:
                        data = zf.read(name)
                        text = data.decode("utf-8", errors="ignore")
                        # Normalize path (remove Payload/<app>.app/)
                        norm_name = re.sub(
                            r"^Payload/[^/]+\.app/", "", name
                        )
                        extracted[norm_name] = text
                    except Exception:
                        pass

                # Native binaries
                if name.endswith((".dylib", ".framework")):
                    extracted.setdefault("__native_libs__", "")
                    extracted["__native_libs__"] += name + "\n"

    except zipfile.BadZipFile as e:
        extracted["__error__"] = str(e)

    return extracted


def parse_ios_plist(plist_content: str) -> tuple[AppInfo, list[PermissionFinding]]:
    """
    Parse Info.plist (text/XML format).
    Extract: bundle ID, version, permissions, ATS config.
    """
    app_info = AppInfo(platform="ios")
    perms:    list[PermissionFinding] = []

    # Bundle ID
    bid = re.search(
        r'<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>',
        plist_content
    )
    if bid:
        app_info.package_name = bid.group(1)

    # Version
    ver = re.search(
        r'<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>',
        plist_content
    )
    if ver:
        app_info.version_name = ver.group(1)

    # App name
    name = re.search(
        r'<key>CFBundleName</key>\s*<string>([^<]+)</string>',
        plist_content
    )
    if name:
        app_info.app_name = name.group(1)

    # Privacy permissions
    for key, perm_info in IOS_PRIVACY_PERMISSIONS.items():
        if key in plist_content:
            # Find the description
            desc_m = re.search(
                rf'<key>{re.escape(key)}</key>\s*<string>([^<]+)</string>',
                plist_content
            )
            reason = desc_m.group(1) if desc_m else ""
            perms.append(PermissionFinding(
                permission=key,
                description=perm_info["desc"],
                dangerous=perm_info["severity"] in ("high", "critical"),
                protection_level="dangerous"
                if perm_info["severity"] in ("high", "critical") else "normal",
                reason=reason[:100],
                severity=perm_info["severity"],
            ))

    # ATS / Cleartext
    if "NSAllowsArbitraryLoads" in plist_content:
        app_info.uses_cleartext = True

    return app_info, perms


# ══════════════════════════════════════════════════════════════
# 7. PARSERS (External Tools)
# ══════════════════════════════════════════════════════════════

def parse_mobsf_report(report: dict) -> MobileStaticResult:
    """
    Parse MobSF JSON report into our schema.
    MobSF reports: /api/v1/report_json endpoint.
    """
    result = MobileStaticResult(
        success=True,
        tool="mobsf",
        target=report.get("file_name", ""),
        command="mobsf_api",
        platform=report.get("platform", "unknown").lower(),
    )

    # App Info
    ai = AppInfo(
        platform=result.platform,
        package_name=report.get("package_name")
                     or report.get("bundle_id"),
        app_name=report.get("app_name"),
        version_name=report.get("version_name"),
        version_code=str(report.get("version_code", "")),
        min_sdk=str(report.get("min_sdk", "")),
        target_sdk=str(report.get("target_sdk", "")),
        md5=report.get("md5"),
        sha256=report.get("sha256"),
        debuggable=report.get("manifest_analysis", {})
                         .get("is_debuggable", False),
        allow_backup=report.get("manifest_analysis", {})
                           .get("is_allowbackup", False),
    )
    result.app_info = ai

    # Permissions
    for perm_name, perm_info in (
        report.get("permissions", {}) or {}
    ).items():
        status   = perm_info.get("status", "normal")
        severity = "high" if status == "dangerous" else "info"
        result.permissions.append(PermissionFinding(
            permission=perm_name,
            description=perm_info.get("description", ""),
            dangerous=status == "dangerous",
            protection_level=status,
            severity=severity,
        ))

    # Secrets from MobSF
    for item in report.get("secrets", []):
        result.secrets.append(SecretFinding(
            file_path=item.get("file_path", ""),
            secret_type=item.get("key_type", "Generic Secret"),
            value_snippet=item.get("secret", "")[:12] + "...",
            severity="high",
            confidence="medium",
            evidence=[str(item)[:200]],
        ))

    # Code analysis
    for item in (report.get("code_analysis", {})
                       .get("findings", {}) or {}).values():
        for metadata in (item.get("metadata", []) or []):
            result.code_findings.append(CodeFinding(
                file_path=metadata.get("file_path", ""),
                line_number=metadata.get("line_no"),
                rule_id=item.get("id", "MOBSF"),
                category=item.get("category", "general"),
                title=item.get("title", ""),
                description=item.get("description", ""),
                code_snippet=metadata.get("match_lines", [""])[0][:200],
                severity=item.get("severity", "medium").lower(),
                cwe=item.get("cwe"),
                owasp=item.get("owasp", ""),
                remediation=[item.get("remediation", "")],
            ))

    # Exported components
    for comp in report.get("manifest_analysis", {}).get(
        "exported_activities", []
    ) or []:
        result.exported_components.append(ExportedComponent(
            component_type="activity",
            name=comp.get("name", ""),
            exported=True,
            vulnerable=not comp.get("permission"),
            issues=comp.get("issues", []),
            severity="high" if not comp.get("permission") else "info",
        ))

    # Network security
    ns = report.get("network_security", {}) or {}
    if ns.get("cleartext_traffic"):
        result.network_findings.append(NetworkFinding(
            finding_type="cleartext_traffic",
            description="Cleartext traffic detected",
            severity="high",
            evidence=ns.get("cleartext_traffic", []),
        ))

    # Counts
    result.total_secrets             = len(result.secrets)
    result.total_dangerous_permissions = sum(
        1 for p in result.permissions if p.dangerous
    )
    result.total_exported            = len(result.exported_components)
    result.total_code_findings       = len(result.code_findings)

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    result.critical_count = sum(
        1 for f in result.code_findings + result.secrets
        if f.severity == "critical"
    )
    result.high_count = sum(
        1 for f in result.code_findings + result.secrets
        if f.severity == "high"
    )
    result.medium_count = sum(
        1 for f in result.code_findings
        if f.severity == "medium"
    )

    result.risk_score = compute_risk_score(
        result.secrets, result.permissions,
        result.exported_components, result.code_findings,
        result.network_findings, result.app_info,
    )

    return result


def parse_apktool_output(stdout: str, output_dir: str) -> AppInfo:
    """
    Parse apktool decode output and read decompiled files.
    Returns basic AppInfo from apktool output.
    """
    app_info = AppInfo(platform="android")

    # Parse apktool output
    pkg = re.search(r"Package: ([^\s]+)", stdout)
    if pkg:
        app_info.package_name = pkg.group(1)

    ver = re.search(r"versionName=([^\s]+)", stdout)
    if ver:
        app_info.version_name = ver.group(1)

    return app_info


def parse_jadx_output(jadx_dir: str) -> dict[str, str]:
    """
    Read JADX-decompiled Java source files.
    Returns {relative_path: content}.
    """
    sources: dict[str, str] = {}
    base = Path(jadx_dir)

    if not base.exists():
        return sources

    for java_file in base.rglob("*.java"):
        try:
            rel = str(java_file.relative_to(base))
            content = java_file.read_text(errors="ignore")
            if len(content) < 10 * 1024 * 1024:  # 10MB limit
                sources[rel] = content
        except Exception:
            pass

    # Also read smali files
    for smali_file in list(base.rglob("*.smali"))[:200]:
        try:
            rel     = str(smali_file.relative_to(base))
            content = smali_file.read_text(errors="ignore")
            if len(content) < 1024 * 1024:
                sources[rel] = content
        except Exception:
            pass

    return sources


def parse_class_dump_output(stdout: str, stderr: str) -> list[CodeFinding]:
    """
    Parse class-dump output for iOS (Objective-C headers).
    Look for sensitive method names and patterns.
    """
    findings: list[CodeFinding] = []
    raw = stdout + "\n" + stderr

    sensitive_method_patterns = [
        (r"(?i)-(.*)?(?:password|passwd|secret|token|key|pin|auth|credential)"
         r"(?:With.*)?:", "Sensitive method name in ObjC class"),
        (r"(?i)@property.*(?:password|token|secret|key|pin)",
         "Sensitive property in ObjC class"),
        (r"(?i)-(void|id|NSString\s*\*).*(?:decrypt|encrypt).*:",
         "Crypto method found"),
        (r"(?i)NSURLSession.*(?:didReceiveChallenge|willPerformHTTPRedirection)",
         "SSL challenge handler — check implementation"),
    ]

    lines = raw.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern, title in sensitive_method_patterns:
            if re.search(pattern, line):
                findings.append(CodeFinding(
                    file_path="class_dump_output",
                    line_number=line_num,
                    rule_id="CLASS_DUMP",
                    category="ios",
                    title=title,
                    description=f"Sensitive pattern in ObjC header: {line.strip()[:100]}",
                    code_snippet=line.strip()[:200],
                    severity="medium",
                    owasp="M2",
                ))

    return findings


# ══════════════════════════════════════════════════════════════
# 8. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run subprocess safely — no shell, no injection."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


def compute_file_hashes(file_path: str) -> tuple[str, str]:
    """Compute MD5 and SHA256 of a file."""
    import hashlib
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
    except Exception:
        pass
    return md5.hexdigest(), sha256.hexdigest()


# ══════════════════════════════════════════════════════════════
# 9. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def mobile_static_analysis(
    tool:       str,
    target:     str,
    args:       list[str] = [],
    platform:   str = "auto",
    output_dir: Optional[str] = None,
    api_key:    Optional[str] = None,
) -> dict:
    """
    🔧 Agent Tool: Mobile Application Static Analysis

    Capabilities:
      ┌──────────────────────────────────────────────────────────────────┐
      │  DECOMPILATION        APK → apktool (smali) + jadx (Java)        │
      │                       IPA → class-dump (ObjC headers)            │
      │  SECRET DETECTION     40+ patterns: AWS/GCP/Firebase/Stripe/JWT  │
      │                       GitHub/Slack/Twilio/DB connections/keys     │
      │  PERMISSIONS          Android: 35 dangerous perms + groups       │
      │                       iOS: 14 privacy permission keys             │
      │  EXPORTED COMPONENTS  Activity/Service/Receiver/Provider audit   │
      │  INSECURE CODE        37 rules: crypto/network/storage/logging/  │
      │                       WebView/Intent/auth — Android + iOS        │
      │  NETWORK SECURITY     NSC analysis, ATS config, cleartext URLs,  │
      │                       certificate pinning detection               │
      │  MANIFEST ANALYSIS    debuggable, allowBackup, minSdk, targetSdk │
      │  RISK SCORING         0-100 risk score from all findings         │
      │  TOOL INTEGRATION     MobSF, apktool, jadx, class-dump, manual  │
      └──────────────────────────────────────────────────────────────────┘

    Args:
        tool:       "mobsf" | "apktool" | "jadx" | "class_dump" | "manual"
        target:     Path to APK/IPA/AAB file
        args:       Raw tool arguments — agent decides
        platform:   "android" | "ios" | "auto"
        output_dir: Directory for decompiled output
        api_key:    MobSF API key (for mobsf tool)

    Tool args reference:
      mobsf:
        Upload+scan: [] (auto-uploads and scans)
        Custom URL:  ["--url", "http://localhost:8000"]
        Force rescan:["--rescan"]

      apktool:
        Basic:       ["d", "-f", "-r"]
        No resources:["d", "-f", "--no-res"]
        No sources:  ["d", "-f", "--no-src"]
        Verbose:     ["d", "-f", "-v"]

      jadx:
        Basic:       ["-d", "/output/dir"]
        Show bad:    ["--show-bad-code"]
        No res:      ["--no-res"]
        Threads:     ["-j", "4"]
        Verbose:     ["-v"]

      class_dump:
        Basic:       ["-H", "-o", "/output/dir"]
        Framework:   ["-f", "UIKit"]
        Swift:       [] (use class-dump-swift)

      manual:
        (pure Python — no external tool needed)
        Extracts APK/IPA as ZIP, scans all text files.

    Returns:
        Structured JSON: app_info → secrets → permissions →
                         exported_components → code_findings →
                         network_findings → risk_score
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = MobileStaticRequest(
            tool=tool, target=target, args=args,
            platform=platform, output_dir=output_dir,
            api_key=api_key,
        )
    except Exception as e:
        return MobileStaticResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Auto-detect platform
    if req.platform == "auto":
        if target.endswith(".apk") or target.endswith(".aab"):
            req.platform = "android"
        elif target.endswith(".ipa"):
            req.platform = "ios"
        else:
            req.platform = "android"  # default

    # Setup output directory
    out_dir = req.output_dir or os.path.join(
        os.path.dirname(target),
        os.path.splitext(os.path.basename(target))[0] + "_decompiled"
    )

    result = MobileStaticResult(
        success=False,
        tool=tool,
        target=target,
        command="",
        platform=req.platform,
    )
    techniques_used: list[str] = []
    raw_output:      str = ""
    error_msg:       Optional[str] = None

    # Compute file hashes upfront
    md5, sha256 = compute_file_hashes(target)
    file_size   = os.path.getsize(target)

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        result.command = f"manual_static_analysis({target})"

        # ── Extract files ──
        if req.platform == "android":
            files = extract_apk(target, out_dir)
            techniques_used.append("apk_extract")

            # Parse manifest
            manifest = files.get("AndroidManifest.xml", "")
            if manifest:
                app_info, perms, exported = parse_android_manifest(manifest)
                app_info.md5    = md5
                app_info.sha256 = sha256
                app_info.file_size = file_size
                # Native libs
                native_libs = files.get("__native_libs__", "")
                if native_libs:
                    app_info.native_libs = [
                        l for l in native_libs.splitlines() if l
                    ]

                result.app_info             = app_info
                result.permissions          = perms
                result.exported_components  = exported
                techniques_used.append("manifest_analysis")

        elif req.platform == "ios":
            files = analyze_ipa(target)
            techniques_used.append("ipa_extract")

            # Parse Info.plist
            plist = files.get("Info.plist", "")
            if not plist:
                for k, v in files.items():
                    if k.endswith("Info.plist"):
                        plist = v
                        break

            if plist:
                app_info, perms = parse_ios_plist(plist)
                app_info.md5    = md5
                app_info.sha256 = sha256
                app_info.file_size = file_size
                result.app_info    = app_info
                result.permissions = perms
                techniques_used.append("plist_analysis")

        if "__error__" in files:
            error_msg = files["__error__"]
        else:
            # ── Secret scanning ──
            result.secrets = scan_secrets_in_files(files)
            techniques_used.append("secret_scan")

            # ── Code rule scanning ──
            result.code_findings = scan_code_rules(files, req.platform)
            techniques_used.append("code_rules_scan")

            # ── Network security ──
            manifest_c = files.get("AndroidManifest.xml", "") \
                if req.platform == "android" else ""
            result.network_findings = analyze_network_security(
                files, manifest_c, req.platform
            )
            techniques_used.append("network_security_analysis")

        result.success = True

    # ══════════════════════════════
    # TOOL: MOBSF
    # ══════════════════════════════
    elif tool == "mobsf":
        mobsf_url = "http://localhost:8000"
        for i, a in enumerate(req.args):
            if a == "--url" and i + 1 < len(req.args):
                mobsf_url = req.args[i + 1]

        api_key_val = req.api_key or os.environ.get("MOBSF_API_KEY", "")

        try:
            import requests as req_lib

            # Upload file
            result.command = f"mobsf_api_upload({target})"
            with open(target, "rb") as f:
                upload_resp = req_lib.post(
                    f"{mobsf_url}/api/v1/upload",
                    files={"file": (os.path.basename(target), f,
                                    "application/octet-stream")},
                    headers={"Authorization": api_key_val},
                    timeout=120,
                )
            upload_data = upload_resp.json()
            scan_hash   = upload_data.get("hash")
            techniques_used.append("mobsf_upload")

            if not scan_hash:
                error_msg = f"MobSF upload failed: {upload_data}"
            else:
                # Trigger scan
                scan_resp = req_lib.post(
                    f"{mobsf_url}/api/v1/scan",
                    data={"scan_type": req.platform, "hash": scan_hash,
                          "file_name": os.path.basename(target),
                          "re_scan": "1" if "--rescan" in req.args else "0"},
                    headers={"Authorization": api_key_val},
                    timeout=req.timeout,
                )
                techniques_used.append("mobsf_scan")
                raw_output = scan_resp.text[:2000]

                # Get JSON report
                report_resp = req_lib.post(
                    f"{mobsf_url}/api/v1/report_json",
                    data={"hash": scan_hash},
                    headers={"Authorization": api_key_val},
                    timeout=60,
                )
                report_data = report_resp.json()
                parsed      = parse_mobsf_report(report_data)

                # Copy parsed fields
                result.app_info             = parsed.app_info
                result.secrets              = parsed.secrets
                result.permissions          = parsed.permissions
                result.exported_components  = parsed.exported_components
                result.code_findings        = parsed.code_findings
                result.network_findings     = parsed.network_findings
                result.success = True
                techniques_used.append("mobsf_report")

                # Supplement with manual scan on raw APK
                if req.platform == "android":
                    files = extract_apk(target, out_dir)
                    extra_secrets = scan_secrets_in_files(files)
                    seen_vals = {s.value_snippet for s in result.secrets}
                    result.secrets.extend([
                        s for s in extra_secrets
                        if s.value_snippet not in seen_vals
                    ])
                    techniques_used.append("manual_secret_supplement")

        except Exception as e:
            error_msg = f"MobSF error: {e}"
            # Fallback to manual
            files     = extract_apk(target, out_dir) \
                if req.platform == "android" else analyze_ipa(target)
            result.secrets       = scan_secrets_in_files(files)
            result.code_findings = scan_code_rules(files, req.platform)
            result.success = True
            techniques_used.append("manual_fallback")

    # ══════════════════════════════
    # TOOL: APKTOOL (Android only)
    # ══════════════════════════════
    elif tool == "apktool":
        os.makedirs(out_dir, exist_ok=True)

        if req.args:
            cmd = ["apktool"] + list(req.args) + [target, "-o", out_dir]
        else:
            cmd = ["apktool", "d", "-f", "-r", target, "-o", out_dir]

        result.command = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:3000]
        techniques_used.append("apktool_decompile")

        if rc != 0 and not os.path.exists(out_dir):
            error_msg = (stderr or stdout)[:400]
        else:
            # Read decompiled files
            files: dict[str, str] = {}
            for p in Path(out_dir).rglob("*"):
                if p.is_file() and p.stat().st_size < 5 * 1024 * 1024:
                    _, ext = os.path.splitext(str(p).lower())
                    if ext in {".xml", ".smali", ".java", ".kt",
                                ".properties", ".json", ".yml"}:
                        try:
                            rel = str(p.relative_to(out_dir))
                            files[rel] = p.read_text(errors="ignore")
                        except Exception:
                            pass

            # Parse manifest
            manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                with open(manifest_path, errors="ignore") as f:
                    manifest_content = f.read()
                app_info, perms, exported = parse_android_manifest(
                    manifest_content
                )
                app_info.md5    = md5
                app_info.sha256 = sha256
                app_info.file_size = file_size
                result.app_info            = app_info
                result.permissions         = perms
                result.exported_components = exported
                techniques_used.append("manifest_analysis")

            result.secrets       = scan_secrets_in_files(files)
            result.code_findings = scan_code_rules(files, "android")
            result.network_findings = analyze_network_security(
                files,
                files.get("AndroidManifest.xml", ""),
                "android"
            )
            techniques_used += ["secret_scan", "code_rules_scan",
                                 "network_security_analysis"]
            result.success = True

    # ══════════════════════════════
    # TOOL: JADX (Android)
    # ══════════════════════════════
    elif tool == "jadx":
        os.makedirs(out_dir, exist_ok=True)

        if req.args:
            cmd = ["jadx"] + list(req.args) + ["-d", out_dir, target]
        else:
            cmd = ["jadx", "-d", out_dir, "--show-bad-code",
                   "-j", "4", target]

        result.command = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:3000]
        techniques_used.append("jadx_decompile")

        if rc != 0 and not os.listdir(out_dir):
            error_msg = (stderr or stdout)[:400]
        else:
            # Read JADX output
            files = parse_jadx_output(out_dir)
            techniques_used.append("jadx_source_read")

            # Manifest
            for pth, content in files.items():
                if "AndroidManifest.xml" in pth:
                    app_info, perms, exported = parse_android_manifest(content)
                    app_info.md5    = md5
                    app_info.sha256 = sha256
                    app_info.file_size = file_size
                    result.app_info            = app_info
                    result.permissions         = perms
                    result.exported_components = exported
                    techniques_used.append("manifest_analysis")
                    break

            result.secrets       = scan_secrets_in_files(files)
            result.code_findings = scan_code_rules(files, "android")
            result.network_findings = analyze_network_security(
                files,
                files.get("resources/AndroidManifest.xml", ""),
                "android"
            )
            techniques_used += ["secret_scan", "code_rules_scan",
                                 "network_security_analysis"]
            result.success = True

    # ══════════════════════════════
    # TOOL: CLASS-DUMP (iOS)
    # ══════════════════════════════
    elif tool == "class_dump":
        os.makedirs(out_dir, exist_ok=True)

        # First extract IPA
        files = analyze_ipa(target)
        techniques_used.append("ipa_extract")

        # Find binary in extracted IPA
        binary_name = re.sub(r"\.ipa$", "", os.path.basename(target))
        binary_path = os.path.join(
            os.path.dirname(target),
            f"Payload/{binary_name}.app/{binary_name}"
        )

        if req.args:
            cmd = ["class-dump"] + list(req.args) + [binary_path]
        else:
            cmd = ["class-dump", "-H", "-o", out_dir, binary_path]

        result.command = " ".join(cmd)
        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]
        techniques_used.append("class_dump")

        # Parse class-dump output
        extra_findings = parse_class_dump_output(stdout, stderr)
        result.code_findings.extend(extra_findings)

        # Parse Info.plist
        plist = files.get("Info.plist", "")
        if plist:
            app_info, perms = parse_ios_plist(plist)
            app_info.md5    = md5
            app_info.sha256 = sha256
            app_info.file_size = file_size
            result.app_info    = app_info
            result.permissions = perms
            techniques_used.append("plist_analysis")

        # Scan extracted text files for secrets + code rules
        result.secrets      = scan_secrets_in_files(files)
        result.code_findings += scan_code_rules(files, "ios")
        result.network_findings = analyze_network_security(
            files, "", "ios"
        )
        techniques_used += ["secret_scan", "code_rules_scan",
                             "network_security_analysis"]
        result.success = True

    # ══════════════════════════════
    # POST-PROCESS
    # ══════════════════════════════
    if result.success:
        result.total_secrets = len(result.secrets)
        result.total_dangerous_permissions = sum(
            1 for p in result.permissions if p.dangerous
        )
        result.total_exported = len(result.exported_components)
        result.total_code_findings = len(result.code_findings)

        severity_rank = {
            "critical": 4, "high": 3,
            "medium": 2, "low": 1, "info": 0,
        }

        result.critical_count = sum(
            1 for f in (result.secrets + result.code_findings)
            if f.severity == "critical"
        )
        result.high_count = sum(
            1 for f in (result.secrets + result.code_findings)
            if f.severity == "high"
        )
        result.medium_count = sum(
            1 for f in result.code_findings
            if f.severity == "medium"
        )

        # Sort by severity
        result.secrets.sort(
            key=lambda s: severity_rank.get(s.severity, 0), reverse=True
        )
        result.code_findings.sort(
            key=lambda c: severity_rank.get(c.severity, 0), reverse=True
        )

        result.risk_score = compute_risk_score(
            result.secrets,
            result.permissions,
            result.exported_components,
            result.code_findings,
            result.network_findings,
            result.app_info,
        )

    result.techniques_used = list(dict.fromkeys(techniques_used))
    result.raw_output      = raw_output[:5000] if raw_output else None
    result.error           = error_msg
    result.execution_time  = round(time.time() - start, 2)

    return result.model_dump()


# ══════════════════════════════════════════════════════════════
# 10. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

MOBILE_STATIC_TOOL_DEFINITION = {
    "name": "mobile_static_analysis",
    "description": (
        "Static security analysis of Android APK/AAB and iOS IPA files. "
        "Decompiles and analyzes: hardcoded secrets (40+ patterns: AWS/GCP/Firebase/"
        "Stripe/GitHub/JWT/DB connections), dangerous permissions (35 Android + 14 iOS), "
        "exported components (Activity/Service/Receiver/Provider), insecure code patterns "
        "(37 rules: weak crypto, disabled SSL, cleartext storage, WebView XSS, Intent "
        "injection, logging, auth bypass), network security config, ATS configuration. "
        "Computes 0-100 risk score. Supports MobSF (full SAST), apktool (smali), "
        "jadx (Java decompile), class-dump (iOS ObjC), manual (built-in Python)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["mobsf", "apktool", "jadx", "class_dump", "manual"],
                "description": (
                    "mobsf      = Full SAST via MobSF API (most thorough) | "
                    "apktool    = Android APK decompile to smali | "
                    "jadx       = Android APK → Java source decompile | "
                    "class_dump = iOS binary → ObjC headers | "
                    "manual     = built-in Python analysis (no external tool)"
                ),
            },
            "target": {
                "type": "string",
                "description": "Path to APK/IPA/AAB file (e.g. '/path/to/app.apk')",
            },
            "platform": {
                "type": "string",
                "enum": ["android", "ios", "auto"],
                "description": "Target platform (auto-detected from file extension)",
            },
            "output_dir": {
                "type": "string",
                "description": "Directory for decompiled output (optional)",
            },
            "api_key": {
                "type": "string",
                "description": "MobSF API key (required for mobsf tool)",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "mobsf:      ['--url', 'http://localhost:8000', '--rescan']\n"
                    "apktool:    ['d', '-f', '-r'] or ['d', '--no-res', '-f']\n"
                    "jadx:       ['-j', '4', '--show-bad-code']\n"
                    "class_dump: ['-H', '-o', '/output']\n"
                    "manual:     [] (no args needed)"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 11. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Manual — full analysis
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="manual",
        target="/path/to/app.apk",
        platform="android",
    )
    print("=== MANUAL APK ANALYSIS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Manual — iOS IPA
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="manual",
        target="/path/to/app.ipa",
        platform="ios",
    )
    print("=== MANUAL IPA ANALYSIS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. MobSF full scan
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="mobsf",
        target="/path/to/app.apk",
        api_key="your_mobsf_api_key",
        args=["--url", "http://localhost:8000"],
    )
    print("=== MOBSF FULL SCAN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. apktool decompile + scan
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="apktool",
        target="/path/to/app.apk",
        args=["d", "-f", "-r"],
        output_dir="/tmp/apk_decompiled",
    )
    print("=== APKTOOL DECOMPILE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. JADX Java decompile + scan
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="jadx",
        target="/path/to/app.apk",
        args=["-j", "4", "--show-bad-code"],
        output_dir="/tmp/jadx_output",
    )
    print("=== JADX DECOMPILE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. class-dump iOS
    # ─────────────────────────────
    r = mobile_static_analysis(
        tool="class_dump",
        target="/path/to/app.ipa",
        platform="ios",
        output_dir="/tmp/classdump_output",
    )
    print("=== CLASS-DUMP IOS ===")
    print(json.dumps(r, indent=2))