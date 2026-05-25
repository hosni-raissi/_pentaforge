import subprocess
import json
import re
import os
import time
import plistlib
import sqlite3
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum


# ══════════════════════════════════════════════════════════════
# 1. PROJECT CONFIGURATION & UTILITIES
# ══════════════════════════════════════════════════════════════

class ProjectConfig:
    """Central configuration for agent tools"""
    _project_dir: Optional[Path] = None
    OUTPUT_DIR  = "output"
    TEMP_DIR    = "tmp"
    LOGS_DIR    = "logs"

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


def safe_execute(cmd: list[str], timeout: int = 120,
                 cwd: Optional[str] = None) -> tuple[str, str, int, str]:
    """Run a command safely, return (stdout, stderr, returncode, cwd)"""
    work_dir = Path(cwd) if cwd else ProjectConfig.get_project_dir()
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False, cwd=str(work_dir)
        )
        return result.stdout, result.stderr, result.returncode, str(work_dir)
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1, str(work_dir)
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed or not in PATH", -1, str(work_dir)
    except Exception as e:
        return "", str(e), -1, str(work_dir)


def _default_android_device_id() -> str:
    remote = str(os.environ.get("PENTAFORGE_MOBILE_REMOTE_ADB_ENDPOINT", "")).strip()
    if remote:
        return remote
    explicit = str(os.environ.get("PENTAFORGE_MOBILE_ANDROID_DEFAULT_DEVICE_ID", "")).strip()
    if explicit:
        return explicit
    host = str(os.environ.get("PENTAFORGE_MOBILE_ANDROID_HOST", "")).strip()
    port = str(os.environ.get("PENTAFORGE_MOBILE_ANDROID_ADB_PORT", "5555")).strip() or "5555"
    if host:
        return f"{host}:{port}"
    return ""


def _prepare_android_storage_device(device_id: Optional[str]) -> tuple[Optional[str], Optional[str], str]:
    resolved_device = str(device_id or _default_android_device_id()).strip()
    if not resolved_device:
        return device_id, None, ""

    stdout, stderr, rc, _ = safe_execute(["adb", "connect", resolved_device], timeout=45)
    output = (stdout or stderr or "").strip()
    note = f"mobile-lab adb connect: {output or 'ok'}"
    lowered = output.lower()
    if rc != 0 and "connected to" not in lowered and "already connected" not in lowered:
        return resolved_device, f"ADB connection to {resolved_device} failed: {output or 'unknown error'}", note
    return resolved_device, None, note


# ══════════════════════════════════════════════════════════════
# 2. CONSTANTS — SENSITIVE PATTERNS
# ══════════════════════════════════════════════════════════════

# Regex patterns that flag a key/value pair as sensitive
SENSITIVE_KEY_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"passw(or)?d", r"passwd", r"secret",  r"token",
        r"api[_\-]?key",r"auth",    r"credential",r"private[_\-]?key",
        r"access[_\-]?key", r"session", r"cookie", r"jwt",
        r"pin$",        r"passcode", r"biometric", r"fingerprint",
        r"ssn",         r"credit[_\-]?card", r"cvv", r"account",
        r"email",       r"username", r"user[_\-]?id",
    ]
]

SENSITIVE_VALUE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"[A-Za-z0-9+/]{32,}={0,2}",           # base64-like blobs
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", # JWT header
        r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",  # Bearer token
        r"\b[0-9]{13,19}\b",                     # Credit card numbers
        r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",       # SSN
        r"(?i)(true|false)\b",                   # Boolean flags (auth bypass)
        r"password\s*=\s*\S+",                   # inline password= strings
    ]
]

# Log file patterns that may leak sensitive data
LOG_SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"passw(or)?d[\s:=]+\S+",
        r"token[\s:=]+[A-Za-z0-9\-._~+/]{8,}",
        r"authorization[\s:=]+\S+",
        r"api[_\-]?key[\s:=]+\S+",
        r"credit.?card[\s:=]+[0-9\s\-]{12,}",
        r"\b[0-9]{13,19}\b",
        r"jwt[\s:=]+eyJ",
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    ]
]

# SharedPreferences XML attribute flags
SHARED_PREF_WORLD_READABLE = re.compile(r"MODE_WORLD_READABLE|0x1\b", re.I)
SHARED_PREF_WORLD_WRITABLE  = re.compile(r"MODE_WORLD_WRITABLE|0x2\b",  re.I)


# ══════════════════════════════════════════════════════════════
# 3. SCHEMAS
# ══════════════════════════════════════════════════════════════

class Platform(str, Enum):
    android = "android"
    ios     = "ios"
    both    = "both"


class CheckType(str, Enum):
    shared_prefs = "shared_prefs"   # Android SharedPreferences XML
    sqlite       = "sqlite"         # SQLite databases
    plist        = "plist"          # iOS property list files
    keychain     = "keychain"       # iOS Keychain dump (objection/frida)
    log_files    = "log_files"      # Application log files
    clipboard    = "clipboard"      # Clipboard content (dynamic via objection)
    mobsf        = "mobsf"          # MobSF REST API scan
    objection    = "objection"      # Objection runtime checks
    custom       = "custom"         # Custom regex scan on arbitrary paths
    all          = "all"            # Run every applicable check


class StorageFinding(BaseModel):
    """A single insecure storage finding"""
    check_type:  str
    severity:    str                  # critical | high | medium | low | info
    location:    str                  # file path, db table, plist key …
    key:         Optional[str] = None
    value:       Optional[str] = None # may be truncated / redacted for safety
    description: str
    recommendation: str


class MobileStorageRequest(BaseModel):
    platform:    Platform
    checks:      list[CheckType] = [CheckType.all]
    # Path to the extracted app directory (APK/IPA unpacked)
    app_dir:     Optional[str]   = None
    # Live device checks (requires connected device + objection)
    package:     Optional[str]   = None   # e.g. "com.example.app"
    bundle_id:   Optional[str]   = None   # e.g. "com.example.App"
    device_id:   Optional[str]   = None   # adb device serial / udid
    # MobSF
    mobsf_url:   Optional[str]   = None   # e.g. "http://localhost:8000"
    mobsf_key:   Optional[str]   = None   # REST API key
    mobsf_scan_hash: Optional[str] = None # existing scan hash to reuse
    # Custom pattern scan
    custom_paths:   list[str]    = []
    custom_patterns: list[str]   = []
    timeout:     int             = Field(default=120, ge=10, le=600)

    @field_validator("app_dir", mode="before")
    @classmethod
    def validate_app_dir(cls, v):
        if v and not Path(v).is_dir():
            raise ValueError(f"app_dir '{v}' does not exist or is not a directory")
        return v

    @field_validator("checks", mode="before")
    @classmethod
    def expand_all(cls, v):
        if CheckType.all in v:
            return [c for c in CheckType if c != CheckType.all]
        return v


class MobileStorageResult(BaseModel):
    success:        bool
    platform:       str
    checks_run:     list[str]
    findings:       list[StorageFinding] = []
    summary:        dict[str, int]       = {}   # severity → count
    tool_outputs:   dict[str, str]       = {}   # tool name → raw stdout snippet
    errors:         list[str]            = []
    execution_time: float                = 0.0


# ══════════════════════════════════════════════════════════════
# 4. HELPER — sensitive detection
# ══════════════════════════════════════════════════════════════

def _is_sensitive_key(k: str) -> bool:
    return any(p.search(str(k)) for p in SENSITIVE_KEY_PATTERNS)


def _is_sensitive_value(v: str) -> bool:
    return any(p.search(str(v)) for p in SENSITIVE_VALUE_PATTERNS)


def _redact(value: str, max_len: int = 60) -> str:
    """Show only first few chars so logs aren't accidentally leaked"""
    s = str(value)
    if len(s) > max_len:
        return s[:max_len] + "…[truncated]"
    return s


def _severity_for_key(key: str) -> str:
    critical = ["password", "passwd", "secret", "private_key",
                 "credit_card", "cvv", "ssn", "pin", "passcode"]
    high     = ["token", "api_key", "auth", "session", "jwt",
                 "access_key", "bearer", "credential"]
    if any(c in key.lower() for c in critical):
        return "critical"
    if any(h in key.lower() for h in high):
        return "high"
    return "medium"


# ══════════════════════════════════════════════════════════════
# 5. CHECK IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════

# ─────────────────────────────────────────
# 5A. SharedPreferences (Android XML)
# ─────────────────────────────────────────

def _check_shared_prefs(app_dir: Path) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    # Typical locations inside an extracted APK / data backup
    search_roots = [
        app_dir / "shared_prefs",
        app_dir / "data" / "shared_prefs",
        app_dir / "res" / "xml",        # sometimes embedded defaults
    ]

    xml_files: list[Path] = []
    for root in search_roots:
        if root.is_dir():
            xml_files.extend(root.rglob("*.xml"))

    # Also search entire app_dir shallowly for any *prefs*.xml
    xml_files.extend(
        p for p in app_dir.rglob("*pref*.xml") if p not in xml_files
    )

    if not xml_files:
        raw_log.append("No SharedPreferences XML files found.")
        return findings, "\n".join(raw_log)

    for xml_file in xml_files:
        raw_log.append(f"[SharedPrefs] Scanning: {xml_file}")
        try:
            content = xml_file.read_text(errors="replace")
        except Exception as e:
            raw_log.append(f"  ERROR reading {xml_file}: {e}")
            continue

        # ── World-readable / world-writable flags in source ──
        if SHARED_PREF_WORLD_READABLE.search(content):
            findings.append(StorageFinding(
                check_type="shared_prefs",
                severity="high",
                location=str(xml_file),
                description="SharedPreferences opened with MODE_WORLD_READABLE — "
                            "any app on the device can read this file.",
                recommendation="Use MODE_PRIVATE (0x0) instead."
            ))

        if SHARED_PREF_WORLD_WRITABLE.search(content):
            findings.append(StorageFinding(
                check_type="shared_prefs",
                severity="high",
                location=str(xml_file),
                description="SharedPreferences opened with MODE_WORLD_WRITABLE — "
                            "any app on the device can overwrite this file.",
                recommendation="Use MODE_PRIVATE (0x0) instead."
            ))

        # ── Parse key/value pairs ──
        # Format: <string name="key">value</string>  or  <boolean name="key" value="true"/>
        kv_patterns = [
            re.compile(r'<(?:string|int|long|float|boolean)\s+name="([^"]+)"[^>]*>([^<]*)</', re.S),
            re.compile(r'<(?:string|int|long|float|boolean)\s+name="([^"]+)"\s+value="([^"]*)"', re.S),
        ]
        for pat in kv_patterns:
            for m in pat.finditer(content):
                key, value = m.group(1), m.group(2).strip()
                raw_log.append(f"  key={key!r}  value={_redact(value)!r}")
                if _is_sensitive_key(key) or _is_sensitive_value(value):
                    findings.append(StorageFinding(
                        check_type="shared_prefs",
                        severity=_severity_for_key(key),
                        location=str(xml_file),
                        key=key,
                        value=_redact(value),
                        description=f"Sensitive data stored in plaintext SharedPreferences: "
                                    f"key='{key}'",
                        recommendation="Encrypt sensitive values with EncryptedSharedPreferences "
                                       "(Jetpack Security) before storing."
                    ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5B. SQLite Databases
# ─────────────────────────────────────────

def _check_sqlite(app_dir: Path) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    db_files = list(app_dir.rglob("*.db")) + list(app_dir.rglob("*.sqlite")) \
             + list(app_dir.rglob("*.sqlite3"))

    if not db_files:
        raw_log.append("No SQLite database files found.")
        return findings, "\n".join(raw_log)

    for db_path in db_files:
        raw_log.append(f"[SQLite] Scanning: {db_path}")

        # ── Check for missing encryption (SQLCipher header) ──
        try:
            header = db_path.read_bytes()[:16]
            if header.startswith(b"SQLite format 3"):
                findings.append(StorageFinding(
                    check_type="sqlite",
                    severity="high",
                    location=str(db_path),
                    description="Unencrypted SQLite database detected (standard SQLite3 header). "
                                "Data is accessible without authentication.",
                    recommendation="Use SQLCipher or Android's EncryptedFile API to encrypt "
                                   "the database at rest."
                ))
        except Exception as e:
            raw_log.append(f"  ERROR reading header: {e}")
            continue

        # ── Open and inspect tables ──
        try:
            # Copy to temp so we don't lock a live file
            tmp = ProjectConfig.get_temp_dir() / f"_tmp_{db_path.name}"
            shutil.copy2(db_path, tmp)
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()

            # Get all tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]
            raw_log.append(f"  Tables: {tables}")

            for table in tables:
                # Get column names
                try:
                    cur.execute(f"PRAGMA table_info('{table}')")
                    columns = [row[1] for row in cur.fetchall()]
                except Exception:
                    continue

                # Check column names for sensitivity
                for col in columns:
                    if _is_sensitive_key(col):
                        # Sample up to 3 rows
                        try:
                            cur.execute(f"SELECT [{col}] FROM [{table}] LIMIT 3")
                            rows = cur.fetchall()
                            for row in rows:
                                val = str(row[0]) if row[0] is not None else ""
                                raw_log.append(f"  {table}.{col} = {_redact(val)!r}")
                                findings.append(StorageFinding(
                                    check_type="sqlite",
                                    severity=_severity_for_key(col),
                                    location=f"{db_path} → table={table}, col={col}",
                                    key=col,
                                    value=_redact(val),
                                    description=f"Sensitive column '{col}' stored in plaintext "
                                                f"SQLite table '{table}'.",
                                    recommendation="Encrypt sensitive fields before inserting, "
                                                   "or use SQLCipher full-database encryption."
                                ))
                        except Exception:
                            pass

            con.close()
            tmp.unlink(missing_ok=True)

        except Exception as e:
            raw_log.append(f"  ERROR connecting to db: {e}")

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5C. Plist Files (iOS)
# ─────────────────────────────────────────

def _check_plist(app_dir: Path) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    plist_files = list(app_dir.rglob("*.plist"))
    if not plist_files:
        raw_log.append("No .plist files found.")
        return findings, "\n".join(raw_log)

    def _flatten(obj, prefix="") -> list[tuple[str, Any]]:
        """Recursively flatten plist dict/array into (dotted_key, value) pairs"""
        pairs = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                pairs.extend(_flatten(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                pairs.extend(_flatten(item, f"{prefix}[{i}]"))
        else:
            pairs.append((prefix, obj))
        return pairs

    for plist_path in plist_files:
        raw_log.append(f"[Plist] Scanning: {plist_path}")
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception as e:
            # Could be binary plist that needs plutil conversion
            raw_log.append(f"  Could not parse (try `plutil -convert xml1`): {e}")
            # Attempt plutil fallback
            stdout, _, rc, _ = safe_execute(
                ["plutil", "-convert", "xml1", "-o", "-", str(plist_path)]
            )
            if rc == 0 and stdout:
                try:
                    data = plistlib.loads(stdout.encode())
                except Exception:
                    continue
            else:
                continue

        pairs = _flatten(data)
        for key, value in pairs:
            val_str = str(value)
            raw_log.append(f"  {key} = {_redact(val_str)!r}")
            if _is_sensitive_key(key) or _is_sensitive_value(val_str):
                findings.append(StorageFinding(
                    check_type="plist",
                    severity=_severity_for_key(key),
                    location=str(plist_path),
                    key=key,
                    value=_redact(val_str),
                    description=f"Sensitive data found in plist: key='{key}'",
                    recommendation="Do not store credentials/tokens in plist files. "
                                   "Use the iOS Keychain with kSecAttrAccessibleWhenUnlocked "
                                   "or higher protection class."
                ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5D. iOS Keychain (via objection dump)
# ─────────────────────────────────────────

def _check_keychain(bundle_id: Optional[str],
                    device_id: Optional[str],
                    timeout: int) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    # objection must be installed: `pip install objection`
    # Device must be jailbroken or frida-server running
    cmd = ["objection"]
    if device_id:
        cmd += ["--serial", device_id]
    if bundle_id:
        cmd += ["-g", bundle_id]
    cmd += ["run", "ios keychain dump"]

    raw_log.append(f"[Keychain] Running: {' '.join(cmd)}")
    stdout, stderr, rc, _ = safe_execute(cmd, timeout=timeout)
    raw_log.append(stdout[:2000])
    if stderr:
        raw_log.append(f"STDERR: {stderr[:500]}")

    if rc != 0 and not stdout:
        findings.append(StorageFinding(
            check_type="keychain",
            severity="info",
            location="iOS Keychain (live device)",
            description=f"Keychain dump failed or objection not available: {stderr[:200]}",
            recommendation="Install objection (`pip install objection`) and ensure "
                           "frida-server is running on a jailbroken device."
        ))
        return findings, "\n".join(raw_log)

    # Parse objection keychain table output
    # Typical line: klass | creation_date | ... | account | service | data
    lines = stdout.splitlines()
    for line in lines:
        if "|" not in line:
            continue
        cols = [c.strip() for c in line.split("|")]

        # Objection keychain dump columns vary; look for sensitive data column
        for col in cols:
            if _is_sensitive_value(col) or len(col) > 20:
                findings.append(StorageFinding(
                    check_type="keychain",
                    severity="medium",
                    location="iOS Keychain",
                    value=_redact(col),
                    description="Keychain entry with potentially sensitive data found. "
                                "Verify accessibility flags (kSecAttrAccessible*).",
                    recommendation="Ensure kSecAttrAccessibleWhenUnlockedThisDeviceOnly "
                                   "or stricter; never use kSecAttrAccessibleAlways."
                ))
                break

    # Check for world-accessible items (kSecAttrAccessibleAlways)
    if "kSecAttrAccessibleAlways" in stdout:
        findings.append(StorageFinding(
            check_type="keychain",
            severity="critical",
            location="iOS Keychain",
            description="Keychain item(s) use kSecAttrAccessibleAlways — "
                        "data accessible even when device is locked.",
            recommendation="Change to kSecAttrAccessibleWhenUnlockedThisDeviceOnly "
                           "for maximum protection."
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5E. Log Files
# ─────────────────────────────────────────

def _check_log_files(app_dir: Optional[Path],
                     package: Optional[str],
                     bundle_id: Optional[str],
                     platform: str,
                     device_id: Optional[str],
                     timeout: int) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    # ── Static: scan extracted app log files ──
    if app_dir:
        log_extensions = ["*.log", "*.txt", "*.out", "*.trace"]
        log_files: list[Path] = []
        for ext in log_extensions:
            log_files.extend(app_dir.rglob(ext))

        for log_file in log_files:
            raw_log.append(f"[Logs-Static] Scanning: {log_file}")
            try:
                content = log_file.read_text(errors="replace")
            except Exception as e:
                raw_log.append(f"  ERROR: {e}")
                continue

            for pattern in LOG_SENSITIVE_PATTERNS:
                for match in pattern.finditer(content):
                    matched = match.group(0)
                    # Find line number
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(StorageFinding(
                        check_type="log_files",
                        severity="high",
                        location=f"{log_file}:{line_no}",
                        value=_redact(matched),
                        description=f"Sensitive data pattern found in log file at line {line_no}.",
                        recommendation="Disable verbose logging in production builds. "
                                       "Use ProGuard/R8 stripping rules or a logging facade "
                                       "that strips sensitive fields."
                    ))

    # ── Dynamic: pull logcat (Android) ──
    if platform in ("android", "both") and package:
        cmd = ["adb"]
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["logcat", "-d",           # dump and exit
                "-v", "brief",
                f"*:W"]                   # warnings and above

        raw_log.append(f"[Logs-Logcat] Running: {' '.join(cmd)}")
        stdout, stderr, rc, _ = safe_execute(cmd, timeout=timeout)
        raw_log.append(stdout[:3000])

        if stdout:
            # Filter to package name only
            pkg_lines = [l for l in stdout.splitlines() if package in l]
            for pattern in LOG_SENSITIVE_PATTERNS:
                for line in pkg_lines:
                    if pattern.search(line):
                        findings.append(StorageFinding(
                            check_type="log_files",
                            severity="high",
                            location=f"adb logcat (package={package})",
                            value=_redact(line),
                            description="Sensitive data found in Android logcat output.",
                            recommendation="Remove Log.d/Log.e calls that output user data. "
                                           "Use BuildConfig.DEBUG guards or Timber."
                        ))

    # ── Dynamic: pull iOS device log ──
    if platform in ("ios", "both"):
        cmd = ["idevicesyslog"]
        if device_id:
            cmd += ["-u", device_id]
        if bundle_id:
            raw_log.append(f"[Logs-iOS] Target bundle_id: {bundle_id}")
        raw_log.append("[Logs-iOS] idevicesyslog not run in dump mode here — "
                       "attach manually for live capture.")

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5F. Clipboard (via objection — Android / iOS)
# ─────────────────────────────────────────

def _check_clipboard(package: Optional[str],
                     bundle_id: Optional[str],
                     platform: str,
                     device_id: Optional[str],
                     timeout: int) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    target = package or bundle_id
    if not target:
        raw_log.append("[Clipboard] No package/bundle_id provided — skipping live check.")
        findings.append(StorageFinding(
            check_type="clipboard",
            severity="info",
            location="Clipboard (live device)",
            description="Clipboard check skipped: no package or bundle_id specified.",
            recommendation="Provide package (Android) or bundle_id (iOS) for live clipboard audit."
        ))
        return findings, "\n".join(raw_log)

    # Android: use objection
    if platform in ("android", "both"):
        cmd = ["objection"]
        if device_id:
            cmd += ["--serial", device_id]
        cmd += ["-g", target, "run", "android clipboard monitor"]
        raw_log.append(f"[Clipboard-Android] Command: {' '.join(cmd)}")
        raw_log.append("  NOTE: clipboard monitor is interactive; "
                       "this tool performs a single snapshot attempt.")

        # For a one-shot check we use a frida snippet instead
        frida_script = (
            "Java.perform(function(){"
            "  var CM = Java.use('android.content.ClipboardManager');"
            "  // hook getPrimaryClip"
            "  send('clipboard_check:done');"
            "});"
        )
        # We can't easily run frida inline here without a proper harness,
        # so we report advisory finding
        findings.append(StorageFinding(
            check_type="clipboard",
            severity="medium",
            location=f"Android Clipboard ({target})",
            description="Clipboard monitoring check requested. "
                        "Verify the app does not place sensitive data (passwords, "
                        "credit card numbers, tokens) in the clipboard. "
                        "Use `objection -g <pkg> run android clipboard monitor` for live check.",
            recommendation="Override onWindowFocusChanged to clear clipboard when app loses focus. "
                           "Use ClipboardManager.clearPrimaryClip(). "
                           "Mark sensitive EditText fields with "
                           "android:textIsSelectable=\"false\"."
        ))

    # iOS
    if platform in ("ios", "both"):
        cmd = ["objection"]
        if device_id:
            cmd += ["--serial", device_id]
        if bundle_id:
            cmd += ["-g", bundle_id]
        cmd += ["run", "ios pasteboard monitor"]
        raw_log.append(f"[Clipboard-iOS] Command: {' '.join(cmd)}")

        findings.append(StorageFinding(
            check_type="clipboard",
            severity="medium",
            location=f"iOS Pasteboard ({bundle_id or 'unknown'})",
            description="Clipboard monitoring check requested. "
                        "Verify the app does not write sensitive data to UIPasteboard. "
                        "Use `objection -g <bundle> run ios pasteboard monitor` for live check.",
            recommendation="Avoid writing to UIPasteboard.general for sensitive fields. "
                           "Use UITextView.textContentType appropriately. "
                           "Consider setting isExcludedFromBackup on pasteboard items."
        ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5G. MobSF REST API Scan
# ─────────────────────────────────────────

def _check_mobsf(mobsf_url: str, mobsf_key: str,
                 scan_hash: Optional[str],
                 app_dir: Optional[Path],
                 timeout: int) -> tuple[list[StorageFinding], str]:
    """
    Query MobSF's REST API for storage-related findings.
    Either reuse an existing scan hash or trigger a new scan.
    """
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    try:
        import requests  # soft dependency
    except ImportError:
        raw_log.append("[MobSF] 'requests' not installed — run `pip install requests`")
        return findings, "\n".join(raw_log)

    headers = {"Authorization": mobsf_key}
    base    = mobsf_url.rstrip("/")

    # ── Reuse existing scan or kick off a new one ──
    if not scan_hash:
        raw_log.append("[MobSF] No scan_hash provided — attempting upload.")
        # Find the first APK/IPA in app_dir parent
        apk_ipa: Optional[Path] = None
        if app_dir:
            for ext in ("*.apk", "*.ipa", "*.aab"):
                hits = list(app_dir.parent.glob(ext))
                if hits:
                    apk_ipa = hits[0]
                    break
        if not apk_ipa:
            raw_log.append("[MobSF] No APK/IPA found to upload; cannot proceed.")
            return findings, "\n".join(raw_log)

        with open(apk_ipa, "rb") as f:
            resp = requests.post(
                f"{base}/api/v1/upload",
                headers=headers,
                files={"file": (apk_ipa.name, f,
                                "application/octet-stream")},
                timeout=timeout
            )
        if resp.status_code != 200:
            raw_log.append(f"[MobSF] Upload failed: {resp.status_code} {resp.text[:200]}")
            return findings, "\n".join(raw_log)

        upload_data = resp.json()
        scan_hash   = upload_data.get("hash")
        raw_log.append(f"[MobSF] Uploaded → hash={scan_hash}")

        # Trigger scan
        requests.post(
            f"{base}/api/v1/scan",
            headers=headers,
            data={"scan_type": upload_data.get("scan_type", "apk"), "hash": scan_hash},
            timeout=timeout
        )

    # ── Pull the JSON report ──
    raw_log.append(f"[MobSF] Fetching report for hash={scan_hash}")
    try:
        resp = requests.post(
            f"{base}/api/v1/report_json",
            headers=headers,
            data={"hash": scan_hash},
            timeout=timeout
        )
        report = resp.json()
    except Exception as e:
        raw_log.append(f"[MobSF] Report fetch failed: {e}")
        return findings, "\n".join(raw_log)

    raw_log.append(f"[MobSF] Report keys: {list(report.keys())[:15]}")

    # ── Extract storage-related findings ──
    # MobSF report sections we care about
    storage_keys = [
        "insecure_data_storage",
        "shared_preferences",
        "sqlite",
        "logs",
        "external_storage",
        "internal_storage",
        "world_readable_files",
        "world_writable_files",
        "keystore",
    ]

    for section in storage_keys:
        items = report.get(section, [])
        if isinstance(items, list):
            for item in items:
                desc = (item.get("description") or item.get("issue")
                        or item.get("title") or str(item))
                sev  = (item.get("severity") or "medium").lower()
                path = (item.get("file_path") or item.get("path") or section)
                findings.append(StorageFinding(
                    check_type="mobsf",
                    severity=sev,
                    location=f"MobSF → {path}",
                    description=desc,
                    recommendation=item.get("recommendation", "Refer to MobSF report.")
                ))
        elif isinstance(items, dict):
            # Some sections are dicts
            for k, v in items.items():
                findings.append(StorageFinding(
                    check_type="mobsf",
                    severity="medium",
                    location=f"MobSF → {section} → {k}",
                    description=str(v)[:300],
                    recommendation="Review MobSF full report for remediation details."
                ))

    # ── Binary analysis: look for insecure API usage ──
    binary_analysis = report.get("binary_analysis", {})
    insecure_apis   = report.get("insecure_connections", [])
    for api in insecure_apis:
        if any(kw in str(api).lower() for kw in
               ["nsuserdefaults", "sharedpreferences", "getsharedpreferences",
                "sqliteopenhelper", "openorcreatedatabase"]):
            findings.append(StorageFinding(
                check_type="mobsf",
                severity="medium",
                location=f"MobSF binary analysis → {str(api)[:100]}",
                description="Insecure storage API usage detected in binary/bytecode analysis.",
                recommendation="Verify data stored via this API is encrypted or non-sensitive."
            ))

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5H. Objection Runtime Storage Checks
# ─────────────────────────────────────────

def _check_objection(package: Optional[str],
                     bundle_id: Optional[str],
                     platform: str,
                     device_id: Optional[str],
                     timeout: int) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    target = package or bundle_id
    if not target:
        raw_log.append("[Objection] No target app specified — skipping.")
        return findings, "\n".join(raw_log)

    # Commands to run through objection's non-interactive mode
    objection_commands: dict[str, str] = {}
    if platform in ("android", "both"):
        objection_commands.update({
            "android_filesystem_ls":   "android filesystem ls",
            "android_sharedprefs_ls":  "android shared_preferences list",
            "android_sqlite_ls":       "android sqlite list",
        })
    if platform in ("ios", "both"):
        objection_commands.update({
            "ios_nsuserdefaults_dump": "ios nsuserdefaults get",
            "ios_filesystem_ls":       "ios filesystem ls",
            "ios_cookies":             "ios cookies get",
        })

    for label, obj_cmd in objection_commands.items():
        cmd = ["objection"]
        if device_id:
            cmd += ["--serial", device_id]
        cmd += ["-g", target, "run", obj_cmd]

        raw_log.append(f"[Objection] {label}: {' '.join(cmd)}")
        stdout, stderr, rc, _ = safe_execute(cmd, timeout=timeout)
        raw_log.append(stdout[:2000] or f"  (no output; rc={rc})")

        if rc != 0 and not stdout:
            continue

        # ── NSUserDefaults (iOS) — check for sensitive keys ──
        if "ios_nsuserdefaults" in label:
            for line in stdout.splitlines():
                if "=" in line or ":" in line:
                    parts = re.split(r"[=:]", line, maxsplit=1)
                    key = parts[0].strip()
                    val = parts[1].strip() if len(parts) > 1 else ""
                    if _is_sensitive_key(key) or _is_sensitive_value(val):
                        findings.append(StorageFinding(
                            check_type="objection",
                            severity=_severity_for_key(key),
                            location=f"NSUserDefaults ({target})",
                            key=key,
                            value=_redact(val),
                            description=f"Sensitive key '{key}' found in NSUserDefaults.",
                            recommendation="Move sensitive data to Keychain. "
                                           "NSUserDefaults is not encrypted."
                        ))

        # ── SharedPreferences list (Android) ──
        if "android_sharedprefs" in label:
            for line in stdout.splitlines():
                if _is_sensitive_key(line) or _is_sensitive_value(line):
                    findings.append(StorageFinding(
                        check_type="objection",
                        severity="high",
                        location=f"SharedPreferences list ({target})",
                        value=_redact(line),
                        description="Potentially sensitive SharedPreferences key/file detected "
                                    "at runtime.",
                        recommendation="Use EncryptedSharedPreferences from Jetpack Security."
                    ))

        # ── SQLite listing (Android) ──
        if "android_sqlite" in label:
            for line in stdout.splitlines():
                if _is_sensitive_key(line):
                    findings.append(StorageFinding(
                        check_type="objection",
                        severity="high",
                        location=f"SQLite ({target})",
                        value=_redact(line),
                        description="Potentially sensitive SQLite database or table detected "
                                    "at runtime.",
                        recommendation="Use SQLCipher for encrypted SQLite databases."
                    ))

        # ── iOS Cookies ──
        if "ios_cookies" in label:
            for pattern in SENSITIVE_VALUE_PATTERNS:
                if pattern.search(stdout):
                    findings.append(StorageFinding(
                        check_type="objection",
                        severity="medium",
                        location=f"iOS Cookies ({target})",
                        description="Sensitive-looking data found in iOS cookies at runtime.",
                        recommendation="Set cookie flags: Secure, HttpOnly, and appropriate "
                                       "SameSite policy. Do not store secrets in cookies."
                    ))
                    break

    return findings, "\n".join(raw_log)


# ─────────────────────────────────────────
# 5I. Custom Regex Scan
# ─────────────────────────────────────────

def _check_custom(paths: list[str],
                  patterns: list[str],
                  app_dir: Optional[Path]) -> tuple[list[StorageFinding], str]:
    findings: list[StorageFinding] = []
    raw_log: list[str] = []

    # Compile user-supplied patterns
    compiled: list[re.Pattern] = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            raw_log.append(f"[Custom] Invalid regex '{p}': {e}")

    if not compiled:
        compiled = SENSITIVE_KEY_PATTERNS + LOG_SENSITIVE_PATTERNS
        raw_log.append("[Custom] No patterns provided — using built-in sensitive patterns.")

    # Resolve scan paths
    scan_paths: list[Path] = []
    for p in paths:
        sp = Path(p)
        if sp.is_dir() or sp.is_file():
            scan_paths.append(sp)
        else:
            raw_log.append(f"[Custom] Path not found: {p}")

    if not scan_paths and app_dir:
        scan_paths = [app_dir]

    if not scan_paths:
        raw_log.append("[Custom] No valid paths to scan.")
        return findings, "\n".join(raw_log)

    for scan_path in scan_paths:
        files = list(scan_path.rglob("*")) if scan_path.is_dir() else [scan_path]
        for file in files:
            if not file.is_file():
                continue
            try:
                content = file.read_text(errors="replace")
            except Exception:
                continue
            for pat in compiled:
                for match in pat.finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(StorageFinding(
                        check_type="custom",
                        severity="medium",
                        location=f"{file}:{line_no}",
                        value=_redact(match.group(0)),
                        description=f"Custom pattern '{pat.pattern}' matched in file.",
                        recommendation="Review matched content and ensure no secrets are "
                                       "stored in plaintext."
                    ))

    return findings, "\n".join(raw_log)


# ══════════════════════════════════════════════════════════════
# 6. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def mobile_storage_check(
    platform:          str            = "android",
    checks:            list[str]      = ["all"],
    app_dir:           Optional[str]  = None,
    package:           Optional[str]  = None,
    bundle_id:         Optional[str]  = None,
    device_id:         Optional[str]  = None,
    mobsf_url:         Optional[str]  = None,
    mobsf_key:         Optional[str]  = None,
    mobsf_scan_hash:   Optional[str]  = None,
    custom_paths:      list[str]      = [],
    custom_patterns:   list[str]      = [],
    timeout:           int            = 120,
) -> dict:
    """
    🔧 Agent Tool: Mobile Insecure Storage Check

    Audits mobile applications for insecure local storage across all common
    storage mechanisms: SharedPreferences, SQLite, Plist, Keychain, log files,
    clipboard, MobSF REST API, and Objection runtime analysis.

    Args:
        platform:        "android" | "ios" | "both"
        checks:          List of check names, or ["all"] to run everything.
                         Options: shared_prefs | sqlite | plist | keychain |
                                  log_files | clipboard | mobsf | objection | custom
        app_dir:         Path to extracted APK/IPA directory (static analysis)
        package:         Android package name  (e.g. "com.example.app")
        bundle_id:       iOS bundle identifier (e.g. "com.example.App")
        device_id:       ADB serial / iOS UDID for live device checks
        mobsf_url:       MobSF server URL (e.g. "http://localhost:8000")
        mobsf_key:       MobSF REST API key
        mobsf_scan_hash: Existing MobSF scan hash to reuse
        custom_paths:    File/dir paths for custom regex scan
        custom_patterns: Regex patterns for custom scan
        timeout:         Per-command timeout in seconds

    Returns:
        Structured dict with all findings, severity summary, and raw tool output.
    """
    start = time.time()

    # ── VALIDATE ──
    try:
        req = MobileStorageRequest(
            platform        = platform,
            checks          = checks,
            app_dir         = app_dir,
            package         = package,
            bundle_id       = bundle_id,
            device_id       = device_id,
            mobsf_url       = mobsf_url,
            mobsf_key       = mobsf_key,
            mobsf_scan_hash = mobsf_scan_hash,
            custom_paths    = custom_paths,
            custom_patterns = custom_patterns,
            timeout         = timeout,
        )
    except Exception as e:
        return MobileStorageResult(
            success=False,
            platform=platform,
            checks_run=[],
            errors=[f"Validation error: {e}"]
        ).model_dump()

    app_path          = Path(app_dir) if app_dir else None
    all_findings:     list[StorageFinding] = []
    all_tool_outputs: dict[str, str]       = {}
    all_errors:       list[str]            = []
    checks_run:       list[str]            = []

    needs_android_live_device = (
        req.platform in (Platform.android, Platform.both)
        and bool(req.package)
        and any(
            check in req.checks
            for check in (CheckType.log_files, CheckType.clipboard, CheckType.objection)
        )
    )
    if needs_android_live_device:
        resolved_device, prep_error, prep_note = _prepare_android_storage_device(req.device_id)
        if resolved_device:
            req.device_id = resolved_device
        if prep_note:
            all_tool_outputs["mobile_lab"] = prep_note
        if prep_error:
            all_errors.append(prep_error)

    # ══════════════════════════════════════
    # DISPATCH CHECKS
    # ══════════════════════════════════════

    # 1. SharedPreferences
    if CheckType.shared_prefs in req.checks:
        if app_path:
            checks_run.append("shared_prefs")
            f, log = _check_shared_prefs(app_path)
            all_findings.extend(f)
            all_tool_outputs["shared_prefs"] = log
        else:
            all_errors.append("shared_prefs: requires app_dir")

    # 2. SQLite
    if CheckType.sqlite in req.checks:
        if app_path:
            checks_run.append("sqlite")
            f, log = _check_sqlite(app_path)
            all_findings.extend(f)
            all_tool_outputs["sqlite"] = log
        else:
            all_errors.append("sqlite: requires app_dir")

    # 3. Plist (iOS)
    if CheckType.plist in req.checks:
        if req.platform in (Platform.ios, Platform.both):
            if app_path:
                checks_run.append("plist")
                f, log = _check_plist(app_path)
                all_findings.extend(f)
                all_tool_outputs["plist"] = log
            else:
                all_errors.append("plist: requires app_dir")
        else:
            all_tool_outputs["plist"] = "Skipped: not an iOS target."

    # 4. Keychain
    if CheckType.keychain in req.checks:
        if req.platform in (Platform.ios, Platform.both):
            checks_run.append("keychain")
            f, log = _check_keychain(req.bundle_id, req.device_id, req.timeout)
            all_findings.extend(f)
            all_tool_outputs["keychain"] = log
        else:
            all_tool_outputs["keychain"] = "Skipped: not an iOS target."

    # 5. Log Files
    if CheckType.log_files in req.checks:
        checks_run.append("log_files")
        f, log = _check_log_files(
            app_path, req.package, req.bundle_id, req.platform.value,
            req.device_id, req.timeout
        )
        all_findings.extend(f)
        all_tool_outputs["log_files"] = log

    # 6. Clipboard
    if CheckType.clipboard in req.checks:
        checks_run.append("clipboard")
        f, log = _check_clipboard(
            req.package, req.bundle_id,
            req.platform.value, req.device_id, req.timeout
        )
        all_findings.extend(f)
        all_tool_outputs["clipboard"] = log

    # 7. MobSF
    if CheckType.mobsf in req.checks:
        if req.mobsf_url and req.mobsf_key:
            checks_run.append("mobsf")
            f, log = _check_mobsf(
                req.mobsf_url, req.mobsf_key,
                req.mobsf_scan_hash, app_path, req.timeout
            )
            all_findings.extend(f)
            all_tool_outputs["mobsf"] = log
        else:
            all_errors.append("mobsf: requires mobsf_url and mobsf_key")

    # 8. Objection
    if CheckType.objection in req.checks:
        if req.package or req.bundle_id:
            checks_run.append("objection")
            f, log = _check_objection(
                req.package, req.bundle_id,
                req.platform.value, req.device_id, req.timeout
            )
            all_findings.extend(f)
            all_tool_outputs["objection"] = log
        else:
            all_errors.append("objection: requires package (Android) or bundle_id (iOS)")

    # 9. Custom
    if CheckType.custom in req.checks:
        checks_run.append("custom")
        f, log = _check_custom(req.custom_paths, req.custom_patterns, app_path)
        all_findings.extend(f)
        all_tool_outputs["custom"] = log

    # ══════════════════════════════════════
    # DEDUPLICATE & SUMMARISE
    # ══════════════════════════════════════

    seen_sigs: set[str] = set()
    unique_findings: list[StorageFinding] = []
    for finding in all_findings:
        sig = f"{finding.check_type}:{finding.location}:{finding.key}:{finding.value}"
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            unique_findings.append(finding)

    severity_order = ["critical", "high", "medium", "low", "info"]
    unique_findings.sort(key=lambda f: severity_order.index(f.severity)
                         if f.severity in severity_order else 99)

    summary: dict[str, int] = {s: 0 for s in severity_order}
    for f in unique_findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    return MobileStorageResult(
        success        = True,
        platform       = req.platform.value,
        checks_run     = checks_run,
        findings       = unique_findings,
        summary        = summary,
        tool_outputs   = all_tool_outputs,
        errors         = all_errors,
        execution_time = round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 7. TOOL DEFINITION (for LLM function calling)
# ══════════════════════════════════════════════════════════════

MOBILE_STORAGE_CHECK_TOOL_DEFINITION = {
    "name": "mobile_storage_check",
    "description": (
        "Audit a mobile application for insecure local storage. "
        "Covers SharedPreferences, SQLite, iOS Plist, Keychain, log files, "
        "clipboard, MobSF REST API analysis, and Objection runtime inspection. "
        "Works on extracted APK/IPA directories (static) and live devices (dynamic)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "platform": {
                "type": "string",
                "enum": ["android", "ios", "both"],
                "description": "Target mobile platform."
            },
            "checks": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "all", "shared_prefs", "sqlite", "plist",
                        "keychain", "log_files", "clipboard",
                        "mobsf", "objection", "custom"
                    ]
                },
                "description": (
                    "Storage checks to run. Use ['all'] for everything, or pick:\n"
                    " shared_prefs — Android SharedPreferences XML files\n"
                    " sqlite       — SQLite DB schema + plaintext data\n"
                    " plist        — iOS .plist property list files\n"
                    " keychain     — iOS Keychain dump via objection\n"
                    " log_files    — Static log files + live logcat/idevicesyslog\n"
                    " clipboard    — Clipboard/Pasteboard monitoring via objection\n"
                    " mobsf        — MobSF REST API report parsing\n"
                    " objection    — Runtime storage enumeration\n"
                    " custom       — Custom regex scan on specified paths"
                )
            },
            "app_dir": {
                "type": "string",
                "description": "Path to extracted APK/IPA directory for static analysis."
            },
            "package": {
                "type": "string",
                "description": "Android package name (e.g. 'com.example.app') for live checks."
            },
            "bundle_id": {
                "type": "string",
                "description": "iOS bundle identifier (e.g. 'com.example.App') for live checks."
            },
            "device_id": {
                "type": "string",
                "description": "ADB serial number or iOS UDID for targeting a specific device."
            },
            "mobsf_url": {
                "type": "string",
                "description": "MobSF server base URL (e.g. 'http://localhost:8000')."
            },
            "mobsf_key": {
                "type": "string",
                "description": "MobSF REST API key."
            },
            "mobsf_scan_hash": {
                "type": "string",
                "description": "Existing MobSF scan hash to reuse instead of uploading again."
            },
            "custom_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "File or directory paths to scan with custom regex patterns."
            },
            "custom_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Regex patterns for custom scan. Uses built-in patterns if empty."
            },
            "timeout": {
                "type": "integer",
                "description": "Per-command timeout in seconds (default 120, max 600)."
            }
        },
        "required": ["platform"]
    }
}


# ══════════════════════════════════════════════════════════════
# 8. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=" * 65)
    print("MOBILE STORAGE CHECK — EXAMPLES")
    print("=" * 65)

    # ── Example 1: Static analysis of extracted Android APK ──────
    print("\n=== 1. Android Static (SharedPrefs + SQLite + Logs) ===")
    result = mobile_storage_check(
        platform = "android",
        checks   = ["shared_prefs", "sqlite", "log_files"],
        app_dir  = "/tmp/extracted_apk",   # path to `apktool d app.apk`
    )
    print(f"Checks run : {result['checks_run']}")
    print(f"Summary    : {result['summary']}")
    for f in result["findings"]:
        print(f"  [{f['severity'].upper():8s}] {f['check_type']} | {f['location']}")
        if f["key"]:
            print(f"             key={f['key']!r}  value={f['value']!r}")
        print(f"             → {f['description'][:80]}")

    # ── Example 2: iOS Static + Keychain + Plist ─────────────────
    print("\n=== 2. iOS Static + Keychain (objection) ===")
    result = mobile_storage_check(
        platform  = "ios",
        checks    = ["plist", "keychain"],
        app_dir   = "/tmp/extracted_ipa/Payload/MyApp.app",
        bundle_id = "com.example.MyApp",
        device_id = "00001234-000A1234B3C4",
    )
    print(f"Summary: {result['summary']}")
    for f in result["findings"]:
        print(f"  [{f['severity'].upper():8s}] {f['description'][:90]}")

    # ── Example 3: MobSF report parsing ──────────────────────────
    print("\n=== 3. MobSF REST API ===")
    result = mobile_storage_check(
        platform       = "android",
        checks         = ["mobsf"],
        mobsf_url      = "http://localhost:8000",
        mobsf_key      = "YOUR_MOBSF_API_KEY",
        mobsf_scan_hash= "abc123def456",   # or None to auto-upload
        app_dir        = "/tmp/apps",       # only needed for upload
    )
    print(f"MobSF findings: {len(result['findings'])}")
    print(f"Summary: {result['summary']}")

    # ── Example 4: Full audit — all checks ───────────────────────
    print("\n=== 4. Full Audit (all checks) ===")
    result = mobile_storage_check(
        platform  = "android",
        checks    = ["all"],
        app_dir   = "/tmp/extracted_apk",
        package   = "com.example.app",
        device_id = "emulator-5554",
    )
    print(f"Total findings : {sum(result['summary'].values())}")
    print(f"Summary        : {result['summary']}")
    print(f"Execution time : {result['execution_time']}s")
    print("\n=== FULL JSON ===")
    print(json.dumps(result, indent=2, default=str))
