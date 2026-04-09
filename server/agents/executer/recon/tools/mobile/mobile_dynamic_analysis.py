import subprocess
import json
import re
import time
import os
import socket
import threading
import requests
import concurrent.futures
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class MobileDynamicRequest(BaseModel):
    tool: str
    target: str                          # package name / bundle ID
    args: list[str] = []
    timeout: int = Field(default=900, ge=60, le=7200)
    platform: str = "android"           # android / ios
    device_id: Optional[str] = None     # ADB device ID / USB device
    host: str = "127.0.0.1"            # Frida server host
    port: int = 27042                   # Frida server port
    proxy_host: str = "127.0.0.1"      # mitmproxy host
    proxy_port: int = 8080              # mitmproxy port
    scripts: list[str] = []             # custom Frida script paths
    functions: list[str] = []           # specific functions to hook
    intercept_duration: int = 60        # seconds to intercept traffic

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v):
        allowed = {"frida", "objection", "mitmproxy", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        # Package name or bundle ID pattern
        pkg = r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){1,}$"
        if not re.match(pkg, v):
            raise ValueError(f"Invalid package/bundle ID: {v}")
        return v

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v):
        allowed = {"android", "ios"}
        if v.lower() not in allowed:
            raise ValueError(f"Platform must be: {allowed}")
        return v.lower()

    @field_validator("args")
    @classmethod
    def validate_args(cls, v):
        dangerous = [";", "&&", "||", "`", "$(", ">>", "'", '"']
        blocked   = ["--rm", "-rf", "|"]
        for arg in v:
            for c in dangerous:
                if c in arg:
                    raise ValueError(f"Dangerous char '{c}' in: {arg}")
            for f in blocked:
                if arg.strip() == f:
                    raise ValueError(f"Blocked flag: {f}")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v):
        if not (1024 <= v <= 65535):
            raise ValueError(f"Port must be 1024-65535, got {v}")
        return v

    @field_validator("proxy_port")
    @classmethod
    def validate_proxy_port(cls, v):
        if not (1024 <= v <= 65535):
            raise ValueError(f"Proxy port must be 1024-65535, got {v}")
        return v


# ── SSL Pinning bypass result ──
class SSLPinningResult(BaseModel):
    bypassed: bool = False
    method_used: str = ""              # frida-script / objection / custom
    pinning_detected: bool = False
    pinning_type: str = ""             # certificate / public-key / spki
    intercepted_hosts: list[str] = []
    intercepted_count: int = 0
    bypass_errors: list[str] = []
    evidence: list[str] = []


# ── Intercepted HTTP request/response ──
class InterceptedRequest(BaseModel):
    timestamp: str = ""
    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    request_headers: dict[str, str] = {}
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: dict[str, str] = {}
    response_body: Optional[str] = None
    response_size: Optional[int] = None
    duration_ms: Optional[float] = None
    is_https: bool = False
    # Security analysis
    auth_headers: list[str] = []       # Authorization, X-API-Key, etc.
    sensitive_data: list[str] = []     # detected secrets in req/resp
    issues: list[str] = []
    severity: str = "info"


# ── Hooked function call ──
class HookResult(BaseModel):
    timestamp: str = ""
    function_name: str = ""
    class_name: Optional[str] = None
    module: Optional[str] = None
    arguments: list[str] = []
    return_value: Optional[str] = None
    stack_trace: list[str] = []
    finding_type: str = "info"         # crypto / auth / storage / network /
                                        # root_check / debug / biometric
    description: str = ""
    severity: str = "info"
    tampered: bool = False             # if we modified behavior
    original_value: Optional[str] = None
    new_value: Optional[str] = None


# ── Runtime security check result ──
class SecurityCheckResult(BaseModel):
    check_name: str
    category: str                      # root / debug / emulator / frida /
                                       # ssl_pinning / biometric / integrity
    detected: bool = False             # was the check present
    bypassed: bool = False             # did we bypass it
    method: str = ""
    evidence: list[str] = []
    severity: str = "info"


# ── Crypto operation found at runtime ──
class CryptoOperation(BaseModel):
    algorithm: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    iv: Optional[str] = None
    key_snippet: Optional[str] = None  # first 8 bytes hex
    plaintext_snippet: Optional[str] = None
    encrypted_snippet: Optional[str] = None
    function_name: str = ""
    severity: str = "info"
    issues: list[str] = []


# ── Storage access at runtime ──
class StorageAccess(BaseModel):
    access_type: str                   # file_read / file_write / prefs /
                                       # db_query / keychain / clipboard
    path: Optional[str] = None
    key: Optional[str] = None
    value_snippet: Optional[str] = None
    sensitive: bool = False
    severity: str = "info"
    evidence: list[str] = []


# ── Final result ──
class MobileDynamicResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    platform: str
    ssl_pinning: Optional[SSLPinningResult] = None
    intercepted_requests: list[InterceptedRequest] = []
    hook_results: list[HookResult] = []
    security_checks: list[SecurityCheckResult] = []
    crypto_operations: list[CryptoOperation] = []
    storage_accesses: list[StorageAccess] = []
    total_requests: int = 0
    total_hooks: int = 0
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    techniques_used: list[str] = []


# ══════════════════════════════════════════════════════════════
# 2. FRIDA SCRIPTS
# ══════════════════════════════════════════════════════════════

# ── Android SSL Pinning Bypass ──
FRIDA_ANDROID_SSL_BYPASS = """
// Universal Android SSL Pinning Bypass
// Bypasses: OkHttp, TrustManager, Conscrypt, Appcelerator, Cordova,
//            Xamarin, OpenSSL, Flutter, Cronet, Retrofit

Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    if (ApiClient) {
        ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
            console.log('[SSL Bypass] conscrypt.TrustManagerImpl bypassed');
            return array_list.$new();
        };
    }

    // TrustManager X509
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var TMs = [TM.$new()];
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, TMs, null);
        SSLContext.getDefault.implementation = function() { return ctx; };
        console.log('[SSL Bypass] X509TrustManager hooked');
    } catch(e) {}

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String','java.util.List')
            .implementation = function(a, b) {
            console.log('[SSL Bypass] OkHttp3 CertificatePinner.check bypassed: ' + a);
        };
        CertificatePinner.check.overload('java.lang.String','[Ljava.security.cert.Certificate;')
            .implementation = function(a, b) {
            console.log('[SSL Bypass] OkHttp3 CertificatePinner.check (cert) bypassed: ' + a);
        };
    } catch(e) {}

    // OkHttp2 / Square OkHttp
    try {
        var OkHttpCP = Java.use('com.squareup.okhttp.CertificatePinner');
        OkHttpCP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
            .implementation = function(a, b) {
            console.log('[SSL Bypass] OkHttp2 CertificatePinner bypassed: ' + a);
        };
    } catch(e) {}

    // Hostname Verifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HV = Java.registerClass({
            name: 'com.bypass.HostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[SSL Bypass] HostnameVerifier bypassed: ' + hostname);
                    return true;
                }
            }
        });
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier(HV.$new());
        console.log('[SSL Bypass] HttpsURLConnection HostnameVerifier hooked');
    } catch(e) {}

    // WebViewClient SSL
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[SSL Bypass] WebViewClient SSL error bypassed');
            handler.proceed();
        };
    } catch(e) {}

    // TrustKit
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function(a, b) {
            console.log('[SSL Bypass] TrustKit bypassed: ' + a);
            return true;
        };
    } catch(e) {}

    // Appcelerator / Titanium
    try {
        var Pinning = Java.use('appcelerator.https.PinningTrustManager');
        Pinning.checkServerTrusted.implementation = function() {
            console.log('[SSL Bypass] Appcelerator PinningTrustManager bypassed');
        };
    } catch(e) {}

    // Flutter / Dart (native layer bypass via OpenSSL hook)
    try {
        var ssl_verify = Module.findExportByName('libflutter.so', 'ssl_verify_peer_cert');
        if(ssl_verify) {
            Interceptor.attach(ssl_verify, {
                onEnter: function(args) {},
                onLeave: function(retval) {
                    retval.replace(0);
                    console.log('[SSL Bypass] Flutter ssl_verify_peer_cert bypassed');
                }
            });
        }
    } catch(e) {}

    // Android Network Security Config bypass
    try {
        var NetworkSecurityTrustManager = Java.use(
            'android.security.net.config.NetworkSecurityTrustManager'
        );
        NetworkSecurityTrustManager.checkPins.implementation = function(chain) {
            console.log('[SSL Bypass] NetworkSecurityConfig checkPins bypassed');
        };
    } catch(e) {}

    console.log('[SSL Bypass] Android SSL pinning bypass loaded');
});
"""

# ── iOS SSL Pinning Bypass ──
FRIDA_IOS_SSL_BYPASS = """
// Universal iOS SSL Pinning Bypass
// Bypasses: SecTrustEvaluate, AFNetworking, AlamoFire,
//            TrustKit, URLSession, NSURLConnection

// SecTrustEvaluate (low-level)
try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if(SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) {
                retval.replace(0); // errSecSuccess
                console.log('[iOS SSL Bypass] SecTrustEvaluate patched');
            }
        });
    }

    // SecTrustEvaluateWithError (iOS 12+)
    var SecTrustEvaluateWithError = Module.findExportByName(
        'Security', 'SecTrustEvaluateWithError'
    );
    if(SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onLeave: function(retval) {
                retval.replace(1); // true = trusted
                console.log('[iOS SSL Bypass] SecTrustEvaluateWithError patched');
            }
        });
    }
} catch(e) { console.log('[iOS SSL Bypass] SecTrust error: ' + e); }

// TrustKit
try {
    var TrustKit = ObjC.classes.TSKPinningValidator;
    if(TrustKit) {
        ObjC.choose(TrustKit, {
            onMatch: function(obj) {
                obj['- evaluateTrust:forHostname:'].implementation = function(
                    trust, hostname
                ) {
                    console.log('[iOS SSL Bypass] TrustKit bypassed: ' + hostname);
                    return 0; // TSKTrustDecisionShouldAllowConnection
                };
            },
            onComplete: function() {}
        });
    }
} catch(e) {}

// AFNetworking
try {
    var AFPolicy = ObjC.classes.AFSecurityPolicy;
    if(AFPolicy) {
        var setAllow = AFPolicy['+ policyWithPinningMode:withPinnedCertificates:'];
        AFPolicy['- evaluateServerTrust:forDomain:'].implementation = function(
            trust, domain
        ) {
            console.log('[iOS SSL Bypass] AFNetworking bypassed: ' + domain);
            return 1;
        };
    }
} catch(e) {}

// NSURLSession / NSURLConnection delegate
try {
    var NSURLSession = ObjC.classes.NSURLSession;
    if(ObjC.classes.NSURLSessionTask) {
        var URLAuth = ObjC.classes.NSURLAuthenticationChallenge;
    }
} catch(e) {}

console.log('[iOS SSL Bypass] iOS SSL pinning bypass loaded');
"""

# ── Android Root Detection Bypass ──
FRIDA_ROOT_BYPASS = """
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[Root Bypass] RootBeer.isRooted -> false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            return false;
        };
    } catch(e) {}

    // File checks for su binary
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if(path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1
           || path.indexOf('superuser') !== -1) {
            console.log('[Root Bypass] File.exists blocked: ' + path);
            return false;
        }
        return this.exists();
    };

    // Runtime.exec for su check
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if(cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            console.log('[Root Bypass] Runtime.exec blocked: ' + cmd);
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
    };

    // Build.TAGS check
    var Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', {
        get: function() { return 'release-keys'; }
    });

    // RootGuard / Custom implementations
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if(key === 'ro.build.tags') return 'release-keys';
        if(key === 'ro.debuggable') return '0';
        return this.get(key);
    };

    console.log('[Root Bypass] Root detection bypass loaded');
});
"""

# ── Android Emulator Detection Bypass ──
FRIDA_EMULATOR_BYPASS = """
Java.perform(function() {
    var Build = Java.use('android.os.Build');

    var fakeBuildValues = {
        'FINGERPRINT': 'google/coral/coral:11/RQ3A.210805.001/7474174:user/release-keys',
        'MODEL': 'Pixel 4',
        'MANUFACTURER': 'Google',
        'BRAND': 'google',
        'DEVICE': 'coral',
        'PRODUCT': 'coral',
        'HARDWARE': 'coral',
        'BOARD': 'coral',
    };

    Object.keys(fakeBuildValues).forEach(function(key) {
        try {
            Object.defineProperty(Build, key, {
                get: function() { return fakeBuildValues[key]; }
            });
            console.log('[Emulator Bypass] Build.' + key + ' patched');
        } catch(e) {}
    });

    // TelephonyManager
    try {
        var TM = Java.use('android.telephony.TelephonyManager');
        TM.getDeviceId.overload().implementation = function() {
            return '352000000000000';
        };
        TM.getNetworkOperatorName.implementation = function() {
            return 'T-Mobile';
        };
    } catch(e) {}

    console.log('[Emulator Bypass] Emulator detection bypass loaded');
});
"""

# ── Android Debug Detection Bypass ──
FRIDA_DEBUG_BYPASS = """
Java.perform(function() {
    // ApplicationInfo.FLAG_DEBUGGABLE
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        console.log('[Debug Bypass] isDebuggerConnected -> false');
        return false;
    };

    // ActivityManager debug check
    try {
        var ActivityManager = Java.use('android.app.ActivityManager');
        ActivityManager.isRunningInTestHarness.implementation = function() {
            return false;
        };
    } catch(e) {}

    // ApplicationInfo flag
    try {
        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
        ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~2; // clear FLAG_DEBUGGABLE
    } catch(e) {}

    // ptrace anti-debug
    try {
        Interceptor.attach(Module.findExportByName('libc.so', 'ptrace'), {
            onLeave: function(retval) {
                retval.replace(-1);
                console.log('[Debug Bypass] ptrace patched');
            }
        });
    } catch(e) {}

    console.log('[Debug Bypass] Debug detection bypass loaded');
});
"""

# ── Crypto Monitoring ──
FRIDA_CRYPTO_MONITOR = """
Java.perform(function() {
    // Monitor Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[Crypto] Cipher.getInstance: ' + algo);
        return this.getInstance(algo);
    };

    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        console.log('[Crypto] Cipher.doFinal input: ' + bytesToHex(input).substr(0,32));
        console.log('[Crypto] Cipher.doFinal output: ' + bytesToHex(result).substr(0,32));
        return result;
    };

    // Monitor MessageDigest (hashing)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[Crypto] MessageDigest: ' + algo);
        return this.getInstance(algo);
    };

    // Monitor SecretKeySpec (key material)
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(
        key, algo
    ) {
        console.log('[Crypto] SecretKeySpec key (' + algo + '): ' + bytesToHex(key).substr(0,16));
        return this.$init(key, algo);
    };

    // Monitor IvParameterSpec (IV)
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[Crypto] IvParameterSpec IV: ' + bytesToHex(iv));
        return this.$init(iv);
    };

    function bytesToHex(bytes) {
        var hex = '';
        for(var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }

    console.log('[Crypto Monitor] Crypto monitoring loaded');
});
"""

# ── Storage Monitor ──
FRIDA_STORAGE_MONITOR = """
Java.perform(function() {
    // SharedPreferences
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function(key, def) {
        var result = this.getString(key, def);
        console.log('[Storage] SharedPreferences.getString key=' + key
                    + ' value=' + (result ? result.substr(0,20) : 'null'));
        return result;
    };
    SharedPreferences.putString = function(key, value) {
        console.log('[Storage] SharedPreferences.putString key=' + key);
    };

    // File I/O
    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log('[Storage] FileInputStream: ' + path);
        return this.$init(path);
    };

    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log('[Storage] FileOutputStream: ' + path);
        return this.$init(path);
    };

    // SQLite
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.implementation = function(sql, args) {
        console.log('[Storage] SQLiteDatabase.rawQuery: ' + sql.substr(0,100));
        return this.rawQuery(sql, args);
    };

    // Clipboard
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        console.log('[Storage] Clipboard write detected');
        return this.setPrimaryClip(clip);
    };

    console.log('[Storage Monitor] Storage monitoring loaded');
});
"""

# ── Network Monitor ──
FRIDA_NETWORK_MONITOR = """
Java.perform(function() {
    // OkHttp3 Request/Response
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        if(RealCall) {
            RealCall.execute.implementation = function() {
                var request = this.request();
                console.log('[Network] OkHttp3 Request: '
                    + request.method() + ' ' + request.url().toString());
                var response = this.execute();
                console.log('[Network] OkHttp3 Response: ' + response.code());
                return response;
            };
        }
    } catch(e) {}

    // HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getResponseCode.implementation = function() {
            var url = this.getURL().toString();
            var code = this.getResponseCode();
            console.log('[Network] HttpURLConnection: ' + url + ' -> ' + code);
            return code;
        };
    } catch(e) {}

    // Retrofit (OkHttp based)
    try {
        var Interceptor = Java.use('okhttp3.Interceptor');
    } catch(e) {}

    console.log('[Network Monitor] Network monitoring loaded');
});
"""

# ── Biometric Bypass ──
FRIDA_BIOMETRIC_BYPASS = """
Java.perform(function() {
    // BiometricPrompt
    try {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        BiometricPrompt.authenticate.overload(
            'android.os.CancellationSignal',
            'java.util.concurrent.Executor',
            'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
        ).implementation = function(cancel, executor, callback) {
            console.log('[Biometric Bypass] BiometricPrompt.authenticate intercepted');
            var AuthResult = Java.use(
                'android.hardware.biometrics.BiometricPrompt$AuthenticationResult'
            );
            callback.onAuthenticationSucceeded(AuthResult.$new(null));
        };
    } catch(e) {}

    // FingerprintManager (legacy)
    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        FingerprintManager.authenticate.overload(
            'android.hardware.fingerprint.FingerprintManager$CryptoObject',
            'android.os.CancellationSignal',
            'int',
            'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
            'android.os.Handler'
        ).implementation = function(crypto, cancel, flags, callback, handler) {
            console.log('[Biometric Bypass] FingerprintManager.authenticate intercepted');
            var AuthResult = Java.use(
                'android.hardware.fingerprint.FingerprintManager$AuthenticationResult'
            );
            callback.onAuthenticationSucceeded(AuthResult.$new(crypto));
        };
    } catch(e) {}

    // androidx.biometric
    try {
        var BiometricFragment = Java.use(
            'androidx.biometric.BiometricFragment'
        );
        BiometricFragment.onAuthenticationSucceeded.implementation = function(result) {
            console.log('[Biometric Bypass] androidx BiometricFragment.onAuthenticationSucceeded');
            return this.onAuthenticationSucceeded(result);
        };
    } catch(e) {}

    console.log('[Biometric Bypass] Biometric bypass loaded');
});
"""

# ── Full Frida script combining all bypasses ──
FRIDA_FULL_ANDROID = "\n\n".join([
    FRIDA_ANDROID_SSL_BYPASS,
    FRIDA_ROOT_BYPASS,
    FRIDA_EMULATOR_BYPASS,
    FRIDA_DEBUG_BYPASS,
    FRIDA_CRYPTO_MONITOR,
    FRIDA_STORAGE_MONITOR,
    FRIDA_NETWORK_MONITOR,
    FRIDA_BIOMETRIC_BYPASS,
])

FRIDA_FULL_IOS = "\n\n".join([
    FRIDA_IOS_SSL_BYPASS,
])


# ── Objection commands ──
OBJECTION_COMMANDS: dict[str, list[str]] = {
    "ssl_pinning":   [
        "android sslpinning disable",
        "ios sslpinning disable",
    ],
    "root_bypass":   [
        "android root disable",
        "android root simulate",
    ],
    "debug_bypass":  [
        "android hooking search classes Debug",
    ],
    "keychain": [
        "ios keychain dump",
        "ios keychain dump --json",
    ],
    "shared_prefs":  [
        "android shared_preferences list",
        "android shared_preferences get",
    ],
    "crypto":        [
        "android hooking watch class javax.crypto.Cipher",
        "android hooking watch class javax.crypto.spec.SecretKeySpec",
    ],
    "intent":        [
        "android intent launch_activity",
        "android intent launch_service",
    ],
    "env":           [
        "env",
        "android environment",
    ],
    "screenshot":    [
        "android ui screenshot",
        "ios ui screenshot",
    ],
    "classes":       [
        "android hooking list classes",
        "android hooking search classes ssl",
        "android hooking search classes pin",
        "android hooking search classes cert",
    ],
    "jobs":          [
        "jobs list",
    ],
    "memory":        [
        "memory list modules",
        "memory list exports libssl.so",
    ],
}


# ══════════════════════════════════════════════════════════════
# 3. TRAFFIC ANALYSIS
# ══════════════════════════════════════════════════════════════

# Sensitive data patterns for request/response analysis
SENSITIVE_REQUEST_PATTERNS: list[dict] = [
    {"type": "Authorization Header",
     "pattern": r"(?i)^(authorization|x-api-key|x-auth-token): (.+)$",
     "severity": "high"},
    {"type": "Bearer Token",
     "pattern": r"(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})",
     "severity": "high"},
    {"type": "JWT in Body",
     "pattern": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*",
     "severity": "high"},
    {"type": "AWS Key in Traffic",
     "pattern": r"AKIA[0-9A-Z]{16}",
     "severity": "critical"},
    {"type": "Password in Request",
     "pattern": r"(?i)[\"']?(password|passwd|pwd)[\"']?\s*[=:]\s*[\"']?([^\s\"'&]{4,})",
     "severity": "critical"},
    {"type": "Credit Card",
     "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
     "severity": "critical"},
    {"type": "SSN",
     "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
     "severity": "critical"},
    {"type": "Email Address",
     "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
     "severity": "low"},
    {"type": "Google API Key",
     "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "severity": "critical"},
    {"type": "Firebase URL",
     "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com",
     "severity": "medium"},
    {"type": "Private IP",
     "pattern": r"(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
     "severity": "low"},
    {"type": "Stripe Key",
     "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
     "severity": "critical"},
]

# Interesting response patterns
RESPONSE_PATTERNS: list[dict] = [
    {"type": "Stack Trace",
     "pattern": r"(?i)(traceback|stack trace|at java\.|exception in thread)",
     "severity": "medium"},
    {"type": "Debug Info",
     "pattern": r"(?i)(debug|development mode|test environment)",
     "severity": "low"},
    {"type": "SQL Error",
     "pattern": r"(?i)(sql syntax|mysql_fetch|ora-0|postgresql error)",
     "severity": "high"},
    {"type": "Internal Path",
     "pattern": r"(?:/var/www|/home/\w+|/usr/local|C:\\\\inetpub)",
     "severity": "medium"},
    {"type": "Version Info",
     "pattern": r"(?i)(server|x-powered-by|x-aspnet-version): (.+)",
     "severity": "low"},
]

def analyze_intercepted_request(
    method: str,
    url: str,
    req_headers: dict[str, str],
    req_body: Optional[str],
    resp_status: Optional[int],
    resp_headers: dict[str, str],
    resp_body: Optional[str],
) -> InterceptedRequest:
    """
    Analyze an intercepted HTTP request/response pair for security issues.
    """
    host = re.sub(r"https?://([^/]+).*", r"\1", url)
    path = re.sub(r"https?://[^/]+(.*)", r"\1", url) or "/"

    ir = InterceptedRequest(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        method=method.upper(),
        url=url,
        host=host,
        path=path,
        request_headers={k.lower(): v for k, v in req_headers.items()},
        request_body=req_body[:2000] if req_body else None,
        response_status=resp_status,
        response_headers={k.lower(): v for k, v in resp_headers.items()},
        response_body=resp_body[:2000] if resp_body else None,
        response_size=len(resp_body) if resp_body else None,
        is_https=url.startswith("https://"),
    )

    # HTTP cleartext
    if not ir.is_https:
        ir.issues.append("Cleartext HTTP traffic — data transmitted without encryption")
        ir.severity = "high"

    # Auth headers
    auth_hdrs = ["authorization", "x-api-key", "x-auth-token",
                 "x-access-token", "x-csrf-token", "cookie"]
    for h in auth_hdrs:
        if h in ir.request_headers:
            ir.auth_headers.append(f"{h}: {ir.request_headers[h][:20]}...")

    # Scan request for sensitive data
    req_text = (req_body or "") + " ".join(
        f"{k}: {v}" for k, v in req_headers.items()
    )
    for sp in SENSITIVE_REQUEST_PATTERNS:
        if re.search(sp["pattern"], req_text, re.MULTILINE | re.IGNORECASE):
            ir.sensitive_data.append(sp["type"])
            if sp["severity"] in ("critical", "high"):
                ir.issues.append(f"Sensitive data in request: {sp['type']}")
                if sp["severity"] == "critical":
                    ir.severity = "critical"
                elif ir.severity == "info":
                    ir.severity = "high"

    # Scan response
    resp_text = (resp_body or "")
    for rp in RESPONSE_PATTERNS:
        if re.search(rp["pattern"], resp_text, re.MULTILINE | re.IGNORECASE):
            ir.issues.append(f"Sensitive info in response: {rp['type']}")

    # Missing security headers in response
    sec_hdrs = ["strict-transport-security", "x-content-type-options",
                "x-frame-options", "content-security-policy"]
    missing = [h for h in sec_hdrs if h not in ir.response_headers]
    if missing:
        ir.issues.append(f"Missing security headers: {', '.join(missing)}")

    return ir


# ══════════════════════════════════════════════════════════════
# 4. MITMPROXY INTEGRATION
# ══════════════════════════════════════════════════════════════

MITMPROXY_ADDON_SCRIPT = """
# mitmproxy addon script for API traffic capture
import json
import time
from mitmproxy import http

captured = []

class APICapture:
    def request(self, flow: http.HTTPFlow) -> None:
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        entry = {
            "timestamp": time.time(),
            "method":    flow.request.method,
            "url":       flow.request.pretty_url,
            "host":      flow.request.host,
            "path":      flow.request.path,
            "req_headers": dict(flow.request.headers),
            "req_body":  flow.request.content.decode('utf-8', errors='replace')
                         if flow.request.content else None,
            "resp_status": flow.response.status_code if flow.response else None,
            "resp_headers": dict(flow.response.headers) if flow.response else {},
            "resp_body": flow.response.content.decode('utf-8', errors='replace')[:2000]
                         if flow.response and flow.response.content else None,
            "is_https":  flow.request.scheme == "https",
        }
        captured.append(entry)
        # Write to stdout for capture
        print("MITMFLOW:" + json.dumps(entry))

addons = [APICapture()]
"""


def parse_mitmproxy_flow(flow_line: str) -> Optional[InterceptedRequest]:
    """Parse a single mitmproxy flow JSON line."""
    try:
        if not flow_line.startswith("MITMFLOW:"):
            return None
        data = json.loads(flow_line[9:])
        return analyze_intercepted_request(
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            req_headers=data.get("req_headers", {}),
            req_body=data.get("req_body"),
            resp_status=data.get("resp_status"),
            resp_headers=data.get("resp_headers", {}),
            resp_body=data.get("resp_body"),
        )
    except Exception:
        return None


def start_mitmproxy(
    host: str,
    port: int,
    output_file: Optional[str] = None,
    ssl_bypass: bool = True,
    timeout: int = 60,
) -> tuple[Optional[subprocess.Popen], str]:
    """
    Start mitmproxy in the background.
    Returns (process, addon_script_path).
    """
    import tempfile

    # Write addon script to temp file
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="mitm_addon_"
    )
    tmp.write(MITMPROXY_ADDON_SCRIPT)
    tmp.close()

    cmd = [
        "mitmdump",
        "--listen-host", host,
        "--listen-port", str(port),
        "-s", tmp.name,
        "--set", "ssl_insecure=true",
        "--set", "stream_large_bodies=1m",
    ]

    if ssl_bypass:
        cmd += ["--ssl-insecure"]

    if output_file:
        cmd += ["-w", output_file]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(2)   # wait for startup
        return proc, tmp.name
    except Exception as e:
        return None, str(e)


# ══════════════════════════════════════════════════════════════
# 5. FRIDA UTILITIES
# ══════════════════════════════════════════════════════════════

def frida_check_server(host: str, port: int) -> bool:
    """Check if Frida server is reachable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def parse_frida_output(output: str, platform: str) -> tuple[
    SSLPinningResult,
    list[HookResult],
    list[CryptoOperation],
    list[StorageAccess],
    list[SecurityCheckResult],
]:
    """
    Parse Frida script output lines into structured results.
    """
    ssl_result    = SSLPinningResult()
    hooks:        list[HookResult] = []
    crypto_ops:   list[CryptoOperation] = []
    storage_acc:  list[StorageAccess] = []
    sec_checks:   list[SecurityCheckResult] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # ── SSL Bypass messages ──
        if "[SSL Bypass]" in line or "[iOS SSL Bypass]" in line:
            ssl_result.bypassed = True
            ssl_result.pinning_detected = True
            ssl_result.evidence.append(line)

            # Extract host
            host_m = re.search(r"bypassed:\s*([^\s]+)", line)
            if host_m:
                host = host_m.group(1)
                if host not in ssl_result.intercepted_hosts:
                    ssl_result.intercepted_hosts.append(host)
                    ssl_result.intercepted_count += 1

            if "OkHttp" in line:
                ssl_result.pinning_type = "certificate"
                ssl_result.method_used  = "OkHttp3 CertificatePinner hook"
            elif "TrustKit" in line:
                ssl_result.method_used = "TrustKit hook"
            elif "conscrypt" in line:
                ssl_result.method_used = "Conscrypt TrustManagerImpl hook"
            elif "WebView" in line:
                ssl_result.method_used = "WebViewClient SSL hook"
            elif "Flutter" in line:
                ssl_result.method_used = "Flutter ssl_verify_peer_cert hook"
            elif "NetworkSecurityConfig" in line:
                ssl_result.method_used = "NetworkSecurityConfig checkPins hook"
            elif "AFNetworking" in line or "SecTrust" in line:
                ssl_result.method_used = "iOS SecTrust/AFNetworking hook"

        # ── Root Detection Bypass ──
        elif "[Root Bypass]" in line:
            sec_checks.append(SecurityCheckResult(
                check_name="Root Detection",
                category="root",
                detected=True,
                bypassed=True,
                method="Frida runtime hook",
                evidence=[line],
                severity="medium",
            ))

        # ── Emulator Bypass ──
        elif "[Emulator Bypass]" in line:
            sec_checks.append(SecurityCheckResult(
                check_name="Emulator Detection",
                category="emulator",
                detected=True,
                bypassed=True,
                method="Frida Build property hook",
                evidence=[line],
                severity="medium",
            ))

        # ── Debug Bypass ──
        elif "[Debug Bypass]" in line:
            sec_checks.append(SecurityCheckResult(
                check_name="Debug Detection",
                category="debug",
                detected=True,
                bypassed=True,
                method="Frida isDebuggerConnected hook",
                evidence=[line],
                severity="medium",
            ))

        # ── Biometric Bypass ──
        elif "[Biometric Bypass]" in line:
            sec_checks.append(SecurityCheckResult(
                check_name="Biometric Authentication",
                category="biometric",
                detected=True,
                bypassed=True,
                method="Frida BiometricPrompt hook",
                evidence=[line],
                severity="high",
            ))
            hooks.append(HookResult(
                timestamp=ts,
                function_name="BiometricPrompt.authenticate",
                class_name="android.hardware.biometrics.BiometricPrompt",
                finding_type="biometric",
                description="Biometric auth bypassed — callback forced to succeed",
                severity="high",
                tampered=True,
                original_value="pending_authentication",
                new_value="authentication_succeeded",
                evidence=[line],
            ))

        # ── Crypto operations ──
        elif "[Crypto]" in line:
            algo_m    = re.search(r"Cipher\.getInstance:\s*(.+)", line)
            digest_m  = re.search(r"MessageDigest:\s*(.+)", line)
            key_m     = re.search(r"SecretKeySpec key \((.+)\):\s*([0-9a-f]+)", line)
            iv_m      = re.search(r"IvParameterSpec IV:\s*([0-9a-f]+)", line)
            final_m   = re.search(r"Cipher\.doFinal (input|output):\s*([0-9a-f]+)", line)

            if algo_m:
                algo     = algo_m.group(1).strip()
                issues   = []
                severity = "info"

                # Check for weak algorithms
                if any(w in algo.upper() for w in
                       ["DES", "RC4", "RC2", "ECB", "MD5", "SHA1"]):
                    issues.append(f"Weak algorithm in use: {algo}")
                    severity = "high"

                crypto_ops.append(CryptoOperation(
                    algorithm=algo,
                    function_name="Cipher.getInstance",
                    severity=severity,
                    issues=issues,
                ))

            elif digest_m:
                algo     = digest_m.group(1).strip()
                severity = "high" if algo in ("MD5", "SHA-1", "SHA1") else "info"
                crypto_ops.append(CryptoOperation(
                    algorithm=algo,
                    function_name="MessageDigest.getInstance",
                    severity=severity,
                    issues=[f"Weak hash: {algo}"] if severity == "high" else [],
                ))

            elif key_m:
                algo       = key_m.group(1)
                key_hex    = key_m.group(2)
                key_size_b = len(key_hex) // 2
                # Check key size
                issues = []
                severity = "info"
                if algo == "AES" and key_size_b < 32:
                    issues.append(f"AES key size {key_size_b*8} bits < 256 bits")
                    severity = "medium"
                crypto_ops.append(CryptoOperation(
                    algorithm=algo,
                    key_size=key_size_b * 8,
                    key_snippet=key_hex[:16],
                    function_name="SecretKeySpec",
                    severity=severity,
                    issues=issues,
                ))

            elif iv_m:
                iv_hex = iv_m.group(1)
                # Check for static IV
                issues = []
                severity = "info"
                if iv_hex == "0" * len(iv_hex) or len(set(iv_hex)) < 3:
                    issues.append("Potentially static/weak IV detected")
                    severity = "high"
                crypto_ops.append(CryptoOperation(
                    algorithm="AES",
                    iv=iv_hex,
                    function_name="IvParameterSpec",
                    severity=severity,
                    issues=issues,
                ))

        # ── Storage access ──
        elif "[Storage]" in line:
            if "SharedPreferences.getString" in line:
                key_m = re.search(r"key=(\S+)\s+value=(.+)", line)
                if key_m:
                    key = key_m.group(1)
                    val = key_m.group(2)
                    sensitive = any(s in key.lower() for s in
                                    ["password", "token", "secret", "key", "pin"])
                    storage_acc.append(StorageAccess(
                        access_type="prefs_read",
                        key=key,
                        value_snippet=val[:20],
                        sensitive=sensitive,
                        severity="high" if sensitive else "info",
                        evidence=[line],
                    ))

            elif "FileInputStream" in line or "FileOutputStream" in line:
                path_m = re.search(r"(?:FileInput|FileOutput)Stream:\s*(.+)", line)
                if path_m:
                    path = path_m.group(1).strip()
                    sensitive = any(s in path.lower() for s in
                                    ["password", "token", "key", "secret",
                                     "/sdcard", "/storage"])
                    storage_acc.append(StorageAccess(
                        access_type="file_write" if "Output" in line else "file_read",
                        path=path,
                        sensitive=sensitive or "/sdcard" in path,
                        severity="medium" if sensitive else "info",
                        evidence=[line],
                    ))

            elif "SQLiteDatabase.rawQuery" in line:
                sql_m = re.search(r"rawQuery:\s*(.+)", line)
                sql   = sql_m.group(1).strip() if sql_m else ""
                # Check for SQL injection risk
                issues = []
                severity = "info"
                if any(s in sql.lower() for s in ["' or ", "1=1", "union select"]):
                    issues.append("Potential SQL injection in query")
                    severity = "high"
                storage_acc.append(StorageAccess(
                    access_type="db_query",
                    value_snippet=sql[:80],
                    sensitive=True,
                    severity=severity,
                    evidence=[line] + issues,
                ))

            elif "Clipboard" in line:
                storage_acc.append(StorageAccess(
                    access_type="clipboard",
                    sensitive=True,
                    severity="medium",
                    evidence=["Clipboard write detected — may expose sensitive data"],
                ))

        # ── Network hooks ──
        elif "[Network]" in line:
            m = re.search(r"(OkHttp3|HttpURLConnection) (?:Request|Response)?: (.+)", line)
            if m:
                hooks.append(HookResult(
                    timestamp=ts,
                    function_name=m.group(1),
                    finding_type="network",
                    description=m.group(2).strip()[:200],
                    severity="info",
                ))

    return ssl_result, hooks, crypto_ops, storage_acc, sec_checks


# ══════════════════════════════════════════════════════════════
# 6. OBJECTION RUNNER
# ══════════════════════════════════════════════════════════════

def run_objection_commands(
    package: str,
    platform: str,
    commands: list[str],
    device_id: Optional[str] = None,
    timeout: int = 30,
) -> tuple[str, list[str]]:
    """
    Run objection commands against a running app.
    Returns (combined_output, list_of_outputs).
    """
    outputs = []

    for cmd_str in commands:
        # Build objection command
        cmd = ["objection"]
        if device_id:
            cmd += ["--serial", device_id]
        cmd += [
            "--gadget", package,
            "run", cmd_str,
        ]

        stdout, stderr, rc = safe_execute(cmd, timeout)
        output = stdout or stderr
        outputs.append(output[:2000])

    return "\n".join(outputs), outputs


def parse_objection_output(
    output: str,
    platform: str,
) -> tuple[SSLPinningResult, list[HookResult],
           list[StorageAccess], list[SecurityCheckResult]]:
    """
    Parse objection output into structured results.
    """
    ssl_result  = SSLPinningResult()
    hooks:      list[HookResult] = []
    storage:    list[StorageAccess] = []
    sec_checks: list[SecurityCheckResult] = []

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # SSL pinning disable
        if "ssl pinning disabled" in line.lower() or \
           "successfully disabled" in line.lower():
            ssl_result.bypassed = True
            ssl_result.pinning_detected = True
            ssl_result.method_used = "objection ssl pinning disable"
            ssl_result.evidence.append(line)

        # Keychain items (iOS)
        elif "keychain" in line.lower():
            key_m = re.search(r'"(.+?)"\s*:\s*"(.+?)"', line)
            if key_m:
                k, v = key_m.group(1), key_m.group(2)
                sensitive = any(s in k.lower() for s in
                                ["password", "token", "key", "secret"])
                storage.append(StorageAccess(
                    access_type="keychain",
                    key=k,
                    value_snippet=v[:20] + "..." if len(v) > 20 else v,
                    sensitive=sensitive,
                    severity="critical" if sensitive else "medium",
                    evidence=[f"Keychain item: {k}"],
                ))

        # SharedPreferences
        elif "shared_preferences" in line.lower() or "sharedpreferences" in line.lower():
            pref_m = re.search(r'(\S+)\s*=\s*(.+)', line)
            if pref_m:
                k = pref_m.group(1)
                v = pref_m.group(2)
                sensitive = any(s in k.lower() for s in
                                ["password", "token", "key", "secret", "auth"])
                storage.append(StorageAccess(
                    access_type="prefs_read",
                    key=k,
                    value_snippet=v[:30],
                    sensitive=sensitive,
                    severity="high" if sensitive else "info",
                    evidence=[line],
                ))

        # Classes found
        elif re.match(r"^\[.*\] (android|ios)\.", line):
            class_m = re.search(r"\] (\S+)", line)
            if class_m:
                hooks.append(HookResult(
                    timestamp=ts,
                    class_name=class_m.group(1),
                    function_name="class_discovered",
                    finding_type="info",
                    description=f"Class found: {class_m.group(1)}",
                    severity="info",
                ))

        # Root detection
        elif "root" in line.lower() and "simul" in line.lower():
            sec_checks.append(SecurityCheckResult(
                check_name="Root Check",
                category="root",
                detected=True,
                bypassed=True,
                method="objection android root disable",
                evidence=[line],
                severity="medium",
            ))

    return ssl_result, hooks, storage, sec_checks


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
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


# ══════════════════════════════════════════════════════════════
# 8. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def mobile_dynamic_analysis(
    tool:               str,
    target:             str,
    args:               list[str] = [],
    platform:           str = "android",
    device_id:          Optional[str] = None,
    host:               str = "127.0.0.1",
    port:               int = 27042,
    proxy_host:         str = "127.0.0.1",
    proxy_port:         int = 8080,
    scripts:            list[str] = [],
    functions:          list[str] = [],
    intercept_duration: int = 60,
) -> dict:
    """
    🔧 Agent Tool: Mobile Application Dynamic Analysis

    Capabilities:
      ┌─────────────────────────────────────────────────────────────────────┐
      │  SSL PINNING BYPASS   Universal Android bypass: OkHttp3, TrustKit, │
      │                       Conscrypt, Flutter, NSC, WebView, AFNetwork,  │
      │                       iOS SecTrust, AlamoFire, URLSession            │
      │  RUNTIME HOOKING      Crypto ops (key/IV extraction), storage       │
      │                       access, network calls, auth functions          │
      │  TRAFFIC INTERCEPT    mitmproxy integration, full HTTP/HTTPS dump,  │
      │                       sensitive data detection in requests/responses  │
      │  SECURITY BYPASS      Root detection, emulator detection, debug     │
      │                       detection, anti-frida, biometric auth bypass  │
      │  CRYPTO MONITORING    Algorithm detection, key extraction, IV check, │
      │                       weak cipher identification at runtime           │
      │  STORAGE MONITORING   SharedPreferences, files, SQLite, keychain,   │
      │                       clipboard access with content capture          │
      │  FUNCTION TAMPERING   Modify return values, inject values,           │
      │                       bypass conditional checks                      │
      │  TOOL INTEGRATION     Frida, Objection, mitmproxy, manual           │
      └─────────────────────────────────────────────────────────────────────┘

    Args:
        tool:               "frida" | "objection" | "mitmproxy" | "manual"
        target:             Package name or bundle ID
                            (e.g. "com.example.app" or "com.example.ios")
        platform:           "android" | "ios"
        device_id:          ADB device ID or USB device serial
        host:               Frida server host (default: 127.0.0.1)
        port:               Frida server port (default: 27042)
        proxy_host:         mitmproxy host (default: 127.0.0.1)
        proxy_port:         mitmproxy port (default: 8080)
        scripts:            Paths to custom Frida scripts
        functions:          Specific functions/methods to hook
        intercept_duration: Seconds to capture traffic (default: 60)

    Tool args reference:
      frida:
        Attach:     ["-p", "<pid>"] or ["-n", "<process_name>"]
        Spawn:      ["-f", "com.app.package"]
        Script:     ["-l", "script.js"]
        No pause:   ["--no-pause"]
        Timeout:    ["--runtime=v8"]
        Verbose:    ["-v"]

      objection:
        Explore:    ["explore"]
        No banner:  ["--no-banner"]
        Startup:    ["--startup-command", "android sslpinning disable"]
        Script:     ["--startup-script", "script.js"]

      mitmproxy:
        Port:       ["-p", "8080"]
        Mode:       ["--mode", "transparent"]
        Filter:     ["-f", "~h api.example.com"]
        SSL:        ["--ssl-insecure"]
        Decode:     ["--set", "content_decode=true"]

      manual:
        (runs all Frida scripts + traffic capture automatically)

    Returns:
        Structured JSON: ssl_pinning → intercepted_requests → hook_results →
                         security_checks → crypto_operations →
                         storage_accesses → counts
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = MobileDynamicRequest(
            tool=tool, target=target, args=args,
            platform=platform, device_id=device_id,
            host=host, port=port,
            proxy_host=proxy_host, proxy_port=proxy_port,
            scripts=scripts, functions=functions,
            intercept_duration=intercept_duration,
        )
    except Exception as e:
        return MobileDynamicResult(
            success=False, tool=tool, target=target,
            command="", platform=platform,
            error=f"Validation: {e}"
        ).model_dump()

    result = MobileDynamicResult(
        success=False,
        tool=tool,
        target=target,
        command="",
        platform=req.platform,
    )
    techniques_used: list[str] = []
    raw_output:      str = ""
    error_msg:       Optional[str] = None

    # ══════════════════════════════
    # TOOL: FRIDA
    # ══════════════════════════════
    if tool == "frida":

        # ── Check Frida server ──
        if not frida_check_server(req.host, req.port):
            error_msg = (
                f"Frida server not reachable at {req.host}:{req.port}. "
                "Ensure frida-server is running on device and port is forwarded: "
                "adb forward tcp:27042 tcp:27042"
            )
            result.error = error_msg
            return result.model_dump()

        # ── Build Frida script ──
        import tempfile

        # Choose platform-appropriate full script
        if req.platform == "android":
            full_script = FRIDA_FULL_ANDROID
        else:
            full_script = FRIDA_FULL_IOS

        # Append custom scripts
        for script_path in req.scripts:
            try:
                full_script += "\n\n" + Path(script_path).read_text()
            except Exception as e:
                raw_output += f"Script load error ({script_path}): {e}\n"

        # Append custom function hooks
        if req.functions:
            custom_hooks = "Java.perform(function() {\n"
            for fn in req.functions:
                parts = fn.rsplit(".", 1)
                if len(parts) == 2:
                    cls, method = parts
                    custom_hooks += f"""
    try {{
        var cls_{method} = Java.use('{cls}');
        cls_{method}.{method}.implementation = function() {{
            var args_arr = Array.prototype.slice.call(arguments);
            console.log('[Hook] {fn} called with: ' + JSON.stringify(args_arr));
            var ret = this.{method}.apply(this, arguments);
            console.log('[Hook] {fn} returned: ' + JSON.stringify(ret));
            return ret;
        }};
    }} catch(e) {{ console.log('[Hook] Failed to hook {fn}: ' + e); }}
"""
            custom_hooks += "\n});"
            full_script += "\n\n" + custom_hooks
            techniques_used.append("custom_function_hooks")

        # Write combined script to temp file
        tmp_script = tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, prefix="frida_script_"
        )
        tmp_script.write(full_script)
        tmp_script.close()

        # ── Build frida command ──
        if req.args:
            cmd = ["frida"] + list(req.args)
        else:
            cmd = [
                "frida",
                "--host", req.host,
                "--port", str(req.port),
            ]
            if req.device_id:
                cmd += ["-D", req.device_id]
            cmd += [
                "-l", tmp_script.name,
                "--no-pause",
                "-f", target,
            ]

        result.command = " ".join(cmd)

        # ── Execute Frida ──
        stdout, stderr, rc = safe_execute(
            cmd, min(req.timeout, req.intercept_duration + 30)
        )
        raw_output = (stdout or stderr)[:8000]
        techniques_used.append("frida_instrumentation")

        if rc != 0 and not stdout:
            error_msg = (stderr or stdout)[:400]
        else:
            # ── Parse Frida output ──
            combined = (stdout or "") + (stderr or "")
            (ssl_res, hooks, crypto_ops, storage_acc, sec_checks) = \
                parse_frida_output(combined, req.platform)

            result.ssl_pinning       = ssl_res
            result.hook_results      = hooks
            result.crypto_operations = crypto_ops
            result.storage_accesses  = storage_acc
            result.security_checks   = sec_checks

            if ssl_res.bypassed:
                techniques_used.append("ssl_pinning_bypass")
            if crypto_ops:
                techniques_used.append("crypto_monitoring")
            if storage_acc:
                techniques_used.append("storage_monitoring")

            result.success = True

        # ── Cleanup ──
        try:
            os.unlink(tmp_script.name)
        except Exception:
            pass

    # ══════════════════════════════
    # TOOL: OBJECTION
    # ══════════════════════════════
    elif tool == "objection":

        all_outputs: list[str] = []

        # ── Determine commands to run ──
        platform_prefix = "android" if req.platform == "android" else "ios"

        if req.args:
            # Agent-specified commands
            cmds_to_run = req.args
        else:
            # Default: comprehensive scan
            cmds_to_run = [
                f"{platform_prefix} sslpinning disable",
                f"{platform_prefix} root disable"
                if req.platform == "android"
                else "ios jailbreak disable",
                "env",
                f"{platform_prefix} hooking search classes ssl",
                f"{platform_prefix} hooking search classes pin",
                f"{platform_prefix} hooking search classes cert",
            ]

            if req.platform == "android":
                cmds_to_run += [
                    "android shared_preferences list",
                    "android hooking watch class javax.crypto.Cipher",
                    "android hooking list activities",
                    "android hooking list services",
                ]
            else:
                cmds_to_run += [
                    "ios keychain dump",
                    "ios pasteboard monitor",
                    "ios hooking list classes",
                    "ios cookies get",
                ]

        # ── Build startup-based objection command ──
        obj_base_cmd = ["objection"]
        if req.device_id:
            obj_base_cmd += ["--serial", req.device_id]
        obj_base_cmd += ["--gadget", target]

        combined_output = ""

        for obj_cmd in cmds_to_run:
            full_cmd = obj_base_cmd + ["run", obj_cmd]
            result.command = result.command or " ".join(full_cmd)
            stdout, stderr, rc = safe_execute(full_cmd, 30)
            out = stdout or stderr
            combined_output += f"\n# {obj_cmd}\n{out[:1000]}\n"
            all_outputs.append(out)

        raw_output = combined_output[:5000]
        techniques_used.append("objection_exploration")

        # ── Parse objection output ──
        (ssl_res, hooks, storage_acc, sec_checks) = \
            parse_objection_output(combined_output, req.platform)

        result.ssl_pinning      = ssl_res
        result.hook_results     = hooks
        result.storage_accesses = storage_acc
        result.security_checks  = sec_checks

        if ssl_res.bypassed:
            techniques_used.append("ssl_pinning_bypass")
        if storage_acc:
            techniques_used.append("storage_monitoring")

        result.success = True

    # ══════════════════════════════
    # TOOL: MITMPROXY
    # ══════════════════════════════
    elif tool == "mitmproxy":
        import tempfile

        # ── Write addon script ──
        addon_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="mitm_addon_"
        )
        addon_file.write(MITMPROXY_ADDON_SCRIPT)
        addon_file.close()

        # ── Build mitmproxy command ──
        if req.args:
            cmd = ["mitmdump"] + list(req.args) + [
                "-s", addon_file.name,
            ]
        else:
            cmd = [
                "mitmdump",
                "--listen-host", req.proxy_host,
                "--listen-port", str(req.proxy_port),
                "-s", addon_file.name,
                "--ssl-insecure",
                "--set", "ssl_insecure=true",
                "--set", "stream_large_bodies=1m",
            ]

        result.command = " ".join(cmd)
        techniques_used.append("mitmproxy_intercept")

        # ── Start mitmproxy and capture for duration ──
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            captured_lines: list[str] = []
            start_capture  = time.time()

            # Read output for intercept_duration seconds
            def _read_output():
                while time.time() - start_capture < req.intercept_duration:
                    line = proc.stdout.readline()
                    if line:
                        captured_lines.append(line.strip())

            reader = threading.Thread(target=_read_output, daemon=True)
            reader.start()
            reader.join(timeout=req.intercept_duration + 5)

            # Terminate mitmproxy
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

            # ── Parse captured flows ──
            intercepted: list[InterceptedRequest] = []
            for line in captured_lines:
                ir = parse_mitmproxy_flow(line)
                if ir:
                    intercepted.append(ir)

            raw_output = "\n".join(captured_lines[:100])
            result.intercepted_requests = intercepted
            result.ssl_pinning = SSLPinningResult(
                bypassed=any(r.is_https for r in intercepted),
                method_used="mitmproxy ssl_insecure",
                intercepted_count=len(intercepted),
                intercepted_hosts=list({r.host for r in intercepted}),
                evidence=[f"Intercepted {len(intercepted)} requests"],
            )
            result.success = True

        except Exception as e:
            error_msg = f"mitmproxy error: {e}"
        finally:
            try:
                os.unlink(addon_file.name)
            except Exception:
                pass

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    elif tool == "manual":
        """
        Manual mode:
        1. Write all Frida scripts to temp files
        2. Try Frida first (if server available)
        3. Try Objection as fallback
        4. Start mitmproxy for traffic capture
        5. Parse all outputs
        """
        import tempfile

        result.command = f"manual_dynamic_analysis({target})"
        techniques_used.append("manual_dynamic")

        # ── Phase 1: Frida (if available) ──
        if frida_check_server(req.host, req.port):
            full_script = FRIDA_FULL_ANDROID \
                if req.platform == "android" else FRIDA_FULL_IOS

            tmp_script = tempfile.NamedTemporaryFile(
                mode="w", suffix=".js", delete=False, prefix="frida_manual_"
            )
            tmp_script.write(full_script)
            tmp_script.close()

            frida_cmd = [
                "frida",
                "--host", req.host,
                "--port", str(req.port),
                "-l", tmp_script.name,
                "--no-pause",
                "-f", target,
            ]
            if req.device_id:
                frida_cmd += ["-D", req.device_id]

            stdout, stderr, rc = safe_execute(
                frida_cmd,
                min(req.intercept_duration, req.timeout // 2)
            )
            combined = (stdout or "") + (stderr or "")
            raw_output += combined[:3000]

            (ssl_res, hooks, crypto_ops, storage_acc, sec_checks) = \
                parse_frida_output(combined, req.platform)

            result.ssl_pinning       = ssl_res
            result.hook_results.extend(hooks)
            result.crypto_operations.extend(crypto_ops)
            result.storage_accesses.extend(storage_acc)
            result.security_checks.extend(sec_checks)
            techniques_used.append("frida_instrumentation")

            try:
                os.unlink(tmp_script.name)
            except Exception:
                pass

            if ssl_res.bypassed:
                techniques_used.append("ssl_pinning_bypass")

        # ── Phase 2: Objection (supplemental) ──
        obj_cmds = [
            f"{'android' if req.platform == 'android' else 'ios'} sslpinning disable",
            "env",
        ]
        if req.platform == "android":
            obj_cmds.append("android shared_preferences list")
        else:
            obj_cmds.append("ios keychain dump")

        obj_output = ""
        for obj_cmd in obj_cmds:
            full_cmd = ["objection", "--gadget", target, "run", obj_cmd]
            if req.device_id:
                full_cmd = ["objection", "--serial", req.device_id,
                            "--gadget", target, "run", obj_cmd]
            stdout, stderr, _ = safe_execute(full_cmd, 20)
            obj_output += (stdout or stderr)[:500] + "\n"

        if obj_output.strip():
            (obj_ssl, obj_hooks, obj_storage, obj_sec) = \
                parse_objection_output(obj_output, req.platform)
            raw_output += obj_output[:2000]

            if obj_ssl.bypassed and not (result.ssl_pinning and
                                          result.ssl_pinning.bypassed):
                result.ssl_pinning = obj_ssl
            result.hook_results.extend(obj_hooks)
            result.storage_accesses.extend(obj_storage)
            result.security_checks.extend(obj_sec)
            techniques_used.append("objection_exploration")

        # ── Phase 3: mitmproxy traffic capture ──
        addon_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="mitm_manual_"
        )
        addon_file.write(MITMPROXY_ADDON_SCRIPT)
        addon_file.close()

        mitm_cmd = [
            "mitmdump",
            "--listen-host", req.proxy_host,
            "--listen-port", str(req.proxy_port),
            "-s", addon_file.name,
            "--ssl-insecure",
        ]

        try:
            mitm_proc = subprocess.Popen(
                mitm_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            captured_lines: list[str] = []
            cap_start = time.time()
            cap_duration = min(req.intercept_duration, 30)

            def _read_mitm():
                while time.time() - cap_start < cap_duration:
                    try:
                        line = mitm_proc.stdout.readline()
                        if line:
                            captured_lines.append(line.strip())
                    except Exception:
                        break

            t = threading.Thread(target=_read_mitm, daemon=True)
            t.start()
            t.join(timeout=cap_duration + 3)
            mitm_proc.terminate()

            intercepted: list[InterceptedRequest] = []
            for line in captured_lines:
                ir = parse_mitmproxy_flow(line)
                if ir:
                    intercepted.append(ir)

            result.intercepted_requests = intercepted
            if intercepted and not result.ssl_pinning:
                result.ssl_pinning = SSLPinningResult(
                    bypassed=any(r.is_https for r in intercepted),
                    method_used="mitmproxy",
                    intercepted_count=len(intercepted),
                    intercepted_hosts=list({r.host for r in intercepted}),
                )
            techniques_used.append("mitmproxy_intercept")

        except Exception as e:
            raw_output += f"\nmitmproxy error: {e}"
        finally:
            try:
                os.unlink(addon_file.name)
            except Exception:
                pass

        result.success = True

    # ══════════════════════════════
    # POST-PROCESS
    # ══════════════════════════════
    if result.success:
        result.total_requests = len(result.intercepted_requests)
        result.total_hooks    = len(result.hook_results)

        # Count all issues
        all_issues = (
            result.hook_results
            + result.crypto_operations
            + result.storage_accesses
            + [r for r in result.intercepted_requests if r.issues]
        )
        severity_rank = {
            "critical": 4, "high": 3,
            "medium": 2, "low": 1, "info": 0,
        }

        result.critical_count = sum(
            1 for x in all_issues
            if getattr(x, "severity", "info") == "critical"
        )
        result.high_count = sum(
            1 for x in all_issues
            if getattr(x, "severity", "info") == "high"
        )
        result.total_issues = sum(
            1 for x in all_issues
            if getattr(x, "severity", "info") in ("critical", "high", "medium")
        )

        # Sort intercepted by severity
        result.intercepted_requests.sort(
            key=lambda r: severity_rank.get(r.severity, 0),
            reverse=True,
        )

        # Sort crypto ops — weak first
        result.crypto_operations.sort(
            key=lambda c: severity_rank.get(c.severity, 0),
            reverse=True,
        )

    result.techniques_used = list(dict.fromkeys(techniques_used))
    result.raw_output      = raw_output[:5000] if raw_output else None
    result.error           = error_msg
    result.execution_time  = round(time.time() - start, 2)

    return result.model_dump()


# ══════════════════════════════════════════════════════════════
# 9. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

MOBILE_DYNAMIC_TOOL_DEFINITION = {
    "name": "mobile_dynamic_analysis",
    "description": (
        "Dynamic security analysis of running Android/iOS applications. "
        "SSL Pinning Bypass: OkHttp3, TrustKit, Conscrypt, Flutter, NSC, "
        "WebViewClient, AFNetworking, SecTrustEvaluate, iOS URLSession. "
        "Runtime Hooking: crypto operations (key/IV extraction, weak cipher detection), "
        "storage access (SharedPreferences, keychain, files, SQLite, clipboard), "
        "network calls, biometric auth. "
        "Security Bypasses: root detection, emulator detection, debug detection, "
        "anti-frida, biometric prompt. "
        "Traffic Interception: mitmproxy full HTTP/HTTPS dump with sensitive data analysis. "
        "Supports Frida (script injection), Objection (exploration), "
        "mitmproxy (traffic capture), manual (all techniques)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["frida", "objection", "mitmproxy", "manual"],
                "description": (
                    "frida     = JavaScript runtime instrumentation | "
                    "objection = Frida-based mobile exploration toolkit | "
                    "mitmproxy = HTTP/HTTPS traffic interception | "
                    "manual    = all techniques combined (recommended)"
                ),
            },
            "target": {
                "type": "string",
                "description": (
                    "App package name or bundle ID. "
                    "Android: 'com.example.app'. "
                    "iOS: 'com.example.iosapp'"
                ),
            },
            "platform": {
                "type": "string",
                "enum": ["android", "ios"],
                "description": "Target mobile platform",
            },
            "device_id": {
                "type": "string",
                "description": (
                    "ADB device serial or USB device ID. "
                    "Get with: adb devices. "
                    "e.g. 'emulator-5554' or 'R5CX12345'"
                ),
            },
            "host": {
                "type": "string",
                "description": "Frida server host (default: 127.0.0.1)",
            },
            "port": {
                "type": "integer",
                "description": "Frida server port (default: 27042)",
            },
            "proxy_host": {
                "type": "string",
                "description": "mitmproxy listen host (default: 127.0.0.1)",
            },
            "proxy_port": {
                "type": "integer",
                "description": "mitmproxy listen port (default: 8080)",
            },
            "intercept_duration": {
                "type": "integer",
                "description": "Seconds to capture traffic/hooks (default: 60)",
            },
            "scripts": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Paths to custom Frida JavaScript scripts to inject. "
                    "e.g. ['/scripts/custom_hook.js', '/scripts/bypass.js']"
                ),
            },
            "functions": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific functions to hook (class.method format). "
                    "e.g. ['com.example.app.AuthManager.validateToken', "
                    "'com.example.app.CryptoHelper.encrypt']"
                ),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "frida:     ['-f', 'com.app', '-l', 'script.js', '--no-pause']\n"
                    "objection: ['explore', '--startup-command', "
                    "'android sslpinning disable']\n"
                    "mitmproxy: ['-p', '8080', '--ssl-insecure', '-f', '~h api.']\n"
                    "manual:    [] (all techniques auto)"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 10. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ─────────────────────────────
    # 1. Manual — full dynamic analysis
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="manual",
        target="com.example.app",
        platform="android",
        device_id="emulator-5554",
        intercept_duration=60,
    )
    print("=== MANUAL FULL DYNAMIC ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Frida — SSL pinning bypass
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="frida",
        target="com.example.app",
        platform="android",
        host="127.0.0.1",
        port=27042,
        intercept_duration=120,
    )
    print("=== FRIDA SSL BYPASS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. Frida — custom function hooks
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="frida",
        target="com.example.app",
        platform="android",
        functions=[
            "com.example.app.AuthManager.validateToken",
            "com.example.app.CryptoHelper.encryptData",
            "com.example.app.NetworkClient.sendRequest",
        ],
        intercept_duration=60,
    )
    print("=== FRIDA CUSTOM HOOKS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. Frida — with custom scripts
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="frida",
        target="com.example.app",
        platform="android",
        scripts=["/path/to/custom_bypass.js",
                 "/path/to/anti_debug.js"],
        intercept_duration=90,
    )
    print("=== FRIDA CUSTOM SCRIPTS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Objection exploration
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="objection",
        target="com.example.app",
        platform="android",
        args=[
            "android sslpinning disable",
            "android shared_preferences list",
            "android hooking watch class javax.crypto.Cipher",
        ],
    )
    print("=== OBJECTION EXPLORE ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 6. Objection — iOS keychain
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="objection",
        target="com.example.iosapp",
        platform="ios",
        args=[
            "ios sslpinning disable",
            "ios keychain dump",
            "ios cookies get",
            "ios pasteboard monitor",
        ],
    )
    print("=== OBJECTION IOS KEYCHAIN ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 7. mitmproxy traffic capture
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="mitmproxy",
        target="com.example.app",
        platform="android",
        proxy_host="0.0.0.0",
        proxy_port=8080,
        intercept_duration=120,
        args=["--ssl-insecure",
              "--set", "content_decode=true"],
    )
    print("=== MITMPROXY INTERCEPT ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 8. iOS full analysis
    # ─────────────────────────────
    r = mobile_dynamic_analysis(
        tool="manual",
        target="com.example.iosapp",
        platform="ios",
        intercept_duration=60,
    )
    print("=== IOS FULL DYNAMIC ===")
    print(json.dumps(r, indent=2))