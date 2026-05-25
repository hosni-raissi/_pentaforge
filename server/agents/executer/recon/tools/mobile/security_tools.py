"""Curated mobile recon security tool catalog for run_custom usage."""

from __future__ import annotations

from server.agents.executer.recon.tools.security_catalog import normalize_security_catalog

_RAW_MOBILE_APP_RECON_TOOLS: dict[str, dict[str, object]] = {
    # ─────────────────────────────────────────────────────────────
    # 📱 APK/IPA STATIC ANALYSIS (Decompile & Inspect)
    # ─────────────────────────────────────────────────────────────
    "apktool": {
        "t": "static",
        "c": "apk_decompile_resources",
        "u": "apktool d app.apk -o app_decompiled -f",
        "d": ["APK decompilation", "Resource file extraction", "AndroidManifest.xml decoding", "Smali code extraction", "Rebuild capability"],
        "tgt": ["android_apk", "resource_enum", "manifest_analysis"]
    },
    
    "jadx": {
        "t": "static",
        "c": "apk_java_decompile",
        "u": "jadx -d app_source -r -j 4 app.apk",
        "d": ["APK to Java source decompilation", "Resource decoding", "Searchable code view", "Multi-threaded", "GUI/CLI modes"],
        "tgt": ["android_apk", "source_code_review", "api_endpoint_discovery"]
    },
    
    "bytecode-viewer": {
        "t": "static",
        "c": "multi_format_decompile",
        "u": "bytecode-viewer app.apk  # GUI: Auto-decompiles with multiple engines",
        "d": ["Multiple decompiler backends (CFR, FernFlower, Procyon)", "APK/JAR/DEX support", "Search functionality", "Plugin architecture"],
        "tgt": ["android_apk", "java_bytecode", "cross_platform"]
    },
    
    "ios-decompile-tools": {
        "t": "static",
        "c": "ipa_analysis",
        "u": "class-dump -H app_binary > headers.h  # OR  otool -ov app_binary",
        "d": ["iOS binary class-dump", "Objective-C/Swift header extraction", "Method enumeration", "Framework analysis"],
        "tgt": ["ios_ipa", "objective_c", "swift_apps"]
    },
    
    "mobSF": {
        "t": "static",
        "c": "automated_mobile_security_framework",
        "u": "# Web UI: Upload APK/IPA → Auto static analysis + API endpoint extraction",
        "d": ["Automated static analysis", "API key/secret detection", "Certificate pinning detection", "Manifest/Info.plist analysis", "Vulnerability scoring", "REST API available"],
        "tgt": ["android_apk", "ios_ipa", "comprehensive_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📋 MANIFEST & CONFIGURATION ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "aapt2": {
        "t": "static",
        "c": "apk_package_analysis",
        "u": "aapt2 dump badging app.apk | grep -E 'package|sdkVersion|uses-permission'",
        "d": ["APK metadata extraction", "Package name discovery", "SDK version enumeration", "Permission listing", "Activity/service/intent-filter discovery"],
        "tgt": ["android_apk", "manifest_enum", "permission_audit"]
    },
    
    "bundletool": {
        "t": "static",
        "c": "aab_analysis",
        "u": "bundletool dump manifest --bundle=app.aab --output=manifest.xml",
        "d": ["Android App Bundle (AAB) analysis", "Manifest extraction", "Resource inspection", "Split APK enumeration"],
        "tgt": ["android_aab", "modern_android", "play_store_apps"]
    },
    
    "plist-extractor": {
        "t": "static",
        "c": "ios_plist_analysis",
        "u": "plutil -convert xml1 -o Info.plist Info.plist.bak  # OR  defaults read Info.plist",
        "d": ["iOS Info.plist parsing", "Bundle identifier extraction", "URL scheme enumeration", "Permission descriptions", "Background mode detection"],
        "tgt": ["ios_ipa", "plist_config", "ios_permissions"]
    },
    
    "android-manifest-parser": {
        "t": "static",
        "c": "intent_filter_enum",
        "u": "axmlparser AndroidManifest.xml | grep -E 'activity|service|receiver|provider'",
        "d": ["Component enumeration (Activity/Service/BroadcastReceiver/ContentProvider)", "Intent-filter analysis", "Deep link discovery", "Exported component identification"],
        "tgt": ["android_apk", "component_mapping", "attack_surface"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔐 CERTIFICATE & SIGNING ANALYSIS
    # ─────────────────────────────────────────────────────────────
    "apksigner": {
        "t": "static",
        "c": "apk_signature_verify",
        "u": "apksigner verify --print-certs app.apk | grep -E 'SHA-256|subject'",
        "d": ["APK signature verification", "Certificate chain extraction", "Signer identity enumeration", "Signature scheme detection (v1/v2/v3/v4)"],
        "tgt": ["android_apk", "signature_analysis", "tamper_detection"]
    },
    
    "jarsigner": {
        "t": "static",
        "c": "jar_apk_signature_check",
        "u": "jarsigner -verify -verbose -certs app.apk | head -50",
        "d": ["JAR/APK signature validation", "Certificate details", "Timestamp verification", "Digest algorithm inspection"],
        "tgt": ["android_apk", "java_jar", "signature_enum"]
    },
    
    "certificate-pin-detector": {
        "t": "static",
        "c": "pinning_config_discovery",
        "u": "grep -r 'CertificatePinner\\|setPinnedCertificates\\|publicKeyPins' app_decompiled/ 2>/dev/null",
        "d": ["SSL pinning configuration detection", "OkHttp/Retrofit pinning identification", "Network security config analysis", "Pin backup detection"],
        "tgt": ["android_apk", "ios_ipa", "ssl_pinning_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🔑 SECRETS & API KEY EXTRACTION
    # ─────────────────────────────────────────────────────────────
    "trufflehog-mobile": {
        "t": "static",
        "c": "secret_scanning",
        "u": "trufflehog filesystem app_decompiled/ --only-verified --json",
        "d": ["High-entropy string detection", "API key discovery", "Private key identification", "Credential leakage detection", "Verified secrets only"],
        "tgt": ["android_apk", "ios_ipa", "secret_hunting"]
    },
    
    "gitleaks-mobile": {
        "t": "static",
        "c": "credential_enum",
        "u": "gitleaks detect --source=app_decompiled/ --report-path secrets.json --report-format json",
        "d": ["Secret pattern matching", "API token discovery", "Password detection", "Config file scanning", "JSON report generation"],
        "tgt": ["android_apk", "ios_ipa", "cred_leak_recon"]
    },
    
    "ripgrep-secrets": {
        "t": "static",
        "c": "pattern_based_secret_hunt",
        "u": "rg -i 'api[_-]?key|password|secret|token|bearer' app_decompiled/ -t smali -t xml -t json",
        "d": ["Fast regex-based secret search", "Smali/XML/JSON filtering", "Case-insensitive matching", "Context extraction"],
        "tgt": ["android_apk", "ios_ipa", "quick_secret_scan"]
    },
    
    "aws-mobile-detector": {
        "t": "static",
        "c": "cloud_cred_discovery",
        "u": "grep -rE 'AKIA[0-9A-Z]{16}|aws_access_key|aws_secret' app_decompiled/ 2>/dev/null",
        "d": ["AWS access key detection", "S3 bucket enumeration", "Cognito pool ID discovery", "API Gateway endpoint extraction"],
        "tgt": ["android_apk", "ios_ipa", "aws_integration"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🌐 API ENDPOINT & BACKEND DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "api-endpoint-extractor": {
        "t": "static",
        "c": "url_string_harvesting",
        "u": "grep -roE 'https?://[a-zA-Z0-9.-]+/api[^\"\\s]*' app_decompiled/ | sort -u",
        "d": ["Hardcoded API endpoint extraction", "Base URL discovery", "REST/GraphQL endpoint mapping", "Environment URL enumeration (dev/staging/prod)"],
        "tgt": ["android_apk", "ios_ipa", "backend_discovery"]
    },
    
    "strings-analyzer": {
        "t": "static",
        "c": "binary_string_extraction",
        "u": "strings app_binary | grep -iE 'api|http|graphql|rest|v[0-9]+' | sort -u",
        "d": ["Binary string extraction", "URL/endpoint discovery", "Domain enumeration", "Protocol detection", "Filtering for API patterns"],
        "tgt": ["android_apk", "ios_ipa", "native_binaries"]
    },
    
    "firebase-config-parser": {
        "t": "static",
        "c": "firebase_enum",
        "u": "grep -r 'firebaseio.com\\|googleapis.com.*firebase' app_decompiled/ | sort -u",
        "d": ["Firebase Realtime Database URL extraction", "Firestore configuration discovery", "API key enumeration", "Project ID identification", "Storage bucket discovery"],
        "tgt": ["android_apk", "ios_ipa", "firebase_integration"]
    },

    # ─────────────────────────────────────────────────────────────
    # 📡 DEEP LINK & URL SCHEME ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "deep-link-finder": {
        "t": "static",
        "c": "intent_scheme_discovery",
        "u": "aapt2 dump xmltree app.apk AndroidManifest.xml | grep -A5 'intent-filter' | grep -E 'data|scheme|host'",
        "d": ["Deep link enumeration", "URL scheme discovery (myapp://)", "App link detection (https://domain.com/path)", "Intent-filter analysis", "Exported activity mapping"],
        "tgt": ["android_apk", "deep_links", "app_links"]
    },
    
    "ios-url-scheme-enum": {
        "t": "static",
        "c": "custom_scheme_discovery",
        "u": "plutil -p Info.plist | grep -A10 'CFBundleURLTypes' | grep -E 'CFBundleURLName|CFBundleURLSchemes'",
        "d": ["iOS custom URL scheme enumeration", "Universal link detection", "Associated domain discovery", "App extension analysis"],
        "tgt": ["ios_ipa", "url_schemes", "universal_links"]
    },
    
    # ─────────────────────────────────────────────────────────────
    # 📚 LIBRARY & DEPENDENCY ENUMERATION
    # ─────────────────────────────────────────────────────────────
    "library-detector": {
        "t": "static",
        "c": "third_party_lib_enum",
        "u": "grep -r 'Lokhttp3\\|Lretrofit2\\|Lcom/google/gson\\|Lcom/facebook' app_decompiled/ | cut -d: -f1 | sort -u",
        "d": ["Third-party library detection", "Networking library identification (OkHttp/Retrofit)", "JSON parser discovery (Gson/Jackson)", "Analytics SDK enumeration", "Ad network detection"],
        "tgt": ["android_apk", "dependency_mapping", "supply_chain_recon"]
    },
    
    "cocoapods-enum": {
        "t": "static",
        "c": "ios_dependency_analysis",
        "u": "grep -r 'Pods/' Payload/app.app/ | head -20  # OR  otool -L app_binary",
        "d": ["CocoaPods dependency enumeration", "Framework linking analysis", "Third-party library detection", "Version identification"],
        "tgt": ["ios_ipa", "ios_dependencies", "framework_enum"]
    },
    
    "native-lib-analyzer": {
        "t": "static",
        "c": "so_dll_enum",
        "u": "readelf -d libnative.so | grep NEEDED  # OR  ldd app_binary",
        "d": ["Native library (.so/.dll) enumeration", "Dynamic dependency analysis", "C/C++ library detection", "JNI bridge identification"],
        "tgt": ["android_ndk", "ios_native", "native_code_recon"]
    },

    # ─────────────────────────────────────────────────────────────
    # 🛡️ SECURITY CONFIGURATION DISCOVERY
    # ─────────────────────────────────────────────────────────────
    "network-security-config-parser": {
        "t": "static",
        "c": "android_network_config",
        "u": "cat res/xml/network_security_config.xml 2>/dev/null | grep -E 'cleartext|pin-set|certificate'",
        "d": ["Android Network Security Config analysis", "Cleartext traffic permission detection", "Certificate pinning configuration", "Trust anchor enumeration", "Debug override detection"],
        "tgt": ["android_apk", "network_config", "ssl_config"]
    },
    
    "ios-ats-checker": {
        "t": "static",
        "c": "app_transport_security",
        "u": "plutil -p Info.plist | grep -A20 'NSAppTransportSecurity'",
        "d": ["iOS App Transport Security (ATS) configuration", "Cleartext HTTP allowance detection", "Exception domain enumeration", "Certificate validation settings"],
        "tgt": ["ios_ipa", "ats_config", "ios_network_security"]
    },
    
    "permission-auditor": {
        "t": "static",
        "c": "permission_enum",
        "u": "aapt2 dump permissions app.apk | grep -E 'uses-permission|permission'",
        "d": ["Android permission enumeration", "Dangerous permission identification", "Custom permission discovery", "Permission group mapping"],
        "tgt": ["android_apk", "permission_audit", "privacy_recon"]
    },

    "mobile-recon-automation": {
        "t": "automation",
        "c": "pipeline_orchestration",
        "u": "# Your script: apktool d app.apk && jadx -d src app.apk && grep -r 'api' src/ | tee endpoints.txt",
        "d": ["Multi-tool chaining", "Automated decompilation → analysis → extraction", "JSON/XML report generation", "Deduplication", "CI/CD integration"],
        "tgt": ["android_apk", "ios_ipa", "scalable_recon"]
    },
    
    "docker-mobile-recon": {
        "t": "automation",
        "c": "containerized_toolchain",
        "u": "docker run -v $(pwd):/data opensecurity/mobile-security-framework-mobsf app.apk",
        "d": ["Reproducible mobile recon environments", "Version-pinned tools", "Clean workspaces", "Pre-configured toolchains", "No host pollution"],
        "tgt": ["android_apk", "ios_ipa", "lab_environment"]
    },
    
    "custom-api-extractor": {
        "t": "automation",
        "c": "specialized_endpoint_harvesting",
        "u": "# Your Python script: Parse smali/XML/JSON → Extract URLs → Validate → Report",
        "d": ["Custom regex patterns", "API endpoint validation", "Environment detection (dev/staging/prod)", "Duplicate removal", "Structured output (JSON/CSV)"],
        "tgt": ["android_apk", "ios_ipa", "engagement_specific"]
    }
}

MOBILE_APP_RECON_TOOLS: dict[str, dict[str, object]] = normalize_security_catalog(_RAW_MOBILE_APP_RECON_TOOLS)

network_tools = MOBILE_APP_RECON_TOOLS
