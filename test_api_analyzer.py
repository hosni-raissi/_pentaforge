#!/usr/bin/env python
"""
Test API Response Analyzer against crAPI
Demonstrates comprehensive API analysis using _common utilities
"""

import os
import sys
import json

# Enable local testing
os.environ["PENTAFORGE_ALLOW_LOCAL_API_TARGETS"] = "true"

from server.agents.executer.recon.tools.api.api_response_analyzer import analyze_api_response

def test_crapi_analysis():
    """Analyze crAPI responses"""

    api_target = "http://127.0.0.1:8888"

    print("=" * 70)
    print("🔍 API Response Analyzer — crAPI Test")
    print("=" * 70)
    print(f"\nTarget: {api_target}")
    print("\nAnalyzing API structure, data exposure, and ID patterns...\n")

    # Run analysis
    result = analyze_api_response(
        target=api_target,
        endpoints=[
            "/",
            "/api",
            "/api/v1",
            "/api/v1/home",
            "/api/v1/user/profile",
            "/api/v1/vehicle/list",
            "/api/v1/community/posts",
        ],
        headers={
            "User-Agent": "PentaForge/1.0",
            "Accept": "application/json",
        },
        timeout=10,
    )

    if not result["success"]:
        print(f"❌ Analysis failed: {result.get('error')}")
        return False

    # Display results
    print(f"✅ Successfully analyzed {result['total_endpoints']} endpoints\n")

    # Endpoint findings
    print("📊 ENDPOINT ANALYSIS")
    print("-" * 70)
    for ep in result["endpoints_analyzed"]:
        print(f"\n  Endpoint: {ep['endpoint']}")
        print(f"    Status: {ep['status_code']} | Size: {ep['response_size']} bytes")
        print(f"    Auth Required: {'✓ Yes' if ep['auth_required'] else '✗ No'}")
        print(f"    Fields Discovered: {len(ep['detected_fields'])}")
        print(f"    ID Candidates: {ep['id_candidates']}")

        if ep['sensitive_data']:
            print(f"    ⚠️  Sensitive Data Found:")
            for sensitive in ep['sensitive_data']:
                print(f"        - {sensitive['field_path']}: {sensitive['sensitivity'].upper()}")
                if sensitive['sample_value']:
                    print(f"          Sample: {sensitive['sample_value'][:40]}")

    # Data discovery insights
    print(f"\n\n📈 DATA DISCOVERY INSIGHTS")
    print("-" * 70)
    print(f"  Total Unique Fields: {len(result['unique_fields_discovered'])}")
    print(f"  ID Patterns Found: {len(result['id_patterns_found'])}")
    print(f"  Common IDs: {', '.join(result['common_id_names'][:5])}")

    if result['sensitive_fields_detected']:
        print(f"\n  🚨 Sensitive Fields Detected:")
        for field in result['sensitive_fields_detected'][:10]:
            print(f"    - {field}")

    # Risk assessment
    print(f"\n\n⚠️  RISK ASSESSMENT")
    print("-" * 70)
    print(f"  Information Disclosure Risk: {result['info_disclosure_risk'].upper()}")
    print(f"  High-Risk Fields: {len(result['high_risk_fields'])}")
    if result['high_risk_fields']:
        print(f"    {', '.join(result['high_risk_fields'][:5])}")

    print(f"\n  Auth Patterns Detected: {len(result['auth_patterns'])}")
    if result['auth_patterns']:
        print(f"    {', '.join(result['auth_patterns'])}")

    print(f"\n  Execution Time: {result['execution_time']:.2f}s")
    print(f"\n{'=' * 70}\n")

    return True


if __name__ == "__main__":
    success = test_crapi_analysis()
    sys.exit(0 if success else 1)
