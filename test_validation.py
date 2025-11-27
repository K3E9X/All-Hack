#!/usr/bin/env python3
"""
Test script for PoC Validation

Tests the automatic vulnerability validation system.
"""
import asyncio
import httpx
import json
from typing import Dict, Any

# API Configuration
API_BASE = "http://localhost:8000"
API_PREFIX = "/api/v1"

async def test_validation():
    """Test PoC validation endpoints"""

    print("🧪 Testing PoC Validation System\n")

    async with httpx.AsyncClient(timeout=60.0) as client:

        # 1. Create a test scan (replace with your actual scan)
        print("1️⃣  Starting test scan...")
        scan_response = await client.post(
            f"{API_BASE}{API_PREFIX}/scans",
            json={
                "target_url": "http://testphp.vulnweb.com",
                "mode": "black_box"
            }
        )

        if scan_response.status_code != 200:
            print(f"❌ Failed to start scan: {scan_response.text}")
            return

        scan_data = scan_response.json()
        scan_id = scan_data["scan_id"]
        print(f"✅ Scan started: {scan_id}\n")

        # 2. Wait for scan to complete
        print("2️⃣  Waiting for scan to complete...")
        while True:
            result_response = await client.get(
                f"{API_BASE}{API_PREFIX}/scans/{scan_id}"
            )

            if result_response.status_code != 200:
                print(f"❌ Failed to get scan result: {result_response.text}")
                return

            result = result_response.json()
            status = result.get("status", "unknown")

            if status == "completed":
                print(f"✅ Scan completed!\n")
                vuln_count = len(result.get("vulnerabilities", []))
                print(f"📊 Found {vuln_count} vulnerabilities\n")
                break
            elif status == "failed":
                print(f"❌ Scan failed: {result.get('error', 'Unknown error')}")
                return
            elif status in ["pending", "running"]:
                print(f"⏳ Scan status: {status}...")
                await asyncio.sleep(3)
            else:
                print(f"⚠️  Unknown status: {status}")
                await asyncio.sleep(3)

        # 3. Validate all vulnerabilities
        print("3️⃣  Validating all vulnerabilities with PoC...")
        validation_response = await client.post(
            f"{API_BASE}{API_PREFIX}/scans/{scan_id}/validate"
        )

        if validation_response.status_code != 200:
            print(f"❌ Validation failed: {validation_response.text}")
            return

        validation_data = validation_response.json()
        print(f"✅ Validation complete!\n")

        # Display statistics
        stats = validation_data.get("statistics", {})
        print("📊 Validation Statistics:")
        print(f"   Total: {stats.get('total', 0)}")
        print(f"   ✅ Confirmed: {stats.get('confirmed', 0)}")
        print(f"   🟡 Likely: {stats.get('likely', 0)}")
        print(f"   ⚪ Unconfirmed: {stats.get('unconfirmed', 0)}")
        print(f"   ❌ False Positives: {stats.get('false_positives', 0)}")
        print(f"   🎯 Average Confidence: {stats.get('average_confidence', 0.0)}")
        print(f"   📈 Confirmation Rate: {stats.get('confirmation_rate', 0.0)}%\n")

        # Display validated vulnerabilities
        results = validation_data.get("results", [])
        if results:
            print("📋 Validated Vulnerabilities:\n")
            for i, item in enumerate(results[:5], 1):  # Show first 5
                vuln = item.get("vulnerability", {})
                val = item.get("validation", {})

                print(f"{i}. {vuln.get('title', 'Unknown')}")
                print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                print(f"   Status: {val.get('status', 'Unknown')}")
                print(f"   Confidence: {val.get('confidence', 0.0):.2f}")
                print(f"   Evidence: {val.get('evidence', 'N/A')[:100]}...")
                print()

        # 4. Get confirmed vulnerabilities only
        print("4️⃣  Getting confirmed vulnerabilities (confidence >= 0.8)...")
        confirmed_response = await client.get(
            f"{API_BASE}{API_PREFIX}/scans/{scan_id}/confirmed-vulnerabilities",
            params={"min_confidence": 0.8}
        )

        if confirmed_response.status_code == 200:
            confirmed_data = confirmed_response.json()
            total = confirmed_data.get("total_vulnerabilities", 0)
            confirmed = confirmed_data.get("confirmed_vulnerabilities", 0)

            print(f"✅ Confirmed: {confirmed}/{total} vulnerabilities\n")

            # Show confirmed vulnerabilities
            confirmed_vulns = confirmed_data.get("vulnerabilities", [])
            if confirmed_vulns:
                print("🎯 High-Confidence Vulnerabilities:\n")
                for i, vuln in enumerate(confirmed_vulns[:3], 1):
                    print(f"{i}. {vuln.get('title', 'Unknown')}")
                    print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                    print(f"   URL: {vuln.get('affected_url', 'N/A')}")
                    print()

        # 5. Test single vulnerability validation
        if results:
            print("5️⃣  Testing single vulnerability validation...")
            first_vuln = results[0]["vulnerability"]
            vuln_id = first_vuln["id"]

            single_val_response = await client.post(
                f"{API_BASE}{API_PREFIX}/vulnerabilities/{vuln_id}/validate",
                params={"scan_id": scan_id}
            )

            if single_val_response.status_code == 200:
                single_val_data = single_val_response.json()
                val = single_val_data.get("validation", {})

                print(f"✅ Single validation complete!")
                print(f"   Vulnerability: {first_vuln.get('title', 'Unknown')}")
                print(f"   Status: {val.get('status', 'Unknown')}")
                print(f"   Confidence: {val.get('confidence', 0.0):.2f}")
                print(f"   Validator: {val.get('validator', 'Unknown')}")
                print(f"   Evidence: {val.get('evidence', 'N/A')[:150]}...")
                print()

        print("✅ All validation tests completed!\n")

async def test_validation_with_sample_data():
    """Test validation with sample vulnerability data"""

    print("🧪 Testing Validation with Sample Data\n")

    from app.models import Vulnerability, VulnerabilityCategory, SeverityLevel
    from app.validation import get_validation_orchestrator
    from app.utils import PentestHTTPClient

    # Create sample vulnerabilities
    sample_vulns = [
        Vulnerability(
            id="test_sqli_1",
            title="SQL Injection in search parameter",
            category=VulnerabilityCategory.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            affected_url="http://testphp.vulnweb.com/search.php",
            affected_parameter="searchFor",
            description="SQL injection vulnerability detected",
            proof_of_concept="searchFor=' OR 1=1--",
            payload="' OR 1=1--"
        ),
        Vulnerability(
            id="test_xss_1",
            title="Reflected XSS in name parameter",
            category=VulnerabilityCategory.XSS,
            severity=SeverityLevel.MEDIUM,
            affected_url="http://testphp.vulnweb.com/artists.php",
            affected_parameter="artist",
            description="XSS vulnerability detected",
            proof_of_concept="artist=<script>alert('XSS')</script>",
            payload="<script>alert('XSS')</script>"
        )
    ]

    # Get validation orchestrator
    validator = get_validation_orchestrator()

    # Create HTTP client
    client = PentestHTTPClient(base_url="http://testphp.vulnweb.com")

    # Validate all
    print("🔍 Validating sample vulnerabilities...\n")

    for vuln in sample_vulns:
        print(f"Testing: {vuln.title}")
        result = await validator.validate_vulnerability(
            vulnerability=vuln,
            target_url="http://testphp.vulnweb.com",
            client=client
        )

        if result:
            print(f"   Status: {result.status.value}")
            print(f"   Confidence: {result.confidence:.2f}")
            print(f"   Evidence: {result.evidence[:100]}...")
        else:
            print(f"   ⚠️  No validator available")
        print()

    print("✅ Sample validation complete!\n")

def main():
    """Main entry point"""
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        # Test with sample data (requires backend running)
        asyncio.run(test_validation_with_sample_data())
    else:
        # Test with API endpoints
        asyncio.run(test_validation())

if __name__ == "__main__":
    main()
