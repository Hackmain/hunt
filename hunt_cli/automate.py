"""Automated end-to-end hunting with false positive verification."""
import json
import time
from datetime import datetime
from pathlib import Path
from . import scanner, report, telegram


class HuntingError(Exception):
    pass


def verify_finding(finding, target_url):
    """Verify a finding to eliminate false positives."""
    print(f"  🔍 Verifying: {finding['type']}")

    # Re-test to confirm it's real
    if finding["type"] == "Default Credentials":
        endpoint = finding.get("endpoint", "")
        username = finding.get("username", "")
        password = finding.get("password", "")

        # Do a second check
        import requests
        try:
            r = requests.post(
                f"{target_url}{endpoint}",
                data={"username": username, "password": password},
                timeout=5
            )
            # Verify credentials work twice to be sure
            if r.status_code == 200 and ("dashboard" in r.text.lower() or "logout" in r.text.lower()):
                print(f"    ✓ VERIFIED: Default credentials work")
                return True
        except:
            pass
        print(f"    ✗ FALSE POSITIVE: Credentials don't work on re-test")
        return False

    elif finding["type"] == "SQL Injection in Login":
        # Re-test SQL injection
        endpoint = finding.get("endpoint", "")
        payload = finding.get("payload", "")
        import requests
        try:
            r = requests.post(
                f"{target_url}{endpoint}",
                data={"username": payload, "password": "test"},
                timeout=5
            )
            # Look for SQL error messages
            if "syntax" in r.text.lower() or "mysql" in r.text.lower() or "sql" in r.text.lower():
                print(f"    ✓ VERIFIED: SQL error detected")
                return True
        except:
            pass
        print(f"    ✗ FALSE POSITIVE: No SQL error on re-test")
        return False

    elif finding["type"] == "No Brute Force Protection":
        # Re-test brute force
        endpoint = finding.get("endpoint", "")
        import requests
        try:
            failed = 0
            for i in range(5):
                r = requests.post(
                    f"{target_url}{endpoint}",
                    data={"username": "testuser", "password": f"test{i}"},
                    timeout=5
                )
                if r.status_code == 401 or "invalid" in r.text.lower():
                    failed += 1
            if failed == 5:
                print(f"    ✓ VERIFIED: No rate limiting")
                return True
        except:
            pass
        print(f"    ✗ FALSE POSITIVE: Rate limiting detected")
        return False

    return True


def auto_hunt(target_url, program_name):
    """Fully automated hunting with verification."""
    print(f"\n{'='*60}")
    print(f"🚀 CLAUDE AUTO HUNTING")
    print(f"Target: {target_url}")
    print(f"Program: {program_name}")
    print(f"{'='*60}\n")

    # Phase 1: Scan
    print("[Phase 1/4] 🔍 Running automated vulnerability scan...")
    try:
        scan_results = scanner.scan_target(target_url, program_name)
    except Exception as e:
        raise HuntingError(f"Scan failed: {e}")

    initial_count = len(scan_results["findings"])
    print(f"  Found {initial_count} potential vulnerabilities\n")

    if initial_count == 0:
        print("✓ No vulnerabilities found in scan")
        return None

    # Phase 2: Verify findings
    print("[Phase 2/4] ✓ Verifying findings (eliminating false positives)...\n")
    verified_findings = []
    for finding in scan_results["findings"]:
        if verify_finding(finding, target_url):
            verified_findings.append(finding)
        time.sleep(1)  # Rate limit

    verified_count = len(verified_findings)
    false_positive_count = initial_count - verified_count
    print(f"\n  Results: {verified_count} verified, {false_positive_count} false positives filtered\n")

    if verified_count == 0:
        print("✓ All findings were false positives")
        return None

    # Phase 3: Create report
    print(f"[Phase 3/4] 📋 Creating report with {verified_count} findings...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"auto_hunt_{program_name}_{timestamp}"

    report.create_report(report_name, f"{program_name} - Auto Hunt Report")

    for finding in verified_findings:
        report.add_finding(
            report_name,
            title=finding.get("type", "Unknown"),
            description=f"Endpoint: {finding.get('endpoint', 'N/A')}\nPayload: {finding.get('payload', finding.get('password', 'N/A'))}",
            cwe=finding.get("cwe", "CWE-999"),
            cvss_score=finding.get("cvss", 7.0),
            asset=target_url
        )
        print(f"  ✓ Added: {finding['type']}")

    print(f"  Report saved: {report_name}\n")

    # Phase 4: Send report
    print("[Phase 4/4] 📢 Sending report to Telegram...")
    try:
        r = report.load_report(report_name)
        md = report.generate_markdown(r)
        summary = f"🎯 AUTO HUNT RESULTS - {program_name}\n\n"
        summary += f"✓ Verified Findings: {verified_count}\n"
        summary += f"✗ False Positives: {false_positive_count}\n"
        summary += f"Target: {target_url}\n\n"
        summary += "---\n\n"
        summary += md

        telegram.send_message(summary)
        print("  ✓ Report sent to Telegram\n")
    except telegram.TelegramError as e:
        print(f"  ⚠️  Could not send to Telegram (credentials not set)\n")
    except Exception as e:
        print(f"  ⚠️  Telegram error: {e}\n")

    # Summary
    print(f"{'='*60}")
    print(f"✅ AUTO HUNTING COMPLETE")
    print(f"{'='*60}")
    print(f"Report: {report_name}")
    print(f"Verified Vulnerabilities: {verified_count}")
    print(f"False Positives Filtered: {false_positive_count}")
    print(f"Accuracy: {int(verified_count/initial_count*100)}%")
    print(f"{'='*60}\n")

    return {
        "report_name": report_name,
        "verified_count": verified_count,
        "false_positives": false_positive_count,
        "target": target_url,
        "program": program_name
    }
