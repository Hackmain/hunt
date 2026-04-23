"""Auto-report generator - Claude analyzes findings and sends to Telegram."""
import json
from pathlib import Path
from datetime import datetime
from . import telegram


def analyze_findings(findings_json):
    """Claude analyzes raw findings and creates detailed report."""
    findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json

    report_text = f"""
🎯 VULNERABILITY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

TARGET: {findings.get('target', 'Unknown')}
PROGRAM: {findings.get('program', 'Unknown')}

"""

    if not findings.get('findings'):
        report_text += "✓ No vulnerabilities found\n"
        return report_text

    # Group by severity
    critical = [f for f in findings['findings'] if f.get('severity') == 'Critical']
    high = [f for f in findings['findings'] if f.get('severity') == 'High']
    medium = [f for f in findings['findings'] if f.get('severity') == 'Medium']

    if critical:
        report_text += f"🚨 CRITICAL ({len(critical)})\n"
        for f in critical:
            report_text += f"  • {f.get('type')}\n"
            report_text += f"    CWE: {f.get('cwe')}\n"
            report_text += f"    CVSS: {f.get('cvss')}\n"

    if high:
        report_text += f"\n⚠️  HIGH ({len(high)})\n"
        for f in high:
            report_text += f"  • {f.get('type')}\n"
            report_text += f"    CWE: {f.get('cwe')}\n"
            report_text += f"    CVSS: {f.get('cvss')}\n"

    if medium:
        report_text += f"\n📌 MEDIUM ({len(medium)})\n"
        for f in medium:
            report_text += f"  • {f.get('type')}\n"
            report_text += f"    CWE: {f.get('cwe')}\n"
            report_text += f"    CVSS: {f.get('cvss')}\n"

    report_text += f"\n📊 TOTAL: {len(findings['findings'])} vulnerabilities found\n"
    return report_text


def send_report_to_telegram(findings, report_name=""):
    """Automatically send analyzed report to Telegram."""
    try:
        # Analyze findings
        report_text = analyze_findings(findings)

        # Send to Telegram
        telegram.send_message(report_text)
        print("✓ Report sent to Telegram")
        return True

    except telegram.TelegramError as e:
        print(f"❌ Failed to send to Telegram: {e}")
        return False


def watch_and_report(scan_dir="scans"):
    """Watch scan directory and auto-send reports to Telegram."""
    scan_path = Path(scan_dir)
    if not scan_path.exists():
        print(f"❌ {scan_dir} directory not found")
        return

    # Get latest scan file
    scan_files = sorted(scan_path.glob("scan_*.json"))
    if not scan_files:
        print("❌ No scan files found")
        return

    latest_scan = scan_files[-1]
    print(f"📄 Found latest scan: {latest_scan.name}")

    # Load and send
    with open(latest_scan) as f:
        findings = json.load(f)

    send_report_to_telegram(findings, latest_scan.stem)
