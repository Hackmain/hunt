"""Claude-powered intelligent bug hunting - auto selects programs and targets."""
import json
import os
import sys
import subprocess
from datetime import datetime
from . import h1, scanner, telegram


def _ensure_anthropic():
    """Lazy import - install anthropic if missing."""
    try:
        import anthropic
        return anthropic
    except ImportError:
        print("📦 Installing anthropic package (first run)...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "anthropic"],
            stdout=subprocess.DEVNULL,
        )
        import anthropic
        print("✓ anthropic installed")
        return anthropic


def get_claude_program_selection(programs):
    """Use Claude to intelligently select best program to hunt."""
    anthropic = _ensure_anthropic()
    if not programs:
        raise ValueError("No programs available")

    programs_text = "\n".join([
        f"- {p['attributes']['handle']}: {p['attributes']['name']}"
        for p in programs
    ])

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    message = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=500,
        messages=[
            {
                "role": "user",
                "content": f"""You are a security researcher selecting a bug bounty program to hunt.

Available programs:
{programs_text}

Choose ONE program that would likely have the most security vulnerabilities based on:
1. Program size and complexity (larger is better)
2. Technology stack hints from the name
3. Likelihood of finding exploitable bugs

Respond with ONLY the program handle (e.g., "example_program"), nothing else."""
            }
        ]
    )

    handle = message.content[0].text.strip()
    print(f"🤖 Claude selected program: {handle}")
    return handle


def get_claude_target_selection(handle, scopes):
    """Use Claude to intelligently select best target from scope."""
    anthropic = _ensure_anthropic()
    if not scopes:
        raise ValueError(f"No targets in scope for {handle}")

    in_scope = [s for s in scopes if s.get("attributes", {}).get("eligible_for_submission")]
    if not in_scope:
        raise ValueError(f"No eligible targets for {handle}")

    targets_text = "\n".join([
        f"- {s['attributes']['asset_identifier']} ({s['attributes']['asset_type']})"
        for s in in_scope[:20]  # Limit to first 20 for context
    ])

    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    message = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=500,
        messages=[
            {
                "role": "user",
                "content": f"""You are selecting a target to test for security vulnerabilities.

Available targets in scope:
{targets_text}

Choose ONE target that is most likely to have exploitable security vulnerabilities based on:
1. Web applications are typically better targets than mobile/hardware
2. Complex systems more likely than simple APIs
3. Look for common patterns that typically have bugs (login, payment, file upload)

Respond with ONLY the exact target identifier (e.g., "api.example.com"), nothing else."""
            }
        ]
    )

    target = message.content[0].text.strip()
    print(f"🤖 Claude selected target: {target}")
    return target


def run_intelligent_hunt(program_handle=None):
    """Run Claude-powered hunting: select program, select target, scan, report."""

    print("\n🔍 CLAUDE BUG HUNTING - INTELLIGENT MODE\n")

    # Get all programs
    print("📋 Fetching available programs...")
    try:
        programs = h1.list_programs()
    except h1.H1Error as e:
        raise ValueError(f"Failed to fetch programs: {e}")

    if not programs:
        raise ValueError("No programs available")

    print(f"Found {len(programs)} programs")

    # Let Claude select program if not specified
    if not program_handle:
        selected_handle = get_claude_program_selection(programs)
    else:
        selected_handle = program_handle

    # Get scopes for selected program
    print(f"📍 Fetching targets for {selected_handle}...")
    try:
        scopes = h1.program_scopes(selected_handle)
    except h1.H1Error as e:
        raise ValueError(f"Failed to fetch scopes for {selected_handle}: {e}")

    # Let Claude select target
    target = get_claude_target_selection(selected_handle, scopes)

    # Normalize target to URL
    if not target.startswith(("http://", "https://")):
        target_url = f"https://{target}"
    else:
        target_url = target

    # Run scan
    print(f"\n🔨 Scanning {target_url}...")
    try:
        results = scanner.scan_target(target_url, selected_handle)
    except scanner.ScannerError as e:
        raise ValueError(f"Scan failed: {e}")

    # Generate report
    report = generate_hunt_report(selected_handle, target, results)

    # Send to Telegram
    print("📤 Sending to Telegram...")
    try:
        telegram.send_message(report)
        print("✓ Report sent to Telegram")
    except telegram.TelegramError as e:
        print(f"⚠️  Failed to send to Telegram: {e}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"Program: {selected_handle}")
    print(f"Target: {target}")
    if results["findings"]:
        print(f"Vulnerabilities found: {len(results['findings'])}")
        for finding in results["findings"]:
            print(f"  - [{finding['severity']}] {finding['type']}")
    else:
        print("No vulnerabilities found")
    print(f"{'='*60}\n")

    return {
        "program": selected_handle,
        "target": target,
        "findings": results["findings"]
    }


def generate_hunt_report(program, target, results):
    """Format hunt results for Telegram."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""<b>🔍 CLAUDE INTELLIGENT BUG HUNT</b>

<b>Program:</b> {program}
<b>Target:</b> {target}
<b>Time:</b> {timestamp}

"""

    if results["findings"]:
        report += f"<b>⚠️  Found {len(results['findings'])} vulnerabilities:</b>\n\n"
        for finding in results["findings"]:
            report += f"<b>[{finding['severity']}]</b> {finding['type']}\n"
            report += f"  CWE: {finding.get('cwe', 'N/A')}\n"
            report += f"  CVSS: {finding.get('cvss', 'N/A')}\n"
            if "endpoint" in finding:
                report += f"  Endpoint: {finding['endpoint']}\n"
            report += "\n"
    else:
        report += "<b>✓ No vulnerabilities found</b>\n"

    report += f"\n<i>Scanned and reported by Claude Intelligence Engine</i>"

    return report
