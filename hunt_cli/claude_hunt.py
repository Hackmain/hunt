"""Claude-powered autonomous bug hunting - fetches H1 scope and lets Claude CLI do the work."""
import os
import subprocess
from datetime import datetime
from . import h1, telegram


def build_target_prompt(target):
    """Build autonomous hunting prompt for a specific target."""
    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    telegram_chat = os.environ.get("TELEGRAM_CHAT_ID", "")

    return f"""You are an autonomous bug bounty hunter. Bug hunting this "{target}".

## Your Mission
1. Run active security tests against {target} using bash tools (curl, nmap, whatweb, etc.).
2. Test for: default creds, SQLi, XSS, open redirects, IDOR, exposed admin panels, missing auth, info disclosure, CORS misconfig, directory traversal, sensitive files (.env, .git, backup files).
3. Confirm every finding is real before reporting.
4. Send your report to Telegram when done.

## Telegram Credentials
TELEGRAM_BOT_TOKEN = {telegram_token}
TELEGRAM_CHAT_ID   = {telegram_chat}

Send report with:
```
curl -s -X POST "https://api.telegram.org/bot{telegram_token}/sendMessage" \\
  -d chat_id="{telegram_chat}" \\
  -d parse_mode="HTML" \\
  -d text="<YOUR_REPORT_HERE>"
```

## Report Format
```
<b>🔍 BUG HUNT REPORT</b>
<b>Target:</b> {target}
<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}

[findings or ✓ No vulnerabilities confirmed]

<i>Hunted autonomously by Claude</i>
```

Start now. Test {target} and send the report to Telegram when done.
"""


def run_target_hunt(target):
    """Launch Claude CLI to autonomously hunt a specific target."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    print(f"\n🔍 CLAUDE BUG HUNTING: {target}\n")
    print("🤖 Launching Claude CLI with --dangerously-skip-permissions...\n")
    print("=" * 60)

    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)

    prompt = build_target_prompt(target)

    result = subprocess.run(
        ["claude", "--dangerously-skip-permissions", "-p", prompt],
        text=True,
        env=env,
    )

    print("=" * 60)

    if result.returncode != 0:
        raise RuntimeError("Claude CLI exited with an error")


def build_autonomous_prompt(programs, scopes_by_handle):
    """Build the full autonomous hunting prompt for Claude CLI."""
    programs_block = "\n".join([
        f"  - handle: {p['attributes']['handle']}  name: {p['attributes']['name']}"
        for p in programs[:30]
    ])

    scopes_block = ""
    for handle, scopes in scopes_by_handle.items():
        in_scope = [
            s for s in scopes
            if s.get("attributes", {}).get("eligible_for_submission")
        ]
        if not in_scope:
            continue
        scopes_block += f"\n[{handle}]\n"
        for s in in_scope[:10]:
            a = s["attributes"]
            scopes_block += f"  {a['asset_type']:<15} {a['asset_identifier']}\n"

    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    telegram_chat = os.environ.get("TELEGRAM_CHAT_ID", "")

    return f"""You are an autonomous bug bounty hunter. Your job is to find real vulnerabilities in HackerOne programs and report them.

## HackerOne Programs Available
{programs_block}

## In-Scope Targets (per program)
{scopes_block}

## Your Mission
1. Pick the single best program and target from the lists above (prefer web apps over mobile/hardware).
2. Run active security tests against that target using bash tools (curl, nmap, whatweb, etc.).
3. Test for common vulnerabilities: default creds, SQLi, XSS, open redirects, IDOR, exposed admin panels, missing auth, info disclosure, CORS misconfig, directory traversal.
4. For each finding: confirm it is real (not a false positive) before reporting.
5. Format a Telegram report and send it using the bot credentials below.

## Telegram Credentials (already set in environment)
TELEGRAM_BOT_TOKEN = {telegram_token}
TELEGRAM_CHAT_ID   = {telegram_chat}

Send your final report with this curl command (fill in the message):
```
curl -s -X POST "https://api.telegram.org/bot{telegram_token}/sendMessage" \\
  -d chat_id="{telegram_chat}" \\
  -d parse_mode="HTML" \\
  -d text="<YOUR_REPORT_HERE>"
```

## Report Format
```
<b>🔍 BUG HUNT REPORT</b>
<b>Program:</b> [handle]
<b>Target:</b> [url]
<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}

[If findings:]
<b>⚠️ Vulnerabilities Found:</b>

<b>[SEVERITY]</b> [Type]
  Endpoint: [url]
  Evidence: [proof]
  CWE: [number]
  CVSS: [score]

[If no findings:]
<b>✓ No vulnerabilities confirmed on this target.</b>

<i>Hunted autonomously by Claude</i>
```

Start now. Pick your target, run your tests, and send the report to Telegram when done.
"""


def run_intelligent_hunt(program_handle=None):
    """Fetch H1 scope then launch Claude CLI to hunt autonomously."""

    print("\n🔍 CLAUDE AUTONOMOUS BUG HUNT\n")

    print("📋 Fetching programs from HackerOne...")
    try:
        programs = h1.list_programs()
    except h1.H1Error as e:
        raise ValueError(f"Failed to fetch programs: {e}")

    if not programs:
        raise ValueError("No programs available")

    # If specific program requested, only fetch that scope; otherwise sample top 5
    if program_handle:
        target_programs = [p for p in programs if p["attributes"]["handle"] == program_handle]
    else:
        target_programs = programs[:5]

    scopes_by_handle = {}
    for p in target_programs:
        handle = p["attributes"]["handle"]
        print(f"  Fetching scope for {handle}...")
        try:
            scopes_by_handle[handle] = h1.program_scopes(handle)
        except h1.H1Error:
            scopes_by_handle[handle] = []

    prompt = build_autonomous_prompt(programs, scopes_by_handle)

    print("\n🤖 Launching Claude CLI with --dangerously-skip-permissions...\n")
    print("=" * 60)

    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)  # use subscription auth, not API key

    result = subprocess.run(
        ["claude", "--dangerously-skip-permissions", "-p", prompt],
        text=True,
        env=env,
    )

    print("=" * 60)

    if result.returncode != 0:
        raise RuntimeError("Claude CLI exited with an error")

    return {"status": "complete"}
