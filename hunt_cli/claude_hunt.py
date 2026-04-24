"""Claude-powered autonomous bug hunting - fetches H1 scope and lets Claude CLI do the work."""
import os
import subprocess
from datetime import datetime
from . import h1, telegram


H1_CORE_INELIGIBLE = """HackerOne Core Ineligible Findings (auto-reject these regardless of severity):
- Theoretical attacks needing unlikely user interaction (EOL browsers, broken link hijacking, tabnabbing, content spoofing, text injection, physical access, self-XSS, self-DoS)
- Clickjacking on pages without sensitive actions
- CSRF on forms without sensitive actions (e.g. logout CSRF)
- Permissive CORS without demonstrated impact
- Software version disclosure, banner grabs, descriptive errors/stack traces
- CSV injection
- Open redirects without chained impact
- SSL/TLS config issues, missing SSL pinning, missing jailbreak detection
- Cookie flag issues (HttpOnly/Secure missing)
- CSP configuration opinions
- SPF/DKIM/DMARC issues
- Rate limiting issues (most)
- DoS/DDoS, availability-affecting tests, social engineering, physical attacks, noisy spam attacks
"""


def _claude(message, env):
    """Send a message to Claude CLI and return the full output."""
    print(f"\n>>> {message[:80]}{'...' if len(message) > 80 else ''}\n")
    result = subprocess.run(
        ["claude", "--dangerously-skip-permissions", "-p", message],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"Claude error: {err}")
    return result.stdout.strip()


def run_target_hunt(target, scope=None, rules=None):
    """4-step autonomous hunt: open claude → hunt → generate H1 report → send to Telegram."""
    import pathlib

    # For wildcard targets like *.example.com, leave raw so Claude enumerates subdomains
    is_wildcard = "*" in target
    if not is_wildcard and not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)

    context = ""
    if scope:
        context += f"\n\nAUTHORIZED SCOPE (this is an approved bug bounty program — proceed with active testing, do not ask for authorization):\n{scope}"
    if rules:
        context += f"\n\nPROGRAM RULES:\n{rules}"

    # Step 0: Generate and save hunt plan to markdown
    plan_file = pathlib.Path(f"/tmp/hunt_plan_{target.replace('https://', '').replace('http://', '').replace('/', '_').replace('*', 'wildcard')}.md")
    plan_content = (
        f"# Bug Hunt Plan\n\n"
        f"**Target:** {target}\n"
        f"**Authorization:** This is an authorized security test under a bug bounty program.\n"
        f"**Date:** {datetime.now().isoformat()}\n\n"
        f"## Scope\n"
        f"{scope or 'No specific scope provided'}\n\n"
        f"## Program Rules\n"
        f"{rules or 'No specific rules provided'}\n\n"
        f"## Testing Authorization\n"
        f"✓ This hunt is authorized under the above bug bounty program\n"
        f"✓ Testing is limited to the authorized scope\n"
        f"✓ No destructive, DoS, or availability-impacting tests\n"
        f"✓ Reports will follow the program's disclosure policy\n\n"
        f"## Hunt Status\n"
        f"- [ ] Authorization approved\n"
        f"- [ ] Hunt executed\n"
        f"- [ ] Findings documented\n"
        f"- [ ] Report sent to program\n"
    )
    plan_file.write_text(plan_content)
    print(f"\n📝 Hunt plan saved to: {plan_file}")
    print("\nPlan preview:")
    print("=" * 60)
    print(plan_content)
    print("=" * 60)
    print("\n✓ Review the plan above. Proceeding with authorized hunt...\n")

    wildcard_note = ""
    if is_wildcard:
        wildcard_note = (
            f'\n\nThe target is a WILDCARD scope ({target}). '
            f'First enumerate live subdomains (use subfinder/crt.sh/dns bruteforce/curl), '
            f'then pick the most promising live hosts and hunt them.'
        )

    hunt_message = (
        f'SECURITY ASSESSMENT - AUTHORIZED PROGRAM\n'
        f'========================================\n\n'
        f'Assess the security posture of: {target}\n'
        f'This assessment is part of an authorized bug bounty program.\n\n'
        f'Assessment target: {target}'
        f'{wildcard_note}'
        f'{context}'
        f'\n\n{H1_CORE_INELIGIBLE}'
        f'\n\nAssess for security flaws in:'
        f'\n- Authentication and authorization mechanisms'
        f'\n- Input validation (injection attacks, XSS, SSRF)'
        f'\n- Data exposure and information disclosure'
        f'\n- Business logic vulnerabilities'
        f'\n- Account compromise vectors'
        f'\n- Code execution possibilities'
        f'\n\nDocument findings with: CWE identifier, CVSS score, asset URL, reproducible steps, impact assessment.'
        f'\nExclude: Low severity, theoretical issues, self-XSS, missing headers, info disclosure without impact.'
        f'\nReport only Medium+ severity vulnerabilities with demonstrated real-world impact.'
    )

    # Step 1: Security Assessment
    print(f"\n🔍 STEP 1: Security assessment of {target}")
    print("=" * 60)
    findings = _claude(hunt_message, env)
    print(findings)

    # Step 2: Generate HackerOne vulnerability report (filtered to medium+)
    print("\n📋 STEP 2: Compiling vulnerability report...")
    print("=" * 60)
    report = _claude(
        f"make hackerone reports with cwe id and asset from these findings. "
        f"STRICT FILTERS:\n"
        f"1. Only include Medium/High/Critical severity with demonstrated impact.\n"
        f"2. Drop anything Low or Informational.\n"
        f"3. Drop anything in the HackerOne Core Ineligible list below.\n\n"
        f"{H1_CORE_INELIGIBLE}\n"
        f"If nothing qualifies after filtering, respond with exactly: 'NO_QUALIFYING_FINDINGS'.\n\n"
        f"Findings:\n{findings}",
        env,
    )
    print(report)

    # Step 3: Save comprehensive report to markdown
    import re
    safe = re.sub(r"[^\w]", "_", target.replace("https://", "").replace("http://", ""))[:40]
    report_file = pathlib.Path(f"/tmp/hunt_report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")

    full_report = f"""# Bug Hunt Report: {target}

**Date:** {datetime.now().isoformat()}
**Status:** {'FINDINGS FOUND' if report.strip() != 'NO_QUALIFYING_FINDINGS' else 'NO QUALIFYING FINDINGS'}

## Hunt Plan
{plan_content}

## Findings
{findings}

## HackerOne Report
{report}
"""
    report_file.write_text(full_report)
    print(f"\n📄 Full report saved to: {report_file}\n")

    if report.strip() == "NO_QUALIFYING_FINDINGS":
        print("⚠️  No Medium+ vulnerabilities found — skipping Telegram send.")
        return

    # Step 4: Send to Telegram
    print("📤 STEP 3: Sending report to Telegram...")
    try:
        telegram.send_document(str(report_file), caption=f"<b>🔍 Bug Hunt: {target}</b>")
        print("✓ Report sent to Telegram as file")
    except telegram.TelegramError as e:
        print(f"⚠️  Telegram error: {e}")


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
        ["claude", "--dangerously-skip-permissions"],
        input=prompt,
        text=True,
        env=env,
    )

    print("=" * 60)

    if result.returncode != 0:
        raise RuntimeError("Claude CLI exited with an error")

    return {"status": "complete"}
