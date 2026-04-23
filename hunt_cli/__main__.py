import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from . import h1, report, telegram, session, scanner, automate, autonomous, reporter, claude_hunt

REQUIRED_SECRETS = [
    "HACKERONE_USERNAME",
    "HACKERONE_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
]

STATE_FILE = Path(".hunt_rec_state")


def cmd_version(args):
    print("hunt 0.1.0")
    return 0


def cmd_doctor(args):
    ok = True
    for name in REQUIRED_SECRETS:
        present = bool(os.environ.get(name))
        mark = "OK " if present else "MISS"
        print(f"  [{mark}] {name}")
        if not present:
            ok = False
    if not ok:
        print("")
        print("Secrets missing. Add in Codespaces Secrets, restart Codespace.")
        return 1
    print("")
    print("all secrets present")
    return 0


def cmd_programs(args):
    try:
        programs = h1.list_programs()
    except h1.H1Error as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not programs:
        print("no programs found")
        return 0
    print(f"{'handle':<30} {'name'}")
    print(f"{'-'*30} {'-'*40}")
    for p in programs:
        a = p.get("attributes", {})
        print(f"{a.get('handle','?'):<30} {a.get('name','?')}")
    print(f"")
    print(f"{len(programs)} program(s)")
    return 0


def cmd_scope(args):
    try:
        scopes = h1.program_scopes(args.handle)
    except h1.H1Error as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not scopes:
        print(f"no scopes found for {args.handle}")
        return 0

    in_scope = [s for s in scopes if s.get("attributes", {}).get("eligible_for_submission")]
    out_scope = [s for s in scopes if not s.get("attributes", {}).get("eligible_for_submission")]

    if in_scope:
        print(f"\n{'IN SCOPE':^60}")
        print("=" * 60)
        for s in in_scope:
            a = s.get("attributes", {})
            print(f"{a.get('asset_type','?'):<20} {a.get('asset_identifier','?')}")

    if out_scope:
        print(f"\n{'OUT OF SCOPE':^60}")
        print("=" * 60)
        for s in out_scope:
            a = s.get("attributes", {})
            print(f"{a.get('asset_type','?'):<20} {a.get('asset_identifier','?')}")

    return 0


def cmd_rec(args):
    Path("recordings").mkdir(exist_ok=True)

    if args.action == "start":
        if not args.name:
            print("error: recording name required", file=sys.stderr)
            return 1

        if STATE_FILE.exists():
            print("error: recording already in progress", file=sys.stderr)
            return 1

        cast_file = Path("recordings") / f"{args.name}.cast"
        try:
            proc = subprocess.Popen(["asciinema", "rec", str(cast_file)])
            STATE_FILE.write_text(json.dumps({"pid": proc.pid, "name": args.name}))
            print(f"recording started: {args.name}")
            return 0
        except FileNotFoundError:
            print("error: asciinema not installed. run: pip install asciinema", file=sys.stderr)
            return 1

    elif args.action == "stop":
        if not STATE_FILE.exists():
            print("error: no recording in progress", file=sys.stderr)
            return 1

        try:
            state = json.loads(STATE_FILE.read_text())
            pid = state["pid"]
            os.kill(pid, 2)
            STATE_FILE.unlink()
            print(f"recording stopped: {state['name']}")
            return 0
        except (json.JSONDecodeError, ProcessLookupError, KeyError) as e:
            print(f"error stopping recording: {e}", file=sys.stderr)
            return 1


def cmd_report(args):
    try:
        if args.action == "new":
            r = report.create_report(args.name, args.program)
            print(f"report created: {args.name}")
            return 0

        elif args.action == "add":
            finding = report.add_finding(
                args.name, args.title, args.description, args.cwe, args.cvss, args.asset or ""
            )
            print(f"finding added to {args.name}")
            print(f"  Title: {finding['title']}")
            print(f"  CVSS: {finding['cvss_score']} ({finding['severity']})")
            return 0

        elif args.action == "view":
            r = report.load_report(args.name)
            md = report.generate_markdown(r)
            print(md)
            return 0

        elif args.action == "list":
            reports_list = report.list_reports()
            if not reports_list:
                print("no reports found")
                return 0
            for name in reports_list:
                r = report.load_report(name)
                count = len(r["findings"])
                print(f"  {name:<30} ({count} findings)")
            return 0

        elif args.action == "send":
            r = report.load_report(args.name)
            md = report.generate_markdown(r)
            md_file = Path("drafts") / f"{args.name}.md"
            Path("drafts").mkdir(exist_ok=True)
            md_file.write_text(md)
            try:
                telegram.send_message(f"<b>{r['program']} Report</b>\n\n{md}")
                print(f"report sent to Telegram: {args.name}")
                return 0
            except telegram.TelegramError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1

    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_session(args):
    try:
        if args.action == "start":
            s = session.start_session(args.program, args.notes or "")
            limit_check = session.check_daily_limit()
            if limit_check["exceeded"]:
                print("error: 5-hour daily limit reached", file=sys.stderr)
                return 1
            print(f"session started: {args.program}")
            if limit_check["warning"]:
                print(f"⚠️  WARNING: {session.format_time(limit_check['remaining'])} remaining today")
            return 0

        elif args.action == "pause":
            s = session.pause_session()
            print(f"session paused: {s['program']}")
            return 0

        elif args.action == "resume":
            s = session.resume_session()
            print(f"session resumed: {s['program']}")
            return 0

        elif args.action == "stop":
            s, elapsed = session.stop_session()
            session.log_session_end(s["program"], elapsed)
            limit_check = session.check_daily_limit()
            print(f"session stopped: {s['program']}")
            print(f"  Duration: {session.format_time(elapsed)}")
            print(f"  Daily total: {session.format_time(limit_check['daily_total'])}")
            if limit_check["warning"]:
                print(f"  ⚠️  {session.format_time(limit_check['remaining'])} remaining")
            return 0

        elif args.action == "status":
            current = session.get_current_session()
            if not current:
                print("no session in progress")
            else:
                s = current["session"]
                elapsed = current["elapsed_seconds"]
                status = "paused" if current["is_paused"] else "active"
                print(f"current session: {s['program']} ({status})")
                print(f"  Elapsed: {session.format_time(elapsed)}")

            limit_check = session.check_daily_limit()
            print(f"  Daily total: {session.format_time(limit_check['daily_total'])}")
            print(f"  Remaining: {session.format_time(limit_check['remaining'])}")
            if limit_check["warning"]:
                print(f"  ⚠️  Approaching daily limit!")
            return 0

    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_scan(args):
    try:
        print(f"🔍 Starting automated scan of {args.target}")
        results = scanner.scan_target(args.target, args.program)

        if not results["findings"]:
            print("✓ No vulnerabilities found")
            return 0

        print(f"\n⚠️  Found {len(results['findings'])} potential vulnerabilities:\n")
        for finding in results["findings"]:
            print(f"  [{finding['severity']}] {finding['type']}")
            print(f"    CWE: {finding['cwe']}")
            print(f"    CVSS: {finding['cvss']}")
            if "endpoint" in finding:
                print(f"    Endpoint: {finding['endpoint']}")
            print()

        # Save results
        filename = scanner.save_scan_results(results)
        print(f"✓ Results saved to: {filename}")

        # Ask user if they want to create report
        print("\n📋 Create report from findings? (manual: run 'hunt report new')")
        return 0

    except scanner.ScannerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_auto(args):
    try:
        result = automate.auto_hunt(args.target, args.program)
        if result:
            print(f"📊 Report available: hunt report view {result['report_name']}")
        return 0
    except automate.HuntingError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_hunt(args):
    """Autonomous hunting agent - discovers and tests all targets."""
    try:
        hunter = autonomous.start_autonomous_hunt(args.program, args.domain)
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_send(args):
    """Analyze latest scan and send report to Telegram."""
    try:
        reporter.watch_and_report()
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_notify(args):
    """Send message to Telegram."""
    try:
        message = args.message
        telegram.send_message(message)
        print("✓ Sent to Telegram")
        return 0
    except telegram.TelegramError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_claude(args):
    """Claude autonomously hunts a specific target and reports to Telegram."""
    try:
        scope = None
        if args.scope:
            scope = args.scope
        elif args.scope_file:
            scope = Path(args.scope_file).read_text()
        claude_hunt.run_target_hunt(args.target, scope=scope)
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_claude_hunt(args):
    """Claude intelligently selects H1 program & target, then hunts for vulnerabilities."""
    try:
        claude_hunt.run_intelligent_hunt(args.program if args.program else None)
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def main():
    p = argparse.ArgumentParser(prog="hunt")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version")
    sub.add_parser("doctor")
    sub.add_parser("programs")

    scope = sub.add_parser("scope")
    scope.add_argument("handle")

    rec = sub.add_parser("rec")
    rec_sub = rec.add_subparsers(dest="action", required=True)
    rec_sub.add_parser("start").add_argument("name")
    rec_sub.add_parser("stop")

    rep = sub.add_parser("report")
    rep_sub = rep.add_subparsers(dest="action", required=True)
    rep_new = rep_sub.add_parser("new")
    rep_new.add_argument("name")
    rep_new.add_argument("program")
    rep_add = rep_sub.add_parser("add")
    rep_add.add_argument("name")
    rep_add.add_argument("title")
    rep_add.add_argument("description")
    rep_add.add_argument("cwe")
    rep_add.add_argument("cvss", type=float)
    rep_add.add_argument("--asset", default="")
    rep_sub.add_parser("view").add_argument("name")
    rep_sub.add_parser("list")
    rep_sub.add_parser("send").add_argument("name")

    sess = sub.add_parser("session")
    sess_sub = sess.add_subparsers(dest="action", required=True)
    sess_start = sess_sub.add_parser("start")
    sess_start.add_argument("program")
    sess_start.add_argument("--notes", default="")
    sess_sub.add_parser("pause")
    sess_sub.add_parser("resume")
    sess_sub.add_parser("stop")
    sess_sub.add_parser("status")

    scan = sub.add_parser("scan")
    scan.add_argument("target", help="Target URL (e.g., https://example.com)")
    scan.add_argument("program", help="Program name (e.g., british_airways_vdp)")

    auto = sub.add_parser("auto")
    auto.add_argument("program", help="Program name (e.g., british_airways_vdp)")
    auto.add_argument("target", help="Target URL (e.g., https://example.com)")

    hunt_cmd = sub.add_parser("hunt")
    hunt_cmd.add_argument("program", help="Program name (e.g., british_airways_vdp)")
    hunt_cmd.add_argument("domain", help="Domain to hunt (e.g., britishairways.com)")

    sub.add_parser("send", help="Analyze latest scan and send report to Telegram")

    claude_cmd = sub.add_parser("claude")
    claude_cmd.add_argument("target", help="Target to analyze (e.g., britishairways.com)")
    claude_cmd.add_argument("--scope", default=None, help="Authorized scope (paste scope table as string)")
    claude_cmd.add_argument("--scope-file", default=None, help="Path to a file containing the authorized scope")

    claude_hunt_cmd = sub.add_parser("claude-hunt", help="Claude intelligently hunts H1 programs")
    claude_hunt_cmd.add_argument("--program", default=None, help="Specific program to hunt (optional, Claude picks if not specified)")

    notify_cmd = sub.add_parser("notify")
    notify_cmd.add_argument("message", help="Message to send to Telegram")

    args = p.parse_args()
    return {
        "version": cmd_version,
        "doctor": cmd_doctor,
        "programs": cmd_programs,
        "scope": cmd_scope,
        "rec": cmd_rec,
        "report": cmd_report,
        "session": cmd_session,
        "scan": cmd_scan,
        "auto": cmd_auto,
        "hunt": cmd_hunt,
        "send": cmd_send,
        "claude": cmd_claude,
        "claude-hunt": cmd_claude_hunt,
        "notify": cmd_notify,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
