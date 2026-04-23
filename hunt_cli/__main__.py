import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import h1, report

REQUIRED_SECRETS = [
    "ANTHROPIC_API_KEY",
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

    except ValueError as e:
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

    args = p.parse_args()
    return {
        "version": cmd_version,
        "doctor": cmd_doctor,
        "programs": cmd_programs,
        "scope": cmd_scope,
        "rec": cmd_rec,
        "report": cmd_report,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
