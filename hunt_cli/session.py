"""Session tracking with daily time limit."""
import json
from datetime import datetime, timedelta
from pathlib import Path

SESSIONS_DIR = Path("sessions")
SESSION_FILE = SESSIONS_DIR / "active_session.json"
DAILY_LIMIT_HOURS = 5


def ensure_sessions_dir():
    SESSIONS_DIR.mkdir(exist_ok=True)


def get_today_key():
    return datetime.now().strftime("%Y-%m-%d")


def start_session(program, notes=""):
    ensure_sessions_dir()
    if SESSION_FILE.exists():
        raise ValueError("Session already in progress")

    session = {
        "program": program,
        "notes": notes,
        "started_at": datetime.now().isoformat(),
        "paused_at": None,
        "total_paused_seconds": 0,
        "day": get_today_key(),
    }
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    return session


def stop_session():
    ensure_sessions_dir()
    if not SESSION_FILE.exists():
        raise ValueError("No session in progress")

    session = json.loads(SESSION_FILE.read_text())
    if session["paused_at"]:
        SESSION_FILE.unlink()
        return session, 0

    started = datetime.fromisoformat(session["started_at"])
    elapsed = (datetime.now() - started).total_seconds() - session["total_paused_seconds"]
    SESSION_FILE.unlink()
    return session, elapsed


def pause_session():
    ensure_sessions_dir()
    if not SESSION_FILE.exists():
        raise ValueError("No session in progress")

    session = json.loads(SESSION_FILE.read_text())
    if session["paused_at"]:
        raise ValueError("Session already paused")

    session["paused_at"] = datetime.now().isoformat()
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    return session


def resume_session():
    ensure_sessions_dir()
    if not SESSION_FILE.exists():
        raise ValueError("No session in progress")

    session = json.loads(SESSION_FILE.read_text())
    if not session["paused_at"]:
        raise ValueError("Session not paused")

    paused_start = datetime.fromisoformat(session["paused_at"])
    pause_duration = (datetime.now() - paused_start).total_seconds()
    session["total_paused_seconds"] += pause_duration
    session["paused_at"] = None
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    return session


def get_current_session():
    ensure_sessions_dir()
    if not SESSION_FILE.exists():
        return None

    session = json.loads(SESSION_FILE.read_text())
    started = datetime.fromisoformat(session["started_at"])
    elapsed = (datetime.now() - started).total_seconds() - session["total_paused_seconds"]
    if session["paused_at"]:
        elapsed -= (datetime.now() - datetime.fromisoformat(session["paused_at"])).total_seconds()

    return {
        "session": session,
        "elapsed_seconds": int(elapsed),
        "is_paused": session["paused_at"] is not None,
    }


def get_daily_total():
    ensure_sessions_dir()
    today = get_today_key()
    total = 0

    for session_file in SESSIONS_DIR.glob("session_*.json"):
        try:
            data = json.loads(session_file.read_text())
            if data.get("day") != today:
                continue
            started = datetime.fromisoformat(data["started_at"])
            if data.get("ended_at"):
                ended = datetime.fromisoformat(data["ended_at"])
            else:
                ended = datetime.now()
            elapsed = (ended - started).total_seconds() - data.get("total_paused_seconds", 0)
            total += max(0, elapsed)
        except (json.JSONDecodeError, KeyError):
            continue

    return int(total)


def log_session_end(program, duration_seconds):
    ensure_sessions_dir()
    today = get_today_key()
    session_id = datetime.now().strftime("%H%M%S")
    session_file = SESSIONS_DIR / f"session_{today}_{session_id}.json"

    session = {
        "program": program,
        "day": today,
        "duration_seconds": duration_seconds,
        "ended_at": datetime.now().isoformat(),
    }
    session_file.write_text(json.dumps(session, indent=2))


def format_time(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours}h {minutes}m {secs}s"


def check_daily_limit():
    daily_total = get_daily_total()
    limit_seconds = DAILY_LIMIT_HOURS * 3600
    remaining = max(0, limit_seconds - daily_total)

    return {
        "daily_total": daily_total,
        "limit_seconds": limit_seconds,
        "remaining": remaining,
        "exceeded": daily_total >= limit_seconds,
        "warning": daily_total >= (limit_seconds - 3600),
    }
