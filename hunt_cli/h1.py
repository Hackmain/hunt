"""HackerOne API client."""
import os
import requests

BASE = "https://api.hackerone.com/v1"


class H1Error(Exception):
    pass


def _auth():
    user = os.environ.get("HACKERONE_USERNAME")
    token = os.environ.get("HACKERONE_TOKEN")
    if not user or not token:
        raise H1Error("HACKERONE_USERNAME or HACKERONE_TOKEN not set")
    return (user, token)


def _get_all(path, params=None):
    url = f"{BASE}{path}"
    params = params or {}
    out = []
    while url:
        r = requests.get(url, auth=_auth(), params=params, timeout=30)
        params = None
        if r.status_code == 401:
            raise H1Error("401 unauthorized - check HACKERONE_USERNAME / HACKERONE_TOKEN")
        if r.status_code != 200:
            raise H1Error(f"{r.status_code} from {url}: {r.text[:200]}")
        data = r.json()
        out.extend(data.get("data", []))
        url = (data.get("links") or {}).get("next")
    return out


def list_programs():
    return _get_all("/hackers/programs", {"page[size]": 100})


def program_scopes(handle):
    return _get_all(f"/hackers/programs/{handle}/structured_scopes", {"page[size]": 100})


def program_weaknesses(handle):
    return _get_all(f"/hackers/programs/{handle}/weaknesses", {"page[size]": 100})
