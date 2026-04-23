"""Automated vulnerability scanner - accurate and sophisticated testing."""
import subprocess
import json
import requests
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin


class ScannerError(Exception):
    pass


def _make_request(url, method="get", **kwargs):
    """Make HTTP request with proper timeout and error handling."""
    try:
        if method == "get":
            return requests.get(url, timeout=10, verify=False, **kwargs)
        elif method == "post":
            return requests.post(url, timeout=10, verify=False, **kwargs)
    except requests.RequestException:
        return None


def test_default_credentials(url, endpoints):
    """Test common default credentials - accurate detection."""
    findings = []
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "12345678"),
        ("root", "root"),
        ("root", "password"),
        ("test", "test"),
        ("user", "user"),
        ("admin", "admin123"),
    ]

    for endpoint in endpoints:
        target_url = urljoin(url, endpoint)

        # Get baseline response with wrong credentials
        baseline = _make_request(target_url, "post", data={"username": "admin", "password": "wrong_password_xyz"})
        if not baseline:
            continue

        baseline_status = baseline.status_code
        baseline_len = len(baseline.text)

        for username, password in common_creds:
            r = _make_request(target_url, "post", data={"username": username, "password": password})
            if not r:
                continue

            # Accurate detection:
            # 1. Status code different from baseline (usually 200 vs 401)
            # 2. Content length significantly different
            # 3. Success indicators present (dashboard, welcome, logout, redirect)
            # 4. Absence of error/invalid indicators

            success_indicators = [
                r.status_code == 200,
                abs(len(r.text) - baseline_len) > 500,
                any(x in r.text.lower() for x in ["dashboard", "welcome", "logout", "profile", "user home"]),
                r.headers.get("location") and "login" not in r.headers.get("location", "").lower(),
            ]

            error_indicators = [
                "invalid" in r.text.lower(),
                "wrong" in r.text.lower(),
                "failed" in r.text.lower(),
                "unauthorized" in r.text.lower(),
            ]

            # Only report if success indicators present AND error indicators absent
            if sum(success_indicators) >= 2 and not any(error_indicators):
                findings.append({
                    "type": "Default Credentials",
                    "endpoint": endpoint,
                    "username": username,
                    "password": password,
                    "severity": "Critical",
                    "cvss": 9.8,
                    "cwe": "CWE-521",
                    "confidence": "High"
                })

    return findings


def test_sqli_login(url, endpoints):
    """Test for SQL injection - sophisticated detection."""
    findings = []
    sqli_payloads = [
        ("admin' --", "comment"),
        ("admin' #", "hash comment"),
        ("' or '1'='1", "always true"),
        ("' or 1=1 --", "or true"),
        ("admin' /*", "multi-line comment"),
        ("' UNION SELECT NULL --", "union based"),
    ]

    sql_error_patterns = [
        r"syntax error",
        r"mysql_fetch",
        r"Warning: mysql",
        r"undefined offset",
        r"ORA-\d+",  # Oracle errors
        r"SQL Server",
        r"PostgreSQL",
        r"SQLite",
    ]

    for endpoint in endpoints:
        target_url = urljoin(url, endpoint)

        # Get baseline with normal input
        baseline = _make_request(target_url, "post", data={"username": "admin", "password": "test123"})
        if not baseline:
            continue

        baseline_text = baseline.text.lower()

        for payload, payload_type in sqli_payloads:
            r = _make_request(target_url, "post", data={"username": payload, "password": "test"})
            if not r:
                continue

            response_text = r.text

            # Detect SQL errors with regex
            sql_errors = sum(1 for pattern in sql_error_patterns if re.search(pattern, response_text, re.IGNORECASE))

            # Detect response differences
            response_diff = abs(len(response_text) - len(baseline.text))

            # Only report if confident SQL injection
            if sql_errors >= 1 or (response_diff > 1000 and "error" in response_text.lower()):
                findings.append({
                    "type": "SQL Injection in Login",
                    "endpoint": endpoint,
                    "payload": payload,
                    "payload_type": payload_type,
                    "severity": "Critical",
                    "cvss": 9.8,
                    "cwe": "CWE-89",
                    "confidence": "High"
                })

    return findings


def test_brute_force(url, endpoint):
    """Test password brute force protection - accurate detection."""
    findings = []
    target_url = urljoin(url, endpoint)

    try:
        response_times = []
        consecutive_401s = 0

        for i in range(15):
            start = datetime.now()
            r = _make_request(target_url, "post", data={"username": "admin", "password": f"wrong{i}"})
            elapsed = (datetime.now() - start).total_seconds()

            if not r:
                continue

            response_times.append(elapsed)

            # Count 401 responses (typical for failed auth)
            if r.status_code == 401:
                consecutive_401s += 1

            # Check for rate limiting indicators
            rate_limit_indicators = [
                r.status_code == 429,  # Too many requests
                r.status_code == 503,  # Service unavailable
                "rate limit" in r.text.lower(),
                "too many" in r.text.lower(),
                "locked" in r.text.lower(),
                "blocked" in r.text.lower(),
            ]

            if any(rate_limit_indicators):
                return findings  # Rate limiting detected

        # No rate limiting if all 15 requests returned 401
        if consecutive_401s == 15:
            findings.append({
                "type": "No Brute Force Protection",
                "endpoint": endpoint,
                "severity": "High",
                "cvss": 7.5,
                "cwe": "CWE-307",
                "confidence": "High"
            })

    except Exception:
        pass

    return findings


def scan_target(target_url, program_name):
    """Run full accurate vulnerability scan."""
    results = {
        "program": program_name,
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "findings": []
    }

    # Extended login endpoints
    login_endpoints = [
        "/login", "/admin/login", "/api/login", "/auth/login",
        "/user/login", "/signin", "/admin/signin", "/authenticate",
        "/api/authenticate", "/api/auth", "/api/user/login",
        "/portal/login", "/dashboard/login",
    ]

    print(f"[*] Scanning {target_url} for {program_name}")

    # Phase 1: Test default credentials (most accurate)
    print("[*] Testing default credentials...")
    creds_findings = test_default_credentials(target_url, login_endpoints)
    results["findings"].extend(creds_findings)

    # Phase 2: Test SQL injection (sophisticated detection)
    print("[*] Testing SQL injection in login...")
    sqli_findings = test_sqli_login(target_url, login_endpoints)
    results["findings"].extend(sqli_findings)

    # Phase 3: Test brute force protection (accurate)
    print("[*] Testing brute force protection...")
    for endpoint in login_endpoints:
        bf_findings = test_brute_force(target_url, endpoint)
        results["findings"].extend(bf_findings)

    return results


def save_scan_results(results):
    """Save scan results to file."""
    Path("scans").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = Path("scans") / f"scan_{timestamp}.json"
    filename.write_text(json.dumps(results, indent=2))
    return filename
