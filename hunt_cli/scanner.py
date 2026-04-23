"""Automated vulnerability scanner focused on authentication."""
import subprocess
import json
import requests
from pathlib import Path
from datetime import datetime


class ScannerError(Exception):
    pass


def run_nmap(target):
    """Run nmap port scan."""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-p", "80,443,8080,8443", target],
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout
    except FileNotFoundError:
        raise ScannerError("nmap not installed")
    except subprocess.TimeoutExpired:
        raise ScannerError("nmap timeout")


def test_default_credentials(url, endpoints):
    """Test common default credentials on login endpoints."""
    findings = []
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "password"),
        ("test", "test"),
    ]

    for endpoint in endpoints:
        for username, password in common_creds:
            try:
                # Try POST login
                r = requests.post(
                    f"{url}{endpoint}",
                    data={"username": username, "password": password},
                    timeout=10
                )
                # Check for success indicators
                if r.status_code == 200 and ("dashboard" in r.text.lower() or "logout" in r.text.lower()):
                    findings.append({
                        "type": "Default Credentials",
                        "endpoint": endpoint,
                        "username": username,
                        "password": password,
                        "severity": "Critical",
                        "cvss": 9.8,
                        "cwe": "CWE-521"
                    })
            except requests.RequestException:
                pass

    return findings


def test_sqli_login(url, endpoints):
    """Test for SQL injection in login forms."""
    findings = []
    sqli_payloads = [
        "admin' --",
        "admin' #",
        "' or '1'='1",
        "' or 1=1 --",
    ]

    for endpoint in endpoints:
        for payload in sqli_payloads:
            try:
                r = requests.post(
                    f"{url}{endpoint}",
                    data={"username": payload, "password": "test"},
                    timeout=10
                )
                # Simple check for SQLi indicators
                if "error" in r.text.lower() and ("sql" in r.text.lower() or "syntax" in r.text.lower()):
                    findings.append({
                        "type": "SQL Injection in Login",
                        "endpoint": endpoint,
                        "payload": payload,
                        "severity": "Critical",
                        "cvss": 9.8,
                        "cwe": "CWE-89"
                    })
            except requests.RequestException:
                pass

    return findings


def test_brute_force(url, endpoint):
    """Test password brute force protection."""
    findings = []
    try:
        failed_attempts = 0
        for i in range(10):
            r = requests.post(
                f"{url}{endpoint}",
                data={"username": "admin", "password": f"wrong{i}"},
                timeout=5
            )
            if r.status_code == 401 or "invalid" in r.text.lower():
                failed_attempts += 1

        # If no rate limiting after 10 attempts, it's vulnerable
        if failed_attempts == 10:
            findings.append({
                "type": "No Brute Force Protection",
                "endpoint": endpoint,
                "severity": "High",
                "cvss": 7.5,
                "cwe": "CWE-307"
            })
    except requests.RequestException:
        pass

    return findings


def test_weak_password_policy(url, endpoints):
    """Check for weak password policy indicators."""
    findings = []
    # This would require analyzing HTML forms or API responses
    # Placeholder for actual implementation
    return findings


def scan_target(target_url, program_name):
    """Run full authentication-focused scan."""
    results = {
        "program": program_name,
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "findings": []
    }

    # Common login endpoints
    login_endpoints = [
        "/login",
        "/admin/login",
        "/api/login",
        "/auth/login",
        "/user/login",
        "/signin",
        "/admin/signin",
    ]

    print(f"[*] Scanning {target_url} for {program_name}")

    # Phase 1: Test default credentials
    print("[*] Testing default credentials...")
    results["findings"].extend(test_default_credentials(target_url, login_endpoints))

    # Phase 2: Test SQL injection
    print("[*] Testing SQL injection in login...")
    results["findings"].extend(test_sqli_login(target_url, login_endpoints))

    # Phase 3: Test brute force protection
    print("[*] Testing brute force protection...")
    for endpoint in login_endpoints:
        results["findings"].extend(test_brute_force(target_url, endpoint))

    return results


def save_scan_results(results):
    """Save scan results to file."""
    Path("scans").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = Path("scans") / f"scan_{timestamp}.json"
    filename.write_text(json.dumps(results, indent=2))
    return filename
