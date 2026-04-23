"""Autonomous continuous hunting agent - discovers, tests, and reports."""
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
from . import scanner, report, telegram


class AutonomousHunter:
    def __init__(self, program_name, domain, max_duration_seconds=18000):
        self.program = program_name
        self.domain = domain
        self.max_duration = max_duration_seconds
        self.start_time = datetime.now()
        self.targets_tested = []
        self.vulnerabilities_found = []
        self.all_findings = []

    def log(self, message):
        """Log with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def discover_targets(self):
        """Autonomously discover all subdomains in scope."""
        self.log("🔍 PHASE 1: Autonomous target discovery")

        targets = set()

        # Add base domain
        targets.add(f"https://{self.domain}")
        targets.add(f"http://{self.domain}")

        # Common subdomains to test
        common_subs = [
            "api", "admin", "auth", "login", "app", "mail", "mobile",
            "booking", "loyalty", "test", "staging", "dev", "prod",
            "backend", "frontend", "payment", "secure", "user", "account",
            "portal", "dashboard", "panel", "service", "gateway",
        ]

        for sub in common_subs:
            targets.add(f"https://{sub}.{self.domain}")
            targets.add(f"http://{sub}.{self.domain}")

        # Try to use subfinder if available
        try:
            self.log("  Attempting subdomain enumeration with subfinder...")
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        targets.add(f"https://{line}")
                        targets.add(f"http://{line}")
            self.log(f"  ✓ Subfinder found {len(result.stdout.strip().split())} additional targets")
        except FileNotFoundError:
            self.log("  ⚠️  subfinder not installed (optional)")
        except:
            self.log("  ⚠️  subfinder enumeration failed")

        self.log(f"✓ Discovered {len(targets)} targets to test\n")
        return list(targets)

    def test_target(self, target):
        """Test a single target for vulnerabilities."""
        self.log(f"🎯 Testing: {target}")

        try:
            results = scanner.scan_target(target, self.program)

            if results["findings"]:
                self.log(f"  ⚠️  Found {len(results['findings'])} potential vulnerabilities")

                # Verify each finding
                for finding in results["findings"]:
                    self.log(f"    Verifying: {finding['type']}...")

                    # Re-test to confirm
                    if self._verify_finding(finding, target):
                        self.log(f"    ✓ CONFIRMED: {finding['type']}")
                        self.vulnerabilities_found.append({
                            **finding,
                            "target": target,
                            "verified": True
                        })
                    else:
                        self.log(f"    ✗ False positive")
            else:
                self.log(f"  ✓ No vulnerabilities")

        except Exception as e:
            self.log(f"  ❌ Error testing: {e}")

        self.targets_tested.append(target)

    def _verify_finding(self, finding, target):
        """Verify a finding is real."""
        try:
            import requests

            if finding["type"] == "Default Credentials":
                endpoint = finding.get("endpoint", "")
                username = finding.get("username", "")
                password = finding.get("password", "")

                r = requests.post(
                    f"{target}{endpoint}",
                    data={"username": username, "password": password},
                    timeout=5
                )
                if r.status_code == 200 and ("dashboard" in r.text.lower() or "logout" in r.text.lower()):
                    return True

            elif finding["type"] == "SQL Injection in Login":
                endpoint = finding.get("endpoint", "")
                payload = finding.get("payload", "")

                r = requests.post(
                    f"{target}{endpoint}",
                    data={"username": payload, "password": "test"},
                    timeout=5
                )
                if "syntax" in r.text.lower() or "sql" in r.text.lower():
                    return True

            elif finding["type"] == "No Brute Force Protection":
                endpoint = finding.get("endpoint", "")
                failed = 0
                for i in range(3):
                    r = requests.post(
                        f"{target}{endpoint}",
                        data={"username": "test", "password": f"test{i}"},
                        timeout=5
                    )
                    if r.status_code == 401 or "invalid" in r.text.lower():
                        failed += 1
                if failed == 3:
                    return True

        except:
            pass

        return False

    def create_report(self):
        """Create and send report of all findings."""
        if not self.vulnerabilities_found:
            self.log("\n✓ No vulnerabilities verified")
            return None

        self.log(f"\n📋 Creating report with {len(self.vulnerabilities_found)} verified vulnerabilities...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"autonomous_hunt_{self.program}_{timestamp}"

        report.create_report(report_name, f"{self.program} - Autonomous Hunt Report")

        for vuln in self.vulnerabilities_found:
            report.add_finding(
                report_name,
                title=f"{vuln['type']} @ {vuln['target']}",
                description=f"Target: {vuln['target']}\nType: {vuln['type']}\nEndpoint: {vuln.get('endpoint', 'N/A')}",
                cwe=vuln.get("cwe", "CWE-999"),
                cvss_score=vuln.get("cvss", 7.0),
                asset=vuln.get("target", "")
            )

        self.log(f"✓ Report created: {report_name}")

        # Send to Telegram
        try:
            self.log("📢 Sending to Telegram...")
            r = report.load_report(report_name)
            md = report.generate_markdown(r)

            summary = f"""🤖 AUTONOMOUS HUNT COMPLETE
Program: {self.program}
Domain: {self.domain}

📊 RESULTS:
✓ Targets Tested: {len(self.targets_tested)}
🎯 Vulnerabilities Found: {len(self.vulnerabilities_found)}
Duration: {(datetime.now() - self.start_time).total_seconds()/60:.1f} minutes

VERIFIED VULNERABILITIES:
"""
            for vuln in self.vulnerabilities_found:
                summary += f"\n• {vuln['type']} ({vuln['severity']})\n  Target: {vuln['target']}\n  CVSS: {vuln['cvss']}"

            summary += f"\n\n---\n\n{md}"

            telegram.send_message(summary)
            self.log("✓ Report sent to Telegram")
        except telegram.TelegramError:
            self.log("⚠️  Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)")
        except Exception as e:
            self.log(f"⚠️  Could not send to Telegram: {e}")

        return report_name

    def hunt(self):
        """Run autonomous hunting loop."""
        print("\n" + "="*60)
        print("🤖 AUTONOMOUS HUNTING AGENT ACTIVATED")
        print("="*60 + "\n")

        self.log(f"Target: {self.domain}")
        self.log(f"Program: {self.program}")
        self.log(f"Max Duration: {self.max_duration/3600:.1f} hours\n")

        # Phase 1: Discover targets
        targets = self.discover_targets()

        # Phase 2: Hunt across all targets
        self.log("🚀 PHASE 2: Autonomous vulnerability hunting\n")

        for i, target in enumerate(targets):
            # Check time limit
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > self.max_duration:
                self.log(f"⏰ Time limit reached ({self.max_duration/3600:.1f} hours)")
                break

            self.log(f"[{i+1}/{len(targets)}] Testing...")
            self.test_target(target)
            time.sleep(1)  # Rate limit

        # Phase 3: Report findings
        self.log("\n📋 PHASE 3: Generating report")
        report_name = self.create_report()

        # Summary
        print("\n" + "="*60)
        print("✅ AUTONOMOUS HUNT COMPLETE")
        print("="*60)
        print(f"Targets Tested: {len(self.targets_tested)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities_found)}")
        print(f"Duration: {(datetime.now() - self.start_time).total_seconds()/60:.1f} minutes")
        if report_name:
            print(f"Report: {report_name}")
        print("="*60 + "\n")


def start_autonomous_hunt(program_name, domain):
    """Start autonomous hunting agent."""
    hunter = AutonomousHunter(program_name, domain)
    hunter.hunt()
    return hunter
