"""Report management and CVSS scoring."""
import json
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")


def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)


def get_report_path(name):
    return REPORTS_DIR / f"{name}.json"


def create_report(name, program):
    ensure_reports_dir()
    path = get_report_path(name)
    if path.exists():
        raise ValueError(f"Report '{name}' already exists")

    report = {
        "name": name,
        "program": program,
        "findings": [],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }
    path.write_text(json.dumps(report, indent=2))
    return report


def load_report(name):
    ensure_reports_dir()
    path = get_report_path(name)
    if not path.exists():
        raise ValueError(f"Report '{name}' not found")
    return json.loads(path.read_text())


def save_report(report):
    ensure_reports_dir()
    report["updated_at"] = datetime.now().isoformat()
    path = get_report_path(report["name"])
    path.write_text(json.dumps(report, indent=2))


def add_finding(name, title, description, cwe, cvss_score, asset=""):
    report = load_report(name)
    severity = cvss_to_severity(cvss_score)
    finding = {
        "title": title,
        "description": description,
        "cwe": cwe,
        "cvss_score": cvss_score,
        "severity": severity,
        "asset": asset,
        "added_at": datetime.now().isoformat(),
    }
    report["findings"].append(finding)
    save_report(report)
    return finding


def cvss_to_severity(score):
    """Convert CVSS 3.1 score to severity rating."""
    score = float(score)
    if score == 0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


def generate_markdown(report):
    """Generate markdown report from findings."""
    md = f"# {report['program']} - Vulnerability Report\n\n"
    md += f"**Generated:** {report['updated_at']}\n\n"

    if not report["findings"]:
        md += "No findings.\n"
        return md

    # Group by severity
    by_severity = {}
    for f in report["findings"]:
        sev = f["severity"]
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)

    # Sort by severity
    severity_order = ["Critical", "High", "Medium", "Low", "None"]
    for severity in severity_order:
        if severity not in by_severity:
            continue

        md += f"\n## {severity} Severity\n\n"
        for finding in by_severity[severity]:
            md += f"### {finding['title']}\n\n"
            md += f"- **CVSS Score:** {finding['cvss_score']} ({finding['severity']})\n"
            md += f"- **CWE:** {finding['cwe']}\n"
            if finding.get("asset"):
                md += f"- **Asset:** {finding['asset']}\n"
            md += f"\n{finding['description']}\n\n"

    md += f"\n## Summary\n\n"
    md += f"- **Total Findings:** {len(report['findings'])}\n"
    for severity in severity_order:
        count = len(by_severity.get(severity, []))
        if count > 0:
            md += f"- **{severity}:** {count}\n"

    return md


def list_reports():
    ensure_reports_dir()
    return sorted([p.stem for p in REPORTS_DIR.glob("*.json")])
