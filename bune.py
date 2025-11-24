"""Security awareness scoring tool.

This script provides a quick scoring framework (1-100) based on 100+ control
parameters. It is intentionally data-driven so a tester can adjust control
statuses (pass/warn/fail) via CLI flags or a JSON file while on-site.

Usage examples:
  python bune.py                      # show default scores (all unknown)
  python bune.py --status "Password rotation=pass" --status "EDR coverage=fail"
  python bune.py --input findings.json

The default parameter set is grouped across 10 domains to encourage balanced
coverage: Identity, Endpoint, Network, Email, Cloud, Application, Monitoring,
Backup, Physical, and Governance. Each parameter has a weight (1-5) roughly
aligned to severity; the overall score scales to 100.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List


Status = str
ALLOWED_STATUSES = {"pass", "warn", "fail", "unknown"}


@dataclass
class Parameter:
    """Single control/parameter used for scoring."""

    name: str
    category: str
    weight: int
    status: Status = "unknown"
    description: str = ""

    def score(self) -> float:
        multiplier = {
            "pass": 1.0,
            "warn": 0.5,
            "fail": 0.0,
            "unknown": 0.0,
        }.get(self.status, 0.0)
        return self.weight * multiplier


def default_parameters() -> List[Parameter]:
    """Return a list with at least 100 pre-defined parameters."""

    catalog = [
        # Identity & Active Directory
        {"name": "Tiered admin model enforced", "category": "Identity", "weight": 5},
        {"name": "Privileged account MFA", "category": "Identity", "weight": 5},
        {"name": "User MFA adoption", "category": "Identity", "weight": 4},
        {"name": "Password rotation", "category": "Identity", "weight": 3},
        {"name": "Password complexity", "category": "Identity", "weight": 3},
        {"name": "Kerberos pre-auth enabled", "category": "Identity", "weight": 4},
        {"name": "LDAPS enforced", "category": "Identity", "weight": 4},
        {"name": "Inactive accounts cleanup", "category": "Identity", "weight": 3},
        {"name": "Service account vaulting", "category": "Identity", "weight": 4},
        {"name": "DC event auditing", "category": "Identity", "weight": 4},
        # Endpoint
        {"name": "EDR coverage", "category": "Endpoint", "weight": 5},
        {"name": "EDR tamper protection", "category": "Endpoint", "weight": 4},
        {"name": "Disk encryption", "category": "Endpoint", "weight": 4},
        {"name": "Local admin control", "category": "Endpoint", "weight": 4},
        {"name": "USB control", "category": "Endpoint", "weight": 3},
        {"name": "Device compliance policy", "category": "Endpoint", "weight": 3},
        {"name": "Patch cadence OS", "category": "Endpoint", "weight": 4},
        {"name": "Patch cadence apps", "category": "Endpoint", "weight": 4},
        {"name": "Application allowlisting", "category": "Endpoint", "weight": 4},
        {"name": "Host firewall enabled", "category": "Endpoint", "weight": 3},
        # Network
        {"name": "Internal segmentation", "category": "Network", "weight": 4},
        {"name": "North-south firewalling", "category": "Network", "weight": 4},
        {"name": "East-west firewalling", "category": "Network", "weight": 4},
        {"name": "DNS filtering", "category": "Network", "weight": 3},
        {"name": "DHCP guard", "category": "Network", "weight": 3},
        {"name": "802.1X enforcement", "category": "Network", "weight": 4},
        {"name": "VPN MFA", "category": "Network", "weight": 4},
        {"name": "Remote access logging", "category": "Network", "weight": 3},
        {"name": "Outbound allowlist", "category": "Network", "weight": 3},
        {"name": "Network device hardening", "category": "Network", "weight": 4},
        # Email / Collaboration
        {"name": "SPF alignment", "category": "Email", "weight": 3},
        {"name": "DKIM alignment", "category": "Email", "weight": 3},
        {"name": "DMARC enforcement", "category": "Email", "weight": 4},
        {"name": "Malware scanning", "category": "Email", "weight": 4},
        {"name": "Phishing simulation program", "category": "Email", "weight": 3},
        {"name": "Attachment sandboxing", "category": "Email", "weight": 4},
        {"name": "Link rewriting", "category": "Email", "weight": 3},
        {"name": "O365/Workspace audit logging", "category": "Email", "weight": 3},
        {"name": "Shared mailbox governance", "category": "Email", "weight": 2},
        {"name": "Guest access review", "category": "Email", "weight": 3},
        # Cloud
        {"name": "CSPM coverage", "category": "Cloud", "weight": 4},
        {"name": "Root account MFA", "category": "Cloud", "weight": 5},
        {"name": "IAM role separation", "category": "Cloud", "weight": 4},
        {"name": "Key rotation", "category": "Cloud", "weight": 3},
        {"name": "Storage encryption", "category": "Cloud", "weight": 4},
        {"name": "Public bucket monitoring", "category": "Cloud", "weight": 4},
        {"name": "Security group hygiene", "category": "Cloud", "weight": 4},
        {"name": "Instance metadata v2", "category": "Cloud", "weight": 3},
        {"name": "Cloud trail retention", "category": "Cloud", "weight": 4},
        {"name": "Break-glass account control", "category": "Cloud", "weight": 4},
        # Application Security
        {"name": "Static code analysis", "category": "Application", "weight": 4},
        {"name": "Dependency scanning", "category": "Application", "weight": 4},
        {"name": "Secret scanning", "category": "Application", "weight": 4},
        {"name": "DAST coverage", "category": "Application", "weight": 4},
        {"name": "SBOM generation", "category": "Application", "weight": 3},
        {"name": "Prod change approvals", "category": "Application", "weight": 3},
        {"name": "RASP/WAFF", "category": "Application", "weight": 4},
        {"name": "Session management controls", "category": "Application", "weight": 3},
        {"name": "Secure coding training", "category": "Application", "weight": 3},
        {"name": "Bug bounty or VDP", "category": "Application", "weight": 2},
        # Monitoring & Detection
        {"name": "SIEM coverage", "category": "Monitoring", "weight": 5},
        {"name": "Use case library", "category": "Monitoring", "weight": 3},
        {"name": "Alert tuning", "category": "Monitoring", "weight": 3},
        {"name": "24/7 monitoring", "category": "Monitoring", "weight": 3},
        {"name": "UEBA deployed", "category": "Monitoring", "weight": 3},
        {"name": "NDR coverage", "category": "Monitoring", "weight": 3},
        {"name": "EDR signal to SIEM", "category": "Monitoring", "weight": 3},
        {"name": "Threat intel ingestion", "category": "Monitoring", "weight": 2},
        {"name": "SOAR automation", "category": "Monitoring", "weight": 3},
        {"name": "Playbook testing", "category": "Monitoring", "weight": 3},
        # Backup & Recovery
        {"name": "Offline backups", "category": "Backup", "weight": 4},
        {"name": "Backup immutability", "category": "Backup", "weight": 4},
        {"name": "Backup MFA", "category": "Backup", "weight": 3},
        {"name": "Restore testing frequency", "category": "Backup", "weight": 4},
        {"name": "RPO adherence", "category": "Backup", "weight": 3},
        {"name": "RTO adherence", "category": "Backup", "weight": 3},
        {"name": "Backup network isolation", "category": "Backup", "weight": 3},
        {"name": "AD backup integrity", "category": "Backup", "weight": 4},
        {"name": "Cloud backup encryption", "category": "Backup", "weight": 3},
        {"name": "Privilege separation backup ops", "category": "Backup", "weight": 3},
        # Physical & Social
        {"name": "Badge access", "category": "Physical", "weight": 3},
        {"name": "Visitor logging", "category": "Physical", "weight": 2},
        {"name": "Camera coverage", "category": "Physical", "weight": 2},
        {"name": "Server room access control", "category": "Physical", "weight": 4},
        {"name": "Clean desk policy", "category": "Physical", "weight": 2},
        {"name": "Screen lock timeout", "category": "Physical", "weight": 2},
        {"name": "Tailgating awareness", "category": "Physical", "weight": 2},
        {"name": "Hardware inventory", "category": "Physical", "weight": 3},
        {"name": "Asset disposal process", "category": "Physical", "weight": 2},
        {"name": "Offsite media storage", "category": "Physical", "weight": 2},
        # Governance & Process
        {"name": "Security awareness training", "category": "Governance", "weight": 3},
        {"name": "Incident response plan", "category": "Governance", "weight": 4},
        {"name": "IR tabletop frequency", "category": "Governance", "weight": 3},
        {"name": "Third-party risk program", "category": "Governance", "weight": 3},
        {"name": "Vulnerability management SLA", "category": "Governance", "weight": 4},
        {"name": "Pen-test cadence", "category": "Governance", "weight": 3},
        {"name": "Data classification", "category": "Governance", "weight": 3},
        {"name": "DLP coverage", "category": "Governance", "weight": 3},
        {"name": "Privacy impact assessments", "category": "Governance", "weight": 2},
        {"name": "Secure build standard", "category": "Governance", "weight": 3},
        # Extra Identity depth (10 more)
        {"name": "Admin workstation isolation", "category": "Identity", "weight": 4},
        {"name": "GPO change control", "category": "Identity", "weight": 3},
        {"name": "LSASS protection", "category": "Identity", "weight": 3},
        {"name": "NTLMv1 disabled", "category": "Identity", "weight": 3},
        {"name": "SMB signing", "category": "Identity", "weight": 3},
        {"name": "LAPS deployment", "category": "Identity", "weight": 3},
        {"name": "Credential guard", "category": "Identity", "weight": 3},
        {"name": "Smartcard for admins", "category": "Identity", "weight": 4},
        {"name": "Passwordless pilot", "category": "Identity", "weight": 2},
        {"name": "Tier 0 asset inventory", "category": "Identity", "weight": 4},
    ]

    return [Parameter(**item) for item in catalog]


def load_status_overrides(path: Path) -> Dict[str, Status]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    overrides: Dict[str, Status] = {}

    if isinstance(data, dict):
        # Support {"parameter": "status", ...}
        for key, value in data.items():
            overrides[key] = str(value)
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "name" in entry and "status" in entry:
                overrides[entry["name"]] = str(entry["status"])
    return overrides


def apply_overrides(parameters: Iterable[Parameter], overrides: Dict[str, Status]) -> Dict[str, List[str]]:
    lookup = {p.name.lower(): p for p in parameters}
    issues: Dict[str, List[str]] = {"unknown_parameters": [], "invalid_statuses": []}

    for name, status in overrides.items():
        param = lookup.get(name.lower())
        normalized = str(status).strip().lower()

        if not param:
            issues["unknown_parameters"].append(name)
            continue

        if normalized not in ALLOWED_STATUSES:
            issues["invalid_statuses"].append(f"{name}={status}")
            continue

        param.status = normalized

    return issues


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute a security awareness score (1-100).")
    parser.add_argument(
        "--input",
        type=Path,
        help="JSON file with parameter statuses (dict name->status or list of {name,status}).",
    )
    parser.add_argument(
        "--status",
        action="append",
        help="Inline parameter status in the form 'Parameter Name=pass|warn|fail'.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of lowest scoring parameters to highlight (default: 10).",
    )
    return parser.parse_args()


def parse_inline_status(entries: Iterable[str]) -> Dict[str, Status]:
    overrides: Dict[str, Status] = {}
    for entry in entries:
        if "=" not in entry:
            continue
        name, status = entry.split("=", 1)
        overrides[name.strip()] = status.strip()
    return overrides


def summarize(parameters: List[Parameter], top_n: int) -> Dict[str, object]:
    max_score = sum(p.weight for p in parameters)
    actual_score = sum(p.score() for p in parameters)
    overall = round((actual_score / max_score) * 100, 2) if max_score else 0.0

    per_category: Dict[str, Dict[str, float]] = {}
    for param in parameters:
        cat = per_category.setdefault(param.category, {"score": 0.0, "max": 0.0})
        cat["score"] += param.score()
        cat["max"] += param.weight

    cat_scores = {
        category: round((values["score"] / values["max"]) * 100, 2)
        for category, values in per_category.items()
    }

    failing = [p for p in parameters if p.status == "fail"]
    warning = [p for p in parameters if p.status == "warn"]

    def sort_key(param: Parameter) -> float:
        return (param.score() / param.weight) if param.weight else 0.0

    lowest = sorted(parameters, key=sort_key)[:top_n]

    return {
        "overall_score": overall,
        "category_scores": cat_scores,
        "failed_parameters": [p.name for p in failing],
        "warning_parameters": [p.name for p in warning],
        "lowest_parameters": [{"name": p.name, "status": p.status, "category": p.category} for p in lowest],
    }


def format_report(summary: Dict[str, object]) -> str:
    lines = [
        "=== Security Awareness Score ===",
        f"Overall: {summary['overall_score']} / 100",
        "",
        "-- Category Scores --",
    ]
    for category, score in sorted(summary["category_scores"].items()):
        lines.append(f"{category}: {score}")

    if summary["failed_parameters"]:
        lines.append("\n-- Failed Controls --")
        lines.extend(f"- {name}" for name in summary["failed_parameters"])

    if summary["warning_parameters"]:
        lines.append("\n-- Warning Controls --")
        lines.extend(f"- {name}" for name in summary["warning_parameters"])

    if summary["lowest_parameters"]:
        lines.append("\n-- Lowest Scoring Parameters --")
        for item in summary["lowest_parameters"]:
            lines.append(f"- {item['name']} ({item['status']}, {item['category']})")

    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    parameters = default_parameters()
    issues: Dict[str, List[str]] = {"unknown_parameters": [], "invalid_statuses": []}

    if args.input:
        overrides = load_status_overrides(args.input)
        file_issues = apply_overrides(parameters, overrides)
        for key, values in file_issues.items():
            issues[key].extend(values)

    if args.status:
        inline_overrides = parse_inline_status(args.status)
        inline_issues = apply_overrides(parameters, inline_overrides)
        for key, values in inline_issues.items():
            issues[key].extend(values)

    summary = summarize(parameters, top_n=args.top)

    if any(values for values in issues.values()):
        print("-- Input warnings --")
        if issues["invalid_statuses"]:
            print("Ignored invalid statuses (use pass/warn/fail/unknown):")
            for item in issues["invalid_statuses"]:
                print(f"- {item}")
        if issues["unknown_parameters"]:
            print("Entries not matched to known parameters:")
            for item in issues["unknown_parameters"]:
                print(f"- {item}")
        print()

    if all(p.status == "unknown" for p in parameters):
        print("No evidence provided yet; all 110 controls are still 'unknown'.")
        print("Use --status 'Control=pass|warn|fail' or --input findings.json to score.")
        print()

    print(format_report(summary))


if __name__ == "__main__":
    main()
