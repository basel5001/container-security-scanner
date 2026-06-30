#!/usr/bin/env python3
"""Read Trivy and Grype JSON results and produce a Markdown summary."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def load_json(path: str | Path) -> dict | None:
    """Load a JSON file, returning None if it doesn't exist or is invalid."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# -- Trivy helpers -----------------------------------------------------------

def parse_trivy(data: dict) -> list[dict]:
    """Extract vulnerability records from Trivy JSON output.

    Returns a flat list of dicts with keys:
        id, severity, package, installed_version, fixed_version, title
    """
    vulns: list[dict] = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vulns.append({
                "id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "package": v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version": v.get("FixedVersion", ""),
                "title": v.get("Title", v.get("Description", "")[:120]),
            })
    return vulns


def trivy_severity_counts(vulns: list[dict]) -> Counter:
    """Count Trivy vulnerabilities by severity."""
    return Counter(v["severity"] for v in vulns)


# -- Grype helpers -----------------------------------------------------------

def parse_grype(data: dict) -> list[dict]:
    """Extract vulnerability records from Grype JSON output.

    Returns a flat list of dicts with keys:
        id, severity, package, installed_version, fixed_version
    """
    vulns: list[dict] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vulns.append({
            "id": vuln.get("id", ""),
            "severity": vuln.get("severity", "Unknown"),
            "package": artifact.get("name", ""),
            "installed_version": artifact.get("version", ""),
            "fixed_version": (
                vuln.get("fix", {}).get("versions", [""])[0]
                if vuln.get("fix", {}).get("versions")
                else ""
            ),
        })
    return vulns


def grype_severity_counts(vulns: list[dict]) -> Counter:
    """Count Grype vulnerabilities by severity."""
    return Counter(v["severity"] for v in vulns)


# -- Markdown rendering ------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "UNKNOWN": "⚪",
}


def _severity_table(counts: Counter) -> str:
    """Render a severity-count table."""
    lines = ["| Severity | Count |", "|----------|-------|"]
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev} | {c} |")
    return "\n".join(lines)


def _vuln_table(vulns: list[dict], limit: int = 20) -> str:
    """Render a vulnerability details table (capped at *limit* rows)."""
    if not vulns:
        return "_No vulnerabilities found._"

    sorted_vulns = sorted(
        vulns,
        key=lambda v: SEVERITY_ORDER.index(v["severity"])
        if v["severity"] in SEVERITY_ORDER
        else len(SEVERITY_ORDER),
    )

    lines = [
        "| ID | Severity | Package | Installed | Fixed |",
        "|----|----------|---------|-----------|-------|",
    ]
    for v in sorted_vulns[:limit]:
        fixed = v.get("fixed_version") or "-"
        lines.append(
            f"| {v['id']} | {v['severity']} | {v['package']} "
            f"| {v['installed_version']} | {fixed} |"
        )
    if len(sorted_vulns) > limit:
        lines.append(f"| ... | ... | _+{len(sorted_vulns) - limit} more_ | ... | ... |")
    return "\n".join(lines)


def generate_summary(
    trivy_path: str = "trivy-results.json",
    grype_path: str = "grype-results.json",
) -> str:
    """Produce a full Markdown summary from scan result files."""
    sections: list[str] = ["# Container Security Scan Summary\n"]

    # -- Trivy ---------------------------------------------------------------
    trivy_data = load_json(trivy_path)
    if trivy_data is not None:
        trivy_vulns = parse_trivy(trivy_data)
        t_counts = trivy_severity_counts(trivy_vulns)
        sections.append("## Trivy Results\n")
        sections.append(f"**Total vulnerabilities: {len(trivy_vulns)}**\n")
        sections.append(_severity_table(t_counts))
        sections.append("\n### Details\n")
        sections.append(_vuln_table(trivy_vulns))
    else:
        sections.append("## Trivy Results\n")
        sections.append("_No Trivy results found._")

    sections.append("")

    # -- Grype ---------------------------------------------------------------
    grype_data = load_json(grype_path)
    if grype_data is not None:
        grype_vulns = parse_grype(grype_data)
        g_counts = grype_severity_counts(grype_vulns)
        sections.append("## Grype Results\n")
        sections.append(f"**Total vulnerabilities: {len(grype_vulns)}**\n")
        sections.append(_severity_table(g_counts))
        sections.append("\n### Details\n")
        sections.append(_vuln_table(grype_vulns))
    else:
        sections.append("## Grype Results\n")
        sections.append("_No Grype results found._")

    # -- Footer --------------------------------------------------------------
    sections.append("\n---")
    sections.append("_Generated by [container-security-scanner]"
                     "(https://github.com/basel5001/container-security-scanner)_")

    return "\n".join(sections) + "\n"


# -- CLI entry point ---------------------------------------------------------

def main() -> None:
    trivy_path = sys.argv[1] if len(sys.argv) > 1 else "trivy-results.json"
    grype_path = sys.argv[2] if len(sys.argv) > 2 else "grype-results.json"
    print(generate_summary(trivy_path, grype_path))


if __name__ == "__main__":
    main()
