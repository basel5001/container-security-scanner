"""Tests for src/summarize.py."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

# Allow importing from src/
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from summarize import (
    generate_summary,
    grype_severity_counts,
    load_json,
    parse_grype,
    parse_trivy,
    trivy_severity_counts,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TRIVY_SAMPLE: dict = {
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.0)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-0001",
                    "Severity": "CRITICAL",
                    "PkgName": "libcrypto",
                    "InstalledVersion": "1.1.1",
                    "FixedVersion": "1.1.2",
                    "Title": "Buffer overflow in libcrypto",
                },
                {
                    "VulnerabilityID": "CVE-2023-0002",
                    "Severity": "HIGH",
                    "PkgName": "musl",
                    "InstalledVersion": "1.2.3",
                    "FixedVersion": "",
                    "Title": "Use-after-free in musl",
                },
            ],
        },
        {
            "Target": "usr/bin/app",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-0003",
                    "Severity": "MEDIUM",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.11",
                    "FixedVersion": "1.2.12",
                    "Title": "Integer overflow in zlib",
                },
            ],
        },
    ]
}

GRYPE_SAMPLE: dict = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-1001",
                "severity": "CRITICAL",
                "fix": {"versions": ["2.0.0"]},
            },
            "artifact": {
                "name": "openssl",
                "version": "1.1.1",
            },
        },
        {
            "vulnerability": {
                "id": "CVE-2023-1002",
                "severity": "LOW",
                "fix": {"versions": []},
            },
            "artifact": {
                "name": "busybox",
                "version": "1.35.0",
            },
        },
    ]
}


@pytest.fixture()
def trivy_file(tmp_path: Path) -> Path:
    p = tmp_path / "trivy-results.json"
    p.write_text(json.dumps(TRIVY_SAMPLE))
    return p


@pytest.fixture()
def grype_file(tmp_path: Path) -> Path:
    p = tmp_path / "grype-results.json"
    p.write_text(json.dumps(GRYPE_SAMPLE))
    return p


# ---------------------------------------------------------------------------
# load_json
# ---------------------------------------------------------------------------


class TestLoadJson:
    def test_valid_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')
        assert load_json(f) == {"key": "value"}

    def test_missing_file(self, tmp_path: Path) -> None:
        assert load_json(tmp_path / "nope.json") is None

    def test_invalid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("{not json")
        assert load_json(f) is None

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text("")
        assert load_json(f) is None


# ---------------------------------------------------------------------------
# Trivy parsing
# ---------------------------------------------------------------------------


class TestParsTrivy:
    def test_basic_parse(self) -> None:
        vulns = parse_trivy(TRIVY_SAMPLE)
        assert len(vulns) == 3

    def test_fields(self) -> None:
        vulns = parse_trivy(TRIVY_SAMPLE)
        crit = [v for v in vulns if v["severity"] == "CRITICAL"]
        assert len(crit) == 1
        assert crit[0]["id"] == "CVE-2023-0001"
        assert crit[0]["package"] == "libcrypto"
        assert crit[0]["fixed_version"] == "1.1.2"

    def test_empty_results(self) -> None:
        assert parse_trivy({"Results": []}) == []

    def test_missing_results_key(self) -> None:
        assert parse_trivy({}) == []

    def test_no_vulnerabilities_in_result(self) -> None:
        data = {"Results": [{"Target": "foo"}]}
        assert parse_trivy(data) == []

    def test_severity_counts(self) -> None:
        vulns = parse_trivy(TRIVY_SAMPLE)
        counts = trivy_severity_counts(vulns)
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1


# ---------------------------------------------------------------------------
# Grype parsing
# ---------------------------------------------------------------------------


class TestParseGrype:
    def test_basic_parse(self) -> None:
        vulns = parse_grype(GRYPE_SAMPLE)
        assert len(vulns) == 2

    def test_fields(self) -> None:
        vulns = parse_grype(GRYPE_SAMPLE)
        crit = [v for v in vulns if v["severity"] == "CRITICAL"]
        assert len(crit) == 1
        assert crit[0]["id"] == "CVE-2023-1001"
        assert crit[0]["package"] == "openssl"
        assert crit[0]["fixed_version"] == "2.0.0"

    def test_no_fix_versions(self) -> None:
        vulns = parse_grype(GRYPE_SAMPLE)
        low = [v for v in vulns if v["severity"] == "LOW"]
        assert low[0]["fixed_version"] == ""

    def test_empty_matches(self) -> None:
        assert parse_grype({"matches": []}) == []

    def test_missing_matches_key(self) -> None:
        assert parse_grype({}) == []

    def test_severity_counts(self) -> None:
        vulns = parse_grype(GRYPE_SAMPLE)
        counts = grype_severity_counts(vulns)
        assert counts["CRITICAL"] == 1
        assert counts["LOW"] == 1


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------


class TestGenerateSummary:
    def test_full_summary(self, trivy_file: Path, grype_file: Path) -> None:
        md = generate_summary(str(trivy_file), str(grype_file))
        assert "# Container Security Scan Summary" in md
        assert "## Trivy Results" in md
        assert "## Grype Results" in md
        assert "CVE-2023-0001" in md
        assert "CVE-2023-1001" in md

    def test_trivy_only(self, trivy_file: Path, tmp_path: Path) -> None:
        md = generate_summary(str(trivy_file), str(tmp_path / "missing.json"))
        assert "## Trivy Results" in md
        assert "Total vulnerabilities: 3" in md
        assert "_No Grype results found._" in md

    def test_grype_only(self, tmp_path: Path, grype_file: Path) -> None:
        md = generate_summary(str(tmp_path / "missing.json"), str(grype_file))
        assert "_No Trivy results found._" in md
        assert "## Grype Results" in md
        assert "Total vulnerabilities: 2" in md

    def test_no_files(self, tmp_path: Path) -> None:
        md = generate_summary(
            str(tmp_path / "no-trivy.json"),
            str(tmp_path / "no-grype.json"),
        )
        assert "_No Trivy results found._" in md
        assert "_No Grype results found._" in md

    def test_empty_scan_results(self, tmp_path: Path) -> None:
        t = tmp_path / "trivy.json"
        t.write_text(json.dumps({"Results": []}))
        g = tmp_path / "grype.json"
        g.write_text(json.dumps({"matches": []}))
        md = generate_summary(str(t), str(g))
        assert "Total vulnerabilities: 0" in md

    def test_severity_order_in_details(self, trivy_file: Path, grype_file: Path) -> None:
        md = generate_summary(str(trivy_file), str(grype_file))
        # CRITICAL should appear before HIGH in the details table
        crit_pos = md.index("CRITICAL")
        high_pos = md.index("HIGH")
        assert crit_pos < high_pos

    def test_footer_present(self, trivy_file: Path, grype_file: Path) -> None:
        md = generate_summary(str(trivy_file), str(grype_file))
        assert "container-security-scanner" in md


class TestGrypeNoFixKey:
    """Edge case: Grype match with no 'fix' key at all."""

    def test_missing_fix_key(self) -> None:
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-9999-0001", "severity": "HIGH"},
                    "artifact": {"name": "pkg", "version": "1.0"},
                }
            ]
        }
        vulns = parse_grype(data)
        assert len(vulns) == 1
        assert vulns[0]["fixed_version"] == ""
