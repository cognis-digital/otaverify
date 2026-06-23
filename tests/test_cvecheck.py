"""Tests for the offline component CVE check (otaverify.cvecheck).

All offline against the bundled ~262k-record OSV corpus. Proves real lookups
(CVE-2021-44228 / Log4Shell resolves), severity scoring from CVSS vectors,
component extraction precedence, gating, and SARIF rendering.
"""

import json

import pytest

from otaverify.cvecheck import (
    ComponentVuln,
    CveReport,
    cve_to_sarif,
    cvss_bucket,
    _cvss_base_score,
    extract_components,
    scan_components,
    scan_package,
)
from otaverify.vulndb_local import VulnDB

DB = VulnDB()


# --- severity / CVSS scoring -------------------------------------------------

def test_cvss_bucket_empty_is_unknown():
    assert cvss_bucket("") == "unknown"
    assert cvss_bucket(None) == "unknown"


def test_cvss_bucket_bare_scores():
    assert cvss_bucket("9.8") == "critical"
    assert cvss_bucket("7.5") == "high"
    assert cvss_bucket("5.0") == "medium"
    assert cvss_bucket("2.1") == "low"
    assert cvss_bucket("0.0") == "none"


def test_cvss_bucket_from_log4shell_vector():
    # Log4Shell CVSS:3.1 vector is a perfect 10.0 -> critical.
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert _cvss_base_score(vec) == pytest.approx(10.0)
    assert cvss_bucket(vec) == "critical"


def test_cvss_base_score_known_vector_high():
    # A scope-unchanged high-impact vector.
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = _cvss_base_score(vec)
    assert score == pytest.approx(9.8)
    assert cvss_bucket(vec) == "critical"


def test_cvss_base_score_medium_vector():
    vec = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
    score = _cvss_base_score(vec)
    assert 0.0 < score < 7.0


def test_cvss_base_score_garbage_is_none():
    assert _cvss_base_score("not-a-vector") is None
    assert _cvss_base_score("CVSS:2.0/AV:N") is None


# --- direct DB lookups (proof of real data) ---------------------------------

def test_log4shell_resolves_by_cve():
    hits = DB.by_cve("CVE-2021-44228")
    assert hits, "CVE-2021-44228 (Log4Shell) must resolve from the bundled DB"
    summaries = " ".join(h.get("summary", "").lower() for h in hits)
    assert "log4j" in summaries


def test_log4shell_alias_uppercase_lowercase():
    assert DB.by_cve("cve-2021-44228")
    assert DB.by_cve("CVE-2021-44228")


def test_known_lodash_package_present():
    assert DB.by_package("lodash")


def test_unknown_package_empty():
    assert DB.by_package("cognis-zzz-nonexistent-component-xyz") == []


# --- component extraction precedence ----------------------------------------

def test_extract_from_top_level_components():
    pkg = {"components": [{"name": "openssl", "version": "1.1.1k"}]}
    comps = extract_components(pkg)
    assert len(comps) == 1
    assert comps[0]["name"] == "openssl"
    assert comps[0]["version"] == "1.1.1k"


def test_extract_string_component_normalised():
    pkg = {"components": ["lodash"]}
    comps = extract_components(pkg)
    assert comps[0]["name"] == "lodash"


def test_extract_from_image_components():
    pkg = {"manifest": {"images": [{"name": "app", "components": [{"name": "log4j-core"}]}]}}
    comps = extract_components(pkg)
    names = {c["name"] for c in comps}
    assert "log4j-core" in names


def test_extract_falls_back_to_image_name():
    pkg = {"manifest": {"images": [{"name": "busybox"}]}}
    comps = extract_components(pkg)
    assert comps[0]["name"] == "busybox"
    assert comps[0].get("_from_image") is True


def test_extract_dedupes():
    pkg = {
        "components": [{"name": "openssl", "version": "1.0"}, {"name": "openssl", "version": "1.0"}],
    }
    assert len(extract_components(pkg)) == 1


def test_extract_skips_blank_names():
    pkg = {"components": [{"name": ""}, {"version": "1.0"}]}
    assert extract_components(pkg) == []


def test_extract_empty_package():
    assert extract_components({}) == []


# --- scanning ----------------------------------------------------------------

def test_scan_component_finds_log4shell():
    report = scan_components([{"name": "log4j-core", "version": "2.14.1"}], DB)
    ids = {a for m in report.matches for a in m.aliases}
    assert "CVE-2021-44228" in ids


def test_scan_reports_components_scanned():
    report = scan_components(
        [{"name": "log4j-core"}, {"name": "lodash"}, {"name": "cognis-zzz-nonexistent-xyz"}], DB
    )
    assert report.components_scanned == 3


def test_scan_clean_component_no_matches():
    report = scan_components([{"name": "cognis-zzz-nonexistent-component-xyz"}], DB)
    assert report.matches == []
    assert report.max_bucket() == "none"


def test_scan_lodash_has_matches():
    report = scan_components([{"name": "lodash"}], DB)
    assert len(report.matches) >= 1
    assert "lodash" in report.vulnerable_components


def test_scan_explicit_cve_resolves():
    report = scan_components([{"name": "whatever", "cves": ["CVE-2021-44228"]}], DB)
    ids = {a for m in report.matches for a in m.aliases}
    assert "CVE-2021-44228" in ids


def test_scan_min_severity_filters():
    full = scan_components([{"name": "lodash"}], DB)
    crit = scan_components([{"name": "lodash"}], DB, min_severity="critical")
    assert len(crit.matches) <= len(full.matches)
    for m in crit.matches:
        assert m.severity_bucket == "critical"


def test_scan_matches_sorted_by_severity():
    report = scan_components([{"name": "lodash"}, {"name": "log4j-core"}], DB)
    from otaverify.cvecheck import _SEV_ORDER

    ranks = [_SEV_ORDER.get(m.severity_bucket, 0) for m in report.matches]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_dedupes_vuln_ids_per_component():
    report = scan_components([{"name": "log4j-core"}], DB)
    per_comp = [m.vuln_id for m in report.matches if m.component == "log4j-core"]
    assert len(per_comp) == len(set(per_comp))


def test_suffix_match_maven_coordinate():
    # log4j-core stored under org.apache.logging.log4j:log4j-core
    report = scan_components([{"name": "log4j-core"}], DB)
    assert report.matches, "Maven-coordinate suffix match should resolve log4j-core"


# --- scan_package end to end -------------------------------------------------

def test_scan_package_vulnerable_demo():
    import os

    here = os.path.dirname(__file__)
    pkg = json.load(open(os.path.join(here, "..", "demos", "11-vulnerable-components", "package.json")))
    report = scan_package(pkg)
    assert report.max_bucket() == "critical"
    aliases = {a for m in report.matches for a in m.aliases}
    assert "CVE-2021-44228" in aliases


def test_scan_package_clean_demo():
    import os

    here = os.path.dirname(__file__)
    pkg = json.load(open(os.path.join(here, "..", "demos", "12-clean-components", "package.json")))
    report = scan_package(pkg)
    assert report.matches == []


# --- report shape ------------------------------------------------------------

def test_report_to_dict_shape():
    report = scan_components([{"name": "lodash"}], DB)
    d = report.to_dict()
    for key in ("components_scanned", "vulnerable_components", "match_count",
                "by_severity", "max_severity", "matches"):
        assert key in d
    assert d["match_count"] == len(report.matches)


def test_report_by_bucket_counts():
    report = scan_components([{"name": "lodash"}], DB)
    counts = report.by_bucket()
    assert sum(counts.values()) == len(report.matches)


def test_componentvuln_to_dict():
    cv = ComponentVuln("x", "1.0", "CVE-X", ["CVE-X"], "npm", "high", "summary")
    d = cv.to_dict()
    assert d["component"] == "x"
    assert d["severity"] == "high"
    assert d["vuln_id"] == "CVE-X"


def test_empty_report_max_bucket_none():
    assert CveReport(components_scanned=0).max_bucket() == "none"


# --- SARIF -------------------------------------------------------------------

def test_cve_sarif_envelope():
    report = scan_components([{"name": "lodash"}], DB)
    sarif = cve_to_sarif(report, "pkg.json", "1.2.3")
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "otaverify-cve"
    assert driver["version"] == "1.2.3"


def test_cve_sarif_results_match_matches():
    report = scan_components([{"name": "lodash"}], DB)
    sarif = cve_to_sarif(report, "pkg.json")
    assert len(sarif["runs"][0]["results"]) == len(report.matches)


def test_cve_sarif_rules_deduplicated():
    report = scan_components([{"name": "lodash"}, {"name": "log4j-core"}], DB)
    rules = cve_to_sarif(report, "pkg.json")["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_cve_sarif_levels_valid():
    report = scan_components([{"name": "lodash"}], DB)
    for res in cve_to_sarif(report, "pkg.json")["runs"][0]["results"]:
        assert res["level"] in ("error", "warning", "note")


def test_cve_sarif_critical_is_error_level():
    report = scan_components([{"name": "log4j-core"}], DB, min_severity="critical")
    if report.matches:
        for res in cve_to_sarif(report, "pkg.json")["runs"][0]["results"]:
            assert res["level"] == "error"
