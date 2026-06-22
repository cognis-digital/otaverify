"""Tests for SARIF 2.1.0 export and the bundled demo packages.

No network. Each demo ships with VALID precomputed HMAC signatures, so these
tests verify the demos actually produce their documented verdicts and that the
SARIF output is well-formed for code-scanning ingestion.
"""

import glob
import json
import os

from otaverify import TOOL_VERSION
from otaverify.cli import main
from otaverify.core import load_json, to_sarif, verify_package

HERE = os.path.dirname(__file__)
DEMOS = os.path.join(HERE, "..", "demos")


def _demo(name):
    return os.path.join(DEMOS, name, "package.json")


# --- SARIF export -----------------------------------------------------------

def test_sarif_envelope_shape():
    pkg = load_json(_demo("06-downgrade-blocked"))
    sarif = to_sarif(verify_package(pkg), "pkg.json", TOOL_VERSION)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "otaverify"
    assert driver["version"] == TOOL_VERSION
    assert driver["informationUri"].startswith("https://")


def test_sarif_results_match_findings():
    pkg = load_json(_demo("06-downgrade-blocked"))
    result = verify_package(pkg)
    sarif = to_sarif(result, "pkg.json")
    run = sarif["runs"][0]
    # One SARIF result per finding.
    assert len(run["results"]) == len(result.findings)
    # Every result references a real rule by index.
    rules = run["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "pkg.json"
    # Error-severity findings map to SARIF level "error".
    err_rules = {f.check for f in result.findings if f.severity == "error"}
    sarif_err_rules = {r["ruleId"] for r in run["results"] if r["level"] == "error"}
    assert err_rules == sarif_err_rules


def test_sarif_rules_are_deduplicated():
    # 10-router has three payload.digest findings -> one shared rule entry.
    pkg = load_json(_demo("10-router-multi-image"))
    sarif = to_sarif(verify_package(pkg), "pkg.json")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))  # no duplicate rule ids


def test_cli_sarif_is_valid_json(tmp_path, capsys):
    code = main(["--format", "sarif", "verify", _demo("10-router-multi-image")])
    assert code == 0  # clean accept
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"


# --- Demo verdicts ----------------------------------------------------------

# (demo dir, expected ok, must-have error checks)
EXPECTED = {
    "04-automotive-ecu": (True, []),
    "05-expired-manifest": (False, ["manifest.expiry"]),
    "06-downgrade-blocked": (False, ["rollback.version", "rollback.counter"]),
    "07-payload-tampered": (False, ["payload.digest"]),
    "08-threshold-not-met": (False, ["sig.threshold"]),
    "09-unknown-key": (False, ["sig.threshold"]),
    "10-router-multi-image": (True, []),
}


def test_every_demo_matches_documented_verdict():
    for name, (expect_ok, must_err) in EXPECTED.items():
        result = verify_package(load_json(_demo(name)))
        assert result.ok is expect_ok, f"{name}: ok={result.ok}, want {expect_ok}"
        err_checks = {f.check for f in result.errors}
        for c in must_err:
            assert c in err_checks, f"{name}: missing expected error {c}"


def test_all_demo_packages_load_and_verify():
    # Every demos/*/package.json parses and runs without raising.
    found = glob.glob(os.path.join(DEMOS, "*", "package.json"))
    assert len(found) >= 8  # 01-basic + 04..10
    for path in found:
        result = verify_package(load_json(path))
        assert isinstance(result.ok, bool)


def test_demo_09_ignores_rogue_key():
    result = verify_package(load_json(_demo("09-unknown-key")))
    assert any(f.check == "sig.unknown" and f.severity == "warning" for f in result.findings)
    assert any(
        f.check == "sig.threshold" and f.severity == "error" and "0/1" in f.message
        for f in result.findings
    )
