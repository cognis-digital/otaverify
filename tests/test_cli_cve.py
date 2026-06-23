"""CLI tests for the `otaverify cve` subcommand. Offline; uses bundled DB + demos."""

import json
import os

from otaverify.cli import main, build_parser

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "..", "demos", "11-vulnerable-components", "package.json")
CLEAN = os.path.join(HERE, "..", "demos", "12-clean-components", "package.json")


def test_parser_has_cve_subcommand():
    parser = build_parser()
    args = parser.parse_args(["cve", "x.json"])
    assert args.command == "cve"
    assert args.package == "x.json"
    assert args.min_severity == "none"
    assert args.fail_on == "none"


def test_cve_table_on_vulnerable_exits_nonzero(capsys):
    code = main(["cve", VULN])
    out = capsys.readouterr().out
    assert code == 1  # known vulns -> gate fails
    assert "CVE-2021-44228" in out or "Log4" in out


def test_cve_table_on_clean_exits_zero(capsys):
    code = main(["cve", CLEAN])
    out = capsys.readouterr().out
    assert code == 0
    assert "no known vulnerabilities" in out.lower()


def test_cve_json_output(capsys):
    code = main(["--format", "json", "cve", VULN])
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["max_severity"] == "critical"
    assert "log4j-core" in doc["vulnerable_components"]
    assert doc["package"].endswith("package.json")


def test_cve_sarif_output(capsys):
    code = main(["--format", "sarif", "cve", VULN])
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "otaverify-cve"


def test_cve_fail_on_critical_gates(capsys):
    code = main(["cve", VULN, "--fail-on", "critical"])
    capsys.readouterr()
    assert code == 1  # there ARE critical matches


def test_cve_min_severity_critical_only(capsys):
    main(["--format", "json", "cve", VULN, "--min-severity", "critical"])
    doc = json.loads(capsys.readouterr().out)
    for m in doc["matches"]:
        assert m["severity"] == "critical"


def test_cve_missing_file_returns_2(capsys):
    code = main(["cve", os.path.join(HERE, "does-not-exist.json")])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cve_clean_fail_on_high_exits_zero(capsys):
    code = main(["cve", CLEAN, "--fail-on", "high"])
    capsys.readouterr()
    assert code == 0
