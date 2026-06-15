"""Hardening tests: edge cases, bad input, and error paths.

These tests verify that the tooling fails gracefully on real-world bad input
rather than emitting raw tracebacks or silently producing wrong results.
"""

from __future__ import annotations

import json
import os

import pytest

from otaverify.cli import main
from otaverify.core import (
    _hmac_hex,
    canonical_bytes,
    load_json,
    verify_package,
)

HERE = os.path.dirname(__file__)
DEMO = os.path.join(HERE, "..", "demos", "01-basic", "package.json")


def _load_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sign(pkg):
    payload = canonical_bytes(pkg["manifest"])
    keys = pkg["root"]["keys"]
    pkg["signatures"] = [
        {"keyid": kid, "sig": _hmac_hex(secret, payload)}
        for kid, secret in keys.items()
    ]
    return pkg


# ---------------------------------------------------------------------------
# load_json edge cases
# ---------------------------------------------------------------------------


def test_load_json_missing_file_raises_oserror(tmp_path):
    """load_json on a nonexistent file must raise OSError, not crash."""
    with pytest.raises(OSError):
        load_json(str(tmp_path / "does_not_exist.json"))


def test_load_json_malformed_json_raises_valueerror(tmp_path):
    """load_json on malformed JSON must raise ValueError with a useful message."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_json(str(bad))


def test_load_json_non_dict_raises_valueerror(tmp_path):
    """load_json on a JSON array must raise ValueError."""
    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_json(str(arr))


def test_load_json_empty_path_raises_valueerror():
    """load_json with an empty path string must raise ValueError."""
    with pytest.raises(ValueError, match="path must not be empty"):
        load_json("")


# ---------------------------------------------------------------------------
# CLI exit-code hardening
# ---------------------------------------------------------------------------


def test_cli_missing_file_exits_2(capsys):
    """CLI must exit 2 and print to stderr when the file does not exist."""
    code = main(["verify", "/nonexistent/path/pkg.json"])
    assert code == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_malformed_json_exits_2(tmp_path, capsys):
    """CLI must exit 2 and print to stderr when JSON is malformed."""
    bad = tmp_path / "bad.json"
    bad.write_text("{bad", encoding="utf-8")
    code = main(["verify", str(bad)])
    assert code == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_json_array_exits_2(tmp_path, capsys):
    """CLI must exit 2 when the JSON root is not an object."""
    arr = tmp_path / "arr.json"
    arr.write_text("[1,2,3]", encoding="utf-8")
    code = main(["verify", str(arr)])
    assert code == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_no_subcommand_exits_2(capsys):
    """CLI with no subcommand must exit 2 (help printed, no traceback)."""
    code = main([])
    assert code == 2


# ---------------------------------------------------------------------------
# Core: non-list signatures
# ---------------------------------------------------------------------------


def test_signatures_as_dict_produces_error():
    """Passing signatures as a dict (not a list) must produce an error finding."""
    pkg = _sign(_load_demo())
    pkg["signatures"] = {"keyid": "vendor-a", "sig": "abc"}  # wrong type
    result = verify_package(pkg)
    assert result.ok is False
    checks = {f.check: f.severity for f in result.findings}
    assert checks.get("sig.present") == "error"


def test_signatures_as_none_treated_as_unsigned():
    """Passing signatures as null must be treated as unsigned."""
    pkg = _sign(_load_demo())
    pkg["signatures"] = None
    result = verify_package(pkg)
    assert result.ok is False


# ---------------------------------------------------------------------------
# Core: malformed signature entries
# ---------------------------------------------------------------------------


def test_non_dict_signature_entry_produces_warning():
    """A non-dict entry in the signatures list must produce a warning, not crash."""
    pkg = _sign(_load_demo())
    # Mix in a bad entry; the good ones still exist but threshold won't be met
    # because the bad entry is skipped.
    pkg["signatures"].append("not-a-dict")
    result = verify_package(pkg)
    # The original two valid signatures are still there so it should pass.
    assert result.ok is True
    warn_checks = [f.check for f in result.findings if f.severity == "warning"]
    assert "sig.malformed" in warn_checks


# ---------------------------------------------------------------------------
# Core: payloads not a dict
# ---------------------------------------------------------------------------


def test_payloads_non_dict_ignored(tmp_path):
    """A non-dict 'payloads' field must be silently ignored (treated as empty)."""
    pkg = _sign(_load_demo())
    pkg["payloads"] = "not-a-dict"
    result = verify_package(pkg)
    # Payloads skipped; rest of verification should still pass.
    assert result.ok is True


# ---------------------------------------------------------------------------
# Core: _hmac_hex robustness
# ---------------------------------------------------------------------------


def test_hmac_hex_non_hex_key_falls_back_to_utf8():
    """_hmac_hex with a plain-text (non-hex) key must not raise."""
    result = _hmac_hex("plaintext-key", b"data")
    assert len(result) == 64  # sha256 hex digest


def test_hmac_hex_with_non_string_key():
    """_hmac_hex with a non-string key (e.g. int) must not raise."""
    result = _hmac_hex(12345, b"data")
    assert len(result) == 64


# ---------------------------------------------------------------------------
# Core: empty manifest
# ---------------------------------------------------------------------------


def test_empty_manifest_rejected():
    """A package with no manifest must be rejected cleanly."""
    result = verify_package({})
    assert result.ok is False
    assert any(f.check == "package" for f in result.findings)


def test_empty_package_summary_has_error_count():
    """Even on an empty package, the summary must contain error/warning counts."""
    result = verify_package({})
    assert "errors" in result.summary
    assert result.summary["errors"] >= 1
