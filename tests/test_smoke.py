"""Smoke tests for OTAVERIFY. No network. Runs against the real demo package.

The demo package ships with placeholder signatures (so the file is human-
readable). These tests recompute the correct HMAC signatures with the stdlib
and assert that the full pipeline behaves correctly for accept/reject cases.
"""

import json
import os

from otaverify import TOOL_NAME, TOOL_VERSION, verify_package
from otaverify.core import canonical_bytes, _hmac_hex
from otaverify.cli import main

HERE = os.path.dirname(__file__)
DEMO = os.path.join(HERE, "..", "demos", "01-basic", "package.json")


def _load_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sign(pkg):
    """Recompute valid signatures for the demo's manifest in-place."""
    payload = canonical_bytes(pkg["manifest"])
    keys = pkg["root"]["keys"]
    pkg["signatures"] = [
        {"keyid": kid, "sig": _hmac_hex(secret, payload)}
        for kid, secret in keys.items()
    ]
    return pkg


def test_metadata():
    assert TOOL_NAME == "otaverify"
    assert TOOL_VERSION.count(".") == 2


def test_demo_payload_digest_matches():
    # The demo's declared sha256 must actually match the bytes 'deadbeef'.
    import hashlib

    pkg = _load_demo()
    raw = bytes.fromhex(pkg["payloads"]["config"])
    assert hashlib.sha256(raw).hexdigest() == pkg["manifest"]["images"][0]["sha256"]


def test_valid_package_accepts():
    pkg = _sign(_load_demo())
    result = verify_package(pkg)
    assert result.ok is True
    assert result.summary["errors"] == 0
    checks = {f.check: f.severity for f in result.findings}
    assert checks["sig.threshold"] == "info"
    assert checks["rollback.version"] == "info"
    assert checks["payload.digest"] == "info"


def test_unsigned_rejected():
    pkg = _load_demo()
    pkg["signatures"] = []
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "sig.present" for f in result.errors)


def test_bad_signature_rejected():
    pkg = _sign(_load_demo())
    # Corrupt one signature -> threshold no longer met.
    pkg["signatures"][0]["sig"] = "00" * 32
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "sig.invalid" for f in result.errors)
    assert any(f.check == "sig.threshold" and f.severity == "error" for f in result.findings)


def test_downgrade_blocked():
    pkg = _load_demo()
    # Device already on version 11; offer version 10.
    pkg["manifest"]["version"] = 10
    pkg["manifest"]["counter"] = 10
    pkg = _sign(pkg)  # re-sign so signatures aren't the failing reason
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "rollback.version" and f.severity == "error" for f in result.findings)
    assert any(f.check == "rollback.counter" and f.severity == "error" for f in result.findings)


def test_counter_rollback_blocked():
    pkg = _load_demo()
    pkg["manifest"]["counter"] = 5  # below device counter 11
    pkg = _sign(pkg)
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "rollback.counter" and f.severity == "error" for f in result.findings)


def test_payload_digest_mismatch_rejected():
    pkg = _sign(_load_demo())
    pkg["payloads"]["config"] = "00000000"  # wrong bytes
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "payload.digest" and f.severity == "error" for f in result.findings)


def test_expired_manifest_rejected():
    pkg = _load_demo()
    pkg["manifest"]["expires"] = "2000-01-01T00:00:00Z"
    pkg = _sign(pkg)
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "manifest.expiry" and f.severity == "error" for f in result.findings)


def test_threshold_not_met_with_single_signer():
    pkg = _sign(_load_demo())
    pkg["signatures"] = pkg["signatures"][:1]  # only 1 of 2 required
    result = verify_package(pkg)
    assert result.ok is False
    assert any(f.check == "sig.threshold" and f.severity == "error" for f in result.findings)


def test_cli_json_accept(tmp_path, capsys):
    pkg = _sign(_load_demo())
    p = tmp_path / "pkg.json"
    p.write_text(json.dumps(pkg), encoding="utf-8")
    code = main(["--format", "json", "verify", str(p)])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True


def test_cli_reject_exit_code(tmp_path, capsys):
    pkg = _load_demo()
    pkg["signatures"] = []  # unsigned
    p = tmp_path / "pkg.json"
    p.write_text(json.dumps(pkg), encoding="utf-8")
    code = main(["verify", str(p)])
    assert code == 1  # non-zero gates CI
    assert "REJECT" in capsys.readouterr().out
