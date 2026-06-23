"""Additional core-engine coverage: canonical encoding, signature edge cases,
expiry parsing, and payload size checks. Offline, stdlib only.
"""

import hashlib

from datetime import datetime, timezone

from otaverify.core import (
    Finding,
    VerifyResult,
    canonical_bytes,
    check_anti_downgrade,
    check_payloads,
    _hmac_hex,
    _parse_expiry,
    to_sarif,
    verify_manifest,
    verify_package,
)


def _signed(manifest, keys, threshold=1, device=None, payloads=None):
    payload = canonical_bytes(manifest)
    return {
        "root": {"keys": keys, "threshold": threshold},
        "manifest": manifest,
        "signatures": [{"keyid": k, "sig": _hmac_hex(s, payload)} for k, s in keys.items()],
        "device": device or {},
        "payloads": payloads or {},
    }


# --- canonical encoding ------------------------------------------------------

def test_canonical_sorts_keys():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_no_whitespace():
    out = canonical_bytes({"a": [1, 2, 3]})
    assert b" " not in out


def test_canonical_deterministic():
    a = canonical_bytes({"x": 1, "y": {"z": 2, "w": 3}})
    b = canonical_bytes({"y": {"w": 3, "z": 2}, "x": 1})
    assert a == b


def test_canonical_nested():
    assert canonical_bytes({"a": {"c": 1, "b": 2}}) == b'{"a":{"b":2,"c":1}}'


# --- hmac key handling -------------------------------------------------------

def test_hmac_hex_with_hex_key():
    h = _hmac_hex("00112233", b"x")
    assert len(h) == 64


def test_hmac_hex_with_plaintext_key():
    # Odd-length / non-hex secret is treated as utf-8 bytes.
    h = _hmac_hex("not-hex-key!", b"x")
    assert len(h) == 64


def test_hmac_hex_reproducible():
    assert _hmac_hex("aa", b"abc") == _hmac_hex("aa", b"abc")


# --- expiry parsing ----------------------------------------------------------

def test_parse_expiry_z_suffix():
    dt = _parse_expiry("2030-01-01T00:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2030


def test_parse_expiry_offset():
    dt = _parse_expiry("2030-01-01T00:00:00+00:00")
    assert dt.year == 2030


def test_parse_expiry_naive_gets_utc():
    dt = _parse_expiry("2030-01-01T00:00:00")
    assert dt.tzinfo == timezone.utc


# --- signature verification --------------------------------------------------

def test_verify_manifest_no_keys_errors():
    f = verify_manifest({}, {"version": 1}, [])
    assert any(x.check == "sig.root" and x.severity == "error" for x in f)


def test_verify_manifest_unsigned_errors():
    f = verify_manifest({"keys": {"k": "aa"}, "threshold": 1}, {"version": 1}, [])
    assert any(x.check == "sig.present" for x in f)


def test_verify_manifest_unknown_key_warning():
    keys = {"k": "aa"}
    m = {"version": 1}
    sigs = [{"keyid": "rogue", "sig": "00"}]
    f = verify_manifest(keys and {"keys": keys, "threshold": 1}, m, sigs)
    assert any(x.check == "sig.unknown" and x.severity == "warning" for x in f)


def test_verify_manifest_duplicate_key_warning():
    keys = {"k": "aa"}
    m = {"version": 1}
    good = _hmac_hex("aa", canonical_bytes(m))
    sigs = [{"keyid": "k", "sig": good}, {"keyid": "k", "sig": good}]
    f = verify_manifest({"keys": keys, "threshold": 1}, m, sigs)
    assert any(x.check == "sig.dup" for x in f)


def test_verify_manifest_threshold_met_info():
    keys = {"a": "aa", "b": "bb"}
    m = {"version": 1}
    p = canonical_bytes(m)
    sigs = [{"keyid": k, "sig": _hmac_hex(s, p)} for k, s in keys.items()]
    f = verify_manifest({"keys": keys, "threshold": 2}, m, sigs)
    assert any(x.check == "sig.threshold" and x.severity == "info" for x in f)


# --- anti-downgrade ----------------------------------------------------------

def test_downgrade_version_blocked():
    f = check_anti_downgrade({"version": 5}, {"version": 6})
    assert any(x.check == "rollback.version" and x.severity == "error" for x in f)


def test_same_version_warning():
    f = check_anti_downgrade({"version": 5}, {"version": 5})
    assert any(x.check == "rollback.version" and x.severity == "warning" for x in f)


def test_version_forward_info():
    f = check_anti_downgrade({"version": 7}, {"version": 5})
    assert any(x.check == "rollback.version" and x.severity == "info" for x in f)


def test_counter_regression_blocked():
    f = check_anti_downgrade({"counter": 1}, {"counter": 9})
    assert any(x.check == "rollback.counter" and x.severity == "error" for x in f)


def test_missing_version_warning():
    f = check_anti_downgrade({}, {})
    assert any(x.check == "rollback.version" and x.severity == "warning" for x in f)


# --- payload digest + size ---------------------------------------------------

def test_payload_digest_ok():
    raw = b"hello"
    manifest = {"images": [{"name": "x", "sha256": hashlib.sha256(raw).hexdigest(), "size": 5}]}
    f = check_payloads(manifest, {"x": raw.hex()})
    assert any(x.check == "payload.digest" and x.severity == "info" for x in f)


def test_payload_size_mismatch():
    raw = b"hello"
    manifest = {"images": [{"name": "x", "sha256": hashlib.sha256(raw).hexdigest(), "size": 99}]}
    f = check_payloads(manifest, {"x": raw.hex()})
    assert any(x.check == "payload.size" and x.severity == "error" for x in f)


def test_payload_unknown_image():
    f = check_payloads({"images": []}, {"ghost": "aa"})
    assert any(x.check == "payload.unknown" for x in f)


def test_payload_bad_hex():
    manifest = {"images": [{"name": "x", "sha256": "00"}]}
    f = check_payloads(manifest, {"x": "zzzz"})
    assert any(x.check == "payload.encoding" for x in f)


# --- verify_package integration ---------------------------------------------

def test_verify_package_no_manifest():
    r = verify_package({})
    assert r.ok is False
    assert any(f.check == "package" for f in r.findings)


def test_verify_package_accepts_forward_update():
    m = {"version": 3, "counter": 3, "expires": "2030-01-01T00:00:00Z"}
    pkg = _signed(m, {"k": "aa"}, threshold=1, device={"version": 2, "counter": 2})
    r = verify_package(m and pkg)
    assert r.ok is True


def test_verify_package_now_param_for_expiry():
    m = {"version": 1, "counter": 1, "expires": "2026-01-01T00:00:00Z"}
    pkg = _signed(m, {"k": "aa"}, threshold=1, device={"version": 0, "counter": 0})
    # Evaluate "now" AFTER expiry -> reject.
    later = datetime(2027, 1, 1, tzinfo=timezone.utc)
    r = verify_package(pkg, now=later)
    assert r.ok is False
    assert any(f.check == "manifest.expiry" for f in r.errors)


def test_verifyresult_errors_and_warnings_props():
    r = VerifyResult(ok=False, findings=[
        Finding("a", "error", "e"),
        Finding("b", "warning", "w"),
        Finding("c", "info", "i"),
    ])
    assert len(r.errors) == 1
    assert len(r.warnings) == 1


def test_to_sarif_roundtrip_levels():
    r = VerifyResult(ok=False, findings=[Finding("sig.invalid", "error", "bad")])
    sarif = to_sarif(r, "p.json", "9.9.9")
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "9.9.9"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
