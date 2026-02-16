"""Core engine for OTAVERIFY.

The verifier operates on a JSON "package" document describing an OTA update plus
the current device state. Everything is self-contained: signatures use HMAC-
SHA256 over a canonical (sorted-key, compact) JSON encoding of the signed
portion, which is reproducible with only the standard library.

Package schema (all signature material is hex-encoded)::

    {
      "root": {                       # trust root pinned on the device
        "keys": {"<keyid>": "<hex secret>", ...},
        "threshold": 2                  # M-of-N signatures required
      },
      "manifest": {
        "version": 12,                  # update version (anti-downgrade)
        "counter": 12,                  # monotonic anti-rollback counter
        "expires": "2030-01-01T00:00:00Z",
        "images": [
          {"name": "kernel", "sha256": "<hex>", "size": 1024}
        ]
      },
      "signatures": [
        {"keyid": "<keyid>", "sig": "<hex hmac of canonical manifest>"}
      ],
      "device": {                       # current state (anti-downgrade basis)
        "version": 11,
        "counter": 11
      },
      "payloads": {                     # optional: actual bytes for digest check
        "kernel": "<hex bytes>"
      }
    }

The device.* fields and payloads are NOT part of the signed manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Severity ordering for sorting / gating.
_SEVERITY_RANK = {"error": 2, "warning": 1, "info": 0}


@dataclass
class Finding:
    """A single verification result line."""

    check: str
    severity: str  # "error" | "warning" | "info"
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"check": self.check, "severity": self.severity, "message": self.message}


@dataclass
class VerifyResult:
    """Aggregate result of verifying one package."""

    ok: bool
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON package document from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("package root must be a JSON object")
    return data


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used as the signing basis.

    Sorted keys + no whitespace makes the encoding reproducible across
    languages, so a signature computed elsewhere verifies here.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_hex(secret_hex: str, payload: bytes) -> str:
    try:
        key = bytes.fromhex(secret_hex)
    except ValueError:
        # Allow plain-text keys too; treat as utf-8 bytes.
        key = secret_hex.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _parse_expiry(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z'."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_manifest(
    root: dict[str, Any],
    manifest: dict[str, Any],
    signatures: list[dict[str, Any]],
    now: datetime | None = None,
) -> list[Finding]:
    """Verify the cryptographic signature chain over a manifest.

    Returns a list of Findings (errors mean the manifest is untrusted).
    """
    findings: list[Finding] = []
    keys = root.get("keys") or {}
    if not isinstance(keys, dict) or not keys:
        findings.append(Finding("sig.root", "error", "trust root has no keys"))
        return findings

    threshold = root.get("threshold", 1)
    if not isinstance(threshold, int) or threshold < 1:
        findings.append(
            Finding("sig.threshold", "error", f"invalid signature threshold: {threshold!r}")
        )
        threshold = max(1, threshold if isinstance(threshold, int) else 1)

    payload = canonical_bytes(manifest)
    valid_keyids: set[str] = set()
    seen_keyids: set[str] = set()

    if not signatures:
        findings.append(Finding("sig.present", "error", "manifest is unsigned"))

    for sig in signatures:
        keyid = sig.get("keyid")
        provided = sig.get("sig", "")
        if keyid not in keys:
            findings.append(
                Finding("sig.unknown", "warning", f"signature from unknown key {keyid!r} ignored")
            )
            continue
        if keyid in seen_keyids:
            findings.append(
                Finding("sig.dup", "warning", f"duplicate signature from key {keyid!r} ignored")
            )
            continue
        seen_keyids.add(keyid)
        expected = _hmac_hex(keys[keyid], payload)
        if hmac.compare_digest(expected, str(provided)):
            valid_keyids.add(keyid)
        else:
            findings.append(
                Finding("sig.invalid", "error", f"bad signature from key {keyid!r}")
            )

    if len(valid_keyids) < threshold:
        findings.append(
            Finding(
                "sig.threshold",
                "error",
                f"signature threshold not met: {len(valid_keyids)}/{threshold} valid",
            )
        )
    else:
        findings.append(
            Finding(
                "sig.threshold",
                "info",
                f"signature threshold met: {len(valid_keyids)}/{threshold} valid",
            )
        )

    # Expiry check.
    expires = manifest.get("expires")
    if expires:
        now = now or datetime.now(timezone.utc)
        try:
            exp_dt = _parse_expiry(str(expires))
        except ValueError:
            findings.append(Finding("manifest.expiry", "error", f"unparseable expiry: {expires!r}"))
        else:
            if exp_dt < now:
                findings.append(
                    Finding("manifest.expiry", "error", f"manifest expired at {expires}")
                )
            else:
                findings.append(
                    Finding("manifest.expiry", "info", f"manifest valid until {expires}")
                )

    return findings


def check_anti_downgrade(
    manifest: dict[str, Any], device: dict[str, Any]
) -> list[Finding]:
    """Enforce anti-rollback: version and monotonic counter must not regress."""
    findings: list[Finding] = []

    new_version = manifest.get("version")
    cur_version = device.get("version")
    if isinstance(new_version, int) and isinstance(cur_version, int):
        if new_version < cur_version:
            findings.append(
                Finding(
                    "rollback.version",
                    "error",
                    f"downgrade blocked: update version {new_version} < installed {cur_version}",
                )
            )
        elif new_version == cur_version:
            findings.append(
                Finding(
                    "rollback.version",
                    "warning",
                    f"update version {new_version} equals installed version (no-op?)",
                )
            )
        else:
            findings.append(
                Finding(
                    "rollback.version",
                    "info",
                    f"version ok: {cur_version} -> {new_version}",
                )
            )
    else:
        findings.append(
            Finding("rollback.version", "warning", "version not comparable (missing/non-int)")
        )

    new_counter = manifest.get("counter")
    cur_counter = device.get("counter")
    if isinstance(new_counter, int) and isinstance(cur_counter, int):
        if new_counter < cur_counter:
            findings.append(
                Finding(
                    "rollback.counter",
                    "error",
                    f"anti-rollback counter regressed: {new_counter} < {cur_counter}",
                )
            )
        else:
            findings.append(
                Finding(
                    "rollback.counter",
                    "info",
                    f"anti-rollback counter ok: {cur_counter} -> {new_counter}",
                )
            )
    else:
        findings.append(
            Finding("rollback.counter", "warning", "counter not comparable (missing/non-int)")
        )

    return findings


def check_payloads(
    manifest: dict[str, Any], payloads: dict[str, Any]
) -> list[Finding]:
    """Verify each provided payload's sha256 matches the signed manifest."""
    findings: list[Finding] = []
    images = manifest.get("images") or []
    declared = {img.get("name"): img for img in images if isinstance(img, dict)}

    for name, hex_bytes in payloads.items():
        img = declared.get(name)
        if img is None:
            findings.append(
                Finding("payload.unknown", "error", f"payload {name!r} not declared in manifest")
            )
            continue
        try:
            raw = bytes.fromhex(str(hex_bytes))
        except ValueError:
            findings.append(
                Finding("payload.encoding", "error", f"payload {name!r} is not valid hex")
            )
            continue
        actual = hashlib.sha256(raw).hexdigest()
        expected = str(img.get("sha256", "")).lower()
        if actual != expected:
            findings.append(
                Finding(
                    "payload.digest",
                    "error",
                    f"payload {name!r} digest mismatch (got {actual[:16]}..., want {expected[:16]}...)",
                )
            )
        else:
            findings.append(Finding("payload.digest", "info", f"payload {name!r} digest ok"))
        size = img.get("size")
        if isinstance(size, int) and size != len(raw):
            findings.append(
                Finding(
                    "payload.size",
                    "error",
                    f"payload {name!r} size mismatch (got {len(raw)}, want {size})",
                )
            )
    return findings


def verify_package(
    package: dict[str, Any], now: datetime | None = None
) -> VerifyResult:
    """Run the full verification pipeline over a package document."""
    findings: list[Finding] = []

    root = package.get("root") or {}
    manifest = package.get("manifest") or {}
    signatures = package.get("signatures") or []
    device = package.get("device") or {}
    payloads = package.get("payloads") or {}

    if not manifest:
        findings.append(Finding("package", "error", "package has no manifest"))
        return VerifyResult(ok=False, findings=findings, summary={"errors": 1, "warnings": 0})

    findings += verify_manifest(root, manifest, signatures, now=now)
    findings += check_anti_downgrade(manifest, device)
    if payloads:
        findings += check_payloads(manifest, payloads)

    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.severity, 0))
    n_err = sum(1 for f in findings if f.severity == "error")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    summary = {
        "errors": n_err,
        "warnings": n_warn,
        "version": manifest.get("version"),
        "counter": manifest.get("counter"),
        "valid_signatures": sum(
            1 for f in findings if f.check == "sig.threshold" and f.severity == "info"
        ),
    }
    return VerifyResult(ok=(n_err == 0), findings=findings, summary=summary)
