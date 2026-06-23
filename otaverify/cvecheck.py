"""Offline CVE matching for components shipped inside an OTA payload.

An OTA update bundles software components (a kernel, busybox, openssl, an app's
npm/pip/cargo dependencies, ...). Before you flash a fleet you want to know
whether any of those components carries a *known* vulnerability. This module
matches the components declared in an OTA package against the bundled,
fully-offline OSV corpus (``cognis_vulndb.jsonl.gz`` — ~262k real records) so the
check runs on air-gapped / disconnected gear with zero network calls.

Where components come from
--------------------------
The verifier reads a component list from the package in this precedence order:

1. ``package["components"]`` — an explicit list (preferred for SBOM-style input)::

       "components": [
         {"name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven"},
         {"name": "openssl",    "version": "1.1.1k"}
       ]

2. ``manifest.images[].components`` — components attached per image.
3. ``manifest.images[].name`` — falls back to treating each image name as a
   component name (best-effort).

A component may also be a bare string (``"log4j-core"``) or carry an explicit
list of CVE/GHSA ids in ``cves`` / ``advisories`` which are resolved directly.

Nothing here makes a network connection. To *refresh* the corpus from NVD/OSV/
GHSA for an edge deployment, see :mod:`otaverify.datafeeds` and the air-gap
snapshot workflow documented in the README.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from otaverify.vulndb_local import VulnDB

# Severity bucket inferred from a CVSS v3 vector or score string.
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0}


def cvss_bucket(severity: str) -> str:
    """Map a raw OSV severity string (CVSS vector or score) to a bucket.

    OSV records store severity either as a CVSS v3 vector
    (``CVSS:3.1/AV:N/...``) or, occasionally, a bare base score. We derive the
    qualitative bucket the way NVD does so findings can be gated by level.
    """
    s = (severity or "").strip()
    if not s:
        return "unknown"
    score = _cvss_base_score(s)
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _cvss_base_score(s: str) -> Optional[float]:
    """Best-effort CVSS base score from a vector or a numeric string.

    For a full CVSS:3.x vector we compute the official base score; for a bare
    number we just parse it. Pure stdlib, no external CVSS library.
    """
    text = s.strip()
    # Bare numeric score, e.g. "9.8".
    try:
        return float(text)
    except ValueError:
        pass
    if not text.upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        return _cvss3_base(metrics)
    except (KeyError, ValueError):
        return None


# CVSS v3.1 metric weights (FIRST.org specification, public formula).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS v3.1 'roundup' — smallest 1-decimal value >= x."""
    import math

    return math.ceil(x * 10) / 10.0


def _cvss3_base(m: dict[str, str]) -> float:
    """Official CVSS v3.1 base-score formula (FIRST.org public spec)."""
    scope_changed = m["S"] == "C"
    pr_table = _PR_C if scope_changed else _PR_U
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup(base)


@dataclass
class ComponentVuln:
    """One (component -> vulnerability) match."""

    component: str
    version: Optional[str]
    vuln_id: str
    aliases: list[str]
    ecosystem: str
    severity_bucket: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "version": self.version,
            "vuln_id": self.vuln_id,
            "aliases": self.aliases,
            "ecosystem": self.ecosystem,
            "severity": self.severity_bucket,
            "summary": self.summary,
        }


@dataclass
class CveReport:
    """Aggregate result of a component CVE scan."""

    components_scanned: int
    matches: list[ComponentVuln] = field(default_factory=list)

    @property
    def vulnerable_components(self) -> set[str]:
        return {m.component for m in self.matches}

    def by_bucket(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for m in self.matches:
            counts[m.severity_bucket] = counts.get(m.severity_bucket, 0) + 1
        return counts

    def max_bucket(self) -> str:
        best = "none"
        for m in self.matches:
            if _SEV_ORDER.get(m.severity_bucket, 0) > _SEV_ORDER.get(best, 0):
                best = m.severity_bucket
        return best if self.matches else "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "components_scanned": self.components_scanned,
            "vulnerable_components": sorted(self.vulnerable_components),
            "match_count": len(self.matches),
            "by_severity": self.by_bucket(),
            "max_severity": self.max_bucket(),
            "matches": [m.to_dict() for m in self.matches],
        }


def _norm_component(item: Any) -> dict[str, Any]:
    """Normalise a component entry (string or dict) to a dict."""
    if isinstance(item, str):
        return {"name": item}
    if isinstance(item, dict):
        return dict(item)
    return {"name": str(item)}


def extract_components(package: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect components from a package per the documented precedence."""
    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    def add(entry: dict[str, Any]) -> None:
        name = str(entry.get("name", "")).strip()
        if not name:
            return
        key = (name.lower(), str(entry.get("version", "")), str(entry.get("ecosystem", "")).lower())
        if key in seen:
            return
        seen.add(key)
        out.append(entry)

    for c in package.get("components") or []:
        add(_norm_component(c))

    manifest = package.get("manifest") or {}
    for img in manifest.get("images") or []:
        if not isinstance(img, dict):
            continue
        comps = img.get("components")
        if comps:
            for c in comps:
                add(_norm_component(c))
        elif img.get("name"):
            # Best-effort: treat the image name as a component name.
            add({"name": img["name"], "_from_image": True})

    return out


def _matches_version(vuln: dict[str, Any], version: Optional[str]) -> bool:
    """Conservative version filter.

    The compact corpus stores affected package *names* but not full version
    ranges, so by default a name match is reported regardless of version (a
    superset — safe for a "do not flash" gate). If a record happens to carry an
    explicit ``versions`` list we honour it.
    """
    if not version:
        return True
    versions = vuln.get("versions")
    if isinstance(versions, list) and versions:
        return version in {str(v) for v in versions}
    return True


def _suffix_lookup(db: VulnDB, name: str) -> list[dict[str, Any]]:
    """Match a bare artifact name against Maven-style ``group:artifact`` keys.

    Components are often declared by their short artifact name (``log4j-core``)
    while the corpus keys them by full coordinate
    (``org.apache.logging.log4j:log4j-core``). This resolves that gap by
    matching on the part after the last ``:``. Builds a one-time index on the
    DB instance so repeated calls are cheap.
    """
    n = (name or "").lower()
    if not n:
        return []
    db._index()  # ensure _by_pkg is populated
    idx = getattr(db, "_otaverify_suffix_idx", None)
    if idx is None:
        idx = {}
        for key, recs in (db._by_pkg or {}).items():
            if ":" in key:
                short = key.rsplit(":", 1)[-1]
                idx.setdefault(short, []).extend(recs)
        # Attach the cache to the db instance (it is otherwise idle).
        try:
            db._otaverify_suffix_idx = idx  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover
            pass
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in idx.get(n, []):
        vid = r.get("id", "")
        if vid not in seen:
            seen.add(vid)
            out.append(r)
    return out


def scan_components(
    components: Iterable[dict[str, Any]],
    db: Optional[VulnDB] = None,
    *,
    min_severity: str = "none",
) -> CveReport:
    """Match each component against the offline vuln DB.

    ``min_severity`` filters out matches below the given bucket
    (none<low<medium<high<critical). Unknown-severity matches are always kept
    unless ``min_severity`` is above 'none', in which case they are dropped.
    """
    db = db or VulnDB()
    floor = _SEV_ORDER.get(min_severity, 0)
    comps = list(components)
    matches: list[ComponentVuln] = []

    for comp in comps:
        name = str(comp.get("name", "")).strip()
        if not name:
            continue
        version = comp.get("version")
        ecosystem = comp.get("ecosystem")
        records: list[dict[str, Any]] = []

        # 1) Explicit advisory ids on the component resolve directly.
        for cve in (comp.get("cves") or []) + (comp.get("advisories") or []):
            records.extend(db.by_cve(str(cve)))

        # 2) Name-based lookup. Try exact name (ecosystem-filtered if given);
        #    if that is empty, fall back to an ecosystem-agnostic exact match;
        #    if still empty, try a Maven-coordinate suffix match
        #    (e.g. component "log4j-core" -> "org.apache.logging.log4j:log4j-core").
        hits = db.by_package(name, ecosystem)
        if not hits and ecosystem:
            hits = db.by_package(name)
        if not hits:
            hits = _suffix_lookup(db, name)
        records.extend(hits)

        # Dedup records by id for this component.
        seen_ids: set[str] = set()
        for r in records:
            vid = r.get("id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)
            if not _matches_version(r, version):
                continue
            bucket = cvss_bucket(r.get("severity", ""))
            rank = _SEV_ORDER.get(bucket, 0)
            if floor > 0 and rank < floor:
                continue
            matches.append(
                ComponentVuln(
                    component=name,
                    version=str(version) if version else None,
                    vuln_id=vid,
                    aliases=list(r.get("aliases") or []),
                    ecosystem=r.get("ecosystem", ""),
                    severity_bucket=bucket,
                    summary=(r.get("summary") or "")[:300],
                )
            )

    # Stable ordering: highest severity first, then component, then id.
    matches.sort(key=lambda m: (-_SEV_ORDER.get(m.severity_bucket, 0), m.component, m.vuln_id))
    return CveReport(components_scanned=len(comps), matches=matches)


def scan_package(
    package: dict[str, Any],
    db: Optional[VulnDB] = None,
    *,
    min_severity: str = "none",
) -> CveReport:
    """Extract components from an OTA package and scan them offline."""
    return scan_components(extract_components(package), db, min_severity=min_severity)


# SARIF level per severity bucket.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "none": "note", "unknown": "note"}


def cve_to_sarif(report: CveReport, path: str, tool_version: str = "0.0.0") -> dict[str, Any]:
    """Render a CveReport as a SARIF 2.1.0 log for code-scanning ingestion."""
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for m in report.matches:
        if m.vuln_id not in rule_index:
            rule_index[m.vuln_id] = len(rules)
            rules.append(
                {
                    "id": m.vuln_id,
                    "name": m.vuln_id.replace("-", ""),
                    "shortDescription": {"text": m.summary or m.vuln_id},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(m.severity_bucket, "note")},
                }
            )
        results.append(
            {
                "ruleId": m.vuln_id,
                "ruleIndex": rule_index[m.vuln_id],
                "level": _SARIF_LEVEL.get(m.severity_bucket, "note"),
                "message": {
                    "text": f"component {m.component}"
                    + (f"@{m.version}" if m.version else "")
                    + f" affected by {m.vuln_id} ({m.severity_bucket}): {m.summary}"
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": path}}}
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "otaverify-cve",
                        "informationUri": "https://github.com/cognis-digital/otaverify",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
