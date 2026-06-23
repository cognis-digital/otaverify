"""Command-line interface for OTAVERIFY.

Examples
--------
  # Verify an OTA package; exit non-zero if it would be rejected (CI gate):
  otaverify verify demos/01-basic/package.json

  # Machine-readable output for pipelines:
  otaverify verify --format json package.json | jq .ok

  # Show version:
  otaverify --version
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from otaverify import TOOL_NAME, TOOL_VERSION
from otaverify.core import VerifyResult, load_json, to_sarif, verify_package
from otaverify.cvecheck import (
    CveReport,
    cve_to_sarif,
    extract_components,
    scan_package,
)

_SEVERITY_GLYPH = {"error": "FAIL", "warning": "WARN", "info": "ok"}


def _render_table(result: VerifyResult, path: str) -> str:
    lines: list[str] = []
    verdict = "ACCEPT" if result.ok else "REJECT"
    lines.append(f"OTA package: {path}")
    lines.append(f"Verdict    : {verdict}")
    s = result.summary
    lines.append(
        f"Manifest   : version={s.get('version')} counter={s.get('counter')} "
        f"errors={s.get('errors')} warnings={s.get('warnings')}"
    )
    lines.append("")
    width = max((len(f.check) for f in result.findings), default=8)
    for f in result.findings:
        glyph = _SEVERITY_GLYPH.get(f.severity, f.severity)
        lines.append(f"  [{glyph:>4}] {f.check.ljust(width)}  {f.message}")
    if not result.findings:
        lines.append("  (no findings)")
    return "\n".join(lines)


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        package = load_json(args.package)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load package: {exc}", file=sys.stderr)
        return 2

    result = verify_package(package)

    if args.format == "json":
        out = result.to_dict()
        out["package"] = args.package
        print(json.dumps(out, indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(result, args.package, TOOL_VERSION), indent=2))
    else:
        print(_render_table(result, args.package))

    # Exit non-zero when the package would be rejected (CI gate semantics).
    return 0 if result.ok else 1


def _render_cve_table(report: CveReport, path: str) -> str:
    lines: list[str] = []
    lines.append(f"OTA package: {path}")
    lines.append(
        f"Components  : {report.components_scanned} scanned, "
        f"{len(report.vulnerable_components)} vulnerable, "
        f"{len(report.matches)} known vulnerabilities"
    )
    lines.append(f"Max severity: {report.max_bucket().upper()}")
    lines.append("")
    if not report.matches:
        lines.append("  (no known vulnerabilities in the offline corpus)")
        return "\n".join(lines)
    cwidth = max((len(m.component) for m in report.matches), default=8)
    for m in report.matches:
        comp = m.component + (f"@{m.version}" if m.version else "")
        alias = m.aliases[0] if m.aliases else m.vuln_id
        lines.append(
            f"  [{m.severity_bucket.upper():>8}] {comp.ljust(cwidth)}  "
            f"{m.vuln_id} ({alias})  {m.summary[:70]}"
        )
    return "\n".join(lines)


def _cmd_cve(args: argparse.Namespace) -> int:
    try:
        package = load_json(args.package)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load package: {exc}", file=sys.stderr)
        return 2

    report = scan_package(package, min_severity=args.min_severity)

    if args.format == "json":
        out = report.to_dict()
        out["package"] = args.package
        print(json.dumps(out, indent=2))
    elif args.format == "sarif":
        print(json.dumps(cve_to_sarif(report, args.package, TOOL_VERSION), indent=2))
    else:
        print(_render_cve_table(report, args.package))

    # Gate: non-zero exit when any match meets/exceeds --fail-on severity.
    from otaverify.cvecheck import _SEV_ORDER

    floor = _SEV_ORDER.get(args.fail_on, 0)
    if floor > 0:
        worst = _SEV_ORDER.get(report.max_bucket(), 0)
        return 1 if worst >= floor else 0
    # Default: fail if ANY known vuln was found.
    return 1 if report.matches else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Validate OTA update packages: signature chains, rollback "
            "protection, and anti-downgrade counters (TUF/Uptane spirit)."
        ),
        epilog=(
            "examples:\n"
            "  otaverify verify package.json\n"
            "  otaverify verify --format json package.json | jq .ok\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format: table, json, or sarif (SARIF 2.1.0 for code-scanning) (default: table)",
    )

    sub = parser.add_subparsers(dest="command")
    p_verify = sub.add_parser(
        "verify",
        help="verify an OTA package and gate on the result",
        description="Verify signatures, expiry, anti-downgrade, and payload digests.",
    )
    p_verify.add_argument("package", help="path to the OTA package JSON document")
    p_verify.set_defaults(func=_cmd_verify)

    p_cve = sub.add_parser(
        "cve",
        help="match the package's components against the bundled offline CVE DB",
        description=(
            "Offline component CVE check. Extracts components from the OTA "
            "package (components[], manifest.images[].components, or image "
            "names) and matches them against the bundled ~262k-record OSV "
            "corpus. Fully offline / air-gap safe — no network."
        ),
    )
    p_cve.add_argument("package", help="path to the OTA package JSON document")
    p_cve.add_argument(
        "--min-severity",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="drop matches below this severity bucket (default: none = report all)",
    )
    p_cve.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help=(
            "exit non-zero only if a match meets/exceeds this severity "
            "(default: none = fail on ANY known vuln)"
        ),
    )
    p_cve.set_defaults(func=_cmd_cve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
