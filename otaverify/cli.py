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
from otaverify.core import VerifyResult, load_json, verify_package

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
    else:
        print(_render_table(result, args.package))

    # Exit non-zero when the package would be rejected (CI gate semantics).
    return 0 if result.ok else 1


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
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command")
    p_verify = sub.add_parser(
        "verify",
        help="verify an OTA package and gate on the result",
        description="Verify signatures, expiry, anti-downgrade, and payload digests.",
    )
    p_verify.add_argument("package", help="path to the OTA package JSON document")
    p_verify.set_defaults(func=_cmd_verify)

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
