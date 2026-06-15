#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> verify package.json --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Destination URL for POST")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    args = ap.parse_args()

    url = args.url.strip()
    if not url:
        print("error: --url must not be empty", file=sys.stderr)
        return 2
    if not (url.startswith("http://") or url.startswith("https://")):
        print(f"error: --url must start with http:// or https://, got {url!r}", file=sys.stderr)
        return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        print("error: stdin is empty — nothing to post", file=sys.stderr)
        return 2

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"warning: skipping malformed header {h!r}", file=sys.stderr)
            continue
        req.add_header(k.strip(), v.strip())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
