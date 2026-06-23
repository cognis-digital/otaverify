#!/bin/sh
# Smoke test for the shell port. Generates a correctly signed demo package and
# asserts ACCEPT, then tampers it and asserts REJECT. Needs python3 + openssl.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SH="$HERE/otaverify.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build a signed package with python3 (mirrors the reference signing).
python3 - "$TMP/good.json" <<'PY'
import hashlib, hmac, json, sys
keys = {"vendor-a": "00112233445566778899aabbccddeeff",
        "vendor-b": "ffeeddccbbaa99887766554433221100"}
raw = b"abc"
m = {"version": 12, "counter": 12, "expires": "2031-01-01T00:00:00Z",
     "images": [{"name": "fw", "sha256": hashlib.sha256(raw).hexdigest(), "size": 3}]}
payload = json.dumps(m, sort_keys=True, separators=(",", ":")).encode()
sigs = [{"keyid": k, "sig": hmac.new(bytes.fromhex(s), payload, hashlib.sha256).hexdigest()}
        for k, s in keys.items()]
pkg = {"root": {"keys": keys, "threshold": 2}, "manifest": m,
       "device": {"version": 11, "counter": 11},
       "payloads": {"fw": raw.hex()}, "signatures": sigs}
json.dump(pkg, open(sys.argv[1], "w"))
PY

fail=0

if sh "$SH" verify "$TMP/good.json" >/dev/null 2>&1; then
  echo "PASS: valid package accepted"
else
  echo "FAIL: valid package was rejected"; fail=1
fi

# Tamper the payload -> must REJECT.
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));d["payloads"]["fw"]="000000";json.dump(d,open(sys.argv[2],"w"))' "$TMP/good.json" "$TMP/bad.json"
if sh "$SH" verify "$TMP/bad.json" >/dev/null 2>&1; then
  echo "FAIL: tampered package was accepted"; fail=1
else
  echo "PASS: tampered package rejected"
fi

exit "$fail"
