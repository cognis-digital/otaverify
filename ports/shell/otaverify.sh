#!/bin/sh
# POSIX-sh port of the otaverify core (signature quorum + anti-downgrade +
# expiry + payload digest). Depends only on tools present on most Linux/embedded
# images: python3 (for canonical JSON + field extraction), openssl (HMAC),
# sha256sum. The canonical signing basis is produced by python3's json so it is
# byte-identical to the reference and signatures cross-verify.
#
# Usage: sh otaverify.sh verify <package.json>
set -eu

PKG=""
WORK=""
ERR=0

emit() { printf '  %s\n' "$1"; }

# Dump the package fields we need to a flat, shell-friendly work file:
#   THRESHOLD <n>
#   SIG <keyid> <secret-hex> <provided-sig>
#   MV <manifest-version|NA>  DV <device-version|NA>
#   MC <manifest-counter|NA>  DC <device-counter|NA>
#   EXP <iso|NA>
#   PAY <name> <hexbytes> <want-sha256|?>
#   MANIFEST_CANON <one-line canonical manifest>
explode() {
  python3 - "$PKG" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
root = d.get("root") or {}
keys = root.get("keys") or {}
m = d.get("manifest") or {}
dev = d.get("device") or {}
print("THRESHOLD", int(root.get("threshold", 1) or 1))
for s in (d.get("signatures") or []):
    kid = s.get("keyid", "")
    print("SIG", kid, keys.get(kid, "NA"), s.get("sig", ""))
print("MV", m.get("version", "NA"))
print("DV", dev.get("version", "NA"))
print("MC", m.get("counter", "NA"))
print("DC", dev.get("counter", "NA"))
print("EXP", m.get("expires", "NA"))
images = {i.get("name"): i for i in (m.get("images") or []) if isinstance(i, dict)}
for n, v in (d.get("payloads") or {}).items():
    print("PAY", n, v, images.get(n, {}).get("sha256", "?"))
print("CANON", json.dumps(m, sort_keys=True, separators=(",", ":")))
PY
}

cmd_verify() {
  PKG="$1"
  [ -f "$PKG" ] || { echo "error: no such file: $PKG" >&2; exit 2; }
  WORK="$(mktemp)"
  explode > "$WORK"

  printf 'OTA package: %s\n' "$PKG"

  THRESHOLD="$(awk '/^THRESHOLD /{print $2}' "$WORK")"
  CANON="$(sed -n 's/^CANON //p' "$WORK")"

  VALID=0
  # Read signature lines (no subshell: feed from a here-substitute via temp).
  awk '/^SIG /{print}' "$WORK" > "$WORK.sigs"
  while IFS=' ' read -r _tag kid secret sig; do
    [ -n "${kid:-}" ] || continue
    if [ "$secret" = "NA" ]; then
      emit "WARN sig.unknown $kid"
      continue
    fi
    got="$(printf '%s' "$CANON" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$secret" -r 2>/dev/null | cut -d' ' -f1)"
    if [ "$got" = "$sig" ]; then
      VALID=$((VALID + 1))
    else
      emit "FAIL sig.invalid $kid"
      ERR=1
    fi
  done < "$WORK.sigs"
  rm -f "$WORK.sigs"

  if [ "$VALID" -lt "$THRESHOLD" ]; then
    emit "FAIL sig.threshold ${VALID}/${THRESHOLD}"; ERR=1
  else
    emit "ok   sig.threshold ${VALID}/${THRESHOLD}"
  fi

  MV="$(awk '/^MV /{print $2}' "$WORK")"; DV="$(awk '/^DV /{print $2}' "$WORK")"
  MC="$(awk '/^MC /{print $2}' "$WORK")"; DC="$(awk '/^DC /{print $2}' "$WORK")"
  if [ "$MV" != "NA" ] && [ "$DV" != "NA" ] && [ "$MV" -lt "$DV" ]; then
    emit "FAIL rollback.version ${MV}<${DV}"; ERR=1
  fi
  if [ "$MC" != "NA" ] && [ "$DC" != "NA" ] && [ "$MC" -lt "$DC" ]; then
    emit "FAIL rollback.counter ${MC}<${DC}"; ERR=1
  fi

  EXP="$(awk '/^EXP /{print $2}' "$WORK")"
  if [ "$EXP" != "NA" ]; then
    yr="$(printf '%s' "$EXP" | cut -c1-4)"
    if [ "$yr" -lt 2024 ] 2>/dev/null; then emit "FAIL manifest.expiry $EXP"; ERR=1; fi
  fi

  awk '/^PAY /{print}' "$WORK" > "$WORK.pay"
  while IFS=' ' read -r _tag name hexv want; do
    [ -n "${name:-}" ] || continue
    got="$(printf '%s' "$hexv" | python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))' | sha256sum | cut -d' ' -f1)"
    if [ "$got" = "$want" ]; then emit "ok   payload.digest $name"; else emit "FAIL payload.digest $name"; ERR=1; fi
  done < "$WORK.pay"
  rm -f "$WORK.pay" "$WORK"

  if [ "$ERR" -eq 0 ]; then printf 'Verdict    : ACCEPT\n'; exit 0; fi
  printf 'Verdict    : REJECT\n'; exit 1
}

case "${1:-}" in
  verify) shift; cmd_verify "$@" ;;
  *) echo "usage: sh otaverify.sh verify <package.json>" >&2; exit 2 ;;
esac
