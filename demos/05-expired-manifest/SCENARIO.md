# Demo 05 — Expired staging artifact

## Where this came from

A build-bot produced a signed staging package months ago and it sat in an
artifact bucket. An operator tries to push it to devices today. The signature
is perfectly valid and the version advances normally — but the manifest's
`expires` field (`2025-03-01`) is in the past.

Freshness is a first-class TUF/Uptane property: a cryptographically valid but
stale manifest is exactly the vector a replay/freeze attacker uses to pin a
fleet to known-vulnerable firmware.

## Run it

```bash
python -m otaverify verify demos/05-expired-manifest/package.json
```

## What to expect

**Verdict: REJECT** (exit `1`). One error: `manifest.expiry` — *manifest expired
at 2025-03-01T00:00:00Z*. Every other check (`sig.threshold`, both rollback
checks, `payload.digest`) is green, which isolates expiry as the sole blocker.

## How to act

Do not ship. Re-cut and re-sign the release with a fresh `expires` window, then
re-verify. Treat any expired-but-valid manifest reaching production as a process
gap in your artifact retention/promotion policy.
