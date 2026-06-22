# Demo 07 — Tampered payload (digest mismatch)

## Where this came from

The manifest is authentic — signed by the offline `hsm-prod` key, version and
counter advance cleanly, not expired. But the delivered `modem` image bytes do
**not** hash to the `sha256` the signed manifest commits to. This is what a
man-in-the-middle, a flipped bit on a flaky CDN, or a substituted artifact looks
like: the signed metadata is trustworthy, the actual payload is not.

The manifest's signature covers only the metadata (names, digests, sizes). The
payload digest check is what binds the *bytes you received* to that signed
promise.

## Run it

```bash
python -m otaverify verify demos/07-payload-tampered/package.json
```

## What to expect

**Verdict: REJECT** (exit `1`). One error:

- `payload.digest` — *payload 'modem' digest mismatch (got 4da70c00…, want 6f7a141d…)*

Signature, expiry, and rollback checks all pass — the integrity break is on the
content layer, exactly where it should be caught.

## How to act

Discard the artifact and re-fetch from the trusted origin. A persistent mismatch
after re-download points at a compromised mirror or a corrupted build pipeline —
escalate, do not retry blindly.
