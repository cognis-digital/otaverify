# Demo 08 — Signature threshold not met

## Where this came from

The trust root requires **2-of-2** signatures (`release-eng` + `hsm-prod`).
During this release the HSM holding `hsm-prod` was unavailable, so only
`release-eng` signed. The one signature present is completely valid — but a
single signer cannot satisfy a 2-of-2 policy.

This is the everyday operational case for M-of-N signing: a lost/locked key, an
HSM outage, or a rushed release that skipped a required signer. The threshold
exists precisely so one compromised or absent key cannot ship firmware alone.

## Run it

```bash
python -m otaverify verify demos/08-threshold-not-met/package.json
```

## What to expect

**Verdict: REJECT** (exit `1`). One error:

- `sig.threshold` — *signature threshold not met: 1/2 valid*

Expiry, rollback, and the payload digest are all green. The lone valid signature
is acknowledged but the quorum is not reached.

## How to act

Do not override the threshold. Restore access to the second signer (bring the
HSM back, recover the key per your key-ceremony runbook), collect the missing
signature, and re-verify. Lowering the threshold to ship faster defeats the
whole control.
