# Demo 06 — Downgrade attack blocked

## Where this came from

A device is healthy on `version 44` / anti-rollback `counter 102`. An attacker
(or a misconfigured release tool) presents a **properly signed** older package —
`version 31` / `counter 90` — hoping to roll the device back to firmware with a
known, exploitable bug. The 2-of-3 signatures (`release-eng` + `qa-signer`) are
genuine; cryptographic trust alone would let this through.

Anti-downgrade is the defense. otaverify compares the offered manifest against
the device's current state and refuses any regression in either the version or
the monotonic counter.

## Run it

```bash
python -m otaverify verify demos/06-downgrade-blocked/package.json
python -m otaverify --format json verify demos/06-downgrade-blocked/package.json | jq '.ok, .findings[]|select(.severity=="error")'
```

## What to expect

**Verdict: REJECT** (exit `1`). Two errors:

- `rollback.version` — *downgrade blocked: update version 31 < installed 44*
- `rollback.counter` — *anti-rollback counter regressed: 90 < 102*

Signatures and expiry are fine — proving a valid signature is necessary but not
sufficient.

## How to act

Block it. This is the canonical rollback-protection case from R155 threat
modelling. If a legitimate downgrade is truly required (e.g. a bad release),
it must go through an explicit, audited counter-reset on the device side — never
silently through the OTA channel.
