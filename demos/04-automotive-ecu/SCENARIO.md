# Demo 04 — Automotive ECU fleet upgrade (UN R155/R156)

## Where this came from

A Tier-1 supplier ships a scheduled ECU firmware bump to a connected-vehicle
fleet. Under **UN R156** (software update management) the release must carry a
verifiable, multi-signed manifest before the OTA campaign can begin. The trust
root pins three keys — `fleet-root`, `release-eng`, and an offline `hsm-prod`
key — with a **2-of-3 threshold**. This release was signed by `fleet-root` and
`hsm-prod` (release-eng was out that day); two valid signatures still meet the
threshold.

The campaign moves devices from build `2026-05-15` (`version 2026051501`,
counter 47) to build `2026-06-20` (`version 2026062001`, counter 48) — a clean
forward step. Two images ride along: `ecu-app` and `ecu-cfg`, each digest-checked
against the signed manifest.

## Run it

```bash
python -m otaverify verify demos/04-automotive-ecu/package.json
python -m otaverify --format sarif verify demos/04-automotive-ecu/package.json
```

## What to expect

**Verdict: ACCEPT** (exit `0`). `sig.threshold` reports `2/2 valid`, both
rollback checks advance, and both payload digests match.

## How to act

Green here means the manifest is authentic and non-regressive — promote the
campaign to the rollout ring. Pipe `--format sarif` into your CI dashboard to
keep an auditable R156 evidence trail per release.
