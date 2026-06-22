# Demo 09 — Unknown signing key (supply-chain injection)

## Where this came from

An attacker who never had access to the pinned keys signs a manifest with their
own `rogue-key` and slips the package into the update channel. The HMAC they
produced is internally consistent — but `rogue-key` is **not in the device's
trust root**, so it carries no authority here.

This is the supply-chain / unauthorized-publisher case: trust is anchored to the
*pinned root keys*, not to "any valid-looking signature." A signature from an
unknown key must be ignored, not counted.

## Run it

```bash
python -m otaverify verify demos/09-unknown-key/package.json
```

## What to expect

**Verdict: REJECT** (exit `1`). One warning and one error:

- `sig.unknown` (warning) — *signature from unknown key 'rogue-key' ignored*
- `sig.threshold` (error) — *signature threshold not met: 0/1 valid*

The rogue signature is discarded, leaving zero trusted signatures against a
threshold of one.

## How to act

Reject and alert. A package signed only by an unrecognized key in your update
feed is a strong indicator of a publishing-credential or distribution compromise.
Rotate keys if you suspect exposure and investigate how the artifact entered the
channel.
