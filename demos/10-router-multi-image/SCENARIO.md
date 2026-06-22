# Demo 10 — Multi-image router firmware (full quorum, clean accept)

## Where this came from

A network-equipment vendor ships a composite firmware bundle for an edge router:
three images — `kernel`, `rootfs`, and `bootldr` — in a single OTA package. The
release policy is strict **3-of-3** signing (`fleet-root` + `release-eng` +
`qa-signer` must all sign), reflecting a high-assurance device where every
signer represents a separate control gate.

All three signatures are valid, the version steps `4 -> 5`, the counter advances,
the manifest is well within its validity window, and every one of the three
payload digests matches the signed manifest.

## Run it

```bash
python -m otaverify verify demos/10-router-multi-image/package.json
python -m otaverify --format sarif verify demos/10-router-multi-image/package.json
```

## What to expect

**Verdict: ACCEPT** (exit `0`). `sig.threshold` reports `3/3 valid` and you get
three separate `payload.digest` *ok* lines — one per image — confirming each
component independently.

## How to act

This is the all-green reference: a fully-quorum-signed, fresh, non-regressive,
content-verified bundle. Use it as the known-good baseline when wiring otaverify
into CI, and diff future runs against it.
