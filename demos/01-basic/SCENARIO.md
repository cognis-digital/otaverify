# Demo 01 - Basic OTA verification

This demo shows OTAVERIFY validating a real OTA update package.

## The package (`package.json`)

A device pinned trust root with **two** signing keys and a **threshold of 2**
(both keys must sign). The manifest declares update `version 12` / anti-rollback
`counter 12`, while the device currently runs `version 11` / `counter 11` — a
legitimate forward upgrade. One small image payload (`config`, the bytes
`deadbeef`) is included and its sha256 is checked against the signed manifest.

The two HMAC-SHA256 signatures were computed over the canonical (sorted-key,
compact) JSON encoding of the manifest using the pinned key secrets, so they
verify with the standard library alone.

## Run it

```
python -m otaverify verify demos/01-basic/package.json
python -m otaverify verify --format json demos/01-basic/package.json
```

## Expected result

**Verdict: ACCEPT** (exit code `0`). The findings include:

- `sig.threshold` info: `2/2 valid`
- `rollback.version` info: `11 -> 12`
- `rollback.counter` info: `11 -> 12`
- `payload.digest` info: `config` digest ok
- `manifest.expiry` info: valid until 2030

### Try breaking it

Lower the device `version` requirement by editing the manifest `version` to
`10` (below the device's `11`): the verdict flips to **REJECT** with a
`rollback.version` error — exactly the downgrade attack the tool blocks. Note
that editing the manifest also invalidates the signatures, demonstrating the
signature-chain check at the same time.
