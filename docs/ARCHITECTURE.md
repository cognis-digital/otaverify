# OTAVERIFY — Architecture

> Validate OTA update packages end-to-end: signature chains, rollback protection, anti-downgrade counters, and delta-patch integrity.

```
package.json ─▶ verify ─▶ signatures · rollback · expiry · digests ─▶ verdict ─▶ table · json · sarif
            └─▶ cve    ─▶ extract components ─▶ match vs bundled OSV (offline) ─▶ findings
```

- **verify** (`otaverify/core.py`) checks the HMAC-SHA256 signature quorum over a
  canonical manifest encoding, anti-rollback (version + monotonic counter),
  expiry, and per-image payload SHA-256/size.
- **cve** (`otaverify/cvecheck.py`) extracts components from the package and
  matches them against the bundled `cognis_vulndb.jsonl.gz` (~262k OSV records)
  via `otaverify/vulndb_local.py` — fully offline. Severity buckets come from a
  CVSS v3.1 base-score computed in-tree.
- **datafeeds** (`otaverify/datafeeds.py`) refreshes the corpus from OSV/NVD/GHSA
  for edge deployment and supports air-gap snapshot export/import.
- **MCP server** (`otaverify mcp`) exposes the verifier for Cognis.Studio agents.
- **Ports** (`ports/`) re-implement `verify` in JS/Go/Rust/shell, cross-verified in CI.

Extend by adding a check + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
