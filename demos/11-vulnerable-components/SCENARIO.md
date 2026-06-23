# 11 — Vulnerable components inside a signed OTA bundle

**Provenance.** A correctly signed, forward-versioned gateway firmware update.
The cryptography is perfect — 2-of-2 quorum, monotonic counter, valid payload
digest — so plain `verify` **ACCEPTS** it. But the bundle ships components with
*known* CVEs: `log4j-core 2.14.1`, `lodash 4.17.15`, and `openssl 1.1.1k`.

This is the supply-chain blind spot `otaverify cve` closes: a cryptographically
trustworthy update can still carry exploitable software.

**Run it.**

```bash
otaverify verify demos/11-vulnerable-components/package.json     # ACCEPT (crypto is fine)
otaverify cve    demos/11-vulnerable-components/package.json     # exit 1 — known CVEs found
otaverify cve    demos/11-vulnerable-components/package.json --fail-on critical
otaverify --format sarif cve demos/11-vulnerable-components/package.json > cve.sarif
```

**What you should see.** Among the matches is **CVE-2021-44228** (Log4Shell,
remote code injection in Log4j) resolved entirely from the bundled offline OSV
corpus — no network. `lodash 4.17.15` brings prototype-pollution and
command-injection advisories; `openssl` brings several more.

**How to act.** Gate your release pipeline with
`otaverify cve … --fail-on high` so a flashing job aborts before a known-
vulnerable component reaches the fleet. Rebuild the bundle with patched
component versions and re-run until clean.
