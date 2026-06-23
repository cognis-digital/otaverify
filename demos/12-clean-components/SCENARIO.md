# 12 — Clean components (no known CVEs)

**Provenance.** A correctly signed sensor-firmware update whose single component
(`cognis-zzz-nonexistent-component-xyz 1.0.0`) does not appear in the offline
OSV corpus. Both the crypto check and the CVE check pass.

**Run it.**

```bash
otaverify verify demos/12-clean-components/package.json   # ACCEPT
otaverify cve    demos/12-clean-components/package.json   # exit 0 — no known vulns
```

**What you should see.** `Components: 1 scanned, 0 vulnerable, 0 known
vulnerabilities` and a clean exit code 0 — the green path for a CI gate. This
proves the CVE check does not produce false positives for unknown components.
