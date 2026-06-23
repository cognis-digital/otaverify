# Ports of otaverify

Each port re-implements the **`verify`** command from `otaverify`'s core engine:
HMAC-SHA256 signature quorum, anti-downgrade (version + monotonic counter),
manifest expiry, and per-image payload digests. The canonical signing basis
(sorted-key, compact JSON) is byte-for-byte identical across every port, so a
signature produced by the Python reference **cross-verifies** in Go, Rust, Node,
and shell — and the CI (`.github/workflows/ports.yml`) proves it on every push by
running each port against the same Python-signed demo packages.

| Language | Path | Run | Smoke test | Deps |
|---|---|---|---|---|
| Python (reference) | [`../otaverify/`](../otaverify/) | `otaverify verify demos/04-automotive-ecu/package.json` | `pytest` | stdlib |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js verify <pkg>` | `node ports/javascript/test.js` | Node stdlib |
| Go | [`go/`](go/) | `cd ports/go && go run . verify ../../demos/04-automotive-ecu/package.json` | `go test ./...` | stdlib |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- verify ../../demos/04-automotive-ecu/package.json` | `cargo test` | **zero crates** (in-tree SHA-256/HMAC + JSON) |
| POSIX shell | [`shell/`](shell/) | `sh ports/shell/otaverify.sh verify <pkg>` | `sh ports/shell/test.sh` | python3 + openssl + sha256sum |

All ports print the same verdict format (`Verdict: ACCEPT|REJECT` + per-check
findings) and use **exit code 1 for REJECT, 0 for ACCEPT** so they drop into a CI
gate unchanged. The component CVE check (`otaverify cve`) lives in the Python
reference only, since it relies on the bundled offline OSV corpus.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).
