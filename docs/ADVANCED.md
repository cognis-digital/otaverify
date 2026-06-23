# otaverify — Advanced usage

## CI gate (block an unsafe or vulnerable update)
```yaml
- run: pip install cognis-otaverify
# 1) crypto + rollback + digest gate
- run: otaverify verify release/package.json
# 2) known-CVE gate (offline), emit SARIF for code-scanning
- run: otaverify --format sarif cve release/package.json > cve.sarif
- run: otaverify cve release/package.json --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: cve.sarif }
```

## Offline component CVE check
```bash
# Match payload components against the bundled ~262k-record OSV corpus (no network).
otaverify cve release/package.json
otaverify cve release/package.json --min-severity high --fail-on critical
otaverify --format json cve release/package.json | jq '.max_severity, .vulnerable_components'
```

## Refresh the CVE corpus for the edge / air gap
```bash
python -m otaverify.datafeeds update osv cisa-kev epss     # fetch + cache (online side)
python -m otaverify.datafeeds bulk nvd-cve --max 250000    # paginate NVD to disk
python -m otaverify.datafeeds snapshot-export feeds.tar.gz # sneakernet to an air gap
python -m otaverify.datafeeds snapshot-import feeds.tar.gz # inside the enclave
```

## Pipe into a SIEM / webhook
```bash
otaverify --format json verify release/package.json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "otaverify": { "command": "otaverify", "args": ["mcp"] } } }
```

## Run a language port instead of Python
```bash
node ports/javascript/index.js verify demos/04-automotive-ecu/package.json    # Node
( cd ports/go   && go run   . verify ../../demos/04-automotive-ecu/package.json )  # Go
( cd ports/rust && cargo run -- verify ../../demos/04-automotive-ecu/package.json ) # Rust (zero crates)
sh ports/shell/otaverify.sh verify demos/04-automotive-ecu/package.json       # POSIX shell
```

## Ports & services
Default service/forward ports: **8000** (HTTP API), **8080** (alt), **3000** (UI), **9090** (metrics).
