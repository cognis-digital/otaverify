"""OTAVERIFY MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from otaverify.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-otaverify[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-otaverify[mcp]'")
        return 1
    app = FastMCP("otaverify")

    @app.tool()
    def otaverify_scan(target: str) -> str:
        """Validate OTA update packages end-to-end: signature chains, rollback protection, anti-downgrade counters, and delta-patch integrity.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
