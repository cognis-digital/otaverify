"""OTAVERIFY MCP server — exposes verify() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from otaverify.core import load_json, verify_package


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
        """Validate OTA update packages end-to-end: signature chains, rollback
        protection, anti-downgrade counters, and delta-patch integrity.
        Returns JSON findings."""
        try:
            package = load_json(target)
        except (OSError, ValueError) as exc:
            return json.dumps({"ok": False, "error": str(exc)})
        result = verify_package(package)
        return json.dumps(result.to_dict())

    app.run()
    return 0
