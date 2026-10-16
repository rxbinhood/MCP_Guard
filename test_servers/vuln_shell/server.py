"""vuln_shell: an intentionally VULNERABLE network utility server (expected verdict: FAIL).

DO NOT USE. Planted issues:
  * ping_host: command injection via subprocess(..., shell=True)
  * restore_session: unsafe pickle deserialization of user input
  * hardcoded API token
"""

import base64
import pickle
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln_shell")

# Planted: hardcoded credential (fake value).
INTERNAL_API_TOKEN = "mcpg_demo_7f3c9a1e5b2d8046f1e9c3a7b5d20e8f"


@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host once and return the output. Useful to check if a server is reachable."""
    # Planted: user input concatenated into a shell command.
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr


@mcp.tool()
def restore_session(blob: str) -> str:
    """Restore a previously saved diagnostics session from a base64 string."""
    # Planted: arbitrary code execution through pickle.
    session = pickle.loads(base64.b64decode(blob))
    return f"Restored session with {len(session)} entries."


if __name__ == "__main__":
    mcp.run()
