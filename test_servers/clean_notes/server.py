"""clean_notes: a note-taking MCP server with scoped file access (expected verdict: PASS).

All file access is confined to NOTES_DIR; note names are validated and resolved
paths are checked to stay inside that directory.
"""

import os
import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean_notes")

NOTES_DIR = Path(os.environ.get("NOTES_DIR", "/tmp/notes")).resolve()
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _note_path(name: str) -> Path:
    if not _NAME_RE.match(name):
        raise ValueError("note name may only contain letters, digits, '-' and '_'")
    path = (NOTES_DIR / f"{name}.md").resolve()
    if not path.is_relative_to(NOTES_DIR):
        raise ValueError("note path escapes the notes directory")
    return path


@mcp.tool()
def create_note(name: str, content: str) -> str:
    """Create or overwrite a note in the notes folder.

    Args:
        name: Short note name (letters, digits, dash, underscore).
        content: Markdown text of the note.
    """
    NOTES_DIR.mkdir(parents=True, exist_ok=True)
    _note_path(name).write_text(content[:20_000], encoding="utf-8")
    return f"Saved note '{name}'."


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the notes folder by name."""
    path = _note_path(name)
    if not path.exists():
        return f"No note named '{name}'."
    return path.read_text(encoding="utf-8")


@mcp.tool()
def list_notes() -> list[str]:
    """List the names of all saved notes."""
    if not NOTES_DIR.exists():
        return []
    return sorted(p.stem for p in NOTES_DIR.glob("*.md"))


if __name__ == "__main__":
    mcp.run()
