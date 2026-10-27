"""Plugin environment variables, with a single trust rule."""

from __future__ import annotations

import os


def variable(name: str) -> str | None:
    """ANONYMIZER_* variables only count outside Claude Code (tests, CLI). Inside a session a
    project can set variables from its settings.json, so they are not trusted there.
    scripts/run.sh exports CLAUDE_PLUGIN_ROOT to hooks and to the MCP server alike."""
    if os.environ.get("CLAUDE_PLUGIN_ROOT"):
        return None
    return os.environ.get(name)
