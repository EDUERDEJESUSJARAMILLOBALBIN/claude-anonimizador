"""MCP server over stdio: the model's only door to the original files.

It implements the minimum of the protocol (initialize, tools/list, tools/call, ping) without
external dependencies. No response carries values: only validated profiles, summaries with counts,
and errors redacted by the engine.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import __version__, engine
from .adapters import UnsupportedFormat
from .profile import InvalidProfile
from .structured import InvalidFile

PROTOCOL = "2025-06-18"
INSTRUCTIONS = (
    "Use these tools instead of reading files with personal data. Never open the original with Read, "
    "Bash or any other tool: profile it, agree on the plan with the user and work only with the "
    "anonymized output that apply returns."
)

_PATH = {"type": "string",
         "description": "Absolute path of the original file (.csv, .tsv, .xlsx, .xlsm, .json, .jsonl, .yaml)"}
_STRICT = {"type": "boolean", "description": "Also hide sheet and column names", "default": False}

TOOLS = [
    {
        "name": "profile",
        "description": (
            "Profile a data file without returning values: for each table and column it gives an alias, the "
            "detected category (document, email, name...), confidence, % empty, unique count and suggested "
            "action, plus a count of hidden content (hidden sheets, comments, metadata). Once profiled, the "
            "file is protected and the hooks block reading it any other way."
        ),
        "inputSchema": {"type": "object", "properties": {"path": _PATH, "strict": _STRICT}, "required": ["path"]},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "apply",
        "description": (
            "Write an anonymized copy from scratch (no comments, metadata or formulas) and verify it byte by "
            "byte against the original's fingerprints; if a single value remains, the copy is deleted and the "
            "call fails. Requires a previous profile. Columns the plan does not mention take the suggested "
            "action; 'review' is dropped; hidden sheets are omitted unless the plan names them. Document, email, "
            "phone, name, address, birth date, card, bank account, ip and plate cannot be kept. The user "
            "approves the whole plan, with column names, before it runs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH,
                "plan": {
                    "type": "object",
                    "description": 'By alias: {"t1": {"c3": "pseudonymize", "c7": "generalize"}, "t2": "omit"}. '
                    "Actions: drop, pseudonymize, generalize, keep.",
                },
                "strict": _STRICT,
            },
            "required": ["path", "plan"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]


def _call(name: str, arguments: dict[str, Any]) -> str:
    if name == "profile":
        return engine.profile(Path(arguments["path"]), bool(arguments.get("strict", False)))
    if name == "apply":
        # The engine decides the output: the model chooses neither where nor under which name
        result = engine.apply(Path(arguments["path"]), arguments.get("plan") or {}, None,
                              bool(arguments.get("strict", False)))
        return json.dumps(result, ensure_ascii=False)
    raise KeyError(name)


def _tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return {"content": [{"type": "text", "text": _call(name, arguments)}], "isError": False}
    except (engine.InvalidPlan, UnsupportedFormat, InvalidFile) as error:
        message = str(error)
    except InvalidProfile as error:
        message = f"the profile broke the contract ({str(error).split(':')[0]}); retry with strict=true"
    except FileNotFoundError:
        message = "the file does not exist"
    except KeyError:
        message = "unknown tool or argument"
    except Exception as error:  # noqa: BLE001 — the original message may carry values
        message = f"the file could not be processed ({type(error).__name__})"
    return {"content": [{"type": "text", "text": message}], "isError": True}


def respond(message: dict[str, Any]) -> dict[str, Any] | None:
    method, request_id = message.get("method"), message.get("id")
    if request_id is None:
        return None  # a notification
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion") or PROTOCOL
        result: Any = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "anonymizer", "version": __version__},
            "instructions": INSTRUCTIONS,
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params") or {}
        result = _tool(params.get("name", ""), params.get("arguments") or {})
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"unsupported method: {method}"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            response = respond(json.loads(line))
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}}
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
