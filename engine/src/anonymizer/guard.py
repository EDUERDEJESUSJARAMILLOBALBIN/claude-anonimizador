"""The plugin's hooks. Standard library only: they run on every tool call.

Rules:
1. Allowlist: Claude reads no data file (.csv, .xlsx, .sql, .db...) outside ~/anonimizados,
   whether it was profiled or not.
2. Bash is protected by the operating system, not by this hook: reading a command's text is not
   enough to know which file it will open. If the sandbox is not configured or a project loosens
   it, Bash is closed. The text checks that remain for Bash are an extra layer.
3. Tripwire: if an output carries data from an original, it is blocked whole, without saying which
   value matched, and the session uses no more tools.

    pre     PreToolUse        blocks every path to an original other than the plugin's MCP server
    post    PostToolUse       tripwire over every output
    prompt  UserPromptSubmit  blocks @mentions of data files and pasted personal data
    end     SessionEnd        audits the transcript and warns if it found values
"""

from __future__ import annotations

import glob
import itertools
import json
import os
import re
import shlex
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlparse

from . import state
from .detect import is_colombian_phone, is_valid_luhn
from .fingerprints import FRAGMENT
from .settings import project_problems, sandbox_problems

OWN_TOOLS = "mcp__plugin_anonimizador_anonymizer__"
PREFIX = "Anonymizer:"
# Tools that neither touch local files nor return their content
NO_FILES = {"WebSearch", "TodoWrite", "AskUserQuestion", "ExitPlanMode", "EnterPlanMode",
            "TaskStop", "ScheduleWakeup", "ToolSearch", "Skill", "SendMessage", "ListAgents",
            # Delegating reads nothing: the subagent's tools go through this same guard
            "Agent", "Task"}
# Writing text that mentions a path does not read the original; for these only the target counts
WRITERS = {"Edit": ("file_path",), "Write": ("file_path",), "MultiEdit": ("file_path",),
           "NotebookEdit": ("notebook_path",)}
READERS = {"Read", "Grep", "Glob", "LSP"}
SHELL = {"Bash", "PowerShell", "Monitor"}
# Third-party MCP tools that run code (they can build a path no text reveals) or search and read
# files from an index (they return lines of a CSV fixture without naming it)
OPAQUE_MCP = re.compile(r"(run_|evaluate|eval|exec|javascript|python|shell|terminal|command|script|repl|"
                        r"notebook|cell|sql|search_code|code_search|snippet|query_graph|grep|read_file|"
                        r"read_multiple|read_text_file|search_files|file_content|get_file|search_text|"
                        r"text_search|find_in|full_text|detect_changes|diff)", re.IGNORECASE)
# Files that make Claude Code run something outside the plugin's reach: hooks, MCP servers, skills
# The folders themselves count too: moving a prepared folder into place names no file inside it
CLAUDE_CONFIG = re.compile(r"(^|/)(\.claude(/(settings[^/]*\.json|hooks|skills|commands|agents)(/|$)|$)|"
                           r"\.mcp\.json$|\.claude\.json$|managed-settings)", re.IGNORECASE)
HARD_LINK = re.compile(r"^\s*ln(\s|$)")
MOVES = re.compile(r"^\s*(mv|rm|rmdir|ln|unlink|cp|rsync)(\s|$)")
INDEXERS = re.compile(r"\b(mdfind|mdls|mdimport|qlmanage|textutil|spotlight)\b")
KEYCHAIN = re.compile(r"\bsecurity\b.*\b(find-generic-password|dump-keychain|export)\b|\bdump-keychain\b")
# Creating folders, changing permissions or looking at the folder itself (ls -d) reads no original
NO_READ = re.compile(r"^\s*(mkdir|chmod|ls\s+-[a-zA-Z]*d[a-zA-Z]*)\s[^$`<>*?{\n]*$|^\s*(echo|true|:)(\s[^$`<>\n]*)?$")
SEPARATORS = re.compile(r"&&|\|\||[;&|()`\n]|\$\(")
CHANGE_DIR = re.compile(r"^\s*(cd|pushd)(\s|$)")
SIMPLE_CHANGE_DIR = re.compile(r"^\s*(?:cd|pushd)\s+([^\s$`*?\[{]+)\s*$")
_EXT = "|".join(state.DATA_EXTENSIONS)
DATA_PATH = re.compile(rf"[~\w./\-*?\[\]]*\.(?:{_EXT})(?![\w])", re.IGNORECASE)
ENDS_IN_DATA = re.compile(rf"\.(?:{_EXT})$", re.IGNORECASE)
# Grep outside the allowed folders: only simple globs of an extension that is not data there
SIMPLE_GLOB = re.compile(r"^(?:\*\*/)?\*\.([A-Za-z0-9]{1,10})$")
EXCLUDE_DATA = "!*.{" + ",".join(state.DATA_EXTENSIONS) + "}"
# Inside a project JSON, YAML and archives are configuration or dependencies: only tabular is excluded
EXCLUDE_TABULAR = "!*.{" + ",".join(state.TABULAR_EXTENSIONS) + "}"
SAFE_TYPES = {"py", "js", "ts", "jsx", "tsx", "rb", "go", "rust", "java", "kotlin", "swift", "c", "cpp", "h",
              "cs", "php", "sh", "html", "css", "scss", "md", "markdown", "vue", "svelte", "elixir", "erb",
              "haml", "lua", "dart", "scala", "clojure", "r", "toml", "make", "docker", "cmake"}
GLOB_BUDGET = 2.0  # seconds; beyond that it is denied rather than risking the hook timeout
MAX_WILDCARDS = 3  # path components with a wildcard; more than that walks half the disk
MAX_DIALOG = 2500
MIN_PASTED_DATA = 3
MIN_BASENAME = 5
UNKNOWN_DIR = "/anonymizer-unknown-folder"


class SlowGlob(Exception):
    pass


def _exit(payload: dict[str, Any] | None = None) -> None:
    if payload is not None:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.exit(0)


def _deny(reason: str) -> None:
    _exit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"{PREFIX} {reason} Use /anonimizador:anonymize and work with the copy in "
                                    "~/anonimizados.",
    }})


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
        decoded = unquote(value)
        if decoded != value:
            yield decoded
        if value.startswith("file:"):
            yield unquote(urlparse(value).path)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _tokens(text: str) -> list[str]:
    try:
        parts = shlex.split(text, posix=True)
    except ValueError:
        parts = text.split()
    return [p.lstrip("@<>") for p in parts] + [text.strip()]


def _resolve(token: str, cwd: Path) -> Path | None:
    if not token or "\n" in token or len(token) > 4096:
        return None
    try:
        path = Path(os.path.expandvars(token)).expanduser()
        return (path if path.is_absolute() else cwd / path).resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _expand(path: Path, deadline: float) -> list[Path]:
    """Expand a wildcard like the shell does, capped in components, results and time. It runs in a
    thread: a glob that finds nothing does not return control while it searches either."""
    if sum(glob.has_magic(p) for p in path.parts) > MAX_WILDCARDS or time.monotonic() >= deadline:
        raise SlowGlob  # with no budget it does not start: the result never depends on machine speed
    found: list[Path] = []
    worker = threading.Thread(
        target=lambda: found.extend(Path(p) for p in itertools.islice(glob.iglob(str(path)), 500)),
        daemon=True,
    )
    worker.start()
    worker.join(max(deadline - time.monotonic(), 0))
    if worker.is_alive():
        raise SlowGlob
    return [p.resolve() for p in found]


def _name_pattern(name: str) -> re.Pattern[str]:
    flags = re.IGNORECASE if state.CASE_INSENSITIVE else 0
    return re.compile(rf"(^|[\s/'\"=@]){re.escape(name)}($|[\s'\";|&)])", flags)


def touches_protected(text: str, cwd: Path, files: list[Path], roots: list[Path], deadline: float) -> bool:
    """Does the text name or resolve to a protected original or something inside a protected root?"""
    home = str(Path.home())
    comparable = state.path_key(text) if state.CASE_INSENSITIVE else text
    for path in files:
        for form in (str(path), str(path).replace(home, "~", 1)):
            if state.path_key(form) in comparable:
                return True
        if len(path.name) >= MIN_BASENAME and _name_pattern(path.name).search(text):
            return True
    for root in roots:
        for form in (str(root), str(root).replace(home, "~", 1)):
            if state.path_key(form) in comparable:
                return True
    for token in _tokens(text):
        if (resolved := _resolve(token, cwd)) is None:
            continue
        candidates = (_expand(resolved, deadline) or [resolved]) if glob.has_magic(token) else [resolved]
        for candidate in candidates:
            if any(state.path_key(candidate) == state.path_key(f) for f in files) \
                    or any(state.inside(candidate, r) for r in roots):
                return True
    return False


def closed_data_file(text: str, cwd: Path, deadline: float) -> Path | None:
    """The first data file outside the allowed folders that the text names (or its wildcard
    expands to). It looks at whole arguments (with quotes and spaces: "My drive/export.zip") as well
    as path-shaped fragments."""
    candidates = dict.fromkeys(DATA_PATH.findall(text))
    candidates.update(dict.fromkeys(t for t in _tokens(text) if ENDS_IN_DATA.search(t)))
    for candidate in candidates:
        if (path := _resolve(candidate, cwd)) is None:
            continue
        if glob.has_magic(candidate):
            # A wildcard that expands to nothing here may expand where the command runs: closed
            matches = _expand(path, deadline) or [path]
            if matches == [path]:
                return path if not state.is_allowed(path) else None
        else:
            # A file that does not exist yet (`-o release.zip`, `> summary.csv`) has nothing to read
            matches = [path] if path.exists() else []
        for match in matches:
            if state.closed_by_extension(match) and not state.is_allowed(match):
                return match
    return None


def _is_ancestor(path: Path, files: list[Path]) -> bool:
    return any(state.inside(f, path) for f in files)


def _safe_glob(pattern: str, receiving: bool) -> bool:
    """A Grep glob is safe only if it is `*.ext` or `**/*.ext` of an extension that is not data
    there. Braces, negations and wildcards inside the extension (`*.{py,csv}`, `!*.py`, `*.c?v`) are not."""
    match = SIMPLE_GLOB.match(pattern.strip())
    closed = state.DATA_EXTENSIONS if receiving else state.TABULAR_EXTENSIONS
    return bool(match) and match.group(1).lower() not in closed


def _readable_plan(tool_input: dict[str, Any]) -> str:
    """The resolved plan with the profile's names. First, in full, what goes out as-is; then the
    rest summarized. If it does not fit, the caller must deny."""
    plan = tool_input.get("plan") or {}
    profile = state.read_profile(Path(str(tool_input.get("path", ""))).expanduser())
    if not isinstance(plan, dict) or profile is None:
        return "Plan without a previous profile: apply will reject it."
    shown, rest = [], {}
    for table in profile.get("tables", []):
        alias, requested = table["alias"], plan.get(table["alias"])
        if requested == "omit" or (table.get("hidden") and requested is None):
            rest["omitted table"] = rest.get("omitted table", 0) + 1
            continue
        requested = requested if isinstance(requested, dict) else {}
        for column in table["columns"]:
            action = requested.get(column["alias"], column["suggested_action"])
            action = "drop" if action == "review" else action
            if action in ("keep", "generalize"):
                shown.append(f"{alias}.{column['alias']} {column.get('name', '(hidden name)')} [{column['category']}] "
                             f"→ {'GOES OUT AS-IS' if action == 'keep' else 'as ranges'}")
            else:
                rest[action] = rest.get(action, 0) + 1
    others = ", ".join(f"{n} {a}" for a, n in sorted(rest.items()))
    return ("This is what Claude will see: " + ("; ".join(shown) or "no column as-is")
            + f". Also: {others or 'nothing'}. Output in {state.output_dir()}.")


def pre(event: dict[str, Any]) -> None:
    name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    if state.session_locked(str(event.get("session_id", ""))):
        _deny("this session was locked because an output carried data from an original. "
              "Check ~/.anonimizador/alerts.log and start a new session.")
    cwd = Path(event.get("cwd") or os.getcwd())
    if problems := project_problems(cwd):
        # The project may have changed variables, keys or the sandbox: no tool can be trusted
        _deny("; ".join(problems) + ". Remove it from the project settings or use managed settings.")
    if name.startswith(OWN_TOOLS):
        if name.endswith("__apply"):
            dialog = _readable_plan(tool_input)
            if len(dialog) > MAX_DIALOG:
                _deny("the plan keeps too many columns to review in the dialog; split it or drop more.")
            _exit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                          "permissionDecisionReason": f"{PREFIX} {dialog}"}})
        # profile only returns a profile validated by the engine
        _exit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                      "permissionDecisionReason": f"{PREFIX} tool without values"}})
    if name in NO_FILES:
        _exit()

    deadline = time.monotonic() + GLOB_BUDGET
    files, roots = state.protected()
    code = [str(c) for c in state.plugin_code()]

    def touches_code(text: str) -> bool:
        return any(state.path_key(c) in state.path_key(text) for c in code)

    if name.startswith("mcp__") and OPAQUE_MCP.search(name.rsplit("__", 1)[-1]) \
            and name not in state.trusted_mcp_tools():
        _deny("that tool runs code, queries or searches file contents, and could open a data file without "
              'naming it. If you trust it, add it to ~/.anonimizador/config.json under "trusted_mcp_tools".')
    # Built-in writers by their target; third-party MCP tools (write_file, move_file…) by any argument
    targets = ([str(tool_input.get(WRITERS[name][0], ""))] if name in WRITERS
               else list(_strings(tool_input)) if name.startswith("mcp__") else [])
    for text in targets:
        target = _resolve(text, cwd)
        if target is not None and CLAUDE_CONFIG.search(target.as_posix()):
            _deny("Claude does not edit Claude Code settings, hooks, skills or MCP servers from a session: "
                  "they run outside the plugin's protection. Edit that file yourself.")

    try:
        if name in SHELL:
            _shell(str(tool_input.get("command", "")), cwd, files, roots, code, deadline)
            _exit()
        texts = ([str(tool_input.get(f, "")) for f in WRITERS[name]] if name in WRITERS
                 else list(_strings(tool_input)))
        if name not in READERS and any(touches_code(t) for t in texts):
            _deny("the plugin's code is not modified from a session.")
        for text in texts:
            if touches_protected(text, cwd, files, roots, deadline):
                _deny("that path is a protected original or is inside a protected folder.")
        # Glob only returns names; Write creates new files
        if name != "Glob":
            for text in texts:
                if closed_data_file(text, cwd, deadline) is not None:
                    _deny(f"Claude does not read data files outside {state.output_dir()}.")
    except SlowGlob:
        _deny("the wildcard walks too many folders to check in time; use a concrete path.")

    if name in {"Grep", "Glob"}:
        base = _resolve(tool_input.get("path") or str(cwd), cwd) or cwd
        if _is_ancestor(base, files):
            _deny("the search would walk a folder that holds a protected original; narrow the path.")
        if name == "Grep" and any(state.inside(base, folder) for folder in state.allowed_dirs()) \
                and state.has_escaping_links(base):
            _deny("that folder has a hard link or an outgoing symlink, which could be an original under another name.")
        if name == "Grep" and not state.is_allowed(base):
            pattern, file_type = str(tool_input.get("glob") or ""), str(tool_input.get("type") or "")
            receiving = state.in_receiving_folder(base)
            safe_types = SAFE_TYPES if receiving else SAFE_TYPES | {"json", "yaml", "xml"}
            if file_type and file_type.lower() not in safe_types:
                _deny(f"the type '{file_type}' may include data files; use a glob such as '*.py'.")
            if pattern and not _safe_glob(pattern, receiving):
                _deny("that glob could include data files; use a simple one such as '*.py' or '**/*.rb'.")
            if not pattern and not file_type:
                if not state.inside(base, cwd.resolve()):
                    _deny("a search outside the project without a 'glob' would read data files; add a glob.")
                # Inside the project: the same search, without opening data files
                _exit({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": f"{PREFIX} search without data files",
                    "updatedInput": {**tool_input, "glob": EXCLUDE_DATA if receiving else EXCLUDE_TABULAR},
                }})
    _exit()


def _shell(command: str, cwd: Path, files: list[Path], roots: list[Path], code: list[str], deadline: float) -> None:
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root and command.strip() in (f'"{root}/scripts/run.sh" config', f'"{root}/scripts/run.sh" config managed'):
        return  # the only command /anonimizador:setup needs before there is a sandbox
    parts = [p for p in SEPARATORS.split(command) if p.strip()]
    texts = [p for p in parts if not NO_READ.match(p)]
    if not texts:
        return
    if KEYCHAIN.search(command):
        _deny("the Anonymizer key does not leave the Keychain.")
    if any(state.path_key(c) in state.path_key(command) for c in code):
        _deny("the plugin's code is not modified from a session.")
    if problems := sandbox_problems(cwd):
        _deny("Bash is closed because " + "; ".join(problems) + ".")
    if files and INDEXERS.search(command):
        _deny("Spotlight and Quick Look read the indexed content of the originals.")
    # Extra layer (the sandbox is the main one): literal paths, following the command's cd
    directory = cwd
    for text in texts:
        if HARD_LINK.match(text) and not re.search(r"\s(-[a-zA-Z]*s[a-zA-Z]*|--symbolic)(\s|$)", text):
            _deny("a hard link would let an original pass as a copy; use symbolic links (ln -s).")
        if MOVES.match(text) and _names_output_dir(text, directory):
            _deny(f"{state.output_dir()} is not moved, deleted or replaced from a session.")
        if CHANGE_DIR.match(text):
            simple = SIMPLE_CHANGE_DIR.match(_with_variables(text))
            if not simple:
                _deny("I cannot follow that change of folder; use full paths.")
            directory = _resolve(simple.group(1).strip("'\""), directory) or directory
            continue
        if touches_protected(text, directory, files, roots, deadline):
            _deny("that path is a protected original or is inside a protected folder.")
        if closed_data_file(text, directory, deadline) is not None:
            _deny(f"Claude does not read data files outside {state.output_dir()}.")


def _with_variables(text: str) -> str:
    """`cd "$TMPDIR"`, `cd ~/x`: expands simple variables; anything else ($(...), wildcards) stays as
    it is and is denied. The sandbox is Bash's real protection: this only follows paths for the
    extra layer. An empty variable, or one that does not exist here (on Linux TMPDIR often does
    not), cannot be followed: the folder becomes unknown, and whatever is named from there is still
    checked."""
    expanded = re.sub(r"\$\{?(\w+)\}?", lambda m: os.environ.get(m.group(1)) or UNKNOWN_DIR, text.replace('"', ""))
    return os.path.expanduser(expanded)


def _names_output_dir(text: str, directory: Path) -> bool:
    """Does the command point at the output folder itself (not at a file inside it)?"""
    output = state.output_dir()
    for token in _tokens(text)[1:-1]:
        path = _resolve(token.rstrip("/"), directory)
        if path is not None and (state.path_key(path) == state.path_key(output) or state.inside(output, path)):
            return True
    return False


def _blank(value: Any) -> Any:
    """The same output shape without a single piece of text: it does not say which part matched."""
    if isinstance(value, str):
        return "[BLOCKED BY ANONYMIZER]"
    if isinstance(value, list):
        return [_blank(v) for v in value]
    if isinstance(value, dict):
        return {k: _blank(v) for k, v in value.items()}
    return value


def post(event: dict[str, Any]) -> None:
    if event.get("tool_name", "").startswith(OWN_TOOLS):
        _exit()
    session = str(event.get("session_id", ""))
    response = event.get("tool_response")
    # Once tripped, every output of the session is blanked: otherwise parallel calls would tell
    # which one matched and which one did not
    if not state.session_locked(session):
        if not state.has_indices():
            _exit()
        index = state.global_index()
        if not any(index.matches(t, strong=True) for t in _strings(response)):
            _exit()
        state.lock_session(session)
    _log(f"tripwire {event.get('tool_name')}: output with data from an original; session locked")
    _exit({
        "systemMessage": f"{PREFIX} an output carried data from a protected original. It was blocked whole "
                         "and this session will use no more tools. Check ~/.anonimizador/alerts.log.",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": _blank(response),
            "additionalContext": "This output was blocked by the Anonymizer and the session is locked.",
        },
    })


def _block_prompt(reason: str) -> None:
    _exit({
        "decision": "block",
        "reason": f"{PREFIX} {reason}",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    })


def personal_data_count(text: str) -> int:
    """How many distinct emails, mobile numbers or cards a text carries. National IDs do not count
    here: in a message they are confused with amounts and dates ("1500000", "20261026")."""
    seen = set()
    for fragment in FRAGMENT.findall(text):
        f = fragment.strip()
        if "@" in f or is_colombian_phone(f) or is_valid_luhn(f):
            seen.add(re.sub(r"[\s.\-]", "", f.lower()))
    return len(seen)


def prompt(event: dict[str, Any]) -> None:
    text = event.get("prompt") or ""
    cwd = Path(event.get("cwd") or os.getcwd())
    files, roots = state.protected()
    deadline = time.monotonic() + GLOB_BUDGET
    for mention in re.findall(r"@(\"[^\"]+\"|\S+)", text):
        mention = mention.strip('"')
        try:
            closed = touches_protected(mention, cwd, files, roots, deadline) \
                or closed_data_file(mention, cwd, deadline) is not None
        except SlowGlob:
            closed = True
        if closed:
            _block_prompt("that @file is a data file that is not anonymized. Ask for /anonimizador:anonymize "
                          "and mention the copy in ~/anonimizados.")
    if state.has_indices() and state.global_index().matches(text, strong=True):
        _log("prompt blocked: it contained values from an original")
        _block_prompt("the message contains data from a protected original; it was not sent to Claude.")
    if personal_data_count(text) >= MIN_PASTED_DATA:
        _log("prompt blocked: pasted personal data")
        _block_prompt("the message carries several emails, mobile numbers or cards; it was not sent to Claude. "
                      "Save them to a file in ~/sensibles and use /anonimizador:anonymize.")
    _exit()


def end(event: dict[str, Any]) -> None:
    path = event.get("transcript_path")
    if not path or not state.has_indices() or not Path(path).is_file():
        _exit()
    n = len(state.global_index().matches(Path(path).read_text(errors="replace"), strong=True))
    if n:
        _log(f"audit {Path(path).name}: {n} matches")
        print(f"{PREFIX} this session's transcript holds {n} values from protected originals. "
              f"Check {state.home() / 'alerts.log'} and consider `claude purge`.", file=sys.stderr)
    _exit()


def _log(line: str) -> None:
    try:
        with (state.home() / "alerts.log").open("a") as handle:
            handle.write(f"{datetime.now().isoformat(timespec='seconds')} {line}\n")
    except OSError:
        pass


EVENTS = {"pre": pre, "post": post, "prompt": prompt, "end": end}


def main() -> None:
    event_name = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        event = json.load(sys.stdin)
        EVENTS[event_name](event)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001
        # If the guard fails, it blocks: a stopped tool or message beats a leak.
        if event_name == "pre":
            _deny(f"the guard failed ({type(error).__name__}); blocked as a precaution.")
        if event_name == "prompt":
            _block_prompt(f"the guard failed ({type(error).__name__}); the message was not sent.")
        print(f"anonymizer: hook {event_name} failed ({type(error).__name__})", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
