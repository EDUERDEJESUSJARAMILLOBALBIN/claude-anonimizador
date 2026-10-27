#!/bin/sh
# Entry point for the hooks and the MCP server.
#   run.sh mcp        MCP server (with its virtualenv in CLAUDE_PLUGIN_DATA)
#   run.sh prepare    create or update the virtualenv (SessionStart)
#   run.sh config     settings.json block (or "config managed" for managed settings)
#   run.sh install | uninstall | allow <folder>   run by the user with `!`, never by Claude
#   run.sh pre|post|prompt|end   hooks (standard library only)
set -eu
ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
DATA="${CLAUDE_PLUGIN_DATA:-$HOME/.anonimizador/plugin}"
VENV="$DATA/venv"
REQUIREMENTS="$ROOT/engine/requirements.txt"

# Nothing from the open project or the environment can change which code the guard runs: no
# inherited Python variables, no user site, and the working directory is the plugin's own code
# (python -m looks there first, not in the user's repository).
unset PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONUSERBASE PYTHONEXECUTABLE \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH LD_PRELOAD LD_LIBRARY_PATH
export PYTHONPATH="$ROOT/engine/src" PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 PYTHONDONTWRITEBYTECODE=1
# Marks "inside Claude Code" for hooks and the MCP server alike: ANONYMIZER_* variables are ignored
export CLAUDE_PLUGIN_ROOT="$ROOT"

block() {
  # If the guard cannot run, it blocks (exit code 2): never let a call through unchecked
  echo "Anonymizer: $1; blocked as a precaution. Check the plugin installation." >&2
  exit 2
}

guard_python() {
  if [ -x "$VENV/bin/python" ]; then echo "$VENV/bin/python"; return; fi
  command -v python3 || true
}

prepare() {
  if [ -x "$VENV/bin/python" ] && cmp -s "$REQUIREMENTS" "$VENV/requirements.txt"; then return 0; fi
  mkdir -p "$DATA"
  # One installer at a time; a lock older than 10 minutes was left by a dead install
  find "$DATA" -maxdepth 1 -name .installing -mmin +10 -exec rmdir {} \; 2>/dev/null || true
  while ! mkdir "$DATA/.installing" 2>/dev/null; do sleep 1; done
  trap 'rmdir "$DATA/.installing" 2>/dev/null || true' EXIT
  if ! { [ -x "$VENV/bin/python" ] && cmp -s "$REQUIREMENTS" "$VENV/requirements.txt"; }; then
    python3 -m venv "$VENV" >&2
    "$VENV/bin/pip" install -q --disable-pip-version-check --require-hashes --only-binary=:all: -r "$REQUIREMENTS" >&2
    cp "$REQUIREMENTS" "$VENV/requirements.txt"
  fi
}

cd "$ROOT/engine/src"
case "${1:-}" in
  mcp) prepare; exec "$VENV/bin/python" -m anonymizer.mcp ;;
  prepare) prepare ;;
  config) exec "$(guard_python)" -m anonymizer.settings "${2:-}" ;;
  install|uninstall) exec "$(guard_python)" -m anonymizer.settings "$1" ;;
  allow) exec "$(guard_python)" -m anonymizer.settings allow "${2:?usage: run.sh allow <folder>}" ;;
  pre|prompt)
    PY="$(guard_python)"
    [ -n "$PY" ] || block "python3 was not found"
    exec "$PY" -m anonymizer.guard "$1" ;;
  post|end)
    PY="$(guard_python)"
    [ -n "$PY" ] || exit 0
    exec "$PY" -m anonymizer.guard "$1" ;;
  *) echo "usage: run.sh mcp|prepare|config|install|uninstall|allow|pre|post|prompt|end" >&2; exit 2 ;;
esac
