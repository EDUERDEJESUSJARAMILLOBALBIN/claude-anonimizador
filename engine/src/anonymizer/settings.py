"""The settings.json block that `run.sh install` merges into the user's settings, and the check
that it is in place and nobody weakens it.

A plugin cannot declare permissions or a sandbox, so they are generated here and the user approves
them. Tested on Claude Code 2.1.311 (macOS, Seatbelt): an `allowRead` exception only beats a
wildcard `denyRead` if it is also written with a per-extension wildcard.

Trust model: the user's settings protect against the model's mistakes. Against a malicious
repository that disables the plugin from its own settings, no plugin can defend itself: that takes
managed settings (see `managed_block`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .state import DEFAULT_HOME, DEFAULT_OUTPUT, DEFAULT_ROOTS, RECEIVED_EXTENSIONS, RECEIVING_FOLDERS
from .state import TABULAR_EXTENSIONS, path_key

# Every place a user leaves files: their home, external disks and the system's temporary folders
VOLUMES = ("~", "/Volumes", "/tmp", "/private/tmp", "/private/var/folders")
MARKERS = ("~/**/*.csv", DEFAULT_ROOTS[0])  # if these are present, the block was applied
PLUGIN = "anonimizador@anonimizador"


def _variants(extension: str) -> tuple[str, ...]:
    # Seatbelt matches paths case-sensitively: export.CSV does not match *.csv
    return tuple(dict.fromkeys((extension, extension.upper(), extension.capitalize())))


def extensions(names: tuple[str, ...]) -> list[str]:
    return [variant for name in names for variant in _variants(name)]


def block() -> dict:
    # Tabular files everywhere; archives and ML binaries only where files are received, so that
    # dependencies (.tar.gz, Yarn or Go .zip) and models inside projects keep working
    deny_read = [f"{v}/**/*.{e}" for v in VOLUMES for e in extensions(TABULAR_EXTENSIONS)]
    deny_read += [f"{f}/**/*.{e}" for f in RECEIVING_FOLDERS for e in extensions(RECEIVED_EXTENSIONS)]
    every = extensions(TABULAR_EXTENSIONS + RECEIVED_EXTENSIONS)
    allow_read = [f"{DEFAULT_OUTPUT}/{p}.{e}" for e in every for p in ("*", "**/*")]
    return {
        "permissions": {
            "deny": [f"Read({DEFAULT_ROOTS[0]}/**)", f"Edit({DEFAULT_ROOTS[0]}/**)", f"Read({DEFAULT_HOME}/**)"],
            "disableBypassPermissionsMode": "disable",
        },
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {
                "denyRead": [DEFAULT_ROOTS[0], DEFAULT_HOME, *deny_read],
                "allowRead": allow_read,
            },
        },
    }


def managed_block() -> dict:
    """For teams: in managed-settings.json neither a repository nor the user can loosen it."""
    managed = block()
    managed["allowManagedHooksOnly"] = True
    managed["enabledPlugins"] = {PLUGIN: True}
    return managed


def _user_sources() -> list[Path]:
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude").expanduser()
    return [
        Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
        Path("/etc/claude-code/managed-settings.json"),
        base / "settings.json",
        base / "settings.local.json",  # the /sandbox panel writes it when used from the home folder
    ]


def _project_sources(cwd: Path) -> list[Path]:
    """Project settings Claude Code applies on top of the user's. The home folder is not a
    project: ~/.claude/settings.json are the user's settings."""
    user = {path_key(p) for p in _user_sources()}
    paths, current, home = [], cwd.resolve(), Path.home().resolve()
    while current != home and current.parent != current:
        for name in ("settings.json", "settings.local.json"):
            path = current / ".claude" / name
            if path_key(path) not in user:
                paths.append(path)
        current = current.parent
    return paths


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# Environment variables a project cannot set without changing which code or which settings apply
_DANGEROUS_ENV = ("CLAUDE_CONFIG_DIR", "CLAUDE_PLUGIN", "ANONYMIZER_", "PYTHON", "PATH", "HOME", "DYLD_",
                  "LD_", "NODE_OPTIONS", "BASH_ENV", "ENV", "ZDOTDIR", "SHELL", "PERL5", "RUBYOPT", "TMPDIR")
# Sandbox keys a project may set: only the ones that close more
_ALLOWED_SANDBOX_KEYS = {"enabled", "failIfUnavailable", "allowUnsandboxedCommands", "filesystem", "network",
                         "autoAllowBashIfSandboxed"}  # the /sandbox panel writes it; it only changes prompting
_ALLOWED_FILESYSTEM_KEYS = {"denyRead", "denyWrite"}  # a project never opens reads, not even in ~/anonimizados


def _weakens(settings: dict) -> str | None:
    """An allowlist of what a project may touch: anything else is treated as an attempt to loosen."""
    sandbox = settings.get("sandbox", {})
    if not isinstance(sandbox, dict) or set(sandbox) - _ALLOWED_SANDBOX_KEYS:
        return "changes sandbox keys that may only be tightened from your own settings"
    filesystem = sandbox.get("filesystem", {})
    if not isinstance(filesystem, dict) or set(filesystem) - _ALLOWED_FILESYSTEM_KEYS:
        return "changes the sandbox's file access"
    if sandbox.get("enabled") is False or sandbox.get("allowUnsandboxedCommands") is True \
            or sandbox.get("failIfUnavailable") is False:
        return "turns off or loosens the sandbox"
    env = settings.get("env") or {}
    if not isinstance(env, dict) or any(str(k).startswith(_DANGEROUS_ENV) for k in env):
        return "sets environment variables that change the plugin or the settings"
    permissions = settings.get("permissions") or {}
    if isinstance(permissions, dict) and (permissions.get("additionalDirectories")
                                          or permissions.get("defaultMode") == "bypassPermissions"):
        return "adds directories or bypasses permissions"
    plugins = settings.get("enabledPlugins")
    if settings.get("disableAllHooks") is True or (isinstance(plugins, dict) and plugins.get(PLUGIN) is False):
        return "turns off the hooks or the plugin"
    return None


def project_problems(cwd: Path) -> list[str]:
    """Project settings that loosen the sandbox or the plugin. With any of them no tool can be
    trusted: the project may have changed variables, keys or the sandbox itself."""
    problems = []
    for source in _project_sources(cwd):
        settings = _read(source)
        if settings and (reason := _weakens(settings)):
            problems.append(f"the project settings ({source}) {reason}")
    return problems


def sandbox_problems(cwd: Path) -> list[str]:
    """Why Bash is not protected by the operating system; empty if it is."""
    enabled = no_escape = closes_data = False
    excluded: list[str] = []
    for source in _user_sources():
        sandbox = _read(source).get("sandbox") or {}
        if not isinstance(sandbox, dict):
            continue
        enabled |= sandbox.get("enabled") is True
        no_escape |= sandbox.get("allowUnsandboxedCommands") is False
        deny_read = (sandbox.get("filesystem") or {}).get("denyRead") or []
        closes_data |= all(marker in deny_read for marker in MARKERS)
        excluded += sandbox.get("excludedCommands") or []
    problems = []
    if not (enabled and no_escape and closes_data):
        problems.append("the sandbox is not configured (run /anonimizador:setup and restart)")
    problems += project_problems(cwd)
    if excluded:
        problems.append("sandbox.excludedCommands runs commands without the sandbox; remove them or use managed settings")
    return problems


def _user_settings() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude").expanduser() / "settings.json"


def _merge(target: dict, source: dict) -> int:
    """Add source to target without deleting anything: lists without duplicates, objects recursively,
    plain values replaced. Returns how many new rules were added."""
    added = 0
    for key, value in source.items():
        if isinstance(value, dict):
            added += _merge(target.setdefault(key, {}), value)
        elif isinstance(value, list):
            current = target.setdefault(key, [])
            missing = [v for v in value if v not in current]
            current.extend(missing)
            added += len(missing)
        elif target.get(key) != value:
            target[key] = value
            added += 1
    return added


def _unmerge(target: dict, source: dict) -> int:
    removed = 0
    for key, value in source.items():
        if key not in target:
            continue
        if isinstance(value, dict) and isinstance(target[key], dict):
            removed += _unmerge(target[key], value)
            if not target[key]:
                del target[key]
        elif isinstance(value, list) and isinstance(target[key], list):
            before = len(target[key])
            target[key] = [v for v in target[key] if v not in value]
            removed += before - len(target[key])
            if not target[key]:
                del target[key]
        elif target[key] == value:
            del target[key]
            removed += 1
    return removed


def _save(path: Path, settings: dict) -> Path:
    """A dated backup and an atomic write that keeps the file's permissions."""
    import shutil
    import tempfile
    from datetime import datetime

    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(f"{path.name}.before-anonymizer-{datetime.now():%Y%m%d-%H%M%S}")
    if path.exists():
        shutil.copy2(path, backup)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".settings-")
    with os.fdopen(descriptor, "w") as handle:
        json.dump(settings, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    if path.exists():
        os.chmod(temporary, path.stat().st_mode & 0o777)
    os.replace(temporary, path)
    return backup


def install() -> str:
    path = _user_settings()
    settings = _read(path) if path.exists() else {}
    if path.exists() and not settings and path.read_text().strip():
        raise SystemExit(f"{path} is not valid JSON; fix it before installing. Nothing was changed.")
    added = _merge(settings, block())
    for folder in (DEFAULT_ROOTS[0], DEFAULT_OUTPUT, DEFAULT_HOME):
        Path(folder).expanduser().mkdir(mode=0o700, exist_ok=True)
    if not added:
        return "Already installed: nothing changed."
    backup = _save(path, settings)
    return (f"Done: {added} rules added to {path} (backup in {backup.name}). Folders {DEFAULT_ROOTS[0]} and "
            f"{DEFAULT_OUTPUT} are ready. Restart Claude Code and confirm with /sandbox.")


def uninstall() -> str:
    path = _user_settings()
    settings = _read(path)
    removed = _unmerge(settings, block())
    if not removed:
        return "There were no Anonymizer rules: nothing changed."
    backup = _save(path, settings)
    return f"Removed {removed} rules from {path} (backup in {backup.name}). Restart Claude Code."


def allow(folder: str) -> str:
    """Open a folder without personal data (e.g. a project with test CSVs) in the sandbox and the guard."""
    path = Path(folder).expanduser().resolve()
    home = Path.home().resolve()
    if not path.is_dir():
        raise SystemExit(f"{path} is not a folder.")
    too_broad = {home, Path("/"), Path(DEFAULT_ROOTS[0]).expanduser().resolve(),
                 *(Path(f).expanduser().resolve() for f in RECEIVING_FOLDERS)}
    if path in too_broad:
        raise SystemExit(f"{path} is too broad or is where originals arrive; choose the project folder.")
    pattern = "~/" + str(path.relative_to(home)) if path.is_relative_to(home) else str(path)
    every = extensions(TABULAR_EXTENSIONS + RECEIVED_EXTENSIONS)
    settings_path = _user_settings()
    settings = _read(settings_path)
    added = _merge(settings, {"sandbox": {"filesystem": {"allowRead": [f"{pattern}/{p}.{e}" for e in every
                                                                       for p in ("*", "**/*")]}}})
    config_path = Path(DEFAULT_HOME).expanduser() / "config.json"
    config = _read(config_path)
    if str(path) not in config.setdefault("allowed_dirs", []):
        config["allowed_dirs"].append(str(path))
        config_path.parent.mkdir(mode=0o700, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False))
        os.chmod(config_path, 0o600)
    if added:
        _save(settings_path, settings)
    return f"Claude can now read data files in {path}. Do this only if there is no personal data there."


def main() -> None:
    import sys

    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "managed":
        print(json.dumps(managed_block(), indent=2, ensure_ascii=False))
    elif command == "install":
        print(install())
    elif command == "uninstall":
        print(uninstall())
    elif command == "allow" and len(sys.argv) > 2:
        print(allow(sys.argv[2]))
    else:
        print(json.dumps(block(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
