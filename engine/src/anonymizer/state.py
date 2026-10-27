"""Local state: protected originals, fingerprint indices and the profiles already shown.

Lives in ~/.anonimizador (or $ANONYMIZER_HOME). It only stores paths, HMAC fingerprints and
validated profiles: without the Keychain key a fingerprint reveals nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from . import key
from .env import variable
from .fingerprints import Fingerprinter, Index

# Folder names kept from v0.1: they are already in the user's sandbox settings.
DEFAULT_ROOTS = ("~/sensibles",)
DEFAULT_OUTPUT = "~/anonimizados"
DEFAULT_HOME = "~/.anonimizador"

# Tabular files, databases and statistical formats: closed everywhere on disk
TABULAR_EXTENSIONS = (
    "csv", "tsv", "xlsx", "xlsm", "xlsb", "xls", "ods", "numbers", "sql", "dump",
    "sqlite", "sqlite3", "db", "parquet", "feather", "sav", "zsav", "por", "dta", "dbf", "mdb", "accdb",
    "jsonl", "ndjson", "sas7bdat", "xpt", "rds", "rdata", "avro", "orc",
)
# Archives, ML binaries and JSON/YAML/XML: exports usually arrive like this in Downloads, but inside
# a project they are dependencies, models or configuration. Closed only where files are received.
RECEIVED_EXTENSIONS = (
    "zip", "gz", "tgz", "tar", "7z", "rar", "bz2", "xz", "zst",
    "pkl", "pickle", "h5", "hdf5", "arrow", "npz", "npy",
    "json", "yaml", "yml", "xml",
)
DATA_EXTENSIONS = TABULAR_EXTENSIONS + RECEIVED_EXTENSIONS
# Documents and Desktop are left out on purpose: projects live there (Yarn, ML models, fixtures)
RECEIVING_FOLDERS = (
    "~/Downloads", "~/Library/CloudStorage", "~/Dropbox", "~/Library/Mobile Documents",
    "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads", "/Volumes",
)
# APFS and HFS+ are case-insensitive: /x/DATA.CSV is the same file as /x/data.csv
CASE_INSENSITIVE = sys.platform == "darwin"
NO_SESSION = "no-session"  # without an id we cannot tell what to lock, so everything is locked


def path_key(path: Path | str) -> str:
    text = os.path.normpath(str(path))
    return text.casefold() if CASE_INSENSITIVE else text


def inside(path: Path, root: Path) -> bool:
    candidate, base = path_key(path), path_key(root)
    return candidate == base or candidate.startswith(base.rstrip(os.sep) + os.sep)


def home() -> Path:
    return Path(variable("ANONYMIZER_HOME") or DEFAULT_HOME).expanduser()


def _output_expanded() -> Path:
    return Path(variable("ANONYMIZER_OUTPUT") or DEFAULT_OUTPUT).expanduser()


def output_dir() -> Path:
    """The folder of anonymized copies: the only place with data files Claude may read."""
    return _output_expanded().resolve()


def output_dir_is_safe() -> bool:
    """The output folder cannot be (or hang from) a symlink: if ~/anonimizados pointed at
    ~/Downloads, all of Downloads would pass as "anonymized copy"."""
    expanded = Path(os.path.abspath(_output_expanded()))
    current = expanded
    while current != current.parent:
        if current.is_symlink():
            return False
        current = current.parent
    try:
        return not expanded.exists() or expanded.stat().st_uid == os.getuid()
    except OSError:
        return False


def _config() -> dict:
    try:
        config = json.loads((home() / "config.json").read_text())
        return config if isinstance(config, dict) else {}
    except (OSError, ValueError):
        return {}


def allowed_dirs() -> list[Path]:
    """Folders where Claude may read data files: the output folder plus the ones the user adds
    to config.json ("allowed_dirs": ["~/project/fixtures"]) at their own risk."""
    extra = _config().get("allowed_dirs", [])
    return ([output_dir()] if output_dir_is_safe() else []) + [Path(p).expanduser().resolve() for p in extra]


def trusted_mcp_tools() -> set[str]:
    """Third-party MCP tools the user declared trustworthy even though they run code."""
    return set(_config().get("trusted_mcp_tools", []))


def is_data_file(path: Path | str) -> bool:
    return Path(str(path)).suffix.lower().lstrip(".") in DATA_EXTENSIONS


def in_receiving_folder(path: Path) -> bool:
    """Is it in a folder where files are received (Downloads, Drive, iCloud, Mail, external disks)?"""
    return any(inside(path, Path(folder).expanduser().resolve()) for folder in RECEIVING_FOLDERS)


def closed_by_extension(path: Path) -> bool:
    """Tabular files anywhere; archives, ML binaries and JSON/YAML only in receiving folders."""
    extension = path.suffix.lower().lstrip(".")
    if extension in TABULAR_EXTENSIONS:
        return True
    return extension in RECEIVED_EXTENSIONS and in_receiving_folder(path)


def is_allowed(path: Path) -> bool:
    if not any(inside(path, folder) for folder in allowed_dirs()):
        return False
    # A hard link to an original inside ~/anonimizados would still be the original
    try:
        return path.stat().st_nlink <= 1 if path.is_file() else True
    except OSError:
        return True


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _registry() -> Path:
    return home() / "protected.json"


def _read_registry() -> dict:
    try:
        return json.loads(_registry().read_text())
    except (OSError, ValueError):
        return {"files": [], "roots": list(DEFAULT_ROOTS)}


def protect(path: Path) -> None:
    registry = _read_registry()
    real = str(path.expanduser().resolve())
    if real not in registry["files"]:
        registry["files"].append(real)
        _private_dir(home())
        _write_private(_registry(), json.dumps(registry, ensure_ascii=False, indent=2))


def forget(original: Path) -> None:
    """Remove an original from the registry, with its index and profile (used by the attack suite)."""
    registry = _read_registry()
    real = str(original.expanduser().resolve())
    if real in registry.get("files", []):
        registry["files"].remove(real)
        _write_private(_registry(), json.dumps(registry, ensure_ascii=False, indent=2))
    for path in (home() / "indices" / f"{_id(original)}.fp", home() / "profiles" / f"{_id(original)}.json"):
        path.unlink(missing_ok=True)


def plugin_code() -> list[Path]:
    """The plugin's code and environment: nobody, Claude included, may edit them during a session."""
    paths = [Path(__file__).resolve().parents[2]]  # engine/
    for name in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"):
        if value := os.environ.get(name):
            paths.append(Path(value).expanduser().resolve())
    return paths


def protected() -> tuple[list[Path], list[Path]]:
    """(files, roots), resolved. Always includes the state folder itself."""
    registry = _read_registry()
    roots = [Path(r).expanduser().resolve() for r in registry.get("roots", DEFAULT_ROOTS)]
    roots.append(home().resolve())
    return [Path(f) for f in registry.get("files", [])], roots


def _id(original: Path) -> str:
    return hashlib.sha256(path_key(original.expanduser().resolve()).encode()).hexdigest()[:24]


def fingerprinter() -> Fingerprinter:
    return Fingerprinter(key.get_or_create())


def save_index(original: Path, index: Index) -> None:
    index.save(_private_dir(home() / "indices") / f"{_id(original)}.fp")


def save_profile(original: Path, profile: str, digest: str) -> None:
    """The validated (value-free) profile the model saw: the approval dialog uses it. The digest of
    the file it describes keeps the dialog and the copy about the same content."""
    folder = _private_dir(home() / "profiles")
    _write_private(folder / f"{_id(original)}.json", profile)
    _write_private(folder / f"{_id(original)}.sha256", digest)


def profile_digest(original: Path) -> str | None:
    try:
        return (home() / "profiles" / f"{_id(original)}.sha256").read_text().strip()
    except OSError:
        return None


def read_profile(original: Path) -> dict | None:
    try:
        return json.loads((home() / "profiles" / f"{_id(original)}.json").read_text())
    except (OSError, ValueError):
        return None


def global_index() -> Index:
    """Every fingerprint of every protected original, for hooks and audits."""
    total = Index(fingerprinter())
    folder = home() / "indices"
    if folder.is_dir():
        for path in folder.glob("*.fp"):
            total.fingerprints |= Index.load(path, total.fingerprinter).fingerprints
    return total


def has_indices() -> bool:
    folder = home() / "indices"
    return folder.is_dir() and any(folder.glob("*.fp"))


def _lock(session: str) -> Path:
    digest = hashlib.sha256((session or NO_SESSION).encode()).hexdigest()[:24]
    return _private_dir(home() / "locks") / digest


def lock_session(session: str) -> None:
    """Tripwire: once an output carried data from an original, the session uses no more tools."""
    _lock(session).touch()


def session_locked(session: str) -> bool:
    return _lock(session).exists() or _lock(NO_SESSION).exists()


def has_escaping_links(folder: Path, limit: int = 5000) -> bool:
    """Is there a hard link in the folder, or a symlink that leaves it? Either one would let an
    original pass as a copy."""
    base = folder.resolve()
    try:
        for i, (root, dirs, files) in enumerate(os.walk(folder)):
            for name in files + dirs:
                path = Path(root) / name
                if path.is_symlink():
                    if not inside(path.resolve(), base):
                        return True
                elif path.is_file() and path.stat().st_nlink > 1:
                    return True
            if i > limit:
                return True
    except OSError:
        return True
    return False
