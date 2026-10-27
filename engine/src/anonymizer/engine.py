"""Engine operations: profile a file, apply a plan and verify the output.

Everything this module returns is fit for the model: profiles validated against the contract and
summaries with counts and aliases. The values stay here.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import zipfile
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any

from . import state
from .adapters import Reading, Table, read, write
from .detect import Action, Category, Classification, classify, is_known_header
from .fingerprints import Index, normalize
from .profile import Column, build, count, validate

# Direct identifiers and strong quasi-identifiers: they never leave as-is, even if the plan asks
NEVER_KEEP = {
    Category.DOCUMENT, Category.EMAIL, Category.PHONE, Category.NAME, Category.CARD,
    Category.BANK_ACCOUNT, Category.IP, Category.PLATE, Category.ADDRESS, Category.BIRTH_DATE,
}
_OUTPUT_SUFFIX = {".csv": ".csv", ".tsv": ".tsv", ".xlsx": ".xlsx", ".xlsm": ".xlsx", ".json": ".json",
                  ".jsonl": ".jsonl", ".ndjson": ".ndjson", ".yaml": ".yaml", ".yml": ".yml"}
OMIT = "omit"
WHOLE_TABLE = "*"


class InvalidPlan(ValueError):
    """A safe message for the model: only aliases and action names."""


@dataclass
class _Table:
    alias: str
    table: Table
    safe_name: str | None
    columns: list[Column]


@dataclass
class _Analysis:
    reading: Reading
    tables: list[_Table]
    everything: Index  # fingerprints of every value in the original
    strict: bool = False

    def shows(self, name: str | None) -> bool:
        """Allowlist: only headers made of known vocabulary. In a file without a header row the
        first row is data ("Ana Ruiz", "Calle 5"), and it stays here."""
        return not self.strict and bool(name) and is_known_header(name) and not self.everything.matches(name)


def _analyze(path: Path, strict: bool) -> _Analysis:
    state.protect(path)  # from now on the hooks block any other way of reading it
    reading = read(path)
    everything = Index(state.fingerprinter())
    everything.add(reading.loose)
    for table in reading.tables:
        for row in table.rows:
            everything.add(row)

    analysis = _Analysis(reading, [], everything, strict)

    def safe(name: str | None, path: tuple = ()) -> str | None:
        # JSON and YAML: every key of the path on its own, the same rule the copy's keys follow
        # (`pacientes.1985-03-12.ciudad` reads as known words and short numbers when joined)
        keys = [key for key in path if key != "[]"]
        return name if analysis.shows(name) and all(analysis.shows(key) for key in keys) else None

    def classification(table: Table, index: int) -> Classification:
        found = classify(_column_key(table, index), table.values(index))
        if getattr(table, "has_containers", lambda _: False)(index):
            return replace(found, category=Category.UNCLASSIFIED)  # never kept by default
        return found

    analysis.tables = [
        _Table(
            f"t{i}",
            table,
            safe(table.name, getattr(table, "path", ())),
            [
                Column(f"c{j}", safe(name, _column_path(table, j - 1)), classification(table, j - 1))
                for j, name in enumerate(table.columns, start=1)
            ],
        )
        for i, table in enumerate(reading.tables, start=1)
    ]
    return analysis


def _sensitive_index(analysis: _Analysis, kept: set[tuple[str, str]]) -> Index:
    """Fingerprints of what must not leave: everything except the columns that are kept."""
    sensitive = Index(analysis.everything.fingerprinter)
    allowed = Index(analysis.everything.fingerprinter)
    sensitive.add(analysis.reading.loose)
    for t in analysis.tables:
        sensitive.add([t.table.name] if t.safe_name is None else [])
        # JSON and YAML: a key the copy renames may be data ("ana_ruiz", "CC1020304050")
        for path in [getattr(t.table, "path", ()), *getattr(t.table, "paths", [])]:
            sensitive.add([key for key in path if key != "[]" and not analysis.shows(key)])
        for j, column in enumerate(t.columns):
            if column.name is None:
                sensitive.add([t.table.columns[j]])
            values = t.table.values(j)
            if (t.alias, column.alias) in kept:
                # The value itself is allowed, not the emails or phone numbers written inside it
                allowed.add(values, fragments=False)
                sensitive.add(values, whole=False)
            else:
                sensitive.add(values)
    sensitive.fingerprints -= allowed.fingerprints
    return sensitive


def profile(path: Path, strict: bool = False) -> str:
    path = path.expanduser()
    analysis = _analyze(path, strict)
    result = build(
        analysis.reading.file_format,
        [(t.safe_name, len(t.table.rows), t.columns, t.table.hidden) for t in analysis.tables],
        analysis.reading.findings,
    )
    text = validate(result, analysis.everything)
    # For the hooks: what is suggested as keepable is not treated as sensitive in other outputs
    kept = {
        (t.alias, c.alias)
        for t in analysis.tables
        for c in t.columns
        if c.classification.suggested_action == Action.KEEP
    }
    state.save_index(path, _sensitive_index(analysis, kept))
    state.save_profile(path, text, _digest(path))
    return text


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:  # hashlib.file_digest needs Python 3.11
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply(path: Path, plan: dict[str, Any], output: Path | None = None, strict: bool = False) -> dict[str, Any]:
    path = path.expanduser()
    suffix = _OUTPUT_SUFFIX.get(path.suffix.lower())
    if suffix is None:
        raise InvalidPlan(f"{path.suffix or 'that format'} cannot be written yet")
    if state.read_profile(path) is None:
        # The approval dialog shows the plan with the profile's names: no profile, no plan
        raise InvalidPlan("profile the file first with the profile tool")
    if state.profile_digest(path) != _digest(path):
        raise InvalidPlan("the file changed after it was profiled; profile it again")
    analysis = _analyze(path, strict)
    destination = output or state.output_dir() / f"{_output_name(path, analysis.everything)}.anon{suffix}"
    destination = destination.expanduser().resolve()
    _check_destination(destination, path)
    if not state.is_allowed(destination):
        raise InvalidPlan(f"the output must go to {state.output_dir()} so Claude can read it")
    actions = _resolve_plan(analysis, plan)
    kept = {k for k, a in actions.items() if a == Action.KEEP}
    sensitive = _sensitive_index(analysis, kept)

    key = analysis.everything.fingerprinter.key
    summary, new_tables = [], []
    for t in analysis.tables:
        if actions.get((t.alias, WHOLE_TABLE)) == OMIT:
            continue
        counts = {a.value: 0 for a in (Action.DROP, Action.PSEUDONYMIZE, Action.GENERALIZE, Action.KEEP)}
        indices, headers = [], []
        for j, column in enumerate(t.columns):
            action = actions[(t.alias, column.alias)]
            counts[action.value] += 1
            if action != Action.DROP:
                indices.append((j, action, column.classification))
                headers.append(column.name or column.alias)
        rows = [
            [_transform(row[j] if j < len(row) else None, action, classification, key)
             for j, action, classification in indices]
            for row in t.table.rows
        ]
        new_tables.append(Table(t.safe_name or t.alias, headers, rows))
        summary.append({"alias": t.alias, "rows": count(len(rows)), **counts})

    if not new_tables:
        raise InvalidPlan("the plan omits every table")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if analysis.reading.document is not None:
        _write_structured(analysis, actions, destination, key)
    else:
        write(new_tables, destination)

    matches = verify(destination, sensitive)
    if matches:
        destination.unlink(missing_ok=True)
        raise InvalidPlan(
            f"the verification found {matches} values from the original in the output, so it was deleted. "
            "Drop or pseudonymize the free-text columns and try again."
        )
    # The fingerprints of what was dropped or pseudonymized go to the index the hooks use
    state.save_index(path, sensitive)
    result = {
        "output": str(destination),
        "tables": summary,
        "verification": {"fingerprints_checked": len(sensitive), "matches": 0},
    }
    if analysis.everything.matches(json.dumps(result, ensure_ascii=False)):
        raise InvalidPlan("the summary contains a value from the original (the file name?)")
    return result


def _column_path(table: Table, index: int) -> tuple:
    return table.paths[index] if hasattr(table, "paths") else ()


def _column_key(table: Table, index: int) -> str:
    """JSON and YAML are classified by the last field of the path (`cliente.ciudad` → `ciudad`)."""
    return table.column_key(index) if hasattr(table, "column_key") else table.columns[index]


def _write_structured(analysis: _Analysis, actions: dict, destination: Path, key: bytes) -> None:
    """Rebuild the JSON or YAML with the same shape. A path the plan does not cover is dropped."""
    from . import structured

    by_path: dict[tuple, tuple[Action, Classification]] = {}
    decisions: dict[tuple, Any] = {}
    for t in analysis.tables:
        if actions.get((t.alias, WHOLE_TABLE)) == OMIT:
            decisions[t.table.path] = structured.OMIT
            continue
        for j, column in enumerate(t.columns):
            by_path[(t.table.path, t.table.paths[j])] = (actions[(t.alias, column.alias)], column.classification)

    def drop(table_path: tuple, path: tuple) -> bool:
        return by_path.get((table_path, path), (Action.DROP, None))[0] == Action.DROP

    def transform(table_path: tuple, path: tuple, value: Any) -> Any:
        action, classification = by_path[(table_path, path)]
        if isinstance(value, (dict, list)):
            # An object or list inside a list of values was profiled as its text: it is transformed
            # as that text, never copied through (and such a column is never kept)
            value = structured.as_text(value)
        return _transform(value, action, classification, key)

    aliases: dict[str, str] = {}

    def rename(name: str) -> str:
        # Like a spreadsheet header: a key that is not known vocabulary leaves as an alias
        return name if analysis.shows(name) else aliases.setdefault(name, f"k{len(aliases) + 1}")

    document = structured.rebuild(analysis.reading.document, decisions, transform, drop, rename)
    structured.write(document, destination, analysis.reading.file_format)


def _output_name(path: Path, everything: Index) -> str:
    """The copy's name never carries data: if the original's name matches a value, it is replaced."""
    if re.fullmatch(r"[\w.\- ]{1,64}", path.stem) and not everything.matches(path.stem):
        return path.stem
    return "file-" + hashlib.sha256(state.path_key(path).encode()).hexdigest()[:8]


def verify(output: Path, index: Index) -> int:
    """How many spans of the output file match fingerprints of the original."""
    parts: list[bytes]
    if zipfile.is_zipfile(output):
        with zipfile.ZipFile(output) as package:
            parts = [package.read(name) for name in package.namelist()]
    else:
        parts = [output.read_bytes()]
    return sum(len(index.matches(html.unescape(data.decode("utf-8", errors="replace")))) for data in parts)


def _resolve_plan(analysis: _Analysis, plan: dict[str, Any]) -> dict[tuple[str, str], Any]:
    if not isinstance(plan, dict):
        raise InvalidPlan("the plan must be an object {table: {column: action}}")
    tables = {t.alias: t for t in analysis.tables}
    actions: dict[tuple[str, str], Any] = {}
    for table_alias, columns in plan.items():
        if table_alias not in tables:
            raise InvalidPlan(f"unknown table: {str(table_alias)[:8]}")
        if columns == OMIT:
            actions[(table_alias, WHOLE_TABLE)] = OMIT
            continue
        if not isinstance(columns, dict):
            raise InvalidPlan(f'{table_alias}: expected {{column: action}} or "omit"')
        valid = {c.alias for c in tables[table_alias].columns}
        for column_alias, action in columns.items():
            if column_alias not in valid:
                raise InvalidPlan(f"{table_alias}: unknown column {str(column_alias)[:8]}")
            try:
                actions[(table_alias, column_alias)] = Action(action)
            except ValueError:
                raise InvalidPlan(f"{table_alias}.{column_alias}: invalid action") from None

    problems = []
    for t in analysis.tables:
        if t.table.hidden and t.alias not in plan:
            actions[(t.alias, WHOLE_TABLE)] = OMIT  # a hidden sheet only goes out if the plan names it
        for j, c in enumerate(t.columns):
            column_key = (t.alias, c.alias)
            action = actions.get(column_key, c.classification.suggested_action)
            if action == Action.REVIEW:
                action = Action.DROP  # what nobody decided does not go out
            if action == Action.KEEP and c.classification.category in NEVER_KEEP:
                problems.append(f"{t.alias}.{c.alias} ({c.classification.category.value})")
            if action == Action.KEEP and getattr(t.table, "has_containers", lambda _: False)(j):
                problems.append(f"{t.alias}.{c.alias} (objects inside a list)")
            if action == Action.GENERALIZE and not _generalizable(c.classification):
                problems.append(f"{t.alias}.{c.alias} cannot be generalized")
            actions[column_key] = action
    if problems:
        raise InvalidPlan("these columns cannot be kept or generalized: " + ", ".join(problems))
    return actions


def _generalizable(c: Classification) -> bool:
    return c.category in {Category.BIRTH_DATE, Category.NOT_SENSITIVE}


def _transform(value: object, action: Action, c: Classification, key: bytes) -> object:
    if value is None or str(value).strip() == "":
        return value
    if action == Action.KEEP:
        return value
    if action == Action.PSEUDONYMIZE:
        signature = hmac.new(key, normalize(value).encode(), hashlib.sha256).hexdigest()
        return f"ID_{signature[:12]}"
    if action == Action.GENERALIZE:
        return _generalize(value, c.category)
    raise AssertionError(action)


def _generalize(value: object, category: Category) -> object:
    parsed = _date(value)
    if parsed is not None:
        if category == Category.BIRTH_DATE:
            today = date.today()
            age = today.year - parsed.year - ((today.month, today.day) < (parsed.month, parsed.day))
            base = max(age, 0) // 10 * 10
            return f"{base}-{base + 9}"
        return parsed.year
    try:
        number = float(str(value).replace(",", ""))
    except ValueError:
        return None  # no safe way to generalize it: empty
    scale = 10 ** max(len(str(int(abs(number)))) - 1, 0)
    lower = int(abs(number)) // scale * scale
    return f"{lower}-{lower + scale - 1}"


def _date(value: object) -> date | None:
    if isinstance(value, date):
        return value if not hasattr(value, "date") else value.date()
    text = str(value).strip()[:10]
    for separator in ("-", "/"):
        parts = text.split(separator)
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            a, b, c = (int(p) for p in parts)
            try:
                return date(a, b, c) if a > 31 else date(c if c > 99 else 1900 + c, b, a)
            except ValueError:
                return None
    return None


def _check_destination(destination: Path, original: Path) -> None:
    files, roots = state.protected()
    if destination == original.resolve() or destination in files:
        raise InvalidPlan("the output cannot overwrite an original")
    if any(destination.is_relative_to(r) for r in roots):
        raise InvalidPlan("the output cannot go inside a protected folder")
