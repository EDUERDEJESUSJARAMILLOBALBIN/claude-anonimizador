"""JSON, JSONL and YAML as tables, and back.

Every list of objects is a table (`customers[]`, `customers[].orders[]`) and every leaf path inside a
record is a column (`contact.email`, `phones[]`). The root, if it is an object, is a one-record
table (`$`). That way the rest of the engine (detection, profile, plan, verification) works exactly
as with a spreadsheet.

Defensive reading: maximum size, YAML in safe mode and without aliases (a "bomb" of references
multiplies in memory), and caps on nodes and depth.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .adapters import Reading, Table, UnsupportedFormat

MAX_BYTES = 50 * 1024 * 1024
MAX_NODES = 2_000_000
MAX_DEPTH = 64
ROOT = "$"
LIST = "[]"
OMIT = "omit"
# An identifier-shaped key is a field name; anything else (an email, an ID number, "Ana Ruiz")
# may be data used as a key, so it goes into the fingerprints
_FIELD_KEY = re.compile(r"[A-Za-z_][\w\-]{0,40}")

Path_ = tuple[str, ...]


class InvalidFile(ValueError):
    """A safe message: it never includes file content."""


@dataclass
class StructuredTable(Table):
    path: Path_ = ()  # where the records live inside the document
    paths: list[Path_] = field(default_factory=list)  # relative path of each column

    def values(self, index: int) -> list[object]:
        flat: list[object] = []
        for row in self.rows:
            value = row[index] if index < len(row) else None
            if isinstance(value, list) and self.paths[index] != ():
                flat.extend(as_text(v) for v in value)
            else:
                flat.append(as_text(value))
        return flat

    def has_containers(self, index: int) -> bool:
        """Objects or lists inside a list of values: profiled as text, they can hide anything. The
        root list of values (path `()`) holds its elements as they are; any other column, lists."""
        for row in self.rows:
            value = row[index] if index < len(row) else None
            items = [value] if self.paths[index] == () else value if isinstance(value, list) else []
            if any(isinstance(v, (dict, list)) for v in items):
                return True
        return False

    def column_key(self, index: int) -> str:
        """The last field name of the path, which is what gets classified (`cliente.ciudad` → `ciudad`)."""
        parts = [p for p in self.paths[index] if p != LIST]
        return parts[-1] if parts else "value"


def read(path: Path, file_format: str) -> Reading:
    if path.stat().st_size > MAX_BYTES:
        raise InvalidFile(f"the file is larger than {MAX_BYTES // 2**20} MB")
    text = path.read_text(encoding="utf-8-sig")
    try:
        if file_format == "json":
            document = json.loads(text)
        elif file_format == "jsonl":
            document = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            document = _safe_yaml(text)
    except RecursionError:
        raise InvalidFile("the file is nested too deeply") from None
    except ValueError as error:
        # json and yaml include the failing fragment in their messages: it is never repeated
        raise InvalidFile(f"not valid {file_format} ({type(error).__name__})") from None
    _check_size(document)
    tables, loose = _tables(document)
    return Reading(file_format, tables, {}, loose, document=document)


def _safe_yaml(text: str) -> Any:
    import yaml

    # The C loader (CSafeLoader) never calls compose_node: the alias check only works in the Python one
    class NoAliases(yaml.SafeLoader):
        def compose_node(self, parent, index):  # noqa: ANN001
            if self.check_event(yaml.events.AliasEvent):
                raise InvalidFile("the YAML uses aliases (*references); they are not accepted")
            return super().compose_node(parent, index)

    try:
        documents = list(yaml.load_all(text, Loader=NoAliases))  # noqa: S506 — SafeLoader without aliases
    except InvalidFile:
        raise
    except yaml.YAMLError as error:
        raise InvalidFile(f"not valid yaml ({type(error).__name__})") from None
    return documents[0] if len(documents) == 1 else documents


def _check_size(document: Any) -> None:
    pending, nodes = [(document, 0)], 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InvalidFile("the file is too large or too nested to check safely")
        if isinstance(node, dict) and len({str(k) for k in node}) != len(node):
            # YAML allows 1 and '1' side by side; as text they would merge and lose a record
            raise InvalidFile("two keys of the same object are the same text (1 and '1'); rename one")
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        pending.extend((child, depth + 1) for child in children)


def _is_table(node: Any) -> bool:
    return isinstance(node, list) and bool(node) and all(isinstance(x, dict) for x in node)


def as_text(value: Any) -> Any:
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value


def _name(path: Path_) -> str:
    return ROOT if not path else ".".join(path).replace("." + LIST, LIST)


def _leaves(record: dict, prefix: Path_ = ()) -> list[Path_]:
    """Leaf paths of a record, without entering its lists of objects (those are separate tables)."""
    paths: list[Path_] = []
    for key, value in record.items():
        path = prefix + (str(key),)
        if isinstance(value, dict) and value:
            paths += _leaves(value, path)
        elif _is_table(value):
            continue
        elif isinstance(value, list):
            paths.append(path + (LIST,))
        else:
            paths.append(path)
    return paths


def _read_leaf(record: dict, path: Path_) -> Any:
    node: Any = record
    for part in path:
        if part == LIST:
            return node if isinstance(node, list) else None
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _records(document: Any) -> dict[Path_, list[dict]]:
    """The path of each table → all of its records, in order of appearance."""
    tables: dict[Path_, list[dict]] = {}

    def record(node: dict, table_path: Path_) -> None:
        tables.setdefault(table_path, []).append(node)
        descend(node, table_path, ())

    def descend(node: Any, table_path: Path_, relative: Path_) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if _is_table(value):
                    for item in value:
                        record(item, table_path + relative + (str(key), LIST))
                elif isinstance(value, dict):
                    descend(value, table_path, relative + (str(key),))

    if isinstance(document, dict):
        record(document, ())
    elif _is_table(document):
        for item in document:
            record(item, (LIST,))
    return tables


def _tables(document: Any) -> tuple[list[StructuredTable], list[str]]:
    tables = []
    for table_path, records in _records(document).items():
        paths = list(dict.fromkeys(p for record in records for p in _leaves(record)))
        if not paths:
            continue
        rows = [[_read_leaf(record, p) for p in paths] for record in records]
        tables.append(StructuredTable(_name(table_path), [_name(p) for p in paths], rows, path=table_path, paths=paths))
    if isinstance(document, list) and document and not _is_table(document):
        # A list of plain values at the root: a one-column table
        tables.append(StructuredTable(LIST, ["value"], [[v] for v in document], path=(LIST,), paths=[()]))
    return tables, _data_keys(document)


def _data_keys(document: Any) -> list[str]:
    keys, pending = [], [document]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            keys += [str(k) for k in node if not _FIELD_KEY.fullmatch(str(k))]
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return keys


def rebuild(
    document: Any,
    decisions: dict[Path_, Any],
    transform: Callable[[Path_, Path_, Any], Any],
    drop: Callable[[Path_, Path_], bool],
    rename: Callable[[str], str],
) -> Any:
    """A copy of the document with every column transformed or dropped, every omitted table
    removed and every key passed through `rename`. `decisions[table_path]` is OMIT for a table that
    does not go to the copy."""
    return _renamed(_rebuilt(copy.deepcopy(document), decisions, transform, drop), rename)


def _rebuilt(result: Any, decisions: dict[Path_, Any], transform: Callable[[Path_, Path_, Any], Any],
             drop: Callable[[Path_, Path_], bool]) -> Any:

    def record(node: dict, table_path: Path_) -> None:
        for path in _leaves(node):
            if drop(table_path, path):
                _remove(node, path)
            else:
                _change(node, path, lambda v, p=path: transform(table_path, p, v))
        descend(node, table_path, ())

    def descend(node: Any, table_path: Path_, relative: Path_) -> None:
        if not isinstance(node, dict):
            return
        for key in list(node):
            value = node[key]
            if _is_table(value):
                nested = table_path + relative + (str(key), LIST)
                if decisions.get(nested) == OMIT:
                    del node[key]
                    continue
                for item in value:
                    record(item, nested)
            elif isinstance(value, dict):
                descend(value, table_path, relative + (str(key),))

    if isinstance(result, dict):
        record(result, ())
    elif _is_table(result):
        if decisions.get((LIST,)) == OMIT:
            return []
        for item in result:
            record(item, (LIST,))
    elif isinstance(result, list):
        if drop((LIST,), ()):
            return []
        return [transform((LIST,), (), v) for v in result]
    return result


def _renamed(node: Any, rename: Callable[[str], str]) -> Any:
    if isinstance(node, dict):
        return {rename(str(k)): _renamed(v, rename) for k, v in node.items()}
    if isinstance(node, list):
        return [_renamed(v, rename) for v in node]
    return node


def _parent(record: dict, path: Path_) -> tuple[dict | None, str | None]:
    parts = [p for p in path if p != LIST]
    node: Any = record
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return None, None
        node = node[part]
    return (node, parts[-1]) if isinstance(node, dict) and parts and parts[-1] in node else (None, None)


def _remove(record: dict, path: Path_) -> None:
    parent, key = _parent(record, path)
    if parent is None:
        return
    del parent[key]
    # An object left empty by the drops goes too: its key alone would still say something
    parts = [p for p in path if p != LIST][:-1]
    while parts:
        holder, last = _parent(record, tuple(parts))
        if holder is None or holder[last]:
            break
        del holder[last]
        parts.pop()


def _change(record: dict, path: Path_, function: Callable[[Any], Any]) -> None:
    parent, key = _parent(record, path)
    if parent is None:
        return
    value = parent[key]
    if isinstance(value, list):
        parent[key] = [function(v) for v in value]
    else:
        parent[key] = function(value)


def write(document: Any, destination: Path, file_format: str) -> None:
    if file_format == "json":
        destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif file_format == "jsonl":
        lines = document if isinstance(document, list) else [document]
        destination.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in lines), encoding="utf-8")
    elif file_format == "yaml":
        import yaml

        destination.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=2**31),
                               encoding="utf-8")
    else:
        raise UnsupportedFormat(file_format)
