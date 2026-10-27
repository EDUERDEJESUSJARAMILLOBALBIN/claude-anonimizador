"""The profile contract: the only thing from the original file that reaches the model.

The schema is closed. A new field, free text where an enum belongs, or a small count makes the
validation fail; nothing is "cleaned up" silently.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .detect import Action, Category, Classification
from .fingerprints import Index

VERSION = 2
MIN_COUNT = 5  # below this, a count helps re-identify someone
FEW = "<5"
MAX_NAME = 64
FORMATS = {"xlsx", "xlsm", "xls", "ods", "csv", "tsv", "sql", "sqlite", "json", "jsonl", "yaml"}
FINDINGS = {
    "hidden_sheets",
    "comments",
    "defined_names",
    "metadata",
    "headers_footers",
    "validations",
    "formulas",
    "pivot_tables",
    "charts",
    "embedded_objects",
    "external_links",
    "data_model",
    "sql_views",
    "sql_routines",
    "sql_comments",
}

_TABLE_ALIAS = re.compile(r"^t\d{1,4}$")
_COLUMN_ALIAS = re.compile(r"^c\d{1,4}$")


class InvalidProfile(ValueError):
    """The profile breaks the contract; it must never leave the engine."""


def count(n: int) -> int | str:
    return FEW if 0 < n < MIN_COUNT else n


@dataclass(frozen=True)
class Column:
    alias: str
    name: str | None  # None in strict mode or when the header is not known vocabulary
    classification: Classification

    def to_dict(self) -> dict[str, Any]:
        c = self.classification
        data: dict[str, Any] = {
            "alias": self.alias,
            "category": c.category.value,
            "confidence": c.confidence,
            "empty_pct": round(100 * c.empty / c.rows) if c.rows else 0,
            "unique": count(c.unique),
            "suggested_action": c.suggested_action.value,
        }
        if self.name is not None:
            data["name"] = self.name
        return data


def build(
    file_format: str,
    tables: list[tuple[str | None, int, list[Column], bool]],
    findings: dict[str, int],
) -> dict[str, Any]:
    return {
        "version": VERSION,
        "format": file_format,
        "tables": [
            {
                "alias": f"t{i}",
                **({"name": name} if name is not None else {}),
                **({"hidden": True} if hidden else {}),
                "rows": count(rows),
                "columns": [column.to_dict() for column in columns],
            }
            for i, (name, rows, columns, hidden) in enumerate(tables, start=1)
        ],
        "hidden_findings": dict(sorted(findings.items())),
    }


def validate(profile: dict[str, Any], index: Index) -> str:
    """Validate the profile and return it serialized, ready for the model."""
    _exact(profile, {"version", "format", "tables", "hidden_findings"}, "profile")
    _require(profile["version"] == VERSION, "version")
    _require(profile["format"] in FORMATS, "format")
    _require(isinstance(profile["tables"], list), "tables")
    for table in profile["tables"]:
        _exact(table, {"alias", "rows", "columns"}, "table", optional={"name", "hidden"})
        _require(table.get("hidden", True) is True, "table.hidden")
        _require(bool(_TABLE_ALIAS.match(str(table["alias"]))), "table.alias")
        _name(table.get("name"), "table.name")
        _count(table["rows"], "table.rows")
        for column in table["columns"]:
            _column(column)
    findings = profile["hidden_findings"]
    _require(isinstance(findings, dict) and set(findings) <= FINDINGS, "hidden_findings")
    for name, value in findings.items():
        _require(type(value) is int and value >= 0, f"hidden_findings.{name}")

    text = json.dumps(profile, ensure_ascii=False, sort_keys=True)
    # Last barrier: no span of the profile may match a value of the original, not even a header
    # that was really a data row.
    # Paths are also checked key by key: `1985-03-12.ciudad` is a single token as it stands
    _require(not index.matches(text) and not index.matches(re.sub(r"[.\[\]]", " ", text)),
             "the profile contains a value from the original file")
    return text


def _column(column: dict[str, Any]) -> None:
    _exact(column, {"alias", "category", "confidence", "empty_pct", "unique", "suggested_action"}, "column",
           optional={"name"})
    _require(bool(_COLUMN_ALIAS.match(str(column["alias"]))), "column.alias")
    _name(column.get("name"), "column.name")
    _require(column["category"] in {c.value for c in Category}, "column.category")
    _require(column["suggested_action"] in {a.value for a in Action}, "column.suggested_action")
    _require(isinstance(column["confidence"], float) and 0 <= column["confidence"] <= 1, "column.confidence")
    _require(type(column["empty_pct"]) is int and 0 <= column["empty_pct"] <= 100, "column.empty_pct")
    _count(column["unique"], "column.unique")


def _exact(obj: Any, required: set[str], where: str, optional: set[str] = frozenset()) -> None:
    _require(isinstance(obj, dict), where)
    keys = set(obj)
    _require(required <= keys <= required | optional, f"{where}: fields {sorted(keys ^ required - optional)}")


def _count(value: Any, where: str) -> None:
    _require(value == FEW or (type(value) is int and (value == 0 or value >= MIN_COUNT)), where)


def _name(value: Any, where: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and 0 < len(value) <= MAX_NAME and value.isprintable(), where)


def _require(condition: bool, where: str) -> None:
    if not condition:
        raise InvalidProfile(where)
