"""HMAC fingerprints of sensitive values.

A fingerprint identifies a value without containing it. It is used to look for leaks in a tool's
output, in the anonymized file or in a transcript, without the scanner having to store or show
the real value.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

MIN_LENGTH = 4  # shorter values collide with ordinary text ("ana", "12")
MAX_WORDS = 4  # full names of up to four words
MARK = "[REDACTED]"

_TOKEN = re.compile(r"[\w@.+\-]+", re.UNICODE)
# Personal-data-shaped fragments inside longer text: emails and long numbers
FRAGMENT = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+|\+?\d[\d .\-]{4,}\d", re.UNICODE)
_ONLY_NUMBER = re.compile(r"^\+?[\d .\-]+$")
_EDGES = ".,;:-+_"


def normalize(value: object) -> str:
    """Canonical form: no accents, lowercase, numbers without separators."""
    text = unicodedata.normalize("NFKD", str(value))
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = " ".join(text.lower().split()).strip(_EDGES)
    if _ONLY_NUMBER.match(text):
        return re.sub(r"\D", "", text)
    return text


@dataclass(frozen=True)
class Fingerprinter:
    key: bytes

    def fingerprint(self, value: object) -> str | None:
        canonical = normalize(value)
        if len(canonical) < MIN_LENGTH:
            return None
        return hmac.new(self.key, canonical.encode(), hashlib.sha256).hexdigest()[:32]


@dataclass
class Index:
    """The set of fingerprints of one original file."""

    fingerprinter: Fingerprinter
    fingerprints: set[str] = field(default_factory=set)

    def add(self, values: Iterable[object], whole: bool = True, fragments: bool = True) -> None:
        """The whole value and also every email or long number inside it: a comment or a
        formula like ="juan@x.co" must not hide the email."""
        for value in values:
            if value is None:
                continue
            text = str(value)
            parts = ([text] if whole else []) + (FRAGMENT.findall(text) if fragments else [])
            for part in parts:
                if (fp := self.fingerprinter.fingerprint(part)) is not None:
                    self.fingerprints.add(fp)

    def __len__(self) -> int:
        return len(self.fingerprints)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.writelines(f"{fp}\n" for fp in sorted(self.fingerprints))

    @classmethod
    def load(cls, path: Path, fingerprinter: Fingerprinter) -> "Index":
        return cls(fingerprinter, {line.strip() for line in path.read_text().splitlines() if line.strip()})

    def matches(self, text: str, strong: bool = False) -> list[tuple[int, int]]:
        """(start, end) spans of the text whose fingerprint is in the index. With `strong`, only
        spans that identify someone on their own count (a name of two or more words, an email,
        a long number): "Maria" in a `git log` must not raise an alarm."""
        spans = [
            (start, end)
            for start, end, candidate in _candidates(text)
            if (not strong or is_strong(candidate)) and self.fingerprinter.fingerprint(candidate) in self.fingerprints
        ]
        return _merge(spans)

    def redact(self, text: str) -> tuple[str, int]:
        spans = self.matches(text)
        for start, end in reversed(spans):
            text = text[:start] + MARK + text[end:]
        return text, len(spans)


def is_strong(candidate: str) -> bool:
    return "@" in candidate or len(re.sub(r"\D", "", candidate)) >= 7 or len(candidate.split()) >= 2


def _candidates(text: str) -> Iterator[tuple[int, int, str]]:
    tokens = [(m.start(), m.end()) for m in _TOKEN.finditer(text)]
    for i, (start, _) in enumerate(tokens):
        for n in range(1, MAX_WORDS + 1):
            if i + n > len(tokens):
                break
            end = tokens[i + n - 1][1]
            yield start, end, text[start:end]


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged
