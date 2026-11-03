"""One request's work: find what to replace in a piece of text and what to replace it with.

The same `Redactor` drives plain text and every file format, in one of three modes:
mask (`<EMAIL_ADDRESS>`), tokenise (`<EMAIL_ADDRESS_7f3a9c21>`, value kept in the vault) or unmask (tokens back to values).
It counts what it replaced by type; it never keeps or returns a value except in unmask output.
"""
from collections import Counter
from dataclasses import dataclass

from app import detect, vault
from app.policy import KEYWORD_TYPE, Policy

MODES = ("mask", "tokenise", "unmask")


@dataclass(frozen=True)
class Change:
    start: int
    end: int
    entity_type: str
    score: float
    replacement: str


class Redactor:
    def __init__(self, mode: str, policy: Policy | None, scope: str = ""):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        self.mode, self.policy, self.scope = mode, policy, scope
        self.counts: Counter = Counter()
        self.unknown_tokens: set[str] = set()
        self._tokens: dict[tuple[str, str], str] = {}

    @property
    def keywords(self) -> tuple:
        return self.policy.keywords if self.policy and self.mode != "unmask" else ()

    def replacement(self, entity: str, value: str) -> str:
        if self.mode == "mask":
            return f"<{entity}>"
        key = (entity, " ".join(value.split()).casefold())
        if key not in self._tokens:
            self._tokens[key] = vault.token_for(self.scope, entity, value)
        return f"<{self._tokens[key]}>"

    def whole(self, value: str, entity: str = KEYWORD_TYPE) -> str:
        """Replace a whole value (a spreadsheet cell next to a keyword) and count it."""
        self.counts[entity] += 1
        return self.replacement(entity, value)

    def find(self, text: str) -> list[Change]:
        if not text:
            return []
        if self.mode == "unmask":
            matches = list(detect.TOKEN_RE.finditer(text))
            values = vault.lookup(self.scope, {m.group(1) for m in matches})
            out = []
            for m in matches:
                if m.group(1) in values:
                    out.append(Change(m.start(), m.end(), m.group(2), 1.0, values[m.group(1)]))
                    self.counts[m.group(2)] += 1
                else:
                    self.unknown_tokens.add(m.group(1))
            return out
        out = []
        for h in detect.detect(text, self.policy):
            out.append(Change(h.start, h.end, h.entity_type, h.score, self.replacement(h.entity_type, text[h.start:h.end])))
            self.counts[h.entity_type] += 1
        return out

    def run(self, text: str) -> tuple[str, list[Change]]:
        changes = self.find(text)
        return apply(text, changes), changes

    def summary(self) -> dict:
        out = {"counts": dict(sorted(self.counts.items())), "total": sum(self.counts.values())}
        if self.mode == "unmask":
            out["unknown_tokens"] = len(self.unknown_tokens)
        return out


def apply(text: str, changes) -> str:
    for c in sorted(changes, key=lambda c: c.start, reverse=True):
        text = text[:c.start] + c.replacement + text[c.end:]
    return text
