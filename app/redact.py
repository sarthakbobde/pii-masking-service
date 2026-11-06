"""One request's work: find what to hide in a piece of text and replace it with a label such as `<EMAIL_ADDRESS>`.

The same `Redactor` drives plain text and every file format. Masking is one-way: the original value is not kept
anywhere, so nothing can be restored. It counts what it replaced by type and never keeps or returns a value.
"""
from collections import Counter
from dataclasses import dataclass

from app import detect
from app.policy import KEYWORD_TYPE, Policy


@dataclass(frozen=True)
class Change:
    start: int
    end: int
    entity_type: str
    score: float
    replacement: str


class Redactor:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.counts: Counter = Counter()

    @property
    def label_groups(self) -> tuple:
        """[(what the value becomes, labels)] for table cells that label the cell beside or below them."""
        return self.policy.label_groups

    @property
    def scrub(self) -> bool:
        """Whether to clear document properties (author, title, ...) from the file."""
        return bool(self.policy.scrub_metadata)

    @staticmethod
    def replacement(entity: str, _value: str = "") -> str:
        return f"<{entity}>"

    def whole(self, value: str, entity: str = KEYWORD_TYPE) -> str:
        """Replace a whole value (a table cell next to a keyword or field label) and count it."""
        self.counts[entity] += 1
        return self.replacement(entity, value)

    def find(self, text: str) -> list[Change]:
        if not text:
            return []
        out = []
        for h in detect.detect(text, self.policy):
            out.append(Change(h.start, h.end, h.entity_type, h.score, self.replacement(h.entity_type)))
            self.counts[h.entity_type] += 1
        return out

    def run(self, text: str) -> tuple[str, list[Change]]:
        changes = self.find(text)
        return apply(text, changes), changes

    def summary(self) -> dict:
        return {"counts": dict(sorted(self.counts.items())), "total": sum(self.counts.values())}


def apply(text: str, changes) -> str:
    for c in sorted(changes, key=lambda c: c.start, reverse=True):
        text = text[:c.start] + c.replacement + text[c.end:]
    return text
