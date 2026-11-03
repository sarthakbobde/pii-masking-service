"""Finding personal data in text: Presidio (spaCy) for the built-in and admin-defined types, plus sensitive keywords.

* Admin-defined types are regular expressions registered with Presidio next to the built-in recognizers.
* Sensitive keywords: when a listed keyword appears ("Salary: 12,40,000", "DOB 12/03/1990", a "Salary | 12,40,000"
  table row), the value that follows it is personal data whatever its format. After `:`, `=`, `|` or ` - ` any value up
  to the end of the sentence or cell counts; otherwise only a value that starts with a number. At most 120 characters.
* Text that is already masked (`<EMAIL_ADDRESS>`, `<EMAIL_ADDRESS_7f3a9c21>`) is never masked again.

Nothing here logs a value. Errors propagate: callers fail closed.
"""
import logging
import re
import threading
import time
from dataclasses import dataclass

from app import policy as pol
from app.config import config

log = logging.getLogger(__name__)
# Presidio logs the words around a match at DEBUG level, which would put personal data in the log
logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)

KEYWORD_SCORE = 0.85
MAX_VALUE = 120
TOKEN_RE = re.compile(r"<(([A-Z][A-Z0-9_]*?)_[0-9a-f]{8,64})>")            # group 1: the token, group 2: its type
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*(?:_[0-9a-f]{8,64})?>")    # a token or a plain label such as <EMAIL_ADDRESS>

_engine_lock = threading.Lock()
_sync_lock = threading.Lock()
_analyzer = None
_load_error: str | None = None
_registered: tuple | None = None


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    entity_type: str
    score: float


# ---- the detector ---------------------------------------------------------------------------------------------------
def _extra_recognizers():
    from presidio_analyzer import predefined_recognizers as pr
    names = ["InAadhaarRecognizer", "InPanRecognizer", "InVehicleRegistrationRecognizer", "InVoterRecognizer", "InPassportRecognizer"]
    return [getattr(pr, n)() for n in names if hasattr(pr, n)]


def analyzer():
    global _analyzer, _load_error
    if _analyzer is not None:
        return _analyzer
    with _engine_lock:
        if _analyzer is None:
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider
                nlp = NlpEngineProvider(nlp_configuration={
                    "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": config.spacy_model}]}).create_engine()
                engine = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
                have = {r.name for r in engine.registry.recognizers}
                for rec in _extra_recognizers():
                    if rec.name not in have:
                        engine.registry.add_recognizer(rec)
                _analyzer = engine
                _load_error = None
            except Exception as e:
                _load_error = f"{type(e).__name__}: {e}"
                raise
    return _analyzer


def warm_up() -> None:
    try:
        started = time.time()
        analyzer().analyze(text="warm up test@example.com", language="en", entities=["EMAIL_ADDRESS"])
        log.info("personal-data detection ready in %.1f s", time.time() - started)
    except Exception:
        log.exception("personal-data detection could not be loaded; requests will fail until it is fixed")


def status() -> str:
    """ready | loading | error"""
    if _analyzer is not None:
        return "ready"
    return "error" if _load_error else "loading"


def sync_custom(engine, custom: list[dict]) -> None:
    """Make the detector hold exactly the current admin-defined types (cheap when nothing changed)."""
    global _registered
    sig = tuple((r["name"], r["pattern"], tuple(r["context"]), r["confidence"]) for r in custom)
    with _sync_lock:
        if _registered == sig:
            return
        from presidio_analyzer import Pattern, PatternRecognizer
        for rec in list(engine.registry.recognizers):
            if getattr(rec, "name", "").startswith("custom_"):
                engine.registry.remove_recognizer(rec.name)
        for name, pattern, context, confidence in sig:
            engine.registry.add_recognizer(PatternRecognizer(
                supported_entity=name, name=f"custom_{name}", patterns=[Pattern(name, pattern, confidence / 100)],
                context=list(context) or None))
        _registered = sig


# ---- sensitive keywords ----------------------------------------------------------------------------------------------
_NUMBER = r"(?:[₹$€£]\s?)?\d[\d,./\-: ]*\d(?:\s?(?:lakhs?|crores?|k|L|INR|USD|EUR|GBP))?"
_LABEL = r"(?:\s*(?:no\.?|number|#))?"
_compiled: dict[tuple, list] = {}


def _patterns(keywords) -> list:
    key = tuple(sorted({k.strip().lower() for k in keywords if k.strip()}))
    if key not in _compiled:
        if len(_compiled) > 32:
            _compiled.clear()
        out = []
        for kw in key:
            words = r"\s+".join(re.escape(w) for w in kw.split())
            head = r"(?<!\w)" + words + r"(?!\w)" + _LABEL
            # "Salary: x", "Salary = x", "Salary | x" (a table row) or "Salary - x": any value up to the end of the sentence or cell
            out.append(re.compile(head + r"\s*(?:[:=|]|\s[-–—])\s*(?P<v>(?:[^\n;|.]|\.(?=\S))+)", re.I))
            # "Salary 12,40,000", "salary is 12 lakh", "DOB of 12/03/1990": a value that starts with a number
            out.append(re.compile(head + r"(?:\s+(?:is|was|are|were|of))?\s*(?P<v>" + _NUMBER + ")", re.I))
        _compiled[key] = out
    return _compiled[key]


def keyword_spans(text: str, keywords) -> list[tuple[int, int]]:
    """(start, end) of each value that follows a sensitive keyword."""
    if not keywords or not text:
        return []
    spans = []
    for rx in _patterns(keywords):
        for m in rx.finditer(text):
            start, end = m.span("v")
            end = start + len(text[start:end].rstrip())
            if end - start > MAX_VALUE:
                cut = text.rfind(" ", start, start + MAX_VALUE)
                end = cut if cut > start else start + MAX_VALUE
            if end > start and any(c.isalnum() for c in text[start:end]):
                spans.append((start, end))
    return spans


def is_keyword_label(text: str, keywords) -> bool:
    """True when a whole cell is just a keyword ("Salary", "DOB:", "Account no."), so the next cell holds its value."""
    t = re.sub(r"[\s:=|#.\-–—]+$", "", (text or "").strip()).strip()
    t = re.sub(r"\s+(?:no|number)$", "", t, flags=re.I)
    t = " ".join(t.split()).casefold()
    return bool(t) and t in {" ".join(k.split()).casefold() for k in keywords}


# ---- detection ------------------------------------------------------------------------------------------------------
def detect(text: str, p: "pol.Policy") -> list[Hit]:
    """Personal data in `text` under policy `p`: non-overlapping hits in order; allow-listed values are left out."""
    entities = list(p.types) + ([pol.NAME_TYPE] if p.mask_names else [])
    if not text or not text.strip() or not (entities or p.keywords):
        return []
    found: list[Hit] = []
    if entities:
        engine = analyzer()
        sync_custom(engine, pol.custom_types())
        supported = set(engine.get_supported_entities("en"))
        entities = [e for e in entities if e in supported]      # a custom type deleted a moment ago is simply skipped
        if entities:
            found = [Hit(r.start, r.end, r.entity_type, round(float(r.score), 2))
                     for r in engine.analyze(text=text, language="en", entities=entities, score_threshold=p.threshold)]
    found += [Hit(a, b, pol.KEYWORD_TYPE, KEYWORD_SCORE) for a, b in keyword_spans(text, p.keywords)]
    allowed = {a.strip().casefold() for a in p.allow_list}
    found = [h for h in found if text[h.start:h.end].strip().casefold() not in allowed]
    masked = [m.span() for m in PLACEHOLDER_RE.finditer(text)]
    if masked:
        found = [h for h in found if not any(h.start < b and a < h.end for a, b in masked)]
    kept, end = [], -1
    for h in sorted(found, key=lambda h: (h.start, -h.score, -(h.end - h.start))):   # overlaps: keep the first / strongest
        if h.start >= end:
            kept.append(h)
            end = h.end
    return kept
