"""Finding personal data in text: Presidio (spaCy) for the built-in and admin-defined types, plus sensitive keywords.

* Admin-defined types are regular expressions registered with Presidio next to the built-in recognizers.
* Fields (the dictionary): known values ("Acme Technologies Pvt Ltd") found wherever they appear, case and spacing
  ignored, and labels ("Client Name:") whose value is masked as that field.
* Sensitive keywords: when a listed keyword appears ("Salary: 12,40,000", "DOB 12/03/1990", a "Salary | 12,40,000"
  table row), the value that follows it is personal data whatever its format. After `:`, `=`, `|` or ` - ` any value up
  to the end of the sentence or cell counts; otherwise only a value that starts with a number. At most 120 characters.
* Text that is already masked (`<EMAIL_ADDRESS>`) is never masked again.

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
TERM_SCORE = 1.0          # a value an admin listed is certain, so it wins over anything overlapping it
MAX_VALUE = 120
MAX_COMPILED = 512
_PAN_SHAPE = re.compile(r"[A-Za-z]{5}\d{4}[A-Za-z]")
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*>")                          # an already-masked label such as <EMAIL_ADDRESS>

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
    priority: int = 0         # breaks ties between overlapping hits: an admin-listed value (1) names whose value it is


# ---- the detector ---------------------------------------------------------------------------------------------------
def _extra_recognizers():
    from presidio_analyzer import Pattern, PatternRecognizer
    from presidio_analyzer import predefined_recognizers as pr
    names = ["InAadhaarRecognizer", "InPanRecognizer", "InGstinRecognizer", "InVehicleRegistrationRecognizer",
             "InVoterRecognizer", "InPassportRecognizer"]
    out = [getattr(pr, n)() for n in names if hasattr(pr, n)]
    # Indian Corporate Identification Number: listing status, industry code, state, year, ownership, registration number
    out.append(PatternRecognizer(
        supported_entity="IN_CIN", name="InCinRecognizer",
        patterns=[Pattern("IN_CIN", r"\b[LU]\d{5}[A-Z]{2}\d{4}(?:PLC|PTC|FLC|FTC|GOI|SGC|GAT|GAP|NPL|ULL|ULT|OPC)\d{6}\b", 0.85)],
        context=["cin", "corporate identification", "company identification", "corporate identity"]))
    return out


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
_compiled: dict[str, list] = {}
_terms_compiled: dict[tuple, re.Pattern] = {}
# A full stop ends a keyword's value, except: inside a word ("a.b@x.com"); after a title ("Mr. Rao"); after a company
# or address abbreviation when more of the name follows ("Acme Pvt. Ltd.", "Plot No. 4"), but not before a new sentence
# ("Acme Inc. The parties agree").
_TITLES = ("Mr", "Mrs", "Ms", "Dr", "Shri", "Smt")
_ABBREV = ("Pvt", "Ltd", "Co", "Inc", "Corp", "LLP", "St", "Rd", "No", "Opp", "Bldg", "Nr")


def _after(words) -> str:
    return "(?:" + "|".join(rf"(?<=\b{w})" for w in words) + ")"


_DOT = (r"(?:\.(?=\S)"
        + "|" + _after(_TITLES) + r"\."
        + "|" + _after(_ABBREV) + r"\.(?=\s*(?-i:[a-z0-9]|(?:" + "|".join(_ABBREV) + r")\b))"
        + ")")


def _patterns(keyword: str) -> list:
    kw = " ".join(keyword.lower().split())
    if kw not in _compiled:
        if len(_compiled) > MAX_COMPILED:
            _compiled.clear()
        words = r"\s+".join(re.escape(w) for w in kw.split())
        head = r"(?<!\w)" + words + r"(?!\w)" + _LABEL
        _compiled[kw] = [
            # "Salary: x", "Salary = x", "Salary | x" (a table row) or "Salary - x": any value up to the end of the sentence or cell
            re.compile(head + r"\s*(?:[:=|]|\s[-–—])\s*(?P<v>(?:[^\n;|.]|" + _DOT + r")+)", re.I),
            # "Salary 12,40,000", "salary is 12 lakh", "DOB of 12/03/1990": a value that starts with a number
            re.compile(head + r"(?:\s+(?:is|was|are|were|of))?\s*(?P<v>" + _NUMBER + ")", re.I),
        ]
    return _compiled[kw]


def keyword_spans(text: str, keywords) -> list[tuple[int, int]]:
    """(start, end) of each value that follows a sensitive keyword."""
    if not keywords or not text:
        return []
    spans = []
    for kw in {k.strip() for k in keywords if k.strip()}:
        for rx in _patterns(kw):
            for m in rx.finditer(text):
                start, end = m.span("v")
                end = start + len(text[start:end].rstrip())
                if end - start > MAX_VALUE:
                    cut = text.rfind(" ", start, start + MAX_VALUE)
                    end = cut if cut > start else start + MAX_VALUE
                if end > start and any(c.isalnum() for c in text[start:end]):
                    spans.append((start, end))
    return spans


def label_hits(text: str, groups) -> list[Hit]:
    """Values after labels, each named by its field ([(field, labels)]). When labels of two fields find the same value
    ("Authorised Signatory:" and "Client Authorised Signatory:"), the longer label decides."""
    best: dict[tuple[int, int], tuple[int, str]] = {}
    for entity, labels in groups:
        for label in labels:
            for span in keyword_spans(text, [label]):
                if span not in best or len(label) > best[span][0]:
                    best[span] = (len(label), entity)
    return [Hit(a, b, entity, KEYWORD_SCORE) for (a, b), (_, entity) in best.items()]


def _term_regex(terms: tuple) -> re.Pattern:
    """One pattern for a field's known values: case-insensitive, any spacing, optional full stops and commas
    ("Acme Pvt Ltd" also finds "ACME Pvt. Ltd." and "Acme  Pvt Ltd")."""
    if terms not in _terms_compiled:
        if len(_terms_compiled) > MAX_COMPILED:
            _terms_compiled.clear()
        alts = []
        for t in sorted(terms, key=len, reverse=True):                 # longest first: "Acme Pvt Ltd" before "Acme"
            bare = [w.rstrip(".,") for w in t.split() if w.rstrip(".,")]
            if not bare:
                continue
            if t.endswith("."):
                tail = r"\.?"
            elif bare[-1].casefold() in {a.casefold() for a in _ABBREV}:
                # "Globex Pvt. Ltd., with" takes the full stop; "... Ltd. The next sentence" leaves it
                tail = r"(?:\.(?=(?-i:\s*[,;:)\]]|\s+[a-z0-9])))?"
            else:
                tail = ""
            alts.append(r"[.,]?\s+".join(re.escape(w) for w in bare) + tail)
        _terms_compiled[terms] = re.compile(r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.I)
    return _terms_compiled[terms]


def term_hits(text: str, fields) -> list[Hit]:
    out = []
    for f in fields:
        if f.terms:
            out += [Hit(m.start(), m.end(), f.name, TERM_SCORE, 1) for m in _term_regex(f.terms).finditer(text)]
    return out


def _norm_label(s: str) -> str:
    s = re.sub(r"[\s:=|#.\-–—]+$", "", (s or "").strip()).strip()
    s = re.sub(r"\s+(?:no|number)$", "", s, flags=re.I)                # "Account no" and "Account" are the same label
    return " ".join(s.split()).casefold()


def label_of(text: str, groups) -> str | None:
    """The field whose label a whole cell is ("Salary", "Client Name:", "Account no."), so the next cell holds its value.
    None when the cell is not a label."""
    t = _norm_label(text)
    if not t:
        return None
    best = None
    for entity, labels in groups:
        for label in labels:
            if _norm_label(label) == t and (best is None or len(label) > best[0]):
                best = (len(label), entity)
    return best[1] if best else None


# ---- detection ------------------------------------------------------------------------------------------------------
def detect(text: str, p: "pol.Policy") -> list[Hit]:
    """Personal data in `text` under policy `p`: non-overlapping hits in order; allow-listed values are left out."""
    entities = list(p.types) + ([pol.NAME_TYPE] if p.mask_names else [])
    if not text or not text.strip() or not (entities or p.keywords or p.fields):
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
            # Presidio's loose PAN pattern also takes any 10-letter word ("registered") when "PAN" and digits are near
            found = [h for h in found if h.entity_type != "IN_PAN" or _PAN_SHAPE.fullmatch(text[h.start:h.end])]
    found += label_hits(text, p.label_groups)
    found += term_hits(text, p.fields)
    allowed = {a.strip().casefold() for a in p.allow_list}
    found = [h for h in found if text[h.start:h.end].strip().casefold() not in allowed]
    masked = [m.span() for m in PLACEHOLDER_RE.finditer(text)]
    if masked:
        found = [h for h in found if not any(h.start < b and a < h.end for a, b in masked)]
    kept: list[Hit] = []
    for h in sorted(found, key=lambda h: (-h.score, -h.priority, -(h.end - h.start), h.start)):   # overlaps: strongest wins
        if not any(h.start < k.end and k.start < h.end for k in kept):
            kept.append(h)
    return sorted(kept, key=lambda h: h.start)
