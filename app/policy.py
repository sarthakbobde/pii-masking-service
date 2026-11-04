"""Masking settings (one row, managed through the admin API), admin-defined types, fields and the per-request policy.

* Custom types: a regular expression that finds a kind of value (EMPLOYEE_ID: EMP-12345).
* Fields, the dictionary: a named kind of data (CLIENT_COMPANY_NAME) with known values ("terms", found wherever they
  appear) and labels ("Client Name:", whose value is masked as that field). Admins add fields and values at any time.

A request may override the settings for itself (types, threshold, names, keywords, allow-list, extra field values)
unless the admin has switched overrides off; the result is a `Policy` that detection works from.
"""
import json
import re
import threading
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import config
from app.db import CustomType, Database, Field, Settings, get_db

DEFAULT_TYPES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_PAN", "IN_GSTIN", "IN_CIN",
                 "IBAN_CODE"]
OTHER_TYPES = ["IP_ADDRESS", "URL", "US_PASSPORT", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "UK_NHS", "CRYPTO",
               "MEDICAL_LICENSE", "IN_VEHICLE_REGISTRATION", "IN_VOTER", "IN_PASSPORT"]
BUILT_IN_TYPES = DEFAULT_TYPES + OTHER_TYPES
KEYWORD_TYPE = "SENSITIVE_VALUE"          # what a value next to a sensitive keyword becomes
NAME_TYPE = "PERSON"
RESERVED = {NAME_TYPE, KEYWORD_TYPE, "LOCATION", "DATE_TIME", "NRP", "ORGANIZATION"}
DEFAULT_KEYWORDS = ["Salary", "CTC", "DOB", "Date of birth", "Bank account", "Account no", "IFSC", "Aadhaar No", "PAN",
                    "Passport", "Medical", "Diagnosis", "Home address"]
# The dictionary a new service starts with: add each field's values ("terms") through the admin API.
# Generic labels such as "CIN:" or "GSTIN:" are left to format detection (IN_CIN, IN_GSTIN, IN_PAN), which finds every
# such number whoever it belongs to; a field's own terms say whose it is.
STARTER_FIELDS = [
    {"name": "COMPANY_NAME", "description": "Our company's name", "labels": ["Company Name"]},
    {"name": "COMPANY_CIN", "description": "Our Corporate Identification Number", "labels": ["Company CIN"]},
    {"name": "COMPANY_ADDRESS", "description": "Our company's address",
     "labels": ["Company Address", "Registered Office", "Registered Address", "Office Address"]},
    {"name": "COMPANY_GSTIN", "description": "Our GST number", "labels": ["Company GST", "Company GSTIN", "Company GST Number"]},
    {"name": "COMPANY_PAN", "description": "Our PAN", "labels": ["Company PAN"]},
    {"name": "CLIENT_COMPANY_NAME", "description": "The client company's name",
     "labels": ["Client Name", "Client Company Name", "Customer Name"]},
    {"name": "CLIENT_CIN", "description": "The client's Corporate Identification Number", "labels": ["Client CIN"]},
    {"name": "CLIENT_ADDRESS", "description": "The client company's address",
     "labels": ["Client Address", "Client Company Address", "Billing Address"]},
    {"name": "CLIENT_GSTIN", "description": "The client's GST number", "labels": ["Client GST", "Client GSTIN", "Client GST Number"]},
    {"name": "CLIENT_PAN", "description": "The client's PAN", "labels": ["Client PAN"]},
    {"name": "CLIENT_SIGNATORY", "description": "Authorised signatory name on the client's side",
     "labels": ["Client Authorised Signatory", "Client Authorized Signatory", "Client Signatory"]},
    {"name": "INTERNAL_SIGNATORY", "description": "Authorised signatory name on our side",
     "labels": ["Authorised Signatory", "Authorized Signatory", "Signatory Name"]},
]
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
MAX_TERMS = 5000
CACHE_SECONDS = 2.0

_lock = threading.Lock()
_cache: tuple[float, int, dict, list, list] | None = None     # (when, id(db), settings, custom types, fields)


def defaults() -> dict:
    return {"enabled_types": list(DEFAULT_TYPES), "threshold": 40, "mask_names": False, "keywords_enabled": True,
            "sensitive_keywords": list(DEFAULT_KEYWORDS), "allow_list": [], "allow_overrides": True,
            "ocr_enabled": True, "ocr_language": "eng"}


# ---- validation -----------------------------------------------------------------------------------------------------
def _strings(name: str, raw, limit: int = 200, length: int = 200) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ValueError(f"{name} must be a list of strings.")
    items = list(dict.fromkeys(" ".join(x.split()) for x in raw if x.strip()))
    if len(items) > limit or any(len(x) > length for x in items):
        raise ValueError(f"{name} can hold up to {limit} values of up to {length} characters.")
    return items


def check_types(raw, custom_names) -> list[str]:
    items = _strings("Types", raw)
    allowed = BUILT_IN_TYPES + list(custom_names)
    bad = [x for x in items if x not in allowed]
    if bad:
        raise ValueError("Unknown type: " + ", ".join(bad) + ". Known: " + ", ".join(allowed) + ".")
    return items


def check_threshold(raw) -> int:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw != int(raw) or not 10 <= raw <= 95:
        raise ValueError("Threshold must be a whole number between 10 and 95 (percent).")
    return int(raw)


def validate(values: dict, custom_names) -> dict:
    known = set(defaults())
    unknown = sorted(set(values) - known)
    if unknown:
        raise ValueError("Unknown setting: " + ", ".join(unknown) + ".")
    clean = {}
    for k, v in values.items():
        if k == "enabled_types":
            clean[k] = check_types(v, custom_names)
        elif k == "threshold":
            clean[k] = check_threshold(v)
        elif k in ("mask_names", "keywords_enabled", "allow_overrides", "ocr_enabled"):
            if not isinstance(v, bool):
                raise ValueError(f"{k} must be true or false.")
            clean[k] = v
        elif k == "ocr_language":
            if not isinstance(v, str) or not re.fullmatch(r"[a-z_]{3,8}(\+[a-z_]{3,8}){0,4}", v):
                raise ValueError("ocr_language must be Tesseract language codes such as eng or eng+hin.")
            clean[k] = v
        else:
            clean[k] = _strings(k, v)
    return clean


def _type_name(raw, what: str) -> str:
    name = str(raw or "").strip().upper().replace(" ", "_").replace("-", "_")
    if not NAME_RE.match(name):
        raise ValueError(f"The {what} name must be 2 to 40 capital letters, digits or underscores, starting with a letter "
                         "(for example EMPLOYEE_ID).")
    if name in BUILT_IN_TYPES or name in RESERVED:
        raise ValueError(f"{name} is a built-in type. Choose another name.")
    return name


def check_custom(data: dict) -> dict:
    """Validate an admin-defined type. Raises ValueError with a message an admin can act on."""
    name = _type_name(data.get("name"), "type")
    pattern = str(data.get("pattern") or "").strip()
    if not pattern or len(pattern) > 300:
        raise ValueError("The pattern must be between 1 and 300 characters.")
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"The pattern is not a valid regular expression: {e}.") from None
    if rx.fullmatch(""):
        raise ValueError("The pattern matches empty text, so it would match everywhere.")
    context = [c.lower() for c in _strings("Context words", data.get("context") or [], 20, 40)]
    confidence = data.get("confidence", 60)
    if isinstance(confidence, bool) or not isinstance(confidence, int) or not 10 <= confidence <= 100:
        raise ValueError("Confidence must be a whole number between 10 and 100.")
    return {"name": name, "pattern": pattern, "context": context, "confidence": confidence}


def check_terms(raw) -> list[str]:
    terms = _strings("terms", raw, MAX_TERMS, 200)
    short = [t for t in terms if sum(c.isalnum() for c in t) < 2]
    if short:
        raise ValueError("Each term needs at least 2 letters or digits (a shorter one would match everywhere).")
    return terms


def check_labels(raw) -> list[str]:
    labels = _strings("labels", raw, 100, 80)
    if any(not any(c.isalpha() for c in x) for x in labels):
        raise ValueError("Each label needs at least one letter.")
    return labels


def check_field(data: dict, partial: bool = False) -> dict:
    """Validate a field (dictionary entry). With partial, only the keys given are checked."""
    unknown = sorted(set(data) - {"name", "description", "terms", "labels", "enabled"})
    if unknown:
        raise ValueError("Unknown field property: " + ", ".join(unknown) + ".")
    clean = {}
    if not partial or "name" in data:
        clean["name"] = _type_name(data.get("name"), "field")
    if "description" in data:
        if not isinstance(data["description"], str) or len(data["description"]) > 200:
            raise ValueError("description is text of up to 200 characters.")
        clean["description"] = data["description"].strip()
    if not partial or "terms" in data:
        clean["terms"] = check_terms(data.get("terms") or [])
    if not partial or "labels" in data:
        clean["labels"] = check_labels(data.get("labels") or [])
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise ValueError("enabled must be true or false.")
        clean["enabled"] = data["enabled"]
    return clean


# ---- storage --------------------------------------------------------------------------------------------------------
def _view(t: CustomType) -> dict:
    return {"id": t.id, "name": t.name, "pattern": t.pattern, "context": list(t.context or []), "confidence": t.confidence,
            "updated_at": t.updated_at, "updated_by": t.updated_by}


def _field_view(f: Field) -> dict:
    return {"id": f.id, "name": f.name, "description": f.description, "terms": list(f.terms or []),
            "labels": list(f.labels or []), "enabled": f.enabled, "updated_at": f.updated_at, "updated_by": f.updated_by}


def invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def _add_fields(db: Database, fields: list[dict], actor: str) -> None:
    for f in fields:
        clean = check_field(f)
        with db.session() as s:
            if s.scalar(select(Field.id).where(Field.name == clean["name"])) is None:
                s.add(Field(updated_by=actor, **clean))


def seed(db: Database) -> None:
    """Create the settings row and the starter fields on first start, from PII_SETTINGS_FILE when given."""
    with db.session() as s:
        if s.get(Settings, 1) is not None:
            return
    data = defaults()
    fields = STARTER_FIELDS
    if config.settings_file:
        with open(config.settings_file, encoding="utf-8") as f:
            seeded = json.load(f)
        custom = seeded.pop("custom_types", [])
        fields = seeded.pop("fields", fields)
        for c in custom:
            clean = check_custom(c)
            with db.session() as s:
                if s.scalar(select(CustomType.id).where(CustomType.name == clean["name"])) is None:
                    s.add(CustomType(updated_by="settings file", **clean))
        names = [check_custom(c)["name"] for c in custom]
        data.update(validate(seeded, names))
        data["enabled_types"] += [n for n in names if n not in data["enabled_types"]]   # like a type added through the API
    _add_fields(db, fields, "system (first start)")
    try:
        with db.session() as s:
            s.add(Settings(id=1, data=data, updated_by="system (first start)"))
    except IntegrityError:
        pass                                              # another worker created it first
    invalidate()


def _load(db: Database) -> tuple[dict, list, list]:
    global _cache
    now = time.monotonic()
    with _lock:
        hit = _cache
    if hit and hit[1] == id(db) and now - hit[0] < CACHE_SECONDS:
        return hit[2], hit[3], hit[4]
    with db.session() as s:
        row = s.get(Settings, 1)
        data = {**defaults(), **(row.data if row else {})}
        custom = [_view(t) for t in s.scalars(select(CustomType).order_by(CustomType.name))]
        fields = [_field_view(f) for f in s.scalars(select(Field).order_by(Field.name))]
    with _lock:
        _cache = (now, id(db), data, custom, fields)
    return data, custom, fields


def current(db: Database | None = None) -> dict:
    return dict(_load(db or get_db())[0])


def custom_types(db: Database | None = None) -> list[dict]:
    return list(_load(db or get_db())[1])


def fields(db: Database | None = None) -> list[dict]:
    return list(_load(db or get_db())[2])


def view(db: Database | None = None) -> dict:
    db = db or get_db()
    with db.session() as s:
        row = s.get(Settings, 1)
        meta = {"updated_at": row.updated_at, "updated_by": row.updated_by} if row else {}
    return {"settings": current(db), "built_in_types": BUILT_IN_TYPES,
            "custom_types": [t["name"] for t in custom_types(db)], "fields": [f["name"] for f in fields(db)], **meta}


def update(values: dict, actor: str, db: Database | None = None) -> dict:
    db = db or get_db()
    clean = validate(values, [t["name"] for t in custom_types(db)])
    if clean:
        with db.session() as s:
            row = s.get(Settings, 1)
            if row is None:
                row = Settings(id=1, data=defaults())
                s.add(row)
            row.data = {**defaults(), **(row.data or {}), **clean}
            row.updated_by = actor
        invalidate()
    return view(db)


def save_custom(data: dict, actor: str, type_id: int | None = None, db: Database | None = None) -> dict:
    """Create or change an admin-defined type. A new type is switched on straight away; a rename follows it."""
    db = db or get_db()
    clean = check_custom(data)
    with db.session() as s:
        clash = s.scalar(select(CustomType.id).where(CustomType.name == clean["name"]))
        if clash and clash != type_id:
            raise LookupError(f"A type called {clean['name']} already exists.")
        if s.scalar(select(Field.id).where(Field.name == clean["name"])) is not None:
            raise LookupError(f"A field called {clean['name']} already exists.")
        old = None
        if type_id is None:
            row = CustomType(updated_by=actor, **clean)
            s.add(row)
        else:
            row = s.get(CustomType, type_id)
            if row is None:
                raise KeyError("No such type.")
            old = row.name
            for k, v in clean.items():
                setattr(row, k, v)
            row.updated_by = actor
        s.flush()
        out = _view(row)
    invalidate()
    types = current(db)["enabled_types"]
    if old and old != out["name"]:
        new = [out["name"] if t == old else t for t in types]
    elif old is None and out["name"] not in types:
        new = types + [out["name"]]
    else:
        new = types
    if new != types:
        update({"enabled_types": new}, actor, db)
    return out


def delete_custom(type_id: int, actor: str, db: Database | None = None) -> dict:
    db = db or get_db()
    with db.session() as s:
        row = s.get(CustomType, type_id)
        if row is None:
            raise KeyError("No such type.")
        out = _view(row)
        s.delete(row)
    invalidate()
    types = current(db)["enabled_types"]
    if out["name"] in types:
        update({"enabled_types": [t for t in types if t != out["name"]]}, actor, db)
    return out


def save_field(data: dict, actor: str, field_id: int | None = None, db: Database | None = None) -> dict:
    """Create a field (field_id None) or change some of its properties."""
    db = db or get_db()
    clean = check_field(data, partial=field_id is not None)
    with db.session() as s:
        if "name" in clean:
            clash = s.scalar(select(Field.id).where(Field.name == clean["name"]))
            if clash and clash != field_id:
                raise LookupError(f"A field called {clean['name']} already exists.")
            if s.scalar(select(CustomType.id).where(CustomType.name == clean["name"])) is not None:
                raise LookupError(f"A custom type called {clean['name']} already exists.")
        if field_id is None:
            row = Field(updated_by=actor, **clean)
            s.add(row)
        else:
            row = s.get(Field, field_id)
            if row is None:
                raise KeyError("No such field.")
            for k, v in clean.items():
                setattr(row, k, v)
            row.updated_by = actor
        s.flush()
        out = _field_view(row)
    invalidate()
    return out


def change_terms(field_id: int, add, remove, actor: str, db: Database | None = None) -> dict:
    """Add values to a field's dictionary and/or take some out (matched ignoring case and spacing)."""
    db = db or get_db()
    add, remove = check_terms(add or []), _strings("remove", remove or [], MAX_TERMS, 200)
    with db.session() as s:
        row = s.get(Field, field_id)
        if row is None:
            raise KeyError("No such field.")
        gone = {r.casefold() for r in remove}
        terms = [t for t in (row.terms or []) if t.casefold() not in gone]
        have = {t.casefold() for t in terms}
        terms += [t for t in add if t.casefold() not in have]
        row.terms = check_terms(terms)
        row.updated_by = actor
        s.flush()
        out = _field_view(row)
    invalidate()
    return out


def delete_field(field_id: int, db: Database | None = None) -> dict:
    db = db or get_db()
    with db.session() as s:
        row = s.get(Field, field_id)
        if row is None:
            raise KeyError("No such field.")
        out = _field_view(row)
        s.delete(row)
    invalidate()
    return out


# ---- the policy a request runs with -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class FieldSpec:
    name: str
    terms: tuple
    labels: tuple


@dataclass(frozen=True)
class Policy:
    types: tuple
    threshold: float
    mask_names: bool
    keywords: tuple
    allow_list: tuple
    ocr_enabled: bool
    ocr_language: str
    fields: tuple = ()

    @property
    def label_groups(self) -> tuple:
        """[(what the value becomes, labels)]: the sensitive keywords, then each field's labels."""
        groups = ((KEYWORD_TYPE, self.keywords),) if self.keywords else ()
        return groups + tuple((f.name, f.labels) for f in self.fields if f.labels)


OVERRIDABLE = ("types", "threshold", "mask_names", "keywords", "allow_list", "fields")


def _request_fields(raw, stored: list[dict]) -> tuple:
    """The enabled fields, plus the values and labels a request adds: [{"name", "terms", "labels"}]. A name that is not
    a stored field makes a field for this request only."""
    merged = {f["name"]: (list(f["terms"]), list(f["labels"])) for f in stored if f["enabled"]}
    if raw is not None:
        if not isinstance(raw, list) or len(raw) > 100 or not all(isinstance(x, dict) for x in raw):
            raise ValueError("fields must be a list of {\"name\", \"terms\", \"labels\"} objects (at most 100).")
        for item in raw:
            extra = set(item) - {"name", "terms", "labels"}
            if extra:
                raise ValueError("A request field takes only name, terms and labels.")
            clean = check_field(item)
            terms, labels = merged.setdefault(clean["name"], ([], []))
            terms += [t for t in clean["terms"] if t not in terms]
            labels += [x for x in clean["labels"] if x not in labels]
    return tuple(FieldSpec(n, tuple(t), tuple(lab)) for n, (t, lab) in sorted(merged.items()) if t or lab)


def resolve(overrides: dict | None, db: Database | None = None) -> Policy:
    """The settings in force for one request, with its overrides applied (ValueError / PermissionError if not allowed)."""
    db = db or get_db()
    s, custom, stored_fields = _load(db)
    o = {k: v for k, v in (overrides or {}).items() if v is not None}
    unknown = sorted(set(o) - set(OVERRIDABLE))
    if unknown:
        raise ValueError("Unknown option: " + ", ".join(unknown) + ".")
    if o and not s["allow_overrides"]:
        raise PermissionError("Per-request options are switched off on this service.")
    custom_names = [t["name"] for t in custom]
    types = check_types(o["types"], custom_names) if "types" in o else s["enabled_types"]
    threshold = check_threshold(o["threshold"]) if "threshold" in o else s["threshold"]
    names = o.get("mask_names", s["mask_names"])
    if not isinstance(names, bool):
        raise ValueError("mask_names must be true or false.")
    if "keywords" in o:
        keywords = _strings("keywords", o["keywords"])
    else:
        keywords = s["sensitive_keywords"] if s["keywords_enabled"] else []
    allow = _strings("allow_list", o["allow_list"]) if "allow_list" in o else s["allow_list"]
    return Policy(tuple(types), threshold / 100, names, tuple(keywords), tuple(allow), s["ocr_enabled"], s["ocr_language"],
                  _request_fields(o.get("fields"), stored_fields))
