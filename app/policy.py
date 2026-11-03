"""Masking settings (one row, managed through the admin API), admin-defined types and the per-request policy.

A request may override the settings for itself (types, threshold, names, keywords, allow-list) unless the admin has
switched overrides off; the result is a `Policy` that detection works from.
"""
import json
import re
import threading
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import config
from app.db import CustomType, Database, Settings, get_db

DEFAULT_TYPES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IN_AADHAAR", "IN_PAN", "IBAN_CODE"]
OTHER_TYPES = ["IP_ADDRESS", "URL", "US_PASSPORT", "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "UK_NHS", "CRYPTO",
               "MEDICAL_LICENSE", "IN_VEHICLE_REGISTRATION", "IN_VOTER", "IN_PASSPORT"]
BUILT_IN_TYPES = DEFAULT_TYPES + OTHER_TYPES
KEYWORD_TYPE = "SENSITIVE_VALUE"          # what a value next to a sensitive keyword becomes
NAME_TYPE = "PERSON"
RESERVED = {NAME_TYPE, KEYWORD_TYPE, "LOCATION", "DATE_TIME", "NRP", "ORGANIZATION"}
DEFAULT_KEYWORDS = ["Salary", "CTC", "DOB", "Date of birth", "Bank account", "Account no", "IFSC", "Aadhaar No", "PAN",
                    "Passport", "Medical", "Diagnosis", "Home address"]
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,39}$")
CACHE_SECONDS = 2.0

_lock = threading.Lock()
_cache: tuple[float, int, dict, list] | None = None     # (when, id(db), settings, custom types)


def defaults() -> dict:
    return {"enabled_types": list(DEFAULT_TYPES), "threshold": 40, "mask_names": False, "keywords_enabled": True,
            "sensitive_keywords": list(DEFAULT_KEYWORDS), "allow_list": [], "allow_overrides": True,
            "ocr_enabled": True, "ocr_language": "eng"}


# ---- validation -----------------------------------------------------------------------------------------------------
def _strings(name: str, raw, limit: int = 200, length: int = 200) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ValueError(f"{name} must be a list of strings.")
    items = list(dict.fromkeys(x.strip() for x in raw if x.strip()))
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


def check_custom(data: dict) -> dict:
    """Validate an admin-defined type. Raises ValueError with a message an admin can act on."""
    name = str(data.get("name") or "").strip().upper().replace(" ", "_")
    if not NAME_RE.match(name):
        raise ValueError("The name must be 2 to 40 capital letters, digits or underscores, starting with a letter (for example EMPLOYEE_ID).")
    if name in BUILT_IN_TYPES or name in RESERVED:
        raise ValueError(f"{name} is a built-in type. Choose another name.")
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


# ---- storage --------------------------------------------------------------------------------------------------------
def _view(t: CustomType) -> dict:
    return {"id": t.id, "name": t.name, "pattern": t.pattern, "context": list(t.context or []), "confidence": t.confidence,
            "updated_at": t.updated_at, "updated_by": t.updated_by}


def invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def seed(db: Database) -> None:
    """Create the settings row on first start, from PII_SETTINGS_FILE when given."""
    with db.session() as s:
        if s.get(Settings, 1) is not None:
            return
    data = defaults()
    if config.settings_file:
        with open(config.settings_file, encoding="utf-8") as f:
            seeded = json.load(f)
        custom = seeded.pop("custom_types", [])
        for c in custom:
            clean = check_custom(c)
            with db.session() as s:
                if s.scalar(select(CustomType.id).where(CustomType.name == clean["name"])) is None:
                    s.add(CustomType(updated_by="settings file", **clean))
        names = [check_custom(c)["name"] for c in custom]
        data.update(validate(seeded, names))
        data["enabled_types"] += [n for n in names if n not in data["enabled_types"]]   # like a type added through the API
    try:
        with db.session() as s:
            s.add(Settings(id=1, data=data, updated_by="system (first start)"))
    except IntegrityError:
        pass                                              # another worker created it first
    invalidate()


def _load(db: Database) -> tuple[dict, list]:
    global _cache
    now = time.monotonic()
    with _lock:
        hit = _cache
    if hit and hit[1] == id(db) and now - hit[0] < CACHE_SECONDS:
        return hit[2], hit[3]
    with db.session() as s:
        row = s.get(Settings, 1)
        data = {**defaults(), **(row.data if row else {})}
        custom = [_view(t) for t in s.scalars(select(CustomType).order_by(CustomType.name))]
    with _lock:
        _cache = (now, id(db), data, custom)
    return data, custom


def current(db: Database | None = None) -> dict:
    return dict(_load(db or get_db())[0])


def custom_types(db: Database | None = None) -> list[dict]:
    return list(_load(db or get_db())[1])


def view(db: Database | None = None) -> dict:
    db = db or get_db()
    with db.session() as s:
        row = s.get(Settings, 1)
        meta = {"updated_at": row.updated_at, "updated_by": row.updated_by} if row else {}
    return {"settings": current(db), "built_in_types": BUILT_IN_TYPES,
            "custom_types": [t["name"] for t in custom_types(db)], **meta}


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


# ---- the policy a request runs with -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Policy:
    types: tuple
    threshold: float
    mask_names: bool
    keywords: tuple
    allow_list: tuple
    ocr_enabled: bool
    ocr_language: str


OVERRIDABLE = ("types", "threshold", "mask_names", "keywords", "allow_list")


def resolve(overrides: dict | None, db: Database | None = None) -> Policy:
    """The settings in force for one request, with its overrides applied (ValueError / PermissionError if not allowed)."""
    db = db or get_db()
    s, custom = _load(db)
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
    return Policy(tuple(types), threshold / 100, names, tuple(keywords), tuple(allow), s["ocr_enabled"], s["ocr_language"])
