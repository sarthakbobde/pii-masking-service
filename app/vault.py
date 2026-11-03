"""Tokens and the vault.

A value becomes `<EMAIL_ADDRESS_7f3a9c21>`: the suffix is an HMAC-SHA256 of the value keyed by a random service secret
and the scope, so the same value gets the same token in every request of that scope (callers can still tell that two
texts mention the same person) while the token says nothing about the value. On the rare clash of the first 8 hex
digits the token grows to 12, 16 or 64. The real value is kept encrypted (Fernet, PII_MASTER_KEY) and is only put back
by `reveal`, for callers allowed to unmask in that scope. Nothing here logs a value.
"""
import hashlib
import hmac
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from app.config import config
from app.db import Database, Secret, VaultEntry, get_db
from app.detect import TOKEN_RE


class VaultUnavailable(RuntimeError):
    """The master key is missing or wrong, so values cannot be stored or read."""


_lock = threading.Lock()
_key: tuple[int, str, bytes] | None = None      # (id(db), master key, HMAC secret)


def crypto() -> MultiFernet:
    keys = [k.strip() for k in (config.master_key or "").split(",") if k.strip()]
    if not keys:
        raise VaultUnavailable("PII_MASTER_KEY is not set, so tokenising and unmasking are unavailable.")
    try:
        return MultiFernet([Fernet(k.encode()) for k in keys])
    except (ValueError, TypeError):
        raise VaultUnavailable("PII_MASTER_KEY is not a valid Fernet key (generate one with: python -m app.cli master-key).") from None


def available() -> bool:
    try:
        crypto()
        return True
    except VaultUnavailable:
        return False


def _hmac_key(db: Database) -> bytes:
    """The secret that keys the token HMAC: random, stored encrypted, created on first use."""
    global _key
    with _lock:
        if _key and _key[0] == id(db) and _key[1] == config.master_key:
            return _key[2]
    f = crypto()
    with db.session() as s:
        row = s.get(Secret, "token_hmac")
        if row is None:
            try:
                s.add(Secret(name="token_hmac", ciphertext=f.encrypt(secrets.token_hex(32).encode()).decode()))
                s.flush()
            except IntegrityError:
                s.rollback()
            row = s.get(Secret, "token_hmac")
        try:
            key = bytes.fromhex(f.decrypt(row.ciphertext.encode()).decode())
        except InvalidToken:
            raise VaultUnavailable("PII_MASTER_KEY does not match the key the vault was created with.") from None
    with _lock:
        _key = (id(db), config.master_key, key)
    return key


def _normalise(value: str) -> str:
    return " ".join(value.split()).casefold()


def token_for(scope: str, entity: str, value: str, db: Database | None = None) -> str:
    """The token for a value (stored in the vault on first sight). Returns it without the angle brackets."""
    db = db or get_db()
    digest = hmac.new(_hmac_key(db), f"{scope}\x00{entity}\x00{_normalise(value)}".encode(), hashlib.sha256).hexdigest()
    for _ in range(3):
        with db.session() as s:
            row = s.scalar(select(VaultEntry).where(VaultEntry.scope == scope, VaultEntry.value_hash == digest))
            if row is not None:
                return row.token
            taken = set(s.scalars(select(VaultEntry.token).where(VaultEntry.scope == scope,
                                                                 VaultEntry.token.like(f"{entity}_{digest[:8]}%"))))
            token = next(f"{entity}_{digest[:n]}" for n in (8, 12, 16, 64) if f"{entity}_{digest[:n]}" not in taken)
            try:
                s.add(VaultEntry(scope=scope, token=token, entity_type=entity, value_hash=digest,
                                 value_encrypted=crypto().encrypt(value.encode()).decode()))
                s.flush()
                return token
            except IntegrityError:               # another request stored the same value a moment ago: use theirs
                s.rollback()
    raise RuntimeError("could not store a personal-data value")


def lookup(scope: str, tokens, db: Database | None = None) -> dict[str, str]:
    """{token: real value} for the given tokens of one scope (unknown tokens are absent)."""
    tokens = list(set(tokens))
    if not tokens:
        return {}
    db = db or get_db()
    f = crypto()
    out = {}
    with db.session() as s:
        for i in range(0, len(tokens), 500):
            for t, v in s.execute(select(VaultEntry.token, VaultEntry.value_encrypted)
                                  .where(VaultEntry.scope == scope, VaultEntry.token.in_(tokens[i:i + 500]))):
                try:
                    out[t] = f.decrypt(v.encode()).decode()
                except InvalidToken:
                    raise VaultUnavailable("PII_MASTER_KEY does not match the key the vault was created with.") from None
    return out


def tokens_in(text: str) -> set[str]:
    return {m.group(1) for m in TOKEN_RE.finditer(text or "")}


def stats(db: Database | None = None) -> list[dict]:
    db = db or get_db()
    with db.session() as s:
        rows = s.execute(select(VaultEntry.scope, VaultEntry.entity_type, func.count())
                         .group_by(VaultEntry.scope, VaultEntry.entity_type)).all()
    out: dict = {}
    for scope, entity, n in rows:
        out.setdefault(scope, {})[entity] = n
    return [{"scope": k, "counts": v, "total": sum(v.values())} for k, v in sorted(out.items())]


def purge(scope: str, db: Database | None = None) -> int:
    """Delete every value of a scope. Its tokens can no longer be unmasked."""
    db = db or get_db()
    with db.session() as s:
        n = s.scalar(select(func.count()).select_from(VaultEntry).where(VaultEntry.scope == scope)) or 0
        s.execute(delete(VaultEntry).where(VaultEntry.scope == scope))
    return n
