"""The audit log: who called what, in which scope, how it went and how many values of each type. Never a value."""
import logging
from datetime import datetime

from sqlalchemy import select

from app.db import AuditEntry, Database, get_db

log = logging.getLogger(__name__)


def record(caller, operation: str, scope: str, status: int, counts: dict | None = None, detail: str = "",
           duration_ms: int = 0, db: Database | None = None) -> None:
    counts = dict(counts or {})
    try:
        with (db or get_db()).session() as s:
            s.add(AuditEntry(key_id=getattr(caller, "id", None), key_name=getattr(caller, "name", "") or "",
                             operation=operation, scope=scope or "", status=status, counts=counts,
                             total=sum(counts.values()), detail=detail[:200], duration_ms=duration_ms))
    except Exception:
        log.warning("could not write an audit entry", exc_info=True)


def entries(key_name: str | None = None, operation: str | None = None, since: datetime | None = None, limit: int = 100,
            db: Database | None = None) -> list[dict]:
    q = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(max(1, min(limit, 1000)))
    if key_name:
        q = q.where(AuditEntry.key_name == key_name)
    if operation:
        q = q.where(AuditEntry.operation == operation)
    if since:
        q = q.where(AuditEntry.at >= since)
    with (db or get_db()).session() as s:
        return [{"id": e.id, "at": e.at, "key": e.key_name, "operation": e.operation, "scope": e.scope, "status": e.status,
                 "counts": e.counts, "total": e.total, "detail": e.detail, "duration_ms": e.duration_ms}
                for e in s.scalars(q)]
