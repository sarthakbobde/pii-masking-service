"""The audit log: who called what, in which scope, how it went and how many values of each type. Never a value."""
import logging
from datetime import datetime, timedelta

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


def summary(hours: int = 24, db: Database | None = None) -> dict:
    """Calls, values hidden and errors in the last `hours` hours, by type and operation (never values)."""
    since = datetime.utcnow() - timedelta(hours=hours)
    by_type: dict = {}
    by_op: dict = {}
    calls = values = errors = 0
    with (db or get_db()).session() as s:
        for e in s.scalars(select(AuditEntry).where(AuditEntry.at >= since).limit(50_000)):
            calls += 1
            errors += e.status >= 400
            by_op[e.operation] = by_op.get(e.operation, 0) + 1
            if e.operation.split("_")[-1] in ("mask", "tokenise") and e.status == 200:
                values += e.total
                for t, n in (e.counts or {}).items():
                    by_type[t] = by_type.get(t, 0) + n
    top = sorted(by_type.items(), key=lambda kv: -kv[1])[:10]
    return {"hours": hours, "calls": calls, "values": values, "errors": errors, "by_type": dict(top),
            "by_operation": dict(sorted(by_op.items(), key=lambda kv: -kv[1]))}


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
