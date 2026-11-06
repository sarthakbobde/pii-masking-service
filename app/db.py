"""Tables: API keys, settings, fields, custom types and the audit log. SQLite by default, any SQLAlchemy URL works."""
import os
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))                       # shown in listings to tell keys apart
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)        # SHA-256 of the whole key; the key is never stored
    permissions: Mapped[list] = mapped_column(JSON)
    scopes: Mapped[list] = mapped_column(JSON, default=lambda: ["*"])     # unused: kept so older databases still load
    rate_limit: Mapped[int] = mapped_column(Integer)                      # requests per minute
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    created_by: Mapped[str] = mapped_column(String(80), default="")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)
    updated_by: Mapped[str] = mapped_column(String(80), default="")


class CustomType(Base):
    __tablename__ = "custom_types"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(40), unique=True)
    pattern: Mapped[str] = mapped_column(String(300))
    context: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)
    updated_by: Mapped[str] = mapped_column(String(80), default="")


class Field(Base):
    """A dictionary entry: known values to mask wherever they appear, and labels whose following value is masked."""
    __tablename__ = "fields"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(40), unique=True)
    description: Mapped[str] = mapped_column(String(200), default="")
    terms: Mapped[list] = mapped_column(JSON, default=list)
    labels: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)
    updated_by: Mapped[str] = mapped_column(String(80), default="")


class AuditEntry(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    key_id: Mapped[int | None] = mapped_column(ForeignKey("api_keys.id"), nullable=True)
    key_name: Mapped[str] = mapped_column(String(80), default="")
    operation: Mapped[str] = mapped_column(String(40))
    scope: Mapped[str] = mapped_column(String(80), default="")
    status: Mapped[int] = mapped_column(Integer)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)              # {type: how many}, never values
    total: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str] = mapped_column(String(200), default="")          # file type and size, error kind
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)


class Database:
    def __init__(self, url: str):
        if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
            folder = os.path.dirname(url[len("sqlite:///"):])
            if folder:
                os.makedirs(folder, exist_ok=True)
        kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
        self.engine = create_engine(url, **kw)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def _pragmas(conn, _):
                cur = conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=5000")
                cur.close()
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self):
        s = self._sessions()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()


_db: Database | None = None


def init_db(url: str) -> Database:
    global _db
    _db = Database(url)
    return _db


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("the database is not initialised")
    return _db
