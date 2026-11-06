"""Masking jobs for the CMS API (A.8): the masked file waits here until CMS has downloaded it.

Only the masked result is kept, never the original file. Jobs live in this process's memory and are dropped after
`PII_JOB_TTL_MINUTES`, or earlier when the total size passes `PII_JOB_MAX_MB` (oldest first). A job id is random (96 bits), so it cannot be
guessed. With several workers or replicas, route status and download calls to the worker that took the upload
(or put the service behind session affinity); a restart drops every job, and CMS then submits the file again.
"""
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.config import config


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Job:
    id: str
    contract_id: str
    version: str
    original_filename: str
    output_filename: str
    media_type: str
    file_type: str
    content: bytes
    counts: dict
    pages: int | None = None
    unprocessed_pages: list = field(default_factory=list)
    ocr_pages: list = field(default_factory=list)
    protection_off: bool = False
    created_at: str = field(default_factory=_now)
    completed_at: str = field(default_factory=_now)
    expires: float = 0.0

    @property
    def masked_fields_count(self) -> int:
        return sum(self.counts.values())

    def status(self) -> dict:
        """The job as CMS sees it (no file content)."""
        out = {
            "job_id": self.id, "contract_id": self.contract_id, "version": self.version, "status": "completed",
            "original_filename": self.original_filename, "output_filename": self.output_filename,
            "content_type": self.media_type, "file_size_bytes": len(self.content),
            "masked_fields_count": self.masked_fields_count, "field_types": dict(sorted(self.counts.items())),
            "pages": self.pages, "unprocessed_pages": self.unprocessed_pages, "ocr_pages": self.ocr_pages,
            "created_at": self.created_at, "completed_at": self.completed_at,
            "download_url": f"/api/v1/documents/mask/{self.id}/download", "error_message": None, "error_code": None,
        }
        if self.protection_off:
            out["protection"] = "off"
        return out


class JobStore:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def put(self, job: Job) -> Job:
        job.expires = time.monotonic() + config.job_ttl_minutes * 60
        with self._lock:
            self._drop_expired()
            self._jobs[job.id] = job
            limit = config.job_max_mb * 1024 * 1024
            while len(self._jobs) > 1 and sum(len(j.content) for j in self._jobs.values()) > limit:
                del self._jobs[next(iter(self._jobs))]                    # oldest first, never the one just added
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            self._drop_expired()
            job = self._jobs.get(job_id)
        return job

    def _drop_expired(self) -> None:
        now = time.monotonic()
        for jid in [j for j, job in self._jobs.items() if job.expires <= now]:
            del self._jobs[jid]

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()


def new_id() -> str:
    return "mask-" + secrets.token_hex(12)


store = JobStore()
