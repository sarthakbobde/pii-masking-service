"""The HTTP API (masking only: nothing here can put a hidden value back).

CMS:   POST /api/v1/documents/mask, GET .../{job_id}/status, GET .../{job_id}/download (ContractAI and CMS spec, A.8)
Text:  POST /v1/mask
Files: POST /v1/files/mask (same file type back; summary in X-PII-Summary)
Admin: /v1/admin/overview, check, settings, custom-types, fields, keys, audit
GET /healthz needs no key.

Every call is checked against the caller's key (permission, rate limit) and written to the audit log with its counts by type,
never values. Fail closed: if detection errors, the caller gets an error and no text or file. Errors under /api/v1/ use the
specification's format: {"error": {"code", "message", "details"}}.
"""
import base64
import json
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__, audit, auth, detect, files, jobs, policy
from app.config import config
from app.db import get_db, init_db
from app.files.pdf import UnsupportedFile, tessdata
from app.redact import Redactor

log = logging.getLogger("pii")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(level=config.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)
    db = init_db(config.database_url)
    policy.seed(db)
    auth.bootstrap(db)
    if config.warm_up:
        threading.Thread(target=detect.warm_up, name="warm-up", daemon=True).start()
    yield


app = FastAPI(title="PII masking service", version=__version__, lifespan=lifespan,
              description="Mask personal data in text and documents. Masking is one-way: nothing can be restored.")


# ---- requests and responses ---------------------------------------------------------------------------------------------
class RequestField(BaseModel):
    name: str = Field(..., description="A stored field (its values are added to) or a new name for this request only.")
    terms: list[str] = []
    labels: list[str] = []


class Options(BaseModel):
    """Per-request overrides of the service settings (allowed unless the admin switched them off)."""
    types: list[str] | None = None
    threshold: int | None = Field(None, description="Detection confidence in percent, 10 to 95.")
    mask_names: bool | None = None
    keywords: list[str] | None = None
    allow_list: list[str] | None = None
    fields: list[RequestField] | None = Field(None, description="Extra known values for this request, e.g. this client's name.")


class TermsChange(BaseModel):
    add: list[str] = []
    remove: list[str] = []


class TextIn(BaseModel):
    text: str
    options: Options | None = None


class KeyIn(BaseModel):
    name: str
    permissions: list[str]
    rate_limit: int | None = None


class PatternTest(BaseModel):
    pattern: str
    text: str


# ---- the caller ------------------------------------------------------------------------------------------------------------
def _key_from(authorization: str | None, x_api_key: str | None) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def require(permission: str, operation: str):
    def dep(authorization: str | None = Header(None), x_api_key: str | None = Header(None)) -> auth.Caller:
        caller = auth.authenticate(_key_from(authorization, x_api_key))
        if caller is None:
            raise HTTPException(401, "A valid API key is required (Authorization: Bearer <key> or X-API-Key).",
                                headers={"WWW-Authenticate": "Bearer"})
        if not caller.can(permission):
            audit.record(caller, operation, 403, detail="permission")
            raise HTTPException(403, f"This key does not have the '{permission}' permission.")
        wait = auth.allow(caller)
        if wait:
            audit.record(caller, operation, 429, detail="rate limit")
            raise HTTPException(429, "Rate limit reached for this key.", headers={"Retry-After": str(int(wait) + 1)})
        return caller
    return dep


def _run(caller: auth.Caller, operation: str, work, counts=lambda: {}):
    """Run one operation, audit it, and turn errors into HTTP answers (nothing partial is ever returned)."""
    started = time.monotonic()
    status, detail = 200, ""
    try:
        result, detail = work()
        return result
    except HTTPException as e:
        status, detail = e.status_code, "rejected"
        raise
    except UnsupportedFile as e:
        status, detail = 415, "unsupported file"
        raise HTTPException(415, str(e)) from None
    except PermissionError as e:
        status, detail = 403, "permission"
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        status, detail = 400, "invalid request"
        raise HTTPException(400, str(e)) from None
    except Exception as e:
        status, detail = 500, f"error: {type(e).__name__}"
        log.error("%s failed: %s", operation, type(e).__name__, exc_info=True)
        raise HTTPException(500, "Personal-data processing failed, so nothing was returned. Try again; if it keeps "
                                 "failing, check the service log.") from None
    finally:
        audit.record(caller, operation, status, counts() if status == 200 else {}, detail,
                     int((time.monotonic() - started) * 1000))


def _check_length(text: str) -> None:
    if len(text) > config.max_text_chars:
        raise HTTPException(413, f"Text is longer than {config.max_text_chars} characters.")


def _resolve(options: Options | dict | None):
    raw = options.model_dump(exclude_none=True) if isinstance(options, Options) else (options or {})
    try:
        return policy.resolve(raw)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


# ---- CMS: mask a document (specification A.8) -------------------------------------------------------------------------------
class ApiError(Exception):
    """An error in the specification's format: {"error": {"code", "message", "details"}}."""

    def __init__(self, status: int, code: str, message: str, details=None, headers: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.details, self.headers = status, code, message, details, headers


CMS_TYPES = ("docx", "pdf")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\- ]{0,99}$")
CODES = {400: "VALIDATION_ERROR", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED",
         413: "PAYLOAD_TOO_LARGE", 415: "UNSUPPORTED_MEDIA_TYPE", 422: "VALIDATION_ERROR", 429: "RATE_LIMITED",
         503: "SERVICE_UNAVAILABLE"}
CMS_MAX = "50 MB"


def _error_response(status: int, code: str, message: str, details=None, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, "details": details}}, status_code=status, headers=headers)


def _output_name(original: str, requested: str | None, ext: str) -> str:
    """CMS's output_filename (or <original>_Masked.<ext>), made safe for a download header."""
    stem = original.rpartition(".")[0] or original
    name = (requested or "").strip() or f"{stem}_Masked.{ext}"
    name = re.sub(r"[^A-Za-z0-9._ ()\-]+", "_", name.replace("\\", "/").rsplit("/", 1)[-1]).strip(" .")
    name = name or f"document_Masked.{ext}"
    return (name if name.lower().endswith("." + ext) else f"{name}.{ext}")[:150]


def _cms_mask(caller: auth.Caller, upload: UploadFile | None, contract_id: str | None, version: str | None,
              output_filename: str | None) -> jobs.Job:
    for field, value in (("contract_id", contract_id), ("version", version)):
        if not (value or "").strip():
            raise ApiError(400, "VALIDATION_ERROR", f"{field} is required")
        if not ID_RE.match(value.strip()):
            raise ApiError(400, "VALIDATION_ERROR", f"{field} may hold up to 100 letters, digits, spaces and . _ : -")
    if upload is None or not (upload.filename or "").strip():
        raise ApiError(400, "VALIDATION_ERROR", "A file is required")
    limit = config.max_upload_mb * 1024 * 1024
    data = upload.file.read(limit + 1)
    if len(data) > limit:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", f"File exceeds maximum allowed size of {config.max_upload_mb} MB")
    if not data:
        raise ApiError(400, "EMPTY_FILE", "Uploaded file is empty")
    name = upload.filename.strip()
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in CMS_TYPES:
        raise ApiError(400, "UNSUPPORTED_MEDIA_TYPE",
                       f"File type .{ext or '(none)'} is not supported. Accepted: " + ", ".join("." + t for t in CMS_TYPES))
    try:
        p = policy.resolve(None)
        if not policy.protection_on():           # the admin switched PII protection off: the file is returned unchanged
            return jobs.Job(jobs.new_id(), caller.id, contract_id.strip(), version.strip(), name,
                            _output_name(name, output_filename, ext), files.MEDIA[ext], ext, data, {}, protection_off=True)
        r = Redactor(p)
        out, media, extra = files.process(name, data, r)
        original_text, _ = files.preview_text(ext, data, 50)
    except UnsupportedFile:
        raise ApiError(422, "UNREADABLE_DOCUMENT", "Document could not be read. It may be corrupt or password protected.") from None
    except HTTPException:
        raise
    except Exception as e:
        log.error("masking failed: %s", type(e).__name__, exc_info=True)
        if isinstance(e, (OSError, ImportError)) or detect.status() == "error":
            raise ApiError(503, "SERVICE_UNAVAILABLE", "ContractAI is temporarily unavailable. Try again shortly.") from None
        raise ApiError(500, "MASKING_FAILED", "Document could not be masked. Contact support with request timestamp.") from None
    if not original_text.strip() and not extra.get("ocr_pages"):
        raise ApiError(422, "UNREADABLE_DOCUMENT", "Document could not be read. It may be corrupt or have no extractable text.")
    return jobs.Job(jobs.new_id(), caller.id, contract_id.strip(), version.strip(), name,
                    _output_name(name, output_filename, ext), media, ext, out, dict(r.counts), pages=extra.get("pages"),
                    unprocessed_pages=extra.get("unprocessed_image_pages", []), ocr_pages=extra.get("ocr_pages", []))


@app.post("/api/v1/documents/mask", tags=["cms"],
          summary="Mask a document for CMS: multipart file, contract_id, version and optional output_filename")
def cms_submit(file: UploadFile | None = File(None), contract_id: str | None = Form(None), version: str | None = Form(None),
               output_filename: str | None = Form(None), caller: auth.Caller = Depends(require("mask", "cms_mask"))):
    started = time.monotonic()
    status, detail, counts = 200, "", {}
    try:
        job = _cms_mask(caller, file, contract_id, version, output_filename)
        jobs.store.put(job)
        counts, detail = job.counts, f"{job.file_type} {len(job.content)} bytes, contract {job.contract_id}"
        return job.status()
    except ApiError as e:
        status, detail = e.status, e.code
        raise
    except Exception:
        status, detail = 500, "error"
        raise
    finally:
        audit.record(caller, "cms_mask", status, counts, detail, int((time.monotonic() - started) * 1000))


def _job_or_404(job_id: str, caller: auth.Caller) -> jobs.Job:
    job = jobs.store.get(job_id, caller.id)
    if job is None:
        raise ApiError(404, "JOB_NOT_FOUND", f"No job found with id {job_id[:60]}")
    return job


@app.get("/api/v1/documents/mask/{job_id}/status", tags=["cms"], summary="The masking status and summary (counts, field types)")
def cms_status(job_id: str, caller: auth.Caller = Depends(require("mask", "cms_status"))):
    return _job_or_404(job_id, caller).status()


@app.get("/api/v1/documents/mask/{job_id}/download", tags=["cms"], summary="The masked file, in the format that was uploaded")
def cms_download(job_id: str, caller: auth.Caller = Depends(require("mask", "cms_download"))):
    job = _job_or_404(job_id, caller)
    audit.record(caller, "cms_download", 200, detail=f"contract {job.contract_id}")
    headers = {"Content-Disposition": f'attachment; filename="{job.output_filename}"', "X-Contract-Id": job.contract_id,
               "X-Version": job.version, "X-Original-Filename": quote(job.original_filename, safe=" ._-()"),
               "X-Masked-Fields-Count": str(job.masked_fields_count),
               "Access-Control-Expose-Headers": "X-Contract-Id, X-Version, X-Original-Filename, X-Masked-Fields-Count"}
    if job.protection_off:
        headers["X-PII-Protection"] = "off"
    return Response(job.content, media_type=job.media_type, headers=headers)


# ---- text ----------------------------------------------------------------------------------------------------------------------
@app.post("/v1/mask", tags=["text"], summary="Replace personal data with labels such as <EMAIL_ADDRESS> (one-way)")
def mask(body: TextIn, caller: auth.Caller = Depends(require("mask", "mask"))):
    _check_length(body.text)
    r = Redactor(_resolve(body.options))
    off = not policy.protection_on()

    def work():
        if off:                                  # the admin switched PII protection off: nothing is changed
            return {"text": body.text, "findings": [], "counts": {}, "total": 0, "protection": "off"}, "protection off"
        new, changes = r.run(body.text)
        findings = [{"type": c.entity_type, "start": c.start, "end": c.end, "score": c.score,
                     "replacement": c.replacement} for c in changes]
        return {"text": new, "findings": findings, **r.summary()}, ""
    return _run(caller, "mask", work, lambda: dict(r.counts))


# ---- files -------------------------------------------------------------------------------------------------------------------
def _read_upload(upload: UploadFile) -> bytes:
    limit = config.max_upload_mb * 1024 * 1024
    data = upload.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"Files are limited to {config.max_upload_mb} MB.")
    if not data:
        raise HTTPException(400, "The file is empty.")
    return data


def _options_from_form(options: str | None) -> dict | None:
    try:
        raw = json.loads(options) if options else None
    except json.JSONDecodeError:
        raise HTTPException(400, "options must be a JSON object.") from None
    if raw is not None and not isinstance(raw, dict):
        raise HTTPException(400, "options must be a JSON object.")
    return raw


@app.post("/v1/files/mask", tags=["files"], summary="Same file type back with personal data replaced by labels")
def file_mask(file: UploadFile = File(...), options: str | None = Form(None),
              caller: auth.Caller = Depends(require("mask", "file_mask"))):
    data = _read_upload(file)
    name = file.filename or "file"
    r = Redactor(_resolve(_options_from_form(options)))
    off = not policy.protection_on()

    def work():
        if off:
            kind = files.kind_of(name)
            out, media, extra = data, files.MEDIA[kind], {"file_type": kind, "protection": "off"}
        else:
            out, media, extra = files.process(name, data, r)
        summary = {**r.summary(), **extra}
        stem, _, ext = name.rpartition(".")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", stem or "file")[:100]
        headers = {"Content-Disposition": f'attachment; filename="{safe}.masked.{ext or extra["file_type"]}"',
                   "X-PII-Summary": json.dumps(summary, separators=(",", ":")),
                   "Access-Control-Expose-Headers": "X-PII-Summary, X-PII-Protection"}
        if off:
            headers["X-PII-Protection"] = "off"
        return Response(out, media_type=media, headers=headers), f"{extra['file_type']} {len(data)} bytes"
    return _run(caller, "file_mask", work, lambda: dict(r.counts))


# ---- admin ------------------------------------------------------------------------------------------------------------------
def _admin_call(fn):
    try:
        return fn()
    except KeyError as e:
        raise HTTPException(404, e.args[0] if e.args else "Not found.") from None
    except LookupError as e:
        raise HTTPException(409, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


def admin_op(caller: auth.Caller, operation: str, fn):
    started = time.monotonic()
    status = 200
    try:
        return _admin_call(fn)
    except HTTPException as e:
        status = e.status_code
        raise
    finally:
        audit.record(caller, operation, status, duration_ms=int((time.monotonic() - started) * 1000))


@app.get("/v1/admin/overview", tags=["admin"], summary="Status, protection switch, counts and the last 24 hours")
def get_overview(caller: auth.Caller = Depends(require("admin", "admin_overview"))):
    all_keys = auth.list_keys()
    return {"health": json.loads(health().body), "protection_enabled": policy.protection_on(),
            "counts": {"active_keys": sum(k["active"] for k in all_keys), "fields": len(policy.fields()),
                       "fields_enabled": sum(f["enabled"] for f in policy.fields()),
                       "field_values": sum(len(f["terms"]) for f in policy.fields()),
                       "custom_types": len(policy.custom_types())},
            "last_24h": audit.summary(24),
            "limits": {"max_text_chars": config.max_text_chars, "max_upload_mb": config.max_upload_mb,
                       "default_rate_limit": config.default_rate_limit}}


@app.post("/v1/admin/check", tags=["admin"],
          summary="Check a document: what would be hidden, a text preview of the result and the masked file")
def check_document(file: UploadFile = File(...), options: str | None = Form(None),
                   caller: auth.Caller = Depends(require("admin", "admin_check"))):
    data = _read_upload(file)
    name = file.filename or "file"
    r = Redactor(_resolve(_options_from_form(options)))       # a check never stores anything, and always applies the settings

    def work():
        out, media, extra = files.process(name, data, r)
        preview, cut = files.preview_text(extra["file_type"], out)
        result = {"file": name, "media_type": media, "preview": preview, "preview_truncated": cut,
                  "masked_file": base64.b64encode(out).decode() if len(out) <= CHECK_FILE_LIMIT else None,
                  **r.summary(), **extra}
        return result, f"{extra['file_type']} {len(data)} bytes"
    return _run(caller, "admin_check", work, lambda: dict(r.counts))


@app.get("/v1/admin/settings", tags=["admin"])
def get_settings(caller: auth.Caller = Depends(require("admin", "admin_settings_read"))):
    return policy.view()


@app.put("/v1/admin/settings", tags=["admin"], summary="Change some or all settings")
def put_settings(body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_settings_update"))):
    return admin_op(caller, "admin_settings_update", lambda: policy.update(body, caller.name))


@app.get("/v1/admin/custom-types", tags=["admin"])
def get_custom(caller: auth.Caller = Depends(require("admin", "admin_types_read"))):
    return policy.custom_types()


@app.post("/v1/admin/custom-types", tags=["admin"], status_code=201)
def add_custom(body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_types_create"))):
    return admin_op(caller, "admin_types_create", lambda: policy.save_custom(body, caller.name))


@app.put("/v1/admin/custom-types/{type_id}", tags=["admin"])
def change_custom(type_id: int, body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_types_update"))):
    return admin_op(caller, "admin_types_update", lambda: policy.save_custom(body, caller.name, type_id))


@app.delete("/v1/admin/custom-types/{type_id}", tags=["admin"])
def remove_custom(type_id: int, caller: auth.Caller = Depends(require("admin", "admin_types_delete"))):
    return admin_op(caller, "admin_types_delete", lambda: policy.delete_custom(type_id, caller.name))


@app.post("/v1/admin/custom-types/test", tags=["admin"], summary="What a pattern would match in a sample (max 20)")
def test_pattern(body: PatternTest, caller: auth.Caller = Depends(require("admin", "admin_types_test"))):
    def fn():
        policy.check_custom({"name": "TRY_IT", "pattern": body.pattern})
        return {"matches": [m.group(0) for m in re.finditer(body.pattern, body.text[:10_000])][:20]}
    return _admin_call(fn)


@app.get("/v1/admin/fields", tags=["admin"], summary="The dictionary: every field with its values and labels")
def get_fields(caller: auth.Caller = Depends(require("admin", "admin_fields_read"))):
    return policy.fields()


@app.post("/v1/admin/fields", tags=["admin"], status_code=201,
          summary="Add a field: {name, description, terms, labels, enabled}")
def add_field(body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_fields_create"))):
    return admin_op(caller, "admin_fields_create", lambda: policy.save_field(body, caller.name))


@app.patch("/v1/admin/fields/{field_id}", tags=["admin"], summary="Change a field; terms or labels given replace the old ones")
def change_field(field_id: int, body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_fields_update"))):
    return admin_op(caller, "admin_fields_update", lambda: policy.save_field(body, caller.name, field_id))


@app.post("/v1/admin/fields/{field_id}/terms", tags=["admin"], summary="Add values to a field's dictionary or take some out")
def change_field_terms(field_id: int, body: TermsChange,
                       caller: auth.Caller = Depends(require("admin", "admin_fields_terms"))):
    return admin_op(caller, "admin_fields_terms", lambda: policy.change_terms(field_id, body.add, body.remove, caller.name))


@app.delete("/v1/admin/fields/{field_id}", tags=["admin"])
def remove_field(field_id: int, caller: auth.Caller = Depends(require("admin", "admin_fields_delete"))):
    return admin_op(caller, "admin_fields_delete", lambda: policy.delete_field(field_id))


@app.get("/v1/admin/keys", tags=["admin"])
def get_keys(caller: auth.Caller = Depends(require("admin", "admin_keys_read"))):
    return auth.list_keys()


@app.post("/v1/admin/keys", tags=["admin"], status_code=201, summary="Create a key; the key is in the answer, only this once")
def add_key(body: KeyIn, caller: auth.Caller = Depends(require("admin", "admin_keys_create"))):
    def fn():
        info, key = auth.create(body.name, body.permissions, body.rate_limit, caller.name)
        return {**info, "key": key}
    return admin_op(caller, "admin_keys_create", fn)


@app.patch("/v1/admin/keys/{key_id}", tags=["admin"], summary="Change a key's permissions or rate limit")
def change_key(key_id: int, body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_keys_update"))):
    return admin_op(caller, "admin_keys_update", lambda: auth.update(key_id, body))


@app.delete("/v1/admin/keys/{key_id}", tags=["admin"], summary="Revoke a key")
def remove_key(key_id: int, caller: auth.Caller = Depends(require("admin", "admin_keys_revoke"))):
    return admin_op(caller, "admin_keys_revoke", lambda: auth.revoke(key_id))


@app.get("/v1/admin/audit", tags=["admin"])
def get_audit(key: str | None = None, operation: str | None = None, since: datetime | None = None,
              limit: int = Query(100, ge=1, le=1000), caller: auth.Caller = Depends(require("admin", "admin_audit_read"))):
    return audit.entries(key, operation, since, limit)


# ---- health -------------------------------------------------------------------------------------------------------------------
@app.get("/healthz", tags=["health"])
def health():
    try:
        with get_db().session() as s:
            s.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    state = detect.status()
    body = {"status": "ok" if db_ok and state == "ready" else ("starting" if db_ok and state == "loading" else "error"),
            "version": __version__, "detector": state, "database": db_ok,
            "ocr": tessdata() is not None, "protection": policy.protection_on() if db_ok else None}
    return JSONResponse(body, status_code=200 if body["status"] != "error" else 503)


# ---- errors: the CMS API uses the specification's format -------------------------------------------------------------------
def _cms_path(request: Request) -> bool:
    return request.url.path.startswith("/api/v1/")


@app.exception_handler(ApiError)
async def api_error(_request: Request, exc: ApiError):
    return _error_response(exc.status, exc.code, exc.message, exc.details, exc.headers)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if not _cms_path(request):
        return await http_exception_handler(request, exc)
    code = CODES.get(exc.status_code, "INTERNAL_ERROR" if exc.status_code >= 500 else "VALIDATION_ERROR")
    return _error_response(exc.status_code, code, str(exc.detail), None, getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    if not _cms_path(request):
        return await request_validation_exception_handler(request, exc)
    first = exc.errors()[0] if exc.errors() else {}
    return _error_response(400, "VALIDATION_ERROR", f"{'.'.join(str(x) for x in first.get('loc', [])[1:])}: {first.get('msg', 'invalid')}")


@app.exception_handler(Exception)
async def unexpected(request: Request, exc: Exception):
    log.error("unexpected error: %s", type(exc).__name__, exc_info=True)
    if _cms_path(request):
        return _error_response(500, "INTERNAL_ERROR", "An unexpected error occurred. Contact support with request timestamp.")
    return JSONResponse({"detail": "Internal error."}, status_code=500)


# ---- the admin page ---------------------------------------------------------------------------------------------------------
# A static page: it holds no data, and every call it makes needs an admin key (kept in the browser tab only).
STATIC = Path(__file__).parent / "static"
CHECK_FILE_LIMIT = 8 * 1024 * 1024        # a checked file's masked copy is returned in the answer up to this size
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-cache",
}
ASSETS = {"admin.css": "text/css", "admin.js": "text/javascript", "favicon.svg": "image/svg+xml"}


@app.get("/admin", include_in_schema=False)
def admin_page():
    return FileResponse(STATIC / "index.html", media_type="text/html", headers=PAGE_HEADERS)


@app.get("/admin/assets/{name}", include_in_schema=False)
def admin_asset(name: str):
    if name not in ASSETS:
        raise HTTPException(404, "Not found.")
    return FileResponse(STATIC / name, media_type=ASSETS[name], headers=PAGE_HEADERS)
