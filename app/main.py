"""The HTTP API.

Text:  POST /v1/mask, /v1/tokenise, /v1/unmask
Files: POST /v1/files/mask, /v1/files/tokenise, /v1/files/unmask (same file type back; summary in X-PII-Summary)
Admin: /v1/admin/settings, /v1/admin/custom-types, /v1/admin/fields, /v1/admin/keys, /v1/admin/audit, /v1/admin/vault
GET /healthz needs no key.

Every call is checked against the caller's key (permission, scope, rate limit) and written to the audit log with its
counts by type, never values. Fail closed: if detection or the vault errors, the caller gets an error and no text.
"""
import json
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import text

from app import __version__, audit, auth, detect, files, policy, vault
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
              description="Mask, tokenise and unmask personal data in text and files.")


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
    scope: str | None = Field(None, description="Namespace for tokens; defaults to the key's first scope.")
    options: Options | None = None


class UnmaskIn(BaseModel):
    text: str
    scope: str | None = None


class KeyIn(BaseModel):
    name: str
    permissions: list[str]
    scopes: list[str]
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
            audit.record(caller, operation, "", 403, detail="permission")
            raise HTTPException(403, f"This key does not have the '{permission}' permission.")
        wait = auth.allow(caller)
        if wait:
            audit.record(caller, operation, "", 429, detail="rate limit")
            raise HTTPException(429, "Rate limit reached for this key.", headers={"Retry-After": str(int(wait) + 1)})
        return caller
    return dep


class Failed(Exception):
    def __init__(self, status: int, message: str, kind: str):
        self.status, self.message, self.kind = status, message, kind


def _run(caller: auth.Caller, operation: str, scope: str, work, counts=lambda: {}):
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
    except vault.VaultUnavailable as e:
        status, detail = 503, "vault unavailable"
        raise HTTPException(503, str(e)) from None
    except ValueError as e:
        status, detail = 400, "invalid request"
        raise HTTPException(400, str(e)) from None
    except Exception as e:
        status, detail = 500, f"error: {type(e).__name__}"
        log.error("%s failed: %s", operation, type(e).__name__, exc_info=True)
        raise HTTPException(500, "Personal-data processing failed, so nothing was returned. Try again; if it keeps "
                                 "failing, check the service log.") from None
    finally:
        audit.record(caller, operation, scope, status, counts() if status == 200 else {}, detail,
                     int((time.monotonic() - started) * 1000))


def _scope(caller: auth.Caller, requested: str | None) -> str:
    try:
        return caller.scope(requested)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


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


# ---- text ----------------------------------------------------------------------------------------------------------------------
def _text_op(mode: str, body: TextIn, caller: auth.Caller) -> dict:
    _check_length(body.text)
    scope = _scope(caller, body.scope) if mode == "tokenise" else (body.scope or "")
    p = _resolve(body.options)
    r = Redactor(mode, p, scope)

    def work():
        new, changes = r.run(body.text)
        findings = [{"type": c.entity_type, "start": c.start, "end": c.end, "score": c.score,
                     "replacement": c.replacement} for c in changes]
        out = {"text": new, "findings": findings, **r.summary()}
        if mode == "tokenise":
            out["scope"] = scope
        return out, ""
    return _run(caller, mode, scope, work, lambda: dict(r.counts))


@app.post("/v1/mask", tags=["text"], summary="Replace personal data with labels such as <EMAIL_ADDRESS> (one-way)")
def mask(body: TextIn, caller: auth.Caller = Depends(require("mask", "mask"))):
    return _text_op("mask", body, caller)


@app.post("/v1/tokenise", tags=["text"], summary="Replace personal data with reversible tokens; values go to the vault")
def tokenise(body: TextIn, caller: auth.Caller = Depends(require("tokenise", "tokenise"))):
    return _text_op("tokenise", body, caller)


@app.post("/v1/unmask", tags=["text"], summary="Put the real values back for tokens of one scope")
def unmask(body: UnmaskIn, caller: auth.Caller = Depends(require("unmask", "unmask"))):
    _check_length(body.text)
    scope = _scope(caller, body.scope)
    r = Redactor("unmask", None, scope)

    def work():
        new, _ = r.run(body.text)
        return {"text": new, "scope": scope, **r.summary()}, ""
    return _run(caller, "unmask", scope, work, lambda: dict(r.counts))


# ---- files -------------------------------------------------------------------------------------------------------------------
def _file_op(mode: str, upload: UploadFile, scope_in: str | None, options: str | None, caller: auth.Caller) -> Response:
    limit = config.max_upload_mb * 1024 * 1024
    data = upload.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"Files are limited to {config.max_upload_mb} MB.")
    if not data:
        raise HTTPException(400, "The file is empty.")
    name = upload.filename or "file"
    scope = _scope(caller, scope_in) if mode in ("tokenise", "unmask") else (scope_in or "")
    p = None
    if mode != "unmask":
        try:
            raw = json.loads(options) if options else None
        except json.JSONDecodeError:
            raise HTTPException(400, "options must be a JSON object.") from None
        if raw is not None and not isinstance(raw, dict):
            raise HTTPException(400, "options must be a JSON object.")
        p = _resolve(raw)
    r = Redactor(mode, p, scope)

    def work():
        out, media, extra = files.process(name, data, r)
        summary = {**r.summary(), **extra}
        stem, _, ext = name.rpartition(".")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", stem or "file")[:100]
        suffix = {"mask": "masked", "tokenise": "tokenised", "unmask": "unmasked"}[mode]
        headers = {"Content-Disposition": f'attachment; filename="{safe}.{suffix}.{ext or extra["file_type"]}"',
                   "X-PII-Summary": json.dumps(summary, separators=(",", ":")),
                   "Access-Control-Expose-Headers": "X-PII-Summary"}
        return Response(out, media_type=media, headers=headers), f"{extra['file_type']} {len(data)} bytes"
    return _run(caller, f"file_{mode}", scope, work, lambda: dict(r.counts))


@app.post("/v1/files/mask", tags=["files"], summary="Same file type back with personal data replaced by labels")
def file_mask(file: UploadFile = File(...), scope: str | None = Form(None), options: str | None = Form(None),
              caller: auth.Caller = Depends(require("mask", "file_mask"))):
    return _file_op("mask", file, scope, options, caller)


@app.post("/v1/files/tokenise", tags=["files"], summary="Same file type back with personal data replaced by tokens")
def file_tokenise(file: UploadFile = File(...), scope: str | None = Form(None), options: str | None = Form(None),
                  caller: auth.Caller = Depends(require("tokenise", "file_tokenise"))):
    return _file_op("tokenise", file, scope, options, caller)


@app.post("/v1/files/unmask", tags=["files"], summary="Put real values back into a tokenised file (not PDF)")
def file_unmask(file: UploadFile = File(...), scope: str | None = Form(None),
                caller: auth.Caller = Depends(require("unmask", "file_unmask"))):
    return _file_op("unmask", file, scope, None, caller)


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
        audit.record(caller, operation, "", status, duration_ms=int((time.monotonic() - started) * 1000))


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
        info, key = auth.create(body.name, body.permissions, body.scopes, body.rate_limit, caller.name)
        return {**info, "key": key}
    return admin_op(caller, "admin_keys_create", fn)


@app.patch("/v1/admin/keys/{key_id}", tags=["admin"], summary="Change a key's permissions, scopes or rate limit")
def change_key(key_id: int, body: dict[str, Any], caller: auth.Caller = Depends(require("admin", "admin_keys_update"))):
    return admin_op(caller, "admin_keys_update", lambda: auth.update(key_id, body))


@app.delete("/v1/admin/keys/{key_id}", tags=["admin"], summary="Revoke a key")
def remove_key(key_id: int, caller: auth.Caller = Depends(require("admin", "admin_keys_revoke"))):
    return admin_op(caller, "admin_keys_revoke", lambda: auth.revoke(key_id))


@app.get("/v1/admin/audit", tags=["admin"])
def get_audit(key: str | None = None, operation: str | None = None, since: datetime | None = None,
              limit: int = Query(100, ge=1, le=1000), caller: auth.Caller = Depends(require("admin", "admin_audit_read"))):
    return audit.entries(key, operation, since, limit)


@app.get("/v1/admin/vault", tags=["admin"], summary="How many values each scope holds, by type")
def get_vault(caller: auth.Caller = Depends(require("admin", "admin_vault_read"))):
    return vault.stats()


@app.delete("/v1/admin/vault/{scope}", tags=["admin"], summary="Delete every value of a scope")
def purge_vault(scope: str, caller: auth.Caller = Depends(require("admin", "admin_vault_purge"))):
    return admin_op(caller, "admin_vault_purge", lambda: {"scope": scope, "deleted": vault.purge(scope)})


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
            "version": __version__, "detector": state, "database": db_ok, "vault": vault.available(),
            "ocr": tessdata() is not None}
    return JSONResponse(body, status_code=200 if body["status"] != "error" else 503)


@app.exception_handler(Exception)
async def unexpected(_request: Request, exc: Exception):
    log.error("unexpected error: %s", type(exc).__name__, exc_info=True)
    return JSONResponse({"detail": "Internal error."}, status_code=500)
