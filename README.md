# PII masking service (masking only)

A standalone HTTP API that finds personal data in text and documents and **masks** it: values are replaced by labels such
as `<EMAIL_ADDRESS>`, in the same file format. **Masking is one-way.** This branch has no unmask or decrypt endpoint, no
reversible tokens and no vault, so the original values are not kept anywhere and nothing can put them back.

It includes the document-masking API from the *ContractAI and CMS Integration API Specification* (section A.8), plus a
general text and file API and an admin page for configuring what to hide.

Detection uses Microsoft Presidio with spaCy (`en_core_web_sm`). It covers:
- **built-in types**: email, phone, cards, SSN, Aadhaar, PAN, GSTIN, CIN, IBAN and more;
- **regular-expression types** you define;
- **a dictionary of fields** you maintain: known values such as your company's or a client's name, address or signatory,
  and labels such as "Client Name:" whose value is masked as that field;
- **sensitive keywords**: the value after "Salary:", "DOB" and similar keywords is masked whatever its format.

---

## Contents
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Who can call what](#who-can-call-what)
- [CMS API: mask a document](#cms-api-mask-a-document)
- [Text and file masking](#text-and-file-masking)
- [The admin page](#the-admin-page)
- [Admin API](#admin-api)
- [Fields: the dictionary of values to hide](#fields-the-dictionary-of-values-to-hide)
- [Settings and per-request options](#settings-and-per-request-options)
- [What is covered in each file type](#what-is-covered-in-each-file-type)
- [Security and deployment notes](#security-and-deployment-notes)
- [Tests](#tests)

---

## Quick start

Requires Python 3.11.

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; on Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
```

No configuration is needed to start. To reach the admin page from another computer, create a `.env` (see `.env.example`)
with an admin key: `PII_ADMIN_KEY=<a random string of 24+ characters>`.

Run it:

```bash
uvicorn app.main:app --port 8000
```

The detector loads in the background at start-up (about 10 to 20 s). `GET /healthz` reports `starting` until it is ready.
Interactive API docs are at http://localhost:8000/docs and the admin page is at http://localhost:8000/admin.

With Docker:

```bash
cp .env.example .env              # optional: set PII_ADMIN_KEY
docker compose up -d --build
```

The image includes English OCR data for scanned PDFs, runs as a non-root user and keeps its SQLite database in the `pii-data`
volume. `docker build --target test .` runs the test suite inside the image.

## Configuration

Environment variables (or `.env`):

| Variable | Default | Meaning |
|---|---|---|
| `PII_ADMIN_KEY` | (none) | Protects the admin page and API (at least 24 characters). Without it they answer only from the server itself. The masking API never needs a key. |
| `PII_DATABASE_URL` | `sqlite:///./data/pii.db` | Any SQLAlchemy URL. For PostgreSQL, install a driver (`psycopg`) and use `postgresql+psycopg://...`. |
| `PII_SETTINGS_FILE` | (none) | JSON that seeds the settings and fields on **first** start; see `settings.example.json`. |
| `PII_MAX_UPLOAD_MB` | `50` | Largest document accepted (the specification's limit is 50 MB). |
| `PII_MAX_TEXT_CHARS` | `200000` | Longest text accepted by `/v1/mask`. |
| `PII_JOB_TTL_MINUTES` | `60` | How long a masked CMS document waits to be downloaded. |
| `PII_JOB_MAX_MB` | `500` | Total size of masked documents held at once; the oldest go first. |
| `PII_WARM_UP` | `true` | Load the detector at start-up rather than on the first request. |
| `PII_TESSDATA_DIR` | (auto) | Tesseract language data for OCR of scanned PDFs. |
| `PII_LOG_LEVEL` | `INFO` | |

## Who can call what

**The masking API needs no key.** The CMS specification (A.8) lists no authentication, so `POST /api/v1/documents/mask`,
its status and download, `POST /v1/mask` and `POST /v1/files/mask` answer anyone who can reach the service. That makes
network placement the protection: run it where only CMS can reach it (a private network, or behind your API gateway or
reverse proxy, which can add authentication and rate limiting if you want them).

**The admin page and admin API are protected**, because they change what is hidden and can switch masking off:
- With `PII_ADMIN_KEY` set, send it as `Authorization: Bearer <key>` or `X-API-Key: <key>`. The admin page asks for it.
- Without it, they answer only requests that come from the server itself (loopback). A request that carries proxy headers
  (`X-Forwarded-For`, `Forwarded`, ...) is not treated as local, so a reverse proxy on the same machine does not open the
  admin page to the world. Elsewhere you get `403` with instructions.

Every call is written to the audit log: time, caller address (or `admin`), operation, HTTP status, counts by type, and for the
CMS API the contract id. Values are never logged.

## CMS API: mask a document

Implements specification section A.8. CMS sends a `.docx` or `.pdf` with its contract id and version; the service masks the
sensitive fields defined in the [fields dictionary](#fields-the-dictionary-of-values-to-hide) and returns the masked file
in the same format. **The original file is not stored.** Only the masked result is held, in memory, until it is downloaded
or expires.

### `POST /api/v1/documents/mask`

`multipart/form-data`:

| Field | Required | Description |
|---|---|---|
| `file` | Yes | The document: `.docx` or `.pdf`, up to 50 MB |
| `contract_id` | Yes | CMS contract the file belongs to |
| `version` | Yes | Contract version the file belongs to |
| `output_filename` | No | Name of the masked file. Defaults to `<original_filename>_Masked.<ext>` |

```bash
curl -s localhost:8000/api/v1/documents/mask \
  -F file=@ACME_MSA_2026.docx -F contract_id=CMS-CONTRACT-12345 -F version=2.0 -F output_filename=ACME_MSA_20.docx
```

The masking is done before the answer is sent, so the job is already complete:

```json
{
  "job_id": "mask-2c8f3a56afdb", "contract_id": "CMS-CONTRACT-12345", "version": "2.0", "status": "completed",
  "original_filename": "ACME_MSA_2026.docx", "output_filename": "ACME_MSA_20.docx",
  "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "file_size_bytes": 38112,
  "masked_fields_count": 12, "field_types": {"CLIENT_COMPANY_NAME": 4, "COMPANY_NAME": 4, "IN_GSTIN": 2, "IN_PAN": 2},
  "pages": null, "unprocessed_pages": [], "ocr_pages": [],
  "created_at": "2026-11-05T09:20:00Z", "completed_at": "2026-11-05T09:20:02Z",
  "download_url": "/api/v1/documents/mask/mask-2c8f3a56afdb/download", "error_message": null, "error_code": null
}
```

### `GET /api/v1/documents/mask/{job_id}/status`

The same JSON: the status and the masking summary (counts and field types). Never any value.

### `GET /api/v1/documents/mask/{job_id}/download`

The masked file as binary content, in the format that was uploaded.

| Header | Value |
|---|---|
| `Content-Disposition` | `attachment; filename="ACME_MSA_20.docx"` |
| `X-Contract-Id` | `CMS-CONTRACT-12345` |
| `X-Version` | `2.0` |
| `X-Original-Filename` | `ACME_MSA_2026.docx` (percent-encoded if it has non-ASCII characters) |
| `X-Masked-Fields-Count` | `12` |

A job can be downloaded any number of times until it expires. The job id is random (96 bits), so it cannot be guessed.

### Errors

Under `/api/v1/` every error has the specification's format:

```json
{"error": {"code": "VALIDATION_ERROR", "message": "version is required", "details": null}}
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | `contract_id` or `version` missing or malformed, or no file attached |
| 400 | `EMPTY_FILE` | The file has zero bytes |
| 400 | `UNSUPPORTED_MEDIA_TYPE` | Not `.docx` or `.pdf` |
| 413 | `PAYLOAD_TOO_LARGE` | Over the size limit |
| 422 | `UNREADABLE_DOCUMENT` | Corrupt, password protected, or no extractable text |
| 500 | `MASKING_FAILED` | Masking could not be completed. **No file is returned** |
| 500 | `INTERNAL_ERROR` | Unexpected failure |
| 503 | `SERVICE_UNAVAILABLE` | The detector is not available |
| 404 | `JOB_NOT_FOUND` | No such job, or it has expired |
| 404, 405 | `NOT_FOUND`, `METHOD_NOT_ALLOWED` | A path or method that does not exist under `/api/v1/` |

Not in the specification, and worth knowing:
- **Fails closed.** If detection breaks, CMS gets `MASKING_FAILED` and no file, never a partly masked one.
- **Scanned PDF pages.** A page that is only an image is read with OCR when Tesseract language data is installed. Without
  it the page is left as it is and listed in `unprocessed_pages`. A PDF with no readable text at all is refused as
  `UNREADABLE_DOCUMENT`. Check `unprocessed_pages` if your PDFs can contain scans.
- **Jobs live in memory.** A restart drops them (CMS submits again), and with several workers or replicas the status and
  download calls must reach the worker that took the upload. Use session affinity, or run one worker.
- **PII protection switch.** If an admin has switched protection off, the file comes back unchanged and the response says
  `"protection": "off"` (header `X-PII-Protection: off`).
- Section A.7 (combining supporting documents into one PDF) is a separate service and is not part of this one.

## Text and file masking

### `POST /v1/mask`

```bash
curl -s localhost:8000/v1/mask -H "Content-Type: application/json" \
  -d '{"text": "Mail john.doe@acme.com or call +91 98765 43210. Salary: 12,40,000."}'
```

```json
{
  "text": "Mail <EMAIL_ADDRESS> or call <PHONE_NUMBER>. Salary: <SENSITIVE_VALUE>.",
  "findings": [
    {"type": "EMAIL_ADDRESS", "start": 5, "end": 22, "score": 1.0, "replacement": "<EMAIL_ADDRESS>"},
    {"type": "PHONE_NUMBER", "start": 31, "end": 46, "score": 0.4, "replacement": "<PHONE_NUMBER>"},
    {"type": "SENSITIVE_VALUE", "start": 56, "end": 65, "score": 0.85, "replacement": "<SENSITIVE_VALUE>"}
  ],
  "counts": {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1, "SENSITIVE_VALUE": 1},
  "total": 3
}
```

`start` and `end` are offsets in the **input** text. Responses never echo the values. An optional `options` object overrides
[settings](#settings-and-per-request-options) for the one request.

### `POST /v1/files/mask`

Multipart `file` (and optional `options` as a JSON string). The response is the masked file, of the same type (PDF, DOCX,
PPTX, XLSX, CSV, TXT, Markdown), named `<name>.masked.<ext>`. What was found is in the `X-PII-Summary` header.

```bash
curl -s localhost:8000/v1/files/mask -F file=@report.pdf -D headers.txt -o report.masked.pdf
```

### `GET /healthz` (no key)

```json
{"status": "ok", "version": "0.1.0", "detector": "ready", "database": true, "ocr": true, "protection": true}
```

`status` is `starting` while the detector loads, and `error` (HTTP 503) if the detector or database fails.

## The admin page

Open **`/admin`**. On the server itself it opens straight away; from elsewhere it asks for the admin key (`PII_ADMIN_KEY`), which
stays in the browser tab only. It is plain
HTML, CSS and JavaScript served by the service, with a strict content security policy.

| Screen | What an admin can do |
|---|---|
| **Overview** | See the **PII protection switch**, requests and values hidden in the last 24 hours, the most hidden types, system health and recent activity. |
| **Fields to hide** | Add, edit, pause and delete [fields](#fields-the-dictionary-of-values-to-hide): the labels that introduce a value and the known values to hide. |
| **Detection settings** | Switch each kind of data on or off, add your own regex types (with a pattern tester), set the confidence threshold, names, sensitive keywords, the allow-list, document-property removal, OCR, and whether callers may override settings. |
| **Audit log** | Filter by caller address or operation. Counts only, never values. |
| **Check a document** | Add a file and see what would be hidden: counts by kind, a preview of the masked text, and a download of the masked file. Nothing is stored. |
| **Try it** | Run sample text or a file through masking with optional per-request options. |

**PII protection switch.** Turning it off (with a confirmation) makes every masking endpoint return text and documents
**unchanged**, and the response says so. Use it for testing or an emergency. Its state shows in the page's top bar, in
`/healthz` and in `/v1/admin/overview`.

## Admin API

All need the admin key (or must come from the server itself): see [Who can call what](#who-can-call-what).

| Method and path | Purpose |
|---|---|
| `GET /v1/admin/overview` | Health, protection switch, counts and the last 24 hours. |
| `POST /v1/admin/check` | Multipart `file` (and optional `options`): what would be hidden, a text preview of the masked result and the masked file (base64, up to 8 MB). Stores nothing. |
| `GET /v1/admin/settings`, `PUT` the same path | The settings in force, or change some of them (partial JSON). |
| `GET /v1/admin/custom-types`, `POST` the same path | List or add regex types: `{"name": "EMPLOYEE_ID", "pattern": "\\bEMP-\\d{5}\\b", "context": ["employee"], "confidence": 85}`. A new type is enabled straight away. |
| `PUT` or `DELETE /v1/admin/custom-types/{id}` | Change or delete a type. |
| `POST /v1/admin/custom-types/test` | `{"pattern": "...", "text": "sample"}` shows what a pattern matches. |
| `GET /v1/admin/fields`, `POST` the same path | List the dictionary, or add a field: `{"name", "description", "terms", "labels", "enabled"}`. |
| `PATCH /v1/admin/fields/{id}` | Change a field. `terms` or `labels` given replace the old lists; `{"enabled": false}` pauses it. |
| `POST /v1/admin/fields/{id}/terms` | `{"add": [...], "remove": [...]}` adds values to a field or takes some out. |
| `DELETE /v1/admin/fields/{id}` | Delete a field. |
| `GET /v1/admin/audit?caller=&operation=&since=&limit=` | Recent audit entries, newest first. |

## Fields: the dictionary of values to hide

A **field** is a named kind of data you want hidden, such as `CLIENT_COMPANY_NAME`. Its name is what the value becomes
(`<CLIENT_COMPANY_NAME>`). A field has:

- **terms**: the known values. Each is found wherever it appears, ignoring case, spacing, and full stops or commas
  between words. The term `Acme Technologies Pvt Ltd` also finds "ACME Technologies Pvt. Ltd.". Whole words only: the
  term `Acme` does not match "Acmeville".
- **labels**: words that introduce a value. After "Client Name:" (or `=`, `|`, ` - `), the value up to the end of the
  sentence or cell is masked as this field. In a table, a cell that is just a label masks the cell beside it, or every cell
  below it when the label is a column header. When labels of two fields find the same value, the longer label decides.
- **enabled**: set it to false to pause a field without deleting it.

A value an admin listed beats any other detection of the same text. A CIN in your `COMPANY_CIN` terms becomes
`<COMPANY_CIN>`, while any other CIN is still masked as `<IN_CIN>` by its format.

A new service starts with these fields. Add your values to them, and add any further fields you need:

| Field | Starts with labels |
|---|---|
| `COMPANY_NAME` | Company Name |
| `COMPANY_CIN` | Company CIN |
| `COMPANY_ADDRESS` | Company Address, Registered Office, Registered Address, Office Address |
| `COMPANY_GSTIN` | Company GST, Company GSTIN, Company GST Number |
| `COMPANY_PAN` | Company PAN |
| `CLIENT_COMPANY_NAME` | Client Name, Client Company Name, Customer Name |
| `CLIENT_CIN` | Client CIN |
| `CLIENT_ADDRESS` | Client Address, Client Company Address, Billing Address |
| `CLIENT_GSTIN` | Client GST, Client GSTIN, Client GST Number |
| `CLIENT_PAN` | Client PAN |
| `CLIENT_SIGNATORY` | Client Authorised Signatory, Client Authorized Signatory, Client Signatory |
| `INTERNAL_SIGNATORY` | Authorised Signatory, Authorized Signatory, Signatory Name |

Generic labels such as "CIN:", "GSTIN:" or "PAN:" don't say whose number it is. They are left to format detection
(`IN_CIN`, `IN_GSTIN`, `IN_PAN`), which masks every such number.

```bash
curl -s -X POST localhost:8000/v1/admin/fields/1/terms -H "X-API-Key: $ADMIN" -H "Content-Type: application/json" \
  -d '{"add": ["Acme Technologies Pvt Ltd", "Acme Technologies"]}'
```

**Client-specific values** differ from one contract to the next. Either keep a list of clients in the client fields, or send
this client's values with the request (used for that request only). For `/v1/mask`:

```json
{"text": "...", "options": {"fields": [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Corporation"]}]}}
```

The CMS endpoint takes no per-request options, so it masks with the stored dictionary. Keep the client details it needs in
the dictionary.

**Limits.** An address or name split over several lines of a Word file is matched line by line: add each line as a term, or
use a label. A signatory's name on a line of its own under "Authorised Signatory" has no label beside it: list the names
as terms, or turn on `mask_names`.

## Settings and per-request options

| Setting | Default | Meaning |
|---|---|---|
| `enabled_types` | email, phone, card, US SSN, Aadhaar, PAN, GSTIN, CIN, IBAN | Types to detect (built-in and custom). |
| `threshold` | `40` | Minimum detector confidence in percent. Lower catches more, with more false alarms. |
| `mask_names` | `false` | Also detect people's names (`PERSON`). This is approximate. |
| `keywords_enabled`, `sensitive_keywords` | on, `Salary, CTC, DOB, ...` | The value after a keyword becomes `SENSITIVE_VALUE`. After `:`, `=`, `\|` or ` - `, any value up to the end of the sentence or cell counts; otherwise only a value that starts with a number. At most 120 characters. |
| `allow_list` | `[]` | Exact values never masked (for example a shared HR mailbox). |
| `allow_overrides` | `true` | Whether requests may send `options`. |
| `ocr_enabled`, `ocr_language` | `true`, `eng` | OCR for scanned PDF pages. |
| `protection_enabled` | `true` | The master switch. When `false`, masking passes text and documents through unchanged. |
| `scrub_metadata` | `true` | Clear author, last editor, title and similar properties from Word, PowerPoint, Excel and PDF files. |

A request's `options` can override `types`, `threshold`, `mask_names`, `keywords` and `allow_list`, and add `fields`
values, for that request only. Keyword matching depends on sentence and cell boundaries: end sentences with a full stop so a
keyword's value does not run on into the next sentence.

## What is covered in each file type

| Format | How | Covered | Not covered |
|---|---|---|---|
| TXT, MD | Whole text; encoding is preserved. | Everything | |
| CSV | Cell by cell, plus keyword columns and labels. | Every cell | |
| DOCX | Paragraph by paragraph across runs; formatting is kept. | Body, tables, text boxes, headers, footers, footnotes, endnotes, comments; properties cleared | Charts, SmartArt, embedded objects, images |
| PPTX | The same, per paragraph. | Slides, speaker notes; properties cleared | Charts, SmartArt, masters and layouts, images |
| XLSX | Cell by cell; keyword and field headers mask whole columns. | Cells, comments; properties cleared | Formulas (left alone), chart text, shapes |
| PDF | **True redaction** with PyMuPDF: the characters are removed from the page, not covered with a box. Links over redacted areas, metadata, attachments and JavaScript are removed. | Text layer; scanned pages through OCR | Personal data inside images on pages that also have text, form-field values; encrypted PDFs are refused |

The CMS endpoint accepts `.docx` and `.pdf` only, as in the specification.

## Security and deployment notes

- Values are never logged and never stored. Masking is one-way. Presidio's debug logging, which prints the words around a
  match, is silenced.
- The only thing kept is the **masked** output of a CMS job, in memory, for `PII_JOB_TTL_MINUTES`.
- Run behind TLS (a reverse proxy or load balancer). The service itself speaks plain HTTP.
- There are no per-caller rate limits. Add them in your gateway or reverse proxy if you need them. CMS jobs are per process:
  with several workers or replicas, each holds its own jobs (see the CMS notes above).
- File uploads are size-limited, checked against their claimed type, and refused if they are zip bombs.
- An older database that has `vault` or `api_keys` tables still loads: those tables are simply unused.

## Tests

```bash
python -m pytest -q
```

The suite covers the admin guard (key, local-only and proxy headers); masking of text and every file type with no key; the CMS API
(success, headers, every error code, job expiry, the audit log); the admin API and page; fields; and that no
unmask, token or vault endpoint exists. The PDF tests check that the value is gone from the file bytes. The OCR test runs when
Tesseract language data is available, for example in `docker build --target test .`, and is skipped otherwise.
