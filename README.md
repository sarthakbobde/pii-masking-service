# PII masking service

A standalone HTTP API that finds personal data in text and files and either **masks** it (one-way labels such as
`<EMAIL_ADDRESS>`) or **tokenises** it (reversible tokens such as `<EMAIL_ADDRESS_7f3a9c21>`, with the real value kept
encrypted in a vault, which callers with the `unmask` permission can restore). Files come back in the same format: PDF, DOCX,
PPTX, XLSX, CSV, TXT and Markdown.

Detection uses Microsoft Presidio with spaCy (`en_core_web_sm`). It covers:
- **built-in types**: email, phone, cards, SSN, Aadhaar, PAN, GSTIN, CIN, IBAN and more;
- **regular-expression types** you define;
- **a dictionary of fields** you maintain: known values such as your company's or a client's name, address or
  signatory, and labels such as "Client Name:" whose value is masked as that field;
- **sensitive keywords**: the value after "Salary:", "DOB" and similar keywords is masked whatever its format.

---

## Contents
- [Quick start (local)](#quick-start-local)
- [Quick start (Docker)](#quick-start-docker)
- [Configuration](#configuration)
- [API keys](#api-keys)
- [The admin page](#the-admin-page)
- [Endpoints](#endpoints)
- [Files: what is covered](#files-what-is-covered)
- [Fields: the dictionary of values to hide](#fields-the-dictionary-of-values-to-hide)
- [Settings and per-request options](#settings-and-per-request-options)
- [Security notes](#security-notes)
- [Tests](#tests)

---

## Quick start (local)

Requires Python 3.11.

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; on Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
```

Create a `.env` (see `.env.example`):

```bash
python -m app.cli master-key      # paste the output into PII_MASTER_KEY
```

```
PII_MASTER_KEY=<the key printed above>
PII_BOOTSTRAP_ADMIN_KEY=<any random string of 24+ characters>
```

Run it:

```bash
uvicorn app.main:app --port 8000
```

The detector loads in the background at start-up (about 10 to 20 s). `GET /healthz` reports `starting` until it is
ready, and requests made before then wait for it. Interactive docs are at http://localhost:8000/docs.

## Quick start (Docker)

```bash
cp .env.example .env              # fill in PII_MASTER_KEY and PII_BOOTSTRAP_ADMIN_KEY
docker compose up -d --build
```

The image includes English OCR data for scanned PDFs, runs as a non-root user and keeps its SQLite database in the
`pii-data` volume. To run the test suite inside the image (OCR test included), use `docker build --target test .`.

## Configuration

Environment variables (or `.env`):

| Variable | Default | Meaning |
|---|---|---|
| `PII_MASTER_KEY` | (none) | Fernet key that encrypts vault values and the token secret. **Required for tokenise/unmask.** Comma-separate several keys to rotate (newest first; old ones still decrypt). Losing it makes the vault unreadable. |
| `PII_BOOTSTRAP_ADMIN_KEY` | (none) | Created as an admin key (all permissions, any scope) on start if no key with this value exists. Remove it once you have created your own keys. |
| `PII_DATABASE_URL` | `sqlite:///./data/pii.db` | Any SQLAlchemy URL. For PostgreSQL, install a driver (`psycopg`) and use `postgresql+psycopg://...`. |
| `PII_SETTINGS_FILE` | (none) | JSON that seeds the settings on **first** start; see `settings.example.json`. After that, use the admin API. |
| `PII_MAX_TEXT_CHARS` | `200000` | Longest text accepted by the text endpoints. |
| `PII_MAX_UPLOAD_MB` | `20` | Largest file accepted. |
| `PII_DEFAULT_RATE_LIMIT` | `120` | Requests per minute for keys created without their own limit. |
| `PII_WARM_UP` | `true` | Load the detector at start-up rather than on the first request. |
| `PII_TESSDATA_DIR` | (auto) | Tesseract language data for OCR. Without it, PyMuPDF looks at `TESSDATA_PREFIX` or an installed Tesseract. |
| `PII_LOG_LEVEL` | `INFO` | |

## API keys

Every endpoint except `/healthz` needs a key, sent as `Authorization: Bearer <key>` or `X-API-Key: <key>`.

- Keys are stored as SHA-256 hashes. The key itself is shown **once**, in the response that creates it.
- **Permissions**: `mask`, `tokenise`, `unmask`, `admin`. Give `unmask` only to the services that really need values back.
- **Scopes** are namespaces for tokens and the vault, for example one per team or application. The same value gets
  a different token in each scope, and unmasking only works in the scope that tokenised it. A key's first scope is
  its default; a request may name another scope (`"scope": "..."`) if the key lists it. `"*"` allows any scope, but
  then every request must name one.
- **Rate limit**: requests per minute per key (sliding window, kept in memory per process). Over the limit you get
  `429` with `Retry-After`.
- Every call is written to the audit log: time, key, operation, scope, HTTP status, counts by type and duration.
  Values are never logged.

Create keys through the admin API (below) or the command line:

```bash
python -m app.cli create-key billing-svc --permissions mask,tokenise --scopes billing --rate-limit 300
python -m app.cli create-key support-desk --permissions unmask --scopes billing
python -m app.cli list-keys
python -m app.cli revoke-key 3
```

## The admin page

Open **`/admin`** (for example http://localhost:8000/admin) and sign in with a key that has the `admin` permission. The
key stays in the browser tab only and is cleared when the tab closes. The page is plain HTML, CSS and JavaScript served by
the service itself, with a strict content security policy. It needs nothing else installed.

| Screen | What an admin can do |
|---|---|
| **Overview** | See the **PII protection switch**, requests and values hidden in the last 24 hours, the most hidden types, system health (detector, database, vault, OCR), and recent activity. |
| **Fields to hide** | Add, edit, pause and delete [fields](#fields-the-dictionary-of-values-to-hide): the labels that introduce a value and the known values to hide. Paste values one per line. |
| **Detection settings** | Switch each kind of data on or off (21 built in, plus your own regex types with a pattern tester), set the confidence threshold, names, sensitive keywords, the allow-list, document-property removal, OCR, and whether callers may override settings. Save and discard are at the bottom. |
| **API keys** | Create keys (shown once, with a copy button), change permissions, scopes and rate limits, and revoke. |
| **Audit log** | Filter by caller or operation. Counts only, never values. |
| **Token vault** | See how many values each scope stores, and delete a scope's values. |
| **Check a document** | Add a PDF, Word, PowerPoint, Excel, CSV or text file and see what would be hidden: counts by kind, a text preview with the hidden values highlighted, and a download of the masked file. Nothing is stored. |
| **Try it** | Run sample text or a file through mask, tokenise or unmask with optional per-request options. |

**PII protection switch.** Turning it off (a confirmation is required) makes `mask` and `tokenise` return text and files
**unchanged**: nothing is detected or stored, and the response says so (`"protection": "off"`, header
`X-PII-Protection: off`). `unmask` still works. Use it for testing or an emergency. The state is shown in the page's top bar,
in `GET /healthz` and in `GET /v1/admin/overview`.

## Endpoints

In the examples, `$KEY` is an API key with the needed permission.

### `POST /v1/mask` (permission `mask`)

One-way: replaces personal data with `<TYPE>` labels.

```bash
curl -s localhost:8000/v1/mask -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
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

`start` and `end` are offsets in the **input** text. Responses never echo the values themselves. Optional body fields
are `scope` and `options` ([per-request options](#settings-and-per-request-options)).

### `POST /v1/tokenise` (permission `tokenise`)

The request body is the same as for mask. Each value becomes a token: `TYPE_` plus the first 8 hex digits of
HMAC-SHA256(secret, scope, type, value), compared case-insensitively. The same value always gets the same token in a
scope, so you can still tell that two texts mention the same person. The value is stored encrypted in the vault. The
response also includes `scope`.

```json
{"text": "Mail <EMAIL_ADDRESS_25639bd5> or call <PHONE_NUMBER_d89e22bb>. ...", "scope": "billing", ...}
```

### `POST /v1/unmask` (permission `unmask`)

```bash
curl -s localhost:8000/v1/unmask -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"text": "Mail <EMAIL_ADDRESS_25639bd5>", "scope": "billing"}'
```

```json
{"text": "Mail john.doe@acme.com", "scope": "billing", "counts": {"EMAIL_ADDRESS": 1}, "total": 1, "unknown_tokens": 0}
```

Tokens the scope does not hold are left as they are and counted in `unknown_tokens`.

### Files: `POST /v1/files/mask`, `/v1/files/tokenise` and `/v1/files/unmask`

These endpoints take a multipart upload with the fields `file`, plus optional `scope` and `options` (a JSON string).
The response is the processed file, of the same type, named `<name>.masked.<ext>` (or `.tokenised` / `.unmasked`).
What was found is in the `X-PII-Summary` response header.

```bash
curl -s localhost:8000/v1/files/mask -H "Authorization: Bearer $KEY" \
  -F file=@contract.pdf -F 'options={"keywords":["Salary","Employee id"]}' \
  -D headers.txt -o contract.masked.pdf
```

```
X-PII-Summary: {"counts":{"EMAIL_ADDRESS":3,"SENSITIVE_VALUE":1},"total":4,"file_type":"pdf","pages":5,"ocr_pages":[4],"unprocessed_image_pages":[],"ocr_available":true}
```

`/v1/files/unmask` restores tokenised DOCX, PPTX, XLSX, CSV, TXT and MD files. It cannot restore PDFs, because
tokenising removes the original text from the PDF (the request gets `415`).

### Admin (permission `admin`)

| Method and path | Purpose |
|---|---|
| `GET /v1/admin/overview` | Health, protection switch, counts and the last 24 hours (what the Overview screen shows). |
| `POST /v1/admin/check` | Multipart `file` (and optional `options`): what would be hidden, a text preview of the masked result and the masked file (base64, up to 8 MB). Stores nothing. |
| `GET /v1/admin/settings` | The settings in force, plus the known built-in and custom types. |
| `PUT /v1/admin/settings` | Change some or all settings (partial JSON). |
| `GET /v1/admin/custom-types`, `POST` the same path | List or add regex types: `{"name": "EMPLOYEE_ID", "pattern": "\\bEMP-\\d{5}\\b", "context": ["employee"], "confidence": 85}`. A new type is enabled straight away. |
| `PUT` or `DELETE /v1/admin/custom-types/{id}` | Change or delete a type. A rename carries over to the enabled list. |
| `POST /v1/admin/custom-types/test` | `{"pattern": "...", "text": "sample"}` shows what the pattern matches (at most 20 matches). |
| `GET /v1/admin/fields`, `POST` the same path | List the dictionary, or add a field: `{"name", "description", "terms", "labels", "enabled"}` ([fields](#fields-the-dictionary-of-values-to-hide)). |
| `PATCH /v1/admin/fields/{id}` | Change a field. `terms` or `labels` given replace the old lists; `{"enabled": false}` pauses it. |
| `POST /v1/admin/fields/{id}/terms` | `{"add": [...], "remove": [...]}` adds values to a field or takes some out. |
| `DELETE /v1/admin/fields/{id}` | Delete a field. |
| `GET /v1/admin/keys`, `POST` the same path | List keys (never the key itself) or create one: `{"name", "permissions", "scopes", "rate_limit"}`. The answer holds `key`, shown only once. |
| `PATCH /v1/admin/keys/{id}` | Change `permissions`, `scopes` or `rate_limit`. |
| `DELETE /v1/admin/keys/{id}` | Revoke a key. It stops working within 5 seconds. |
| `GET /v1/admin/audit?key=&operation=&since=&limit=` | Recent audit entries, newest first. |
| `GET /v1/admin/vault` | How many values each scope holds, by type. |
| `DELETE /v1/admin/vault/{scope}` | Delete every value of a scope. Its tokens can no longer be unmasked. |

### `GET /healthz` (no key)

```json
{"status": "ok", "version": "0.1.0", "detector": "ready", "database": true, "vault": true, "ocr": true}
```

`status` is `starting` while the detector loads, and `error` (HTTP 503) if the detector or database fails.

### Errors

| Code | When |
|---|---|
| 400 | Invalid input or options. |
| 401 | Missing or unknown key. |
| 403 | The key lacks the permission or the scope, or per-request options are switched off. |
| 413 | The text or file is too large. |
| 415 | Unsupported or mismatched file type, an encrypted PDF, or unmasking a PDF. |
| 429 | The key's rate limit was reached. |
| 503 | The vault is unavailable because `PII_MASTER_KEY` is missing or wrong. |
| 500 | Detection failed. The service **fails closed**: no text or file is returned, never a partly masked one. |

## Files: what is covered

| Format | How | Covered | Not covered |
|---|---|---|---|
| TXT, MD | Whole text; encoding (UTF-8, UTF-8 BOM, UTF-16, cp1252) is preserved. | Everything | |
| CSV | Cell by cell, plus keyword columns and keyword labels (see XLSX). Delimiter is detected. | Every cell | |
| DOCX | Paragraph by paragraph across runs. The replacement goes in the run where the value starts, so formatting is kept. | Body, tables, text boxes, headers, footers, footnotes, endnotes, comments; author and other properties are cleared | Charts, SmartArt, embedded objects, images |
| PPTX | The same, per paragraph. | Slides (shapes, tables, groups), speaker notes; properties cleared | Charts, SmartArt, slide masters and layouts, images |
| XLSX | Cell by cell. A header cell that is a keyword (`DOB`, `Salary`) makes every value below it sensitive; a cell that is just a keyword (`Salary:`) makes the next cell to its right sensitive. Numbers are checked as text; a replaced number becomes text. | Cells, comments; properties cleared | Formulas (left alone), chart text, shapes (openpyxl drops shapes when saving) |
| PDF | **True redaction** with PyMuPDF. Each value's words get a redaction annotation carrying the label or token, and applying it **removes the characters from the content stream** and blanks image pixels underneath. It is not a box drawn over text that is still there. Whole words are redacted. Links over redacted areas are removed. Metadata, XMP, attachments, JavaScript and thumbnails are scrubbed. | Text layer; scanned pages through OCR | Personal data inside images on pages that also have real text, form-field values, annotation text; encrypted PDFs are refused |

**Scanned PDFs and OCR.** A page with images and almost no text (under 20 characters) is treated as scanned. When
OCR is on (`ocr_enabled`, the default) and Tesseract language data is available (it is in the Docker image), the page
is OCR'd at 300 dpi and the image pixels under each value are blanked, with the label written in their place. Without
OCR data, such pages are left unchanged and listed in `unprocessed_image_pages`, so check that field. OCR quality depends
on the scan. `ocr_language` takes Tesseract codes such as `eng` or `eng+hin` (install the matching language data).

## Fields: the dictionary of values to hide

A **field** is a named kind of data you want hidden, such as `CLIENT_COMPANY_NAME`. Its name is what the value becomes
(`<CLIENT_COMPANY_NAME>`, or a token such as `<CLIENT_COMPANY_NAME_3f9a12c0>`). A field has:

- **terms**: the known values. Each is found wherever it appears, ignoring case, spacing, and full stops or commas
  between words. For example, the term `Acme Technologies Pvt Ltd` also finds "ACME Technologies Pvt. Ltd.". Whole words
  only: the term `Acme` does not match "Acmeville".
- **labels**: words that introduce a value. After "Client Name:" (or `=`, `|`, ` - `), the value up to the end of the
  sentence or cell is masked as this field. In a table, a cell that is just a label masks the cell beside it, or every
  cell below it when the label is a column header. When two fields' labels find the same value ("Authorised
  Signatory:" and "Client Authorised Signatory:"), the longer label decides.
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
(`IN_CIN`, `IN_GSTIN`, `IN_PAN`), which masks every such number. Listing a number as a term labels it as yours or the
client's.

```bash
# your company's details
curl -s localhost:8000/v1/admin/fields -H "X-API-Key: $ADMIN"            # find the field ids
curl -s -X POST localhost:8000/v1/admin/fields/1/terms -H "X-API-Key: $ADMIN" -H "Content-Type: application/json" \
  -d '{"add": ["Acme Technologies Pvt Ltd", "Acme Technologies"]}'

# a field of your own
curl -s -X POST localhost:8000/v1/admin/fields -H "X-API-Key: $ADMIN" -H "Content-Type: application/json" \
  -d '{"name": "PROJECT_NAME", "terms": ["Project Falcon"], "labels": ["Project Name"]}'
```

**Client-specific values** often differ from one document to the next. Either keep a list of clients in
`CLIENT_COMPANY_NAME` and the other client fields, or send this client's values with the request, which uses them
for that request only:

```json
{"text": "...", "options": {"fields": [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Corporation"]},
                                       {"name": "CLIENT_SIGNATORY", "terms": ["Rahul Rao"]}]}}
```

For files, send the same JSON as the `options` form field.

**Limits.**
- An address or name split over several lines of a Word or PowerPoint file is matched line by line. Add each line as
  a term, or use a label.
- A signatory name on a line of its own under "Authorised Signatory" has no label beside it. List the names as terms,
  or turn on `mask_names`.

The settings file (`PII_SETTINGS_FILE`) can hold a `fields` list, which replaces the starter fields on first start.

## Settings and per-request options

| Setting | Default | Meaning |
|---|---|---|
| `enabled_types` | email, phone, card, US SSN, Aadhaar, PAN, GSTIN, CIN, IBAN | Types to detect (built-in and custom). |
| `threshold` | `40` | Minimum detector confidence in percent. Lower values catch more but give more false alarms. |
| `mask_names` | `false` | Also detect people's names (`PERSON`). This is approximate. |
| `keywords_enabled`, `sensitive_keywords` | on, `Salary, CTC, DOB, ...` | The value after a keyword becomes `SENSITIVE_VALUE`. After `:`, `=`, `\|` or ` - `, any value up to the end of the sentence or cell counts; otherwise only a value that starts with a number. A value is at most 120 characters. |
| `allow_list` | `[]` | Exact values never masked (for example a shared HR mailbox). |
| `allow_overrides` | `true` | Whether requests may send `options`. |
| `ocr_enabled`, `ocr_language` | `true`, `eng` | OCR for scanned PDF pages. |
| `protection_enabled` | `true` | The master switch. When `false`, mask and tokenise pass text and files through unchanged. |
| `scrub_metadata` | `true` | Clear author, last editor, title and similar properties from Word, PowerPoint, Excel and PDF files. |

A request's `options` can override `types`, `threshold`, `mask_names`, `keywords` and `allow_list`, and add `fields`
values, for that request only:

```json
{"text": "...", "options": {"types": ["EMAIL_ADDRESS"], "threshold": 60, "keywords": ["Employee id"], "allow_list": ["hr@acme.com"],
                            "fields": [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Corporation"]}]}}
```

Keyword matching depends on sentence and cell boundaries. In running text, end sentences with a full stop so that a
keyword's value does not run on into the next sentence.

## Security notes

- Values are never logged, never stored in plain text, and never returned except by `unmask`. Presidio's debug
  logging, which prints the words around a match, is silenced.
- Vault values are encrypted with Fernet (AES-128-CBC with HMAC-SHA256). Tokens are HMACs keyed by a random secret,
  which is itself stored encrypted, so a token reveals nothing about its value.
- Keep `PII_MASTER_KEY` in a secret store. To rotate it, put the new key first
  (`PII_MASTER_KEY=new,old`); new values use the new key and old values still decrypt.
- Rate limits and the key cache are per process. With several workers or replicas, each enforces its own limit.
- Run behind TLS (a reverse proxy or load balancer). The service itself speaks plain HTTP.
- File uploads are size-limited, checked against their claimed type, and refused if they are zip bombs.

## Tests

```bash
python -m pytest -q
```

The suite covers authentication, permissions, scopes and rate limits; mask; the tokenise → unmask round trip and
scope isolation; overrides; the admin API; the audit log (which must hold no values); failing closed; and a round trip
for every file format. The PDF test checks that the value is gone from the file bytes. The OCR test runs when Tesseract
language data is available, for example in `docker build --target test .`, and is skipped otherwise.
