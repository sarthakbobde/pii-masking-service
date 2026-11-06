# Demo: PII masking service (about 12 minutes)

**The pitch in one line:** any internal app sends text or a document and gets it back with personal data masked:
the same file type, the same layout, and the personal data actually gone.

All data in `demo/files/` is made up.

---

## Before the demo (5 minutes, do it beforehand)

1. Start the service. Either use the **pii-service** entry in Claude's preview, or run this in a terminal:
   ```bash
   cd pii-masking-service
   .venv/Scripts/python.exe -m uvicorn app.main:app --port 8010
   ```
2. Wait for http://127.0.0.1:8010/healthz to show `"status": "ok"`. The first start takes about 10 to 20 s while
   the language model loads.
3. Rehearse once with `python demo/run_demo.py --auto`. This also warms everything up.
4. Have three windows ready:
   - the browser at http://127.0.0.1:8010/docs, the interactive API page
   - the folder `demo/files/`, which holds the originals
   - a terminal in `pii-masking-service`
5. If you rerun `python demo/make_files.py`, it rebuilds the input files. Delete `demo/output/` for a clean start.

## The flow

Run `python demo/run_demo.py`. It pauses before each step; press Enter to run it.

| # | Show | Say |
|---|---|---|
| 1 | **Health check** | "A plain HTTP service. No key is needed to check that it is up; everything else needs a key." |
| 2 | **An API key** is created. A second key with only the admin permission is created to show refusals. | "Each calling system gets its own key and its own permissions. We store only a hash of each key, so even the database can't leak one." |
| 3 | **Mask text**. Email, phone, PAN and the salary after "Salary:" become `<EMAIL_ADDRESS>`, `<PHONE_NUMBER>` and so on. | "It's one-way. The response says what kinds of data it found and where, but never the values themselves. Notice it caught the salary from the keyword, not from a pattern." |
| 4 | **Permissions**: a key without `mask` gets **403**, no key gets **401**, and asking to unmask gets **404**. | "This service can only mask. There is no endpoint, key or setting that puts a hidden value back, so a leak of this service cannot leak the originals." |
| 5 | **CMS contract masking** (specification A.8): submit, status, download. Open `demo/files/service-agreement.docx` next to `demo/output/ACME_MSA_20.docx`. | "CMS sends the file with the contract id and version and gets the masked file back in the same format, with the headers the specification lists. The original is never stored; the masked copy waits for download and then expires. Errors use the specification's format and codes." |
| 6 | **Word**: open `offer-letter.docx`, then `demo/output/offer-letter.masked.docx` | "The same file comes back, with the bold, colours and table style kept. The header, the table and the author property are cleaned too. In the table, the Date of birth, Bank account and Home address values are masked because of their labels in the next column." |
| 7 | **PDF**: open `customer-complaint.pdf`, then `demo/output/customer-complaint.masked.pdf`. **Try to select or copy where the email was.** | "This is true redaction. The text is removed from the file, not covered with a black box. The script just checked that the email can't be extracted from the file. The link over it and the document metadata are gone too." |
| 8 | **Excel**: open `staff-list.xlsx`, then `demo/output/staff-list.masked.xlsx` | "Spreadsheets are handled cell by cell. The DOB and Salary columns are masked because of their headers, even though they're plain numbers and dates. Headers and other columns stay readable." |
| 9 | **Live configuration**: the admin adds a `CASE_REF` type (`CX-12345`) and the same text is masked again | "Each team can add its own identifiers. A new type takes effect on the next request, with no redeploy." |
| 10 | **Fields: company and client details**. The script lists the dictionary: 12 fields such as `COMPANY_NAME`, `COMPANY_CIN`, `CLIENT_COMPANY_NAME` and `CLIENT_SIGNATORY`. It stores our company's details once, sends this client's details with the request, and masks `service-agreement.docx`. Open the original next to `demo/output/service-agreement.masked.docx`. | "Our own company's name, CIN, GSTIN, PAN, address and signatory are kept in a dictionary and hidden wherever they appear, even when written differently ('ACME ANALYTICS PVT. LTD.'). Client details can be stored too, or sent with each document. Labels do the rest: whatever follows 'Client Name:' or sits in the cell next to 'Billing Address' is hidden as that field. Anyone with admin rights can add a field, such as `PROJECT_NAME`, with one API call. Any CIN or GSTIN we don't know is still caught by its format." |
| 11 | **Audit log** | "Every call is logged: which system, what operation and how many items of each type. It never records the data itself, so the log is safe to keep." |

### Doing it in the browser instead (optional, for a hands-on feel)
1. Open http://127.0.0.1:8010/docs.
2. Find **POST /v1/files/mask** and click **Try it out**.
3. Paste a key into `x-api-key`. The demo key is in `data/demo-key.txt`.
4. Choose a file from `demo/files/` and click **Execute**.
5. Click **Download file**. The `x-pii-summary` response header shows what was found.

## Talking points

- **Fails closed:** if detection breaks, the caller gets an error, never a half-masked document.
- **Data handling:** values are never logged and never stored. Masking is one-way, so nothing can restore them.
- **CMS API:** `POST /api/v1/documents/mask` with the contract id and version, then status and download, as in the specification (A.8).
- **Rate limits:** each key has its own rate limit.
- **Deployment:** it runs as a Docker container with its own settings, separate from any other app.
- **Detected out of the box:** email, phone, cards, Aadhaar (checksum-validated), PAN, GSTIN, CIN, IBAN, US SSN, IP
  addresses and more. On top of that come your keywords, your own patterns and your dictionary of fields.
- **Configurable fields:** company and client names, addresses, CIN, GSTIN, PAN and signatories come as starter fields.
  Admins add values and new fields through the API, with no code change or redeploy.

## Likely questions (honest answers)

| Question | Answer |
|---|---|
| Scanned PDFs? | OCR is built in (Tesseract). It's enabled in the Docker image but not on this laptop yet; without it, scanned pages are left unchanged and reported in `unprocessed_image_pages`. |
| Names of people? | Off by default, because names are often needed and detection is approximate. Turn on `mask_names` in settings, or per request. |
| Images, charts, SmartArt? | Text inside images on normal pages, charts and SmartArt isn't masked. Text, tables, headers, notes and comments are. |
| Old `.doc` files or Google Docs? | Convert to `.docx` or PDF first. |
| Can a masked document be restored? | No. This service can only mask: there is no unmask endpoint, no token vault and no key to put values back. Keep the original in CMS. |
| Why was "Rohan Sharma" or "Asha Verma" not masked? | Names are off by default (see above). |
| Why was `hr@example.com` not masked? | It's on the allow-list: shared contact details that are fine to keep. |
| How does it know whose CIN or GSTIN it is? | From the dictionary: our own numbers are stored as `COMPANY_*` values, and the client's are stored or sent with the request. A number it doesn't know is still masked as `IN_CIN` or `IN_GSTIN`, just without saying whose it is. |
| A signatory's name on its own line under "Authorised Signatory"? | Labels need the value on the same line or in the next table cell. List the signatories' names as values, or turn on name detection. |
| Speed? | Text takes tens of milliseconds. A few-page document takes under a second. The first request after a start waits for the model to load. |
| How does another app call it? | One HTTP request with an API key. There are curl and Python examples in the README. |

## If something goes wrong

- **"Connection refused"**: the service isn't running. Start it (step 1 of the preparation) and wait for `/healthz`.
- **401**: wrong key. The demo script creates fresh keys every run, so just rerun it.
- **A step looks slow**: it's the first request after a restart. Run `--auto` once beforehand.
