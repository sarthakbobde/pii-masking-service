"""Walks through the demo against a running service, pausing between steps.

    python demo/run_demo.py                      # http://127.0.0.1:8010, press Enter between steps
    python demo/run_demo.py --url http://127.0.0.1:8000 --auto

The masking API needs no key. The admin calls (fields, settings, audit) work without one when this script runs on the
server itself; if PII_ADMIN_KEY is set in .env it is sent. Shows masking, the CMS document API (submit, status, download),
files, fields and a custom type added live, and the audit log. Masked files go to demo/output/.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import docx
import httpx
import pymupdf

HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from app.policy import STARTER_FIELDS  # noqa: E402

# Our (made-up) company's details, kept in the dictionary once; the client's are sent with the request.
OUR_COMPANY = {
    "COMPANY_NAME": ["Acme Analytics Private Limited", "Acme Analytics Pvt Ltd", "Acme Analytics"],
    "COMPANY_CIN": ["U72900KA2015PTC081234"],
    "COMPANY_GSTIN": ["29AAKCA1234F1Z5"],
    "COMPANY_PAN": ["AAKCA1234F"],
    "COMPANY_ADDRESS": ["4th Floor, Prestige Tower, MG Road, Bengaluru 560001"],
    "INTERNAL_SIGNATORY": ["Priya Nair"],
}
THIS_CLIENT = [
    {"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Retail Pvt Ltd", "Globex Retail"]},
    {"name": "CLIENT_CIN", "terms": ["U51909MH2012PTC234567"]},
    {"name": "CLIENT_GSTIN", "terms": ["27AACCG5678K1ZQ"]},
    {"name": "CLIENT_ADDRESS", "terms": ["12 Marine Drive, Mumbai 400020"]},
    {"name": "CLIENT_SIGNATORY", "terms": ["Rahul Mehta"]},
]
TEXT = ("Hi, I'm Rohan. Mail me at rohan.sharma@gmail.com or call +91 98450 12345. "
        "My PAN is BQKPS4821L. Salary: 24,50,000. Case ref CX-88213.")


class Demo:
    def __init__(self, url: str, auto: bool):
        self.http = httpx.Client(base_url=url, timeout=120)
        self.auto = auto
        self.step_no = 0
        env = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                   if "=" in line and not line.startswith("#")) if (ROOT / ".env").exists() else {}
        key = env.get("PII_ADMIN_KEY", "").strip()
        self.admin = {"X-API-Key": key} if key else {}

    def step(self, title: str, say: str = "") -> None:
        self.step_no += 1
        print(f"\n{'=' * 100}\nSTEP {self.step_no}. {title}\n{'=' * 100}")
        if say:
            print(f"  ({say})")
        if not self.auto:
            input("  press Enter to run... ")

    @staticmethod
    def show(r: httpx.Response, keys=None) -> dict:
        body = r.json()
        if keys:
            body = {k: body[k] for k in keys if k in body}
        print(f"  HTTP {r.status_code}")
        print("  " + json.dumps(body, indent=2, default=str).replace("\n", "\n  "))
        return body

    def file(self, headers, mode: str, name: str, options: dict | None = None) -> dict:
        r = self.http.post(f"/v1/files/{mode}", headers=headers, files={"file": (name, (HERE / "files" / name).read_bytes())},
                           data={"options": json.dumps(options)} if options else None)
        r.raise_for_status()
        stem, ext = name.rsplit(".", 1)
        out = HERE / "output" / f"{stem}.{'masked' if mode == 'mask' else mode + 'd'}.{ext}"
        out.write_bytes(r.content)
        summary = json.loads(r.headers["X-PII-Summary"])
        print(f"  {name}  ->  {out.relative_to(ROOT)}")
        print(f"  found: {summary['counts']}  (total {summary['total']})")
        return summary

    def run(self) -> None:
        (HERE / "output").mkdir(exist_ok=True)

        self.step("Health check", "no key needed; shows the detector, database and vault are ready")
        self.show(self.http.get("/healthz"))

        app = {}                       # the masking API needs no key

        self.step("Mask text (one-way)", "labels replace the values; findings give type and position, never the value")
        print(f"  input: {TEXT}")
        self.show(self.http.post("/v1/mask", headers=app, json={"text": TEXT}), ["text", "counts", "total"])

        self.step("No key, and no way back", "the masking API is open to CMS; nothing can restore a masked value")
        r = self.http.post("/v1/mask", json={"text": "Mail rohan.sharma@gmail.com"})
        print(f"  masking without any key   -> HTTP {r.status_code}: {r.json()['text']}")
        r = self.http.post("/v1/unmask", json={"text": "Mail <EMAIL_ADDRESS>"})
        print(f"  asking to unmask          -> HTTP {r.status_code} (the endpoint does not exist)")

        self.step("CMS: mask a contract (specification A.8)",
                  "CMS sends the file with its contract id and version; ContractAI returns the masked file")
        data = {"contract_id": "CMS-CONTRACT-12345", "version": "2.0", "output_filename": "ACME_MSA_20.docx"}
        r = self.http.post("/api/v1/documents/mask", headers=app, data=data,
                           files={"file": ("ACME_MSA_2026.docx", (HERE / "files" / "service-agreement.docx").read_bytes())})
        job = r.json()
        print(f"  POST /api/v1/documents/mask -> HTTP {r.status_code}")
        print("  " + json.dumps({k: job[k] for k in ("job_id", "status", "output_filename", "masked_fields_count", "field_types")}, indent=2).replace("\n", "\n  "))
        st = self.http.get(f"/api/v1/documents/mask/{job['job_id']}/status", headers=app)
        print(f"  GET .../status             -> HTTP {st.status_code}, status {st.json()['status']}")
        dl = self.http.get(f"/api/v1/documents/mask/{job['job_id']}/download", headers=app)
        out = HERE / "output" / job["output_filename"]
        out.write_bytes(dl.content)
        print(f"  GET .../download           -> HTTP {dl.status_code}, saved {out.relative_to(ROOT)}")
        for h in ("content-disposition", "x-contract-id", "x-version", "x-original-filename", "x-masked-fields-count"):
            print(f"      {h}: {dl.headers[h]}")
        bad = self.http.post("/api/v1/documents/mask", headers=app, data={"contract_id": "C-1"},
                             files={"file": ("sheet.xlsx", b"x")})
        print(f"  a missing version / wrong type -> HTTP {bad.status_code}: {bad.json()}")

        self.step("Mask a Word document", "same .docx back: formatting kept; header, table and properties cleaned")
        self.file(app, "mask", "offer-letter.docx")

        self.step("Mask a PDF (true redaction)", "the values are removed from the file, not covered with a box")
        self.file(app, "mask", "customer-complaint.pdf")
        text = pymupdf.open(HERE / "output" / "customer-complaint.masked.pdf")[0].get_text()
        raw = (HERE / "output" / "customer-complaint.masked.pdf").read_bytes()
        print(f"  'meera.iyer@outlook.com' still extractable from the masked PDF?  {'meera.iyer' in text or b'meera.iyer' in raw}")

        self.step("Mask a spreadsheet", "keyword columns (DOB, Salary) are masked whole, numbers included")
        self.file(app, "mask", "staff-list.xlsx")

        self.step("Add a custom type live", "admin adds CASE_REF (pattern CX-12345); it applies to the next request")
        r = self.http.post("/v1/admin/custom-types", headers=self.admin,
                           json={"name": "CASE_REF", "pattern": r"\bCX-\d{5}\b", "confidence": 90})
        type_id = r.json()["id"]
        print(f"  HTTP {r.status_code}: added {r.json()['name']}")
        self.show(self.http.post("/v1/mask", headers=app, json={"text": TEXT}), ["text"])
        self.http.delete(f"/v1/admin/custom-types/{type_id}", headers=self.admin)

        self.step("Fields: the dictionary of company and client details",
                  "our company's name, CIN, GSTIN, PAN, address and signatory are stored once; this client's are sent "
                  "with the request")
        fields = {f["name"]: f for f in self.http.get("/v1/admin/fields", headers=self.admin).json()}
        for f in STARTER_FIELDS:
            if f["name"] not in fields:
                fields[f["name"]] = self.http.post("/v1/admin/fields", headers=self.admin, json=f).json()
        for name, terms in OUR_COMPANY.items():
            self.http.post(f"/v1/admin/fields/{fields[name]['id']}/terms", headers=self.admin, json={"add": terms})
        for f in self.http.get("/v1/admin/fields", headers=self.admin).json():
            print(f"  {f['name']:<22} {len(f['terms'])} value(s)   labels: {', '.join(f['labels'][:3])}")
        self.file(app, "mask", "service-agreement.docx", {"fields": THIS_CLIENT})
        d = docx.Document(HERE / "output" / "service-agreement.masked.docx")
        for p in d.paragraphs:
            if p.text.strip():
                print("  | " + p.text)
        print("  table: " + "; ".join(f"{r.cells[0].text} = {r.cells[1].text}" for r in d.tables[0].rows))

        self.step("Audit log", "every call: who, what, status, counts by type; never a value")
        for e in self.http.get("/v1/admin/audit", headers=self.admin, params={"limit": 8}).json():
            print(f"  {e['at'][11:19]}  {e['caller']:<18} {e['operation']:<22} {e['status']}  {e['counts']}")

        print("\nDone. Open the files in demo/output/ next to the originals in demo/files/.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8010")
    ap.add_argument("--auto", action="store_true", help="do not pause between steps")
    a = ap.parse_args()
    Demo(a.url, a.auto).run()
