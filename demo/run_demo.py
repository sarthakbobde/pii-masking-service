"""Walks through the demo against a running service, pausing between steps.

    python demo/run_demo.py                      # http://127.0.0.1:8010, press Enter between steps
    python demo/run_demo.py --url http://127.0.0.1:8000 --auto

Uses the admin key from .env (PII_BOOTSTRAP_ADMIN_KEY) to create two demo keys, then shows masking, tokenising,
unmasking, permissions, files, a custom type added live and the audit log. Masked files go to demo/output/.
"""
import argparse
import json
import time
from pathlib import Path

import httpx
import pymupdf

HERE = Path(__file__).parent
ROOT = HERE.parent
TEXT = ("Hi, I'm Rohan. Mail me at rohan.sharma@gmail.com or call +91 98450 12345. "
        "My PAN is BQKPS4821L. Salary: 24,50,000. Case ref CX-88213.")


class Demo:
    def __init__(self, url: str, auto: bool):
        self.http = httpx.Client(base_url=url, timeout=120)
        self.auto = auto
        self.step_no = 0
        env = dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines() if "=" in line and not line.startswith("#"))
        self.admin = {"X-API-Key": env["PII_BOOTSTRAP_ADMIN_KEY"].strip()}

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

    def key(self, name: str, permissions: list, scopes: list) -> dict:
        r = self.http.post("/v1/admin/keys", headers=self.admin,
                           json={"name": f"{name}-{int(time.time())}", "permissions": permissions, "scopes": scopes})
        r.raise_for_status()
        info = r.json()
        print(f"  created key '{info['name']}'  permissions={info['permissions']}  scopes={info['scopes']}  "
              f"(key starts {info['key'][:12]}..., shown once, stored only as a hash)")
        return {"X-API-Key": info["key"]}

    def file(self, headers, mode: str, name: str) -> dict:
        r = self.http.post(f"/v1/files/{mode}", headers=headers, files={"file": (name, (HERE / "files" / name).read_bytes())})
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

        self.step("Create two API keys", "one for an app that masks and tokenises, one for a support desk that may unmask")
        app = self.key("billing-app", ["mask", "tokenise"], ["demo"])
        desk = self.key("support-desk", ["unmask"], ["demo"])

        self.step("Mask text (one-way)", "labels replace the values; findings give type and position, never the value")
        print(f"  input: {TEXT}")
        self.show(self.http.post("/v1/mask", headers=app, json={"text": TEXT}), ["text", "counts", "total"])

        self.step("Tokenise text (reversible)", "same value -> same token every time in this scope; the value is stored encrypted")
        t = self.show(self.http.post("/v1/tokenise", headers=app, json={"text": TEXT}), ["text", "scope", "total"])
        again = self.http.post("/v1/tokenise", headers=app, json={"text": "Second email from ROHAN.SHARMA@gmail.com"}).json()
        print(f"  a later text with the same email: {again['text']}")

        self.step("Unmask: only keys allowed to", "the support desk gets the values back; the billing app is refused")
        self.show(self.http.post("/v1/unmask", headers=desk, json={"text": t["text"]}), ["text", "total"])
        r = self.http.post("/v1/unmask", headers=app, json={"text": t["text"]})
        print(f"  billing-app tries to unmask -> HTTP {r.status_code}: {r.json()['detail']}")
        r = self.http.post("/v1/mask", json={"text": TEXT})
        print(f"  no key at all              -> HTTP {r.status_code}: {r.json()['detail']}")

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

        self.step("Audit log", "every call: who, what, scope, status, counts by type; never a value")
        for e in self.http.get("/v1/admin/audit", headers=self.admin, params={"limit": 8}).json():
            print(f"  {e['at'][11:19]}  {e['key']:<28} {e['operation']:<22} {e['status']}  {e['counts']}")

        print("\nDone. Open the files in demo/output/ next to the originals in demo/files/.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8010")
    ap.add_argument("--auto", action="store_true", help="do not pause between steps")
    a = ap.parse_args()
    Demo(a.url, a.auto).run()
