"""Fetch each CVE's CWE (weakness type) from NVD into Cve_Enrichment.cwe_id.

A CVE is a specific bug; a CWE is its standardized weakness class (CWE-89 = SQL
injection, CWE-918 = SSRF). NVD assigns the CWE authoritatively, so this replaces
the old model-guessed label with a sourced category. One row per CVE, cached
forever; re-runs only fetch CVEs with no cwe_id yet.

CVEs with no usable CWE are stored as 'NONE' so they are not re-fetched nightly.

Prereq: Cve_Enrichment has a cwe_id column. Reads NVD_API_KEY, SUPABASE creds
from web/.env.local.

Usage:
    python scripts/fetch_cwe.py --dry-run [--limit N]
    python scripts/fetch_cwe.py --apply   [--limit N]
"""
import argparse
import json
import os
import time
import urllib.parse
import urllib.request

import requests

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_PATH = os.path.join("web", ".env.local")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SPACING = 0.65  # 50 requests / 30s with a key => ~0.6s between calls


def read_env(path):
    values = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip().strip('"').strip("'")
    return values


ENV = read_env(ENV_PATH)
SUPABASE_URL = ENV["NEXT_PUBLIC_SUPABASE_URL"]
SERVICE_KEY = ENV["SUPABASE_SERVICE_KEY"]
NVD_KEY = ENV.get("NVD_API_KEY", "")


def supabase(path, method="GET", body=None, extra_headers=None):
    headers = {"apikey": SERVICE_KEY, "Authorization": f"Bearer {SERVICE_KEY}",
               "Content-Type": "application/json"}
    headers.update(extra_headers or {})
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(f"{SUPABASE_URL}/rest/v1/{path}", data=data,
                                 method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=90) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else None


def fetch_all(table, select, key="cve_id", page=1000):
    rows, last = [], None
    while True:
        q = f"{table}?select={select}&order={key}&limit={page}"
        if last is not None:
            q += f"&{key}=gt.{last}"
        rows_page = supabase(q)
        if not rows_page:
            break
        rows.extend(rows_page)
        if len(rows_page) < page:
            break
        last = rows_page[-1][key]
    return rows


def nvd_cwe(cve_id):
    """First CWE-nnn assigned to this CVE, or 'NONE'."""
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("vulnerabilities", [])
    if not items:
        return "NONE"
    for grp in items[0]["cve"].get("weaknesses", []):
        for d in grp.get("description", []):
            if str(d.get("value", "")).startswith("CWE-"):
                return d["value"]
    return "NONE"


def main():
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    print("Fetching distinct CVEs...")
    distinct = sorted({r["cve_id"] for r in fetch_all("Company_Vulns", "cve_id")})
    done = {r["cve_id"] for r in fetch_all("Cve_Enrichment", "cve_id,cwe_id") if r.get("cwe_id")}
    todo = [c for c in distinct if c not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"  {len(distinct):,} CVEs, {len(done):,} already have a CWE, {len(todo):,} to fetch")

    fetched, errors, started = {}, 0, time.time()
    for i, cve in enumerate(todo):
        try:
            fetched[cve] = nvd_cwe(cve)
        except Exception as e:  # noqa: BLE001 — one bad lookup must not stop the run
            errors += 1
            print(f"  ! {cve}: {str(e)[:60]}", flush=True)
            time.sleep(2)
            continue
        if not args.dry_run and len(fetched) % 100 == 0:
            _write(fetched)
            fetched.clear()
        if (i + 1) % 100 == 0:
            print(f"  {i + 1:,}/{len(todo):,}  errors {errors}  "
                  f"{(i + 1) / (time.time() - started):.1f}/s", flush=True)
        time.sleep(SPACING)

    if not args.dry_run and fetched:
        _write(fetched)

    from collections import Counter
    top = Counter(list(fetched.values())).most_common(12) if args.dry_run else []
    for cwe, n in top:
        print(f"  {cwe:<16} {n}")
    print(f"\ndone. errors {errors}." + (" (dry run)" if args.dry_run else ""))


def _write(mapping):
    rows = [{"cve_id": c, "cwe_id": w} for c, w in mapping.items()]
    for i in range(0, len(rows), 500):
        supabase("Cve_Enrichment?on_conflict=cve_id", method="POST", body=rows[i:i + 500],
                 extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"})


if __name__ == "__main__":
    main()
