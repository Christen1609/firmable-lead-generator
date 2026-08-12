"""Load the batch per-CVE findings into Supabase Company_Vulns.

Why this exists
---------------
Backend-architecture.md §4 specifies company_vulns as a Supabase table, and the
live pipeline already upserts into it. But the batch findings were only ever
shipped as a gzipped file bundled into the Next.js app, so the app had two
different sources for the same kind of data: existing companies read the file,
pipeline-added companies read Supabase. Findings therefore existed for one set
or the other depending on how a company got there.

This loads the batch findings into the same table the pipeline writes to, so
there is one source of truth for every company regardless of origin.

Prerequisites
-------------
1. web/supabase/company_vulns.sql has been run (the table must exist).
2. web/.env.local holds NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_KEY.

Safe to re-run: every write is an upsert keyed on (company, cve_id).

Usage:
    python load_company_vulns.py [--dry-run] [--batch 1000]
"""
import argparse
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.request

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Lives at the repo root, not under web/: it is this loader's input, not an app
# asset. Bundling it shipped ~9 MB to Vercel and gave the app a second, diverging
# source of findings.
GZ_PATH = "company_vulns.json.gz"
ENV_PATH = os.path.join("web", ".env.local")
TABLE = "Company_Vulns"


def read_env(path):
    """Minimal .env reader — avoids adding a dependency for four values."""
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def fetch_existing_companies(url, key):
    """Every company key already in Companies.

    Company_Vulns has a foreign key onto Companies, and the batch file carries a
    few dozen companies that never made it into the Companies table. Left in,
    each one fails its whole 1000-row batch on a FK violation, so they are
    filtered out here and reported.

    PostgREST caps a response at 1000 rows regardless of Range, so this pages.
    """
    companies = set()
    offset = 0
    while True:
        request = urllib.request.Request(
            f"{url}/rest/v1/Companies?select=company",
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Range": f"{offset}-{offset + 999}",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            page = json.loads(response.read().decode("utf-8"))
        if not page:
            break
        companies.update(row["company"] for row in page)
        if len(page) < 1000:
            break
        offset += 1000
    return companies


def post_batch(url, key, rows, retries=4):
    """Upsert one batch, retrying on transient failures with a backoff."""
    payload = json.dumps(rows).encode("utf-8")
    request = urllib.request.Request(
        f"{url}/rest/v1/{TABLE}?on_conflict=company,cve_id",
        data=payload,
        method="POST",
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            # merge-duplicates makes this an upsert; minimal skips the echo.
            "Prefer": "resolution=merge-duplicates,return=minimal",
        },
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")[:400]
            # 4xx other than rate limiting will not fix themselves — fail loudly.
            if error.code not in (429, 500, 502, 503, 504):
                raise SystemExit(f"\nHTTP {error.code} from Supabase:\n  {body}")
            wait = 2 ** attempt
            print(f"  HTTP {error.code}, retrying in {wait}s...", flush=True)
            time.sleep(wait)
        except urllib.error.URLError as error:
            wait = 2 ** attempt
            print(f"  {error.reason}, retrying in {wait}s...", flush=True)
            time.sleep(wait)
    raise SystemExit("Batch failed after retries.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and report, write nothing.")
    parser.add_argument("--batch", type=int, default=1000,
                        help="Rows per request (default 1000).")
    args = parser.parse_args()

    env = read_env(ENV_PATH)
    url = env.get("NEXT_PUBLIC_SUPABASE_URL")
    key = env.get("NEXT_PUBLIC_SUPABASE_KEY")
    if not url or not key:
        raise SystemExit(f"Supabase URL/key missing from {ENV_PATH}")

    print(f"Reading {GZ_PATH}...")
    with gzip.open(GZ_PATH, "rb") as handle:
        raw = json.loads(handle.read().decode("utf-8"))

    # Columns are positional in the gz: [company, cve_id, cvss, epss, summary, in_kev]
    rows = []
    seen = set()
    for company, entries in raw.items():
        for entry in entries:
            cve_id = entry[1]
            # The table is keyed on (company, cve_id); a duplicate inside one
            # request makes Postgres reject the whole batch.
            if (company, cve_id) in seen:
                continue
            seen.add((company, cve_id))
            rows.append({
                "company": company,
                "cve_id": cve_id,
                "cvss": entry[2],
                "epss": entry[3],
                "summary": entry[4] or None,
                "in_kev": bool(entry[5]),
            })

    print(f"  {len(raw):,} companies, {len(rows):,} unique per-CVE rows")

    print("Fetching existing company keys from Supabase...")
    existing = fetch_existing_companies(url, key)
    print(f"  {len(existing):,} companies in Companies")

    before = len(rows)
    rows = [row for row in rows if row["company"] in existing]
    skipped = before - len(rows)
    if skipped:
        print(f"  skipped {skipped:,} rows for companies absent from Companies")
    print(f"  {len(rows):,} rows to load")

    if args.dry_run:
        print("Dry run — nothing written.")
        print("Sample row:", json.dumps(rows[0], indent=2)[:300])
        return

    total = len(rows)
    started = time.time()
    for offset in range(0, total, args.batch):
        chunk = rows[offset:offset + args.batch]
        post_batch(url, key, chunk)
        done = offset + len(chunk)
        elapsed = time.time() - started
        rate = done / elapsed if elapsed else 0
        print(f"  {done:>7,}/{total:,}  ({100 * done / total:5.1f}%)  "
              f"{rate:,.0f} rows/s", flush=True)

    print(f"\nDone in {time.time() - started:.0f}s.")


if __name__ == "__main__":
    main()
