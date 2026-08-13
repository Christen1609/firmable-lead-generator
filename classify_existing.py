"""Classify the companies already in Supabase as business or infrastructure.

Why this exists
---------------
The 25,171 companies came from the offline notebook, which has no model-assisted
resolution step at all — only the English keyword filter. A sample of 50 found
six small regional ISPs that had survived: their domain names say nothing
("leon.com.pl", "houseti.com.br"), so no keyword could catch them.

Fixing web/src/lib/pipeline.ts only changes future live runs. This applies the
same classification to the rows already stored.

Mirrors the pipeline's guarantees deliberately:
  - chunked, so no prompt is unbounded
  - two known-answer canaries per chunk; a wrong canary discards that chunk
  - verdicts reconciled against domains submitted
  - fails open: anything unanswered is kept, never dropped
  - verdicts persisted to Domain_Classifications, so re-runs are nearly free

Usage:
    python classify_existing.py --dry-run     report only, writes nothing
    python classify_existing.py --apply       delete the infrastructure rows
"""
import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request

os.chdir(os.path.dirname(os.path.abspath(__file__)))

ENV_PATH = os.path.join("web", ".env.local")
CHUNK_SIZE = 40
MIN_ANSWER_RATE = 0.5
GEMINI_MODEL = "gemini-2.5-flash"
REQUEST_SPACING_SECONDS = 0.4

CANARIES = [
    ("cloudflare.com", "infrastructure"),
    ("bmw.com", "business"),
    ("akamai.com", "infrastructure"),
    ("siemens.com", "business"),
]

PROMPT_HEAD = (
    'You are classifying internet domains. For each domain below, answer with '
    'only "business" or "infrastructure".\n\n'
    '"business" = a real operating company, organisation, or commercial entity '
    'that would buy cybersecurity software.\n'
    '"infrastructure" = a hosting provider, telecom, ISP, CDN, DNS provider, '
    'cloud platform, or other infrastructure service.\n\n'
    "Only return the domain name and classification, one per line, in format: "
    "domain=classification\n\nDomains:\n"
)


def read_env(path):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    return values


ENV = read_env(ENV_PATH)
SUPABASE_URL = ENV["NEXT_PUBLIC_SUPABASE_URL"]
SERVICE_KEY = ENV["SUPABASE_SERVICE_KEY"]
GEMINI_KEY = ENV["GEMINI_API_KEY"]


def supabase(path, method="GET", body=None, extra_headers=None):
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}",
        "Content-Type": "application/json",
    }
    headers.update(extra_headers or {})
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/{path}", data=data, method=method, headers=headers
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else None


def fetch_all(table, select, page=1000):
    rows, offset = [], 0
    while True:
        page_rows = supabase(f"{table}?select={select}&offset={offset}&limit={page}")
        if not page_rows:
            break
        rows.extend(page_rows)
        if len(page_rows) < page:
            break
        offset += page
    return rows


def ask_gemini(prompt):
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    request = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_KEY}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["candidates"][0]["content"]["parts"][0]["text"]


def parse_verdicts(text, asked):
    by_key = {d.lower(): d for d in asked}
    verdicts = {}
    for raw in text.strip().split("\n"):
        line = re.sub(r"^\d+[.)]\s*", "", raw.strip())
        match = re.match(r"^(.+?)\s*[=:]\s*(business|infrastructure)\b", line, re.I)
        if not match:
            continue
        original = by_key.get(match.group(1).strip().lower())
        if original:
            verdicts[original] = match.group(2).lower()
    return verdicts


def classify_chunk(domains, canaries):
    submitted = domains + [c[0] for c in canaries]
    listing = "\n".join(f"{i + 1}. {d}" for i, d in enumerate(submitted))
    try:
        verdicts = parse_verdicts(ask_gemini(PROMPT_HEAD + listing), submitted)
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, IndexError):
        return {}, False

    for domain, expected in canaries:
        if verdicts.get(domain) != expected:
            return {}, False
        verdicts.pop(domain, None)

    answered = sum(1 for d in domains if d in verdicts)
    if domains and answered / len(domains) < MIN_ANSWER_RATE:
        return {}, False
    return verdicts, True


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="classify only N domains")
    args = parser.parse_args()

    companies = [r["company"] for r in fetch_all("Companies", "company")]
    print(f"companies in table: {len(companies):,}")

    cached = {
        r["domain"]: r["verdict"]
        for r in fetch_all("Domain_Classifications", "domain,verdict")
    }
    print(f"already classified  : {len(cached):,}")

    todo = [c for c in companies if c not in cached]
    if args.limit:
        todo = todo[: args.limit]
    print(f"to classify         : {len(todo):,}\n")

    fresh, rejected_chunks = {}, 0
    started = time.time()

    for index in range(0, len(todo), CHUNK_SIZE):
        chunk = todo[index : index + CHUNK_SIZE]
        chunk_index = index // CHUNK_SIZE
        pool = [c for c in CANARIES if c[0] not in chunk]
        canaries = pool[0:2] if chunk_index % 2 == 0 else pool[2:4]

        verdicts, trustworthy = classify_chunk(chunk, canaries)
        if not trustworthy:
            rejected_chunks += 1
        else:
            fresh.update(verdicts)

        if fresh and len(fresh) % 400 < CHUNK_SIZE:
            rows = [{"domain": d, "verdict": v} for d, v in fresh.items()]
            supabase(
                "Domain_Classifications?on_conflict=domain",
                method="POST",
                body=rows,
                extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
            )

        done = min(index + CHUNK_SIZE, len(todo))
        elapsed = time.time() - started
        print(
            f"  {done:>6,}/{len(todo):,}  ({100 * done / max(len(todo), 1):5.1f}%)  "
            f"{done / elapsed if elapsed else 0:5.1f} domains/s  rejected chunks: {rejected_chunks}",
            flush=True,
        )
        time.sleep(REQUEST_SPACING_SECONDS)

    if fresh:
        rows = [{"domain": d, "verdict": v} for d, v in fresh.items()]
        for i in range(0, len(rows), 500):
            supabase(
                "Domain_Classifications?on_conflict=domain",
                method="POST",
                body=rows[i : i + 500],
                extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
            )

    everything = dict(cached)
    everything.update(fresh)
    infrastructure = sorted(d for d, v in everything.items() if v == "infrastructure" and d in set(companies))
    unanswered = [d for d in todo if d not in fresh]

    print(f"\nclassified this run : {len(fresh):,}")
    print(f"unanswered (kept)   : {len(unanswered):,}")
    print(f"rejected chunks     : {rejected_chunks}")
    print(f"\nflagged as infrastructure: {len(infrastructure):,} of {len(companies):,} "
          f"({100 * len(infrastructure) / max(len(companies), 1):.1f}%)")
    print("sample of what would be removed:")
    for domain in infrastructure[:30]:
        print("   ", domain)

    if args.dry_run:
        print("\nDry run — nothing deleted.")
        return

    print(f"\nDeleting {len(infrastructure):,} companies (findings cascade)...")
    for i in range(0, len(infrastructure), 100):
        batch = infrastructure[i : i + 100]
        quoted = ",".join(f'"{d}"' for d in batch)
        supabase(f"Companies?company=in.({quoted})", method="DELETE")
    print("Done.")


if __name__ == "__main__":
    main()
