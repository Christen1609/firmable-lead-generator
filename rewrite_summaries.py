"""Rewrite every CVE summary into one plain-English line for salespeople.

Why this exists
---------------
The detail card derives a plain headline (describeVulnerability) but shows the
raw CVE summary verbatim underneath — engineer-speak a salesperson cannot use.
This rewrites that paragraph into 1-2 plain sentences and stores one per CVE in
Cve_Plain_Summaries. Only ~1,876 distinct CVEs exist and their text never
changes, so each is rewritten once (~a few dozen calls) and reused forever.

This is the one place a model writes prose that reaches the page, so every
rewrite is reconciled against its source before it is kept:
  - it may not introduce a number/version absent from the source;
  - it may not claim a breach ("breached", "hacked", "compromised", ...);
  - it may not echo the CVE id;
  - it must be short and non-empty.
A rewrite that breaks a rule is discarded, and the app falls back to the raw
summary — so a failed or empty run behaves exactly like today. Chunks that fail
to parse are skipped and left for a re-run; writes are idempotent.

Usage:
    python rewrite_summaries.py --dry-run [--limit N]   report only
    python rewrite_summaries.py --apply   [--limit N]   write to Supabase
"""
import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

os.chdir(os.path.dirname(os.path.abspath(__file__)))

ENV_PATH = os.path.join("web", ".env.local")
CHUNK_SIZE = 15
WORKERS = 6
GEMINI_MODEL = "gemini-2.5-flash"
REQUEST_SPACING_SECONDS = 0.4
SOURCE_CHARS = 600
MAX_REWRITE_CHARS = 320

FORBIDDEN = [
    "breach", "hacked", "compromis", "you were", "your company",
    "your organisation", "your organization", "already been", "has been breached",
]

PROMPT_HEAD = (
    "You are rewriting software vulnerability descriptions for a non-technical "
    "business owner.\n\n"
    "For each item, rewrite the description into ONE or TWO short, plain "
    "sentences saying, in everyday words, what the flaw is and what it could let "
    "an attacker do.\n\n"
    "Rules:\n"
    "- Use ONLY facts in the given text. Do NOT add any product name, version "
    "number, or figure that is not already in the text.\n"
    "- Do NOT say the company has been breached, hacked, or compromised. "
    "Describe the flaw, not an incident.\n"
    "- Do NOT mention the CVE identifier.\n"
    "- No jargon or acronyms; a business owner should understand it.\n"
    "- Keep each rewrite under 40 words.\n\n"
    'Return ONLY a JSON array, one object per item, using the item\'s number as '
    '"id": [{"id": 1, "text": "<rewrite>"}]\n\nItems:\n'
)

CANARIES = [
    ("CANARY-A", "A remote attacker can execute arbitrary code on the affected server."),
    ("CANARY-B", "An attacker can flood the service with requests until it stops responding."),
]


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

NUMBER = re.compile(r"\d+(?:\.\d+)*")
CVE_ID = re.compile(r"cve-\d{4}-\d+", re.I)


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


def fetch_all(table, select, page=1000, key="cve_id"):
    # Keyset pagination on cve_id: stable AND fast. Offset paging without an
    # ORDER BY shifts rows between pages (silently missed ~264 CVEs on the first
    # run); offset paging WITH an ORDER BY re-sorts 182k rows per page and times
    # out. Walking by `cve_id > last` avoids both. Duplicate rows of a boundary
    # cve_id are dropped, which is fine — this is only used to collect distinct
    # CVEs, and that CVE was already captured on the prior page.
    rows, last = [], None
    while True:
        query = f"{table}?select={select}&order={key}&limit={page}"
        if last is not None:
            query += f"&{key}=gt.{last}"
        page_rows = supabase(query)
        if not page_rows:
            break
        rows.extend(page_rows)
        if len(page_rows) < page:
            break
        last = page_rows[-1][key]
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


def parse_json_array(text):
    """Tolerate ```json fences and stray prose around the array."""
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?|```$", "", cleaned, flags=re.M).strip()
    start, end = cleaned.find("["), cleaned.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return []


def accept(rewrite, source):
    """Reconcile one rewrite against its source. Returns the text or None."""
    text = (rewrite or "").strip()
    if not text or len(text) > MAX_REWRITE_CHARS:
        return None
    low = text.lower()
    if any(word in low for word in FORBIDDEN):
        return None
    if CVE_ID.search(text):
        return None
    # No number/version may appear that is not already in the source text.
    for token in NUMBER.findall(text):
        if token not in source:
            return None
    return text


def rewrite_chunk(entries):
    """entries: [(cve_id, summary)]. Returns {cve_id: accepted_text}."""
    submitted = entries + CANARIES
    listing = "\n".join(
        f"{i + 1}. {(summary or '')[:SOURCE_CHARS]}"
        for i, (_cid, summary) in enumerate(submitted)
    )
    try:
        parsed = parse_json_array(ask_gemini(PROMPT_HEAD + listing))
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, IndexError):
        return {}

    # The model returns the 1-based item number as `id`, so map results back to
    # the CVE id by position rather than trusting it to echo the identifier.
    by_id = {}
    for item in parsed:
        if not isinstance(item, dict):
            continue
        raw_id = str(item.get("id", "")).strip()
        if raw_id.isdigit() and 1 <= int(raw_id) <= len(submitted):
            by_id[submitted[int(raw_id) - 1][0]] = item.get("text", "")
        elif raw_id in dict(submitted):
            by_id[raw_id] = item.get("text", "")

    # Canary check: the model must return a usable, in-spec rewrite for the known
    # inputs. If it fabricates or violates a rule on those, distrust the chunk.
    for cid, src in CANARIES:
        if accept(by_id.get(cid, ""), src) is None:
            return {}

    result = {}
    for cid, summary in entries:
        text = accept(by_id.get(cid, ""), summary or "")
        if text:
            result[cid] = text
    return result


def write_rewrites(mapping):
    """Upsert one chunk's accepted rewrites immediately (idempotent)."""
    rows = [{"cve_id": cid, "plain_summary": text} for cid, text in mapping.items()]
    supabase(
        "Cve_Plain_Summaries?on_conflict=cve_id",
        method="POST",
        body=rows,
        extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
    )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    print("Fetching distinct CVEs from Company_Vulns...")
    rows = fetch_all("Company_Vulns", "cve_id,summary")
    distinct = {}
    for row in rows:
        summary = row["summary"] or ""
        if summary and row["cve_id"] not in distinct:
            distinct[row["cve_id"]] = summary
    print(f"  {len(rows):,} rows -> {len(distinct):,} distinct CVEs with a summary")

    done = {r["cve_id"] for r in fetch_all("Cve_Plain_Summaries", "cve_id")}
    print(f"  {len(done):,} already rewritten")

    todo = [(c, s) for c, s in distinct.items() if c not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"  {len(todo):,} to rewrite\n")

    # Chunks run concurrently (the bottleneck is model latency, not rate) and
    # each chunk's accepted rewrites are written the moment it returns, so
    # progress persists and a re-run resumes from the `done` set above.
    chunks = [todo[i : i + CHUNK_SIZE] for i in range(0, len(todo), CHUNK_SIZE)]
    kept, skipped_chunks, seen = 0, 0, 0
    samples = []
    started = time.time()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(rewrite_chunk, chunk): chunk for chunk in chunks}
        for future in as_completed(futures):
            chunk = futures[future]
            try:
                accepted = future.result()
            except Exception:  # noqa: BLE001 — one bad chunk must not stop the run
                accepted = {}
            if not accepted and chunk:
                skipped_chunks += 1
            if accepted and not args.dry_run:
                write_rewrites(accepted)
            for cid, text in list(accepted.items())[: max(0, 6 - len(samples))]:
                samples.append((cid, distinct[cid], text))
            kept += len(accepted)
            seen += len(chunk)
            elapsed = time.time() - started
            print(f"  {seen:>5,}/{len(todo):,}  kept {kept:,}  "
                  f"skipped chunks {skipped_chunks}  {seen / elapsed if elapsed else 0:.1f}/s",
                  flush=True)

    print(f"\nkept          : {kept:,}")
    print(f"fell back raw : {len(todo) - kept:,} (shown as the original summary)")
    print(f"skipped chunks: {skipped_chunks}")
    print("\nSamples:")
    for cid, was, now in samples:
        print(f"  {cid}\n    was: {was[:120]}\n    now: {now}\n")
    if args.dry_run:
        print("Dry run — nothing written.")


if __name__ == "__main__":
    main()
