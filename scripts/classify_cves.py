"""Resolve a plain-English label for every CVE the regexes cannot classify.

Why this exists
---------------
describeVulnerability() in web/src/lib/constants.ts matches a CVE's summary text
against 15 regexes. Measured across the 1,610 distinct CVEs in Company_Vulns,
647 (40.2%) matched nothing and rendered as "A known flaw on an internet-facing
service", which tells a salesperson nothing.

More regexes only go so far: real CVE text describes a mechanism rather than
naming a class. CVE-2021-40438 is a textbook SSRF whose summary says "forward
the request to an origin server chosen by the remote user" and never says SSRF.

A CVE's description never changes and the dataset holds only ~1,610 of them, so
each is worth resolving once and keeping forever. At 40 per call that is roughly
17 requests for the whole backlog.

Why this cannot hallucinate
---------------------------
The model returns a LABEL KEY from a fixed list, never a sentence. The sentence
shown to the user is looked up in code from that key. The worst a wrong answer
can do is pick the wrong label out of a safe set — it cannot invent a claim
about a company. Anything it will not label is left to the existing regexes.

Carries the same guarantees as classify_existing.py:
  - chunked, so no prompt is unbounded
  - two known-answer canaries per chunk; a wrong canary discards that chunk
  - labels reconciled against the CVEs submitted, and against the allowed set
  - fails open: anything unanswered keeps its current regex behaviour
  - persisted, so re-runs cost nothing

Usage:
    python classify_cves.py --dry-run    report only, writes nothing
    python classify_cves.py --apply      write labels to Cve_Descriptions
"""
import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENV_PATH = os.path.join("web", ".env.local")
CHUNK_SIZE = 40
MIN_ANSWER_RATE = 0.5
GEMINI_MODEL = "gemini-2.5-flash"
REQUEST_SPACING_SECONDS = 0.4
SUMMARY_CHARS = 320

# Must stay in step with VULN_TITLES in web/src/lib/constants.ts. Duplicated
# rather than imported for the same reason classify_existing.py duplicates the
# pipeline's prompt: this is a standalone script, not part of the app build.
LABELS = {
    "RCE": "Attackers can run their own code on this server",
    "CMD": "Attackers can run system commands on this server",
    "SQLI": "Attackers can reach the database behind this server",
    "SSRF": "Attackers can make this server call systems behind the firewall",
    "DESER": "Attackers can smuggle hostile data into the application",
    "FILEWRITE": "Attackers can overwrite files on this server",
    "AUTHBYPASS": "Attackers can get in without valid credentials",
    "PRIVESC": "Attackers can raise their own level of access",
    "TRAVERSAL": "Attackers can read files they should never reach",
    "XSS": "Attackers can hijack a signed-in user's session",
    "CSRF": "Attackers can make a signed-in user act without meaning to",
    "MEMORY": "Attackers can crash or take over the service through memory abuse",
    "REDIRECT": "Attackers can bounce your visitors to a site they control",
    "DOS": "Attackers can knock this service offline",
    "INFO": "Attackers can read information that should stay private",
    "SMUGGLING": "Attackers can sneak hidden requests past your defences",
    "SPOOF": "Attackers can impersonate a trusted source",
    "SESSION": "Attackers can take over a signed-in session",
    "XXE": "Attackers can make this server fetch files and internal systems",
    "RACE": "Attackers can exploit a timing flaw to slip past a check",
    "CREDS": "Attackers can log in with credentials shipped in the product",
    "ACCESS": "Attackers can reach data or actions without permission",
    "VALIDATION": "Attackers can feed this server input it fails to check",
    "ENUM": "Attackers can work out which accounts exist",
    "MITM": "Attackers positioned on the network can read or alter traffic",
}

# Unambiguous by construction, and cannot collide with a real CVE ID. A model
# that mislabels one of these is not to be trusted for the rest of the chunk.
CANARIES = [
    ("CANARY-A", "A remote attacker can execute arbitrary code on the server.", "RCE"),
    ("CANARY-B", "An attacker can inject SQL statements into database queries.", "SQLI"),
    ("CANARY-C", "An attacker can flood the service until it stops responding.", "DOS"),
    ("CANARY-D", "An attacker can read files outside the intended directory.", "TRAVERSAL"),
]

# Verbatim from constants.ts. A CVE the regexes already handle is left alone, so
# this run is strictly additive and the model never overrides working behaviour.
REGEXES = [
    r"remote code execution|code execution|execute arbitrary code|execute untrusted code|arbitrary code|\bRCE\b",
    r"command injection|OS command|shell command|arbitrary commands",
    r"SQL injection",
    r"server-side request forgery|\bSSRF\b",
    r"deserializ|unserializ|\bphar\b|stream.wrapper",
    r"overwrite (?:arbitrary )?files|arbitrary file write|write arbitrary",
    r"authentication bypass|bypass authentication|improper authentication|without authentication",
    r"privilege escalation|escalate privileges|gain privileges|elevation of privilege",
    r"directory traversal|path traversal",
    r"cross-site scripting|\bXSS\b",
    r"cross-site request forgery|\bCSRF\b",
    r"buffer overflow|heap overflow|stack overflow|memory corruption|use.after.free|out-of-bounds",
    r"open redirect",
    r"denial of service|\bDoS\b",
    r"information disclosure|sensitive information|obtain sensitive|read arbitrary files|disclose",
]

PROMPT_HEAD = (
    "You are labelling software vulnerabilities for a non-technical sales audience.\n\n"
    "For each entry below, choose the ONE label that best describes what the flaw "
    "lets an attacker do. Reply with only the identifier and the label.\n\n"
    "Allowed labels — use these exact keys and nothing else:\n"
    + "\n".join(f"  {key} = {text}" for key, text in LABELS.items())
    + "\n\nIf no label fits, answer UNKNOWN. Never invent a label.\n"
    "Format, one per line: identifier=LABEL\n\nEntries:\n"
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


def parse_labels(text, asked):
    """Keep only lines naming a CVE we asked about and a label we allow."""
    by_key = {c.lower(): c for c in asked}
    labels = {}
    for raw in text.strip().split("\n"):
        line = re.sub(r"^\d+[.)]\s*", "", raw.strip()).strip("`* ")
        match = re.match(r"^([A-Za-z0-9\-_.]+)\s*[=:]\s*([A-Z]+)\b", line)
        if not match:
            continue
        original = by_key.get(match.group(1).strip().lower())
        label = match.group(2).upper()
        if original and label in LABELS:
            labels[original] = label
    return labels


def classify_chunk(entries, canaries):
    """entries: list of (cve_id, summary). Returns (labels, trustworthy)."""
    submitted = entries + [(c[0], c[1]) for c in canaries]
    listing = "\n".join(
        f"{i + 1}. {cve}: {(summary or '')[:SUMMARY_CHARS]}"
        for i, (cve, summary) in enumerate(submitted)
    )
    ids = [cve for cve, _ in submitted]
    try:
        labels = parse_labels(ask_gemini(PROMPT_HEAD + listing), ids)
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, IndexError):
        return {}, False

    for cve, _, expected in canaries:
        if labels.get(cve) != expected:
            return {}, False
        labels.pop(cve, None)

    answered = sum(1 for cve, _ in entries if cve in labels)
    if entries and answered / len(entries) < MIN_ANSWER_RATE:
        return {}, False
    return labels, True


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
        distinct.setdefault(row["cve_id"], row["summary"] or "")
    print(f"  {len(rows):,} rows -> {len(distinct):,} distinct CVEs")

    gaps = {
        cve: summary
        for cve, summary in distinct.items()
        if not any(re.search(p, summary, re.I) for p in REGEXES)
    }
    print(f"  {len(gaps):,} fall through the regexes ({100 * len(gaps) / max(len(distinct), 1):.1f}%)")

    try:
        cached = {
            r["cve_id"]: r["label"]
            for r in fetch_all("Cve_Enrichment", "cve_id,label")
            if r.get("label")
        }
    except urllib.error.HTTPError as error:
        raise SystemExit(
            f"Cve_Enrichment unreadable (HTTP {error.code}). "
            "Run web/supabase/cve_enrichment.sql in the Supabase SQL editor first."
        )
    print(f"  {len(cached):,} already labelled")

    todo = [(c, s) for c, s in gaps.items() if c not in cached]
    if args.limit:
        todo = todo[: args.limit]
    print(f"  {len(todo):,} to classify\n")

    fresh, rejected = {}, 0
    started = time.time()

    for index in range(0, len(todo), CHUNK_SIZE):
        chunk = todo[index : index + CHUNK_SIZE]
        chunk_index = index // CHUNK_SIZE
        canaries = CANARIES[0:2] if chunk_index % 2 == 0 else CANARIES[2:4]

        labels, trustworthy = classify_chunk(chunk, canaries)
        if trustworthy:
            fresh.update(labels)
        else:
            rejected += 1

        done = min(index + CHUNK_SIZE, len(todo))
        elapsed = time.time() - started
        print(
            f"  {done:>5,}/{len(todo):,}  labelled {len(fresh):,}  "
            f"rejected chunks {rejected}  {done / elapsed if elapsed else 0:.1f}/s",
            flush=True,
        )
        time.sleep(REQUEST_SPACING_SECONDS)

    print(f"\nlabelled this run : {len(fresh):,}")
    print(f"left to regexes   : {len(todo) - len(fresh):,}")
    print(f"rejected chunks   : {rejected}")

    from collections import Counter
    for label, n in Counter(fresh.values()).most_common():
        print(f"  {label:<12} {n:>4}  {LABELS[label]}")

    if args.dry_run:
        print("\nDry run — nothing written.")
        return

    rows_out = [{"cve_id": c, "label": l} for c, l in fresh.items()]
    for i in range(0, len(rows_out), 500):
        supabase(
            "Cve_Enrichment?on_conflict=cve_id",
            method="POST",
            body=rows_out[i : i + 500],
            extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
        )
    print(f"\nWrote {len(rows_out):,} labels.")


if __name__ == "__main__":
    main()
