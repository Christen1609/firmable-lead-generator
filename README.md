# Lead Generator — Exposure Intelligence

Turns 5.6 GB of raw internet scan data into a ranked list of companies with real,
externally visible security exposures, and gives a salesperson everything needed
to open a conversation: what is wrong, what it is likely to cost, who to contact,
and a drafted email.

**Live:** https://firmabletask.vercel.app

---

## The problem

A cybersecurity company's sales team has a scan of the public internet and no way
to act on it. The raw feed is a 5.6 GB compressed JSON file of individual hosts —
IP addresses, open ports, TLS certificates, software banners, CVE lists. None of
that is a sales prospect. A salesperson cannot call an IP address.

The job is to get from *hosts* to *companies worth calling today*, and to make
the case in language a business owner understands.

## What it does

**Screen 1 — the prospect list.** 25,000+ resolved companies ranked by what is
being attacked right now, not by raw severity. Filter by exposure tier and
country, search by name.

**Screen 2 — the company.** Estimated financial exposure, a plain-English verdict,
and the worst findings written so a non-technical reader can follow them. Three
actions: draft an outreach email, pull contact details for whoever owns security
there, or generate a spoken opener for a cold call.

**Find More** runs the whole cleaning pipeline live against the Shodan API and
adds newly discovered companies to the same tables the batch data lives in.

---

## Architecture

```
test_scans.json.zst  (5.6 GB, 6,124,461 hosts)
        │
        │  DuckDB streaming scan — never loaded into memory
        ▼
  companies_raw.parquet
        │
        │  Layer 1  extract root domain from TLS cert CN, else hostname
        │  Layer 2  drop IPs, .arpa, and infrastructure keywords (hosting, cloud, ISP…)
        │  Layer 3  Gemini classifies only the ambiguous domains (>50 servers)
        ▼
  resolved companies
        │
        │  join CISA KEV  →  in_kev, ransomware flags
        │  score tier     →  Critical / High / Medium / Low
        │  aggregate      →  max CVSS, max EPSS, distinct CVE count
        ▼
  Supabase ──┬── Companies      (one row per company, the summary)
             └── Company_Vulns  (one row per CVE per company, the detail)
                        │
                        ▼
              Next.js app on Vercel
```

The live **Find More** pipeline is the same five stages implemented in
TypeScript, writing to the same two tables. A company's findings do not depend on
whether it arrived via the batch load or a live run — there is one source of
truth for both.

### Why the filtering is layered

The expensive step runs last and on the smallest set. Deterministic rules remove
the obvious infrastructure first (an IP with no hostname is not a company; a
domain containing `hosting` or `aws` is not a prospect). Only domains that are
genuinely ambiguous — typically ones serving an implausible number of hosts —
reach the LLM. Most records never cost an API call.

### How the tier is decided

Ranking is by **probability of attack**, not severity. A CVSS 10.0 nobody is
exploiting is a worse lead than a CVSS 7.5 under active attack.

| Tier | Meaning |
|---|---|
| **Critical** | At least one CVE on the CISA Known Exploited Vulnerabilities list — confirmed exploited in the wild |
| **High** | EPSS ≥ 0.5 — better than even odds of attack within 30 days |
| **Medium** | EPSS ≥ 0.1 |
| **Low** | CVEs present, below elevated thresholds |

### Estimated exposure

```
exposure = IBM average breach cost × highest EPSS score
```

Computed in code and shown with its own arithmetic on screen. It is an estimate
built from two public figures, and the UI says so rather than presenting it as a
quote.

---

## The AI guardrail

Every number in a generated email is computed in code and interpolated into the
prompt as text. The model phrases them; it never derives them. The prompt says
*"Use ONLY the facts given below. Do not invent or alter any number."*

Two things this project learned the hard way, both recorded in the code:

- **Model pinning matters.** The newer Gemini flash models reproducibly rewrote
  the real company domain as `example.com` in this prompt, which destroys the one
  thing a personalised email is selling. `gemini-2.5-flash` keeps it. There is a
  code-level guard that restores the real domain if it ever slips through.
- **Prescribe exact wording where tone matters.** Left to paraphrase, the model
  reaches for sales-speak. Sentences that carry no per-company data are locked as
  literal strings.

The email is three lines by design: what is wrong, what it may cost, and a
booking link.

---

## Call hook

**Generate a Hook** produces the first ten seconds of a cold call — what the
salesperson *says*, as opposed to the email they send. Three sentences, revealed
a character at a time so it reads at roughly speaking pace.

It carries the same grounding as the email, and two claims branch on the data
rather than being asserted:

- Active exploitation is only stated when the company has a CISA KEV hit.
  Otherwise the hook gives the measured attack probability instead. This gets
  said out loud to a real person, so it has to be true.
- The cost is framed as an industry average with this company's exposure as an
  estimate. It is explicitly never presented as a past breach at that company,
  which would be a fabrication the prospect could check.

---

## Rate limiting and input validation

The four API routes are public and each one spends metered quota — a Shodan
credit, a Gemini call, a Hunter search. They are called from the browser, so a
shared secret would ship in the client bundle and protect nothing.

Instead: per-IP rate limiting (5/min on the pipeline, 10/min elsewhere) and
strict input validation. `country` and `product` are matched against patterns
admitting neither spaces nor colons, because Shodan's query syntax is
space-separated `filter:value` pairs — unvalidated, a caller sending
`nginx port:22 country:RU` would rewrite the entire query rather than choose a
product.

The limiter is in-memory and does not span serverless instances. It stops the
realistic failure of one client looping an endpoint; a shared store such as
Upstash is the correct fix under real traffic.

---

## Contact lookup

Pressing **Contact Info** finds up to three people at the company and ranks them:

1. **Security leader** — owns the problem (CISO, Head of Security, Director of InfoSec)
2. **Technical leader** — CTO, CIO, VP Engineering/Infrastructure, IT Director
3. **Decision maker** — founder or owner who would forward it on

Ranked in code, with the reason shown per contact so the ordering is auditable.
A security *title* only counts as leadership when something backs it up — an
explicit leadership word, the CISO/CSO acronym, or executive seniority. A
"Security Analyst" is not the buyer.

Provider fields are used carefully rather than trusted. Sampling showed the
provider labelling "Sales Executive" as `executive` / `decision_maker: true`, and
filing "Principal Engineer" under department `education`. So seniority and
decision-maker act as tiebreakers and supporting signals only, and department is
ignored entirely — it was wrong often enough to cost more accuracy than it added.

The lookup is **on demand only**. It fires when the button is pressed, never
during list or detail rendering, because provider quota is metered and most
companies are never opened.

---

## Stack

| | |
|---|---|
| Frontend | Next.js 16 (App Router), React 19, TypeScript |
| Database | Supabase (Postgres) |
| Batch processing | Python + DuckDB |
| AI | Google Gemini — domain classification and email drafting |
| Data sources | Shodan, CISA KEV, Hunter |
| Hosting | Vercel |

---

## Running locally

```bash
git clone https://github.com/Christen1609/firmable-lead-generator.git
cd firmable-lead-generator/web
npm install
cp .env.local.example .env.local   # then fill in the values below
npm run dev
```

### Environment

| Variable | Purpose |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project REST URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Publishable key — read-only, constrained by RLS |
| `SUPABASE_SERVICE_KEY` | Service-role key, server-only. Used by the pipeline route and the batch loader |
| `GEMINI_API_KEY` | Email drafting and domain classification |
| `SHODAN_API_KEY` | Live Find More pipeline |
| `HUNTER_API_KEY` | Contact lookup |

Reads and writes use separate clients. `src/lib/supabase.ts` holds the
publishable key and is safe to reach the browser; Row Level Security grants it
`SELECT` on the three tables and no write access at all.
`src/lib/supabase-admin.ts` holds the service-role key, imports `server-only`
so a client-side import fails the build rather than leaking the key, and is used
only by the pipeline route.

Apply the policies with `web/supabase/rls_policies.sql`.

### Database

```bash
# Create the per-CVE findings table
psql < web/supabase/company_vulns.sql   # or paste into the Supabase SQL editor
```

### Rebuilding the batch data

The scan file and its derived parquet are excluded from this repo — 5.6 GB and
712 MB respectively, both over GitHub's limits. To regenerate:

```bash
python extract_vulns.py        # scan file  -> company_vulns.json.gz
python load_company_vulns.py   # gz         -> Supabase Company_Vulns
python measure_vulns.py        # reports what the per-company cap discards
```

`load_company_vulns.py` upserts on `(company, cve_id)`, so it is safe to re-run,
and it filters out companies absent from `Companies` rather than failing a whole
batch on a foreign key.

---

## Notes and known limits

- **Findings are capped at 10 per company.** The median company has 12 CVEs, so
  this keeps roughly 16% of all findings. `measure_vulns.py` reports the tradeoff
  at other caps; raising it is a re-extract plus a re-run of the same loader.
- **Estimated exposure saturates.** EPSS tops out near 0.94, so most Critical
  companies land at a similar figure. It communicates scale well and differentiates
  poorly.
- **Contact data depends on the provider plan.** A free Hunter plan caps each
  search at 10 addresses and returns no phone numbers, so a large company's actual
  CISO may not be in the sample returned.
- **`country:US` alone is a poor pipeline query.** It returns arbitrary hosts,
  most without hostnames or known CVEs. Pair a country with a product keyword
  (`nginx`, `Apache`, `OpenSSH`) to target real web servers.
