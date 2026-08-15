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
 1. OFFLINE BATCH  (run once, seeded the database)
 ─────────────────────────────────────────────────
   test_scans.json.zst  5.6 GB / 6,124,461 host records
        │
        ▼   DuckDB streaming read, never loaded into memory
   entity resolution ─► KEV join (CISA) ─► tier scoring
        │
        ▼
   25,117 companies + 177,679 findings ──────────┐
                                                 │
                                                 ▼
 2. READ PATH  (every page view)          ┌──────────────────┐
 ────────────────────────────────         │                  │
   Browser                                │     Supabase     │
      │                                   │     Postgres     │
      ▼                                   │      (syd1)      │
   Vercel edge ─► prerendered shell       │                  │
      │                                   └──────────────────┘
      ▼                                       ▲          ▲
   Next.js server (syd1)                      │ on miss  │
      │                                       │          │
      └─► use cache ─────────────────────────►┘          │
          key = tier + country + search + page + cursor   │
          TTL: minutes (companies + findings) / days (config)
          a repeat view reaches Postgres zero times ──────┘


 3. WRITE PATH  (Find More, on demand)
 ──────────────────────────────────────
   user query (country + product)
        │
        ▼
   Shodan /host/search  ──►  same five stages as batch:
        │                    extract ─► resolve (rules, then Gemini on
        │                    every survivor, verdicts cached by domain)
        │                    ─► KEV ─► score
        ▼
   upsert into Supabase ─► revalidateTag('companies')


 4. PER-CLICK SERVICES  (read only, nothing persisted)
 ──────────────────────────────────────────────────────
   company detail page
        │
        ├─► Gemini 2.5-flash ─► outreach email  ─┐
        ├─► Gemini 2.5-flash ─► call hook       ├─► rendered, then discarded
        └─► Hunter.io        ─► contacts        ─┘
```

The live **Find More** pipeline runs the same five stages as the batch, writing
to the same tables. A company's findings do not depend on whether it arrived via
the batch load or a live run — there is one source of truth for both.

Reads are cached per filter combination and invalidated on write, so a pipeline
run surfaces immediately rather than when a TTL expires.

Caching only the cheap queries turned out to be worth nothing. The detail page
issues its three queries under one `Promise.all`, so the page waits for the
slowest — and while the findings query was uncached it held that floor no matter
how fast the other two returned. Caching it too is what makes a repeat view cost
zero database round trips. The argument for leaving it out was that 25,000+
companies would rarely repeat, which reads the access pattern backwards: nobody
browses 25,000 companies, they reopen the top of a ranked list.

### Why the filtering is layered

Deterministic rules run first and remove the obvious infrastructure: an IP with
no hostname is not a company, and a domain containing `hosting` or `aws` is not
a prospect. Whatever survives goes to the model.

That last part changed after measurement. The model originally only saw domains
serving more than 50 hosts, on the assumption that everything else was cheap to
judge by name. A sampled audit found the opposite — six small regional ISPs had
survived into the prospect list, and their domain names carry no signal at all
(`leon.com.pl`, `houseti.com.br`). No keyword list in any language catches those,
and with a handful of servers each they never crossed the threshold to reach the
model. **The one filter that could have identified them was switched off for
exactly the cases that needed it.**

Classifying everything is affordable because verdicts are chunked at 40 per call
and cached by domain in `Domain_Classifications`. A domain seen before costs
nothing, and a fresh 100-record run is one or two API calls.

### How the classifier is kept honest

Three properties, all enforced in code rather than promised in a prompt:

- **Fails open.** Only a domain the model explicitly calls `infrastructure` is
  dropped. Anything unanswered is kept and counted. Previously a truncated reply
  or a renumbered line silently deleted a domain, which was indistinguishable
  from a real verdict.
- **Reconciled.** Verdicts are matched against domains submitted. If under half
  a batch comes back answered, every verdict in it is discarded rather than
  partially believed.
- **Canaries.** Each batch carries known-answer domains — `cloudflare.com` must
  return infrastructure, `bmw.com` must return business. A wrong canary discards
  the batch. Reconciliation catches malformed output; this catches confidently
  wrong output.

### Measured accuracy

Entity resolution was audited against a reproducible random sample rather than
assumed:

| | |
|---|---|
| Precision | **~80%** — 32 of 40 reachable companies in a 50-company sample were genuine organisations |
| Recall | **~97–99%** — 40 sampled domains from those the filter discarded contained 2–3 real businesses |

The filter is deliberately conservative: it rarely loses a real prospect, and
pays for that by letting some infrastructure through. For a sales tool that is
the right direction — a missed company is a lead you never knew existed, while a
wrongly-kept ISP costs a rep thirty seconds. A security product would tune the
opposite way.

Limits worth stating: n=50 gives roughly a ±12% interval, a homepage title is a
proxy for ground truth rather than ground truth, and recall was measured against
the keyword filter only. The plain-English CVE descriptions and the contact
ranking remain unmeasured.

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
