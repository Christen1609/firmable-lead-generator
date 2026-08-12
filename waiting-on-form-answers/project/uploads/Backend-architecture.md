# Sales Intelligence Platform — Architecture & Build Brief

## 1. What This Is

An OSINT-driven sales prospecting tool for a cybersecurity software company. It turns raw internet scan data into a ranked list of companies with real security exposures, so a sales team can identify who needs the product and open the conversation with specific, evidence-backed urgency.

The core idea: don't sell on "you have vulnerabilities." Sell on "this specific flaw on your systems is being actively exploited right now, here is the probability it gets hit in the next 30 days, and here is a plain-English breakdown a salesperson can act on."

The unit of output is the **company**, not the scan. Raw scans are grouped and resolved into companies, scored by exposure, and ranked.

## 2. The Data (already processed)

Three inputs, reduced to one final table.

**Shodan scan data (provided, ~5 GB, `.zst` NDJSON).** ~6.1M server records. Each record already contains, inside its `vulns` field: the CVE ID, the CVSS severity score, the EPSS attack-probability score, and a plain-English summary of the flaw. This means CVSS, EPSS, and descriptions did NOT require separate downloads — they were already in the data.

**CISA KEV (downloaded once, joins on CVE ID).** The authoritative list of vulnerabilities confirmed exploited in the wild. Also carries a `knownRansomwareCampaignUse` flag, which supplies the ransomware angle for free. ~1,662 entries.

**IBM breach-cost figure (single sourced constant).** One number from IBM's annual Cost of a Data Breach report, stored as an editable row in the database. Used only to compute an estimated financial exposure. NOT scraped, NOT LLM-generated.

Sources deliberately excluded (and why): NVD (descriptions already in Shodan data), ransomware.live (flag already in KEV), live Shodan API (rate-limited, adds only more raw noise, not more resolvable companies).

## 3. The Pipeline

The pipeline runs in two modes off the **same core cleaning code**: (A) batch, over the provided 5 GB file — already done, produced the current Supabase table; (B) live, pulling fresh records from the Shodan API on demand and writing new companies into the same Supabase table. Both share stages 2–6 below.

### Core stages (shared by both modes)

1. **Extract / ingest.** Batch: read the `.zst` with DuckDB (streams the compressed file, never fully decompressed). Live: query the Shodan API for a target slice (e.g. a country or a product), receiving the same record shape. Keep per record: the CVEs (from `vulns`), the domain (from `hostnames` or the SSL cert CN), the country (`location.country_name`), and CVSS/EPSS (already inside `vulns`).

2. **Resolve companies (entity resolution — the hard part).** A server's `org`/`isp` names the hosting provider (AWS, Deutsche Telekom), NOT the company. The real company comes from the hostname or SSL certificate. This stage is designed as **layers, cheap and deterministic first, AI only for the leftovers**:
   - **Layer 1 — extract.** Prefer the cert CN, else the first hostname. Extract the root domain with `tldextract` (correctly handles `co.jp`, `co.uk`, etc.).
   - **Layer 2 — rule filters (deterministic, pattern-based, not a hardcoded list).** Drop system junk (`.arpa`, `in-addr`). Drop hostnames that are just an IP written as text. Drop domains whose server count is implausibly high (a real company does not own thousands of scanned servers — this catches providers you never listed, which a fixed blocklist cannot). A small keyword hint-list (`isp`, `cloud`, `hosting`, `dns`, `broadband`, etc.) handles the obvious ones.
   - **Layer 3 — AI for the uncertain cases only.** For the small set of domains the rules can't confidently classify, ask the LLM a single yes/no: "Is this a real operating business, or a hosting/telecom/infrastructure provider?" This is the robustness answer — the pipeline handles data it was never hardcoded for, by using judgement on the edge cases instead of a brittle list. It is also on-thesis: resolving messy identity with AI is exactly Firmable's core business. **Cost control:** the LLM sees only the ambiguous domains (a fraction), never the whole set; results are cached per domain so the same one is never asked twice.
   - Records with no usable domain are dropped — you cannot sell to an IP.
   - **Honest limitation (state it openly):** resolution covers the subset of servers with a usable domain; a few providers still leak through. Coverage is partial by nature. This is precisely the problem Firmable solves at scale, so the design shows the shape of the real solution rather than faking completeness.

3. **Join KEV.** Match each company's CVEs against the CISA KEV list on CVE ID. Set `in_kev` (actively exploited) and `ransomware` (ransomware-linked, from KEV's `knownRansomwareCampaignUse`).

4. **Score.** One tier per company, set by its worst finding:
   - **Critical** — at least one KEV-listed CVE ("being attacked right now").
   - **High** — highest EPSS ≥ 0.5 ("likely within 30 days").
   - **Medium** — highest EPSS ≥ 0.1 ("real risk, not immediate").
   - **Low** — everything else with a CVE.
   Worst finding wins: one Critical server makes the whole company Critical.

5. **Estimated exposure.** `IBM_avg_breach × company_max_epss`, rounded. The IBM figure is read from the `settings` table in Supabase. Displayed with source and year, labelled an estimate. Computed in code — never produced by the LLM.

6. **Write to database.** Upsert the resulting company rows into the Supabase `companies` table, keyed on `company` (so re-runs update rather than duplicate). Per-CVE detail rows go to `company_vulns`. The batch run already populated the table; live runs append/update new companies into the same tables the app reads.

### Mode A — batch (done)
Ran once over the 5 GB file → ~25,117 companies in Supabase. This is the demo dataset.

### Mode B — live (the "above and beyond" layer)
A single script: given a target (country / product), it calls the Shodan API, runs the exact same stages 2–6, and upserts new companies into Supabase. This is what demonstrates the pipeline is real and not a one-off clean of a fixed file. It answers the "why haven't you made it live?" question by **being** live. Built only after the app works; it reuses the identical cleaning code, so it is assembly, not new logic.

## 4. Database Schema (Supabase / Postgres)

**Table: `companies`** (primary key: `company`)

| column | type | meaning |
|---|---|---|
| company | text (PK) | root domain, e.g. `entreda.net` |
| country | text | company country |
| max_cvss | float8 | worst CVSS severity across its servers |
| max_epss | float8 | highest attack probability (0–1) |
| cve_count | int8 | number of distinct CVEs found |
| in_kev | bool | has an actively-exploited (KEV) CVE |
| ransomware | bool | has a ransomware-linked CVE |
| tier | text | Critical / High / Medium / Low |

**Table: `settings`** (primary key: `key`)

| column | type |
|---|---|
| key | text (PK) |
| value | numeric |

Row: `ibm_avg_breach = 4400000` (verify against the current IBM report before demo).

**Table: `company_vulns`** (the per-CVE detail the detail view and email need)

| column | type | meaning |
|---|---|---|
| company | text (FK → companies.company) | owning company |
| cve_id | text | e.g. `CVE-2025-26465` |
| cvss | float8 | severity |
| epss | float8 | attack probability |
| summary | text | plain-English description (already in the Shodan `vulns` field) |
| in_kev | bool | actively exploited |

The detail screen reads the worst few rows here to show findings in plain English; the email generator is fed these same rows. The current `companies` table has the summary counts/flags; `company_vulns` must be produced by a small pipeline pass (one row per CVE per company) and loaded before the detail view can show real findings.

## 5. The App (to build — Next.js on Vercel)

Stack: Next.js (App Router) + Tailwind + shadcn/ui, Supabase client for data, Gemini API for email generation, deployed on Vercel.

**Screen 1 — Company list (entry screen).**
A table of companies sorted by tier (Critical first), then by EPSS. Columns: company, country, tier (coloured badge — Critical red, High orange, Medium yellow, Low grey), estimated exposure. Filters: country dropdown, tier dropdown. Search by company name. Row click → detail.

**Screen 2 — Company detail (the primary output).**
This is the main deliverable, the sales-consultant view. Shows: company domain, country, tier, estimated exposure with its IBM label, KEV status, ransomware status, CVE count, and the key findings in plain English (worst CVEs, what they do, severity, attack probability). This is what a salesperson reads before a call. Everything is plain language — no raw CVE IDs front-and-centre, no unexplained scores.

**Outreach Email button (on the detail screen).**
A single button labelled "Outreach Email." On click, Gemini generates a personalised outreach email using that company's real findings (the flaws, the KEV/ransomware flags, the estimated exposure figure passed in from code). The email is plain-English, business-owner language, and editable in the UI. This is a deliberate personal touch — outbound outreach is a strength of the author's, and this productises it.

**LLM guardrails (critical):**
- The LLM receives finished data (flaw summaries, flags, the pre-computed exposure number). It only phrases them.
- The LLM never invents numbers — not the exposure figure, not breach costs, nothing quantitative. Any dollar value is computed in code and passed in.
- Feed it only the specific company's real fields, nothing else, to prevent hallucinated facts.

## 6. Build Order (do not invert)

1. Data into Supabase — done.
2. Scaffold Next.js, deploy an empty app to Vercel first so hosting is proven early.
3. Company list screen reading from Supabase.
4. Company detail screen.
5. Outreach Email button + Gemini integration.
6. Filters, tier badge colours, shadcn polish. Final deploy. README.

Functional first, styled second. The app must work plainly before any time goes into visual polish.

## 7. Scope

**Core (must ship):** the app — company list, company detail (primary output), Outreach Email button — reading the existing Supabase table. This is the graded deliverable.

**Above-and-beyond layer (only after core works):** Mode B live pipeline (Shodan API → same cleaning → Supabase) and Layer-3 AI edge-case resolution. These are real work above the ask and directly answer Karthik's likely "why isn't it live / why is it deterministic?" — by shipping the live, AI-assisted version rather than promising it.

**Genuinely out of scope (MVP):** NVD, ransomware.live, WHOIS company-name enrichment, user auth, CRM integration, real-time alerting. Noted as future work.

**Build order is not negotiable:** core app first, live/AI pipeline second. A working app plus a basic pipeline beats a perfect pipeline and no app.

## 8. Honest Framing for the Demo

The valuable, hard part of this project is entity resolution — turning messy scan data into real, identifiable companies. It is imperfect by nature and that is stated openly, with the coverage limitation named. This is precisely the problem the hiring company works on, so demonstrating a working, honest, well-scoped version of it — rather than a fake-perfect one — is the point.
