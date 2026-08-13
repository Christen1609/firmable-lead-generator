# Sales Intelligence Platform

Sales prospecting tool that turns raw internet scan data into a ranked list of companies with real, externally visible security exposures. Companies are ranked by what attackers are actively exploiting rather than by severity score, so a sales team can open with evidence rather than a cold pitch.

## Stack

- **Next.js** (App Router, TypeScript) + Tailwind CSS + shadcn/ui
- **Supabase** (Postgres) for company data
- **Google Gemini** for outreach email generation
- **Vercel** for deployment

## Getting Started

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.local.example .env.local
# Fill in your Supabase URL, key, and Gemini API key

# Run dev server
npm run dev

# Build for production
npm run build
```

## Environment Variables

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project REST URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Publishable key, read-only under RLS |
| `SUPABASE_SERVICE_KEY` | Service-role key, server-only |
| `GEMINI_API_KEY` | Google Gemini API key for email generation |

## Features

### Company List (Entry Screen)
- Table of companies sorted by tier (Critical first), then by EPSS
- Coloured tier badges: Critical (red), High (orange), Medium (yellow), Low (grey)
- Filters: country dropdown, tier dropdown, search by company name
- Pagination (50 per page)
- Estimated financial exposure per company

### Company Detail (Primary Output)
- Company domain, country, tier, estimated exposure with IBM label
- KEV status (actively exploited) and ransomware association
- CVE count and max CVSS/EPSS scores
- Key findings in plain English — worst CVEs with descriptions, severity, and attack probability
- Outreach Email button

### Outreach Email
- Generates a personalised sales email using Google Gemini
- Feeds only the company's real data (flaw summaries, flags, pre-computed exposure)
- LLM never invents numbers — all quantitative values are computed in code and passed in
- Email is editable in the UI with copy-to-clipboard

## Scoring Tiers

| Tier | Criteria |
|---|---|
| **Critical** | At least one KEV-listed CVE (actively exploited) |
| **High** | Highest EPSS ≥ 0.5 (likely within 30 days) |
| **Medium** | Highest EPSS ≥ 0.1 (real risk, not immediate) |
| **Low** | Everything else with a CVE |

## Estimated Exposure

`IBM average breach cost × company max EPSS`, rounded. The IBM figure is stored in the Supabase `settings` table (`ibm_avg_breach = 4,400,000`) and is editable. Displayed with source and year, labelled as an estimate.

## Database Schema

### `companies` (primary key: `company`)
| column | type | meaning |
|---|---|---|
| company | text (PK) | root domain |
| country | text | company country |
| max_cvss | float8 | worst CVSS severity |
| max_epss | float8 | highest attack probability (0–1) |
| cve_count | int8 | number of distinct CVEs |
| in_kev | bool | has an actively-exploited CVE |
| ransomware | bool | has a ransomware-linked CVE |
| tier | text | Critical / High / Medium / Low |

### `settings` (primary key: `key`)
| column | type |
|---|---|
| key | text (PK) |
| value | numeric |

### `company_vulns` (per-CVE detail)
| column | type | meaning |
|---|---|---|
| company | text (FK) | owning company |
| cve_id | text | CVE identifier |
| cvss | float8 | severity |
| epss | float8 | attack probability |
| summary | text | plain-English description |
| in_kev | bool | actively exploited |

## Architecture Decisions

- **Entity resolution** is the hard part: raw scan `org`/`isp` fields name hosting providers, not companies. Resolution uses layered filters (deterministic first, AI for edge cases) to extract real company domains from SSL cert CNs and hostnames.
- **LLM guardrails**: Gemini receives only finished data (flaw summaries, flags, pre-computed exposure number). It only phrases them — it never invents numbers.
- **Honest limitation**: resolution covers the subset of servers with a usable domain; a few providers still leak through. Coverage is partial by nature.
