-- Cve_Plain_Summaries — one salesperson-readable rewrite per CVE.
--
-- The detail card shows a derived plain-English headline (describeVulnerability)
-- but under it, the raw CVE summary verbatim — engineer-speak a salesperson
-- cannot use ("Improper escaping of output in mod_rewrite ... map URLs to
-- filesystem locations"). This table holds a plain rewrite of that paragraph.
--
-- Only ~1,876 distinct CVEs exist across 182k findings and a CVE's text never
-- changes, so each is rewritten once (rewrite_summaries.py) and reused forever.
--
-- This is the ONE place model-written prose reaches the page, so the writer is
-- guarded hard: the rewrite may not add a product, version or number absent from
-- the source, may not claim a breach, and is discarded if it breaks a rule — in
-- which case the app falls back to the raw summary. An empty or unreachable
-- table therefore behaves exactly like today.
--
-- Run once in the Supabase SQL editor. Additive; safe to re-run.

create table if not exists public."Cve_Plain_Summaries" (
  cve_id        text primary key,
  plain_summary text not null,
  rewritten_at  timestamptz not null default now()
);

alter table public."Cve_Plain_Summaries" enable row level security;

-- Read-only for the browser-safe key; the backfill writes with the service key.
drop policy if exists "Cve_Plain_Summaries are readable" on public."Cve_Plain_Summaries";
create policy "Cve_Plain_Summaries are readable"
  on public."Cve_Plain_Summaries" for select
  to anon, authenticated
  using (true);

analyze public."Cve_Plain_Summaries";
