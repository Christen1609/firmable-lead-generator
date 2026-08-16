-- Cve_Descriptions — one plain-English label per CVE, resolved once.
--
-- describeVulnerability() in src/lib/constants.ts matches CVE summary text
-- against a list of regexes. Measured over the 1,610 distinct CVEs in
-- Company_Vulns, 647 of them (40.2%) matched nothing and fell through to a
-- generic string that tells the reader nothing.
--
-- The gap is not fixable by more regexes alone: real CVE text describes a
-- mechanism ("forward the request to an origin server chosen by the remote
-- user") rather than naming a class ("SSRF").
--
-- The dataset only holds ~1,610 distinct CVEs, and a CVE's description never
-- changes, so each one is worth resolving exactly once and keeping forever.
-- classify_cves.py fills this table; the app reads it and falls back to the
-- regexes when a row is missing, so an empty table behaves exactly as before.
--
-- `label` is a key from VULN_TITLES, never free text — the model chooses from a
-- fixed set and the sentence is looked up in code, so a wrong answer is a wrong
-- label from a safe list rather than an invented claim.

create table if not exists public."Cve_Descriptions" (
  cve_id         text primary key,
  label          text not null,
  classified_at  timestamptz not null default now()
);

alter table public."Cve_Descriptions" enable row level security;

-- Read-only for the browser-safe key; the backfill writes with the service key.
drop policy if exists "Cve_Descriptions are readable" on public."Cve_Descriptions";
create policy "Cve_Descriptions are readable"
  on public."Cve_Descriptions" for select
  to anon, authenticated
  using (true);

analyze public."Cve_Descriptions";
