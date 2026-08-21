-- Cve_Enrichment — one row per CVE holding every per-CVE derived field.
--
-- Merges the old Cve_Descriptions (label) and Cve_Plain_Summaries (plain_summary)
-- tables: both were keyed on cve_id and cached once per CVE, so keeping them
-- apart bought nothing but a second round trip. `label` is nullable because only
-- CVEs the regexes cannot classify ever get one; `plain_summary` is nullable
-- because a brand-new CVE may not be rewritten yet.
--
-- Run once in the Supabase SQL editor. Additive; safe to re-run. Backfills from
-- the two old tables if they still exist. Drop the old tables only after the app
-- and scripts read this one.

create table if not exists public."Cve_Enrichment" (
  cve_id        text primary key,
  label         text,          -- one of the VULN_TITLES keys, or null (regex handled it)
  plain_summary text,          -- salesperson-readable rewrite, or null (not rewritten yet)
  cwe_id        text,          -- NVD-assigned CWE weakness class, or null / NONE
  classified_at timestamptz,
  rewritten_at  timestamptz
);

insert into public."Cve_Enrichment" (cve_id, label, classified_at)
  select cve_id, label, classified_at from public."Cve_Descriptions"
  on conflict (cve_id) do update
    set label = excluded.label, classified_at = excluded.classified_at;

insert into public."Cve_Enrichment" (cve_id, plain_summary, rewritten_at)
  select cve_id, plain_summary, rewritten_at from public."Cve_Plain_Summaries"
  on conflict (cve_id) do update
    set plain_summary = excluded.plain_summary, rewritten_at = excluded.rewritten_at;

alter table public."Cve_Enrichment" enable row level security;
drop policy if exists "Cve_Enrichment are readable" on public."Cve_Enrichment";
create policy "Cve_Enrichment are readable"
  on public."Cve_Enrichment" for select
  to anon, authenticated
  using (true);

analyze public."Cve_Enrichment";
