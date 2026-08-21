-- Cwe_Copy — official CWE weakness class -> the plain-English headline.
--
-- NVD tags each CVE with a CWE (fetch_cwe.py -> Cve_Enrichment.cwe_id). This
-- table turns that authoritative class into the sentence shown on the card,
-- replacing the old Gemini label-guess. Each title reuses one of the existing
-- headline sentences, so BUSINESS_IMPACT (keyed on the title) still supplies the
-- "what this means" line unchanged.
--
-- Lives in data, not code, so wording is editable without a redeploy — and a new
-- CWE is one INSERT, not a code change. Covers the CWEs that carry ~85% of
-- findings; anything not here falls back to the keyword/product/generic chain.
--
-- Run once in the Supabase SQL editor. Safe to re-run.

create table if not exists public."Cwe_Copy" (
  cwe_id text primary key,
  title  text not null
);

alter table public."Cwe_Copy" enable row level security;
drop policy if exists "Cwe_Copy are readable" on public."Cwe_Copy";
create policy "Cwe_Copy are readable"
  on public."Cwe_Copy" for select to anon, authenticated using (true);

insert into public."Cwe_Copy" (cwe_id, title) values
  ('CWE-79',  'Attackers can hijack a signed-in user''s session'),
  ('CWE-89',  'Attackers can reach the database behind this server'),
  ('CWE-78',  'Attackers can run system commands on this server'),
  ('CWE-77',  'Attackers can run system commands on this server'),
  ('CWE-94',  'Attackers can run their own code on this server'),
  ('CWE-95',  'Attackers can run their own code on this server'),
  ('CWE-116', 'Attackers can run their own code on this server'),
  ('CWE-918', 'Attackers can make this server call systems behind the firewall'),
  ('CWE-611', 'Attackers can make this server fetch files and internal systems'),
  ('CWE-502', 'Attackers can smuggle hostile data into the application'),
  ('CWE-434', 'Attackers can overwrite files on this server'),
  ('CWE-22',  'Attackers can read files they should never reach'),
  ('CWE-73',  'Attackers can read files they should never reach'),
  ('CWE-352', 'Attackers can make a signed-in user act without meaning to'),
  ('CWE-601', 'Attackers can bounce your visitors to a site they control'),
  ('CWE-444', 'Attackers can sneak hidden requests past your defences'),
  ('CWE-400', 'Attackers can knock this service offline'),
  ('CWE-770', 'Attackers can knock this service offline'),
  ('CWE-787', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-119', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-125', 'Attackers can read information that should stay private'),
  ('CWE-416', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-476', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-190', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-193', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-120', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-843', 'Attackers can crash or take over the service through memory abuse'),
  ('CWE-20',  'Attackers can feed this server input it fails to check'),
  ('CWE-863', 'Attackers can reach data or actions without permission'),
  ('CWE-862', 'Attackers can reach data or actions without permission'),
  ('CWE-284', 'Attackers can reach data or actions without permission'),
  ('CWE-732', 'Attackers can reach data or actions without permission'),
  ('CWE-287', 'Attackers can get in without valid credentials'),
  ('CWE-306', 'Attackers can get in without valid credentials'),
  ('CWE-798', 'Attackers can log in with credentials shipped in the product'),
  ('CWE-522', 'Attackers can read information that should stay private'),
  ('CWE-269', 'Attackers can raise their own level of access'),
  ('CWE-428', 'Attackers can raise their own level of access'),
  ('CWE-295', 'Attackers positioned on the network can read or alter traffic'),
  ('CWE-345', 'Attackers can impersonate a trusted source'),
  ('CWE-203', 'Attackers can read information that should stay private'),
  ('CWE-200', 'Attackers can read information that should stay private'),
  ('CWE-362', 'Attackers can exploit a timing flaw to slip past a check')
on conflict (cwe_id) do update set title = excluded.title;

analyze public."Cwe_Copy";
