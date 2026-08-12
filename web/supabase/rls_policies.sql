-- Row Level Security for the public read path.
--
-- Background: the app shipped using a Supabase service-role key held in
-- NEXT_PUBLIC_SUPABASE_KEY. That key bypasses RLS entirely, which is why the
-- app worked despite "Companies" having RLS enabled and no policies at all.
-- The NEXT_PUBLIC_ prefix means a single client-side import of the Supabase
-- module would have inlined a full-access database key into the browser bundle.
--
-- After this migration the browser-safe anon key can read exactly what the two
-- screens need and nothing else. Writes stay on the server-side service key,
-- which the pipeline route uses and which is never exposed to the client.
--
-- Run once in the Supabase SQL editor.

-- ---------------------------------------------------------------------------
-- Companies — read-only for anon/authenticated
-- ---------------------------------------------------------------------------
alter table public."Companies" enable row level security;

drop policy if exists "Companies are publicly readable" on public."Companies";
create policy "Companies are publicly readable"
  on public."Companies" for select
  to anon, authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- settings — read-only. RLS was previously disabled on this table, so the
-- default grants left it writable by any role holding a key.
-- ---------------------------------------------------------------------------
alter table public.settings enable row level security;

drop policy if exists "settings are publicly readable" on public.settings;
create policy "settings are publicly readable"
  on public.settings for select
  to anon, authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- Company_Vulns already carries a select policy from company_vulns.sql.
-- Restated here so this file is a complete description of the read path.
-- ---------------------------------------------------------------------------
alter table public."Company_Vulns" enable row level security;

drop policy if exists "Company_Vulns are readable" on public."Company_Vulns";
create policy "Company_Vulns are readable"
  on public."Company_Vulns" for select
  to anon, authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- No insert/update/delete policies anywhere by design. With RLS enabled and no
-- write policy, anon and authenticated cannot write at all, regardless of the
-- table grants underneath. The pipeline writes with the service key, which
-- bypasses RLS.
-- ---------------------------------------------------------------------------
