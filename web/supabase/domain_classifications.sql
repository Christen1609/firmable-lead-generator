create table if not exists public."Domain_Classifications" (
  domain         text primary key,
  verdict        text not null check (verdict in ('business', 'infrastructure')),
  classified_at  timestamptz not null default now()
);

alter table public."Domain_Classifications" enable row level security;

analyze public."Domain_Classifications";
