begin;

-- CYCOT detection persistence for Supabase/PostgreSQL.
-- Apply with the Supabase SQL editor or CLI before starting the application.

-- Keep this schema out of Settings > API > Exposed schemas.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create table if not exists public.detection_candidates (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  domain text not null check (char_length(domain) between 1 and 253 and domain !~ '[/:[:space:]]'),
  domain_hash text not null check (domain_hash ~ '^[0-9a-f]{64}$'),
  safe_url text not null check (safe_url ~ '^https?://[^/?#]+/$'),
  source text not null check (char_length(source) between 1 and 64),
  candidate_kind text not null check (char_length(candidate_kind) between 1 and 64),
  brand text not null default '' check (char_length(brand) <= 128),
  score smallint not null default 0 check (score between 0 and 100),
  reason text not null default '' check (char_length(reason) <= 1000),
  status text not null default 'queued' check (status in ('queued', 'scanned', 'scan_failed', 'reviewed')),
  evidence jsonb not null default '{}'::jsonb,
  decision_confirmed boolean,
  decision_category text not null default '' check (char_length(decision_category) <= 128),
  decision_summary text not null default '' check (char_length(decision_summary) <= 2000),
  observation_count integer not null default 1 check (observation_count > 0),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  scanned_at timestamptz,
  reviewed_at timestamptz,
  unique (owner_id, domain_hash)
);

create index if not exists detection_candidates_owner_status_seen_idx
  on public.detection_candidates (owner_id, status, last_seen_at desc);
create index if not exists detection_candidates_owner_kind_seen_idx
  on public.detection_candidates (owner_id, candidate_kind, last_seen_at desc);

alter table public.detection_candidates enable row level security;
alter table public.detection_candidates force row level security;
revoke all on public.detection_candidates from anon, authenticated;

create or replace function public.app_health()
returns boolean
language sql
security invoker
set search_path = ''
as $$
  select auth.uid() is not null;
$$;

create or replace function private.claim_candidate(
  p_domain text,
  p_domain_hash text,
  p_safe_url text,
  p_source text,
  p_candidate_kind text,
  p_brand text,
  p_score integer,
  p_reason text,
  p_dedup_hours integer default 336
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_id uuid;
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if p_domain is null or p_domain !~ '^[a-z0-9.-]{1,253}$' or not (p_domain like '%.%') then
    raise exception 'invalid domain';
  end if;
  if p_domain_hash !~ '^[0-9a-f]{64}$' or p_safe_url !~ '^https?://[^/?#]+/$' then
    raise exception 'invalid candidate';
  end if;

  insert into public.detection_candidates (
    owner_id, domain, domain_hash, safe_url, source, candidate_kind, brand, score, reason
  ) values (
    v_owner, p_domain, p_domain_hash, p_safe_url,
    left(coalesce(nullif(p_source, ''), 'unknown'), 64),
    left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
    left(coalesce(p_brand, ''), 128), least(greatest(coalesce(p_score, 0), 0), 100),
    left(coalesce(p_reason, ''), 1000)
  )
  on conflict (owner_id, domain_hash) do update set
    last_seen_at = now(), observation_count = detection_candidates.observation_count + 1,
    source = excluded.source, candidate_kind = excluded.candidate_kind,
    brand = excluded.brand, score = excluded.score, reason = excluded.reason,
    status = 'queued', evidence = '{}'::jsonb, decision_confirmed = null,
    decision_category = '', decision_summary = '', scanned_at = null, reviewed_at = null
  where (detection_candidates.decision_confirmed is true
         and detection_candidates.last_seen_at < now() - make_interval(hours => least(greatest(p_dedup_hours, 1), 8760)))
     or (detection_candidates.status = 'reviewed'
         and detection_candidates.decision_confirmed is false
         and detection_candidates.last_seen_at < now() - interval '6 hours')
     or (detection_candidates.status = 'scanned'
         and detection_candidates.scanned_at < now() - interval '1 hour')
     or (detection_candidates.status in ('queued', 'scan_failed')
         and detection_candidates.last_seen_at < now() - interval '15 minutes')
  returning id into v_id;

  return v_id;
end;
$$;

create or replace function private.record_candidate_scan(
  p_candidate_id uuid,
  p_success boolean,
  p_evidence jsonb default '{}'::jsonb,
  p_error text default ''
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  if octet_length(coalesce(p_evidence, '{}'::jsonb)::text) > 20000 then
    raise exception 'evidence too large';
  end if;
  update public.detection_candidates set
    status = case when p_success then 'scanned' else 'scan_failed' end,
    evidence = coalesce(p_evidence, '{}'::jsonb) ||
      case when p_error = '' then '{}'::jsonb else jsonb_build_object('error', left(p_error, 500)) end,
    scanned_at = now()
  where id = p_candidate_id and owner_id = auth.uid();
  return found;
end;
$$;

create or replace function private.record_candidate_decision(
  p_candidate_id uuid,
  p_confirmed boolean,
  p_category text default '',
  p_summary text default ''
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  update public.detection_candidates set
    status = 'reviewed', decision_confirmed = p_confirmed,
    decision_category = left(coalesce(p_category, ''), 128),
    decision_summary = left(coalesce(p_summary, ''), 2000), reviewed_at = now()
  where id = p_candidate_id and owner_id = auth.uid();
  return found;
end;
$$;

-- Public Data API wrappers remain SECURITY INVOKER.  Elevated table access is
-- isolated in the non-exposed private schema and every private function checks
-- auth.uid() before touching a row.
create or replace function public.claim_candidate(
  p_domain text, p_domain_hash text, p_safe_url text, p_source text,
  p_candidate_kind text, p_brand text, p_score integer, p_reason text,
  p_dedup_hours integer default 336
)
returns uuid language sql security invoker set search_path = '' as $$
  select private.claim_candidate(
    p_domain, p_domain_hash, p_safe_url, p_source, p_candidate_kind,
    p_brand, p_score, p_reason, p_dedup_hours
  );
$$;

create or replace function public.record_candidate_scan(
  p_candidate_id uuid, p_success boolean, p_evidence jsonb default '{}'::jsonb,
  p_error text default ''
)
returns boolean language sql security invoker set search_path = '' as $$
  select private.record_candidate_scan(p_candidate_id, p_success, p_evidence, p_error);
$$;

create or replace function public.record_candidate_decision(
  p_candidate_id uuid, p_confirmed boolean, p_category text default '',
  p_summary text default ''
)
returns boolean language sql security invoker set search_path = '' as $$
  select private.record_candidate_decision(p_candidate_id, p_confirmed, p_category, p_summary);
$$;

revoke all on function public.app_health() from public, anon;
revoke all on function public.claim_candidate(text, text, text, text, text, text, integer, text, integer) from public, anon;
revoke all on function public.record_candidate_scan(uuid, boolean, jsonb, text) from public, anon;
revoke all on function public.record_candidate_decision(uuid, boolean, text, text) from public, anon;
revoke all on function private.claim_candidate(text, text, text, text, text, text, integer, text, integer) from public, anon;
revoke all on function private.record_candidate_scan(uuid, boolean, jsonb, text) from public, anon;
revoke all on function private.record_candidate_decision(uuid, boolean, text, text) from public, anon;
grant execute on function public.app_health() to authenticated;
grant execute on function public.claim_candidate(text, text, text, text, text, text, integer, text, integer) to authenticated;
grant execute on function public.record_candidate_scan(uuid, boolean, jsonb, text) to authenticated;
grant execute on function public.record_candidate_decision(uuid, boolean, text, text) to authenticated;
grant execute on function private.claim_candidate(text, text, text, text, text, text, integer, text, integer) to authenticated;
grant execute on function private.record_candidate_scan(uuid, boolean, jsonb, text) to authenticated;
grant execute on function private.record_candidate_decision(uuid, boolean, text, text) to authenticated;

comment on table public.detection_candidates is
  'Per-user candidate state. Paths, query strings, DOM and screenshots are intentionally not stored.';

commit;
