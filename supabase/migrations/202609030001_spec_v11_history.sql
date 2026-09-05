begin;

-- Additive v1.1 history/audit model. Apply after 202609020001_detection_schema.sql.
alter table public.detection_candidates
  add column if not exists review_status text not null default 'unreviewed',
  add column if not exists review_version integer not null default 0,
  add column if not exists priority text not null default 'normal',
  add column if not exists completeness text not null default 'insufficient';

alter table public.detection_candidates
  add constraint detection_candidates_review_status_check check (
    review_status in (
      'unreviewed', 'investigating', 'no_issue', 'strong_suspicion',
      'inconclusive', 'report_prepared', 'response_verified'
    )
  ),
  add constraint detection_candidates_priority_check check (
    priority in ('normal', 'review', 'high', 'urgent')
  ),
  add constraint detection_candidates_completeness_check check (
    completeness in ('complete', 'partial', 'insufficient')
  );

create table if not exists public.candidate_discoveries (
  id bigint generated always as identity primary key,
  candidate_id uuid not null references public.detection_candidates(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  source text not null check (char_length(source) between 1 and 64),
  candidate_kind text not null check (char_length(candidate_kind) between 1 and 64),
  reason text not null default '' check (char_length(reason) <= 1000),
  discovered_at timestamptz not null default now()
);

create table if not exists public.candidate_observations (
  id bigint generated always as identity primary key,
  candidate_id uuid not null references public.detection_candidates(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  success boolean not null,
  evidence jsonb not null default '{}'::jsonb,
  error text not null default '' check (char_length(error) <= 500),
  observed_at timestamptz not null default now()
);

create table if not exists public.automated_assessments (
  id bigint generated always as identity primary key,
  candidate_id uuid not null references public.detection_candidates(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  model_confirmed boolean not null,
  category text not null check (char_length(category) between 1 and 128),
  summary text not null default '' check (char_length(summary) <= 2000),
  assessed_at timestamptz not null default now()
);

create table if not exists public.candidate_reviews (
  id bigint generated always as identity primary key,
  candidate_id uuid not null references public.detection_candidates(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  review_status text not null check (
    review_status in (
      'investigating', 'no_issue', 'strong_suspicion', 'inconclusive',
      'report_prepared', 'response_verified'
    )
  ),
  reason text not null check (char_length(reason) between 1 and 2000),
  evidence_refs jsonb not null default '[]'::jsonb,
  reviewed_at timestamptz not null default now()
);

create index if not exists candidate_discoveries_candidate_time_idx
  on public.candidate_discoveries (candidate_id, discovered_at desc);
create index if not exists candidate_observations_candidate_time_idx
  on public.candidate_observations (candidate_id, observed_at desc);
create index if not exists automated_assessments_candidate_time_idx
  on public.automated_assessments (candidate_id, assessed_at desc);
create index if not exists candidate_reviews_candidate_time_idx
  on public.candidate_reviews (candidate_id, reviewed_at desc);

alter table public.candidate_discoveries enable row level security;
alter table public.candidate_discoveries force row level security;
alter table public.candidate_observations enable row level security;
alter table public.candidate_observations force row level security;
alter table public.automated_assessments enable row level security;
alter table public.automated_assessments force row level security;
alter table public.candidate_reviews enable row level security;
alter table public.candidate_reviews force row level security;
revoke all on public.candidate_discoveries from anon, authenticated;
revoke all on public.candidate_observations from anon, authenticated;
revoke all on public.automated_assessments from anon, authenticated;
revoke all on public.candidate_reviews from anon, authenticated;

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
  v_process boolean := false;
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if p_domain is null or p_domain !~ '^[a-z0-9.-]{1,253}$' or not (p_domain like '%.%') then
    raise exception 'invalid domain';
  end if;
  if p_domain_hash !~ '^[0-9a-f]{64}$' or p_safe_url !~ '^https?://[^/?#]+/$' then
    raise exception 'invalid candidate';
  end if;

  select id,
    (decision_confirmed is true and last_seen_at < now() - make_interval(hours => least(greatest(p_dedup_hours, 1), 8760)))
    or (review_status in ('no_issue', 'inconclusive') and last_seen_at < now() - interval '6 hours')
    or (status = 'scanned' and scanned_at < now() - interval '1 hour')
    or (status in ('queued', 'scan_failed') and last_seen_at < now() - interval '15 minutes')
  into v_id, v_process
  from public.detection_candidates
  where owner_id = v_owner and domain_hash = p_domain_hash;

  if v_id is null then
    insert into public.detection_candidates (
      owner_id, domain, domain_hash, safe_url, source, candidate_kind,
      brand, score, reason
    ) values (
      v_owner, p_domain, p_domain_hash, p_safe_url,
      left(coalesce(nullif(p_source, ''), 'unknown'), 64),
      left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
      left(coalesce(p_brand, ''), 128),
      least(greatest(coalesce(p_score, 0), 0), 100),
      left(coalesce(p_reason, ''), 1000)
    ) returning id into v_id;
    v_process := true;
  else
    update public.detection_candidates set
      last_seen_at = now(), observation_count = observation_count + 1,
      source = left(coalesce(nullif(p_source, ''), 'unknown'), 64),
      candidate_kind = left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
      brand = left(coalesce(p_brand, ''), 128),
      score = least(greatest(coalesce(p_score, 0), 0), 100),
      reason = left(coalesce(p_reason, ''), 1000),
      status = case when v_process then 'queued' else status end
    where id = v_id and owner_id = v_owner;
  end if;

  insert into public.candidate_discoveries (
    candidate_id, owner_id, source, candidate_kind, reason
  ) values (
    v_id, v_owner,
    left(coalesce(nullif(p_source, ''), 'unknown'), 64),
    left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
    left(coalesce(p_reason, ''), 1000)
  );
  return case when v_process then v_id else null end;
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
declare
  v_owner uuid := auth.uid();
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if octet_length(coalesce(p_evidence, '{}'::jsonb)::text) > 20000 then
    raise exception 'evidence too large';
  end if;
  if not exists (
    select 1 from public.detection_candidates
    where id = p_candidate_id and owner_id = v_owner
  ) then return false; end if;

  insert into public.candidate_observations (
    candidate_id, owner_id, success, evidence, error
  ) values (
    p_candidate_id, v_owner, p_success, coalesce(p_evidence, '{}'::jsonb),
    left(coalesce(p_error, ''), 500)
  );
  update public.detection_candidates set
    status = case when p_success then 'scanned' else 'scan_failed' end,
    evidence = coalesce(p_evidence, '{}'::jsonb) ||
      case when p_error = '' then '{}'::jsonb
           else jsonb_build_object('error', left(p_error, 500)) end,
    scanned_at = now()
  where id = p_candidate_id and owner_id = v_owner;
  return true;
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
declare
  v_owner uuid := auth.uid();
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if not exists (
    select 1 from public.detection_candidates
    where id = p_candidate_id and owner_id = v_owner
  ) then return false; end if;

  insert into public.automated_assessments (
    candidate_id, owner_id, model_confirmed, category, summary
  ) values (
    p_candidate_id, v_owner, p_confirmed,
    left(coalesce(nullif(p_category, ''), 'unknown'), 128),
    left(coalesce(p_summary, ''), 2000)
  );
  update public.detection_candidates set
    status = case when status = 'scan_failed' then status else 'scanned' end,
    decision_confirmed = p_confirmed,
    decision_category = left(coalesce(p_category, ''), 128),
    decision_summary = left(coalesce(p_summary, ''), 2000)
  where id = p_candidate_id and owner_id = v_owner;
  return true;
end;
$$;

create or replace function private.submit_candidate_review(
  p_candidate_id uuid,
  p_review_status text,
  p_reason text,
  p_evidence_refs jsonb default '[]'::jsonb,
  p_expected_version integer default 0
)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_version integer;
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if p_review_status not in (
    'investigating', 'no_issue', 'strong_suspicion', 'inconclusive',
    'report_prepared', 'response_verified'
  ) then raise exception 'invalid review status'; end if;
  if char_length(trim(coalesce(p_reason, ''))) < 1 then
    raise exception 'review reason required';
  end if;
  if jsonb_typeof(coalesce(p_evidence_refs, '[]'::jsonb)) <> 'array' then
    raise exception 'evidence_refs must be an array';
  end if;

  update public.detection_candidates set
    review_status = p_review_status,
    review_version = review_version + 1,
    reviewed_at = now()
  where id = p_candidate_id and owner_id = v_owner
    and review_version = p_expected_version
  returning review_version into v_version;
  if v_version is null then raise exception 'review conflict or candidate not found'; end if;

  insert into public.candidate_reviews (
    candidate_id, owner_id, review_status, reason, evidence_refs
  ) values (
    p_candidate_id, v_owner, p_review_status,
    left(trim(p_reason), 2000), coalesce(p_evidence_refs, '[]'::jsonb)
  );
  return v_version;
end;
$$;

create or replace function public.submit_candidate_review(
  p_candidate_id uuid, p_review_status text, p_reason text,
  p_evidence_refs jsonb default '[]'::jsonb, p_expected_version integer default 0
)
returns integer language sql security invoker set search_path = '' as $$
  select private.submit_candidate_review(
    p_candidate_id, p_review_status, p_reason, p_evidence_refs, p_expected_version
  );
$$;

revoke all on function public.submit_candidate_review(uuid, text, text, jsonb, integer) from public, anon;
revoke all on function private.submit_candidate_review(uuid, text, text, jsonb, integer) from public, anon;
grant execute on function public.submit_candidate_review(uuid, text, text, jsonb, integer) to authenticated;
grant execute on function private.submit_candidate_review(uuid, text, text, jsonb, integer) to authenticated;

comment on table public.candidate_discoveries is 'Append-only candidate discovery history.';
comment on table public.candidate_observations is 'Append-only fetch/scan observations, including failures.';
comment on table public.automated_assessments is 'Automated assessments; never a human review.';
comment on table public.candidate_reviews is 'Append-only human review and audit history.';

commit;
