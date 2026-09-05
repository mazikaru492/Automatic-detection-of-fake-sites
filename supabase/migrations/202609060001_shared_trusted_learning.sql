begin;

-- Apply after 202609030002_online_learning.sql.
-- One dedicated Supabase project is shared by administrator-approved users.
-- Existing Auth users are trusted during this migration. New users must be
-- explicitly inserted into private.trusted_app_users by an administrator.

create table if not exists private.trusted_app_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '' check (char_length(display_name) <= 120),
  active boolean not null default true,
  added_at timestamptz not null default now()
);
revoke all on private.trusted_app_users from public, anon, authenticated;

insert into private.trusted_app_users (user_id)
select id from auth.users
on conflict (user_id) do nothing;

create or replace function private.require_trusted_user()
returns uuid
language plpgsql
security definer
set search_path = ''
stable
as $$
declare
  v_user uuid := auth.uid();
begin
  if v_user is null then
    raise exception 'authentication required';
  end if;
  if not exists (
    select 1 from private.trusted_app_users
    where user_id = v_user and active is true
  ) then
    raise exception 'trusted user registration required';
  end if;
  return v_user;
end;
$$;

revoke all on function private.require_trusted_user() from public, anon;
grant execute on function private.require_trusted_user() to authenticated;

create or replace function public.app_health()
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select auth.uid() is not null and exists (
    select 1 from private.trusted_app_users
    where user_id = auth.uid() and active is true
  );
$$;
revoke all on function public.app_health() from public, anon;
grant execute on function public.app_health() to authenticated;

-- Merge candidate rows that were previously isolated by owner. History rows
-- are retained and point to one canonical candidate before duplicates vanish.
lock table public.detection_candidates in share row exclusive mode;

create temporary table shared_candidate_merge_map on commit drop as
with ranked as (
  select
    id,
    first_value(id) over (
      partition by domain_hash
      order by
        (review_version > 0) desc,
        reviewed_at desc nulls last,
        last_seen_at desc,
        first_seen_at asc,
        id
    ) as canonical_id
  from public.detection_candidates
)
select id as source_id, canonical_id
from ranked;

with totals as (
  select
    map.canonical_id,
    sum(candidate.observation_count)::integer as observation_count,
    min(candidate.first_seen_at) as first_seen_at,
    max(candidate.last_seen_at) as last_seen_at
  from shared_candidate_merge_map map
  join public.detection_candidates candidate on candidate.id = map.source_id
  group by map.canonical_id
)
update public.detection_candidates candidate set
  observation_count = totals.observation_count,
  first_seen_at = totals.first_seen_at,
  last_seen_at = totals.last_seen_at
from totals
where candidate.id = totals.canonical_id;

update public.candidate_discoveries history
set candidate_id = map.canonical_id
from shared_candidate_merge_map map
where history.candidate_id = map.source_id
  and map.source_id <> map.canonical_id;

update public.candidate_observations history
set candidate_id = map.canonical_id
from shared_candidate_merge_map map
where history.candidate_id = map.source_id
  and map.source_id <> map.canonical_id;

update public.automated_assessments history
set candidate_id = map.canonical_id
from shared_candidate_merge_map map
where history.candidate_id = map.source_id
  and map.source_id <> map.canonical_id;

update public.candidate_reviews history
set candidate_id = map.canonical_id
from shared_candidate_merge_map map
where history.candidate_id = map.source_id
  and map.source_id <> map.canonical_id;

update public.learning_examples history
set candidate_id = map.canonical_id
from shared_candidate_merge_map map
where history.candidate_id = map.source_id
  and map.source_id <> map.canonical_id;

delete from public.detection_candidates candidate
using shared_candidate_merge_map map
where candidate.id = map.source_id
  and map.source_id <> map.canonical_id;

alter table public.detection_candidates
  drop constraint if exists detection_candidates_owner_id_domain_hash_key;
create unique index if not exists detection_candidates_shared_domain_hash_idx
  on public.detection_candidates (domain_hash);

-- Shared records must survive deletion of the account that originally wrote
-- them. The actor remains in append-only history until that account is removed.
alter table public.detection_candidates
  drop constraint if exists detection_candidates_owner_id_fkey,
  drop constraint if exists detection_candidates_creator_fkey,
  alter column owner_id drop not null;
alter table public.detection_candidates
  add constraint detection_candidates_creator_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.candidate_discoveries
  drop constraint if exists candidate_discoveries_owner_id_fkey,
  drop constraint if exists candidate_discoveries_actor_fkey,
  alter column owner_id drop not null;
alter table public.candidate_discoveries
  add constraint candidate_discoveries_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.candidate_observations
  drop constraint if exists candidate_observations_owner_id_fkey,
  drop constraint if exists candidate_observations_actor_fkey,
  alter column owner_id drop not null;
alter table public.candidate_observations
  add constraint candidate_observations_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.automated_assessments
  drop constraint if exists automated_assessments_owner_id_fkey,
  drop constraint if exists automated_assessments_actor_fkey,
  alter column owner_id drop not null;
alter table public.automated_assessments
  add constraint automated_assessments_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.candidate_reviews
  drop constraint if exists candidate_reviews_owner_id_fkey,
  drop constraint if exists candidate_reviews_actor_fkey,
  alter column owner_id drop not null;
alter table public.candidate_reviews
  add constraint candidate_reviews_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.learning_examples
  drop constraint if exists learning_examples_owner_id_fkey,
  drop constraint if exists learning_examples_actor_fkey,
  alter column owner_id drop not null;
alter table public.learning_examples
  add constraint learning_examples_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

alter table public.learning_models
  drop constraint if exists learning_models_owner_id_fkey,
  drop constraint if exists learning_models_actor_fkey,
  alter column owner_id drop not null;
alter table public.learning_models
  add constraint learning_models_actor_fkey
  foreign key (owner_id) references auth.users(id) on delete set null;

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
  v_actor uuid := private.require_trusted_user();
  v_id uuid;
  v_process boolean := false;
begin
  if p_domain is null or p_domain !~ '^[a-z0-9.-]{1,253}$' or not (p_domain like '%.%') then
    raise exception 'invalid domain';
  end if;
  if p_domain_hash !~ '^[0-9a-f]{64}$' or p_safe_url !~ '^https?://[^/?#]+/$' then
    raise exception 'invalid candidate';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('cycot-candidate-' || p_domain_hash)::bigint
  );
  select id,
    (decision_confirmed is true and last_seen_at < now() - make_interval(hours => least(greatest(p_dedup_hours, 1), 8760)))
    or (review_status in ('no_issue', 'inconclusive') and last_seen_at < now() - interval '6 hours')
    or (status = 'scanned' and scanned_at < now() - interval '1 hour')
    or (status in ('queued', 'scan_failed') and last_seen_at < now() - interval '15 minutes')
  into v_id, v_process
  from public.detection_candidates
  where domain_hash = p_domain_hash;

  if v_id is null then
    insert into public.detection_candidates (
      owner_id, domain, domain_hash, safe_url, source, candidate_kind,
      brand, score, reason
    ) values (
      v_actor, p_domain, p_domain_hash, p_safe_url,
      left(coalesce(nullif(p_source, ''), 'unknown'), 64),
      left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
      left(coalesce(p_brand, ''), 128),
      least(greatest(coalesce(p_score, 0), 0), 100),
      left(coalesce(p_reason, ''), 1000)
    ) returning id into v_id;
    v_process := true;
  else
    update public.detection_candidates set
      last_seen_at = now(),
      observation_count = observation_count + 1,
      source = left(coalesce(nullif(p_source, ''), 'unknown'), 64),
      candidate_kind = left(coalesce(nullif(p_candidate_kind, ''), 'unknown'), 64),
      brand = left(coalesce(p_brand, ''), 128),
      score = least(greatest(coalesce(p_score, 0), 0), 100),
      reason = left(coalesce(p_reason, ''), 1000),
      status = case when v_process then 'queued' else status end
    where id = v_id;
  end if;

  insert into public.candidate_discoveries (
    candidate_id, owner_id, source, candidate_kind, reason
  ) values (
    v_id, v_actor,
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
  v_actor uuid := private.require_trusted_user();
begin
  if octet_length(coalesce(p_evidence, '{}'::jsonb)::text) > 20000 then
    raise exception 'evidence too large';
  end if;
  if not exists (
    select 1 from public.detection_candidates where id = p_candidate_id
  ) then return false; end if;

  insert into public.candidate_observations (
    candidate_id, owner_id, success, evidence, error
  ) values (
    p_candidate_id, v_actor, p_success, coalesce(p_evidence, '{}'::jsonb),
    left(coalesce(p_error, ''), 500)
  );
  update public.detection_candidates set
    status = case when p_success then 'scanned' else 'scan_failed' end,
    evidence = coalesce(p_evidence, '{}'::jsonb) ||
      case when p_error = '' then '{}'::jsonb
           else jsonb_build_object('error', left(p_error, 500)) end,
    scanned_at = now()
  where id = p_candidate_id;
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
  v_actor uuid := private.require_trusted_user();
begin
  if not exists (
    select 1 from public.detection_candidates where id = p_candidate_id
  ) then return false; end if;

  insert into public.automated_assessments (
    candidate_id, owner_id, model_confirmed, category, summary
  ) values (
    p_candidate_id, v_actor, p_confirmed,
    left(coalesce(nullif(p_category, ''), 'unknown'), 128),
    left(coalesce(p_summary, ''), 2000)
  );
  update public.detection_candidates set
    status = case when status = 'scan_failed' then status else 'scanned' end,
    decision_confirmed = p_confirmed,
    decision_category = left(coalesce(p_category, ''), 128),
    decision_summary = left(coalesce(p_summary, ''), 2000)
  where id = p_candidate_id;
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
  v_actor uuid := private.require_trusted_user();
  v_version integer;
begin
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
  where id = p_candidate_id and review_version = p_expected_version
  returning review_version into v_version;
  if v_version is null then
    raise exception 'review conflict or candidate not found';
  end if;

  insert into public.candidate_reviews (
    candidate_id, owner_id, review_status, reason, evidence_refs
  ) values (
    p_candidate_id, v_actor, p_review_status,
    left(trim(p_reason), 2000), coalesce(p_evidence_refs, '[]'::jsonb)
  );
  return v_version;
end;
$$;

create or replace function private.record_learning_example(
  p_candidate_id uuid,
  p_review_version integer,
  p_category text,
  p_features jsonb
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := private.require_trusted_user();
  v_status text;
  v_current_version integer;
  v_candidate_kind text;
  v_expected_category text;
  v_label boolean;
begin
  if p_category not in ('phishing', 'fraudulent_ec', 'suspected_counterfeit') then
    raise exception 'invalid learning category';
  end if;
  if jsonb_typeof(p_features) <> 'object' or octet_length(p_features::text) > 10000 then
    raise exception 'invalid learning features';
  end if;
  select review_status, review_version, candidate_kind
    into v_status, v_current_version, v_candidate_kind
  from public.detection_candidates
  where id = p_candidate_id;
  if v_current_version is null or v_current_version <> p_review_version then
    raise exception 'review version conflict';
  end if;
  v_expected_category := case
    when v_candidate_kind in ('suspicious_shop', 'suspected_illegal_goods')
      then 'fraudulent_ec'
    when v_candidate_kind = 'counterfeit_goods' then 'suspected_counterfeit'
    else 'phishing'
  end;
  if p_category <> v_expected_category then
    raise exception 'learning category does not match candidate';
  end if;
  if v_status in ('strong_suspicion', 'report_prepared', 'response_verified') then
    v_label := true;
  elsif v_status = 'no_issue' then
    v_label := false;
  else
    return false;
  end if;
  insert into public.learning_examples (
    owner_id, candidate_id, review_version, category, label, features
  ) values (
    v_actor, p_candidate_id, p_review_version, p_category, v_label, p_features
  ) on conflict (owner_id, candidate_id, review_version) do nothing;
  return true;
end;
$$;

create or replace function private.get_learning_examples(p_limit integer default 5000)
returns jsonb
language plpgsql
security definer
set search_path = ''
stable
as $$
declare
  v_result jsonb;
begin
  perform private.require_trusted_user();
  select coalesce(jsonb_agg(jsonb_build_object(
    'category', source.category,
    'label', source.label,
    'features', source.features,
    'created_at', source.created_at
  ) order by source.created_at), '[]'::jsonb)
  into v_result
  from (
    select category, label, features, created_at
    from (
      select distinct on (candidate_id)
        candidate_id, category, label, features, created_at, review_version, id
      from public.learning_examples
      order by candidate_id, created_at desc, review_version desc, id desc
    ) latest
    order by created_at desc
    limit least(greatest(p_limit, 100), 100000)
  ) source;
  return v_result;
end;
$$;

-- Reduce any per-user champions to the newest shared champion before adding
-- the global one-active-model invariant.
with ranked as (
  select id, row_number() over (order by created_at desc, id desc) as position
  from public.learning_models
  where status = 'active'
)
update public.learning_models model set status = 'archived'
from ranked
where model.id = ranked.id and ranked.position > 1;

drop index if exists public.learning_models_one_active_per_owner_idx;
create unique index if not exists learning_models_one_active_shared_idx
  on public.learning_models ((status)) where status = 'active';

create or replace function private.get_active_learning_model()
returns jsonb
language plpgsql
security definer
set search_path = ''
stable
as $$
declare
  v_result jsonb;
begin
  perform private.require_trusted_user();
  select model_payload into v_result
  from public.learning_models
  where status = 'active'
  order by created_at desc, id desc
  limit 1;
  return v_result;
end;
$$;

drop function if exists public.publish_learning_model(jsonb, jsonb);
drop function if exists private.publish_learning_model(jsonb, jsonb);

create function private.publish_learning_model(
  p_model jsonb,
  p_metrics jsonb default '{}'::jsonb,
  p_expected_parent_version text default ''
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := private.require_trusted_user();
  v_version text := p_model->>'model_version';
  v_parent bigint;
  v_parent_version text;
begin
  if p_model->>'schema_version' <> 'review-logistic-v1'
     or jsonb_typeof(p_model->'weights') <> 'array'
     or jsonb_typeof(p_model->'supported_categories') <> 'array'
     or jsonb_typeof(coalesce(p_metrics, '{}'::jsonb)) <> 'object' then
    raise exception 'invalid learning model';
  end if;
  if jsonb_array_length(p_model->'weights') <> 19
     or jsonb_array_length(p_model->'supported_categories') < 1
     or not (p_model->'supported_categories'
       <@ '["phishing", "fraudulent_ec", "suspected_counterfeit"]'::jsonb)
     or char_length(coalesce(v_version, '')) not between 1 and 128
     or octet_length(p_model::text) > 50000
     or octet_length(coalesce(p_metrics, '{}'::jsonb)::text) > 20000 then
    raise exception 'invalid learning model';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('cycot-shared-learning-model')::bigint
  );
  select id, model_version into v_parent, v_parent_version
  from public.learning_models
  where status = 'active'
  order by created_at desc, id desc
  limit 1;
  if coalesce(v_parent_version, '') <> coalesce(p_expected_parent_version, '') then
    raise exception 'learning model changed; retrain against current model';
  end if;

  update public.learning_models set status = 'archived'
  where status = 'active';
  insert into public.learning_models (
    owner_id, model_version, status, model_payload, metrics, parent_model_id
  ) values (
    v_actor, v_version, 'active', p_model,
    coalesce(p_metrics, '{}'::jsonb), v_parent
  );
  return v_version;
end;
$$;

drop function if exists public.rollback_learning_model(text);
drop function if exists private.rollback_learning_model(text);

create function private.rollback_learning_model(p_model_version text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_target bigint;
begin
  perform private.require_trusted_user();
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('cycot-shared-learning-model')::bigint
  );
  select id into v_target
  from public.learning_models
  where model_version = p_model_version
  order by created_at desc, id desc
  limit 1;
  if v_target is null then return false; end if;
  update public.learning_models set status = 'archived'
  where status = 'active';
  update public.learning_models set status = 'active'
  where id = v_target;
  return found;
end;
$$;

create function public.publish_learning_model(
  p_model jsonb,
  p_metrics jsonb default '{}'::jsonb,
  p_expected_parent_version text default ''
)
returns text
language sql
security invoker
set search_path = ''
as $$
  select private.publish_learning_model(
    p_model, p_metrics, p_expected_parent_version
  );
$$;

create function public.rollback_learning_model(p_model_version text)
returns boolean
language sql
security invoker
set search_path = ''
as $$
  select private.rollback_learning_model(p_model_version);
$$;

revoke all on function public.publish_learning_model(jsonb, jsonb, text) from public, anon;
revoke all on function private.publish_learning_model(jsonb, jsonb, text) from public, anon;
revoke all on function public.rollback_learning_model(text) from public, anon;
revoke all on function private.rollback_learning_model(text) from public, anon;
grant execute on function public.publish_learning_model(jsonb, jsonb, text) to authenticated;
grant execute on function private.publish_learning_model(jsonb, jsonb, text) to authenticated;
grant execute on function public.rollback_learning_model(text) to authenticated;
grant execute on function private.rollback_learning_model(text) to authenticated;

comment on table private.trusted_app_users is
  'Administrator-maintained allowlist for this dedicated application.';
comment on table public.detection_candidates is
  'Shared candidate state. URL paths and query values are intentionally not stored.';
comment on table public.learning_examples is
  'Shared, human-review-derived labels only; no model self-labels.';
comment on table public.learning_models is
  'One shared champion model with versioned rollback history.';

commit;
