begin;

-- Apply after 202609030001_spec_v11_history.sql.
create table if not exists public.learning_examples (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  candidate_id uuid not null references public.detection_candidates(id) on delete cascade,
  review_version integer not null check (review_version > 0),
  category text not null check (category in ('phishing', 'fraudulent_ec', 'suspected_counterfeit')),
  label boolean not null,
  features jsonb not null check (jsonb_typeof(features) = 'object'),
  created_at timestamptz not null default now(),
  unique (owner_id, candidate_id, review_version)
);

create table if not exists public.learning_models (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  model_version text not null check (char_length(model_version) between 1 and 128),
  status text not null check (status in ('active', 'archived')),
  model_payload jsonb not null check (jsonb_typeof(model_payload) = 'object'),
  metrics jsonb not null default '{}'::jsonb,
  parent_model_id bigint references public.learning_models(id),
  created_at timestamptz not null default now(),
  unique (owner_id, model_version)
);

create unique index if not exists learning_models_one_active_per_owner_idx
  on public.learning_models (owner_id) where status = 'active';
create index if not exists learning_examples_owner_created_idx
  on public.learning_examples (owner_id, created_at);

alter table public.learning_examples enable row level security;
alter table public.learning_examples force row level security;
alter table public.learning_models enable row level security;
alter table public.learning_models force row level security;
revoke all on public.learning_examples from anon, authenticated;
revoke all on public.learning_models from anon, authenticated;
revoke all on sequence public.learning_examples_id_seq from anon, authenticated;
revoke all on sequence public.learning_models_id_seq from anon, authenticated;

create or replace function private.record_learning_example(
  p_candidate_id uuid,
  p_review_version integer,
  p_category text,
  p_features jsonb
)
returns boolean
language plpgsql security definer set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_status text;
  v_current_version integer;
  v_candidate_kind text;
  v_expected_category text;
  v_label boolean;
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if p_category not in ('phishing', 'fraudulent_ec', 'suspected_counterfeit') then
    raise exception 'invalid learning category';
  end if;
  if jsonb_typeof(p_features) <> 'object' or octet_length(p_features::text) > 10000 then
    raise exception 'invalid learning features';
  end if;
  select review_status, review_version, candidate_kind
    into v_status, v_current_version, v_candidate_kind
  from public.detection_candidates
  where id = p_candidate_id and owner_id = v_owner;
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
    v_owner, p_candidate_id, p_review_version, p_category, v_label, p_features
  ) on conflict (owner_id, candidate_id, review_version) do nothing;
  return true;
end;
$$;

create or replace function private.get_learning_examples(p_limit integer default 5000)
returns jsonb
language sql security definer set search_path = '' stable
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'category', source.category,
    'label', source.label,
    'features', source.features,
    'created_at', source.created_at
  ) order by source.created_at), '[]'::jsonb)
  from (
    select category, label, features, created_at
    from (
      select distinct on (candidate_id)
        candidate_id, category, label, features, created_at
      from public.learning_examples
      where owner_id = auth.uid()
      order by candidate_id, review_version desc
    ) latest
    order by created_at desc
    limit least(greatest(p_limit, 100), 100000)
  ) source;
$$;

create or replace function private.get_active_learning_model()
returns jsonb
language sql security definer set search_path = '' stable
as $$
  select model_payload
  from public.learning_models
  where owner_id = auth.uid() and status = 'active'
  order by created_at desc limit 1;
$$;

create or replace function private.publish_learning_model(
  p_model jsonb,
  p_metrics jsonb default '{}'::jsonb
)
returns text
language plpgsql security definer set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
  v_version text := p_model->>'model_version';
  v_parent bigint;
begin
  if v_owner is null then raise exception 'authentication required'; end if;
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
  select id into v_parent from public.learning_models
  where owner_id = v_owner and status = 'active' order by created_at desc limit 1;
  update public.learning_models set status = 'archived'
  where owner_id = v_owner and status = 'active';
  insert into public.learning_models (
    owner_id, model_version, status, model_payload, metrics, parent_model_id
  ) values (v_owner, v_version, 'active', p_model, coalesce(p_metrics, '{}'::jsonb), v_parent);
  return v_version;
end;
$$;

create or replace function private.rollback_learning_model(p_model_version text)
returns boolean
language plpgsql security definer set search_path = ''
as $$
declare
  v_owner uuid := auth.uid();
begin
  if v_owner is null then raise exception 'authentication required'; end if;
  if not exists (
    select 1 from public.learning_models
    where owner_id = v_owner and model_version = p_model_version
  ) then return false; end if;
  update public.learning_models set status = 'archived'
  where owner_id = v_owner and status = 'active';
  update public.learning_models set status = 'active'
  where owner_id = v_owner and model_version = p_model_version;
  return found;
end;
$$;

create or replace function public.record_learning_example(
  p_candidate_id uuid, p_review_version integer, p_category text, p_features jsonb
)
returns boolean language sql security invoker set search_path = '' as $$
  select private.record_learning_example(p_candidate_id, p_review_version, p_category, p_features);
$$;
create or replace function public.get_learning_examples(p_limit integer default 5000)
returns jsonb language sql security invoker set search_path = '' as $$
  select private.get_learning_examples(p_limit);
$$;
create or replace function public.get_active_learning_model()
returns jsonb language sql security invoker set search_path = '' as $$
  select private.get_active_learning_model();
$$;
create or replace function public.publish_learning_model(p_model jsonb, p_metrics jsonb default '{}'::jsonb)
returns text language sql security invoker set search_path = '' as $$
  select private.publish_learning_model(p_model, p_metrics);
$$;
create or replace function public.rollback_learning_model(p_model_version text)
returns boolean language sql security invoker set search_path = '' as $$
  select private.rollback_learning_model(p_model_version);
$$;

revoke all on function public.record_learning_example(uuid, integer, text, jsonb) from public, anon;
revoke all on function public.get_learning_examples(integer) from public, anon;
revoke all on function public.get_active_learning_model() from public, anon;
revoke all on function public.publish_learning_model(jsonb, jsonb) from public, anon;
revoke all on function public.rollback_learning_model(text) from public, anon;
revoke all on function private.record_learning_example(uuid, integer, text, jsonb) from public, anon;
revoke all on function private.get_learning_examples(integer) from public, anon;
revoke all on function private.get_active_learning_model() from public, anon;
revoke all on function private.publish_learning_model(jsonb, jsonb) from public, anon;
revoke all on function private.rollback_learning_model(text) from public, anon;
grant execute on function public.record_learning_example(uuid, integer, text, jsonb) to authenticated;
grant execute on function public.get_learning_examples(integer) to authenticated;
grant execute on function public.get_active_learning_model() to authenticated;
grant execute on function public.publish_learning_model(jsonb, jsonb) to authenticated;
grant execute on function public.rollback_learning_model(text) to authenticated;
grant execute on function private.record_learning_example(uuid, integer, text, jsonb) to authenticated;
grant execute on function private.get_learning_examples(integer) to authenticated;
grant execute on function private.get_active_learning_model() to authenticated;
grant execute on function private.publish_learning_model(jsonb, jsonb) to authenticated;
grant execute on function private.rollback_learning_model(text) to authenticated;

comment on table public.learning_examples is 'Human-review-derived labels only; no model self-labels.';
comment on table public.learning_models is 'Versioned champion models and rollback history.';

commit;
