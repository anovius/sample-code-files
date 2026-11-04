-- =============================================================================
-- Migration: lead routing schema
--
-- Scenario (anonymised from a live orthopaedics sales CRM):
--   Inbound leads arrive from Shopify orders, web forms, referrals and phone.
--   Each lead is matched to a sales territory by the first three digits of its
--   postal code, then assigned to the active rep in that territory with the
--   fewest open leads, never exceeding the rep's capacity.
--
-- This file creates tables, constraints, indexes, the routing function and the
-- audit triggers. Row level security lives in the next migration.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Types
-- -----------------------------------------------------------------------------
create type public.app_role as enum ('admin', 'manager', 'rep');

create type public.lead_status as enum (
  'new',        -- received, not yet routed or no rep had capacity
  'assigned',   -- routed to a rep, not yet contacted
  'contacted',
  'qualified',
  'won',
  'lost'
);

create type public.lead_source as enum ('shopify', 'web_form', 'referral', 'phone');

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------
create table public.territories (
  id         uuid primary key default gen_random_uuid(),
  name       text not null unique check (length(trim(name)) > 0),
  created_at timestamptz not null default now()
);

comment on table public.territories is 'Sales territories. Postal code prefixes map leads to a territory.';

create table public.territory_zip_prefixes (
  prefix       text primary key check (prefix ~ '^[0-9]{3}$'),
  territory_id uuid not null references public.territories (id) on delete cascade
);

comment on table public.territory_zip_prefixes is 'Three-digit postal code prefix to territory. One prefix belongs to exactly one territory.';

create table public.profiles (
  id             uuid primary key references auth.users (id) on delete cascade,
  full_name      text not null check (length(trim(full_name)) > 0),
  role           public.app_role not null default 'rep',
  territory_id   uuid references public.territories (id) on delete set null,
  is_active      boolean not null default true,
  max_open_leads integer not null default 25 check (max_open_leads between 1 and 500),
  created_at     timestamptz not null default now(),
  -- reps and managers always belong to a territory; admins are global
  constraint profiles_territory_required
    check (role = 'admin' or territory_id is not null)
);

comment on table public.profiles is 'One row per staff user. Role and territory drive every RLS decision.';

create table public.leads (
  id           uuid primary key default gen_random_uuid(),
  source       public.lead_source not null,
  external_ref text check (external_ref is null or length(external_ref) between 1 and 128),
  full_name    text not null check (length(trim(full_name)) > 0),
  email        text check (email is null or email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  phone        text check (phone is null or phone ~ '^\+?[0-9 ()-]{7,20}$'),
  postal_code  text not null check (postal_code ~ '^[0-9]{5}$'),
  territory_id uuid references public.territories (id) on delete set null,
  assigned_to  uuid references public.profiles (id) on delete set null,
  assigned_at  timestamptz,
  status       public.lead_status not null default 'new',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),

  -- the same Shopify order (or other external record) can only create one lead,
  -- which makes webhook retries safe
  constraint leads_source_external_ref_key unique (source, external_ref),

  -- assigned_to and assigned_at are always set together
  constraint leads_assignment_pair
    check ((assigned_to is null) = (assigned_at is null)),

  -- a lead past 'new' must have an owner
  constraint leads_status_requires_owner
    check (status = 'new' or assigned_to is not null)
);

comment on table public.leads is 'Inbound sales leads. Inserted only by the intake Edge Function (service role).';

create table public.lead_events (
  id         bigint generated always as identity primary key,
  lead_id    uuid not null references public.leads (id) on delete cascade,
  event      text not null check (event in ('created', 'routed', 'unroutable', 'no_capacity', 'reassigned', 'status_changed')),
  actor      uuid references public.profiles (id) on delete set null,
  detail     jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

comment on table public.lead_events is 'Append-only audit trail. Written only by triggers and the routing function.';

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------
create index territory_zip_prefixes_territory_idx on public.territory_zip_prefixes (territory_id);
create index profiles_territory_role_idx on public.profiles (territory_id, role) where is_active;
create index leads_territory_idx on public.leads (territory_id);
create index leads_open_by_owner_idx on public.leads (assigned_to, assigned_at)
  where status in ('assigned', 'contacted', 'qualified');
create index lead_events_lead_idx on public.lead_events (lead_id, created_at);

-- -----------------------------------------------------------------------------
-- Triggers: updated_at, assignment bookkeeping, audit trail
-- -----------------------------------------------------------------------------
create function public.leads_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();

  -- keep assigned_at in step with assigned_to, whoever changes it
  if new.assigned_to is distinct from old.assigned_to then
    new.assigned_at := case when new.assigned_to is null then null else now() end;
  end if;

  -- a lead that loses its owner falls back to 'new' so it can be routed again
  if new.assigned_to is null then
    new.status := 'new';
  end if;

  return new;
end;
$$;

create trigger leads_before_update
  before update on public.leads
  for each row execute function public.leads_before_update();

create function public.leads_audit()
returns trigger
language plpgsql
security definer          -- users have no insert grant on lead_events
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    insert into public.lead_events (lead_id, event, actor, detail)
    values (new.id, 'created', auth.uid(), jsonb_build_object('source', new.source));
    return new;
  end if;

  -- routing writes its own, richer event; only audit changes made by people
  if current_setting('app.routing', true) = 'on' then
    return new;
  end if;

  if new.assigned_to is distinct from old.assigned_to then
    insert into public.lead_events (lead_id, event, actor, detail)
    values (new.id, 'reassigned', auth.uid(),
            jsonb_build_object('from', old.assigned_to, 'to', new.assigned_to));
  end if;

  if new.status is distinct from old.status then
    insert into public.lead_events (lead_id, event, actor, detail)
    values (new.id, 'status_changed', auth.uid(),
            jsonb_build_object('from', old.status, 'to', new.status));
  end if;

  return new;
end;
$$;

create trigger leads_audit_insert
  after insert on public.leads
  for each row execute function public.leads_audit();

create trigger leads_audit_update
  after update on public.leads
  for each row execute function public.leads_audit();

-- -----------------------------------------------------------------------------
-- Routing
--
-- route_lead(lead_id) assigns one lead and returns the rep id, or null when the
-- lead cannot be routed. It is idempotent: an already assigned lead returns its
-- current owner unchanged. Rules:
--   1. territory = owner of the first three digits of the postal code
--   2. candidate reps = active reps in that territory below max_open_leads
--   3. pick the fewest open leads, then the rep who waited longest, then id
-- A transaction-scoped advisory lock per territory serialises concurrent
-- routing, so two leads arriving together can never both take a rep's last
-- free slot.
-- -----------------------------------------------------------------------------
create function public.route_lead(p_lead_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_lead      public.leads%rowtype;
  v_territory uuid;
  v_rep       uuid;
begin
  select * into v_lead
  from public.leads
  where id = p_lead_id
  for update;

  if not found then
    raise exception 'lead % not found', p_lead_id using errcode = 'P0002';
  end if;

  if v_lead.assigned_to is not null then
    return v_lead.assigned_to;
  end if;

  select z.territory_id into v_territory
  from public.territory_zip_prefixes z
  where z.prefix = left(v_lead.postal_code, 3);

  perform set_config('app.routing', 'on', true);

  if v_territory is null then
    update public.leads set territory_id = null where id = p_lead_id;
    insert into public.lead_events (lead_id, event, detail)
    values (p_lead_id, 'unroutable', jsonb_build_object('postal_code', v_lead.postal_code));
    perform set_config('app.routing', 'off', true);
    return null;
  end if;

  perform pg_advisory_xact_lock(hashtextextended('route_lead:' || v_territory::text, 0));

  select p.id into v_rep
  from public.profiles p
  cross join lateral (
    select count(*)           as open_count,
           max(l.assigned_at) as last_assigned_at
    from public.leads l
    where l.assigned_to = p.id
      and l.status in ('assigned', 'contacted', 'qualified')
  ) load
  where p.territory_id = v_territory
    and p.role = 'rep'
    and p.is_active
    and load.open_count < p.max_open_leads
  order by load.open_count, load.last_assigned_at nulls first, p.id
  limit 1;

  if v_rep is null then
    update public.leads set territory_id = v_territory where id = p_lead_id;
    insert into public.lead_events (lead_id, event, detail)
    values (p_lead_id, 'no_capacity', jsonb_build_object('territory_id', v_territory));
    perform set_config('app.routing', 'off', true);
    return null;
  end if;

  update public.leads
  set territory_id = v_territory,
      assigned_to  = v_rep,
      status       = 'assigned'
  where id = p_lead_id;

  insert into public.lead_events (lead_id, event, detail)
  values (p_lead_id, 'routed', jsonb_build_object('territory_id', v_territory, 'rep_id', v_rep));

  perform set_config('app.routing', 'off', true);
  return v_rep;
end;
$$;

comment on function public.route_lead(uuid) is 'Assigns a lead to the least-loaded active rep in its territory. Service role only.';

-- routing is a back-office operation; only the Edge Function may call it
revoke all on function public.route_lead(uuid) from public, anon, authenticated;
grant execute on function public.route_lead(uuid) to service_role;

-- trigger functions are never called directly
revoke all on function public.leads_before_update() from public, anon, authenticated;
revoke all on function public.leads_audit() from public, anon, authenticated;
