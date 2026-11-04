-- =============================================================================
-- Migration: row level security for lead routing
--
-- Access model
--   admin    reads and updates everything
--   manager  reads profiles and leads in their own territory, reassigns leads
--            to active reps in that territory, updates status
--   rep      reads their own profile and the leads assigned to them, updates
--            the status of those leads only
--   anon     no access
--   inactive any profile with is_active = false gets no access at all
--
-- Inserts into leads and every write to lead_events go through the service
-- role (Edge Function) or security definer functions, never through the API.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Helper functions
-- security definer so they can read profiles without recursing into the
-- profiles policies; stable so Postgres evaluates them once per statement.
-- -----------------------------------------------------------------------------
create function public.current_app_role()
returns public.app_role
language sql
stable
security definer
set search_path = ''
as $$
  select p.role
  from public.profiles p
  where p.id = (select auth.uid())
    and p.is_active;
$$;

create function public.current_territory_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.territory_id
  from public.profiles p
  where p.id = (select auth.uid())
    and p.is_active;
$$;

revoke all on function public.current_app_role() from public, anon;
revoke all on function public.current_territory_id() from public, anon;
grant execute on function public.current_app_role() to authenticated;
grant execute on function public.current_territory_id() to authenticated;

-- -----------------------------------------------------------------------------
-- Table privileges (defence in depth: RLS decides rows, grants decide columns)
-- -----------------------------------------------------------------------------
revoke all on public.territories, public.territory_zip_prefixes, public.profiles,
              public.leads, public.lead_events
  from anon, authenticated;

grant select on public.territories, public.territory_zip_prefixes, public.profiles,
                public.leads, public.lead_events
  to authenticated;

-- people may only ever change who owns a lead and where it is in the funnel
grant update (status, assigned_to) on public.leads to authenticated;

-- -----------------------------------------------------------------------------
-- Enable RLS
-- -----------------------------------------------------------------------------
alter table public.territories            enable row level security;
alter table public.territory_zip_prefixes enable row level security;
alter table public.profiles               enable row level security;
alter table public.leads                  enable row level security;
alter table public.lead_events            enable row level security;

-- -----------------------------------------------------------------------------
-- Reference data: any active staff member can read it
-- -----------------------------------------------------------------------------
create policy territories_select_staff
  on public.territories for select to authenticated
  using ((select public.current_app_role()) is not null);

create policy territory_zip_prefixes_select_staff
  on public.territory_zip_prefixes for select to authenticated
  using ((select public.current_app_role()) is not null);

-- -----------------------------------------------------------------------------
-- Profiles
-- -----------------------------------------------------------------------------
create policy profiles_select_self
  on public.profiles for select to authenticated
  using (id = (select auth.uid()) and is_active);

create policy profiles_select_manager_territory
  on public.profiles for select to authenticated
  using (
    (select public.current_app_role()) = 'manager'
    and territory_id = (select public.current_territory_id())
  );

create policy profiles_select_admin
  on public.profiles for select to authenticated
  using ((select public.current_app_role()) = 'admin');

-- -----------------------------------------------------------------------------
-- Leads: read
-- -----------------------------------------------------------------------------
create policy leads_select_rep_own
  on public.leads for select to authenticated
  using (
    (select public.current_app_role()) = 'rep'
    and assigned_to = (select auth.uid())
  );

create policy leads_select_manager_territory
  on public.leads for select to authenticated
  using (
    (select public.current_app_role()) = 'manager'
    and territory_id = (select public.current_territory_id())
  );

create policy leads_select_admin
  on public.leads for select to authenticated
  using ((select public.current_app_role()) = 'admin');

-- -----------------------------------------------------------------------------
-- Leads: update
-- Every WITH CHECK repeats the role test: permissive policies are OR-ed, so a
-- check without it would let one role pass through another role's policy.
-- -----------------------------------------------------------------------------

-- reps work their own leads and cannot hand them away or reset them to 'new'
create policy leads_update_rep_own
  on public.leads for update to authenticated
  using (
    (select public.current_app_role()) = 'rep'
    and assigned_to = (select auth.uid())
  )
  with check (
    (select public.current_app_role()) = 'rep'
    and assigned_to = (select auth.uid())
    and status <> 'new'
  );

-- managers reassign within their territory, only to active reps there
create policy leads_update_manager_territory
  on public.leads for update to authenticated
  using (
    (select public.current_app_role()) = 'manager'
    and territory_id = (select public.current_territory_id())
  )
  with check (
    (select public.current_app_role()) = 'manager'
    and territory_id = (select public.current_territory_id())
    and (
      assigned_to is null
      or exists (
        select 1
        from public.profiles p
        where p.id = assigned_to
          and p.role = 'rep'
          and p.is_active
          and p.territory_id = (select public.current_territory_id())
      )
    )
  );

create policy leads_update_admin
  on public.leads for update to authenticated
  using ((select public.current_app_role()) = 'admin')
  with check ((select public.current_app_role()) = 'admin');

-- -----------------------------------------------------------------------------
-- Lead events: visible exactly when the lead itself is visible
-- (the subquery runs under the caller's lead policies)
-- -----------------------------------------------------------------------------
create policy lead_events_select_visible_lead
  on public.lead_events for select to authenticated
  using (exists (select 1 from public.leads l where l.id = lead_id));
