-- =============================================================================
-- pgTAP tests: lead routing and row level security
-- Run with: supabase test db
--
-- Fixture
--   Territory North  prefix 100   manager M, reps R1 (cap 2), R2 (cap 25),
--                                  inactive rep R4
--   Territory South  prefix 200   rep R3
--   Admin A (global)
--   Leads L1..L5 in North, L6 in South, L7 with an unmapped postal code
-- Everything runs inside one transaction and is rolled back at the end.
-- =============================================================================

begin;

create extension if not exists pgtap with schema extensions;

select plan(42);

-- -----------------------------------------------------------------------------
-- Fixture (as the migration owner, which bypasses RLS)
-- -----------------------------------------------------------------------------
insert into public.territories (id, name) values
  ('00000000-0000-0000-0000-0000000000a1', 'North'),
  ('00000000-0000-0000-0000-0000000000a2', 'South');

insert into public.territory_zip_prefixes (prefix, territory_id) values
  ('100', '00000000-0000-0000-0000-0000000000a1'),
  ('200', '00000000-0000-0000-0000-0000000000a2');

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-000000000001', 'admin@example.test'),
  ('00000000-0000-0000-0000-000000000002', 'manager.north@example.test'),
  ('00000000-0000-0000-0000-000000000011', 'rep1.north@example.test'),
  ('00000000-0000-0000-0000-000000000012', 'rep2.north@example.test'),
  ('00000000-0000-0000-0000-000000000013', 'rep3.south@example.test'),
  ('00000000-0000-0000-0000-000000000014', 'rep4.inactive@example.test');

insert into public.profiles (id, full_name, role, territory_id, is_active, max_open_leads) values
  ('00000000-0000-0000-0000-000000000001', 'Admin A',   'admin',   null,                                   true,  25),
  ('00000000-0000-0000-0000-000000000002', 'Manager M', 'manager', '00000000-0000-0000-0000-0000000000a1', true,  25),
  ('00000000-0000-0000-0000-000000000011', 'Rep R1',    'rep',     '00000000-0000-0000-0000-0000000000a1', true,  2),
  ('00000000-0000-0000-0000-000000000012', 'Rep R2',    'rep',     '00000000-0000-0000-0000-0000000000a1', true,  25),
  ('00000000-0000-0000-0000-000000000013', 'Rep R3',    'rep',     '00000000-0000-0000-0000-0000000000a2', true,  25),
  ('00000000-0000-0000-0000-000000000014', 'Rep R4',    'rep',     '00000000-0000-0000-0000-0000000000a1', false, 25);

insert into public.leads (id, source, external_ref, full_name, email, postal_code) values
  ('00000000-0000-0000-0000-0000000000c1', 'shopify',  '9001', 'Lead One',   'one@example.test',   '10001'),
  ('00000000-0000-0000-0000-0000000000c2', 'shopify',  '9002', 'Lead Two',   'two@example.test',   '10002'),
  ('00000000-0000-0000-0000-0000000000c3', 'web_form', null,   'Lead Three', 'three@example.test', '10003'),
  ('00000000-0000-0000-0000-0000000000c4', 'referral', null,   'Lead Four',  null,                 '10004'),
  ('00000000-0000-0000-0000-0000000000c5', 'phone',    null,   'Lead Five',  null,                 '10005'),
  ('00000000-0000-0000-0000-0000000000c6', 'shopify',  '9006', 'Lead Six',   'six@example.test',   '20001'),
  ('00000000-0000-0000-0000-0000000000c7', 'shopify',  '9007', 'Lead Seven', 'seven@example.test', '99999');

-- =============================================================================
-- 1. Schema guarantees
-- =============================================================================
select has_table('public', 'leads', 'leads table exists');

select ok(
  (select relrowsecurity from pg_class where oid = 'public.leads'::regclass),
  'RLS is enabled on leads'
);

select throws_ok(
  $$ insert into public.leads (source, external_ref, full_name, postal_code)
     values ('shopify', '9001', 'Duplicate', '10001') $$,
  '23505', null,
  'the same Shopify order cannot create a second lead'
);

select throws_ok(
  $$ insert into public.leads (source, full_name, postal_code) values ('phone', 'Bad Zip', '1000') $$,
  '23514', null,
  'postal codes must be five digits'
);

select is(
  (select count(*)::int from public.lead_events where event = 'created'),
  7,
  'every inserted lead writes a created event'
);

-- =============================================================================
-- 2. Routing (as the service role, like the Edge Function)
-- =============================================================================
set local role service_role;

select is(public.route_lead('00000000-0000-0000-0000-0000000000c1'),
          '00000000-0000-0000-0000-000000000011'::uuid,
          'L1: tie on load, lowest id wins, goes to R1');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c2'),
          '00000000-0000-0000-0000-000000000012'::uuid,
          'L2: R2 now has the fewest open leads');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c3'),
          '00000000-0000-0000-0000-000000000011'::uuid,
          'L3: tie again, back to R1, who is now at capacity (2)');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c4'),
          '00000000-0000-0000-0000-000000000012'::uuid,
          'L4: R1 is full, so R2 gets it');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c6'),
          '00000000-0000-0000-0000-000000000013'::uuid,
          'L6: South postal code routes to the South rep');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c7'),
          null::uuid,
          'L7: unmapped postal code is not routed');

select is(public.route_lead('00000000-0000-0000-0000-0000000000c1'),
          '00000000-0000-0000-0000-000000000011'::uuid,
          'routing an assigned lead again is idempotent');

select throws_ok(
  $$ select public.route_lead('00000000-0000-0000-0000-0000000000ff') $$,
  'P0002', null,
  'routing an unknown lead raises no_data_found'
);

reset role;

-- capacity exhausted: R1 full, R2 deactivated, R4 inactive
update public.profiles set is_active = false where id = '00000000-0000-0000-0000-000000000012';

set local role service_role;
select is(public.route_lead('00000000-0000-0000-0000-0000000000c5'),
          null::uuid,
          'L5: no active rep with capacity, lead stays unassigned');
reset role;

update public.profiles set is_active = true where id = '00000000-0000-0000-0000-000000000012';

select results_eq(
  $$ select status::text, territory_id from public.leads
     where id = '00000000-0000-0000-0000-0000000000c5' $$,
  $$ values ('new', '00000000-0000-0000-0000-0000000000a1'::uuid) $$,
  'L5 keeps status new but records its territory for the manager queue'
);

select results_eq(
  $$ select status::text, territory_id from public.leads
     where id = '00000000-0000-0000-0000-0000000000c7' $$,
  $$ values ('new', null::uuid) $$,
  'L7 keeps status new with no territory'
);

select is(
  (select count(*)::int from public.lead_events
   where lead_id = '00000000-0000-0000-0000-0000000000c1' and event = 'routed'),
  1,
  'idempotent re-routing does not write a second routed event'
);

select set_eq(
  $$ select event from public.lead_events
     where lead_id in ('00000000-0000-0000-0000-0000000000c5', '00000000-0000-0000-0000-0000000000c7')
       and event <> 'created' $$,
  array['no_capacity', 'unroutable'],
  'failed routing is audited with the reason'
);

select is(
  (select count(*)::int from public.lead_events where event in ('reassigned', 'status_changed')),
  0,
  'routing does not also log generic reassignment events'
);

select ok(
  (select bool_and(assigned_at is not null and status = 'assigned')
   from public.leads where assigned_to is not null),
  'every routed lead has assigned_at and status assigned'
);

-- =============================================================================
-- 3. Privileges: only the service role may route
-- =============================================================================
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated"}', true);

select throws_ok(
  $$ select public.route_lead('00000000-0000-0000-0000-0000000000c5') $$,
  '42501', null,
  'even an admin user cannot call route_lead through the API'
);

reset role;

-- =============================================================================
-- 4. RLS: rep R1
-- =============================================================================
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000011","role":"authenticated"}', true);

select set_eq(
  $$ select id from public.leads $$,
  array['00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000c3']::uuid[],
  'rep sees only the leads assigned to them'
);

select set_eq(
  $$ select distinct lead_id from public.lead_events $$,
  array['00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000c3']::uuid[],
  'rep sees audit events only for their own leads'
);

select set_eq(
  $$ select id from public.profiles $$,
  array['00000000-0000-0000-0000-000000000011']::uuid[],
  'rep sees only their own profile'
);

select lives_ok(
  $$ update public.leads set status = 'contacted'
     where id = '00000000-0000-0000-0000-0000000000c1' $$,
  'rep can move their own lead forward'
);

-- silently filtered by RLS: affects zero rows, checked below as the owner
update public.leads set status = 'lost' where id = '00000000-0000-0000-0000-0000000000c2';

select throws_ok(
  $$ update public.leads set assigned_to = '00000000-0000-0000-0000-000000000012'
     where id = '00000000-0000-0000-0000-0000000000c1' $$,
  '42501', null,
  'rep cannot hand their lead to someone else'
);

select throws_ok(
  $$ update public.leads set status = 'new'
     where id = '00000000-0000-0000-0000-0000000000c3' $$,
  '42501', null,
  'rep cannot reset a lead to new'
);

select throws_ok(
  $$ update public.leads set full_name = 'Changed'
     where id = '00000000-0000-0000-0000-0000000000c1' $$,
  '42501', null,
  'rep cannot edit columns outside status and owner'
);

select throws_ok(
  $$ insert into public.leads (source, full_name, postal_code) values ('phone', 'Sneaky', '10009') $$,
  '42501', null,
  'users cannot insert leads directly'
);

select throws_ok(
  $$ insert into public.lead_events (lead_id, event) values ('00000000-0000-0000-0000-0000000000c1', 'routed') $$,
  '42501', null,
  'users cannot write to the audit trail'
);

reset role;

select is(
  (select status::text from public.leads where id = '00000000-0000-0000-0000-0000000000c2'),
  'assigned',
  'rep update on a lead they do not own changed nothing'
);

select ok(
  exists (select 1 from public.lead_events
          where lead_id = '00000000-0000-0000-0000-0000000000c1'
            and event = 'status_changed'
            and actor = '00000000-0000-0000-0000-000000000011'
            and detail = '{"from": "assigned", "to": "contacted"}'::jsonb),
  'status change by the rep is audited with actor and before/after'
);

-- =============================================================================
-- 5. RLS: manager M (North)
-- =============================================================================
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000002","role":"authenticated"}', true);

select set_eq(
  $$ select id from public.leads $$,
  array['00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000c2',
        '00000000-0000-0000-0000-0000000000c3', '00000000-0000-0000-0000-0000000000c4',
        '00000000-0000-0000-0000-0000000000c5']::uuid[],
  'manager sees every North lead, including the unassigned one, and nothing else'
);

select is(
  (select count(*)::int from public.profiles),
  4,
  'manager sees the four North profiles (self, R1, R2, inactive R4)'
);

select lives_ok(
  $$ update public.leads set assigned_to = '00000000-0000-0000-0000-000000000012'
     where id = '00000000-0000-0000-0000-0000000000c5' $$,
  'manager can assign the unrouted North lead to an active North rep'
);

select throws_ok(
  $$ update public.leads set assigned_to = '00000000-0000-0000-0000-000000000013'
     where id = '00000000-0000-0000-0000-0000000000c4' $$,
  '42501', null,
  'manager cannot assign a lead to a rep in another territory'
);

select throws_ok(
  $$ update public.leads set assigned_to = '00000000-0000-0000-0000-000000000014'
     where id = '00000000-0000-0000-0000-0000000000c4' $$,
  '42501', null,
  'manager cannot assign a lead to an inactive rep'
);

reset role;

select results_eq(
  $$ select assigned_to, status::text, assigned_at is not null
     from public.leads where id = '00000000-0000-0000-0000-0000000000c5' $$,
  $$ values ('00000000-0000-0000-0000-000000000012'::uuid, 'new', true) $$,
  'manual assignment sets assigned_at automatically and leaves status for the rep'
);

select ok(
  exists (select 1 from public.lead_events
          where lead_id = '00000000-0000-0000-0000-0000000000c5'
            and event = 'reassigned'
            and actor = '00000000-0000-0000-0000-000000000002'),
  'manager reassignment is audited'
);

-- =============================================================================
-- 6. RLS: admin, inactive user, anonymous
-- =============================================================================
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000001","role":"authenticated"}', true);

select is((select count(*)::int from public.leads), 7, 'admin sees every lead');

select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000014","role":"authenticated"}', true);

select is(
  (select count(*)::int from public.leads) + (select count(*)::int from public.territories)
    + (select count(*)::int from public.profiles),
  0,
  'an inactive user sees nothing at all'
);

reset role;
set local role anon;

select throws_ok(
  $$ select count(*) from public.leads $$,
  '42501', null,
  'anonymous requests are refused outright'
);

reset role;

select * from finish();
rollback;
