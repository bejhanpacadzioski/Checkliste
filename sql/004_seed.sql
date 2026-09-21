-- ============================================================
-- Checklists by Bejhan — 004 Bestandsdaten & Bootstrap
-- Nach 001-003 einmalig ausfuehren.
-- ============================================================

-- ------------------------------------------------------------
-- 1) Bestehende Organisation(en) in die neue Tabelle uebernehmen
--    (frueher gab es organization_members.organization_id ohne
--    zugehoerige organizations-Zeile)
-- ------------------------------------------------------------
insert into public.organizations(id, name)
select distinct m.organization_id, 'Checklists'
from public.organization_members m
where m.organization_id is not null
on conflict (id) do nothing;

-- ------------------------------------------------------------
-- 2) Profile fuer bestehende Auth-User nachtragen, falls eines fehlt
-- ------------------------------------------------------------
insert into public.profiles(id, email, display_name)
select u.id, u.email, coalesce(nullif(trim(u.raw_user_meta_data->>'display_name'), ''), split_part(u.email, '@', 1))
from auth.users u
where not exists (select 1 from public.profiles p where p.id = u.id)
on conflict (id) do nothing;

-- ------------------------------------------------------------
-- 3) Jeder Auth-User ohne Mitgliedschaft bekommt eine eigene Organisation
-- ------------------------------------------------------------
do $$
declare r record; v_org uuid;
begin
  for r in
    select p.id, coalesce(p.display_name, p.email, 'Workspace') as name
    from public.profiles p
    where not exists (select 1 from public.organization_members m where m.user_id = p.id)
  loop
    insert into public.organizations(name) values (r.name) returning id into v_org;
    insert into public.organization_members(user_id, organization_id, role)
    values (r.id, v_org, 'user')
    on conflict (user_id, organization_id) do nothing;
  end loop;
end $$;

-- ------------------------------------------------------------
-- 4) Ersten Super Admin setzen
--    E-Mail unten anpassen und die zwei Zeilen einkommentieren.
-- ------------------------------------------------------------
-- update public.organization_members m
--   set role = 'super_admin'
--   from public.profiles p
--  where p.id = m.user_id and lower(p.email) = lower('deine@mail.ch');

-- ------------------------------------------------------------
-- 5) Kontrolle: RLS muss auf allen Tabellen aktiv sein
-- ------------------------------------------------------------
select c.relname as tabelle, c.relrowsecurity as rls_aktiv
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by c.relname;
