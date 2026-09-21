-- ============================================================
-- Checklists by Bejhan — 002 Funktionen, Trigger, RPCs
--
-- Alle Helper sind SECURITY DEFINER. Das ist hier kein Zufall,
-- sondern der Kern der Loesung: Policies duerfen sich nicht
-- gegenseitig aufrufen, sonst entsteht die "infinite recursion
-- detected in policy"-Kette (siehe Handbuch 6.4). SECURITY
-- DEFINER umgeht RLS beim Lesen der Hilfstabellen und bricht
-- die Rekursion auf.
-- ============================================================

-- ------------------------------------------------------------
-- Identitaet / Rollen
-- ------------------------------------------------------------
create or replace function public.my_email()
returns text language sql security definer stable set search_path = public, auth as $$
  select u.email from auth.users u where u.id = auth.uid();
$$;

create or replace function public.my_org()
returns uuid language sql security definer stable set search_path = public as $$
  select m.organization_id from public.organization_members m
  where m.user_id = auth.uid() order by m.created_at limit 1;
$$;

create or replace function public.same_org_id(p_org uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select p_org is not null and exists(
    select 1 from public.organization_members m
    where m.user_id = auth.uid() and m.organization_id = p_org
  );
$$;

create or replace function public.same_org(p_user uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(
    select 1 from public.organization_members a
    join public.organization_members b on a.organization_id = b.organization_id
    where a.user_id = auth.uid() and b.user_id = p_user
  );
$$;

create or replace function public.my_role()
returns text language sql security definer stable set search_path = public as $$
  select m.role from public.organization_members m
  where m.user_id = auth.uid()
  order by case m.role when 'super_admin' then 1 when 'admin' then 2 else 3 end
  limit 1;
$$;

create or replace function public.is_admin()
returns boolean language sql security definer stable set search_path = public as $$
  select coalesce(public.my_role() in ('admin','super_admin'), false);
$$;

create or replace function public.is_super_admin()
returns boolean language sql security definer stable set search_path = public as $$
  select coalesce(public.my_role() = 'super_admin', false);
$$;

-- ------------------------------------------------------------
-- Checklisten-Zugriff
-- ------------------------------------------------------------
create or replace function public.is_checklist_owner(p_checklist uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(
    select 1 from public.checklists c
    where c.id = p_checklist and c.owner_id = auth.uid()
  );
$$;

create or replace function public.can_read_checklist(p_checklist uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select p_checklist is not null and (
    exists(select 1 from public.checklists c where c.id = p_checklist and c.owner_id = auth.uid())
    or exists(select 1 from public.checklist_shares s where s.checklist_id = p_checklist and s.shared_with = auth.uid())
    or public.is_admin()
  );
$$;

create or replace function public.can_edit_checklist(p_checklist uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select p_checklist is not null and (
    exists(select 1 from public.checklists c where c.id = p_checklist and c.owner_id = auth.uid())
    or exists(select 1 from public.checklist_shares s
              where s.checklist_id = p_checklist and s.shared_with = auth.uid() and s.permission = 'edit')
    or public.is_admin()
  );
$$;

-- Eintraege haengen entweder an einer Kategorie ODER direkt an
-- der Checkliste (siehe Handbuch 2.5.1) — hier aufgeloest.
create or replace function public.item_checklist_id(p_category uuid, p_checklist uuid)
returns uuid language sql security definer stable set search_path = public as $$
  select coalesce(
    p_checklist,
    (select cc.checklist_id from public.checklist_categories cc where cc.id = p_category)
  );
$$;

-- ------------------------------------------------------------
-- Vorlagen-Zugriff
-- ------------------------------------------------------------
create or replace function public.can_read_template(p_tpl uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(
    select 1 from public.templates t
    where t.id = p_tpl and (t.owner_id = auth.uid() or t.is_global or public.is_admin())
  );
$$;

create or replace function public.can_edit_template(p_tpl uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(
    select 1 from public.templates t
    where t.id = p_tpl and (t.owner_id = auth.uid() or public.is_admin())
  );
$$;

create or replace function public.template_of_category(p_category uuid)
returns uuid language sql security definer stable set search_path = public as $$
  select tc.template_id from public.template_categories tc where tc.id = p_category;
$$;

-- ------------------------------------------------------------
-- Reise-Zugriff (Reisen sind innerhalb einer Organisation geteilt)
-- ------------------------------------------------------------
create or replace function public.can_access_trip(p_trip uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(
    select 1 from public.trips t
    where t.id = p_trip and (t.owner_id = auth.uid() or public.same_org_id(t.organization_id) or public.is_admin())
  );
$$;

create or replace function public.trip_of_item(p_item uuid)
returns uuid language sql security definer stable set search_path = public as $$
  select ti.trip_id from public.trip_items ti where ti.id = p_item;
$$;

-- ------------------------------------------------------------
-- Sichtbarkeit von Profilen
-- Ein fremdes Profil ist sichtbar, wenn man in derselben
-- Organisation ist ODER tatsaechlich etwas miteinander teilt.
-- Damit sieht bei 1000 Nutzern niemand mehr das ganze Verzeichnis.
-- ------------------------------------------------------------
create or replace function public.is_contact(p_user uuid)
returns boolean language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.checklist_shares s
                where s.created_by = auth.uid() and s.shared_with = p_user)
      or exists(select 1 from public.checklist_shares s
                where s.shared_with = auth.uid() and s.created_by = p_user)
      or exists(select 1 from public.checklist_shares s
                join public.checklists c on c.id = s.checklist_id
                where s.shared_with = auth.uid() and c.owner_id = p_user)
      or exists(select 1 from public.checklist_shares s
                join public.checklists c on c.id = s.checklist_id
                where c.owner_id = auth.uid() and s.shared_with = p_user);
$$;

-- ------------------------------------------------------------
-- RPC: Profil per E-Mail suchen (fuer "Teilen")
-- Gibt hoechstens einen Treffer zurueck — kein Verzeichnis.
-- ------------------------------------------------------------
create or replace function public.lookup_profile_by_email(p_email text)
returns table(id uuid, display_name text, email text)
language sql security definer stable set search_path = public as $$
  select p.id, p.display_name, p.email
  from public.profiles p
  where auth.uid() is not null
    and lower(p.email) = lower(trim(p_email))
    and p.is_disabled = false
  limit 1;
$$;

-- ------------------------------------------------------------
-- RPC: bisherige Teilen-Kontakte (beide Richtungen)
-- ------------------------------------------------------------
create or replace function public.share_contacts()
returns table(id uuid, display_name text, email text)
language sql security definer stable set search_path = public as $$
  select distinct p.id, p.display_name, p.email
  from public.profiles p
  where p.id <> auth.uid()
    and p.is_disabled = false
    and (
      p.id in (select s.shared_with from public.checklist_shares s where s.created_by = auth.uid())
      or p.id in (select s.created_by from public.checklist_shares s where s.shared_with = auth.uid())
      or p.id in (select c.owner_id from public.checklist_shares s
                  join public.checklists c on c.id = s.checklist_id
                  where s.shared_with = auth.uid())
    );
$$;

-- ------------------------------------------------------------
-- RPC: offene Einladungen der eigenen E-Mail einloesen
-- ------------------------------------------------------------
create or replace function public.claim_my_invites()
returns integer language plpgsql security definer set search_path = public as $$
declare v_email text; v_count integer := 0;
begin
  select public.my_email() into v_email;
  if v_email is null then return 0; end if;

  insert into public.checklist_shares(checklist_id, shared_with, permission, created_by)
  select i.checklist_id, auth.uid(), i.permission, i.invited_by
  from public.checklist_invites i
  where lower(i.email) = lower(v_email) and i.accepted_at is null
  on conflict (checklist_id, shared_with) do nothing;

  get diagnostics v_count = row_count;

  update public.checklist_invites
  set accepted_at = now(), accepted_by = auth.uid()
  where lower(email) = lower(v_email) and accepted_at is null;

  return v_count;
end $$;

-- ------------------------------------------------------------
-- Trigger: neuer Auth-User -> Profil + eigene Organisation
--
-- Jeder Self-Signup bekommt eine EIGENE Organisation (Workspace).
-- Geteilt wird ueber checklist_shares ueber Org-Grenzen hinweg.
--
-- Sollen stattdessen alle neuen Nutzer in EINE gemeinsame
-- Organisation (z.B. Familie/Team), dann den markierten Block
-- unten durch diese Zeile ersetzen:
--   select m.organization_id into v_org from public.organization_members m
--     group by m.organization_id order by count(*) desc limit 1;
-- ------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_org uuid;
  v_name text;
begin
  v_name := coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'), ''), split_part(new.email, '@', 1));

  insert into public.profiles(id, email, display_name)
  values (new.id, new.email, v_name)
  on conflict (id) do update set email = excluded.email;

  -- >>> Workspace-Block <<<
  insert into public.organizations(name) values (v_name) returning id into v_org;
  -- >>> Ende Workspace-Block <<<

  insert into public.organization_members(user_id, organization_id, role)
  values (new.id, v_org, 'user')
  on conflict (user_id, organization_id) do nothing;

  -- offene Einladungen an diese Adresse sofort in Freigaben wandeln
  insert into public.checklist_shares(checklist_id, shared_with, permission, created_by)
  select i.checklist_id, new.id, i.permission, i.invited_by
  from public.checklist_invites i
  where lower(i.email) = lower(new.email) and i.accepted_at is null
  on conflict (checklist_id, shared_with) do nothing;

  update public.checklist_invites
  set accepted_at = now(), accepted_by = new.id
  where lower(email) = lower(new.email) and accepted_at is null;

  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ------------------------------------------------------------
-- Trigger: Nutzer duerfen sich nicht selbst entsperren
-- ------------------------------------------------------------
create or replace function public.protect_profile_flags()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    new.is_disabled := old.is_disabled;
  end if;
  return new;
end $$;

drop trigger if exists profiles_protect_flags on public.profiles;
create trigger profiles_protect_flags
  before update on public.profiles
  for each row execute function public.protect_profile_flags();

-- ------------------------------------------------------------
-- Ausfuehrungsrechte
-- ------------------------------------------------------------
grant execute on function public.lookup_profile_by_email(text) to authenticated;
grant execute on function public.share_contacts() to authenticated;
grant execute on function public.claim_my_invites() to authenticated;
