-- ============================================================
-- Checklists by Bejhan — 003 Row Level Security
--
-- Loest den offenen Punkt aus Handbuch 6.4: RLS war auf
-- checklists / checklist_categories / checklist_items
-- deaktiviert, die Zugriffskontrolle lag allein im Client.
-- Mit dem Publishable Key konnte damit theoretisch jeder alle
-- Checklisten aller Nutzer lesen. Ab hier erzwingt die
-- Datenbank die Regeln.
--
-- Rekursionsfrei, weil jede Policy nur SECURITY-DEFINER-Helper
-- aus 002_functions.sql aufruft und niemals direkt eine andere
-- RLS-geschuetzte Tabelle abfragt.
-- ============================================================

-- ------------------------------------------------------------
-- Grundrechte: anon (ausgeloggt) braucht keinerlei Tabellenzugriff
-- ------------------------------------------------------------
grant usage on schema public to anon, authenticated;
revoke all on all tables in schema public from anon;
grant all on all tables in schema public to authenticated;
grant all on all sequences in schema public to authenticated;

-- ------------------------------------------------------------
-- profiles
-- ------------------------------------------------------------
alter table public.profiles enable row level security;
drop policy if exists profiles_select on public.profiles;
drop policy if exists profiles_insert_self on public.profiles;
drop policy if exists profiles_update_self on public.profiles;
drop policy if exists profiles_admin_all on public.profiles;

create policy profiles_select on public.profiles for select using (
  id = auth.uid() or public.same_org(id) or public.is_contact(id) or public.is_admin()
);
create policy profiles_insert_self on public.profiles for insert with check (id = auth.uid());
create policy profiles_update_self on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_admin_all on public.profiles for all using (public.is_admin()) with check (public.is_admin());

-- ------------------------------------------------------------
-- organization_members
-- ------------------------------------------------------------
alter table public.organization_members enable row level security;
drop policy if exists org_members_select on public.organization_members;
drop policy if exists org_members_admin on public.organization_members;

create policy org_members_select on public.organization_members for select using (
  user_id = auth.uid() or public.same_org_id(organization_id) or public.is_admin()
);
-- Rollen vergibt nur ein Admin (bzw. der Service-Role-Key der Edge Functions)
create policy org_members_admin on public.organization_members for all
  using (public.is_admin()) with check (public.is_admin());

-- ------------------------------------------------------------
-- organizations
-- ------------------------------------------------------------
alter table public.organizations enable row level security;
drop policy if exists organizations_select on public.organizations;
create policy organizations_select on public.organizations for select using (
  public.same_org_id(id) or public.is_admin()
);

-- ------------------------------------------------------------
-- checklists
-- ------------------------------------------------------------
alter table public.checklists enable row level security;
drop policy if exists checklists_select on public.checklists;
drop policy if exists checklists_insert on public.checklists;
drop policy if exists checklists_update on public.checklists;
drop policy if exists checklists_delete on public.checklists;

create policy checklists_select on public.checklists for select using (
  owner_id = auth.uid() or public.can_read_checklist(id)
);
create policy checklists_insert on public.checklists for insert with check (
  owner_id = auth.uid() or public.is_admin()
);
create policy checklists_update on public.checklists for update using (
  owner_id = auth.uid() or public.can_edit_checklist(id)
) with check (
  owner_id = auth.uid() or public.can_edit_checklist(id)
);
-- Loeschen bleibt dem Besitzer (und Admins) vorbehalten
create policy checklists_delete on public.checklists for delete using (
  owner_id = auth.uid() or public.is_admin()
);

-- ------------------------------------------------------------
-- checklist_categories
-- ------------------------------------------------------------
alter table public.checklist_categories enable row level security;
drop policy if exists cl_categories_select on public.checklist_categories;
drop policy if exists cl_categories_write on public.checklist_categories;

create policy cl_categories_select on public.checklist_categories for select
  using (public.can_read_checklist(checklist_id));
create policy cl_categories_write on public.checklist_categories for all
  using (public.can_edit_checklist(checklist_id))
  with check (public.can_edit_checklist(checklist_id));

-- ------------------------------------------------------------
-- checklist_items
-- ------------------------------------------------------------
alter table public.checklist_items enable row level security;
drop policy if exists cl_items_select on public.checklist_items;
drop policy if exists cl_items_write on public.checklist_items;

create policy cl_items_select on public.checklist_items for select
  using (public.can_read_checklist(public.item_checklist_id(category_id, checklist_id)));
create policy cl_items_write on public.checklist_items for all
  using (public.can_edit_checklist(public.item_checklist_id(category_id, checklist_id)))
  with check (public.can_edit_checklist(public.item_checklist_id(category_id, checklist_id)));

-- ------------------------------------------------------------
-- checklist_shares
-- ------------------------------------------------------------
alter table public.checklist_shares enable row level security;
drop policy if exists "Owner can manage shares" on public.checklist_shares;
drop policy if exists "Shared users can read their shares" on public.checklist_shares;
drop policy if exists cl_shares_owner on public.checklist_shares;
drop policy if exists cl_shares_recipient on public.checklist_shares;
drop policy if exists cl_shares_admin on public.checklist_shares;

create policy cl_shares_owner on public.checklist_shares for all
  using (public.is_checklist_owner(checklist_id))
  with check (public.is_checklist_owner(checklist_id));
create policy cl_shares_recipient on public.checklist_shares for select
  using (shared_with = auth.uid());
create policy cl_shares_admin on public.checklist_shares for all
  using (public.is_admin()) with check (public.is_admin());

-- ------------------------------------------------------------
-- checklist_invites
-- ------------------------------------------------------------
alter table public.checklist_invites enable row level security;
drop policy if exists cl_invites_owner on public.checklist_invites;
drop policy if exists cl_invites_self on public.checklist_invites;

create policy cl_invites_owner on public.checklist_invites for all
  using (public.is_checklist_owner(checklist_id))
  with check (public.is_checklist_owner(checklist_id));
create policy cl_invites_self on public.checklist_invites for select
  using (lower(email) = lower(coalesce(public.my_email(), '')));

-- ------------------------------------------------------------
-- templates
-- ------------------------------------------------------------
alter table public.templates enable row level security;
drop policy if exists templates_select on public.templates;
drop policy if exists templates_write on public.templates;

create policy templates_select on public.templates for select using (
  owner_id = auth.uid() or is_global or public.is_admin()
);
create policy templates_write on public.templates for all
  using (owner_id = auth.uid() or public.is_admin())
  with check (owner_id = auth.uid() or public.is_admin());

alter table public.template_categories enable row level security;
drop policy if exists tpl_categories_select on public.template_categories;
drop policy if exists tpl_categories_write on public.template_categories;
create policy tpl_categories_select on public.template_categories for select
  using (public.can_read_template(template_id));
create policy tpl_categories_write on public.template_categories for all
  using (public.can_edit_template(template_id))
  with check (public.can_edit_template(template_id));

alter table public.template_items enable row level security;
drop policy if exists tpl_items_select on public.template_items;
drop policy if exists tpl_items_write on public.template_items;
create policy tpl_items_select on public.template_items for select
  using (public.can_read_template(public.template_of_category(category_id)));
create policy tpl_items_write on public.template_items for all
  using (public.can_edit_template(public.template_of_category(category_id)))
  with check (public.can_edit_template(public.template_of_category(category_id)));

-- ------------------------------------------------------------
-- trips (innerhalb der Organisation geteilt)
-- ------------------------------------------------------------
alter table public.trips enable row level security;
drop policy if exists trips_select on public.trips;
drop policy if exists trips_write on public.trips;
drop policy if exists trips_delete on public.trips;

create policy trips_select on public.trips for select using (
  owner_id = auth.uid() or public.same_org_id(organization_id) or public.is_admin()
);
create policy trips_write on public.trips for all
  using (owner_id = auth.uid() or public.same_org_id(organization_id) or public.is_admin())
  with check (owner_id = auth.uid() or public.same_org_id(organization_id) or public.is_admin());

alter table public.trip_items enable row level security;
drop policy if exists trip_items_all on public.trip_items;
create policy trip_items_all on public.trip_items for all
  using (public.can_access_trip(trip_id))
  with check (public.can_access_trip(trip_id));

alter table public.trip_item_ratings enable row level security;
drop policy if exists trip_ratings_select on public.trip_item_ratings;
drop policy if exists trip_ratings_own on public.trip_item_ratings;
create policy trip_ratings_select on public.trip_item_ratings for select
  using (public.can_access_trip(public.trip_of_item(item_id)));
-- Bewerten darf jeder Teilnehmer, aber nur im eigenen Namen
create policy trip_ratings_own on public.trip_item_ratings for all
  using (user_id = auth.uid() and public.can_access_trip(public.trip_of_item(item_id)))
  with check (user_id = auth.uid() and public.can_access_trip(public.trip_of_item(item_id)));
