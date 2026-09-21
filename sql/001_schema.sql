-- ============================================================
-- Checklists by Bejhan — 001 Schema
-- Idempotent: kann gefahrlos mehrfach ausgefuehrt werden.
-- Reihenfolge: 001_schema -> 002_functions -> 003_rls -> 004_seed
-- ============================================================

create extension if not exists pgcrypto;
create extension if not exists pg_trgm;

-- ------------------------------------------------------------
-- Organisationen (Mandanten / Workspaces)
-- ------------------------------------------------------------
create table if not exists public.organizations(
  id uuid primary key default gen_random_uuid(),
  name text not null default 'Workspace',
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- Profile (1:1 zu auth.users)
-- ------------------------------------------------------------
create table if not exists public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  dark_mode boolean not null default false,
  is_disabled boolean not null default false
);
alter table public.profiles add column if not exists created_at timestamptz not null default now();
alter table public.profiles add column if not exists show_trips boolean not null default true;
alter table public.profiles add column if not exists onboarded_at timestamptz;

-- ------------------------------------------------------------
-- Mitgliedschaften
-- Bewusst ohne FK auf organizations: Bestandsdaten koennen
-- organization_ids enthalten, die nie in organizations standen.
-- ------------------------------------------------------------
create table if not exists public.organization_members(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  organization_id uuid not null,
  role text not null default 'user',
  created_at timestamptz not null default now()
);
create unique index if not exists organization_members_user_org_uidx
  on public.organization_members(user_id, organization_id);

-- ------------------------------------------------------------
-- Checklisten
-- ------------------------------------------------------------
create table if not exists public.checklists(
  id uuid primary key default gen_random_uuid(),
  organization_id uuid,
  owner_id uuid references public.profiles(id) on delete cascade,
  created_by uuid,
  updated_by uuid,
  template_id uuid,
  title text not null default '',
  description text,
  icon text,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  deleted_by uuid
);
alter table public.checklists add column if not exists updated_at timestamptz;

create table if not exists public.checklist_categories(
  id uuid primary key default gen_random_uuid(),
  checklist_id uuid not null references public.checklists(id) on delete cascade,
  title text not null default '',
  sort_order int not null default 0
);

create table if not exists public.checklist_items(
  id uuid primary key default gen_random_uuid(),
  category_id uuid references public.checklist_categories(id) on delete cascade,
  checklist_id uuid references public.checklists(id) on delete cascade,
  title text not null default '',
  is_checked boolean not null default false,
  checked_at timestamptz,
  checked_by uuid,
  sort_order int not null default 0
);

create table if not exists public.checklist_shares(
  id uuid primary key default gen_random_uuid(),
  checklist_id uuid not null references public.checklists(id) on delete cascade,
  shared_with uuid not null references public.profiles(id) on delete cascade,
  permission text not null default 'read' check (permission in ('read','edit')),
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
create unique index if not exists checklist_shares_unique
  on public.checklist_shares(checklist_id, shared_with);

-- ------------------------------------------------------------
-- Einladungen an noch nicht registrierte E-Mail-Adressen
-- ------------------------------------------------------------
create table if not exists public.checklist_invites(
  id uuid primary key default gen_random_uuid(),
  checklist_id uuid not null references public.checklists(id) on delete cascade,
  email text not null,
  permission text not null default 'read' check (permission in ('read','edit')),
  invited_by uuid references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  accepted_by uuid references public.profiles(id) on delete set null
);
create unique index if not exists checklist_invites_open_uidx
  on public.checklist_invites(checklist_id, lower(email)) where accepted_at is null;

-- ------------------------------------------------------------
-- Vorlagen
-- ------------------------------------------------------------
create table if not exists public.templates(
  id uuid primary key default gen_random_uuid(),
  organization_id uuid,
  owner_id uuid references public.profiles(id) on delete cascade,
  created_by uuid,
  title text not null default '',
  description text,
  icon text,
  is_global boolean not null default false,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table if not exists public.template_categories(
  id uuid primary key default gen_random_uuid(),
  template_id uuid not null references public.templates(id) on delete cascade,
  title text not null default '',
  sort_order int not null default 0
);

create table if not exists public.template_items(
  id uuid primary key default gen_random_uuid(),
  category_id uuid not null references public.template_categories(id) on delete cascade,
  title text not null default '',
  sort_order int not null default 0
);

-- ------------------------------------------------------------
-- Reisen
-- ------------------------------------------------------------
create table if not exists public.trips(
  id uuid primary key default gen_random_uuid(),
  organization_id uuid,
  owner_id uuid references public.profiles(id) on delete cascade,
  created_by uuid,
  title text not null default '',
  description text,
  destination text,
  travel_date_from date,
  travel_date_to date,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table if not exists public.trip_items(
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.trips(id) on delete cascade,
  category text not null check (category in ('accommodation','flight_out','flight_return','flight_combined')),
  name text,
  provider text,
  price numeric(10,2),
  currency text default 'CHF',
  booking_deadline date,
  url text,
  date_from timestamptz,
  date_to timestamptz,
  persons int,
  notes text,
  status text not null default 'open' check (status in ('open','favorite','booked','rejected')),
  sort_order int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.trip_item_ratings(
  id uuid primary key default gen_random_uuid(),
  item_id uuid not null references public.trip_items(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  rating int check (rating between 1 and 6),
  comment text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists trip_item_ratings_unique
  on public.trip_item_ratings(item_id, user_id);

-- ------------------------------------------------------------
-- Indizes (wichtig ab einigen hundert Nutzern)
-- ------------------------------------------------------------
create index if not exists profiles_email_lower_idx on public.profiles(lower(email));
create index if not exists org_members_user_idx on public.organization_members(user_id);
create index if not exists checklists_owner_idx on public.checklists(owner_id);
create index if not exists checklists_org_idx on public.checklists(organization_id);
create index if not exists checklists_created_idx on public.checklists(created_at desc);
create index if not exists checklists_title_trgm on public.checklists using gin (title gin_trgm_ops);
create index if not exists cl_categories_cl_idx on public.checklist_categories(checklist_id);
create index if not exists cl_items_cat_idx on public.checklist_items(category_id);
create index if not exists cl_items_cl_idx on public.checklist_items(checklist_id);
create index if not exists cl_shares_with_idx on public.checklist_shares(shared_with);
create index if not exists cl_shares_cl_idx on public.checklist_shares(checklist_id);
create index if not exists cl_shares_by_idx on public.checklist_shares(created_by);
create index if not exists cl_invites_email_idx on public.checklist_invites(lower(email));
create index if not exists templates_owner_idx on public.templates(owner_id);
create index if not exists templates_global_idx on public.templates(is_global) where is_global;
create index if not exists tpl_categories_tpl_idx on public.template_categories(template_id);
create index if not exists tpl_items_cat_idx on public.template_items(category_id);
create index if not exists trips_org_idx on public.trips(organization_id);
create index if not exists trip_items_trip_idx on public.trip_items(trip_id);
create index if not exists trip_ratings_item_idx on public.trip_item_ratings(item_id);
