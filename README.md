# Checklists by Bejhan

Progressive Web App für Checklisten, Vorlagen und Reiseplanung.
Eine `index.html` ohne Build-Schritt, Backend ist Supabase.

**Version 5.0.0**

## Einrichtung

### 1. Datenbank

Die SQL-Dateien im Ordner `sql/` **in dieser Reihenfolge** im Supabase
SQL-Editor ausführen:

| Datei | Inhalt |
|---|---|
| `001_schema.sql` | Tabellen, Spalten, Indizes |
| `002_functions.sql` | Hilfsfunktionen, Signup-Trigger, RPCs |
| `003_rls.sql` | Row Level Security für alle Tabellen |
| `004_seed.sql` | Bestandsdaten nachziehen, ersten Super Admin setzen |

Alle Dateien sind idempotent und können erneut ausgeführt werden.

In `004_seed.sql` am Ende die eigene E-Mail eintragen und die zwei
auskommentierten Zeilen aktivieren, um den ersten Super Admin zu setzen.

> **Wichtig:** Vor dieser Migration war RLS auf `checklists`,
> `checklist_categories` und `checklist_items` deaktiviert — mit dem
> Publishable Key waren die Daten aller Nutzer lesbar. `003_rls.sql`
> schliesst das. Ohne diese Migration ist die App nicht für fremde
> Nutzer geeignet.

### 2. Supabase Auth

Unter **Authentication → Sign In / Providers → Email**:

- **Enable Signup** einschalten (sonst schlägt die Registrierung fehl)
- **Confirm email** einschalten (empfohlen)

Unter **Authentication → URL Configuration**:

- **Site URL** auf die Adresse der App setzen
- Diese Adresse zusätzlich unter **Redirect URLs** eintragen —
  sonst funktionieren Bestätigungs- und Passwort-Reset-Links nicht

Für echten Mailversand ab einigen hundert Nutzern einen eigenen
SMTP-Anbieter hinterlegen (**Project Settings → Auth → SMTP**). Der
eingebaute Supabase-Mailer ist stark limitiert und nur für Tests gedacht.

### 3. Edge Functions

Ordnername = Funktionsname, je ein `index.ts`:
`create-user`, `set-user-password`, `delete-user`, `scrape-url`,
`import-checklist`.

Secret `ANTHROPIC_API_KEY` unter **Project Settings → Edge Functions →
Secrets** setzen (für Import per Link/Screenshot/PDF).

### 4. Frontend

`SB_URL` und `SB_KEY` am Anfang des `<script>`-Blocks in `index.html`
eintragen. Dann `index.html`, `manifest.json`, `sw.js` und `icon.svg`
statisch ausliefern (GitHub Pages, Cloudflare Pages oder Vercel).

## Version pflegen

Bei jeder Änderung anpassen:

- `APP_VERSION` und `APP_BUILD` in `index.html`
- `VERSION` in `sw.js` — versioniert den Cache-Namen, sonst bekommen
  installierte PWAs das Update nicht
- `version` in `manifest.json`

Die Angabe erscheint in der Sidebar, auf dem Login-Screen und unter
Einstellungen → Über die App.

## Mandanten-Modell

Jede Registrierung erzeugt eine eigene Organisation (Workspace).
Geteilt wird über Checklisten-Freigaben, auch über Organisationsgrenzen
hinweg. Reisen sind innerhalb einer Organisation gemeinsam sichtbar.

Sollen stattdessen alle neuen Nutzer in einer gemeinsamen Organisation
landen (Familien-/Team-Betrieb), ist der Block in `handle_new_user()`
in `002_functions.sql` entsprechend kommentiert.

## Funktionen

- Registrierung, E-Mail-Bestätigung, Passwort zurücksetzen
- Checklisten mit Kategorien, Drag & Drop, Fortschritt, PDF-Export
- Teilen per E-Mail; wer noch kein Konto hat, wird eingeladen und
  erhält die Freigabe automatisch bei der Registrierung
- Vorlagen (eigene und globale), Import per Link, Screenshot oder PDF
- Reiseplanung mit Angeboten und gemeinsamen Bewertungen (abschaltbar)
- Suche und seitenweises Nachladen
- Admin-Bereich für Benutzerverwaltung
- Dark Mode, installierbar als PWA
