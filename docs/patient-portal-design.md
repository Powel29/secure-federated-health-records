# Patient portal page design — P4-7

Design/layout spec for the patient web portal (Django + Bootstrap, `portal/patient/`).
Component context is `ARCHITECTURE.md` §2 (C16) and ADR-0014/0016/0021; this file
is the per-page layout and behaviour detail.

**Status:** Superseded in part by ADR-0043 and the shipped `portal/patient/`
pages (2026-09-13). The open question below — patient signing-key custody — is
resolved by the Key Custodian service; the Bootstrap chrome described here was
replaced by the shared Custos design (`portal/static/portal/custos.css`). The
per-page behaviour and acceptance criteria still describe what was built and
remain useful for review.

**What this is:** the patient half of the three-portal UI that replaced the old
terminal dashboard (ADR-0014). It lets a patient manage access to their records,
see who has touched them, and read their own record. It renders and identifies;
**it never decides access and never holds keys.**

---

## Governing rules (every page obeys these)

These are not per-page choices — they are the boundary the portal exists inside.

- **Identity, not authority (ADR-0014).** Django login answers "who is asking",
  never "may this be decrypted." A page never releases a key and never makes an
  access decision. If a portal login or DB check ever releases a key, the
  project's novelty is gone.
- **Fail closed.** Any backend/crypto error renders an explicit denial state —
  never a 500, never a blank, never a fabricated success. A missing owner
  attribute means "cannot open," shown plainly.
- **Read display data from the store, act through services.** Read-only display
  data comes via the read-only `store` DB alias (the `portal_core.store_reader`
  pattern, ADR-0021). Every state-changing or crypto action goes over HTTP to
  the owning service (`hospital.py`, `authority_service.py`) — never a direct
  `src/` import, never a store write.
- **No secrets on the wire to the browser.** Never render or log key material,
  DEKs, shares, search tokens, or (except the one streamed view) plaintext.
- **Auth.** `@login_required`; resolve `request.user.profile` with
  `role=PATIENT`. A profile-less login (e.g. a superuser) is routed away.
- **Chrome.** Every page `{% extends "base.html" %}` and shares the patient nav
  linking the four pages below.

- **Service-call failure = fail closed.** When a page calls a backend service
  (`hospital.py`, `authority_service.py`) over HTTP, a timeout, connection
  error, or non-2xx renders an explicit error state on that page — never a
  Django 500 traceback, never a silent empty render that reads as success. Use
  a bounded HTTP timeout on every call.
- **CSRF on every state change.** Every approve / deny / revoke / view-trigger
  is a `POST` carrying Django's `{% csrf_token %}` (as the existing shell forms
  already do); no state change rides on a `GET`.

---

## Django wiring

- **App:** `portal/patient/` (existing). Routes registered in
  `portal/patient/urls.py` under `app_name = "patient"`.
- **Views (function-based, one per page):** `home`, `access`, `history`,
  `record_view` — each `@login_required` and patient-role gated.
- **URL names** (used in templates, never hard-coded paths):
  `patient:home`, `patient:access`, `patient:history`, `patient:record_view`.
- **Templates:** `portal/templates/patient/{home,access,history,record_view}.html`,
  all `{% extends "base.html" %}`.
- **Backend access:** read-only display data via the `store` DB alias
  (`portal_core.store_reader` — extend it with the patient-scoped queries);
  actions via a small portal-side HTTP client to the services (new — no such
  client exists yet; today the shell uses `portal_core.stubs`).

## Notifications (P4-10) placement

Patient notifications for break-glass access and revocation (P4-10, Ojas) surface
*in this portal*, so their placement is part of its design even though the
emitting task is separate:

- A **notification indicator** in the patient sub-nav (a count badge), and an
  **alerts card at the top of Home** listing recent notifications
  (break-glass-access, grant-revoked), newest first.
- Each notification links to the relevant **Access history** row (same
  correlation ID) so "you were accessed under break-glass" leads to the evidence.
- Notifications are display only; dismissing one is portal-local state and never
  changes access or the audit chain.

---

## Page 1 — Dashboard home

- **Route:** `GET /patient/` (extends the existing `patient/home.html`).
- **Purpose:** landing view — enrollment status, the patient's own records, and
  at-a-glance counts.
- **Layout:** three stacked Bootstrap cards / rows.
  1. **Enrollment** (keep existing): `subject_id` + registration-request status
     badge(s).
  2. **My records:** table — `record_id`, facility, `content_type`, uploaded
     date. Each row links to Page 4 (view). Source: read-only SQL filtered by
     `patient_id` (the `find_record_ids_by_patient` shape).
  3. **Summary row:** active-grants count, pending-requests count, most-recent
     access event.
- **Empty states:** "No records yet" (records arrive with ingest, P3-14); "No
  pending requests."
- **Out of scope here:** the shell upload form is ingest (P3-14, Avaneeth) — leave
  as-is or hide; do not present it as working.
- **Backend:** ready (read-only store reads).

## Page 2 — Access grants

- **Route:** `GET /patient/access/`; `POST` for approve / deny / revoke actions.
- **Purpose:** the "who has access" + approve/deny/revoke surface — the heart of
  P4-7's "Done when."
- **Layout:** two sections.
  1. **Pending incoming requests:** per `ConsentRequest` — requester (clinician),
     scope (record list), purpose text, requested / expiry dates. **Approve** and
     **Deny** buttons → HTTP `POST /consent/grants`.
  2. **Active grants:** per `GRANTED` grant — grantee, scope, granted date,
     expiry. **Revoke** button → HTTP `POST /consent/grants/revoke`. Revocation
     is patient-only (ADR-0037 / P3-12); the button is shown only to the owner.
- **Signing (unresolved — see Open questions):** `POST /consent/grants` takes an
  *already patient-signed* `ConsentGrant` and only verifies it; the signature
  must be produced with the patient's ECDSA private key *before* the portal
  posts it. `POST /consent/grants/revoke` currently expects
  `patient_signing_key_pem` in the request body. Neither is compatible with
  ADR-0014 ("the portal holds no keys") as written — **where the patient's
  signing key lives and how a grant gets signed without the portal touching it
  is an open design question**, flagged below. This page must not be built to
  paste a patient private key into a form.
- **Feedback:** after any action, show the resulting state returned by the
  service; on error show the specific `Consent*Error` reason, not a generic
  failure.
- **Empty states:** "No pending requests"; "No one currently has access."
- **Pagination:** both tables cap at a page size (default 50, matching the
  store-reader limit) with older entries paged; a patient with many grants must
  not render an unbounded list.
- **Backend:** requests / approve / deny / revoke endpoints exist. Listing
  **active grants** uses `list_consent_grants_by_patient`
  (`src/api/repository.py`) — added on branch `proposal/p4-7-backend-gaps`,
  pending Avaneeth's review. Until merged, that section is behind a stub or a
  visible "pending backend" note.

## Page 3 — Access history

- **Route:** `GET /patient/history/`.
- **Purpose:** "view the history of who accessed what — including any
  break-glass."
- **Layout:** reverse-chronological table — timestamp, actor (clinician /
  facility), event type, correlation ID. Source: read-only SQL over `audit_log`
  / `transition_events`, filtered to this patient.
- **Break-glass flag:** rows for emergency access (`breakglass_share_release`,
  `federation.rewrap`, lifecycle `EMERGENCY_OPEN`) carry a distinct badge —
  ADR-0016 requires the patient sees break-glass access to their records.
- **Filters:** date range; event type (all / break-glass only / denials).
- **Honesty caveat:** ordinary successful reads are logged only once the
  `log_access_granted` change (branch `proposal/p4-7-backend-gaps`, pending
  Ojas + Avaneeth review) is merged. Until then this page shows break-glass +
  denials only and **must display a visible note** that normal reads are not yet
  recorded — it must not imply a completeness it lacks.
- **Empty state:** "No access events recorded."
- **Backend:** partially ready (break-glass + denial events exist; success-read
  logging is the pending change above).

## Page 4 — View own record

- **Route:** `GET /patient/records/<record_id>/view/`.
- **Purpose:** "open and view their own record, decrypted through the policy
  path, failing closed if the owner attribute is absent" (ADR-0016).
- **Ownership check:** the record's `patient_id` must equal the logged-in
  patient's `subject_id`; otherwise 404-style deny (do not reveal existence).
- **Decrypt path:** portal calls `POST /records/{id}/read` over HTTP with the
  patient's identity. The **home authority** supplies the `owner:<patient_id>`
  attribute key; the service reconstructs → unwraps → AES-256-GCM decrypts. The
  portal receives already-decrypted bytes for that one request. The portal never
  decrypts.
- **Streaming:** response streamed inline (`Content-Disposition: inline`),
  rendered/downloaded in-browser; **never written to disk, never logged**
  (CONVENTIONS §2 rule 3). No browser/proxy caching of the stream.
- **Fail closed (the P5-1 negative-test target):** if the owner attribute is
  absent, the policy is unsatisfied, or the authority declines — show an explicit
  "This record can't be opened — access is not granted by keys." Portal login
  alone must decrypt nothing.
- **Backend:** ready — the owner branch of the read endpoint already exists.

---

## Layout & placement

All pages render inside the `base.html` skeleton: a dark top `navbar` (brand
left, username + role badge + Log out right), then `main.container py-4`
carrying the persistent dev-shell alert, the `notice` slot, and the page
`content` block. Everything below sits in that content block on Bootstrap's
12-column grid. Wireframes are indicative, not pixel-exact.

**Common page skeleton (every page)**

```
┌ navbar (base.html) ─ Federated EHR ················· user [role] [Log out] ┐
├ dev-shell alert (base.html) ······································· (notice?) ┤
│ <h1 class="h4"> Page title </h1>          [ patient sub-nav: tabs/pills ]   │
│ ── page content (cards / table) ──────────────────────────────────────────│
└────────────────────────────────────────────────────────────────────────────┘
```

The patient sub-nav (nav-pills) links the four pages and sits directly under the
page title on every patient page, so the four are always one click apart.

**Page 1 — Home** (stacked full-width cards; records table is the focus)

```
[ Enrollment card ....................... subject_id + status badge(s) ]   full row
[ Summary: (Active grants N) (Pending M) (Last access …) ]                 3 stat tiles, one row
[ My records ─ table ────────────────────────────────────────────── ]     full width
  record_id | facility | type | uploaded |            [ View → ]           row action right-aligned
```

**Page 2 — Access grants** (two stacked sections, pending on top — it needs action)

```
[ Pending requests ]  ← top, because it is the actionable one
  requester | scope | purpose | requested | expires |  [Approve] [Deny]      buttons right
[ Active grants ]
  grantee | scope | granted | expires | status-badge |  [Revoke]            destructive action right
```

**Page 3 — Access history** (filter bar above a single wide table)

```
[ Filters:  (date from) (date to)   (type: all ▾) ]                        filter row, right-aligned
[ History ─ table (reverse-chron) ──────────────────────────────── ]
  when | actor | event | correlation-id | [BREAK-GLASS badge if emergency]
[ caveat note: "normal reads not yet recorded" until backend merged ]      small muted text under table
```

**Page 4 — View record** (narrow single column; the stream is the whole page)

```
[ ← Back to records ]
[ record_id · facility · uploaded ]                    thin metadata header
┌ viewer ─ inline PDF/stream, max-width readable column ─────────────┐
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
 …or, on failure:  [ alert-danger: "This record can't be opened —
                     access is not granted by keys." ]                fail-closed state replaces viewer
```

**Placement rules that hold across pages**

- **Title top-left, sub-nav to its right**, content below — one H1 per page.
- **Primary/confirming actions right-aligned** in their row or card; destructive
  actions (Revoke, Deny) also right, visually separated (outline-danger).
- **Tables are full-width**, wrapped in `table-responsive` so they scroll on
  narrow screens rather than overflowing the page.
- **Stat tiles** (counts) go in a single equal-width row directly under the title
  on pages that have them (Home).
- **Denied / fail-closed states replace the content they gate** (the viewer, the
  section) rather than appearing as a toast — the user must not see an empty
  frame that looks like success.

## Uniformity rules (all three portals)

The three portals (patient / clinician / admin) share only `base.html` today, so
consistency is a convention, not a framework. These rules keep the patient pages
aligned with that shared chrome and with the other two portals. They are written
to be portal-agnostic so clinician (P4-8) and admin (P4-9) can adopt the same
set — if the team wants this enforced, it becomes the shared-component ADR noted
in Open questions.

- **Framework:** Bootstrap 5.3.3 (the version `base.html` loads) only. No extra
  CSS frameworks, no custom stylesheet unless added to `base.html` for all
  portals at once. Use Bootstrap utilities over hand-written CSS.
- **Page shell:** exactly one `<h1 class="h4">` title per page; content in
  `.card` blocks or a `.table`; never bypass the `base.html` `main.container`.
- **Sections are cards.** Each logical section is a `.card` with a `.card-body`
  and an `<h2 class="h6">` heading — matching the existing shells. Group cards
  with `.row .g-3`.
- **Tables:** `.table .table-sm .align-middle`, header in `.table-light`, wrapped
  in `.table-responsive`. Timestamps rendered in one format
  (`YYYY-MM-DD HH:MM` UTC) everywhere.
- **Badges carry fixed meaning across portals:**
  - status GRANTED / issued → `bg-success`
  - PENDING / awaiting → `bg-warning text-dark`
  - DENIED / REVOKED / expired → `bg-secondary` (not danger — a normal outcome)
  - **BREAK-GLASS / emergency → `bg-danger`** (reserved for emergency access only)
- **Buttons carry fixed intent:**
  - primary/confirm → `btn-primary`
  - neutral/secondary → `btn-outline-secondary`
  - destructive (Revoke, Deny) → `btn-outline-danger`
  - all list-row actions → `btn-sm`
- **Empty states are explicit, muted, and inside the section:** a
  `text-muted` line ("No records yet"), never a blank card and never a fake row.
- **Denied / error states use `alert-danger` with a plain-language reason**
  (the specific `*Error` message), and replace the gated content. Never a bare
  HTTP error page, never a silent no-op.
- **"Not wired yet" actions** keep the base.html convention: label the control
  *not wired yet* and let it reach the stub — never fake success.
- **Security boundary is stated, not implied.** The `base.html` dev-shell banner
  stays; no portal page removes or contradicts "identifies users, never decides
  access."
- **Accessibility baseline:** every form control has a `<label>`; every
  icon-only control has `aria-label`; colour is never the only signal (badges
  carry text, not just colour).

## Page → capability → backend map

| Page | P4-7 "Done when" capability | Backend | Buildable now? |
|---|---|---|---|
| Home | see own records | read-only store reads | yes |
| Access grants | see who has access; approve/deny/revoke | consent endpoints exist; **active-grants listing pending review** | mostly |
| Access history | history incl. break-glass | break-glass/denial events exist; **success-read logging pending review** | partially (with caveat) |
| View record | view own record, fail-closed | read endpoint owner branch exists | yes |

## Acceptance criteria (per page)

Each page is "done" when its row holds, from a clean clone. These map to the
P4-7 "Done when" and, where noted, to a P5-1 negative test.

| Page | Passes when | Fails-closed proof |
|---|---|---|
| Home | a patient sees only their own records + accurate counts; empty states show when there is no data | a patient never sees another patient's records |
| Access grants | approve / deny / revoke each round-trip to the service and reflect the returned state | a login with no signed grant grants nothing; no patient private key is ever entered in the UI |
| Access history | history renders reverse-chron with break-glass rows badged; filters work | a patient sees only their own events; the "normal reads not yet logged" caveat shows until that backend merges |
| View record | own record decrypts and streams inline; nothing is persisted or logged | **P5-1 negative test:** a logged-in patient with the owner attribute absent is refused (no plaintext) — portal login alone decrypts nothing (ADR-0016) |

## Non-goals (explicitly not this page set)

- **Upload / ingest** — the record write path is P3-14 (Avaneeth); the shell
  upload form stays a stub here.
- **Drive-style department folders & auto-sorting** — a Phase-5-gated stretch
  goal (`PROJECT.md` §7), not part of P4-7. Do not build it into these pages.
- **Any access decision in the portal** — keys and the threshold gate decide;
  this portal only identifies and displays.

## Open questions for the team

- **Patient signing-key custody (blocks approve/deny/revoke as designed).** A
  `ConsentGrant` and its revocation are only valid when signed by the patient's
  ECDSA private key (`consent.service`), but ADR-0014 says the portal holds no
  keys. The current `/consent/grants/revoke` endpoint takes
  `patient_signing_key_pem` in its body, and `/consent/grants` expects a
  pre-signed grant — so *something* must sign on the patient's behalf without
  the portal touching the key. Options (each with trade-offs, none chosen):
  browser-side signing (key never leaves the client), a patient key held by the
  home authority and a signing endpoint there, or a hardware/other custodian.
  This needs a decision and almost certainly an ADR before Page 2 can be wired;
  the crypto rule forbids inventing a scheme here. **Do not resolve by having
  the portal hold or forward the patient private key.**
- **Uniform cross-portal design is unowned.** Today the only shared surface is
  `base.html`; patient/clinician/admin portals are styled separately by three
  people. If a consistent component set is wanted, it needs an owner and likely
  an ADR (see the design-ownership discussion). This doc styles the patient
  pages within the existing `base.html` only.
- **Success-read logging semantics.** The pending change makes normal reads
  log-before-release (a read that can't be logged returns 503). That choice has
  alternatives and touches a security control — an ADR the module owners ratify
  is likely owed.
