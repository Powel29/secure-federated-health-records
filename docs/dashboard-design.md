# Dashboard page design — T55

Build spec for the four-pane observability dashboard. Component summary and
constraints are in `ARCHITECTURE.md` §2 (C16); this is the layout and behaviour
detail. Owner: Powel. Lives in `demo/dashboard.py`.

**What this is:** a read-only window onto the federation, shown beside the
scripted CLI during the demo. It renders state; it never causes it.

---

## 1. Grid

Textual `Grid`, 2×2 with a full-width footer. Minimum terminal 100×32; below
that, print a message and exit rather than degrading into unreadable wrapping.

```
┌───────────────────────────┬───────────────────────────┐
│  PATIENT                  │  CLINICIAN                │   each 50% × 40%
├───────────────────────────┼───────────────────────────┤
│  AUTHORITY                │  AUDIT SERVICE            │   each 50% × 40%
├───────────────────────────┴───────────────────────────┤
│  AUDIT CHAIN                                          │   100% × 20%
└───────────────────────────────────────────────────────┘
```

Top row is the two human-facing actors — the patient who owns the data and the
clinician who wants it. Bottom row is the two machine actors that hold shares.
The chain runs underneath all four because it is what they all write into.

---

## 2. Panes

### 2.1 Patient — "access travels with the patient"

```
┌─ PATIENT  p-0142 ─────────────────────────────────────┐
│                                                       │
│  RECORD   STATE            HELD AT      SINCE         │
│  rec-7    EMERGENCY-OPEN   fac-a        12:04:09      │
│  rec-2    GRANTED          fac-a        03-11         │
│  rec-9    REVOKED          fac-a        12:04:11      │
│                                                       │
│  ── who opened rec-7 ───────────────────────────────  │
│  dr-nayar @ fac-b   (out-of-network)                  │
│  reason  UNCONSCIOUS_PATIENT                          │
│  opened  12:04:09      expires  12:05:09              │
│                                                       │
└───────────────────────────────────────────────────────┘
```

Query: `lifecycle_state` and `audit_log`, both `WHERE patient_id = ?`.

The access-history block is the pane's reason for existing. It answers the
question an examiner will ask — *"so the out-of-network doctor just took the
data?"* — with: no, and here is the patient's own view of who took it, why, and
when their access dies.

### 2.2 Clinician — "no per-doctor pre-provisioning"

```
┌─ CLINICIAN  dr-nayar @ fac-b ─────────────────────────┐
│                                                       │
│  cert   fac-a CA ✓   cross-cert ✓   valid to 2027-01  │
│  attrs  role:emergency-physician  (auth-med)          │
│                                                       │
│  ── access ─────────────────────────────────────────  │
│  rec-7    OPEN              ⏱  00:47                  │
│  search   ENABLED           (emergency key)           │
│                                                       │
│  ── denied ─────────────────────────────────────────  │
│  p-0088   policy unsatisfied                          │
│  p-0031   revoked 12:04:11                            │
│                                                       │
└───────────────────────────────────────────────────────┘
```

Query: `lifecycle_state` joined to `dek_wrappings` reachable by this clinician's
attribute set; denials from `audit_log WHERE event = 'ACCESS_DENIED' AND actor = ?`.

Three things earn their space. The **certificate line** makes cross-certification
concrete — this clinician was never provisioned at fac-a and still validates.
The **countdown** is the single most legible element on the screen. The **denial
list** is where negative evidence becomes visible; without it, a control working
correctly looks identical to nothing happening.

Depends on T56 (`ACCESS_DENIED` events). Without T56 this section is empty.

### 2.3 Authority — "federated issuance, and it still can't open a record"

```
┌─ AUTHORITY  auth-med ─────────────────────────────────┐
│                                                       │
│  credentials   14 issued                              │
│                12 active   1 expired   1 revoked      │
│                                                       │
│  ── share requests ─────────────────────────────────  │
│  12:04:09  rec-7   RELEASED   (share 2 of 3)          │
│            requester  fac-b / dr-nayar                │
│                                                       │
│  cannot open records alone                            │
│                                                       │
└───────────────────────────────────────────────────────┘
```

Query: `attributes`/`authorities` grouped by status; `audit_log WHERE actor = 'auth-med'`.

The credential status counts are the only place T52's credential lifecycle
becomes visible in the demo — otherwise that work is invisible to an examiner.

### 2.4 Audit service — the headline

```
┌─ AUDIT SERVICE ───────────────────────────────────────┐
│                                                       │
│  chain height  218          status  VERIFIED          │
│  head  4f2a9c7b…                                      │
│                                                       │
│  ── share request  rec-7 ───────────────────────────  │
│  1  log entry committed   → 4f2a9c7b…   ✓             │
│  2  share released        (share 3 of 3)              │
│                                                       │
│  cannot open records alone                            │
│                                                       │
└───────────────────────────────────────────────────────┘
```

The numbered two-step is the entire contribution rendered in six lines. Commit
first, release second, and the release line names the hash it waited on. Never
collapse these into one line, and never render them in the other order even if
they share a timestamp — order the query by chain height, not by clock, since
two events in the same second are otherwise ambiguous.

### 2.5 Audit chain footer

```
┌─ AUDIT CHAIN ─────────────────────────────────────────┐
│ 218  12:04:09  STATE  GRANTED → EMERGENCY-OPEN  ✓     │
│ 217  12:04:09  SHARE_RELEASED     audit-svc  4f2a…    │
│ 216  12:04:09  SHARE_RELEASED     auth-med   c93b…    │
│ 215  12:04:09  BREAK_GLASS_ASSERTED  dr-nayar  a71e…  │
└───────────────────────────────────────────────────────┘
```

Newest first, last 6 entries, `ORDER BY height DESC`. The pane above shows the
audit service *as an actor*; this strip shows the chain as shared ground truth.
Keep them distinct — conflating them blurs what the gate actually does.

---

## 3. States the layout must handle

**Baseline.** rec-7 GRANTED, clinician pane shows no access, no countdown.

**Break-glass in progress.** Shares appear one at a time as their audit events
land. The gap between the authority share and the audit share is where the
examiner's attention should be — do not batch-render them.

**Emergency-open.** Countdown live. Search shows ENABLED. State flips in both
the patient and clinician panes simultaneously, because both read the same row.

**Expired.** Countdown reaches `00:00` → state EXPIRED → a forced-rotation entry
appears in the chain → search flips to DISABLED. No operator touched anything,
and the screen shows that.

**Denied.** A denial appears in the clinician pane and in the chain footer.

---

## 4. Visual rules

| Element | Style |
|---|---|
| `EMERGENCY-OPEN` | bold amber |
| `GRANTED` | green |
| `REVOKED`, `EXPIRED` | dim |
| Denials | red |
| Countdown > 30s | white; ≤ 30s amber; ≤ 10s bold red |
| `VERIFIED` / chain failure | green / bold red |
| Hashes | dim, truncated to 8 chars + `…` |

Truncate hashes but never invent or pad them. If the chain fails verification,
that is the loudest thing on the screen — full width, red, above everything.

---

## 5. Mechanics

- One read-only connection per service DB: `file:…?mode=ro` with `uri=True`.
  Driver-enforced, so read-only is a property rather than a promise.
- Poll every 250ms. **Query into a dataclass first, then render the dataclass** —
  querying inside the render call is what produces flicker when a service writes
  mid-frame.
- Each pane's query takes its actor identity and builds the `WHERE` clause from
  it. Scoping happens in SQL, never by filtering a global result set.
- A pane whose service is unreachable renders `— unavailable —` and the rest of
  the dashboard keeps running.
- No imports from `crypto_core`. One test asserts this, so the "even the
  monitor cannot decrypt" claim is enforced rather than asserted.

---

## 6. Tests

- Each pane's query returns only rows for its actor — the patient pane given
  `p-0142` must never return a `p-0088` row.
- No `crypto_core` import anywhere under `demo/`.
- A write attempt through a dashboard connection raises.
- Countdown reaches zero and the rendered state becomes EXPIRED without any
  operator input.

---

## 7. Out of scope

No buttons, no key handling beyond quit, no forms, no mutation, no web
front-end. The moment a pane can trigger a revocation this stops being
observability and becomes a clinical application — with input validation,
session state, and the browser security surface that `PROJECT.md` §4B
deliberately rejected.
