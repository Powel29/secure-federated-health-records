# ADR-0041: Demo driver and synthetic clinical dataset (P4-5)

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** Nandini (P4-5 owner) → all four for ratification
- **Task / source:** P4-5 (WORKFLOW.md); ARCHITECTURE.md §6, §7; PROJECT.md §5, D2
- **Affects:** `demo/`, `demo/seed_data.py`, `demo/driver.py`, `demo/run_demo.py`,
  `demo/__main__.py`, `tests/demo/test_demo.py`, `pyproject.toml`

## Context

`WORKFLOW.md` Phase 4 Task 5 (P4-5) and `PROJECT.md` Deliverable D2 require:
1. A one-command script that seeds realistic fake patient data and runs the demo scenario with readable output.
2. Zero real patient data, ever (`PROJECT.md` §5 ethical requirement).
3. Clear, informative output demonstrating all four core contributions:
   - Secret-sharing access structure (ADR-0002)
   - Simulated HSM/KMS timer auto-expiry and forced rotation (ADR-0003)
   - Log-before-release share release (ADR-0021, ADR-0034)
   - Ephemeral blind search index and dead-token verification (ADR-0027)

Prior task P4-4 (`deploy/run_scenario.py`) established the technical scenario orchestration across 5 service processes. However, a live demonstration for examiners and paper reviewers requires:
- Realistic, clinically grounded patient profiles (cardiac STEMI with life-saving penicillin allergy, type-2 diabetes, polytrauma).
- An interactive, examiner-ready 8-Act narrative with visual countdown progress, share status indicators, and cryptographic checklist.
- Standalone execution capabilities (`--standalone`) that automatically bind ephemeral OS ports on localhost without port clashes or manual startup.
- Full compliance with `CONVENTIONS.md` §2 rule 3: never log raw key material or shares; output SHA-256 fingerprints, sequence numbers, and state transitions.

## Decision

### 1. Synthetic Clinical Dataset (`demo/seed_data.py`)
Implemented `create_synthetic_dataset()` and `seed_synthetic_data(...)`:
- **Patient 1 (`pat-101`) - Alice Vance (Home: Facility A / Northvale):**
  - Clinical Case: Acute Myocardial Infarction (STEMI), anterolateral wall; cardiogenic shock.
  - Vitals & Labs: HR 112 bpm, BP 85/55 mmHg, Troponin I 4.2 ng/mL.
  - Critical Allergy: Penicillin (Life-threatening anaphylaxis with bronchospasm).
  - Search Tokens: `cardiac`, `infarction`, `aspirin`, `troponin`, `stemi`.
  - Access Policy: `AND(role:physician, specialty:cardiology)` wrapped under ADR-0016 `owner:pat-101` leaf.
- **Patient 2 (`pat-102`) - David Miller (Home: Facility B / Eastbrook):**
  - Clinical Case: Poorly controlled type 2 diabetes mellitus (HbA1c 10.8%).
  - Access Policy: `AND(role:physician, specialty:endocrinology)`.
- **Patient 3 (`pat-103`) - Emma Hartwell (Home: Facility A / Northvale):**
  - Clinical Case: Polytrauma (splenic laceration, closed femur fracture).
  - Access Policy: `AND(role:physician, role:emergency-physician)`.
- **Clinicians:**
  - `doc-201`: Dr. Arjun Rao (Eastbrook Hospital ER, emergency-physician).
  - `doc-301`: Dr. Leela Menon (Northvale General Hospital, cardiology fellow).
  - `doc-202`: Dr. Samuel Okafor (Eastbrook Hospital, endocrinology).
- **Seeding Orchestration:**
  Issues X.509 clinician certificates cross-certified under the federation root anchor, publishes attribute credentials from `authority-med` and `authority-net`, creates ADR-0016 owner leaves, splits 256-bit emergency keys into 3 Shamir shares, and escrows Share 3 at the Standalone Audit Service (`POST /breakglass/shares`).

### 2. Formatted 8-Act Demo Runner (`demo/driver.py`)
Implemented `run_demo_scenario(...)` structured into 8 distinct acts formatted with ANSI color styling and box-drawing borders:
- **Act 1 (Topology & Health):** Confirms all five processes (`facility-a`, `facility-b`, `authority-med`, `authority-net`, `audit`) are healthy across genuine process boundaries.
- **Act 2 (Seeding & Zero-Knowledge Verification):** Validates synthetic data counts, Merkle policy trees with ADR-0016 owner leaves, blind search token derivations, and Share 3 audit escrow.
- **Act 3 (Blind Cross-Hospital Discovery):** Locates Alice's remote record via federated discovery without revealing record content.
- **Act 4 (Policy Denial):** Proves Dr. Rao's routine read attempt is rejected with HTTP 403 Forbidden because emergency credentials fail the cardiology policy.
- **Act 5 (Break-Glass & Shamir Reconstruction):** Dr. Rao signs an `EmergencyAssertion`. Audit Service logs the release entry before returning Share 3 (log-before-release). 2-of-3 threshold is met, DEK is re-wrapped via ElGamal PRE, decapsulated, and the record is decrypted, revealing the critical penicillin allergy and saving the patient.
- **Act 6 (Visual Countdown & Dead Token Verification):** Renders a live terminal progress bar for the emergency time-box window. Upon expiry, the HSM/KMS timer monitor forces DEK rotation and zeroizes the emergency session key. Subsequent emergency search returns HTTP 403 Forbidden ("Emergency search unavailable"), proving search tokens are dead.
- **Act 7 (Audit Hash Chain Verification):** Validates cryptographic hash continuity (`h_i = SHA-256(h_{i-1} ‖ event ‖ time ‖ actor)`) from genesis to chain head.
- **Act 8 (Examiners' Checklist):** Displays a verification matrix confirming ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0016, ADR-0021, ADR-0022, ADR-0027, and zero real PHI.

### 3. Unified Terminal CLI (`python -m demo`)
Created `demo/__main__.py` and `demo/run_demo.py` exposing:
- `--duration <float>`: Emergency window in seconds (default: 3.0s).
- `--standalone`: Runs complete 8-act demonstration locally across ephemeral in-process OS sockets.
- `--seed-only`: Seeds data and exits.
- `--skip-seed`: Runs demo against existing database data.
- `--step`: Interactive mode awaiting Enter between acts for live presentations.
- `--no-color`: Monochromatic output mode.

## Consequences

- **Deliverable D2 Complete:** The project can be demonstrated to examiners and evaluators from a clean clone with a single terminal command (`python -m demo`).
- **Ethical Integrity:** 100% synthetic clinical data; zero real PHI exists in the repository.
- **Cryptographic Transparency:** Output displays cryptographic proofs, fingerprints (`sha256:...`), and state machine transitions while strictly guarding raw secret keys.
