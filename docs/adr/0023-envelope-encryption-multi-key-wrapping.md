# ADR-0023: Envelope Encryption and Multi-Key DEK Lifecycle (P1-4)

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** Powel, Avaneeth, Team
- **Task / source:** P1-4 (WORKFLOW.md); ARCHITECTURE §2 C8, §5; ADR-0011
- **Affects:** `src/records/service.py`, `src/records/exceptions.py`, `src/contracts/records.py`, `tests/records/test_envelope.py`

## Context

Health records vary widely in payload size and must support multiple authorized recipients (e.g., primary care clinician, specialist, emergency break-glass override, patient owner) as well as policy mutations without re-encrypting large multi-megabyte payloads. 

Under ADR-0011, records are stored in a single shared store as encrypted blobs. We needed a decoupled cryptographic lifecycle for the record payload ciphertext versus the record Data Encryption Key (DEK).

## Decision

1. **Per-Record Envelope Encryption**:
   - Each health record payload is encrypted under a unique, freshly generated 256-bit AES-GCM Data Encryption Key (`DEK`).
   - The ciphertext payload includes a 12-byte random IV, AES-GCM ciphertext bytes, and a 16-byte authentication tag with Associated Authenticated Data (`AAD`) binding `record_id`, `patient_id`, `facility_id`, and `policy_id`.

2. **Multi-Key DEK Wrapping & Re-Wrapping Service**:
   - DEKs are never stored in plaintext. They are sealed under one or more Key Encrypting Keys (`KEKs`) using AES-256-GCM key-wrapping, producing `DEKWrapping` contract objects.
   - The `records` service exposes `encrypt_record`, `decrypt_record`, `wrap_dek`, `unwrap_dek`, and `rewrap_dek`.
   - Access policy updates or emergency access provisioning are performed by creating or updating `DEKWrapping` records without reading or modifying the underlying record payload ciphertext.

## Consequences

- Encrypt-once, wrap-many architecture enables $O(1)$ key rotation and policy grant/revocation overhead independent of record payload size.
- Tamper-proofing: Any modification to the payload ciphertext, tag, or bound metadata headers in AAD immediately triggers `InvalidTagError` / `DecryptionError`.
- **Downside**: Managing multiple DEK wrappings requires strict database integrity and foreign key indexing across `records` and `dek_wrappings` tables in storage.

## Alternatives considered

- **Direct Public-Key Encryption of Records**: Encrypting entire records directly under clinician public keys prevents multi-recipient access without multiple payload copies.
- **Dual-Wrapped DEKs in Single Field**: Packing all keys into a single static blob prevents independent revocation and granular emergency additions.

