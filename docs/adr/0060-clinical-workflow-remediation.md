# ADR-0060: Clinical workflow and governance for the disposable demo

Status: Implemented locally; contract changes require team review before merge.

The clinical review exposed gaps in identification, encounters, record provenance,
consent and oversight. The user requested remediation of the remaining findings.

Use the existing signatures, policy trees and threshold scheme. Do not introduce
a new encryption or search construction. Record metadata includes provenance,
clinical date, episode and sensitivity. Ordinary care access requires a signed
patient grant and a physician credential; specialty is not a treating relationship.
Emergency access remains individually audited for every record and viewer.

Clinical justification is committed by digest in the release audit entry, with
the original available to the reviewer. Sensitive records require a distinct
explicit declaration of necessity and mandatory oversight. This is a demo policy,
not an implementation of jurisdiction-specific confidentiality law.

An encounter retains the identified patient across records. Unidentified arrivals
receive a temporary encounter identifier; resolving it requires an explicit,
audited identity confirmation and never guesses or merges historical records.
Guardian and next-of-kin relationships are separate: contact status alone grants
no signing authority (amended by ADR-0061: a verified guardian or parent may
decide consent for a minor). Downtime documentation cannot release encrypted records;
staff use local emergency procedures and reconcile events after audit recovery.

The default clinical window is four hours. Short windows must be requested
explicitly for demonstrations. Each assertion remains short-lived and single-use.
