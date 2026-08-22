---
name: negative-security-test
description: How to write adversarial security tests that prove a control actually fails closed, for this federated EHR project. Use this skill whenever writing or reviewing tests under tests/security/, whenever a task mentions proving, verifying, demonstrating, or evidencing a security property, and whenever implementing any access control, revocation, threshold gate, audit, expiry, replay, or authorization mechanism — a control without its negative test is not finished.
---

# Writing negative security tests

In this project the tests are not quality assurance — they are the **evidence
base for the paper's claims**. Every security property asserted in the write-up
must trace to a test that would fail if the property did not hold. A claim
without such a test is an assertion, and an examiner is entitled to treat it as
one.

## The core distinction

A positive test shows the system works when used correctly. A negative test
shows the system *refuses* when attacked. Models and humans both default to
positive tests, because they're easier to imagine and they pass sooner.

```
Positive:  authorised clinician decrypts the record            -> weak evidence
Negative:  revoked clinician cannot decrypt after re-wrap      -> the claim
```

The positive test would still pass if you deleted the entire access control
layer. That is why it proves little on its own.

## The test that must pass to call a control finished

For any control, the shape is: **disable or subvert the control, then assert the
operation fails.**

The canonical example for this project — and the one that backs the headline
contribution — is the audit gate:

```
Disable the audit service's ability to commit its log entry.
Attempt break-glass.
Assert: no share is released, no emergency key is reconstructed,
        the record does not open.
```

If break-glass still succeeds with logging broken, then
"logging is a cryptographic precondition" is false, and it is the central claim
of the project. This test is worth more than the rest of the suite combined.

## Required suite

`CONVENTIONS.md` §5 lists the ten tests that are phase exit criteria. Each maps
to a specific claim:

| Test | Claim it backs |
|---|---|
| Revoked user cannot decrypt after re-wrap | Revocation is cryptographic, not policy |
| Break-glass fails when audit cannot commit | Logging is a precondition of access |
| One share — including audit's — cannot open a record | No single party holds unilateral power |
| Search token dead after emergency expiry | Search capability is time-boxed |
| Tampered audit entry detected by chain verification | The log is tamper-evident |
| Illegal state transition rejected | The state machine is enforced |
| Transition event with bad signature rejected | Transitions are non-repudiable |
| Replayed emergency assertion rejected | Time-boxing cannot be defeated by replay |
| Authenticated-but-unauthorised caller denied (BOLA) | Endpoint authz is independent of crypto |
| Expired or revoked credential fails validation | Credentials have a lifecycle |

## How to write one

**Name it for the behaviour, not the mechanism.** `test_revoked_user_cannot_decrypt_after_rewrap`, not `test_revocation_3`. The name should read as the claim.

**Assert the specific failure, not merely that something raised.** A test that
accepts any exception will pass when the code fails for an unrelated reason —
a typo, a missing fixture, a connection error. Assert the exception type and,
where it matters, that no partial artifact was produced: no key material
returned, no state transition recorded, no log entry written.

**Prove the setup was valid.** Before asserting that the attack fails, assert
that the same operation *succeeds* under legitimate conditions in the same
fixture. Otherwise a test can pass because the setup was broken rather than
because the control worked. This is the most common way a negative test becomes
worthless.

**Reference the claim in a docstring.** One line naming which paper claim the
test backs. When writing the security analysis section, this is what makes the
mapping from claim to evidence mechanical rather than archaeological.

## The check to run against your own test

Ask: *if I deleted the control this test targets, would this test fail?*

If the answer is no, the test is decorative. Delete it or rewrite it. It is
worth literally trying this — comment out the control, run the test, confirm it
goes red, restore the control. A test never observed failing is a test not known
to work.

## What not to do

Do not weaken a test to make it pass. If a negative test fails, the control is
broken or the design is wrong, and both are findings worth having early. A
surprising failure here usually indicates a design problem wearing a test's
clothing — escalate it rather than adjusting the assertion.

Do not use real patient data, ever. Synthetic fixtures only.
