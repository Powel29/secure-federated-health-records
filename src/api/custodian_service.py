"""Key Custodian Service (ADR-0043, C14) -- the subject's key agent.

The three web portals (C16) identify users and display data; they hold no keys
and decide no access (ADR-0014/0021). But every action the portals must offer
-- a patient signing a consent decision, a patient reading their own record via
the ``owner:<patient_id>`` leaf, a clinician reading under consent, a clinician
signing an ``EmergencyAssertion`` and presenting threshold shares -- needs a
private key or a share on the caller's side of the wire. This service is where
that material lives instead: **one process standing in for every subject's
personal key agent** (a smartcard, an enclave, a browser keystore in a real
deployment). It:

- holds each subject's ECDSA signing key, certificate, PRE keypair and the
  credentials an authority issued them, deposited once at seed time the same
  way the audit service is handed share 3;
- signs on a subject's behalf (consent requests/decisions/revocations,
  emergency assertions) and returns the *signed public artifact* -- never a key;
- performs the key-bearing federation calls a subject would perform themself
  (attribute-key release at the authorities, ``/records/{id}/read``,
  ``/breakglass/release`` at the audit service, ``/records/{id}/breakglass``
  at a facility) and returns only the outcome.

What it does **not** do is decide access. A read still goes through the
facility's policy engine; a break-glass still needs the audit service's
committed log entry before share 3 exists; a consent grant is still verified
by the facility against the patient's public key. A portal login whose subject
has no material here gets ``404`` and nothing decrypts -- that is ADR-0021's
"a portal account alone grants zero access", made concrete.

Invariants:
- CONVENTIONS.md §2 rule 10: no cryptography in route handlers. Signing is
  ``consent.service`` / ``breakglass.assertion``; PRE delivery decode is
  ``pre.delivery``; record decryption is ``records.service``.
- No private key is ever returned by any endpoint (only public keys,
  certificates and credential *summaries*).
- Every federation endpoint this service calls comes from its configuration
  (CONVENTIONS.md §2 rule 8), never from request data -- a request names a
  ``facility_id``, and the allowlist maps it to a URL.
- Every call it makes is signed as the custodian's service identity, and every
  call it takes must be signed by a service whose kind the route allows
  (ADR-0066): the portals, bootstrap, and a facility replacing share 1 after
  a rotation.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import logging
import threading
from dataclasses import dataclass, field
from typing import Annotated, Any, Callable
from uuid import uuid4

import httpx
from audit.chain import verify_entry_signature
from breakglass.assertion import clinical_context_digest
from breakglass.emergency_key import Share
from breakglass.exceptions import SealedShareError
from breakglass.share_sealing import (
    SealedShare,
    ShareKeyStatement,
    ShareRecipient,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
    verify_key_statement,
)
from consent.service import (
    create_consent_grant,
    create_consent_request,
    revoke_consent_grant,
)
from contracts import AttributeCredential, AuditEntry, Record, TransitionEvent
from contracts.enums import ConsentStatus, LifecycleState, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import (
    certificate_from_pem,
    private_key_from_pem,
    public_key_from_pem,
    public_key_to_pem,
)
from crypto_core.exceptions import CryptoError, InvalidTagError, KeyFormatError
from crypto_core.types import ECPrivateKey
from cryptography.x509 import Certificate
from custodian import (
    decrypt_delivered_record,
    justification_digest,
    open_delivered_dek,
    prepare_unlock,
    provision_emergency_key,
    sign_emergency_transition,
    sign_revocation_transition,
)
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pre.exceptions import PREError
from pydantic import ValidationError
from records.exceptions import DecryptionError
from records.labels import LabelTrust, disclosure_rules, sign_clinical_labels

from api.custodian_schemas import (
    BreakglassPayload,
    BreakglassResult,
    CredentialSummary,
    DecideConsentPayload,
    DepositMaterialRequest,
    DepositMaterialResponse,
    DepositShareRequest,
    DepositShareResponse,
    ErrorResponse,
    HealthResponse,
    IngestPayload,
    IngestResult,
    PublicKeyResponse,
    ReadRecordPayload,
    ReadRecordResult,
    ReplaceShareRequest,
    RevokeConsentPayload,
    RevokeRecordPayload,
    RevokeRecordResult,
    SharePresented,
    SignConsentRequestPayload,
    SignConsentRequestResponse,
    SignedGrantResponse,
    SubjectSummary,
    TrustMaterialRequest,
)
from api.service_auth import (
    ServiceAuthConfig,
    ServiceIdentity,
    SignedRequestAuth,
    install_service_auth,
)
from api.share_transport import SHARE_KEY_PATH, sealed_json, serve_share_key

_logger = logging.getLogger(__name__)

AUDIT_SERVICE_ID = "audit-service"

# Which kinds of federation service may call each route (ADR-0066).
_PORTAL = frozenset({"portal", "bootstrap"})
CUSTODIAN_PERMISSIONS: dict[tuple[str, str], frozenset[str]] = {
    ("PUT", "/trust"): frozenset({"bootstrap"}),
    ("POST", "/subjects/{subject_id}/material"): frozenset({"bootstrap"}),
    ("POST", "/records/{record_id}/shares"): frozenset({"bootstrap"}),
    ("PUT", "/records/{record_id}/shares"): frozenset({"facility"}),
    ("GET", "/subjects/{subject_id}"): _PORTAL,
    ("GET", "/subjects/{subject_id}/public-key"): _PORTAL | {"facility"},
    ("POST", "/subjects/{subject_id}/consent/request"): _PORTAL,
    ("POST", "/subjects/{subject_id}/consent/decide"): _PORTAL,
    ("POST", "/subjects/{subject_id}/consent/revoke"): _PORTAL,
    ("POST", "/subjects/{subject_id}/read"): _PORTAL,
    ("POST", "/subjects/{subject_id}/revoke"): _PORTAL,
    ("POST", "/subjects/{subject_id}/records"): _PORTAL,
    ("POST", "/subjects/{subject_id}/breakglass"): _PORTAL,
}
CUSTODIAN_PUBLIC_ROUTES = frozenset({("GET", "/health")})

DEFAULT_TIMEOUT_SECONDS = 10.0

SHARE_HOLDER_CLINICIAN = "clinician"
SHARE_HOLDER_AUDIT = "audit-service"
SHARE_HOLDER_HOME_AUTHORITY = "home-authority"

RecordLoader = Callable[[str], Record | None]
# The record's lifecycle state in the shared store (ADR-0069).
StateLoader = Callable[[str], LifecycleState | None]


# --- In-memory vault ---------------------------------------------------------


@dataclass
class SubjectMaterial:
    """One subject's private material. Never serialised back out."""

    subject_id: str
    kind: str
    display_name: str
    signing_key: ECPrivateKey
    facility_id: str | None = None
    certificate_pem: str | None = None
    pre_private_key: int | None = None
    pre_public_key: int | None = None
    credentials: list[AttributeCredential] = field(default_factory=list)


@dataclass
class CustodianEndpoints:
    """Config allowlist of every federation endpoint this service may call."""

    authorities: dict[str, str] = field(default_factory=dict)
    facilities: dict[str, str] = field(default_factory=dict)
    audit: str | None = None


class CustodianVault:
    """Thread-safe registry of subject material, trust anchors and share 1s.

    Residual risk (ADR-0043, carried to the paper's limitations): every subject's
    private key lives here in process memory for the custodian's whole lifetime.
    There is no eviction and no zeroization -- Python cannot reliably wipe an
    immutable key object, and this one process deliberately stands in for what a
    real deployment would split across each subject's own device (smartcard /
    enclave / browser keystore). A memory dump of this process yields every
    deposited key at once. This does not weaken the threshold or logging
    properties (share 3 is still committed-before-released by the audit service,
    the policy engine still gates reads), but it is the demo's single largest
    trust concentration and must be stated as such, not hidden.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subjects: dict[str, SubjectMaterial] = {}
        self._shares: dict[str, tuple[int, bytes]] = {}
        # Emergency-key generation of each share 1: 0 at ingest, +1 per
        # rotation at expiry (ADR-0069).
        self._share_generations: dict[str, int] = {}
        self.root_certificate_pem: str | None = None
        self.facility_ca_certificate_pems: dict[str, str] = {}
        self.audit_public_key_pem: str | None = None
        # Highest audit seq seen on a release; a lower one means the chain was
        # truncated or replayed (review F31).
        self.last_audit_seq = -1

    def put_subject(self, material: SubjectMaterial) -> None:
        with self._lock:
            self._subjects[material.subject_id] = material

    def get_subject(self, subject_id: str) -> SubjectMaterial | None:
        with self._lock:
            return self._subjects.get(subject_id)

    def put_share(self, record_id: str, share: tuple[int, bytes]) -> None:
        """Hold share 1 for a record; never replace one already held (F4).

        Raises:
            ValueError: A share is already held for ``record_id``.
        """
        with self._lock:
            if record_id in self._shares:
                raise ValueError(f"a share is already held for {record_id!r}")
            self._shares[record_id] = share
            self._share_generations[record_id] = 0

    def replace_share(
        self, record_id: str, share: tuple[int, bytes], generation: int
    ) -> None:
        """Take the next generation's share 1 (ADR-0069); a retry is a no-op.

        Raises:
            KeyError: No share is held for ``record_id``.
            ValueError: ``generation`` is not the held generation + 1 (or the
                same generation with a different share).
        """
        with self._lock:
            current = self._shares.get(record_id)
            if current is None:
                raise KeyError(f"no share held for {record_id!r}")
            held = self._share_generations[record_id]
            if generation == held and current == share:
                return
            if generation != held + 1:
                raise ValueError(
                    f"share for {record_id!r} is at generation {held}; "
                    f"refusing generation {generation}"
                )
            self._shares[record_id] = share
            self._share_generations[record_id] = generation

    def get_share(self, record_id: str) -> tuple[int, bytes] | None:
        with self._lock:
            return self._shares.get(record_id)

    def drop_share(self, record_id: str, share: tuple[int, bytes]) -> None:
        """Release share 1 for a record whose upload failed; only if it is ``share``."""
        with self._lock:
            if self._shares.get(record_id) == share:
                del self._shares[record_id]
                self._share_generations.pop(record_id, None)

    def set_trust(
        self,
        root_pem: str,
        facility_ca_pems: dict[str, str],
        audit_public_key_pem: str | None = None,
    ) -> None:
        with self._lock:
            self.root_certificate_pem = root_pem
            self.facility_ca_certificate_pems = dict(facility_ca_pems)
            if audit_public_key_pem is not None:
                self.audit_public_key_pem = audit_public_key_pem

    def audit_seq_before_release(self) -> int:
        """The highest release seq seen before a new release is requested."""
        with self._lock:
            return self.last_audit_seq

    def advance_audit_seq(self, seq: int, before: int) -> None:
        """Record a release entry's seq; refuse one that goes backwards (F31).

        Every release seen before this one was requested was committed first,
        so ``seq`` must be after ``before``. Concurrent break-glasses may finish
        out of order, so later releases do not count against it.

        Raises:
            ValueError: ``seq`` is not higher than ``before``.
        """
        with self._lock:
            if seq <= before:
                raise ValueError(
                    f"audit entry seq {seq} is not after the last seen "
                    f"{before}: the chain was truncated or replayed"
                )
            self.last_audit_seq = max(seq, self.last_audit_seq)

    def __len__(self) -> int:
        with self._lock:
            return len(self._subjects)


# --- Dependencies ------------------------------------------------------------


def get_vault(request: Request) -> CustodianVault:
    return request.app.state.vault


def get_endpoints(request: Request) -> CustodianEndpoints:
    return request.app.state.endpoints


def get_http(request: Request) -> httpx.Client:
    return request.app.state.http


VaultDep = Annotated[CustodianVault, Depends(get_vault)]
EndpointsDep = Annotated[CustodianEndpoints, Depends(get_endpoints)]
HttpDep = Annotated[httpx.Client, Depends(get_http)]


def _require_subject(vault: CustodianVault, subject_id: str) -> SubjectMaterial:
    """Fail closed: a subject with no deposited material can do nothing."""
    material = vault.get_subject(subject_id)
    if material is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"no key material held for subject {subject_id!r}; a portal "
                "login alone grants nothing (ADR-0021)"
            ),
        )
    return material


def _require_kind(material: SubjectMaterial, kind: str) -> None:
    if material.kind != kind:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"subject {material.subject_id!r} is a {material.kind}, not a {kind}"
            ),
        )


def _facility_url(endpoints: CustodianEndpoints, facility_id: str) -> str:
    url = endpoints.facilities.get(facility_id)
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"facility {facility_id!r} is not in this custodian's allowlist",
        )
    return url


def _raise_upstream(resp: httpx.Response, *, what: str) -> None:
    """Translate an upstream refusal into this service's response, verbatim.

    A facility's 403 (policy/consent denial) stays a 403 -- the portal must
    show the specific reason, not a generic failure. Anything else upstream
    becomes a 502 so a portal never mistakes an outage for a denial.
    """
    try:
        body: Any = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    detail = body.get("detail", resp.text) if isinstance(body, dict) else resp.text
    if resp.status_code in (400, 403, 404, 409, 503):
        raise HTTPException(status_code=resp.status_code, detail=f"{what}: {detail}")
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"{what} failed upstream ({resp.status_code}): {detail}",
    )


def _patient_certificate(material: SubjectMaterial) -> str:
    """The patient's certificate, which a facility verifies their signature by.

    Raises:
        HTTPException: 403 if the patient holds none -- a signature nobody can
            verify is worthless (ADR-0064).
    """
    if not material.certificate_pem:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="patient holds no certificate; their signature cannot be verified",
        )
    return material.certificate_pem


def _label_trust(vault: CustodianVault) -> LabelTrust | None:
    """The vault's trust anchors, to judge a record's labels as a facility does."""
    if not vault.root_certificate_pem:
        return None
    return LabelTrust(
        facility_cas={
            fid: certificate_from_pem(pem.encode("ascii"))
            for fid, pem in vault.facility_ca_certificate_pems.items()
        },
        trusted_root=certificate_from_pem(vault.root_certificate_pem.encode("ascii")),
    )


def _check_release_entry(
    vault: CustodianVault,
    raw_entry: dict[str, Any],
    correlation_id: str,
    seq_before: int,
) -> None:
    """Fail closed unless the audit service really signed this release (F31).

    The share is only worth presenting if its release was logged: the entry
    must carry the audit service's signature, belong to this flow, and come
    after every entry seen before (a lower seq means a truncated chain).
    """
    if vault.audit_public_key_pem is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="audit service key not configured; cannot check the release",
        )
    try:
        entry = AuditEntry.model_validate(raw_entry)
        verify_entry_signature(
            entry, public_key_from_pem(vault.audit_public_key_pem.encode("ascii"))
        )
        if entry.correlation_id != correlation_id:
            raise ValueError("release entry belongs to another flow")
        vault.advance_audit_seq(entry.seq, seq_before)
    except (ValidationError, CryptoError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"audit share release did not verify: {exc}",
        ) from exc


def _post(
    http: httpx.Client, url: str, json: dict[str, Any], *, what: str
) -> dict[str, Any]:
    try:
        resp = http.post(url, json=json)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{what}: could not reach {url}: {exc}",
        ) from exc
    if resp.status_code >= 400:
        _raise_upstream(resp, what=what)
    return resp.json()


def _get(http: httpx.Client, url: str, *, what: str) -> dict[str, Any]:
    try:
        resp = http.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{what}: could not reach {url}: {exc}",
        ) from exc
    if resp.status_code >= 400:
        _raise_upstream(resp, what=what)
    return resp.json()


def _holder_keyring(
    http: httpx.Client,
    endpoints: CustodianEndpoints,
    material: SubjectMaterial,
) -> tuple[dict[str, str], list[str]]:
    """Exchange each held credential for its attribute key at the issuer.

    A credential the issuing authority genuinely *refuses* (4xx: expired,
    revoked, or unknown) is simply not presented -- the facility's policy engine
    then decides with whatever remains, and denies if that is not enough.

    An authority *outage*, by contrast, is not a refusal and must not be
    silently dropped: if it were, a missing key would surface downstream as a
    generic policy denial and a legitimately-authorised clinician would be told
    they lack access when the authority was merely unreachable. So a transport
    failure or a 5xx raises a distinguishable 502 here, failing closed with a
    cause an operator (and the portal) can tell apart from a real denial.
    """
    keyring: dict[str, str] = {}
    presented: list[str] = []
    for cred in material.credentials:
        authority_url = endpoints.authorities.get(cred.issuer_id)
        label = f"{cred.issuer_id}:{cred.attribute.name}:{cred.attribute.value}"
        if not authority_url:
            # A credential from an authority this custodian does not federate
            # with cannot be exchanged. This is static misconfiguration, not a
            # transient outage: log it and skip (the policy engine denies if the
            # leaf was required); an operator sees the warning.
            _logger.warning(
                "no endpoint for issuer %s; skipping %s", cred.issuer_id, label
            )
            continue
        try:
            resp = http.post(
                f"{authority_url}/attribute-keys/release",
                json={"credential": cred.model_dump(mode="json")},
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"attribute authority {cred.issuer_id!r} unavailable while "
                    f"releasing {label}: {exc} (not a policy denial)"
                ),
            ) from exc
        if resp.status_code >= 500:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"attribute authority {cred.issuer_id!r} errored "
                    f"({resp.status_code}) releasing {label} (not a policy denial)"
                ),
            )
        if resp.status_code != 200:
            _logger.info(
                "authority refused %s (%s): %s", label, resp.status_code, resp.text
            )
            continue
        keyring[label] = resp.json()["key_b64"]
        presented.append(label)
    return keyring, presented


def _policy_leaves(tree: PolicyTree) -> list[tuple[str, str, str]]:
    """Every ``(authority_id, name, value)`` leaf a policy tree references."""
    if tree.node_type is PolicyNodeType.LEAF:
        if tree.attribute is None or tree.authority_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="malformed policy leaf"
            )
        return [(tree.authority_id, tree.attribute.name, tree.attribute.value)]
    leaves: list[tuple[str, str, str]] = []
    for child in tree.children:
        leaves.extend(_policy_leaves(child))
    return leaves


def _authoring_keyring(
    http: httpx.Client,
    endpoints: CustodianEndpoints,
    leaves: list[tuple[str, str, str]],
) -> dict[str, str]:
    """Mint/fetch the authoring-side key for each leaf at its owning authority.

    ``/attribute-keys/author`` is the same path ``demo/seed_data.py`` and
    ``deploy/run_scenario.py`` use to seal leaves at ingest; its access
    limitation is documented on the authority service itself.
    """
    keyring: dict[str, str] = {}
    for authority_id, name, value in leaves:
        label = f"{authority_id}:{name}:{value}"
        if label in keyring:
            continue
        authority_url = endpoints.authorities.get(authority_id)
        if not authority_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"policy references unknown authority {authority_id!r}",
            )
        data = _post(
            http,
            f"{authority_url}/attribute-keys/author",
            {"name": name, "value": value},
            what=f"authoring key for {label}",
        )
        keyring[label] = data["key_b64"]
    return keyring


# --- App factory -------------------------------------------------------------


def create_custodian_app(
    *,
    endpoints: CustodianEndpoints | None = None,
    vault: CustodianVault | None = None,
    record_loader: RecordLoader | None = None,
    http_client: httpx.Client | None = None,
    root_certificate_pem: str | None = None,
    facility_ca_certificate_pems: dict[str, str] | None = None,
    audit_public_key_pem: str | None = None,
    identity: ServiceIdentity,
    service_root: Certificate,
    state_loader: StateLoader | None = None,
    share_key: ShareSealingKey | None = None,
) -> FastAPI:
    """Create and configure the Key Custodian Service application.

    Args:
        endpoints: The allowlist of authority / facility / audit URLs this
            service may call. Everything is resolved from here, never from a
            request body (CONVENTIONS.md §2 rule 8).
        vault: Pre-populated vault (tests); a fresh empty one otherwise.
        record_loader: Returns the ciphertext ``Record`` for a ``record_id``
            so a break-glass result can include the decrypted payload. In
            deployment this is ``storage.repositories.get_record`` bound to a
            store connection; ``None`` means break-glass reports the recovered
            DEK only and ``plaintext_b64`` is omitted.
        http_client: Injected client (tests); a default one otherwise.
        root_certificate_pem: Optional trust anchor; may also be set later via
            ``PUT /trust``.
        facility_ca_certificate_pems: Optional per-facility CA certificates.
        audit_public_key_pem: The audit service's public key; may also be set
            later via ``PUT /trust``. Break-glass refuses until it is known.
        identity: The custodian's service identity; every call it makes is
            signed with it (ADR-0066).
        service_root: The federation root callers' service certificates must
            chain to.
        state_loader: Reads a record's lifecycle state from the shared store.
            A facility may replace share 1 only while the record is
            ``expired`` there (ADR-0069); without a loader it may not at all.
    """
    app = FastAPI(
        title="Key Custodian Service",
        description=(
            "Federated Break-Glass EHR -- per-subject key agent standing in for "
            "every persona's smartcard/enclave (ADR-0043). Holds keys, signs on "
            "request, decides nothing."
        ),
        version="1.0.0",
    )
    app.state.vault = vault or CustodianVault()
    app.state.endpoints = endpoints or CustodianEndpoints()
    app.state.http = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
    # Sign every outgoing call; a URL outside the allowlist is never sent.
    configured = app.state.endpoints
    app.state.http.auth = SignedRequestAuth(
        identity,
        {
            **{url: aid for aid, url in configured.authorities.items()},
            **{url: fid for fid, url in configured.facilities.items()},
            **({configured.audit: AUDIT_SERVICE_ID} if configured.audit else {}),
        },
    )
    app.state.record_loader = record_loader
    # Shares reach this service sealed to this key (ADR-0079).
    sealing_key = share_key or ShareSealingKey.generate()

    def open_share(record_id: str, sealed: SealedShare) -> Share:
        try:
            return open_sealed_share(
                sealed,
                record_id=record_id,
                service_id=identity.service_id,
                key=sealing_key,
            )
        except SealedShareError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc

    def share_key_of(
        http: httpx.Client, base_url: str, kind: str
    ) -> tuple[dict[str, Any], ShareRecipient]:
        """A holder's or facility's share-key statement, verified (ADR-0079)."""
        statement = _get(http, f"{base_url}{SHARE_KEY_PATH}", what=f"{kind} share key")
        try:
            recipient = verify_key_statement(
                ShareKeyStatement.model_validate(statement),
                trusted_root=service_root,
                kind=kind,
            )
        except (ValidationError, SealedShareError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"{kind} share key did not verify: {exc}",
            ) from exc
        return statement, recipient

    if root_certificate_pem:
        app.state.vault.set_trust(
            root_certificate_pem,
            facility_ca_certificate_pems or {},
            audit_public_key_pem,
        )

    # --- Health ------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    def health_check(vault: VaultDep) -> HealthResponse:
        return HealthResponse(subjects=len(vault))

    # --- Bootstrap deposits -------------------------------------------------

    @app.put("/trust", response_model=TrustMaterialRequest)
    def set_trust(
        payload: TrustMaterialRequest, vault: VaultDep
    ) -> TrustMaterialRequest:
        """Register the federation root and facility CA certificates (public)."""
        vault.set_trust(
            payload.root_certificate_pem,
            payload.facility_ca_certificate_pems,
            payload.audit_public_key_pem,
        )
        return payload

    @app.post(
        "/subjects/{subject_id}/material",
        response_model=DepositMaterialResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def deposit_material(
        subject_id: str, payload: DepositMaterialRequest, vault: VaultDep
    ) -> DepositMaterialResponse:
        """Deposit a subject's private material (seed/bootstrap step)."""
        try:
            signing_key = private_key_from_pem(payload.signing_key_pem.encode("utf-8"))
        except KeyFormatError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid signing key PEM: {exc}",
            ) from exc
        for cred in payload.credentials:
            if cred.subject_id != subject_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"credential {cred.serial!r} is for {cred.subject_id!r}, "
                        f"not {subject_id!r}"
                    ),
                )
        vault.put_subject(
            SubjectMaterial(
                subject_id=subject_id,
                kind=payload.kind,
                display_name=payload.display_name,
                signing_key=signing_key,
                facility_id=payload.facility_id,
                certificate_pem=payload.certificate_pem,
                pre_private_key=payload.pre_private_key,
                pre_public_key=payload.pre_public_key,
                credentials=list(payload.credentials),
            )
        )
        return DepositMaterialResponse(
            subject_id=subject_id, credentials=len(payload.credentials)
        )

    @app.post(
        "/records/{record_id}/shares",
        response_model=DepositShareResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def deposit_share(
        record_id: str, payload: DepositShareRequest, vault: VaultDep
    ) -> DepositShareResponse:
        """Deposit share 1 (attending-clinician custody) for one record."""
        share = open_share(record_id, payload.sealed_share)
        try:
            vault.put_share(record_id, share)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        return DepositShareResponse(record_id=record_id, x=share[0])

    @app.put(
        "/records/{record_id}/shares",
        response_model=DepositShareResponse,
    )
    def replace_share(
        record_id: str, payload: ReplaceShareRequest, vault: VaultDep
    ) -> DepositShareResponse:
        """Take share 1 of a record's new emergency key after rotation (ADR-0069).

        Only a facility may call this, only while the shared store shows the
        record ``expired`` -- the moment its forced rotation runs -- and only
        for the generation after the one held.
        """
        if state_loader is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="no store access; share 1 cannot be replaced",
            )
        if state_loader(record_id) is not LifecycleState.EXPIRED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="a share is replaced only during its record's expiry rotation",
            )
        share = open_share(record_id, payload.sealed_share)
        try:
            vault.replace_share(record_id, share, payload.generation)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        return DepositShareResponse(status="replaced", record_id=record_id, x=share[0])

    # --- Public read-back --------------------------------------------------

    @app.get(
        "/subjects/{subject_id}",
        response_model=SubjectSummary,
        responses={404: {"model": ErrorResponse}},
    )
    def subject_summary(subject_id: str, vault: VaultDep) -> SubjectSummary:
        """Public identity of a subject: keys are described, never returned."""
        material = _require_subject(vault, subject_id)
        return SubjectSummary(
            subject_id=material.subject_id,
            kind=material.kind,  # type: ignore[arg-type]
            display_name=material.display_name,
            facility_id=material.facility_id,
            public_key_pem=public_key_to_pem(material.signing_key.public_key()).decode(
                "ascii"
            ),
            certificate_pem=material.certificate_pem,
            pre_public_key=material.pre_public_key,
            credentials=[
                CredentialSummary(
                    serial=c.serial,
                    issuer_id=c.issuer_id,
                    name=c.attribute.name,
                    value=c.attribute.value,
                    valid_until=c.valid_until,
                    status=c.status.value,
                )
                for c in material.credentials
            ],
        )

    @app.get("/subjects/{subject_id}/public-key", response_model=PublicKeyResponse)
    def subject_public_key(subject_id: str, vault: VaultDep) -> PublicKeyResponse:
        material = _require_subject(vault, subject_id)
        return PublicKeyResponse(
            subject_id=subject_id,
            public_key_pem=public_key_to_pem(material.signing_key.public_key()).decode(
                "ascii"
            ),
        )

    # --- Consent signing (ADR-0014 / ADR-0031) -------------------------------

    @app.post(
        "/subjects/{subject_id}/consent/request",
        response_model=SignConsentRequestResponse,
    )
    def sign_consent_request(
        subject_id: str, payload: SignConsentRequestPayload, vault: VaultDep
    ) -> SignConsentRequestResponse:
        """Sign a clinician's ``ConsentRequest``. Grants nothing by itself."""
        material = _require_subject(vault, subject_id)
        _require_kind(material, "clinician")
        try:
            req = create_consent_request(
                patient_id=payload.patient_id,
                requester_id=subject_id,
                scope=tuple(payload.scope),
                purpose=payload.purpose,
                requester_signing_key=material.signing_key,
                ttl=datetime.timedelta(days=payload.ttl_days),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            ) from exc
        return SignConsentRequestResponse(request=req)

    @app.post(
        "/subjects/{subject_id}/consent/decide", response_model=SignedGrantResponse
    )
    def sign_consent_decision(
        subject_id: str, payload: DecideConsentPayload, vault: VaultDep
    ) -> SignedGrantResponse:
        """Sign the patient's decision on a request (granted or denied)."""
        material = _require_subject(vault, subject_id)
        _require_kind(material, "patient")
        if payload.request.patient_id != subject_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"request {payload.request.request_id} is addressed to "
                    f"{payload.request.patient_id!r}, not {subject_id!r}"
                ),
            )
        certificate_pem = _patient_certificate(material)
        grant = create_consent_grant(
            request=payload.request,
            status=ConsentStatus(payload.status),
            grantee_id=payload.request.requester_id,
            patient_signing_key=material.signing_key,
            ttl=datetime.timedelta(days=payload.ttl_days),
        )
        return SignedGrantResponse(grant=grant, patient_certificate_pem=certificate_pem)

    @app.post(
        "/subjects/{subject_id}/consent/revoke", response_model=SignedGrantResponse
    )
    def sign_consent_revocation(
        subject_id: str, payload: RevokeConsentPayload, vault: VaultDep
    ) -> SignedGrantResponse:
        """Sign a revocation of a prior grant (patient-only, ADR-0037)."""
        material = _require_subject(vault, subject_id)
        _require_kind(material, "patient")
        if payload.prior_grant.patient_id != subject_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="only the granting patient can revoke this grant",
            )
        certificate_pem = _patient_certificate(material)
        revoked = revoke_consent_grant(
            prior_grant=payload.prior_grant, patient_signing_key=material.signing_key
        )
        return SignedGrantResponse(
            grant=revoked, patient_certificate_pem=certificate_pem
        )

    # --- Key-bearing federation calls ---------------------------------------

    @app.post(
        "/subjects/{subject_id}/read",
        response_model=ReadRecordResult,
        responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    )
    def read_record(
        subject_id: str,
        payload: ReadRecordPayload,
        vault: VaultDep,
        endpoints: EndpointsDep,
        http: HttpDep,
    ) -> ReadRecordResult:
        """Read a record at a facility with this subject's attribute keys.

        The custodian presents; the facility's policy engine decides. A
        patient with no ``owner:<patient_id>`` credential presents an empty
        keyring and is refused by policy -- the ADR-0016 fail-closed case.
        """
        material = _require_subject(vault, subject_id)
        facility_url = _facility_url(endpoints, payload.facility_id)
        keyring, presented = _holder_keyring(http, endpoints, material)

        body: dict[str, Any] = {
            "requester_id": subject_id,
            "holder_keyring": keyring,
            "correlation_id": payload.correlation_id or str(uuid4()),
        }
        access_via = "policy" if material.kind == "clinician" else "owner"
        if payload.grant is not None:
            patient = vault.get_subject(payload.grant.patient_id)
            if patient is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"no public key held for patient {payload.grant.patient_id!r}; "
                        "the grant cannot be verified"
                    ),
                )
            body["grant"] = payload.grant.model_dump(mode="json")
            body["patient_certificate_pem"] = _patient_certificate(patient)
            access_via = "consent"

        data = _post(
            http,
            f"{facility_url}/records/{payload.record_id}/read",
            body,
            what="record read",
        )
        return ReadRecordResult(
            record_id=data["record_id"],
            patient_id=data["patient_id"],
            facility_id=data["facility_id"],
            content_type=data["content_type"],
            plaintext_b64=data["plaintext_b64"],
            access_via=access_via,
            correlation_id=body["correlation_id"],
            attributes_presented=presented,
        )

    @app.post(
        "/subjects/{subject_id}/revoke",
        response_model=RevokeRecordResult,
        responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    )
    def revoke_record(
        subject_id: str,
        payload: RevokeRecordPayload,
        vault: VaultDep,
        endpoints: EndpointsDep,
        http: HttpDep,
    ) -> RevokeRecordResult:
        """Revoke access to the patient's record by key rotation (P3-7).

        The patient's key signs the event here and stays here (review D6);
        the facility verifies the event against the patient's certificate and
        unwraps the current DEK itself, so neither a key nor a DEK is sent.
        """
        material = _require_subject(vault, subject_id)
        _require_kind(material, "patient")
        owner_creds = [
            c
            for c in material.credentials
            if c.attribute.name == "owner" and c.attribute.value == subject_id
        ]
        if not owner_creds:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"patient {subject_id!r} holds no owner credential",
            )
        owner_authority_id = owner_creds[0].issuer_id
        facility_url = _facility_url(endpoints, payload.facility_id)
        certificate_pem = _patient_certificate(material)
        leaves = _policy_leaves(payload.new_clinical_policy)
        leaves.append((owner_authority_id, "owner", subject_id))
        keyring = _authoring_keyring(http, endpoints, leaves)
        event = sign_revocation_transition(
            signing_key=material.signing_key,
            record_id=payload.record_id,
            patient_id=subject_id,
        )
        data = _post(
            http,
            f"{facility_url}/records/{payload.record_id}/revoke",
            {
                "transition_event": event.model_dump(mode="json"),
                "actor_certificate_pem": certificate_pem,
                "new_clinical_policy": payload.new_clinical_policy.model_dump(
                    mode="json"
                ),
                "owner_authority_id": owner_authority_id,
                "attribute_keyring": keyring,
                "correlation_id": payload.correlation_id or str(uuid4()),
            },
            what="record revocation",
        )
        return RevokeRecordResult.model_validate(data)

    @app.post(
        "/subjects/{subject_id}/records",
        response_model=IngestResult,
        status_code=status.HTTP_201_CREATED,
        responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    )
    def ingest_own_record(
        subject_id: str,
        payload: IngestPayload,
        vault: VaultDep,
        endpoints: EndpointsDep,
        http: HttpDep,
    ) -> IngestResult:
        """Upload a record of the patient's own (P3-14 ingest via the key agent).

        Fails closed before touching any service if the patient holds no
        ``owner`` credential: the facility would seal a record the patient
        could never open, so the request is refused instead.
        """
        material = _require_subject(vault, subject_id)
        author_id = subject_id
        source = "patient_upload"
        if material.kind == "clinician":
            if not payload.patient_id:
                raise HTTPException(
                    403,
                    "A clinician cannot upload as a patient; "
                    "a clinical note needs an authorized patient",
                )
            if payload.grant is not None:
                if payload.grant.patient_id != payload.patient_id:
                    raise HTTPException(403, "Grant belongs to another patient")
                read_record(
                    subject_id,
                    ReadRecordPayload(
                        record_id=payload.grant.scope[0],
                        facility_id=payload.facility_id,
                        grant=payload.grant,
                    ),
                    vault,
                    endpoints,
                    http,
                )
            elif payload.emergency is not None:
                if payload.emergency.patient_id != payload.patient_id:
                    raise HTTPException(403, "Emergency belongs to another patient")
                # Writing a note may join the patient's open emergency, never
                # open a new one as a side effect (the facility refuses, 409).
                declare_breakglass(
                    subject_id,
                    payload.emergency.model_copy(update={"join_only": True}),
                    vault,
                    endpoints,
                    http,
                )
            else:
                raise HTTPException(
                    403,
                    "A clinical note needs a live patient grant "
                    "or a fresh emergency authorization",
                )
            subject_id = payload.patient_id
            material = _require_subject(vault, subject_id)
            source = "clinician_note"
        else:
            _require_kind(material, "patient")
            if payload.patient_id and payload.patient_id != subject_id:
                raise HTTPException(403, "Cannot upload for another patient")
        owner_creds = [
            c
            for c in material.credentials
            if c.attribute.name == "owner" and c.attribute.value == subject_id
        ]
        if not owner_creds:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"patient {subject_id!r} holds no owner credential; refusing to "
                    "seal a record its owner could not open (ADR-0016)"
                ),
            )
        owner_authority_id = owner_creds[0].issuer_id
        facility_url = _facility_url(endpoints, payload.facility_id)
        if not endpoints.audit:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="no audit service configured; share 3 has nowhere to go",
            )
        try:
            plaintext = base64.b64decode(payload.content_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"content_b64 is not valid base64: {exc}",
            ) from exc
        if not plaintext:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="empty record"
            )
        record_id = payload.record_id or f"rec-{uuid4().hex[:8]}"

        # Authoring keys for every clinical leaf plus the owner leaf.
        leaves = _policy_leaves(payload.clinical_policy)
        leaves.append((owner_authority_id, "owner", subject_id))
        keyring = _authoring_keyring(http, endpoints, leaves)

        # 2-of-3 emergency key: share 3 to the audit service (commit-before-
        # release custody), share 1 to clinician custody here, share 2 unused
        # (home authority, reserved: ADR-0074) -- the same split the seed performs.
        emergency = provision_emergency_key()
        share1, share3 = emergency.clinician_share, emergency.audit_share

        # The patient signs the labels, bound to this record (ADR-0064), so a
        # store write cannot loosen them; without a certificate they go unsigned
        # and the facility applies the strictest rules.
        clinical = payload.clinical.model_copy(
            update={"author_id": author_id, "source": source}
        )
        if material.certificate_pem:
            clinical = sign_clinical_labels(
                clinical,
                record_id=record_id,
                patient_id=subject_id,
                signing_key=material.signing_key,
                certificate_pem=material.certificate_pem,
            )

        # Shares first, ingest second (review F4): a record must never exist
        # without its break-glass shares, because the emergency key is gone
        # once this request ends. Neither holder overwrites an existing share,
        # so a duplicate record_id is refused (409) before anything is stored.
        _, audit_recipient = share_key_of(http, endpoints.audit, "audit")
        _post(
            http,
            f"{endpoints.audit}/breakglass/shares",
            {
                "share_key": record_id,
                "sealed_share": sealed_json(
                    share3, record_id=record_id, recipient=audit_recipient
                ),
            },
            what="audit share deposit",
        )
        try:
            vault.put_share(record_id, share1)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=str(exc)
            ) from exc
        try:
            data = _post(
                http,
                f"{facility_url}/records/ingest",
                {
                    "plaintext_b64": payload.content_b64,
                    "patient_id": subject_id,
                    "owner_authority_id": owner_authority_id,
                    "clinical_policy": payload.clinical_policy.model_dump(mode="json"),
                    "attribute_keyring": keyring,
                    "search_terms": payload.search_terms or None,
                    "emergency_key_b64": base64.b64encode(emergency.key).decode(
                        "ascii"
                    ),
                    "content_type": payload.content_type,
                    "record_id": record_id,
                    "clinical": clinical.model_dump(mode="json"),
                },
                what="record ingest",
            )
        except HTTPException:
            # No record was stored. Share 1 is released here; share 3 stays
            # with the audit service under an id no record uses, a share of a
            # key that protects nothing. A retry gets a fresh record_id.
            vault.drop_share(record_id, share1)
            raise
        return IngestResult(
            record_id=data["record_id"],
            facility_id=payload.facility_id,
            patient_id=subject_id,
            policy_id=data["policy_id"],
            lifecycle_state=data["lifecycle_state"],
            search_terms_indexed=data["search_terms_indexed"],
            audit_share_deposited=True,
        )

    @app.post(
        "/subjects/{subject_id}/breakglass",
        response_model=BreakglassResult,
        responses={
            400: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            503: {"model": ErrorResponse},
        },
    )
    def declare_breakglass(
        subject_id: str,
        payload: BreakglassPayload,
        vault: VaultDep,
        endpoints: EndpointsDep,
        http: HttpDep,
    ) -> BreakglassResult:
        """Run the clinician's side of ARCHITECTURE.md §5 steps 1-5.

        1. Sign the ``EmergencyAssertion`` with the clinician's certificate key.
        2. Ask the audit service for share 3 -- it commits its log entry
           first and returns the share only with the new chain head
           (log-before-release; a failed commit means no share, no unlock).
        3. Take share 1 from clinician custody.
        4. Present assertion + certificate chain + 2 shares + PRE public key
           to the declaring facility's threshold gate.
        5. Open the PRE delivery package and, when a record loader is
           configured, decrypt the record for display.
        """
        material = _require_subject(vault, subject_id)
        _require_kind(material, "clinician")
        if not material.certificate_pem:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"clinician {subject_id!r} holds no certificate; cannot assert",
            )
        if material.pre_private_key is None or material.pre_public_key is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"clinician {subject_id!r} holds no PRE keypair; "
                    "cannot receive a DEK"
                ),
            )
        facility_id = payload.facility_id or material.facility_id
        # Route all viewers to the record's home node, where its timer lives.
        loader = app.state.record_loader
        target_record = loader(payload.record_id) if loader else None
        if target_record is not None:
            if target_record.patient_id != payload.patient_id:
                raise HTTPException(403, "record belongs to another patient")
            facility_id = target_record.facility_id
            # Unsigned or unverifiable labels get every requirement (ADR-0064).
            rules = disclosure_rules(target_record, _label_trust(vault))
            if rules.clinical_justification and len(payload.justification.strip()) < 20:
                raise HTTPException(
                    403, "Explain the immediate clinical need (at least 20 characters)"
                )
            if rules.sensitive_justification:
                if len(payload.sensitive_justification.strip()) < 20:
                    raise HTTPException(
                        403,
                        "Restricted record: explain why its contents are essential "
                        "now (at least 20 characters)",
                    )
        if not facility_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="no facility_id given and the clinician has no home facility",
            )
        facility_url = _facility_url(endpoints, facility_id)
        if not endpoints.audit:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="no audit service configured; break-glass cannot proceed",
            )
        share1 = vault.get_share(payload.record_id)
        if share1 is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"no clinician-custody share held for record "
                    f"{payload.record_id!r}; threshold cannot be met"
                ),
            )
        corr_id = payload.correlation_id or str(uuid4())

        # 0. The record's state decides whether this opens or joins, and so
        # whether the clinician signs a transition (ADR-0068). Read before
        # share 3 is requested, so a refusal costs no release.
        state = LifecycleState(
            _get(
                http,
                f"{facility_url}/records/{payload.record_id}/lifecycle",
                what="record lifecycle state",
            )["state"]
        )
        if state is LifecycleState.EXPIRED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="the record's emergency window is closing; try again shortly",
            )

        # 1. Sign the assertion, bound to the identified patient (ADR-0033).
        unlock_material = prepare_unlock(
            signing_key=material.signing_key,
            patient_id=payload.patient_id,
            clinician_id=subject_id,
            facility_id=facility_id,
            reason_code=payload.reason_code,
            assertion_ttl=datetime.timedelta(seconds=payload.assertion_ttl_seconds),
            context_digest=clinical_context_digest(
                payload.record_id,
                payload.justification,
                payload.sensitive_justification,
            ),
        )
        assertion = unlock_material.assertion

        # 2. Share 3: the audit service commits first, releases second, and
        # seals it to the facility's gate, so this process never holds shares
        # 1 and 3 together in the clear (ADR-0079).
        gate_statement, gate = share_key_of(http, facility_url, "facility")
        seq_before = vault.audit_seq_before_release()
        release = _post(
            http,
            f"{endpoints.audit}/breakglass/release",
            {
                "share_key": payload.record_id,
                "event_type": "breakglass_share_released",
                "event_data": {
                    "record_id": payload.record_id,
                    "patient_id": payload.patient_id,
                    "clinician_id": subject_id,
                    "facility_id": facility_id,
                    "assertion_id": str(assertion.assertion_id),
                    "reason_code": payload.reason_code.value,
                    "justification_digest": justification_digest(payload.justification),
                    "sensitive_justification_digest": justification_digest(
                        payload.sensitive_justification
                    ),
                    "restricted": bool(target_record and rules.sensitive_justification),
                },
                "actor_id": SHARE_HOLDER_AUDIT,
                "correlation_id": corr_id,
                # The audit service validates the assertion itself before it
                # commits or releases anything (ADR-0067).
                "assertion": assertion.model_dump(mode="json"),
                "clinician_certificate_pem": material.certificate_pem,
                "justification": payload.justification,
                "sensitive_justification": payload.sensitive_justification,
                "recipient": gate_statement,
            },
            what="audit share release",
        )
        _check_release_entry(vault, release["entry"], corr_id, seq_before)
        shares_presented = [
            SharePresented(holder=SHARE_HOLDER_CLINICIAN, x=share1[0]),
            SharePresented(
                holder=SHARE_HOLDER_AUDIT,
                x=release["sealed_share"]["x"],
                audit_entry_seq=release["entry"]["seq"],
            ),
        ]

        # 4. Threshold gate at the declaring facility.
        #
        # Opening carries the record's -> EMERGENCY_OPEN transition signed here
        # with the clinician's own key (ADR-0068, D8-a): the key stays in this
        # process (ADR-0043) and the facility verifies the event against the
        # clinician's certificate. A join signs nothing -- the record is
        # already open and no transition happens (ADR-0057).
        transition_event = (
            sign_emergency_transition(
                signing_key=material.signing_key,
                record_id=payload.record_id,
                from_state=state,
                clinician_id=subject_id,
                reason_code=payload.reason_code,
            )
            if state is not LifecycleState.EMERGENCY_OPEN and not payload.join_only
            else None
        )
        unlock = _post(
            http,
            f"{facility_url}/records/{payload.record_id}/breakglass",
            {
                "assertion": assertion.model_dump(mode="json"),
                # The facility validates this chain against its own configured
                # root and CAs; it never accepts trust anchors from a caller (F1).
                "clinician_certificate_pem": material.certificate_pem,
                "sealed_shares": [
                    sealed_json(share1, record_id=payload.record_id, recipient=gate),
                    release["sealed_share"],
                ],
                "pre_rewrap_key": material.pre_public_key,
                "transition_event": (
                    transition_event.model_dump(mode="json")
                    if transition_event is not None
                    else None
                ),
                "correlation_id": corr_id,
                "emergency_duration_seconds": payload.emergency_duration_seconds,
                "join_only": payload.join_only,
                "sensitive_justification": payload.sensitive_justification,
                "justification": payload.justification,
            },
            what="break-glass unlock",
        )
        # A record already open is joined: no transition, same window (ADR-0057).
        transition = (
            TransitionEvent.model_validate(unlock["transition_event"])
            if unlock.get("transition_event")
            else None
        )
        opened_at = (
            transition.issued_at
            if transition
            else datetime.datetime.now(datetime.timezone.utc)
        )

        # 5. Open the PRE delivery package; decrypt if we can see the store.
        try:
            dek = open_delivered_dek(
                base64.b64decode(unlock["rewrapped_dek_b64"]),
                pre_private_key=material.pre_private_key,
                record_id=payload.record_id,
            )
        except (PREError, InvalidTagError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"PRE delivery package did not open for this clinician: {exc}",
            ) from exc

        plaintext_b64: str | None = None
        content_type: str | None = None
        loader: RecordLoader | None = app.state.record_loader
        if loader is not None:
            record = loader(payload.record_id)
            if record is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"record {payload.record_id!r} not found in the store",
                )
            try:
                plaintext = decrypt_delivered_record(record, dek)
            except DecryptionError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"recovered DEK does not open the record: {exc}",
                ) from exc
            plaintext_b64 = base64.b64encode(plaintext).decode("ascii")
            content_type = record.content_type

        # The facility decides the window (it may shorten the request, F6).
        expires_at = datetime.datetime.fromisoformat(unlock["expires_at"])
        return BreakglassResult(
            record_id=payload.record_id,
            patient_id=payload.patient_id,
            facility_id=facility_id,
            clinician_id=subject_id,
            correlation_id=corr_id,
            assertion_id=str(assertion.assertion_id),
            assertion_expires_at=assertion.expires_at,
            shares_presented=shares_presented,
            transition_event=transition,
            joined=bool(unlock.get("joined")),
            opened_at=opened_at,
            expires_at=expires_at,
            content_type=content_type,
            plaintext_b64=plaintext_b64,
        )

    install_service_auth(
        app,
        ServiceAuthConfig(
            service_id=identity.service_id,
            trusted_root=service_root,
            permissions=CUSTODIAN_PERMISSIONS,
            public_routes=CUSTODIAN_PUBLIC_ROUTES,
        ),
    )
    app.state.share_key = sealing_key
    app.state.share_recipient = ShareRecipient(
        identity.service_id, sealing_key.public_key
    )
    statement = make_key_statement(
        sealing_key,
        service_id=identity.service_id,
        kind=identity.kind,
        signing_key=identity.signing_key,
        certificate_pem=identity.certificate_pem,
    )
    app.state.share_key_statement = statement
    serve_share_key(app, statement)
    return app
