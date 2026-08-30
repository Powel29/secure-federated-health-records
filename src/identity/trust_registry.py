"""In-memory federation trust store (C5).

Simulates what ARCHITECTURE.md §7 describes each facility node holding
locally: "clinician certs + home-authority link." This is the object a
facility node (or a test) consults to answer "is this an out-of-network
clinician's certificate genuine" without needing the deployed API/storage
layer (C14/C4) to exist yet.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from cryptography.x509 import Certificate

from identity.chain import validate_chain
from identity.exceptions import UnknownFacilityError
from identity.root_anchor import RootAnchor


@dataclass
class TrustRegistry:
    """Maps facility ids to their CA certificates, anchored at one root.

    Attributes:
        root: The federation's trusted root anchor.
        facility_ca_certificates: facility_id -> that facility's CA certificate.
    """

    root: RootAnchor
    facility_ca_certificates: dict[str, Certificate] = field(default_factory=dict)

    def register_facility(
        self, facility_id: str, facility_ca_certificate: Certificate
    ) -> None:
        """Register a facility's CA certificate, verifying it chains to the root first.

        Raises:
            InvalidSignatureError: The certificate was not actually signed by
                this registry's root -- refuses to register an untrusted CA.
            CertificateExpiredError: The certificate is outside its validity
                window.
            ChainValidationError: Any other chain defect.
        """
        validate_chain(facility_ca_certificate, [], self.root.certificate)
        self.facility_ca_certificates[facility_id] = facility_ca_certificate

    def validate_clinician_certificate(
        self,
        clinician_certificate: Certificate,
        enrolling_facility_id: str,
        at: datetime.datetime | None = None,
    ) -> None:
        """Validate a clinician's certificate back to the shared root.

        This is the P2-1 exit criterion in one call: an out-of-network
        clinician presents a certificate issued by *their* facility
        (``enrolling_facility_id``, which need not be the facility running
        this check); this validates the full chain -- clinician -> facility CA
        -> shared root -- regardless of which facility is asking.

        Args:
            clinician_certificate: The clinician's leaf certificate.
            enrolling_facility_id: The facility id whose CA should have signed
                this clinician's certificate.
            at: The instant to check validity windows against; defaults to now.

        Raises:
            UnknownFacilityError: No CA certificate is registered for
                ``enrolling_facility_id``.
            InvalidSignatureError: Any link's signature does not verify -- a
                forged clinician certificate is rejected here.
            CertificateExpiredError: Any certificate in the chain has expired.
            ChainValidationError: Any other chain defect.
        """
        facility_cert = self.facility_ca_certificates.get(enrolling_facility_id)
        if facility_cert is None:
            raise UnknownFacilityError(
                f"no registered CA certificate for facility {enrolling_facility_id!r}"
            )
        validate_chain(
            clinician_certificate, [facility_cert], self.root.certificate, at=at
        )
