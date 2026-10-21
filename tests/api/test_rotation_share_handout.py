"""A rotation hands every holder its own new shares, sealed to it (ADR-0089).

``api.rotation.http_rotation_ports`` delivers a rotation's weighted 3-of-4
split: share 1 to the custodian, share 2 to the patient's home authority (the
authority of the policy's ``owner`` leaf), shares 3 and 4 to the audit
service. These tests drive it over a mock transport with real, root-signed
share-key statements and open every delivered share with its holder's key.
"""

from __future__ import annotations

import json
import secrets

import httpx
import pytest
from api.rotation import (
    RotationError,
    ShareDistribution,
    http_rotation_ports,
    owner_authority_of,
)
from breakglass.share_sealing import (
    SealedShare,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
)
from contracts.enums import PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from identity.root_anchor import generate_root_anchor
from policy.engine import author_policy_with_owner, compile_policy

from tests.service_pki import ServicePKI

RECORD = "rec-rot-1"
URLS = {
    "custodian": "http://custodian",
    "authority-net": "http://authority-net",
    "authority-med": "http://authority-med",
    "audit-service": "http://audit",
}
SHARES = {x: (x, secrets.token_bytes(33)) for x in (1, 2, 3, 4)}


@pytest.fixture()
def holders():
    root = generate_root_anchor()
    services = ServicePKI(root)
    keys, statements = {}, {}
    for service_id in URLS:
        identity = services.identity(service_id)
        keys[service_id] = ShareSealingKey.generate()
        statements[service_id] = make_key_statement(
            keys[service_id],
            service_id=identity.service_id,
            kind=identity.kind,
            signing_key=identity.signing_key,
            certificate_pem=identity.certificate_pem,
        ).model_dump(mode="json")
    return {"root": root, "keys": keys, "statements": statements}


def _ports(holders, *, statements=None, authorities=None):
    statements = statements or holders["statements"]
    by_host = {url.removeprefix("http://"): sid for sid, url in URLS.items()}
    puts: list[tuple[str, str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        service_id = by_host[request.url.host]
        if request.method == "GET" and request.url.path == "/share-key":
            return httpx.Response(200, json=statements[service_id])
        puts.append((service_id, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"status": "replaced"})

    ports = http_rotation_ports(
        httpx.Client(transport=httpx.MockTransport(handler)),
        authorities=(
            authorities
            if authorities is not None
            else {k: v for k, v in URLS.items() if k.startswith("authority")}
        ),
        custodian_url=URLS["custodian"],
        audit_url=URLS["audit-service"],
        trusted_root=holders["root"].certificate,
    )
    return ports, puts


def _distribution(home="authority-net"):
    return ShareDistribution(
        clinician=SHARES[1],
        home_authority_id=home,
        home_authority=SHARES[2],
        audit=(SHARES[3], SHARES[4]),
    )


def _opened(holders, service_id, sealed):
    return open_sealed_share(
        SealedShare.model_validate(sealed),
        record_id=RECORD,
        service_id=service_id,
        key=holders["keys"][service_id],
    )


def test_each_holder_receives_exactly_its_own_shares(holders):
    ports, puts = _ports(holders)
    ports.deposit_shares(RECORD, 3, _distribution())
    by_holder = {service_id: (path, body) for service_id, path, body in puts}
    assert set(by_holder) == {"custodian", "authority-net", "audit-service"}

    path, body = by_holder["custodian"]
    assert path == f"/records/{RECORD}/shares" and body["generation"] == 3
    assert _opened(holders, "custodian", body["sealed_share"]) == SHARES[1]

    path, body = by_holder["authority-net"]
    assert path == f"/breakglass/shares/{RECORD}" and body["generation"] == 3
    assert [_opened(holders, "authority-net", s) for s in body["sealed_shares"]] == [
        SHARES[2]
    ]

    path, body = by_holder["audit-service"]
    assert path == f"/breakglass/shares/{RECORD}" and body["generation"] == 3
    assert [_opened(holders, "audit-service", s) for s in body["sealed_shares"]] == [
        SHARES[3],
        SHARES[4],
    ]
    # Sealed on the wire: no share's bytes appear in any request body.
    wire = json.dumps([body for _s, _p, body in puts])
    for _x, value in SHARES.values():
        assert value.hex() not in wire


def test_a_home_authority_answering_as_another_gets_no_share(holders):
    """The statement at the home authority's URL must name that authority."""
    swapped = {
        **holders["statements"],
        "authority-net": holders["statements"]["authority-med"],
    }
    ports, puts = _ports(holders, statements=swapped)
    with pytest.raises(RotationError, match="belongs to 'authority-med'"):
        ports.deposit_shares(RECORD, 1, _distribution())
    assert [service_id for service_id, _p, _b in puts] == ["custodian"]


def test_an_unconfigured_home_authority_stops_the_rotation_first(holders):
    ports, puts = _ports(holders, authorities={"authority-med": URLS["authority-med"]})
    with pytest.raises(RotationError, match="home authority 'authority-net'"):
        ports.deposit_shares(RECORD, 1, _distribution())
    assert puts == []


def _compiled(tree: PolicyTree):
    leaves = []

    def walk(node: PolicyTree) -> None:
        if node.node_type is PolicyNodeType.LEAF:
            leaves.append(
                (node.authority_id, node.attribute.name, node.attribute.value)
            )
        for child in node.children:
            walk(child)

    walk(tree)
    keyring = {leaf: secrets.token_bytes(32) for leaf in leaves}
    return compile_policy(
        tree=tree, root_secret=secrets.token_bytes(32), attribute_keyring=keyring
    )


CLINICAL = PolicyTree(
    node_type=PolicyNodeType.LEAF,
    attribute=Attribute(name="role", value="physician"),
    authority_id="authority-med",
)


def test_owner_authority_is_read_from_the_policys_owner_leaf():
    tree = author_policy_with_owner(CLINICAL, "pat-1", "authority-net")
    assert owner_authority_of(_compiled(tree), "pat-1") == "authority-net"


def test_a_policy_without_one_owner_leaf_has_no_share_2_holder():
    with pytest.raises(RotationError, match="0 owner authorities"):
        owner_authority_of(_compiled(CLINICAL), "pat-1")
    tree = author_policy_with_owner(CLINICAL, "pat-1", "authority-net")
    with pytest.raises(RotationError):
        owner_authority_of(_compiled(tree), "someone-else")
