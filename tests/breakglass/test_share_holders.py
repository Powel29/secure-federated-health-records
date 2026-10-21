"""The weighted 3-of-4 holder map (ADR-0089).

Shares 1, 2, {3, 4} go to the custodian, the home authority and the audit
service. The property the paper relies on is arithmetic about that map:
without at least one audit-service point no set reaches the threshold.
"""

from __future__ import annotations

import itertools

import pytest
from breakglass.emergency_key import (
    AUDIT_SHARE_XS,
    CLINICIAN_SHARE_XS,
    HOME_AUTHORITY_SHARE_XS,
    THRESHOLD,
    TOTAL_SHARES,
    check_holding,
    generate_emergency_key,
    holder_shares,
    split_emergency_key,
)
from breakglass.exceptions import ShareHoldingError


def test_the_holders_partition_the_split():
    sets = (CLINICIAN_SHARE_XS, HOME_AUTHORITY_SHARE_XS, AUDIT_SHARE_XS)
    assert set().union(*sets) == set(range(1, TOTAL_SHARES + 1))
    assert sum(len(s) for s in sets) == TOTAL_SHARES  # disjoint


def test_no_set_of_threshold_points_avoids_the_audit_service():
    """Every THRESHOLD-subset of the split contains an audit-service point, and
    the non-audit holders together are one short of the threshold."""
    non_audit = CLINICIAN_SHARE_XS | HOME_AUTHORITY_SHARE_XS
    assert len(non_audit) == THRESHOLD - 1
    assert len(AUDIT_SHARE_XS) == THRESHOLD - 1  # nor can the audit service alone
    for subset in itertools.combinations(range(1, TOTAL_SHARES + 1), THRESHOLD):
        assert set(subset) & AUDIT_SHARE_XS


def test_holder_shares_routes_each_point_to_its_holder():
    shares = split_emergency_key(generate_emergency_key())
    assert [x for x, _ in holder_shares(shares, CLINICIAN_SHARE_XS)] == [1]
    assert [x for x, _ in holder_shares(shares, HOME_AUTHORITY_SHARE_XS)] == [2]
    assert [x for x, _ in holder_shares(shares, AUDIT_SHARE_XS)] == [3, 4]


@pytest.mark.parametrize(
    ("holding", "holder"),
    [
        ([(3, b"a")], AUDIT_SHARE_XS),  # one short
        ([(3, b"a"), (4, b"b"), (1, b"c")], AUDIT_SHARE_XS),  # one extra
        ([(3, b"a"), (3, b"b")], AUDIT_SHARE_XS),  # duplicate x
        ([(1, b"a")], HOME_AUTHORITY_SHARE_XS),  # another holder's point
        ([(2, b"a")], CLINICIAN_SHARE_XS),
        ([], CLINICIAN_SHARE_XS),
    ],
)
def test_check_holding_refuses_anything_but_the_holders_set(holding, holder):
    with pytest.raises(ShareHoldingError):
        check_holding(holding, holder)


def test_check_holding_accepts_the_holders_own_set():
    check_holding([(3, b"a"), (4, b"b")], AUDIT_SHARE_XS)
    check_holding([(4, b"b"), (3, b"a")], AUDIT_SHARE_XS)  # order is irrelevant
    check_holding([(2, b"a")], HOME_AUTHORITY_SHARE_XS)
    check_holding([(1, b"a")], CLINICIAN_SHARE_XS)
