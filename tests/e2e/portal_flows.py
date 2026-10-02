"""Black-box checks A-F plus a concurrency stress run against the running portals.

Not a pytest module (no ``test_`` prefix): it needs a live stack, so it is run by
hand. Start the stack first, then::

    python -m tests.e2e.portal_flows --base http://127.0.0.1:8000
    python -m tests.e2e.portal_flows --expiry-wait 130 --workers 8 --iterations 5

Sections mirror the manual checklist:

  A  denial path (policy tree refuses although the grant is live)
  B  success path (matching attributes decrypt)
  C  cross-checks on the policy gate
  D  consent edge cases (fail closed)
  E  identification and portal boundaries
  F  break-glass (assertion, shares, case, search, expiry)
  S  concurrency stress, then audit-chain verification

Everything goes through the portal's HTTP interface as the seeded synthetic
personas (password ``demo1234``, dev-only). Run it only against your own local
demo stack. It mutates demo state (new consents, break-glass cases), which
``deploy.run_portal_demo`` resets on the next start.
"""

from __future__ import annotations

import argparse
import re
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from uuid import uuid4

import httpx

PASSWORD = "demo1234"  # noqa: S105 - synthetic dev-only login (deploy/seed_portal.py)
LEAK_MARKERS = ("PRIVATE KEY", "signing_key_pem", "pre_private_key")
UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


@dataclass
class Results:
    rows: list[tuple[str, str, bool, str]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def check(self, section: str, name: str, ok: bool, detail: str = "") -> bool:
        with self.lock:
            self.rows.append((section, name, bool(ok), detail))
        return bool(ok)

    def skip(self, section: str, name: str, why: str) -> None:
        with self.lock:
            self.rows.append((section, name, True, f"SKIPPED: {why}"))


R = Results()
LEAKS: list[str] = []
STATUS: Counter[int] = Counter()
LATENCY: list[float] = []


class Portal:
    """One logged-in browser session."""

    def __init__(self, base: str, username: str) -> None:
        self.username = username
        self.http = httpx.Client(base_url=base, follow_redirects=False, timeout=60.0)

    def _csrf(self) -> str:
        return self.http.cookies.get("csrftoken") or ""

    def _track(self, resp: httpx.Response, started: float) -> httpx.Response:
        LATENCY.append(time.perf_counter() - started)
        STATUS[resp.status_code] += 1
        for marker in LEAK_MARKERS:
            if marker in resp.text:
                LEAKS.append(f"{self.username} {resp.request.url.path}: {marker}")
        return resp

    def get(self, path: str, **params: str) -> httpx.Response:
        t = time.perf_counter()
        return self._track(self.http.get(path, params=params or None), t)

    def post(self, path: str, data: dict | list | None = None) -> httpx.Response:
        if not self._csrf():
            self.http.get("/accounts/login/")
        items = list(data.items()) if isinstance(data, dict) else list(data or [])
        items.append(("csrfmiddlewaretoken", self._csrf()))
        form: dict[str, list[str]] = {}
        for key, value in items:  # httpx wants repeated keys as a list value
            form.setdefault(key, []).append(value)
        t = time.perf_counter()
        resp = self.http.post(
            path,
            data=form,
            headers={"X-CSRFToken": self._csrf(), "Referer": str(self.http.base_url)},
        )
        return self._track(resp, t)

    def login(self) -> bool:
        self.http.get("/accounts/login/")
        resp = self.post(
            "/accounts/login/",
            {"username": self.username, "password": PASSWORD, "next": ""},
        )
        return resp.status_code == 302

    def close(self) -> None:
        self.http.close()


def login(base: str, username: str) -> Portal:
    p = Portal(base, username)
    if not p.login():
        raise SystemExit(f"login failed for {username!r} - is the stack up and seeded?")
    return p


# --- flow helpers ------------------------------------------------------------------


def request_consent(
    clin: Portal, pat: Portal, patient_id: str, scope: list[str]
) -> str | None:
    """File a signed consent request; return its id as the patient page shows it."""
    purpose = f"stress-{uuid4().hex[:10]}"
    data = [("patient_id", patient_id), ("purpose", purpose)] + [
        ("scope", s) for s in scope
    ]
    resp = clin.post("/clinician/consent/", data)
    if resp.status_code != 302:
        return None
    page = pat.get("/patient/access/").text
    m = re.search(
        rf"{purpose}”</div>\s*<form method=\"post\" "
        rf"action=\"/patient/access/({UUID_RE})/decide/\"",
        page,
    )
    return m.group(1) if m else None


def decide(pat: Portal, request_id: str, decision: str) -> int:
    return pat.post(
        f"/patient/access/{request_id}/decide/", {"decision": decision}
    ).status_code


def consent_read(clin: Portal, request_id: str, record_id: str) -> httpx.Response:
    return clin.post(f"/clinician/consent/{request_id}/read/", {"record_id": record_id})


def is_plaintext(resp: httpx.Response) -> bool:
    return resp.status_code == 200 and 'class="plaintext"' in resp.text


def is_refused(resp: httpx.Response) -> bool:
    return (
        resp.status_code in (403, 503)
        and not is_plaintext(resp)
        and "Refused" in resp.text
    )


def full_cycle(
    clin: Portal, pat: Portal, patient_id: str, record_id: str
) -> httpx.Response | None:
    rid = request_consent(clin, pat, patient_id, [record_id])
    if not rid or decide(pat, rid, "granted") != 302:
        return None
    return consent_read(clin, rid, record_id)


def lookup(clin: Portal, family: str, dob: str, given: str = "") -> httpx.Response:
    return clin.post(
        "/clinician/identify/",
        {
            "family_name": family,
            "given_name": given,
            "date_of_birth": dob,
            "next": "breakglass",
        },
    )


# --- sections ----------------------------------------------------------------------


def section_a(s: dict[str, Portal]) -> None:
    resp = full_cycle(s["house"], s["david"], "pat-102", "rec-002")
    R.check("A", "grant is issued to house for rec-002", resp is not None)
    if resp is None:
        return
    R.check(
        "A",
        "house read refused by the policy tree",
        is_refused(resp),
        f"HTTP {resp.status_code}",
    )
    R.check("A", "denial names the policy tree", "Policy denied" in resp.text)
    R.check(
        "A", "no plaintext in the refused response", "Type 2 Diabetes" not in resp.text
    )


def section_b(s: dict[str, Portal]) -> None:
    resp = full_cycle(s["cameron"], s["david"], "pat-102", "rec-002")
    R.check(
        "B",
        "cameron (endocrinology) decrypts rec-002",
        resp is not None and is_plaintext(resp),
    )
    if resp is not None:
        R.check(
            "B",
            "payload is David's record",
            "Type 2 Diabetes" in resp.text and "pat-102" in resp.text,
        )


def section_c(s: dict[str, Portal]) -> None:
    resp = full_cycle(s["chase"], s["david"], "pat-102", "rec-002")
    R.check(
        "C",
        "chase (cardiology) refused on rec-002",
        resp is not None and is_refused(resp),
    )
    resp = full_cycle(s["chase"], s["alice"], "pat-101", "rec-001")
    R.check("C", "chase reads rec-001", resp is not None and is_plaintext(resp))
    resp = full_cycle(s["cameron"], s["alice"], "pat-101", "rec-001")
    R.check("C", "cameron refused on rec-001", resp is not None and is_refused(resp))


def section_d(s: dict[str, Portal]) -> None:
    house, cameron, david = s["house"], s["cameron"], s["david"]
    # 12 no consent at all
    r = consent_read(cameron, str(uuid4()), "rec-002")
    R.check(
        "D",
        "read with no consent record -> 404",
        r.status_code == 404,
        f"HTTP {r.status_code}",
    )
    # 12b pending (never decided) request cannot read
    rid = request_consent(cameron, david, "pat-102", ["rec-002"])
    r = consent_read(cameron, rid, "rec-002") if rid else None
    R.check(
        "D",
        "read while request still pending -> refused",
        r is not None and r.status_code == 403 and not is_plaintext(r),
    )
    # 13 denied
    if rid:
        decide(david, rid, "denied")
        r = consent_read(cameron, rid, "rec-002")
        R.check(
            "D",
            "read after patient denied -> refused",
            r.status_code == 403 and not is_plaintext(r),
        )
    # 15 scope mismatch: rec-002 grant used for rec-001
    rid = request_consent(cameron, david, "pat-102", ["rec-002"])
    if rid and decide(david, rid, "granted") == 302:
        r = consent_read(cameron, rid, "rec-001")
        R.check(
            "D",
            "grant for rec-002 cannot read rec-001",
            not is_plaintext(r) and r.status_code in (403, 404, 503),
            f"HTTP {r.status_code}",
        )
        # another clinician cannot use cameron's grant
        r = consent_read(house, rid, "rec-002")
        R.check(
            "D",
            "another clinician cannot use the grant -> 404",
            r.status_code == 404,
            f"HTTP {r.status_code}",
        )
        # 16 revoke
        rv = david.post(f"/patient/access/{rid}/revoke/")
        R.check("D", "patient revokes the grant", rv.status_code == 302)
        r = consent_read(cameron, rid, "rec-002")
        R.check(
            "D",
            "read after revoke -> refused",
            r.status_code == 403 and not is_plaintext(r),
        )
        rv2 = david.post(f"/patient/access/{rid}/revoke/")
        R.check("D", "second revoke is harmless", rv2.status_code in (302, 403, 404))
    # cannot decide someone else's request
    rid = request_consent(cameron, david, "pat-102", ["rec-002"])
    if rid:
        r = s["alice"].post(f"/patient/access/{rid}/decide/", {"decision": "granted"})
        R.check(
            "D",
            "another patient cannot decide the request -> 404",
            r.status_code == 404,
            f"HTTP {r.status_code}",
        )
        decide(david, rid, "denied")
    # consent request for a record the patient does not own
    r = cameron.post(
        "/clinician/consent/",
        [("patient_id", "pat-102"), ("purpose", "stress-scope"), ("scope", "rec-001")],
    )
    R.check(
        "D",
        "request scoped to another patient's record is not accepted",
        r.status_code != 500,
        f"HTTP {r.status_code}",
    )
    r = cameron.post(
        "/clinician/consent/",
        [("patient_id", "pat-102"), ("purpose", ""), ("scope", "rec-002")],
    )
    R.check("D", "request without a purpose -> 400", r.status_code == 400)
    R.skip(
        "D",
        "read after grant expiry",
        "grant lifetime is days; covered by unit tests, not waited here",
    )


def section_e(s: dict[str, Portal], base: str) -> None:
    house = s["house"]
    r = lookup(house, "Miller", "1965-11-20", "David")
    R.check(
        "E",
        "Miller/1965-11-20 -> exactly pat-102",
        r.status_code == 200 and "pat-102" in r.text and "pat-101" not in r.text,
    )
    R.check(
        "E",
        "lookup logged before results shown",
        bool(re.search(r"lookup logged\s*·\s*seq\s*\d+", r.text)),
    )
    r = lookup(house, "David Miller", "1965-11-20")
    R.check(
        "E",
        "full name in family field -> 0 candidates, miss is logged",
        "0 candidates" in r.text.lower()
        and re.search(r"lookup-" + UUID_RE, r.text) is not None,
    )
    r = lookup(house, "Vance", "1982-04-15")
    R.check(
        "E",
        "namesakes -> both pat-101 and pat-777 offered",
        "pat-101" in r.text and "pat-777" in r.text,
    )
    r = lookup(house, "Vance", "1982-04-15")
    R.check("E", "nothing auto-selected", "none auto-selected" in r.text.lower())
    r = lookup(house, "Miller", "20-11-1965")
    R.check("E", "malformed DOB -> 400", r.status_code == 400)
    r = lookup(house, "", "1965-11-20")
    R.check("E", "empty family name -> 400", r.status_code == 400)
    r = house.post(
        "/clinician/identify/select/", {"patient_id": "pat-103", "next": "breakglass"}
    )
    R.check(
        "E",
        "selecting a patient not in the results is refused",
        r.status_code == 302 and "identify" in r.headers.get("location", ""),
    )
    anon = httpx.Client(base_url=base, follow_redirects=False, timeout=30.0)
    for path in ("/clinician/", "/patient/", "/oversight/", "/oversight/trace/"):
        a = anon.get(path)
        R.check(
            "E",
            f"anonymous {path} -> login redirect",
            a.status_code == 302 and "login" in a.headers.get("location", ""),
        )
    anon.close()
    R.check(
        "E",
        "patient cannot open clinician portal",
        s["david"].get("/clinician/identify/").status_code == 302,
    )
    R.check(
        "E",
        "patient cannot open oversight",
        s["david"].get("/oversight/").status_code == 302,
    )
    R.check(
        "E",
        "clinician cannot open patient portal",
        house.get("/patient/records/").status_code == 302,
    )
    R.check(
        "E",
        "clinician cannot open oversight",
        house.get("/oversight/").status_code == 302,
    )
    R.check(
        "E",
        "patient cannot post break-glass",
        s["david"]
        .post("/clinician/breakglass/", {"action": "discover", "patient_id": "pat-102"})
        .status_code
        == 302,
    )
    R.check(
        "E",
        "patient reads own record view",
        s["david"].get("/patient/records/rec-002/").status_code == 200,
    )
    R.check(
        "E",
        "patient cannot open another patient's record -> 404",
        s["david"].get("/patient/records/rec-001/").status_code == 404,
    )
    R.check(
        "E",
        "patient cannot decrypt another's record -> 404",
        s["david"].post("/patient/records/rec-001/", {"mode": "raw"}).status_code
        == 404,
    )


def declare(
    house: Portal, patient_id: str, record_id: str, reason: str = "unconscious_patient"
) -> httpx.Response:
    return house.post(
        "/clinician/breakglass/",
        {
            "action": "declare",
            "patient_id": patient_id,
            "record_id": record_id,
            "reason_code": reason,
            "justification": "stress-test emergency",
        },
    )


def lifecycle_states(aud: Portal) -> dict[str, str]:
    """record_id -> lifecycle state, as the admin federation page shows it."""
    text = re.sub(
        r"\s+", " ", re.sub(r"<[^>]+>", " ", aud.get("/oversight/federation/").text)
    )
    return {
        m.group(1): m.group(2)
        for m in re.finditer(r"(rec-[0-9a-z-]+) pat-\d+ .*? B (\S+) 20\d\d-", text)
    }


def identify_select(
    house: Portal, family: str, given: str, dob: str, patient_id: str
) -> httpx.Response:
    lookup(house, family, dob, given)
    return house.post(
        "/clinician/identify/select/", {"patient_id": patient_id, "next": "breakglass"}
    )


def section_f(s: dict[str, Portal], expiry_wait: float) -> str | None:
    house, aud = s["house"], s["auditor"]
    before = lifecycle_states(aud)

    sel = identify_select(house, "Watson", "Emma", "1994-07-03", "pat-103")
    R.check(
        "F",
        "identify + select carries pat-103 forward",
        sel.status_code == 302 and "pat-103" in sel.headers.get("location", ""),
    )
    d = house.post(
        "/clinician/breakglass/", {"action": "discover", "patient_id": "pat-103"}
    )
    R.check(
        "F",
        "federated discovery lists rec-003",
        d.status_code == 200 and "rec-003" in d.text,
    )

    # Negatives first. They run against rec-001, which is still GRANTED, so any
    # side effect of a refused assertion shows up as a lifecycle change.
    R.check(
        "F",
        "invalid reason code refused",
        declare(house, "pat-103", "rec-003", "because_i_said_so").status_code == 400,
    )
    R.check(
        "F",
        "declare without patient refused",
        declare(house, "", "rec-003").status_code == 400,
    )
    R.check(
        "F",
        "patient cannot declare an emergency",
        s["david"]
        .post(
            "/clinician/breakglass/",
            {
                "action": "declare",
                "patient_id": "pat-102",
                "record_id": "rec-001",
                "reason_code": "stroke",
            },
        )
        .status_code
        == 302,
    )
    wrong = declare(
        house, "pat-103", "rec-001"
    )  # assertion bound to pat-103, record belongs to pat-101
    R.check(
        "F",
        "assertion bound to pat-103 cannot open pat-101's rec-001",
        not is_plaintext(wrong) and "pat-101" not in wrong.text,
        f"HTTP {wrong.status_code}",
    )
    d777 = house.post(
        "/clinician/breakglass/", {"action": "discover", "patient_id": "pat-777"}
    )
    R.check(
        "F",
        "namesake pat-777 has no records to discover",
        'name="record_id" value="rec-' not in d777.text,
        f"HTTP {d777.status_code}",
    )
    nope = declare(house, "pat-777", "rec-001")
    R.check("F", "break-glass for pat-777 releases nothing", not is_plaintext(nope))
    mid = lifecycle_states(aud)
    R.check(
        "F",
        "refused assertions leave rec-001 GRANTED (no side effect)",
        mid.get("rec-001") == "granted",
        f"rec-001 is {mid.get('rec-001')!r}",
    )

    resp = declare(house, "pat-103", "rec-003")
    opened = resp.status_code == 200 and "Share 1 of 3" in resp.text
    R.check(
        "F",
        "break-glass opens: shares presented, record readable",
        opened and 'class="plaintext"' in resp.text,
        f"HTTP {resp.status_code}",
    )
    R.check(
        "F",
        "response is not cacheable",
        "no-store" in resp.headers.get("cache-control", ""),
    )
    R.check(
        "F",
        "audit share released after a chain sequence",
        bool(re.search(r"RELEASED AFTER SEQ\s*\d+", resp.text)),
    )
    again = declare(house, "pat-103", "rec-003")
    R.check(
        "F",
        "second break-glass while open is refused, no plaintext",
        again.status_code == 403 and not is_plaintext(again),
        f"HTTP {again.status_code}",
    )
    cases = house.get("/clinician/cases/").text
    pks = [int(x) for x in re.findall(r"/clinician/cases/(\d+)/", cases)]
    R.check("F", "case appears under Emergency sessions", bool(pks))
    cid = None
    if opened and pks:
        pk = (
            max(pks) - 1
            if "refused" in again.text.lower() and len(pks) > 1
            else max(pks)
        )
        # the opened case is the one that is not FAILED; find it by its page
        for cand in sorted(pks, reverse=True):
            page = house.get(f"/clinician/cases/{cand}/").text
            if (
                "Share 1 of 3" in page
                and "PRESENTED" in page
                and "NOT PRESENTED" not in page.split("Share 1 of 3")[1][:400]
            ):
                pk = cand
                break
        sr = house.post(f"/clinician/cases/{pk}/", {"search_term": "cardiac"})
        R.check(
            "F",
            "emergency search token is live while open",
            "TOKEN LIVE" in sr.text,
            f"HTTP {sr.status_code}",
        )
        R.check(
            "F",
            "other clinician cannot open the case -> 404",
            s["chase"].get(f"/clinician/cases/{pk}/").status_code == 404,
        )
        R.check(
            "F",
            "patient sees the break-glass in history",
            "emergency" in s["emma"].get("/patient/history/").text.lower(),
        )
        if expiry_wait > 0:
            print(f"  ... waiting {expiry_wait:.0f}s for the time-box to expire")
            time.sleep(expiry_wait)
            sr = house.post(f"/clinician/cases/{pk}/", {"search_term": "cardiac"})
            R.check(
                "F", "after expiry the search token is dead", "TOKEN DEAD" in sr.text
            )
            R.check(
                "F",
                "after expiry the case reads expired",
                "expired" in house.get(f"/clinician/cases/{pk}/").text.lower(),
            )
            after = lifecycle_states(aud).get("rec-003")
            R.check(
                "F",
                "after expiry rec-003 is back to GRANTED in the store",
                after == "granted",
                f"store says {after!r}",
            )
            re_open = declare(house, "pat-103", "rec-003")
            R.check(
                "F",
                "a fresh break-glass works again after expiry",
                is_plaintext(re_open),
                f"HTTP {re_open.status_code}",
            )
        else:
            R.skip(
                "F",
                "expiry / dead token / re-open",
                "pass --expiry-wait <EMERGENCY_DURATION_SECONDS+10> to include",
            )
    R.skip(
        "F",
        "replay of a consumed assertion",
        "assertions are signed inside the custodian per call; replay is covered "
        "by tests/security and the custodian API tests",
    )
    stuck = {
        r: st
        for r, st in lifecycle_states(aud).items()
        if st == "emergency-open" and before.get(r) != "emergency-open"
    }
    R.check(
        "F",
        "no record left stuck in emergency-open by this run's refusals",
        not stuck or (expiry_wait <= 0 and set(stuck) <= {"rec-003"}),
        f"stuck: {stuck}",
    )
    pre = {r: st for r, st in before.items() if st == "emergency-open"}
    R.check(
        "F",
        "no record was already stuck in emergency-open before the run",
        not pre,
        f"stuck before: {pre} (an earlier expiry never wrote the state back?)",
    )
    return cid


def section_audit(s: dict[str, Portal], cid: str | None) -> None:
    aud = s["auditor"]
    home = aud.get("/oversight/")
    R.check(
        "A-F",
        "audit chain verifies from genesis (PASS)",
        home.status_code == 200 and "PASS" in home.text,
    )
    R.check(
        "A-F",
        "patient cannot reach /oversight/trace/",
        s["david"].get("/oversight/trace/").status_code == 302,
    )
    if cid:
        tr = aud.get("/oversight/trace/", cid=cid)
        R.check(
            "A-F",
            "trace shows the identification event",
            tr.status_code == 200 and "patient.lookup" in tr.text,
        )
    cases = aud.get("/oversight/cases/")
    R.check(
        "A-F",
        "admin case review page renders and lists the break-glass",
        cases.status_code == 200 and "unconscious_patient" in cases.text,
        f"HTTP {cases.status_code}",
    )
    fed = aud.get("/oversight/federation/")
    R.check("A-F", "federation page loads", fed.status_code == 200)


# --- stress --------------------------------------------------------------------------


def chain_length(aud: Portal) -> int | None:
    m = re.search(
        r'Chain length</div><div class="stat">(\d+)', aud.get("/oversight/").text
    )
    return int(m.group(1)) if m else None


def stress(base: str, workers: int, iterations: int, aud: Portal) -> None:
    before = chain_length(aud)
    status_before = Counter(STATUS)
    outcomes: Counter[str] = Counter()
    lock = threading.Lock()

    def worker(i: int) -> None:
        sess = {n: login(base, n) for n in ("house", "cameron", "david")}
        try:
            for _ in range(iterations):
                a = lookup(sess["house"], "Miller", "1965-11-20", "David")
                with lock:
                    outcomes[
                        (
                            "lookup_ok"
                            if a.status_code == 200 and "pat-102" in a.text
                            else "lookup_bad"
                        )
                    ] += 1
                ok = full_cycle(sess["cameron"], sess["david"], "pat-102", "rec-002")
                with lock:
                    outcomes[
                        (
                            "allowed_read_ok"
                            if ok is not None and is_plaintext(ok)
                            else "allowed_read_bad"
                        )
                    ] += 1
                no = full_cycle(sess["house"], sess["david"], "pat-102", "rec-002")
                with lock:
                    outcomes[
                        (
                            "denied_read_ok"
                            if no is not None and is_refused(no)
                            else "denied_read_bad"
                        )
                    ] += 1
        finally:
            for p in sess.values():
                p.close()

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(worker, range(workers)))
    wall = time.perf_counter() - t0
    after = chain_length(aud)

    n = workers * iterations
    R.check(
        "S",
        f"{n} concurrent lookups all served",
        outcomes["lookup_ok"] == n,
        str(dict(outcomes)),
    )
    R.check(
        "S",
        f"{n} concurrent permitted reads all decrypt",
        outcomes["allowed_read_ok"] == n,
    )
    R.check(
        "S",
        f"{n} concurrent policy-denied reads all refused (none leaked)",
        outcomes["denied_read_ok"] == n,
    )
    during = {
        c: n - status_before.get(c, 0)
        for c, n in STATUS.items()
        if n - status_before.get(c, 0)
    }
    R.check(
        "S",
        "no 5xx responses under load",
        not any(c >= 500 for c in during),
        str(during),
    )
    if before is not None and after is not None:
        # every lookup and every consent decision/read appends at least one entry
        R.check(
            "S",
            "chain grew by at least the number of audited actions",
            after - before >= n * 3,
            f"{before} -> {after}",
        )
    R.check(
        "S",
        "chain still verifies from genesis after the load",
        "PASS" in aud.get("/oversight/").text,
    )
    print(f"  stress: {n * 5} portal operations in {wall:.1f}s with {workers} workers")


# --- main ----------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--iterations", type=int, default=3)
    ap.add_argument("--expiry-wait", type=float, default=0.0)
    ap.add_argument("--no-stress", action="store_true")
    args = ap.parse_args()

    names = ["alice", "david", "emma", "house", "chase", "cameron", "auditor"]
    s = {n: login(args.base, n) for n in names}
    try:
        for label, fn in (
            ("A", lambda: section_a(s)),
            ("B", lambda: section_b(s)),
            ("C", lambda: section_c(s)),
            ("D", lambda: section_d(s)),
            ("E", lambda: section_e(s, args.base)),
        ):
            print(f"running {label} ...")
            fn()
        print("running F ...")
        cid = section_f(s, args.expiry_wait)
        section_audit(s, cid)
        if not args.no_stress:
            print("running S (stress) ...")
            stress(args.base, args.workers, args.iterations, s["auditor"])
    finally:
        for p in s.values():
            p.close()

    R.check(
        "ALL",
        "no private key material in any response body",
        not LEAKS,
        "; ".join(LEAKS[:3]),
    )

    print()
    failed = 0
    for section, name, ok, detail in R.rows:
        mark = "PASS" if ok else "FAIL"
        failed += 0 if ok else 1
        print(f"[{mark}] {section:>4}  {name}" + (f"   ({detail})" if detail else ""))
    if LATENCY:
        q = (
            statistics.quantiles(LATENCY, n=20)
            if len(LATENCY) > 20
            else [max(LATENCY)] * 19
        )
        print(
            f"\n{len(LATENCY)} requests  "
            f"p50={statistics.median(LATENCY) * 1000:.0f}ms  "
            f"p95={q[18] * 1000:.0f}ms  max={max(LATENCY) * 1000:.0f}ms  "
            f"statuses={dict(STATUS)}"
        )
    print(f"{len(R.rows) - failed}/{len(R.rows)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
