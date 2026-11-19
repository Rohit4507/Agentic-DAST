"""The test library the planner chooses from.

This is the enum-constrained surface an LLM planner is allowed to return (see the build
plan, L2): *the model picks a ``test_id``, it never invents a test and never sends a
request.* Keeping the catalogue in code -- with ``requires_write`` and ``implemented``
as first-class fields -- is what makes that constraint enforceable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class TestSpec:
    test_id: str
    name: str
    vuln_class: str
    owasp: str
    requires_write: bool
    implemented: bool
    run: Callable[..., object] | None = None
    notes: str = ""


def _logic_run(kind: str) -> Callable[..., object] | None:
    from . import logic

    return {
        "logic_double_refund": logic.test_double_refund,
        "logic_skipped_payment": logic.test_skipped_payment,
        "logic_fare_tampering": logic.test_fare_tampering,
    }.get(kind)


_TESTS: list[TestSpec] = [
    # --- implemented ---------------------------------------------------------------
    TestSpec(
        test_id="bola_dual_token",
        name="Cross-tenant object read (dual-token replay)",
        vuln_class="bola",
        owasp="API1:2023",
        requires_write=False,
        implemented=True,
        notes="owner vs other-tenant replay of the same request; negative control first",
    ),
    TestSpec(
        test_id="logic_double_refund",
        name="Double refund",
        vuln_class="double_refund",
        owasp="API6:2023",
        requires_write=True,
        implemented=True,
        run=_logic_run("logic_double_refund"),
        notes="invariant: at most one successful refund per booking",
    ),
    TestSpec(
        test_id="logic_skipped_payment",
        name="Payment step bypass",
        vuln_class="skipped_payment",
        owasp="API6:2023",
        requires_write=True,
        implemented=True,
        run=_logic_run("logic_skipped_payment"),
        notes="invariant: CONFIRMED implies paid > 0",
    ),
    TestSpec(
        test_id="logic_fare_tampering",
        name="Client-supplied fare accepted",
        vuln_class="fare_tampering",
        owasp="API6:2023",
        requires_write=True,
        implemented=True,
        run=_logic_run("logic_fare_tampering"),
        notes="invariant: final >= quoted",
    ),
    TestSpec(
        test_id="exposure_unauthenticated",
        name="Unauthenticated data exposure",
        vuln_class="unauthenticated_data_exposure",
        owasp="API2:2023",
        requires_write=False,
        implemented=True,
        notes="zombie/shadow endpoints that answer without a credential",
    ),
    # --- catalogued, not yet implemented (the planner still sees them) --------------
    TestSpec("bfla_role_probe", "Function-level authorization probe", "bfla", "API5:2023", False, False),
    TestSpec("auth_token_reuse", "Token reuse after logout / session fixation", "auth", "API2:2023", False, False),
    TestSpec("auth_jwt_weakness", "JWT alg/none and signature validation", "auth", "API2:2023", False, False),
    TestSpec("hygiene_mass_assignment", "Mass assignment of role/agency fields", "mass_assignment", "API3:2023", True, False),
    TestSpec("hygiene_missing_rate_limit", "Missing rate limit on sensitive flow", "api_hygiene", "API4:2023", False, False),
    TestSpec("exposure_excessive_data", "Excessive data in response objects", "info_disclosure", "API3:2023", False, False),
    TestSpec("logic_coupon_reuse", "Coupon applied twice", "coupon_reuse", "API6:2023", True, False),
    TestSpec("logic_negative_quantity", "Negative passenger quantity", "negative_quantity", "API6:2023", True, False),
    TestSpec("injection_sql", "SQL/NoSQL injection in search filters", "injection", "API8:2023", False, False),
    TestSpec("ssrf_supplier_url", "SSRF via supplier/webhook URL", "ssrf", "API7:2023", False, False),
    TestSpec("zombie_version_probe", "Superseded API version still live", "zombie_api", "API9:2023", False, False),
]

TESTS: dict[str, TestSpec] = {t.test_id: t for t in _TESTS}


def get_test(test_id: str) -> TestSpec:
    if test_id not in TESTS:
        raise KeyError(f"unknown test_id {test_id!r}; valid ids: {sorted(TESTS)}")
    return TESTS[test_id]


def implemented_tests(*, write: bool | None = None) -> list[TestSpec]:
    out = [t for t in TESTS.values() if t.implemented]
    if write is not None:
        out = [t for t in out if t.requires_write == write]
    return out


def catalogue() -> list[dict[str, object]]:
    return [
        {
            "test_id": t.test_id,
            "name": t.name,
            "vuln_class": t.vuln_class,
            "owasp": t.owasp,
            "requires_write": t.requires_write,
            "implemented": t.implemented,
            "notes": t.notes,
        }
        for t in TESTS.values()
    ]
