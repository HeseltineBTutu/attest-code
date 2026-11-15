"""F3 pairwise comparability function and attribute derivation (§10.7)."""

from __future__ import annotations

from typing import Any

from f3_identity_pkg import INVOCATION_1, INVOCATION_2, TRIPLE, attempt, env
from f3_series_pkg import camp, invocation, package

from attest_core.f3_compare import compare
from attest_core.f3_compare_attrs import InvAttributes, derive_attributes

CONDITIONS = [{"category": "thermal-throttling", "detail": "cpu0 hot"}]
OBSERVED = {"assessment": "observed", "conditions": CONDITIONS}
NONE = {"assessment": "none-declared"}


def _attrs(inv: str, **overrides: Any) -> InvAttributes:
    base = {
        "invocation_id": inv,
        "workload_id": TRIPLE[1],
        "input_digest": TRIPLE[2],
        "profile": "hardened",
        "timeout_s": "60.000000000",
        "pyproject_digest": "ab" * 32,
        "uv_lock_digest": "ab" * 32,
        "git_revision": "cd" * 20,
        "machine_class": ("AMD EPYC 7763", 17179869184),
        "interference": "none-declared",
        "conditions": (),
        "logical_processor_count": 8,
        "cgroup_envelope": "unlimited",
    }
    base.update(overrides)
    return InvAttributes(**base)


def test_comparable() -> None:
    result = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2)])
    assert result.outcome == "comparable"
    assert (result.reasons, result.missing, result.context_notes) == ((), (), ())


def test_inequalities_incomparable() -> None:
    for field, other in (
        ("workload_id", "other"),
        ("input_digest", "ff" * 32),
        ("profile", "standard"),
        ("timeout_s", "30.000000000"),
        ("pyproject_digest", "ff" * 32),
        ("machine_class", ("Intel Xeon", 17179869184)),
    ):
        result = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, **{field: other})])
        assert result.outcome == "incomparable", field
        assert any(field in reason for reason in result.reasons)


def test_git_revision_never_gated() -> None:
    result = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, git_revision="ee" * 20)])
    assert result.outcome == "comparable"


def test_observed_interference_conditional() -> None:
    other = _attrs(INVOCATION_2, interference="observed", conditions=("thermal-throttling",))
    result = compare([_attrs(INVOCATION_1)], [other])
    assert result.outcome == "conditional"
    assert result.reasons == (f"interference observed: {INVOCATION_2}:thermal-throttling",)


def test_unknown_context() -> None:
    result = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, interference="unknown")])
    assert result.outcome == "unknown"
    assert result.missing == (f"interference:{INVOCATION_2}",)
    result2 = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, machine_class=None)])
    assert result2.outcome == "unknown"
    assert result2.missing == (f"machine_class:{INVOCATION_2}",)


def test_markers_are_unknown_never_equal() -> None:
    result = compare([_attrs(INVOCATION_1, pyproject_digest=None)], [_attrs(INVOCATION_2)])
    assert result.outcome == "unknown"
    both_unknown = compare(
        [_attrs(INVOCATION_1, pyproject_digest=None)],
        [_attrs(INVOCATION_2, pyproject_digest=None)],
    )
    assert both_unknown.outcome == "unknown"


def test_precedence() -> None:
    diff = {"profile": "standard"}
    unknown = {"machine_class": None}
    observed = {"interference": "observed", "conditions": ("other",)}
    assert compare([_attrs(INVOCATION_1, **diff)], [_attrs(INVOCATION_2, **unknown)]).outcome == (
        "incomparable"
    )
    assert compare(
        [_attrs(INVOCATION_1, **observed)], [_attrs(INVOCATION_2, **unknown)]
    ).outcome == ("unknown")
    assert compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, **observed)]).outcome == (
        "conditional"
    )


def test_context_notes_never_decisive() -> None:
    result = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, logical_processor_count=16)])
    assert result.outcome == "comparable"
    assert any("logical_processor_count differs" in note for note in result.context_notes)
    result2 = compare([_attrs(INVOCATION_1)], [_attrs(INVOCATION_2, cgroup_envelope="limited:99")])
    assert result2.outcome == "comparable"
    assert any("cgroup_envelope differs" in note for note in result2.context_notes)


def test_derive_from_records() -> None:
    made, _, environment = invocation(INVOCATION_1)
    attrs = derive_attributes(INVOCATION_1, made, environment)
    assert (attrs.workload_id, attrs.profile, attrs.machine_class) == (
        TRIPLE[1],
        "hardened",
        ("AMD EPYC 7763", 17179869184),
    )
    assert attrs.interference == "unknown"
    assert derive_attributes(INVOCATION_1, [], None).profile is None
    assert derive_attributes(INVOCATION_1, [], None).interference == "unknown"


def test_derive_split_profile_unknown() -> None:
    made = [attempt(INVOCATION_1, 1, profile="standard"), attempt(INVOCATION_1, 2)]
    attrs = derive_attributes(INVOCATION_1, made, env(INVOCATION_1))
    assert attrs.profile is None


def test_derive_observed_conditions() -> None:
    made, _, environment = invocation(INVOCATION_1, env_overrides={"interference": OBSERVED})
    attrs = derive_attributes(INVOCATION_1, made, environment)
    assert (attrs.interference, attrs.conditions) == ("observed", ("thermal-throttling",))
    result = compare([attrs], [_attrs(INVOCATION_2)])
    assert result.outcome == "conditional"


def test_deterministic_and_symmetric() -> None:
    left = _attrs(INVOCATION_1, profile="standard")
    right = _attrs(INVOCATION_2)
    assert compare([left], [right]).outcome == compare([right], [left]).outcome == "incomparable"
    assert compare([left], [right]).reasons == compare([left], [right]).reasons


def test_none_declared_passes_clean() -> None:
    campaign = camp([(INVOCATION_1, "measured")], warmups=[])
    made, tot, _ = invocation(INVOCATION_1, env_overrides={"interference": NONE})
    view = package(campaign, (made, tot, env(INVOCATION_1, interference=NONE)))
    attrs = derive_attributes(INVOCATION_1, list(view.attempts), view.envs[0])
    assert attrs.interference == "none-declared"
    assert compare([attrs], [_attrs(INVOCATION_2)]).outcome == "comparable"
