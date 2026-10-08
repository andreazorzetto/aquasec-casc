"""The three-way diff, case by case.

The four rules under test, from the design:

    desired != actual, we own it          -> drift, revert to desired
    in actual, not desired, never ours    -> Aqua default/console edit, leave alone
    we owned it, now absent from desired  -> released
    in desired, absent from actual        -> add it
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aquasec_casc.reconcile.diff import (
    ChangeType,
    Plan,
    ReleasePolicy,
    equivalent,
    flatten,
    three_way_diff,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "runtime_policy_aqua_default.json"


@pytest.fixture(scope="module")
def real_policy() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# flatten
# --------------------------------------------------------------------------- #


def test_flatten_produces_dotted_leaf_paths():
    assert flatten({"a": {"b": {"c": 1}}, "d": 2}) == {"a.b.c": 1, "d": 2}


def test_flatten_treats_lists_as_leaves():
    """Allow-lists are set wholesale; per-element diffs could not be applied."""
    flat = flatten({"drift_prevention": {"exec_lockdown_white_list": ["redis-*", "a"]}})
    assert flat == {"drift_prevention.exec_lockdown_white_list": ["redis-*", "a"]}


def test_flatten_keeps_an_empty_dict_as_a_leaf():
    assert flatten({"scope": {}}) == {"scope": {}}


# --------------------------------------------------------------------------- #
# equivalence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("a,b", [(None, []), ([], None), (None, {}), ([], [])])
def test_empty_collections_are_equivalent(a, b):
    """Aqua returns null for some empty lists and [] for others, same object."""
    assert equivalent(a, b)


@pytest.mark.parametrize("a,b", [(False, None), (False, []), (0, None), ("", None)])
def test_a_control_that_is_off_is_not_the_same_as_absent(a, b):
    """False is a deliberate security posture, not an empty value."""
    assert not equivalent(a, b)


def test_differing_lists_are_not_equivalent():
    assert not equivalent(["a"], ["b"])
    assert not equivalent(["a"], ["a", "b"])


# --------------------------------------------------------------------------- #
# The four rules
# --------------------------------------------------------------------------- #


def test_rule_1_drift_on_a_field_we_own_is_reverted():
    plan = three_way_diff(
        desired={"enforce": False},
        actual={"enforce": True},
        last_applied=["enforce"],
    )
    assert len(plan.changes) == 1
    change = plan.changes[0]
    assert change.change is ChangeType.UPDATE
    assert change.path == "enforce"
    assert change.before is True
    assert change.after is False


def test_rule_2_fields_we_never_owned_are_left_alone():
    """The whole reason a two-way diff fails: Aqua returns far more than we set."""
    plan = three_way_diff(
        desired={"enforce": False},
        actual={
            "enforce": False,
            "author": "someone@example.com",
            "digest": "abc123",
            "lastupdate": 1725000000,
            "is_ootb_policy": True,
            "version": "2.0",
        },
        last_applied=["enforce"],
    )
    assert plan.is_empty()
    assert plan.changes == []


def test_rule_3_a_field_we_owned_and_no_longer_declare_is_released():
    plan = three_way_diff(
        desired={"enforce": False},
        actual={"enforce": False, "block_fileless_exec": True},
        last_applied=["enforce", "block_fileless_exec"],
    )
    releases = plan.of_type(ChangeType.RELEASE)
    assert [c.path for c in releases] == ["block_fileless_exec"]
    assert releases[0].before is True


def test_rule_4_a_field_absent_on_the_server_is_added():
    plan = three_way_diff(
        desired={"block_disallowed_images": False},
        actual={"enforce": False},
        last_applied=[],
    )
    assert len(plan.changes) == 1
    assert plan.changes[0].change is ChangeType.ADD
    assert plan.changes[0].after is False


def test_identical_desired_and_actual_is_in_sync():
    state = {"enforce": False, "description": "x", "application_scopes": ["DevTest"]}
    plan = three_way_diff(desired=state, actual=dict(state), last_applied=list(state))
    assert plan.is_empty()


# --------------------------------------------------------------------------- #
# Nested paths
# --------------------------------------------------------------------------- #


def test_nested_control_drift_is_detected_at_the_leaf():
    plan = three_way_diff(
        desired={"container_exec": {"block_container_exec": True, "enabled": True}},
        actual={
            "container_exec": {
                "block_container_exec": False,
                "enabled": False,
                # Not ours: someone set this in the console.
                "container_exec_proc_white_list": ["/usr/bin/env"],
            }
        },
        last_applied=["container_exec.block_container_exec", "container_exec.enabled"],
    )
    assert {c.path for c in plan.changes} == {
        "container_exec.block_container_exec",
        "container_exec.enabled",
    }


def test_a_null_nested_object_on_the_server_is_an_add():
    """Aqua returns null for unconfigured control blocks."""
    plan = three_way_diff(
        desired={"container_exec": {"block_container_exec": True}},
        actual={"container_exec": None},
        last_applied=[],
    )
    assert plan.changes[0].change is ChangeType.ADD


def test_empty_list_versus_null_is_not_drift():
    """Otherwise 'apply straight after export' would not be a no-op."""
    plan = three_way_diff(
        desired={"drift_prevention": {"exec_lockdown_white_list": []}},
        actual={"drift_prevention": {"exec_lockdown_white_list": None}},
        last_applied=["drift_prevention.exec_lockdown_white_list"],
    )
    assert plan.is_empty()


# --------------------------------------------------------------------------- #
# apply_to -- building the object to PUT
# --------------------------------------------------------------------------- #


def test_apply_to_preserves_everything_we_do_not_own():
    """Aqua's update replaces the object, so unowned fields must survive."""
    actual = {
        "name": "devtest-baseline",
        "enforce": True,
        "author": "System",
        "digest": "abc123",
        "malware_scan_options": {"enabled": True, "action": "alert"},
        "container_exec": {
            "block_container_exec": False,
            "enabled": False,
            "container_exec_proc_white_list": ["/usr/bin/env"],
        },
    }
    plan = three_way_diff(
        desired={"enforce": False, "container_exec": {"block_container_exec": True}},
        actual=actual,
        last_applied=["enforce"],
    )
    merged = plan.apply_to(actual)

    assert merged["enforce"] is False
    assert merged["container_exec"]["block_container_exec"] is True
    # Untouched:
    assert merged["author"] == "System"
    assert merged["digest"] == "abc123"
    assert merged["malware_scan_options"] == {"enabled": True, "action": "alert"}
    assert merged["container_exec"]["container_exec_proc_white_list"] == ["/usr/bin/env"]


def test_apply_to_does_not_mutate_the_server_object():
    actual = {"enforce": True}
    plan = three_way_diff({"enforce": False}, actual, ["enforce"])
    plan.apply_to(actual)
    assert actual == {"enforce": True}


def test_retain_is_the_default_and_leaves_released_values_alone():
    """Tidying a YAML file must not silently switch a security control off."""
    actual = {"enforce": False, "block_fileless_exec": True}
    plan = three_way_diff(
        desired={"enforce": False},
        actual=actual,
        last_applied=["enforce", "block_fileless_exec"],
    )
    assert plan.release_policy is ReleasePolicy.RETAIN

    merged = plan.apply_to(actual)
    assert merged["block_fileless_exec"] is True  # still on
    assert plan.is_empty()  # nothing to send to Aqua


def test_reset_removes_released_fields_when_explicitly_chosen():
    actual = {"enforce": False, "block_fileless_exec": True}
    plan = three_way_diff(
        desired={"enforce": False},
        actual=actual,
        last_applied=["enforce", "block_fileless_exec"],
        release_policy=ReleasePolicy.RESET,
    )
    merged = plan.apply_to(actual)

    assert "block_fileless_exec" not in merged
    assert not plan.is_empty()


def test_reset_prunes_a_container_left_empty():
    actual = {"enforce": False, "container_exec": {"block_container_exec": True}}
    plan = three_way_diff(
        desired={"enforce": False},
        actual=actual,
        last_applied=["enforce", "container_exec.block_container_exec"],
        release_policy=ReleasePolicy.RESET,
    )
    merged = plan.apply_to(actual)
    assert "container_exec" not in merged


def test_releasing_a_field_already_gone_from_the_server_is_not_a_change():
    plan = three_way_diff(
        desired={"enforce": False},
        actual={"enforce": False},
        last_applied=["enforce", "some_field_aqua_removed"],
    )
    assert plan.changes == []


# --------------------------------------------------------------------------- #
# Against a real recorded Aqua response
# --------------------------------------------------------------------------- #


def test_no_drift_against_the_real_object_when_desired_matches(real_policy):
    """The adoption property, on real data with all 72 of Aqua's fields present."""
    desired = {
        "enforce": real_policy["enforce"],
        "block_disallowed_images": real_policy["block_disallowed_images"],
        "container_exec": {
            "block_container_exec": real_policy["container_exec"]["block_container_exec"],
            "enabled": real_policy["container_exec"]["enabled"],
        },
    }
    plan = three_way_diff(
        desired=desired,
        actual=real_policy,
        last_applied=[
            "enforce",
            "block_disallowed_images",
            "container_exec.block_container_exec",
            "container_exec.enabled",
        ],
    )
    assert plan.is_empty(), [c.render() for c in plan.changes]


def test_a_single_control_change_produces_exactly_one_field_change(real_policy):
    """The demo: flip one control, see one line, nothing else."""
    desired = {"block_disallowed_images": False}
    plan = three_way_diff(
        desired=desired,
        actual=real_policy,
        last_applied=["block_disallowed_images"],
    )
    assert len(plan.changes) == 1
    change = plan.changes[0]
    assert change.path == "block_disallowed_images"
    assert change.before is True
    assert change.after is False
    assert "block_disallowed_images" in change.render()


def test_console_drift_on_the_real_object_is_caught(real_policy):
    """Step 6 of the demo: someone changes it back in the console."""
    tampered = json.loads(json.dumps(real_policy))
    tampered["block_disallowed_images"] = True

    plan = three_way_diff(
        desired={"block_disallowed_images": False},
        actual=tampered,
        last_applied=["block_disallowed_images"],
    )
    assert not plan.is_empty()
    assert plan.changes[0].change is ChangeType.UPDATE

    reverted = plan.apply_to(tampered)
    assert reverted["block_disallowed_images"] is False
    # and the other 71 fields are untouched
    assert len(reverted) == len(tampered)


# --------------------------------------------------------------------------- #
# Plan reporting
# --------------------------------------------------------------------------- #


def test_plan_is_falsey_when_it_would_change_nothing():
    assert not Plan()
    assert not three_way_diff({"a": 1}, {"a": 1}, ["a"])
    assert three_way_diff({"a": 2}, {"a": 1}, ["a"])


def test_change_rendering_distinguishes_the_three_kinds():
    plan = three_way_diff(
        desired={"enforce": False, "new_field": True},
        actual={"enforce": True, "old_field": "x"},
        last_applied=["enforce", "old_field"],
    )
    rendered = " | ".join(c.render() for c in plan.changes)
    assert "!" in rendered   # update
    assert "+" in rendered   # add
    assert "~" in rendered   # release
