"""Release: leave management without deleting anything, or hand over."""

from __future__ import annotations

import pytest

from aquasec_casc.reconcile import (
    ClientError,
    Options,
    Outcome,
    ReleaseOptions,
    marker,
    reconcile,
    reconcile_all,
    release_all,
)

from .test_engine import KIND, ME, FakeAqua, policy, server

OTHER = "team-b"


def ropts(**kw):
    return ReleaseOptions(instance=ME, **kw)


def tenant():
    return FakeAqua({
        "devtest-baseline": server("devtest-baseline"),
        "prod-baseline": server("prod-baseline", application_scopes=["AccProd"]),
        "theirs": server("theirs", description=f"Theirs\n\n{marker.marker(OTHER)}"),
        "console": server("console", description="Made in the console"),
    })


# --------------------------------------------------------------------------- #
# What changes, and what does not
# --------------------------------------------------------------------------- #

def test_only_the_marker_line_is_removed():
    aqua = tenant()
    before = dict(aqua.objects["devtest-baseline"])

    summary = release_all(aqua, ropts())

    after = aqua.objects["devtest-baseline"]
    assert after["description"] == "Dev/test"
    assert {k: v for k, v in after.items() if k != "description"} == \
           {k: v for k, v in before.items() if k != "description"}
    assert sorted(r.name for r in summary.of(Outcome.RELEASED)) == ["devtest-baseline", "prod-baseline"]


def test_other_instances_and_unmarked_objects_are_never_touched():
    aqua = tenant()
    release_all(aqua, ropts())
    assert ("update", "theirs") not in aqua.calls
    assert ("update", "console") not in aqua.calls


def test_a_description_that_was_only_the_marker_becomes_empty():
    aqua = FakeAqua({"p": server("p", description=marker.marker(ME))})
    release_all(aqua, ropts())
    assert aqua.objects["p"]["description"] == ""


def test_shipped_policies_are_released_too():
    """The tool never creates or deletes them, but it does mark them on adoption."""
    aqua = FakeAqua({"Aqua default runtime policy": server(
        "Aqua default runtime policy", is_ootb_policy=True, application_scopes=["Global"])})
    summary = release_all(aqua, ropts())
    assert summary.of(Outcome.RELEASED)
    assert marker.owner(aqua.objects["Aqua default runtime policy"]["description"]) is None


def test_name_patterns_narrow_the_release():
    aqua = tenant()
    summary = release_all(aqua, ropts(names=("prod-*",)))
    assert [r.name for r in summary.of(Outcome.RELEASED)] == ["prod-baseline"]
    assert marker.owner(aqua.objects["devtest-baseline"]["description"]) == ME


def test_dry_run_writes_nothing():
    aqua = tenant()
    summary = release_all(aqua, ropts(dry_run=True))
    assert aqua.writes() == []
    assert {r.action for r in summary.of(Outcome.PLANNED)} == {"release"}
    assert len(summary.of(Outcome.PLANNED)) == 2


def test_the_full_object_is_reread_before_the_write():
    """Update is a full replace: the body must be the object as Aqua has it now."""
    aqua = tenant()
    release_all(aqua, ropts(names=("devtest-baseline",)))
    assert aqua.calls.index(("get", "devtest-baseline")) < aqua.calls.index(("update", "devtest-baseline"))


# --------------------------------------------------------------------------- #
# Hand-over
# --------------------------------------------------------------------------- #

def test_to_rewrites_the_marker_for_the_other_instance():
    aqua = tenant()
    summary = release_all(aqua, ropts(to="team-c"))
    assert aqua.objects["devtest-baseline"]["description"] == f"Dev/test\n\n{marker.marker('team-c')}"
    assert {r.outcome for r in summary.results} == {Outcome.RELEASED}


def test_dry_run_hand_over_is_labelled_as_such():
    summary = release_all(tenant(), ropts(to="team-c", dry_run=True))
    assert {r.action for r in summary.results} == {"hand-over"}


@pytest.mark.parametrize("to", [ME, "Not Valid"])
def test_to_must_be_another_valid_instance(to):
    with pytest.raises(ValueError):
        release_all(tenant(), ropts(to=to))


# --------------------------------------------------------------------------- #
# Failures
# --------------------------------------------------------------------------- #

def test_an_object_changed_since_the_list_is_left_alone():
    aqua = tenant()
    original_get = aqua.get

    def get(kind, name):                     # someone hands it over in between
        obj = original_get(kind, name)
        obj["description"] = marker.compose("Dev/test", OTHER)
        return obj

    aqua.get = get
    summary = release_all(aqua, ropts(names=("devtest-baseline",)))
    assert summary.failed and summary.failed[0].reason == "Changed"
    assert aqua.writes() == []


def test_one_failed_write_does_not_stop_the_rest():
    aqua = tenant()
    original_update = aqua.update

    def update(kind, name, body):
        if name == "devtest-baseline":
            raise ClientError("HTTP 500")
        return original_update(kind, name, body)

    aqua.update = update
    summary = release_all(aqua, ropts())
    assert [r.name for r in summary.failed] == ["devtest-baseline"]
    assert [r.name for r in summary.of(Outcome.RELEASED)] == ["prod-baseline"]
    assert summary.exit_code() == 1


def test_a_failed_list_is_reported():
    aqua = tenant()
    aqua.fail_on["list"] = ClientError("HTTP 503")
    summary = release_all(aqua, ropts())
    assert summary.failed and summary.failed[0].reason == "ListFailed"


# --------------------------------------------------------------------------- #
# Why it exists: what happens next
# --------------------------------------------------------------------------- #

def test_after_release_removing_the_files_deletes_nothing():
    """The point of release: Git-driven deletion only ever touches marked objects."""
    aqua = tenant()
    release_all(aqua, ropts())
    summary = reconcile_all([], aqua, Options(instance=ME, allow_empty=True))
    assert summary.of(Outcome.DELETED) == []
    assert "devtest-baseline" in aqua.objects and "prod-baseline" in aqua.objects


def test_release_is_reversible_by_adopting_again():
    aqua = tenant()
    release_all(aqua, ropts())
    r = reconcile(policy(), KIND, aqua, Options(instance=ME))
    assert r.outcome is Outcome.ADOPTED


def test_after_hand_over_the_old_instance_is_blocked_and_the_new_one_in_sync():
    aqua = tenant()
    release_all(aqua, ropts(to="team-c", names=("devtest-baseline",)))
    assert reconcile(policy(), KIND, aqua, Options(instance=ME)).outcome is Outcome.BLOCKED
    assert reconcile(policy(), KIND, aqua, Options(instance="team-c")).outcome is Outcome.IN_SYNC


def test_hand_over_results_say_so():
    summary = release_all(tenant(), ropts(to="team-c", names=("devtest-baseline",)))
    (r,) = summary.results
    assert r.action == "hand-over" and "team-c" in r.message
