"""Destroy: delete what this instance manages -- and only that."""

from __future__ import annotations

from aquasec_casc.reconcile import ClientError, DestroyOptions, Outcome, destroy_all, marker

from .test_engine import ME, FakeAqua, policy, server

OTHER = "team-b"


def tenant():
    return FakeAqua({
        "devtest-baseline": server("devtest-baseline"),
        "prod-baseline": server("prod-baseline"),
        "theirs": server("theirs", description=marker.compose("Theirs", OTHER)),
        "console": server("console", description="Made in the console"),
        "Aqua default runtime policy": server("Aqua default runtime policy", is_ootb_policy=True,
                                              application_scopes=["Global"]),
    })


def dopts(resources=None, **kw):
    return DestroyOptions(instance=ME, resources=None if resources is None else tuple(resources), **kw)


def outcomes(summary):
    return {r.aqua_name: r.outcome for r in summary.results}


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def test_with_files_only_what_they_describe_is_destroyed():
    aqua = tenant()
    summary = destroy_all(aqua, dopts([policy("devtest-baseline")]))
    assert outcomes(summary) == {"devtest-baseline": Outcome.DELETED}
    assert "prod-baseline" in aqua.objects                 # marked, but not in the files


def test_without_files_everything_this_instance_marks_is_destroyed():
    aqua = tenant()
    summary = destroy_all(aqua, dopts())
    assert outcomes(summary) == {"devtest-baseline": Outcome.DELETED,
                                 "prod-baseline": Outcome.DELETED,
                                 "Aqua default runtime policy": Outcome.RELEASED}
    assert set(aqua.objects) == {"theirs", "console", "Aqua default runtime policy"}


def test_name_patterns_narrow_either_scope():
    aqua = tenant()
    summary = destroy_all(aqua, dopts(names=("prod-*",)))
    assert outcomes(summary) == {"prod-baseline": Outcome.DELETED}


# --------------------------------------------------------------------------- #
# What is never deleted
# --------------------------------------------------------------------------- #

def test_a_file_naming_someone_elses_object_is_blocked():
    aqua = tenant()
    summary = destroy_all(aqua, dopts([policy("theirs"), policy("console")]))
    assert outcomes(summary) == {"theirs": Outcome.BLOCKED, "console": Outcome.BLOCKED}
    messages = {r.aqua_name: r.message for r in summary.results}
    assert "team-b" in messages["theirs"] and "no ownership marker" in messages["console"]
    assert aqua.writes() == []


def test_shipped_policies_are_released_not_deleted():
    aqua = tenant()
    name = "Aqua default runtime policy"
    before = dict(aqua.objects[name])
    destroy_all(aqua, dopts(names=(name,)))
    after = aqua.objects[name]
    assert marker.owner(after["description"]) is None
    assert {k: v for k, v in after.items() if k != "description"} == \
           {k: v for k, v in before.items() if k != "description"}
    assert ("delete", name) not in aqua.calls


def test_an_object_already_gone_is_not_an_error():
    summary = destroy_all(FakeAqua(), dopts([policy("devtest-baseline")]))
    (r,) = summary.results
    assert r.outcome is Outcome.IN_SYNC and r.reason == "Absent"
    assert summary.exit_code() == 0


# --------------------------------------------------------------------------- #
# Dry run and failures
# --------------------------------------------------------------------------- #

def test_dry_run_writes_nothing_and_says_what_would_happen():
    aqua = tenant()
    summary = destroy_all(aqua, dopts(dry_run=True))
    assert aqua.writes() == []
    assert {r.aqua_name: r.action for r in summary.of(Outcome.PLANNED)} == {
        "devtest-baseline": "delete", "prod-baseline": "delete",
        "Aqua default runtime policy": "release"}


def test_one_failed_delete_does_not_stop_the_rest():
    aqua = tenant()
    original = aqua.delete

    def delete(kind, name):
        if name == "devtest-baseline":
            raise ClientError("HTTP 500")
        return original(kind, name)

    aqua.delete = delete
    summary = destroy_all(aqua, dopts())
    assert [r.aqua_name for r in summary.failed] == ["devtest-baseline"]
    assert "prod-baseline" not in aqua.objects
    assert summary.exit_code() == 1
