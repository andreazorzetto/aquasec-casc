"""The reconciler end to end, against a fake Aqua.

The fake exists so every rule below is exercised without a tenant -- including
the failure paths (a create that works followed by a delete that does not) which
are impossible to arrange reliably against a live system and are exactly where
an orphan-and-duplicate incident would come from.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from aqua_casc.reconcile import (
    ClientError,
    FileStateBackend,
    Options,
    Outcome,
    ReleasePolicy,
    reconcile,
    reconcile_all,
)
from aqua_casc.schema import load_document, registry


class FakeAqua:
    """An in-memory Aqua, keyed by name like the real one."""

    def __init__(self, objects: dict[str, dict] | None = None) -> None:
        self.objects = dict(objects or {})
        self.calls: list[tuple[str, str]] = []
        self.fail_on: dict[str, ClientError] = {}

    def _maybe_fail(self, op: str) -> None:
        if op in self.fail_on:
            raise self.fail_on[op]

    def get(self, kind, name):
        self.calls.append(("get", name))
        self._maybe_fail("get")
        obj = self.objects.get(name)
        return dict(obj) if obj is not None else None

    def create(self, kind, body):
        self.calls.append(("create", body.get("name", "?")))
        self._maybe_fail("create")
        name = body["name"]
        # A real Aqua fills in defaults on create; mimic that so the test is
        # not accidentally easier than reality.
        stored = {"author": "System", "digest": "generated", "id": 4471, **body}
        self.objects[name] = stored
        return dict(stored)

    def update(self, kind, name, body):
        self.calls.append(("update", name))
        self._maybe_fail("update")
        self.objects[name] = dict(body)
        return dict(body)

    def delete(self, kind, name):
        self.calls.append(("delete", name))
        self._maybe_fail("delete")
        self.objects.pop(name, None)


def policy(body: str):
    return load_document(yaml.safe_load(textwrap.dedent(body).lstrip()), "test.yaml")[0]


DEVTEST = """
    apiVersion: config.aquasec.com/v1alpha1
    kind: RuntimePolicy
    metadata:
      name: devtest-baseline
    spec:
      enforce: false
      applicationScopes: ["DevTest"]
      controls:
        blockNonCompliantImages: false
"""


@pytest.fixture
def kind():
    return registry.get("RuntimePolicy")


@pytest.fixture
def state(tmp_path):
    return FileStateBackend(tmp_path).load()


def server_policy(**overrides) -> dict:
    """A realistic server object: far more fields than we manage."""
    base = {
        "name": "devtest-baseline",
        "id": 4471,
        "enforce": False,
        "enabled": True,
        "application_scopes": ["DevTest"],
        "block_disallowed_images": False,
        "author": "someone@example.com",
        "digest": "abc123",
        "lastupdate": 1725000000,
        "is_ootb_policy": False,
        "malware_scan_options": {"enabled": True},
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Create
# --------------------------------------------------------------------------- #


def test_absent_object_is_created(kind, state):
    client = FakeAqua()
    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.CREATED
    assert client.objects["devtest-baseline"]["block_disallowed_images"] is False
    assert state.get("RuntimePolicy", "devtest-baseline").aquaName == "devtest-baseline"


def test_create_is_only_planned_in_dry_run(kind, state):
    client = FakeAqua()
    result = reconcile(policy(DEVTEST), kind, state, client, Options(dry_run=True))

    assert result.outcome is Outcome.PLANNED
    assert result.reason == "CreateRequired"
    assert client.objects == {}
    assert state.get("RuntimePolicy", "devtest-baseline") is None


def test_create_records_the_numeric_id_for_traceability(kind, state):
    client = FakeAqua()
    reconcile(policy(DEVTEST), kind, state, client)
    assert state.get("RuntimePolicy", "devtest-baseline").aquaId == 4471


def test_a_failed_create_is_reported_not_raised(kind, state):
    client = FakeAqua()
    client.fail_on["create"] = ClientError("HTTP 403 forbidden", status=403)

    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.FAILED
    assert "403" in result.message
    assert state.get("RuntimePolicy", "devtest-baseline") is None


# --------------------------------------------------------------------------- #
# Adoption -- the property the whole tool is judged on
# --------------------------------------------------------------------------- #


def test_adopting_an_existing_policy_changes_nothing(kind, state):
    """export -> commit -> apply must be a no-op. This is the acceptance test."""
    client = FakeAqua({"devtest-baseline": server_policy()})

    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.IN_SYNC
    assert ("update", "devtest-baseline") not in client.calls


def test_adoption_records_state_so_the_next_diff_is_three_way(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    recorded = state.get("RuntimePolicy", "devtest-baseline")
    assert recorded is not None
    assert "block_disallowed_images" in recorded.lastAppliedFields
    assert "author" not in recorded.lastAppliedFields  # never ours


def test_applying_twice_is_idempotent(kind, state):
    client = FakeAqua()

    first = reconcile(policy(DEVTEST), kind, state, client)
    second = reconcile(policy(DEVTEST), kind, state, client)

    assert first.outcome is Outcome.CREATED
    assert second.outcome is Outcome.IN_SYNC


# --------------------------------------------------------------------------- #
# Update and drift
# --------------------------------------------------------------------------- #


def test_console_drift_is_reverted_without_touching_anything_else(kind, state):
    """Demo step 6: someone flips it back in the console."""
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)          # adopt

    client.objects["devtest-baseline"]["block_disallowed_images"] = True
    result = reconcile(policy(DEVTEST), kind, state, client)  # correct

    assert result.outcome is Outcome.UPDATED
    assert len(result.plan.changes) == 1
    assert result.plan.changes[0].path == "block_disallowed_images"

    stored = client.objects["devtest-baseline"]
    assert stored["block_disallowed_images"] is False
    assert stored["author"] == "someone@example.com"        # untouched
    assert stored["malware_scan_options"] == {"enabled": True}


def test_a_console_edit_to_a_field_we_do_not_own_is_left_alone(kind, state):
    """The point of the three-way diff."""
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    client.objects["devtest-baseline"]["block_fileless_exec"] = True
    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.IN_SYNC
    assert client.objects["devtest-baseline"]["block_fileless_exec"] is True


def test_report_only_detects_drift_and_changes_nothing(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    report_only = policy(DEVTEST + "      enforcement: ReportOnly\n")
    client.objects["devtest-baseline"]["block_disallowed_images"] = True
    result = reconcile(report_only, kind, state, client)

    assert result.outcome is Outcome.DRIFT_DETECTED
    assert client.objects["devtest-baseline"]["block_disallowed_images"] is True
    assert ("update", "devtest-baseline") not in client.calls


def test_dry_run_never_writes(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy(block_disallowed_images=True)})
    result = reconcile(policy(DEVTEST), kind, state, client, Options(dry_run=True))

    assert result.outcome is Outcome.PLANNED
    assert client.objects["devtest-baseline"]["block_disallowed_images"] is True
    assert not any(c[0] in ("update", "create", "delete") for c in client.calls)


def test_a_failed_update_leaves_state_untouched(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)
    before = state.get("RuntimePolicy", "devtest-baseline").observedGeneration

    client.objects["devtest-baseline"]["block_disallowed_images"] = True
    client.fail_on["update"] = ClientError("HTTP 500")
    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.FAILED
    assert state.get("RuntimePolicy", "devtest-baseline").observedGeneration == before


# --------------------------------------------------------------------------- #
# Rename
# --------------------------------------------------------------------------- #


RENAMED_AUDIT = """
    apiVersion: config.aquasec.com/v1alpha1
    kind: RuntimePolicy
    metadata:
      name: devtest-baseline
    spec:
      applicationScopes: ["DevTest"]
      aquaName: devtest-baseline-v2
      enforce: false
      controls:
        blockNonCompliantImages: false
"""

RENAMED_ENFORCING = RENAMED_AUDIT.replace("enforce: false", "enforce: true")


def test_rename_in_audit_mode_creates_then_deletes(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    result = reconcile(policy(RENAMED_AUDIT), kind, state, client)

    assert result.outcome is Outcome.RENAMED
    assert "devtest-baseline-v2" in client.objects
    assert "devtest-baseline" not in client.objects

    ops = [c for c in client.calls if c[0] in ("create", "delete")]
    assert ops == [("create", "devtest-baseline-v2"), ("delete", "devtest-baseline")], (
        "must create before deleting, so a failure leaves the policy in place"
    )
    assert state.get("RuntimePolicy", "devtest-baseline").aquaName == "devtest-baseline-v2"


def test_rename_in_enforce_mode_is_blocked_by_default(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    result = reconcile(policy(RENAMED_ENFORCING), kind, state, client)

    assert result.outcome is Outcome.BLOCKED
    assert result.reason == "RenameInEnforceMode"
    assert "--allow-rename" in result.message
    assert client.objects.keys() == {"devtest-baseline"}


def test_rename_in_enforce_mode_proceeds_with_the_flag(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    result = reconcile(
        policy(RENAMED_ENFORCING), kind, state, client, Options(allow_rename=True)
    )

    assert result.outcome is Outcome.RENAMED
    assert "devtest-baseline-v2" in client.objects


def test_a_rename_whose_delete_fails_reports_the_duplicate_loudly(kind, state):
    """The orphan-and-duplicate case. It must never pass quietly."""
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)
    client.fail_on["delete"] = ClientError("HTTP 409 conflict")

    result = reconcile(policy(RENAMED_AUDIT), kind, state, client)

    assert result.outcome is Outcome.FAILED
    assert "BOTH" in result.message
    assert "devtest-baseline" in client.objects
    assert "devtest-baseline-v2" in client.objects
    # State points at the new one, so the next run does not create a third.
    assert state.get("RuntimePolicy", "devtest-baseline").aquaName == "devtest-baseline-v2"


def test_a_rename_whose_create_fails_leaves_the_original_alone(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)
    client.fail_on["create"] = ClientError("HTTP 400 bad request")

    result = reconcile(policy(RENAMED_AUDIT), kind, state, client)

    assert result.outcome is Outcome.FAILED
    assert "left untouched" in result.message
    assert client.objects.keys() == {"devtest-baseline"}
    assert state.get("RuntimePolicy", "devtest-baseline").aquaName == "devtest-baseline"


def test_rename_is_only_described_in_dry_run(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    result = reconcile(policy(RENAMED_AUDIT), kind, state, client, Options(dry_run=True))

    assert result.outcome is Outcome.PLANNED
    assert result.reason == "RenameRequired"
    assert client.objects.keys() == {"devtest-baseline"}


def test_an_unmanaged_object_with_a_new_name_is_a_create_not_a_rename(kind, state):
    """No state entry means no ownership claim."""
    client = FakeAqua()
    result = reconcile(policy(RENAMED_AUDIT), kind, state, client)

    assert result.outcome is Outcome.CREATED
    assert "devtest-baseline-v2" in client.objects


# --------------------------------------------------------------------------- #
# Managed object vanished
# --------------------------------------------------------------------------- #


def test_a_managed_object_missing_from_aqua_blocks_rather_than_recreating(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)

    del client.objects["devtest-baseline"]
    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.BLOCKED
    assert result.reason == "ManagedObjectMissing"
    assert "--allow-recreate-missing" in result.message
    assert client.objects == {}


def test_it_recreates_with_the_explicit_flag(kind, state):
    client = FakeAqua({"devtest-baseline": server_policy()})
    reconcile(policy(DEVTEST), kind, state, client)
    del client.objects["devtest-baseline"]

    result = reconcile(
        policy(DEVTEST), kind, state, client, Options(allow_recreate_missing=True)
    )

    assert result.outcome is Outcome.CREATED
    assert "devtest-baseline" in client.objects


# --------------------------------------------------------------------------- #
# Whole-run behaviour
# --------------------------------------------------------------------------- #


def test_exit_codes_follow_terraform_convention(kind, state, tmp_path):
    client = FakeAqua()

    planned = reconcile_all(
        [policy(DEVTEST)], registry.get, state, client, Options(dry_run=True)
    )
    assert planned.exit_code() == 2  # changes present

    applied = reconcile_all([policy(DEVTEST)], registry.get, state, client)
    assert applied.exit_code() == 0  # applied, nothing outstanding

    again = reconcile_all([policy(DEVTEST)], registry.get, state, client)
    assert again.exit_code() == 0  # in sync


def test_a_failure_gives_exit_code_one_not_two(kind, state):
    client = FakeAqua()
    client.fail_on["create"] = ClientError("HTTP 500")

    summary = reconcile_all([policy(DEVTEST)], registry.get, state, client)
    assert summary.exit_code() == 1


def test_one_failure_does_not_abandon_the_rest(kind, state):
    other = DEVTEST.replace("devtest-baseline", "other-policy")
    client = FakeAqua()
    client.fail_on["get"] = ClientError("boom")

    summary = reconcile_all(
        [policy(DEVTEST), policy(other)], registry.get, state, client
    )
    assert len(summary.results) == 2
    assert all(r.failed for r in summary.results)


def test_orphans_are_reported_and_never_deleted(kind, state):
    client = FakeAqua()
    reconcile_all([policy(DEVTEST)], registry.get, state, client)

    # The file disappears from Git.
    summary = reconcile_all([], registry.get, state, client)

    orphans = summary.of(Outcome.BLOCKED)
    assert len(orphans) == 1
    assert orphans[0].reason == "Orphaned"
    assert "devtest-baseline" in client.objects  # still there
    assert summary.exit_code() == 2


def test_state_is_committed_on_apply_and_not_on_dry_run(kind, state, tmp_path):
    client = FakeAqua()

    reconcile_all([policy(DEVTEST)], registry.get, state, client, Options(dry_run=True))
    assert not state.path.exists()

    reconcile_all([policy(DEVTEST)], registry.get, state, client)
    assert state.path.exists()


def test_summary_line_always_shows_the_core_counts(kind, state):
    client = FakeAqua()
    summary = reconcile_all([policy(DEVTEST)], registry.get, state, client)

    line = summary.summary_line()
    assert "1 created" in line
    assert "0 unchanged" in line
    assert "0 deleted" in line


def test_release_policy_defaults_to_retain(kind, state):
    """Removing a control from YAML must not silently switch it off in Aqua."""
    with_control = DEVTEST + "        blockFilelessExec: true\n"
    client = FakeAqua()

    reconcile(policy(with_control), kind, state, client)
    assert client.objects["devtest-baseline"]["block_fileless_exec"] is True

    result = reconcile(policy(DEVTEST), kind, state, client)

    assert result.outcome is Outcome.IN_SYNC
    assert client.objects["devtest-baseline"]["block_fileless_exec"] is True
    assert "block_fileless_exec" not in state.get(
        "RuntimePolicy", "devtest-baseline"
    ).lastAppliedFields


def test_reset_release_policy_removes_the_field_when_asked(kind, state):
    with_control = DEVTEST + "        blockFilelessExec: true\n"
    client = FakeAqua()
    reconcile(policy(with_control), kind, state, client)

    result = reconcile(
        policy(DEVTEST), kind, state, client,
        Options(release_policy=ReleasePolicy.RESET),
    )

    assert result.outcome is Outcome.UPDATED
    assert "block_fileless_exec" not in client.objects["devtest-baseline"]
