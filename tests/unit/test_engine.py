"""The stateless reconciler, end to end against a fake Aqua.

Covers the decisions the design rests on: ownership by marker, adoption,
recreation of console deletions, GitOps-style deletion of orphans with its
guardrails, the boundary between instances, and built-in policies.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from aquasec_casc.reconcile import ClientError, Options, Outcome, reconcile, reconcile_all
from aquasec_casc.reconcile import marker
from aquasec_casc.schema import load_document, registry

KIND = registry.get("RuntimePolicy")
ME = "platform"
MARK = marker.marker(ME)


class FakeAqua:
    """An in-memory Aqua, keyed by name like the real one."""

    def __init__(self, objects: dict[str, dict] | None = None) -> None:
        self.objects = {k: dict(v) for k, v in (objects or {}).items()}
        self.calls: list[tuple[str, str]] = []
        self.fail_on: dict[str, ClientError] = {}

    def _maybe_fail(self, op):
        if op in self.fail_on:
            raise self.fail_on[op]

    def list(self, kind):
        self.calls.append(("list", "*"))
        self._maybe_fail("list")
        return [dict(o) for o in self.objects.values()]

    def get(self, kind, name):
        self.calls.append(("get", name))
        self._maybe_fail("get")
        o = self.objects.get(name)
        return dict(o) if o is not None else None

    def create(self, kind, body):
        self.calls.append(("create", body["name"]))
        self._maybe_fail("create")
        stored = {"author": "System", "is_ootb_policy": False, "id": 4471, **body}
        self.objects[body["name"]] = stored
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

    def writes(self):
        return [c for c in self.calls if c[0] in ("create", "update", "delete")]


def policy(name="devtest-baseline", **spec):
    spec = {"applicationScopes": ["DevTest"], "enforce": False,
            "controls": {"blockNonCompliantImages": False}, **spec}
    doc = {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy",
           "metadata": {"name": name}, "spec": spec}
    return load_document(doc, "test.yaml")[0]


def server(name="devtest-baseline", description=f"Dev/test\n\n{MARK}", **extra):
    base = {"name": name, "description": description, "enforce": False, "enabled": True,
            "application_scopes": ["DevTest"], "block_disallowed_images": False,
            "author": "someone@example.com", "is_ootb_policy": False,
            "malware_scan_options": {"enabled": False},
            "tripwire": {"enabled": True}}    # a setting the tool does not cover
    base.update(extra)
    return base


def opts(**kw):
    return Options(instance=ME, **kw)


# --------------------------------------------------------------------------- #
# Create, and recreate
# --------------------------------------------------------------------------- #

def test_a_missing_object_is_created_with_the_marker():
    aqua = FakeAqua()
    r = reconcile(policy(description="Dev/test"), KIND, aqua, opts())
    assert r.outcome is Outcome.CREATED
    assert aqua.objects["devtest-baseline"]["description"] == f"Dev/test\n\n{MARK}"


def test_created_without_a_description_gets_just_the_marker():
    aqua = FakeAqua()
    reconcile(policy(), KIND, aqua, opts())
    assert aqua.objects["devtest-baseline"]["description"] == MARK


def test_an_object_deleted_in_the_console_is_recreated():
    """No 'stop and ask': putting it back is the guardrail."""
    aqua = FakeAqua({"devtest-baseline": server()})
    reconcile(policy(), KIND, aqua, opts())
    del aqua.objects["devtest-baseline"]

    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.CREATED
    assert "devtest-baseline" in aqua.objects


def test_create_is_only_planned_in_a_dry_run():
    aqua = FakeAqua()
    r = reconcile(policy(), KIND, aqua, opts(dry_run=True))
    assert r.outcome is Outcome.PLANNED and r.action == "create"
    assert aqua.writes() == []


# --------------------------------------------------------------------------- #
# Adoption
# --------------------------------------------------------------------------- #

def test_an_unmarked_object_is_adopted_and_only_the_marker_changes():
    """The first apply after an export: ownership is recorded, nothing else moves."""
    aqua = FakeAqua({"devtest-baseline": server(description="Set in the console")})
    r = reconcile(policy(), KIND, aqua, opts())

    assert r.outcome is Outcome.ADOPTED
    assert [c.path for c in r.plan.changes] == ["description"]
    stored = aqua.objects["devtest-baseline"]
    assert stored["description"] == f"Set in the console\n\n{MARK}"   # console text kept
    assert stored["author"] == "someone@example.com"                  # untouched


def test_adoption_is_planned_as_such_in_a_dry_run():
    aqua = FakeAqua({"devtest-baseline": server(description="x")})
    r = reconcile(policy(), KIND, aqua, opts(dry_run=True))
    assert r.outcome is Outcome.PLANNED and r.action == "adopt"


def test_after_adoption_every_apply_is_a_no_op():
    aqua = FakeAqua({"devtest-baseline": server(description="x")})
    reconcile(policy(), KIND, aqua, opts())
    before = len(aqua.writes())
    assert reconcile(policy(), KIND, aqua, opts()).outcome is Outcome.IN_SYNC
    assert len(aqua.writes()) == before


def test_a_marker_removed_in_the_console_is_restored():
    aqua = FakeAqua({"devtest-baseline": server()})
    aqua.objects["devtest-baseline"]["description"] = "Dev/test"
    reconcile(policy(), KIND, aqua, opts())
    assert marker.owner(aqua.objects["devtest-baseline"]["description"]) == ME


def test_the_yaml_description_wins_when_it_is_set():
    aqua = FakeAqua({"devtest-baseline": server(description=f"old text\n\n{MARK}")})
    reconcile(policy(description="new text"), KIND, aqua, opts())
    assert aqua.objects["devtest-baseline"]["description"] == f"new text\n\n{MARK}"


# --------------------------------------------------------------------------- #
# Drift
# --------------------------------------------------------------------------- #

def test_drift_on_a_field_we_own_is_reverted_and_nothing_else_moves():
    aqua = FakeAqua({"devtest-baseline": server(block_disallowed_images=True)})
    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.UPDATED
    assert [c.path for c in r.plan.changes] == ["block_disallowed_images"]
    assert aqua.objects["devtest-baseline"]["tripwire"] == {"enabled": True}


def test_a_control_switched_on_in_the_console_is_switched_off():
    """The file is the whole policy: a control it leaves out is off."""
    aqua = FakeAqua({"devtest-baseline": server(block_fileless_exec=True)})
    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.UPDATED
    assert [(c.path, c.before, c.after) for c in r.plan.changes] == [
        ("block_fileless_exec", True, False)]
    assert aqua.objects["devtest-baseline"]["block_fileless_exec"] is False


def test_a_control_left_out_goes_off_with_its_gate_and_settings():
    aqua = FakeAqua({"devtest-baseline": server(
        container_exec={"enabled": True, "block_container_exec": True,
                        "container_exec_proc_white_list": ["sh"]},
        port_block={"enabled": True, "block_inbound_ports": ["22"], "block_outbound_ports": ["25"]},
        fork_guard_process_limit=12,
        block_outdated_images={"enabled": True, "threshold_value": 30, "threshold_unit": "days"})})
    doc = policy(controls={"portBlock": {"blockedInboundPorts": ["22"]}})
    reconcile(doc, KIND, aqua, opts())

    stored = aqua.objects["devtest-baseline"]
    assert stored["container_exec"] == {"enabled": False, "block_container_exec": False,
                                        "container_exec_proc_white_list": []}
    assert stored["port_block"] == {"enabled": True, "block_inbound_ports": ["22"],
                                    "block_outbound_ports": []}
    assert stored["fork_guard_process_limit"] == 0
    assert stored["block_outdated_images"] == {"enabled": False, "threshold_value": 0,
                                               "threshold_unit": ""}
    assert stored["block_disallowed_images"] is False       # was in the file


def test_settings_the_tool_does_not_cover_are_left_alone():
    aqua = FakeAqua({"devtest-baseline": server()})
    assert reconcile(policy(), KIND, aqua, opts()).outcome is Outcome.IN_SYNC
    assert aqua.objects["devtest-baseline"]["tripwire"] == {"enabled": True}


def test_a_control_this_aqua_version_lacks_is_not_sent():
    """Aqua drops fields it does not know, so writing one would never converge."""
    aqua = FakeAqua({"devtest-baseline": server()})
    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.IN_SYNC
    assert "secure_ai_discovery" not in aqua.objects["devtest-baseline"]


def test_bypass_scope_left_out_is_left_as_aqua_has_it():
    """Scope, not a control -- and on by default on the default container policy."""
    bypass = {"enabled": True, "scope": {"expression": "v1", "variables": [
        {"attribute": "kubernetes.namespace", "value": "kube-system"}]}}
    aqua = FakeAqua({"devtest-baseline": server(bypass_scope=bypass)})
    assert reconcile(policy(), KIND, aqua, opts()).outcome is Outcome.IN_SYNC
    assert aqua.objects["devtest-baseline"]["bypass_scope"] == bypass


def test_a_create_sends_only_what_the_file_says():
    """A new policy starts with every control off; there is nothing to switch off."""
    aqua = FakeAqua()
    reconcile(policy(), KIND, aqua, opts())
    body = dict(aqua.objects["devtest-baseline"])
    for server_owned in ("author", "is_ootb_policy", "id"):
        body.pop(server_owned)
    assert set(body) == {"name", "description", "enforce", "application_scopes",
                         "block_disallowed_images"}


def test_report_only_detects_and_changes_nothing():
    aqua = FakeAqua({"devtest-baseline": server(block_disallowed_images=True)})
    r = reconcile(policy(enforcement="ReportOnly"), KIND, aqua, opts())
    assert r.outcome is Outcome.DRIFT_DETECTED
    assert aqua.writes() == []


def test_report_only_does_not_create_a_missing_object():
    aqua = FakeAqua()
    r = reconcile(policy(enforcement="ReportOnly"), KIND, aqua, opts())
    assert r.outcome is Outcome.DRIFT_DETECTED and r.reason == "Missing"
    assert aqua.writes() == []


@pytest.mark.parametrize("existing", [True, False])
def test_a_dry_run_of_report_only_says_what_apply_will_do(existing):
    """diff must not promise an update or a create that apply will not make."""
    aqua = FakeAqua({"devtest-baseline": server(block_disallowed_images=True)} if existing else {})
    r = reconcile(policy(enforcement="ReportOnly"), KIND, aqua, opts(dry_run=True))
    assert r.outcome is Outcome.DRIFT_DETECTED and r.pending
    assert aqua.writes() == []


def test_a_failed_update_is_reported_not_raised():
    aqua = FakeAqua({"devtest-baseline": server(block_disallowed_images=True)})
    aqua.fail_on["update"] = ClientError("HTTP 500", status=500)
    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.FAILED and r.reason == "UpdateFailed"


# --------------------------------------------------------------------------- #
# Instances
# --------------------------------------------------------------------------- #

def test_an_object_owned_by_another_instance_is_refused():
    other = server(description="theirs\n\nmanaged-by: aquasec-casc/team-b", block_disallowed_images=True)
    aqua = FakeAqua({"devtest-baseline": other})
    r = reconcile(policy(), KIND, aqua, opts())
    assert r.outcome is Outcome.BLOCKED and r.reason == "OwnedByOtherInstance"
    assert "team-b" in r.message
    assert aqua.writes() == []


def test_another_instances_orphan_is_never_touched():
    aqua = FakeAqua({"theirs": server(name="theirs", description="managed-by: aquasec-casc/team-b")})
    summary = reconcile_all([policy()], aqua, opts())
    assert "theirs" in aqua.objects
    assert not [r for r in summary.results if r.name == "theirs"]


def test_unmarked_console_objects_are_never_orphans():
    aqua = FakeAqua({"console-made": server(name="console-made", description="hand made")})
    reconcile_all([policy()], aqua, opts())
    assert "console-made" in aqua.objects


# --------------------------------------------------------------------------- #
# Orphans and deletion
# --------------------------------------------------------------------------- #

def test_an_orphan_is_deleted_by_default():
    aqua = FakeAqua({"devtest-baseline": server(), "removed": server(name="removed")})
    summary = reconcile_all([policy()], aqua, opts())
    assert "removed" not in aqua.objects
    assert summary.of(Outcome.DELETED)[0].name == "removed"


def test_diff_lists_pending_deletions_and_exits_2():
    aqua = FakeAqua({"devtest-baseline": server(), "removed": server(name="removed")})
    summary = reconcile_all([policy()], aqua, opts(dry_run=True))
    planned = [r for r in summary.results if r.action == "delete"]
    assert [r.name for r in planned] == ["removed"]
    assert summary.exit_code(detailed=True) == 2
    assert "removed" in aqua.objects


def test_no_delete_holds_orphans_back():
    aqua = FakeAqua({"devtest-baseline": server(), "removed": server(name="removed")})
    summary = reconcile_all([policy()], aqua, opts(no_delete=True))
    orphan = summary.of(Outcome.ORPHANED)[0]
    assert orphan.reason == "DeletionDisabled" and "--no-delete" in orphan.message
    assert "removed" in aqua.objects
    assert summary.exit_code(detailed=False) == 0     # a routine apply passes
    assert summary.exit_code(detailed=True) == 2      # --detailed-exitcode notices


def test_a_git_rename_creates_the_new_object_before_deleting_the_old():
    """Aqua cannot rename: a rename is a new object plus an orphan, never a gap."""
    aqua = FakeAqua({"old-name": server(name="old-name")})
    summary = reconcile_all([policy(name="new-name")], aqua, opts())
    writes = aqua.writes()
    assert writes.index(("create", "new-name")) < writes.index(("delete", "old-name"))
    assert set(aqua.objects) == {"new-name"}
    assert summary.exit_code(detailed=True) == 0


def test_nothing_is_deleted_when_no_resources_were_loaded():
    """An empty directory is more likely a mistake than 'delete everything'."""
    aqua = FakeAqua({"a": server(name="a"), "b": server(name="b")})
    summary = reconcile_all([], aqua, opts())
    assert set(aqua.objects) == {"a", "b"}
    assert {r.reason for r in summary.results} == {"NoResourcesLoaded"}
    assert summary.exit_code(detailed=True) == 2


def test_allow_empty_permits_deleting_everything():
    aqua = FakeAqua({"a": server(name="a")})
    reconcile_all([], aqua, opts(allow_empty=True))
    assert aqua.objects == {}


def test_a_failed_orphan_scan_deletes_nothing_and_fails_the_run():
    aqua = FakeAqua({"removed": server(name="removed")})
    aqua.fail_on["list"] = ClientError("HTTP 500")
    summary = reconcile_all([policy()], aqua, opts())
    assert "removed" in aqua.objects
    assert summary.exit_code(detailed=False) == 1


def test_one_failure_does_not_stop_the_rest():
    aqua = FakeAqua()
    aqua.fail_on["create"] = ClientError("boom")
    summary = reconcile_all([policy(name="a"), policy(name="b")], aqua, opts())
    assert len([r for r in summary.results if r.failed]) == 2


def test_an_invalid_instance_name_is_rejected_before_anything_happens():
    aqua = FakeAqua()
    with pytest.raises(marker.InvalidInstance):
        reconcile_all([policy()], aqua, Options(instance="Not Valid"))
    assert aqua.calls == []


# --------------------------------------------------------------------------- #
# Built-ins
# --------------------------------------------------------------------------- #

PREDEFINED = "Aqua default runtime policy"
PREDEFINED_KIND = replace(KIND, predefined=frozenset({PREDEFINED}))


def builtin(name=PREDEFINED, **extra):
    fields = {"description": f"The default Aqua runtime policy\n\n{MARK}",
              "is_ootb_policy": True, "application_scopes": ["Global"], **extra}
    return server(name=name, **fields)


def adopt_builtin(name=PREDEFINED, **spec):
    return policy(name="aqua-default-runtime-policy", aquaName=name,
                  **{"applicationScopes": ["Global"], **spec})


def test_a_shipped_orphan_is_never_deleted_and_never_pending():
    aqua = FakeAqua({PREDEFINED: builtin(), "devtest-baseline": server()})
    summary = reconcile_all([policy()], aqua, Options(instance=ME, kinds=(PREDEFINED_KIND,)))
    orphan = summary.of(Outcome.ORPHANED)[0]
    assert orphan.reason == "ShippedNeverDeleted" and orphan.informational
    assert PREDEFINED in aqua.objects
    assert summary.exit_code(detailed=True) == 0


def test_a_scope_change_on_a_predefined_policy_is_reported_not_sent():
    aqua = FakeAqua({PREDEFINED: builtin(block_disallowed_images=True)})
    r = reconcile(adopt_builtin(applicationScopes=["DevTest"]), PREDEFINED_KIND, aqua, opts())

    assert r.outcome is Outcome.UPDATED                         # the rest still applies
    assert [c.path for c in r.plan.changes] == ["block_disallowed_images"]
    assert r.not_allowed and "application_scopes" in r.not_allowed[0]
    assert r.pending                                            # Git and Aqua still differ
    assert aqua.objects[PREDEFINED]["application_scopes"] == ["Global"]


def test_only_a_scope_change_on_a_predefined_policy_is_in_sync_but_pending():
    aqua = FakeAqua({PREDEFINED: builtin()})
    r = reconcile(adopt_builtin(applicationScopes=["DevTest"]), PREDEFINED_KIND, aqua, opts())
    assert r.outcome is Outcome.IN_SYNC and r.not_allowed and r.pending
    assert aqua.writes() == []


def test_a_shipped_template_not_on_the_predefined_list_can_change_scope():
    """e.g. scoping the shipped HIPAA policy to production is legitimate."""
    aqua = FakeAqua({"HIPAA": builtin(name="HIPAA")})
    r = reconcile(policy(name="hipaa", aquaName="HIPAA", applicationScopes=["AccProd"]),
                  PREDEFINED_KIND, aqua, opts())
    assert r.outcome is Outcome.UPDATED and not r.not_allowed
    assert aqua.objects["HIPAA"]["application_scopes"] == ["AccProd"]


def test_a_custom_policy_reusing_a_predefined_name_is_not_predefined():
    """Both the flag and the name are required."""
    aqua = FakeAqua({PREDEFINED: server(name=PREDEFINED, application_scopes=["Global"])})
    r = reconcile(adopt_builtin(applicationScopes=["DevTest"]), PREDEFINED_KIND, aqua, opts())
    assert not r.not_allowed
    assert aqua.objects[PREDEFINED]["application_scopes"] == ["DevTest"]


def test_a_predefined_policy_still_carries_the_marker():
    aqua = FakeAqua({PREDEFINED: builtin(description="The default Aqua runtime policy")})
    r = reconcile(adopt_builtin(), PREDEFINED_KIND, aqua, opts())
    assert r.outcome is Outcome.ADOPTED
    assert marker.owner(aqua.objects[PREDEFINED]["description"]) == ME


# --------------------------------------------------------------------------- #
# Run-level
# --------------------------------------------------------------------------- #

def test_exit_codes():
    aqua = FakeAqua()
    assert reconcile_all([policy()], aqua, opts(dry_run=True)).exit_code(detailed=True) == 2
    assert reconcile_all([policy()], aqua, opts()).exit_code(detailed=False) == 0
    assert reconcile_all([policy()], aqua, opts(dry_run=True)).exit_code(detailed=True) == 0


def test_summary_line_always_shows_the_core_counts():
    aqua = FakeAqua({"devtest-baseline": server(description="x")})
    line = reconcile_all([policy()], aqua, opts()).summary_line()
    assert "0 unchanged" in line and "1 adopted" in line and "0 deleted" in line


# --------------------------------------------------------------------------- #
# The real registry: defaults lock scope; Bypass Scope only on two defaults
# --------------------------------------------------------------------------- #

BYPASS = {"enabled": True, "expression": "v1",
          "variables": [{"attribute": "container.label", "name": "team", "value": "infra"}]}


def default_policy(name, **extra):
    return server(name=name, is_ootb_policy=True, application_scopes=["Global"],
                  bypass_scope={"enabled": False, "scope": {"expression": "", "variables": []}},
                  **extra)


def test_the_registry_locks_scope_on_the_three_defaults():
    for name in ("Aqua default runtime policy", "Aqua default host runtime policy",
                 "Aqua default function runtime policy"):
        aqua = FakeAqua({name: default_policy(name)})
        r = reconcile(policy(name="d", aquaName=name, applicationScopes=["DevTest"]), KIND, aqua, opts())
        assert r.not_allowed and "default policy" in r.not_allowed[0], name
        assert aqua.objects[name]["application_scopes"] == ["Global"]


@pytest.mark.parametrize("name", ["Aqua default runtime policy", "Aqua default host runtime policy"])
def test_bypass_scope_is_managed_on_the_two_defaults(name):
    aqua = FakeAqua({name: default_policy(name)})
    r = reconcile(policy(name="d", aquaName=name, applicationScopes=["Global"],
                         controls={"bypassScope": BYPASS}), KIND, aqua, opts())
    assert not r.not_allowed
    stored = aqua.objects[name]["bypass_scope"]
    assert stored["enabled"] is True and stored["scope"]["expression"] == "v1"


@pytest.mark.parametrize("name,obj", [
    ("Aqua default function runtime policy",
     default_policy("Aqua default function runtime policy")),           # a default, but not these
    ("HIPAA", default_policy("HIPAA")),                                  # a system policy
    ("devtest-baseline", server()),                                      # a custom policy
])
def test_bypass_scope_anywhere_else_is_not_allowed_and_not_sent(name, obj):
    aqua = FakeAqua({name: obj})
    r = reconcile(policy(name="p", aquaName=name, applicationScopes=["Global"],
                         controls={"bypassScope": BYPASS}), KIND, aqua, opts())
    assert any("bypass_scope" in n and "only available on" in n for n in r.not_allowed)
    assert (aqua.objects[name].get("bypass_scope") or {}).get("enabled") is not True


def test_bypass_scope_on_create_is_not_allowed_and_not_sent():
    aqua = FakeAqua()
    r = reconcile(policy(controls={"bypassScope": BYPASS}), KIND, aqua, opts())
    assert r.outcome is Outcome.CREATED and r.not_allowed
    assert "bypass_scope" not in aqua.objects["devtest-baseline"]


def test_the_marker_uses_the_tools_name():
    from aquasec_casc import TOOL_NAME
    assert marker.PREFIX == f"managed-by: {TOOL_NAME}/"
