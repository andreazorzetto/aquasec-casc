"""What independent review found: each of these did the wrong thing once."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

import pytest

from aquasec_casc.cli.main import Out, main
from aquasec_casc.client.settings import ConfigError, settings_from_env
from aquasec_casc.export import export_kind
from aquasec_casc.reconcile import Options, Outcome, ReleaseOptions, marker, reconcile_all, release_all
from aquasec_casc.reconcile.client import ClientError
from aquasec_casc.schema import SchemaError, SchemaErrorGroup, load_dir, load_document, registry

from .test_assurance_policy import doc as assurance_doc
from .test_assurance_policy import stored
from .test_engine import KIND, ME, FakeAqua, opts, policy, server

ASSURANCE = registry.get("AssurancePolicy")


def mine(name, **fields):
    return server(name, description=marker.marker(ME), **fields)


def run(argv, aqua):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, connect=lambda profile: aqua)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
# Deletion
# --------------------------------------------------------------------------- #

def test_a_failed_rename_does_not_delete_the_old_policy():
    aqua = FakeAqua({"old": mine("old")})
    aqua.fail_on["create"] = ClientError("HTTP 400")
    summary = reconcile_all([policy("new")], aqua, opts())
    assert "old" in aqua.objects
    held = [r for r in summary.results if r.name == "old"][0]
    assert held.outcome is Outcome.ORPHANED and held.reason == "HeldBack"
    assert summary.exit_code(detailed=False) == 1


def test_a_new_report_only_policy_does_not_delete_the_old_one():
    aqua = FakeAqua({"old": mine("old")})
    reconcile_all([policy("new", enforcement="ReportOnly")], aqua, opts())
    assert "old" in aqua.objects


def test_a_blocked_policy_holds_deletions_back_too():
    aqua = FakeAqua({"old": mine("old"), "new": server("new", description=marker.marker("other"))})
    reconcile_all([policy("new")], aqua, opts())
    assert "old" in aqua.objects


def test_the_old_policy_goes_when_the_new_one_lands():
    aqua = FakeAqua({"old": mine("old")})
    reconcile_all([policy("new")], aqua, opts())
    assert "old" not in aqua.objects


def _write(path: Path, name: str) -> Path:
    path.write_text(textwrap.dedent(f"""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {{name: {name}}}
        spec: {{applicationScopes: [Global]}}
        """))
    return path


def test_one_file_deletes_nothing(tmp_path):
    aqua = FakeAqua({"other": mine("other")})
    file = _write(tmp_path / "one.yaml", "one")
    code, out, _ = run(["apply", "-f", str(file), "--instance", ME], aqua)
    assert code == 0 and "1 created" in out and "other" in aqua.objects


def test_a_directory_without_a_kind_deletes_nothing_of_that_kind(tmp_path):
    aqua = FakeAqua({"image/p": stored("p"), "gone": mine("gone")})
    _write(tmp_path / "one.yaml", "one")
    code, out, _ = run(["apply", "-f", str(tmp_path), "--instance", ME], aqua)
    assert code == 0 and "image/p" in aqua.objects and "gone" not in aqua.objects
    assert "no resources of this kind" in out
    run(["apply", "-f", str(tmp_path), "--instance", ME, "--allow-empty"], aqua)
    assert "image/p" not in aqua.objects


def test_export_that_leaves_an_object_out_fails(tmp_path):
    aqua = FakeAqua({"image/x": stored(
        "x", ignore_recently_published_vln=True, ignore_recently_published_vln_period=0)})
    code, _, err = run(["export", "--scope", "Global", "-o", str(tmp_path), "--instance", ME,
                        "--kind", "AssurancePolicy"], aqua)
    assert code == 1 and "apply of this folder deletes them" in err


def test_a_name_glob_does_not_match_the_type():
    aqua = FakeAqua({"host/prod": stored("prod", "host"), "image/prod": stored("prod"),
                     "host/h1": stored("h1", "host")})
    released = lambda *names: [r.name for r in release_all(
        aqua, ReleaseOptions(instance=ME, kinds=(ASSURANCE,), names=names, dry_run=True)).results]
    assert released("h*") == ["host/h1"]
    assert released("host/*") == ["host/h1", "host/prod"]
    assert released("prod") == ["host/prod", "image/prod"]


def test_a_rename_whose_new_policy_was_not_stored_right_keeps_the_old_one():
    class Forgetful(FakeAqua):
        def get(self, kind, name):
            obj = super().get(kind, name)
            if obj and name == "new":
                obj.pop("no_new_privileges", None)
            return obj

    aqua = Forgetful({"old": mine("old")})
    summary = reconcile_all([policy("new", controls={"limitNewPrivileges": True})], aqua, opts())
    assert "old" in aqua.objects and summary.exit_code(detailed=False) == 1


@pytest.mark.parametrize("command", [
    ["destroy", "-f", "", "--yes"], ["apply", "-f", ""], ["plan", "-f", " "], ["validate", "-f", ""],
    ["release", "-f", ""], ["export", "--scope", "Global", "-o", ""]])
def test_an_empty_path_is_refused(command, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    aqua = FakeAqua({"p": mine("p")})
    code, _, err = run([*command, "--instance", ME], aqua)
    assert code == 1 and "-f is empty" in err and "p" in aqua.objects


def test_export_warns_of_what_this_instance_manages_outside_the_filter(tmp_path):
    aqua = FakeAqua({"a": mine("a", application_scopes=["One"]), "b": mine("b", application_scopes=["Two"])})
    code, _, err = run(["export", "--scope", "One", "-o", str(tmp_path), "--instance", ME,
                        "--kind", "RuntimePolicy"], aqua)
    assert code == 0 and "an apply of this folder deletes them: b" in err


def test_what_a_type_does_not_offer_does_not_stop_adoption():
    aqua = FakeAqua({"host/p": stored("p", "host", description="d", fail_cicd=True, audit_on_failure=True)})
    result = export_kind(aqua, ASSURANCE, instance=ME)
    assert not result.skipped
    exported = result.exported[0]
    assert exported.left_out == ["actions.failCicd"]
    assert exported.document["spec"]["actions"] == {"createAuditMessage": True}
    resource = load_document(exported.document, "x")[0]
    r = reconcile_all([resource], aqua, Options(instance=ME, kinds=(ASSURANCE,), dry_run=True)).results[0]
    assert {c.path for c in r.plan.changes} == {"description", "fail_cicd"}


def test_warnings_leave_json_output_alone(tmp_path):
    import json
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: p
          annotations: {config.aquasec.com/allow-unknown-fields: "true"}
        spec: {applicationScopes: [Global], nope: 1}
        """))
    code, out, err = run(["validate", "-f", str(tmp_path), "--output", "json"], FakeAqua())
    assert code == 0 and json.loads(out)["valid"] and "dropped unknown field" in err


def test_two_documents_in_one_file_for_one_object_are_refused(tmp_path):
    path = tmp_path / "p.yaml"
    body = "apiVersion: config.aquasec.com/v1alpha1\nkind: RuntimePolicy\nmetadata: {name: p}\nspec: {applicationScopes: [Global]}\n"
    path.write_text(body + "---\n" + body)
    with pytest.raises((SchemaError, SchemaErrorGroup), match="duplicate"):
        load_dir(path)


def test_a_merge_key_may_be_overridden(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec:
          <<: &base {applicationScopes: [Global], enforce: false}
          enforce: true
        """))
    assert load_dir(tmp_path).resources[0].spec.enforce is True


def test_a_file_that_is_not_text_is_a_schema_error(tmp_path):
    (tmp_path / "p.yaml").write_bytes(b"\xff\xfe\x00")
    with pytest.raises((SchemaError, SchemaErrorGroup), match="cannot read"):
        load_dir(tmp_path)


def test_the_config_file_refuses_a_repeated_key_and_validate_checks_the_instance(tmp_path):
    _write(tmp_path / "p.yaml", "p")
    (tmp_path / "aquasec-casc.yaml").write_text("instance: a\ninstance: b\n")
    code, _, err = run(["plan", "-f", str(tmp_path)], FakeAqua())
    assert code == 1 and "written twice" in err
    (tmp_path / "aquasec-casc.yaml").write_text("instance: NOT VALID\n")
    code, _, _ = run(["validate", "-f", str(tmp_path)], FakeAqua())
    assert code == 1


def test_a_newline_in_a_server_name_cannot_forge_a_line():
    from aquasec_casc.cli.main import render_text
    from aquasec_casc.reconcile.result import Result, RunSummary
    stream = io.StringIO()
    render_text(RunSummary(results=[Result(kind="K", name="a\nb", outcome=Outcome.DELETED, message="c\nd")]),
                Out(stream, False), ME)
    assert stream.getvalue().splitlines()[0] == "- K/a b: deleted"
    assert stream.getvalue().splitlines()[1] == "    c d"


def test_bypass_scope_settings_switch_it_on():
    assert policy("p", controls={"bypassScope": {"expression": "v1", "variables": [
        {"attribute": "a", "value": "b"}]}}).spec.controls.bypassScope.enabled is True


# --------------------------------------------------------------------------- #
# Shipped, by key
# --------------------------------------------------------------------------- #

def test_a_custom_policy_with_a_name_shipped_on_another_type_is_custom():
    aqua = FakeAqua({"host/DTA": stored("DTA", "host", application_scopes=["Old"]),
                     "host/gone": stored("gone", "host")})
    resource = load_document(assurance_doc(name="x", aquaName="DTA", type_="host",
                                           applicationScopes=["New"]), "t")[0]
    r = reconcile_all([resource], aqua, Options(instance=ME, kinds=(ASSURANCE,))).results[0]
    assert not r.not_allowed and aqua.objects["host/DTA"]["application_scopes"] == ["New"]


# --------------------------------------------------------------------------- #
# What the file says
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("controls,needs", [
    ({"blockOutdatedImages": True}, "'ageThreshold' and 'unit'"),
    ({"blockOutdatedImages": {"ageThreshold": 6}}, "'unit'"),
])
def test_a_control_without_what_it_needs_is_refused(controls, needs):
    with pytest.raises(SchemaError, match=needs):
        policy("p", controls=controls)


@pytest.mark.parametrize("controls,needs", [
    ({"vulnerabilitySeverity": True}, "'severity'"),
    ({"vulnerabilityScore": True}, "'range'"),
    ({"dynamicThreatAnalysis": True}, "'severity'"),
])
def test_an_assurance_control_without_what_it_needs_is_refused(controls, needs):
    with pytest.raises(SchemaError, match=needs):
        load_document(assurance_doc(controls=controls), "t")


def test_a_bare_key_means_left_out():
    aqua = FakeAqua({"p": mine("p", no_new_privileges=True,
                               file_block={"enabled": False, "filename_block_list": ["/etc"]},
                               enable_fork_guard=False)})
    r = reconcile_all([policy("p", controls={"limitNewPrivileges": None, "fileBlock": None})],
                      aqua, opts(dry_run=True)).results[0]
    changed = {c.path: c.after for c in r.plan.changes}
    assert changed["no_new_privileges"] is False
    assert "file_block.filename_block_list" not in changed


def test_off_on_a_field_this_version_lacks_is_nothing_to_do():
    aqua = FakeAqua({"p": mine("p", block_disallowed_images=False)})
    r = reconcile_all([policy("p", controls={"blockNonCompliantImages": False, "fileBlock": False})],
                      aqua, opts()).results[0]
    assert r.outcome is Outcome.IN_SYNC, r.plan.changes


def test_a_key_written_twice_is_refused(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec:
          applicationScopes: [Global]
          controls: {blockContainerExec: true}
          controls: {limitNewPrivileges: true}
        """))
    with pytest.raises((SchemaError, SchemaErrorGroup), match="written twice"):
        load_dir(tmp_path)


def test_an_upper_case_suffix_is_still_a_file(tmp_path):
    _write(tmp_path / "p.YAML", "p")
    assert len(load_dir(tmp_path).resources) == 1


def test_removing_a_scope_variables_name_is_a_change():
    field_map = KIND.field_map
    canonical = {"spec": {"additionalScopeCriteria": {
        "expression": "v1", "variables": [{"attribute": "container.label", "value": "x"}]}}}
    api = field_map.to_api(canonical)["scope"]["variables"][0]
    assert api["name"] == ""
    from aquasec_casc.reconcile.diff import equivalent
    assert not equivalent([{"attribute": "container.label", "value": "x", "name": "team"}], [api])
    assert equivalent([{"attribute": "container.label", "value": "x"}], [api])


def test_settings_with_no_switch_are_not_exported_as_on():
    """Loading settings switches a control on, so a server with no switch for them
    would be changed by adopting its own export."""
    aqua = FakeAqua({"image/p": {k: v for k, v in stored(
        "p", auto_scan_time={"iteration": 1, "iteration_type": "once"}).items()}})
    exported = export_kind(aqua, ASSURANCE, instance=ME).exported[0]
    assert "autoScan" not in exported.document["spec"].get("controls", {})


# --------------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------------- #

ONPREM = {"AQUA_USER": "u", "AQUA_PASSWORD": "p"}


def test_a_password_does_not_go_over_plain_http():
    with pytest.raises(ConfigError, match="not HTTPS"):
        settings_from_env({**ONPREM, "AQUA_URL": "http://aqua.internal"})
    assert settings_from_env({**ONPREM, "AQUA_URL": "https://aqua.internal"})
    assert settings_from_env({**ONPREM, "AQUA_URL": "http://aqua.internal", "AQUA_TLS_INSECURE": "true"})


def test_a_console_url_from_the_token_must_be_https(monkeypatch):
    from aquasec_casc.client import aquasec_client as ac
    monkeypatch.setattr(ac, "get_console_urls_from_token", lambda t: {"console": "http://x"})
    creds = type("C", (), {"console_url": None})()
    with pytest.raises(ConfigError, match="not HTTPS"):
        ac._console_url(creds, "t")


def test_an_unknown_error_prints_its_type_and_not_its_text():
    from aquasec_casc.client.aquasec_client import _translate
    message = str(_translate(ValueError("Invalid header value: X-API-Key: s3cret"), "Sign-in"))
    assert "s3cret" not in message and "ValueError" in message


def test_server_text_cannot_drive_the_terminal():
    stream = io.StringIO()
    Out(stream, colour=False).line("evil\x1b[2Jname\x9b31m\nnext\tline")
    assert stream.getvalue() == "evil?[2Jname?31m\nnext\tline\n"


def test_export_does_not_write_through_a_symbolic_link(tmp_path):
    aqua = FakeAqua({"p": server("p", description="x")})
    victim = tmp_path / "victim"
    target = tmp_path / "out"
    target.mkdir()
    (target / "runtime-policy-p.yaml").symlink_to(victim)
    code, _, err = run(["export", "--scope", "DevTest", "-o", str(target), "--instance", ME, "--force",
                        "--kind", "RuntimePolicy"], aqua)
    assert code == 1 and "symbolic link" in err and not victim.exists()


def test_kubernetes_names_are_kept_when_there_are_no_flags():
    from aquasec_casc.client.aquasec_client import _kubernetes_read_view
    policy_ = {"assurance_type": "kubernetes", "kubernetes_controls_names": ["a"], "kubernetes_controls": []}
    assert _kubernetes_read_view(policy_)["kubernetes_controls_names"] == ["a"]


def test_no_credential_field_can_be_managed():
    from aquasec_casc.reconcile.state import StateError, assert_not_ownable
    for path in ("tripwire.user_password", "x.api_key", "x.secret_key"):
        with pytest.raises(StateError):
            assert_not_ownable([path])


def test_a_type_this_aqua_lacks_is_not_a_failure(monkeypatch):
    from aquasec.exceptions import ApiError

    from aquasec_casc.client import aquasec_client as ac

    def fake(server, token, assurance_type, timeout=None):
        if assurance_type == "cf_application":
            raise ApiError("no such type", status_code=404)
        return [{"name": "x", "assurance_type": "wrong"}] if assurance_type == "image" else []

    monkeypatch.setattr(ac.ap, "get_all_assurance_policies", fake)
    client = type("C", (), {"server": "s", "token": "t", "timeout": 1})()
    assert ac._all_assurance_policies(client) == [{"name": "x", "assurance_type": "image"}]


def test_a_failure_to_list_a_type_is_a_failure(monkeypatch):
    from aquasec.exceptions import ApiError

    from aquasec_casc.client import aquasec_client as ac

    def fake(*a, **k):
        raise ApiError("forbidden", status_code=403)

    monkeypatch.setattr(ac.ap, "get_all_assurance_policies", fake)
    client = type("C", (), {"server": "s", "token": "t", "timeout": 1})()
    with pytest.raises(ApiError):
        ac._all_assurance_policies(client)


# --------------------------------------------------------------------------- #
# Third round
# --------------------------------------------------------------------------- #

def test_a_runtime_policy_left_without_enabled_is_created_on():
    """Aqua's default would be off, with plan then saying it is in sync."""
    aqua = FakeAqua()
    resource = load_document({"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy",
                              "metadata": {"name": "p"}, "spec": {"applicationScopes": ["Global"]}}, "t")[0]
    reconcile_all([resource], aqua, opts())
    stored_ = aqua.objects["p"]
    assert (stored_["enabled"], stored_["enforce"], stored_["runtime_type"]) == (True, False, "container")


BARE = {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy",
        "metadata": {"name": "p"}, "spec": {"applicationScopes": ["Global"]}}


@pytest.mark.parametrize("held", [{"enabled": False}, {"enforce": True}, {"runtime_type": "host"}])
def test_a_default_that_differs_from_aqua_fails_and_changes_nothing(held):
    """Applying it could disable a policy, stop it enforcing, or change its type."""
    aqua = FakeAqua({"p": mine("p", **held)})
    summary = reconcile_all([load_document(BARE, "t")[0]], aqua, opts())
    r = summary.results[0]
    assert r.outcome is Outcome.FAILED and r.reason == "Unstated"
    assert "Write it in the file" in r.message and aqua.writes() == []
    assert summary.exit_code(detailed=False) == 1


def test_a_stated_value_is_applied_as_ever():
    aqua = FakeAqua({"p": mine("p", enabled=False, application_scopes=["Global"])})
    doc = {**BARE, "spec": {**BARE["spec"], "enabled": True}}
    reconcile_all([load_document(doc, "t")[0]], aqua, opts())
    assert aqua.objects["p"]["enabled"] is True


def test_a_policy_of_another_type_changes_nothing_at_all_and_holds_deletions_back():
    aqua = FakeAqua({"p": mine("p", runtime_type="container", no_new_privileges=True),
                     "gone": mine("gone")})
    doc = {**BARE, "spec": {**BARE["spec"], "runtimeType": "host"}}
    summary = reconcile_all([load_document(doc, "t")[0]], aqua, opts())
    assert summary.results[0].reason == "Immutable" and summary.exit_code(detailed=False) == 1
    assert aqua.writes() == [] and "gone" in aqua.objects
    plan = reconcile_all([load_document(doc, "t")[0]], aqua, opts(dry_run=True))
    assert plan.results[0].reason == "Immutable"


def test_no_credentials_with_a_read_only_home_is_the_help_text(monkeypatch):
    from aquasec import config

    from aquasec_casc.client.settings import resolve_settings

    def refuses(*a, **k):
        raise PermissionError("read-only")

    monkeypatch.setattr(config, "ConfigManager", refuses)
    with pytest.raises(ConfigError, match="No Aqua credentials"):
        resolve_settings(None, {})


def test_export_does_not_overwrite_another_objects_file(tmp_path):
    first = FakeAqua({"Foo Bar": server("Foo Bar", description="x", application_scopes=["A"])})
    args = ["export", "-o", str(tmp_path), "--instance", ME, "--kind", "RuntimePolicy", "--force"]
    assert run([*args, "--scope", "A"], first)[0] == 0
    second = FakeAqua({"foo-bar": server("foo-bar", description="x", application_scopes=["B"])})
    code, _, err = run([*args, "--scope", "B"], second)
    assert code == 1 and "a different object" in err
    assert "Foo Bar" in (tmp_path / "runtime-policy-foo-bar.yaml").read_text()
    assert run([*args, "--scope", "A"], first)[0] == 0          # the same one again is fine


def test_a_hand_over_warns_about_the_receiver_needing_the_files():
    aqua = FakeAqua({"p": mine("p")})
    code, _, err = run(["release", "--to", "other", "--instance", ME], aqua)
    assert code == 0 and "without them, that apply deletes the objects" in err


def test_quotes_in_a_password_are_kept_and_a_trailing_newline_is_not():
    settings = settings_from_env({"AQUA_USER": "u", "AQUA_PASSWORD": "\"pa'ss\"\n",
                                  "AQUA_URL": "https://aqua.internal"})
    assert settings.credentials.password == "\"pa'ss\""


def test_an_empty_directory_gets_a_warning(tmp_path):
    code, _, err = run(["plan", "-f", str(tmp_path), "--instance", ME], FakeAqua())
    assert code == 0 and "no resources in" in err


@pytest.mark.parametrize("name", [".", "..", " ", "x" * 129])
def test_a_name_aqua_cannot_address_is_refused(name):
    with pytest.raises(SchemaError, match="not a name Aqua can address"):
        policy("p", aquaName=name)


# --------------------------------------------------------------------------- #
# From following the docs literally
# --------------------------------------------------------------------------- #

def test_aqua_url_alone_is_not_quietly_replaced_by_a_profile():
    from aquasec_casc.client.settings import resolve_settings

    class Profiles:
        def list_profiles(self):
            return ["other-tenant"]

        def get_default_profile(self):
            return "other-tenant"

    with pytest.raises(ConfigError):
        resolve_settings(None, {"AQUA_URL": "https://aqua.internal"}, Profiles())


def test_a_usage_error_does_not_look_like_changes_pending():
    with pytest.raises(SystemExit) as stopped:
        main(["plan", "--detailed-exitcode"], stdout=io.StringIO(), stderr=io.StringIO())
    assert stopped.value.code == 1


def test_version_needs_no_command_and_no_credentials(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["--version"], stdout=io.StringIO(), stderr=io.StringIO())
    assert stopped.value.code == 0
    name, version = capsys.readouterr().out.split()
    assert name == "aquasec-casc" and version[0].isdigit()


def test_export_warns_only_of_what_has_no_file_here(tmp_path):
    (tmp_path / "b.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: b}
        spec: {applicationScopes: [Two]}
        """))
    aqua = FakeAqua({"a": mine("a", application_scopes=["One"]), "b": mine("b", application_scopes=["Two"])})
    code, _, err = run(["export", "--scope", "One", "-o", str(tmp_path), "--instance", ME,
                        "--kind", "RuntimePolicy"], aqua)
    assert code == 0 and "deletes them" not in err


# --------------------------------------------------------------------------- #
# Final review
# --------------------------------------------------------------------------- #

def _outdated(setting):
    return {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy",
            "metadata": {"name": "p"},
            "spec": {"applicationScopes": ["Global"], "controls": {"blockOutdatedImages": setting}}}


@pytest.mark.parametrize("threshold", [True, 0, -3, 1.5, "6"])
def test_an_age_threshold_is_a_positive_whole_number(threshold):
    with pytest.raises(SchemaError, match="ageThreshold"):
        load_document(_outdated({"ageThreshold": threshold, "unit": "months"}), "t.yaml")


def test_an_age_threshold_is_written_as_itself():
    assert load_document(_outdated({"ageThreshold": 6, "unit": "months"}), "t.yaml")


def test_an_age_threshold_of_nothing_is_fine_while_off():
    """Aqua holds 0 there on every policy."""
    load_document(_outdated({"enabled": False, "ageThreshold": 0, "unit": "months"}), "t.yaml")


def test_a_control_that_needs_a_list_needs_something_in_it():
    with pytest.raises(SchemaError, match="exploitTypes"):
        load_document(assurance_doc(controls={"vulnerabilityExploitabilityAndSeverity": {
            "exploitTypes": [], "severity": "high"}}), "t.yaml")


def test_exploitability_and_severity_is_for_images_only():
    controls = {"vulnerabilityExploitabilityAndSeverity": {"exploitTypes": ["dos"], "severity": "high"}}
    load_document(assurance_doc(controls=controls), "t.yaml")
    with pytest.raises(SchemaError, match="vulnerabilityExploitabilityAndSeverity"):
        load_document(assurance_doc(type_="cf_application", controls=controls), "t.yaml")


def test_a_file_it_cannot_use_is_an_error_and_not_a_traceback(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec: {applicationScopes: [Global]}
        """))

    def read_only(profile):
        raise OSError(30, "Read-only file system", "/tmp/.aqua")

    out, err = io.StringIO(), io.StringIO()
    code = main(["plan", "-f", str(tmp_path), "--instance", "x"], stdout=out, stderr=err, connect=read_only)
    assert code == 1
    assert "/tmp/.aqua" in err.getvalue() and "Read-only" in err.getvalue()


def test_the_lock_holds_every_pin():
    tomllib = pytest.importorskip("tomllib")
    root = Path(__file__).parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    lock = (root / "requirements.lock").read_text().lower()
    for pin in [*project["project"]["dependencies"], *project["build-system"]["requires"]]:
        assert f"{pin.lower().replace('_', '-')} \\" in lock, pin


def test_a_closed_output_says_so_and_not_that_a_file_failed(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec: {applicationScopes: [Global]}
        """))

    class Closed(io.StringIO):
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")

    err = io.StringIO()
    code = main(["plan", "-f", str(tmp_path), "--instance", "x"], stdout=Closed(), stderr=err,
                connect=lambda profile: FakeAqua({}))
    assert code == 1
    assert "output was closed" in err.getvalue() and "cannot use" not in err.getvalue()


def test_an_oserror_with_no_file_does_not_blame_a_file(tmp_path):
    def fails(profile):
        raise OSError("out of something")

    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec: {applicationScopes: [Global]}
        """))
    err = io.StringIO()
    assert main(["plan", "-f", str(tmp_path), "--instance", "x"], stdout=io.StringIO(), stderr=err, connect=fails) == 1
    assert "cannot use" not in err.getvalue() and "OSError" in err.getvalue()


def test_a_bad_setting_at_setup_is_an_error_and_not_a_traceback(monkeypatch):
    monkeypatch.setenv("AQUA_TIMEOUT", "abc")
    err = io.StringIO()
    assert main(["setup", "x"], stdout=io.StringIO(), stderr=err) == 1
    assert "AQUA_TIMEOUT" in err.getvalue()


def test_export_says_when_the_first_apply_does_more_than_add_the_marker(tmp_path):
    aqua = FakeAqua({"cf_application/t": stored("t", "cf_application", description="", exploitability_and_severity={
        "enabled": True, "severity": "high", "disallow_exploit_types": ["dos"]})})
    code, out, _ = run(["export", "--scope", "Global", "--kind", "AssurancePolicy", "-o", str(tmp_path),
                        "--instance", "x"], aqua)
    assert code == 0
    assert "does nothing on this type" in out and "switches off what is listed above" in out


def test_auto_scan_is_refused_on_kubernetes():
    with pytest.raises(SchemaError, match="autoScan"):
        load_document(assurance_doc(type_="kubernetes", controls={"autoScan": {"iterationType": "daily"}}), "t.yaml")
    load_document(assurance_doc(controls={"autoScan": {"iterationType": "daily"}}), "t.yaml")


# --------------------------------------------------------------------------- #
# Exclusions: not offered, and not unseen
# --------------------------------------------------------------------------- #

def _kinds():
    """Each kind: its fake Aqua holding ``critical``, its key, and its file."""
    runtime = (FakeAqua({"p": mine("p", exclude_application_scopes=["critical"])}), "p", policy("p"))
    file, _ = load_document(assurance_doc("p"), "t.yaml")
    assurance = (FakeAqua({"image/p": stored("p", exclude_application_scopes=["critical"])}), "image/p", file)
    return [runtime, assurance]


@pytest.mark.parametrize("which", [0, 1], ids=["runtime", "assurance"])
def test_a_file_naming_exclusions_is_refused_and_told_why(which):
    doc = (assurance_doc(excludeApplicationScopes=["x"]) if which else
           {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy", "metadata": {"name": "p"},
            "spec": {"applicationScopes": ["Global"], "excludeApplicationScopes": ["x"]}})
    with pytest.raises(SchemaError, match="not offered") as refused:
        load_document(doc, "t.yaml")
    assert "excludeApplicationScopes" in str(refused.value)


@pytest.mark.parametrize("which", [0, 1], ids=["runtime", "assurance"])
def test_a_plan_changes_nothing_about_exclusions_and_names_them(which):
    aqua, key, file = _kinds()[which]
    summary = reconcile_all([file], aqua, opts(dry_run=True))
    r = summary.results[0]
    assert all("exclude" not in c.path for c in r.plan.changes)
    assert "['critical']" in r.held[0] and "stays as it is" in r.held[0]
    assert summary.exit_code(detailed=False) == 0
    assert "holding settings this tool does not offer" in summary.summary_line()


@pytest.mark.parametrize("which", [0, 1], ids=["runtime", "assurance"])
def test_an_update_sends_exclusions_back_as_they_are(which):
    aqua, key, file = _kinds()[which]
    aqua.objects[key]["description"] = "not ours yet"
    summary = reconcile_all([file], aqua, opts())
    assert aqua.objects[key]["exclude_application_scopes"] == ["critical"]
    assert summary.results[0].outcome is Outcome.ADOPTED and not summary.failed


def test_exclusions_never_change_the_detailed_exit_code():
    aqua = FakeAqua({"p": mine("p", exclude_application_scopes=["critical"])})
    reconcile_all([policy("p")], aqua, opts())
    summary = reconcile_all([policy("p")], aqua, opts(dry_run=True))
    assert summary.results[0].outcome is Outcome.IN_SYNC and summary.results[0].held
    assert summary.exit_code(detailed=True) == 0


def test_no_exclusions_is_nothing_to_say():
    assert reconcile_all([policy("p")], FakeAqua({"p": mine("p", exclude_application_scopes=[])}),
                         opts(dry_run=True)).results[0].held == []


def test_an_in_sync_policy_still_warns_on_stderr(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec: {applicationScopes: [Global]}
        """))
    aqua = FakeAqua({"p": mine("p", exclude_application_scopes=["critical"])})
    reconcile_all([policy("p")], aqua, opts())
    code, out, err = run(["plan", "-f", str(tmp_path), "--instance", ME], aqua)
    assert code == 0
    assert "warning" in err and "excludeApplicationScopes" in err and "critical" in err
    assert "excludeApplicationScopes" not in out


def test_json_carries_the_exclusions_too(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""\
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata: {name: p}
        spec: {applicationScopes: [Global]}
        """))
    aqua = FakeAqua({"p": mine("p", exclude_application_scopes=["critical"])})
    code, out, _ = run(["plan", "-f", str(tmp_path), "--instance", ME, "--output", "json"], aqua)
    assert code == 0
    assert "critical" in json.loads(out)["results"][0]["heldInAqua"][0]


@pytest.mark.parametrize("dry_run", [True, False], ids=["plan", "apply"])
def test_deleting_a_policy_says_its_exclusions_go_with_it(dry_run):
    """A rename is a delete and a create, and the new policy will not hold them."""
    aqua = FakeAqua({"old": mine("old", exclude_application_scopes=["critical"])})
    results = reconcile_all([policy("new")], aqua, opts(dry_run=dry_run)).results
    gone = [r for r in results if r.name == "old"][0]
    assert "['critical']" in gone.held[0] and "goes with this policy" in gone.held[0]


@pytest.mark.parametrize("which", [0, 1], ids=["runtime", "assurance"])
def test_export_leaves_exclusions_out_says_so_and_does_not_fail(tmp_path, which):
    aqua, key, _ = _kinds()[which]
    aqua.objects[key]["description"] = ""
    aqua.objects[key]["application_scopes"] = ["Global"]
    code, out, err = run(["export", "--scope", "Global", "-o", str(tmp_path), "--instance", ME], aqua)
    assert code == 0
    assert "excludeApplicationScopes" in err and "critical" in err and "leaves it as it is" in err
    for written in tmp_path.glob("*policy*.yaml"):
        assert "excludeApplicationScopes" not in written.read_text()
    code, out, _ = run(["export", "--scope", "Global", "-o", str(tmp_path), "--instance", ME, "--force",
                        "--output", "json"], aqua)
    assert code == 0 and json.loads(out)["heldInAqua"] == {key: {"excludeApplicationScopes": ["critical"]}}
    code, out, _ = run(["plan", "-f", str(tmp_path), "--instance", ME], aqua)
    assert code == 0
    assert "will be adopted" in out and "exclude" not in out
    assert all("exclude" not in c.path for r in reconcile_all(load_dir(tmp_path).resources, aqua, opts(dry_run=True)).results
               for c in r.plan.changes)
