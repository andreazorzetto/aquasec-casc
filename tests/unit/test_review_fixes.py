"""What independent review found: each of these did the wrong thing once."""

from __future__ import annotations

import io
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
    ({"blockOutdatedImages": True}, "'olderThan' and 'unit'"),
    ({"blockOutdatedImages": {"olderThan": 6}}, "'unit'"),
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
