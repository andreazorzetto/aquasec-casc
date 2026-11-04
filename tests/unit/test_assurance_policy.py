"""AssurancePolicy: names unique within a type, and the rules runtime policies have."""

from __future__ import annotations

import pytest

from aquasec_casc.client.aquasec_client import _kubernetes_read_view, _kubernetes_write_view
from aquasec_casc.export import export_kind
from aquasec_casc.reconcile import (DestroyOptions, Options, Outcome, ReleaseOptions, destroy_all,
                                    marker, reconcile_all, release_all)
from aquasec_casc.schema import SchemaError, SchemaErrorGroup, load_dir, load_document, registry

from .test_engine import ME, FakeAqua

KIND = registry.get("AssurancePolicy")
OPTS = dict(instance=ME, kinds=(KIND,))


def doc(name="prod", type_="image", **spec):
    return {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "AssurancePolicy",
            "metadata": {"name": name},
            "spec": {"assuranceType": type_, "applicationScopes": ["Global"], **spec}}


def load(**kwargs):
    return load_document(doc(**kwargs), "test")[0]


def stored(name="prod", type_="image", **fields):
    return {"name": name, "assurance_type": type_, "author": "someone", "application_scopes": ["Global"],
            "description": marker.marker(ME), "audit_on_failure": False, "fail_cicd": False,
            "block_failed": False, "cvss_severity_enabled": False, "cvss_severity": "",
            "cves_black_list_enabled": False, "cves_black_list": [], "control_exclude_no_fix": False,
            "ignore_recently_published_vln": False, "ignore_recently_published_vln_period": 30,
            "scope": {"expression": "", "variables": []}, **fields}


def test_the_key_is_type_and_name():
    assert KIND.key(load(name="prod")) == "image/prod"
    assert KIND.key(load(name="x", aquaName="Default", type_="host")) == "host/Default"
    assert KIND.key_of({"name": "Default", "assurance_type": "kubernetes"}) == "kubernetes/Default"
    assert KIND.name_of("image/prod") == "prod"


def test_the_same_name_on_two_types_is_two_objects():
    aqua = FakeAqua()
    resources = [load(name="a", aquaName="shared", type_="image"),
                 load(name="b", aquaName="shared", type_="host")]
    summary = reconcile_all(resources, aqua, Options(**OPTS))
    assert [r.outcome for r in summary.results] == [Outcome.CREATED, Outcome.CREATED]
    assert set(aqua.objects) == {"image/shared", "host/shared"}


def test_two_documents_for_one_object_are_refused(tmp_path):
    import yaml
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(doc(name="a", aquaName="shared")))
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(doc(name="b", aquaName="shared")))
    with pytest.raises((SchemaError, SchemaErrorGroup), match="both describe"):
        load_dir(tmp_path)


def test_same_aqua_name_on_two_types_is_not_a_duplicate(tmp_path):
    import yaml
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(doc(name="a", aquaName="s", type_="image")))
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(doc(name="b", aquaName="s", type_="host")))
    assert len(load_dir(tmp_path).resources) == 2


def test_a_setting_switches_the_control_on_and_lists_become_api_items():
    r = load(controls={"packagesBlocked": {"packages": [{"name": "php", "versionRange": "Less Than",
                                                         "version": "8"}]}})
    api = KIND.field_map.to_api(r.model_dump(exclude_unset=True, mode="json"))
    assert api["packages_black_list_enabled"] is True
    assert api["packages_black_list"] == [{"name": "php", "version": "8", "version_range": "Less Than"}]


def test_a_stored_package_with_fields_of_aquas_own_is_not_drift():
    want = {"packagesBlocked": {"packages": [{"name": "php", "version": "8", "versionRange": "Less Than"}]}}
    have = [{"format": "", "name": "php", "epoch": "", "version": "8", "version_range": "Less Than",
             "release": "", "arch": "", "license": "", "display": "php"}]
    aqua = FakeAqua({"image/prod": stored(packages_black_list_enabled=True, packages_black_list=have)})
    r = reconcile_all([load(controls=want)], aqua, Options(**OPTS, dry_run=True)).results[0]
    assert r.outcome is Outcome.IN_SYNC, r.plan.changes


def test_removing_a_field_of_a_package_is_a_change():
    want = {"packagesBlocked": {"packages": [{"name": "php"}]}}
    have = [{"name": "php", "version": "8", "version_range": "Less Than"}]
    aqua = FakeAqua({"image/prod": stored(packages_black_list_enabled=True, packages_black_list=have)})
    r = reconcile_all([load(controls=want)], aqua, Options(**OPTS, dry_run=True)).results[0]
    assert r.outcome is Outcome.PLANNED


def test_what_the_file_leaves_out_of_actions_exceptions_and_controls_is_off():
    """Not the scope criteria: Aqua fills in its own when a policy has none."""
    aqua = FakeAqua({"image/prod": stored(
        fail_cicd=True, control_exclude_no_fix=True, ignore_recently_published_vln=True,
        cvss_severity_enabled=True, cvss_severity="high",
        scope={"expression": "v1", "variables": [{"attribute": "image.name", "value": "*"}]})})
    r = reconcile_all([load()], aqua, Options(**OPTS, dry_run=True)).results[0]
    changed = {c.path: c.after for c in r.plan.changes}
    assert changed == {"fail_cicd": False, "control_exclude_no_fix": False,
                       "ignore_recently_published_vln": False, "cvss_severity_enabled": False}


def test_a_grace_period_needs_its_days():
    with pytest.raises(SchemaError, match="needs 'days'"):
        load(exceptions={"ignoreRecentlyPublished": True})


@pytest.mark.parametrize("type_,controls,only", [
    ("image", {"cisBenchmarkForLinux": True}, "host"),
    ("host", {"superuser": True}, "cf_application and image"),
    ("image", {"excessivePermissions": True}, "function"),
    ("host", {"kubernetesControls": ["Privileged"]}, "kubernetes"),
])
def test_a_control_this_type_does_not_offer_is_refused(type_, controls, only):
    with pytest.raises(SchemaError, match=f"only available on {only}"):
        load(type_=type_, controls=controls)


def test_actions_and_exceptions_a_type_does_not_offer_are_refused():
    with pytest.raises(SchemaError, match="actions.blockResources is only available on kubernetes"):
        load(actions={"blockResources": True})
    with pytest.raises(SchemaError, match="exceptions.ignoreNoFix is only available on"):
        load(type_="kubernetes", exceptions={"ignoreNoFix": True})
    with pytest.raises(SchemaError, match="controls.malware is only available on"):
        load(type_="function", controls={"malware": True})


def test_orphans_are_found_on_every_type_and_shipped_ones_are_kept():
    aqua = FakeAqua({"image/gone": stored("gone"), "host/gone": stored("gone", "host"),
                     "kubernetes/Default": stored("Default", "kubernetes"),
                     "image/not-mine": stored("not-mine", description="console")})
    summary = reconcile_all([load(name="keep")], aqua, Options(**OPTS))
    assert "image/gone" not in aqua.objects and "host/gone" not in aqua.objects
    assert "image/not-mine" in aqua.objects
    shipped = [r for r in summary.results if r.name == "kubernetes/Default"][0]
    assert shipped.outcome is Outcome.ORPHANED and shipped.informational
    assert "kubernetes/Default" in aqua.objects


def test_a_scope_change_on_a_shipped_policy_is_reported_not_sent():
    aqua = FakeAqua({"image/Default": stored("Default", application_scopes=["Global"])})
    resource = load(name="image-default", aquaName="Default", applicationScopes=["DevTest"])
    r = reconcile_all([resource], aqua, Options(**OPTS)).results[0]
    assert r.not_allowed and aqua.objects["image/Default"]["application_scopes"] == ["Global"]


def test_export_prefixes_the_type_and_keeps_the_aqua_name():
    aqua = FakeAqua({"image/Default": stored("Default", description="d", audit_on_failure=True),
                     "host/Default": stored("Default", "host", description="d")})
    result = export_kind(aqua, KIND, instance=ME)
    assert [e.filename for e in result.exported] == ["assurance-policy-host-default.yaml",
                                                     "assurance-policy-image-default.yaml"]
    image = result.exported[1]
    assert image.shipped and image.document["metadata"]["name"] == "image-default"
    assert image.document["spec"]["aquaName"] == "Default"
    assert image.document["spec"]["actions"] == {"createAuditMessage": True}
    assert "exceptions" not in image.document["spec"]
    assert "additionalScopeCriteria" not in image.document["spec"]


def test_applying_an_export_only_adds_the_marker():
    aqua = FakeAqua({"image/custom": stored(
        "custom", description="mine", block_failed=True, cvss_severity_enabled=True,
        cvss_severity="high", cvss_severity_exclude_no_fix=False,
        scope={"expression": "v1", "variables": [{"attribute": "image.name", "value": "app*"}]})})
    exported = export_kind(aqua, KIND, instance=ME).exported[0]
    resource = load_document(exported.document, "export")[0]
    r = reconcile_all([resource], aqua, Options(**OPTS, dry_run=True)).results[0]
    assert r.action == "adopt"
    assert [c.path for c in r.plan.changes] == ["description"]


def test_release_and_destroy_address_by_key():
    aqua = FakeAqua({"image/p": stored("p"), "host/p": stored("p", "host")})
    summary = release_all(aqua, ReleaseOptions(instance=ME, kinds=(KIND,), names=("host/*",)))
    assert [r.name for r in summary.of(Outcome.RELEASED)] == ["host/p"]
    assert marker.owner(aqua.objects["image/p"]["description"]) == ME
    assert marker.owner(aqua.objects["host/p"]["description"]) is None

    summary = destroy_all(aqua, DestroyOptions(instance=ME, kinds=(KIND,), names=("p",)))
    assert [r.name for r in summary.of(Outcome.DELETED)] == ["image/p"]
    assert "host/p" in aqua.objects


def test_destroy_releases_a_shipped_policy():
    aqua = FakeAqua({"host/Default": stored("Default", "host")})
    summary = destroy_all(aqua, DestroyOptions(instance=ME, kinds=(KIND,)))
    assert [r.outcome for r in summary.results] == [Outcome.RELEASED]
    assert "host/Default" in aqua.objects


# --------------------------------------------------------------------------- #
# Kubernetes checks: three lists in Aqua, one in the file
# --------------------------------------------------------------------------- #

CHECKS = [{"name": "Privileged", "enabled": False, "avd_id": "A"},
          {"name": "Access to host network", "enabled": True, "avd_id": "B"}]


def test_the_checks_are_read_from_the_flags():
    policy = {"assurance_type": "kubernetes", "kubernetes_controls": CHECKS,
              "kubernetes_controls_names": []}                  # as in a 2022.4 export
    assert _kubernetes_read_view(policy)["kubernetes_controls_names"] == ["Access to host network"]
    assert _kubernetes_read_view(None) is None
    assert "kubernetes_controls_names" not in _kubernetes_read_view({"assurance_type": "image"})


def test_a_write_makes_all_three_lists_agree():
    body = {"assurance_type": "kubernetes", "kubernetes_controls": CHECKS,
            "kubernetes_controls_names": ["Privileged"], "kubernetes_controls_avd_ids": ["B"]}
    out = _kubernetes_write_view(body)
    assert out["kubernetes_controls_avd_ids"] == []
    assert [c["enabled"] for c in out["kubernetes_controls"]] == [True, False]
    assert _kubernetes_write_view({"assurance_type": "image", "x": 1}) == {"assurance_type": "image", "x": 1}


def test_the_checks_are_in_a_stable_order():
    resource = load(type_="kubernetes", controls={"kubernetesControls": ["b", "a"]})
    assert resource.spec.controls.kubernetesControls == ["a", "b"]


# --------------------------------------------------------------------------- #
# Read-back
# --------------------------------------------------------------------------- #

class Forgetful(FakeAqua):
    """Accepts a field and does not keep it, as Aqua does with one it lacks."""

    forgets = "fail_cicd"

    def get(self, kind, name):
        obj = super().get(kind, name)
        if obj:
            obj.pop(self.forgets, None)
        return obj


def test_a_field_aqua_did_not_keep_fails_the_run():
    aqua = Forgetful()
    summary = reconcile_all([load(actions={"failCicd": True})], aqua, Options(**OPTS))
    r = summary.results[0]
    assert r.outcome is Outcome.CREATED
    assert r.not_kept == ["fail_cicd: sent True, Aqua holds nothing"]
    assert summary.exit_code(detailed=False) == 1
    assert "1 with fields Aqua did not keep" in summary.summary_line()


def test_a_kept_field_passes():
    aqua = FakeAqua()
    summary = reconcile_all([load(actions={"failCicd": True})], aqua, Options(**OPTS))
    assert not summary.results[0].not_kept and summary.exit_code(detailed=False) == 0


def test_a_failed_read_back_is_reported():
    class Blind(FakeAqua):
        reads = 0

        def get(self, kind, name):
            self.reads += 1
            if self.reads > 1:
                from aquasec_casc.reconcile.client import ClientError
                raise ClientError("HTTP 500")
            return super().get(kind, name)

    summary = reconcile_all([load()], Blind(), Options(**OPTS))
    assert "could not read the object back" in summary.results[0].not_kept[0]


# --------------------------------------------------------------------------- #
# Against a real object, as recorded from a live tenant
# --------------------------------------------------------------------------- #

def _recorded():
    import json
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "fixtures" / "assurance_policy_image_default.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_field_of_a_recorded_policy_is_accounted_for():
    from aquasec_casc.schema.assurance_policy import NOT_OFFERED
    known = {p for m in KIND.field_map.mappings for p in (m.api, *m.also_set)}

    def accounted(path):
        return any(path == k or path.startswith(k + ".") or k.startswith(path + ".")
                   for k in (*known, *NOT_OFFERED))

    def walk(obj, prefix=""):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict) and value:
                yield from walk(value, path)
            else:
                yield path

    stray = [p for p in walk(_recorded()) if not accounted(p)]
    assert not stray, f"map these or list them in NOT_OFFERED: {stray}"


def test_the_recorded_default_is_recognised_exported_and_adopted_without_change():
    policy = _recorded()
    aqua = FakeAqua({"image/Default": policy})
    exported = export_kind(aqua, KIND, instance=ME).exported[0]
    assert exported.shipped
    resource = load_document(exported.document, "export")[0]
    r = reconcile_all([resource], aqua, Options(**OPTS, dry_run=True)).results[0]
    assert r.action == "adopt" and [c.path for c in r.plan.changes] == ["description"]


def test_exploitability_and_severity_as_the_console_saves_it():
    """Read from a console export: a guessed field name is stored, and does nothing."""
    resource = load(controls={"vulnerabilityExploitabilityAndSeverity": {
        "exploitTypes": ["remote", "CISA"], "severity": "high", "useCustomSeverity": True}})
    api = KIND.field_map.to_api(resource.model_dump(exclude_unset=True, mode="json"))
    assert api["exploitability_and_severity"] == {
        "enabled": True, "disallow_exploit_types": ["remote", "CISA"], "severity": "high",
        "custom_severity_enabled": True}
    with pytest.raises(SchemaError, match="'exploitTypes' and 'severity'"):
        load(controls={"vulnerabilityExploitabilityAndSeverity": True})
