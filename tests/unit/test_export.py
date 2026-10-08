"""Export: existing Aqua configuration as YAML, and the adoption round trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aquasec_casc.export import export_kind, kind_filename_prefix, slugify
from aquasec_casc.reconcile import Options, Outcome, marker, reconcile
from aquasec_casc.schema import load_document, registry

from .test_engine import FakeAqua

KIND = registry.get("RuntimePolicy")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "runtime_policy_aqua_default.json"


@pytest.fixture
def real_default() -> dict:
    """The stock 'Aqua default runtime policy', as recorded from a live tenant."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def custom(name, scopes=("DevTest",), description="Custom policy", **extra):
    return {"name": name, "description": description, "enabled": True, "enforce": False,
            "runtime_type": "container", "application_scopes": list(scopes),
            "block_disallowed_images": False, "is_ootb_policy": False, **extra}


# --------------------------------------------------------------------------- #
# Names
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,slug", [
    ("Aqua default runtime policy", "aqua-default-runtime-policy"),
    ("PCI DSS", "pci-dss"),
    ("devtest-baseline", "devtest-baseline"),
    ("  Weird__Name!! ", "weird-name"),
    ("!!!", "unnamed"),
])
def test_slugify(name, slug):
    assert slugify(name) == slug


def test_kind_filename_prefix():
    assert kind_filename_prefix("RuntimePolicy") == "runtime-policy"


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #

def test_only_the_requested_scope_is_exported():
    aqua = FakeAqua({"a": custom("a", ["DevTest"]), "b": custom("b", ["AccProd"])})
    result = export_kind(aqua, KIND, instance="platform", scope="DevTest")
    assert [e.aqua_name for e in result.exported] == ["a"]


def test_name_patterns_narrow_the_export():
    aqua = FakeAqua({"team-a-1": custom("team-a-1"), "team-b-1": custom("team-b-1")})
    result = export_kind(aqua, KIND, instance="platform", scope="DevTest", names=["team-a-*"])
    assert [e.aqua_name for e in result.exported] == ["team-a-1"]


def test_shipped_policies_are_included_and_flagged(real_default):
    aqua = FakeAqua({real_default["name"]: real_default})
    result = export_kind(aqua, KIND, instance="platform", scope="Global")
    assert result.exported[0].shipped is True


def test_another_instances_objects_are_skipped():
    theirs = custom("theirs", description="x\n\nmanaged-by: aquasec-casc/team-b")
    aqua = FakeAqua({"theirs": theirs, "mine": custom("mine")})
    result = export_kind(aqua, KIND, instance="platform", scope="DevTest")
    assert [e.aqua_name for e in result.exported] == ["mine"]
    assert "team-b" in result.skipped[0].reason


# --------------------------------------------------------------------------- #
# The documents
# --------------------------------------------------------------------------- #

def test_the_marker_is_stripped_from_the_exported_description():
    aqua = FakeAqua({"mine": custom("mine", description="Mine\n\nmanaged-by: aquasec-casc/platform")})
    doc = export_kind(aqua, KIND, instance="platform", scope="DevTest").exported[0].document
    assert doc["spec"]["description"] == "Mine"


def test_an_empty_description_is_omitted():
    aqua = FakeAqua({"mine": custom("mine", description="managed-by: aquasec-casc/platform")})
    doc = export_kind(aqua, KIND, instance="platform", scope="DevTest").exported[0].document
    assert "description" not in doc["spec"]


def test_a_name_that_is_not_dns_safe_keeps_its_aqua_name(real_default):
    aqua = FakeAqua({real_default["name"]: real_default})
    item = export_kind(aqua, KIND, instance="platform", scope="Global").exported[0]
    assert item.document["metadata"]["name"] == "aqua-default-runtime-policy"
    assert item.document["spec"]["aquaName"] == "Aqua default runtime policy"
    assert item.filename == "runtime-policy-aqua-default-runtime-policy.yaml"


def test_slug_collisions_get_a_suffix():
    aqua = FakeAqua({"PCI DSS": custom("PCI DSS"), "pci-dss": custom("pci-dss")})
    slugs = sorted(e.document["metadata"]["name"]
                   for e in export_kind(aqua, KIND, instance="platform", scope="DevTest").exported)
    assert slugs == ["pci-dss", "pci-dss-2"]


def test_nulls_from_the_api_are_not_written(real_default):
    aqua = FakeAqua({real_default["name"]: real_default})
    doc = export_kind(aqua, KIND, instance="platform", scope="Global").exported[0].document
    assert "None" not in json.dumps(doc) and "null" not in json.dumps(doc)


def test_every_exported_document_is_schema_valid(real_default):
    aqua = FakeAqua({real_default["name"]: real_default, "mine": custom("mine", ["Global"])})
    for item in export_kind(aqua, KIND, instance="platform", scope="Global").exported:
        load_document(item.document, item.filename)


# --------------------------------------------------------------------------- #
# The acceptance test: export -> apply only adopts -> apply is a no-op
# --------------------------------------------------------------------------- #

def test_applying_an_export_of_a_real_policy_only_adds_the_marker(real_default):
    """Your existing configuration, in Git, and applying it changes nothing --
    except recording that the tool now manages it."""
    aqua = FakeAqua({real_default["name"]: real_default})
    before = dict(aqua.objects[real_default["name"]])

    doc = export_kind(aqua, KIND, instance="platform", scope="Global").exported[0].document
    resource = load_document(doc, "exported.yaml")[0]
    options = Options(instance="platform")

    first = reconcile(resource, KIND, aqua, options)
    assert first.outcome is Outcome.ADOPTED
    assert [c.path for c in first.plan.changes] == ["description"]

    after = aqua.objects[real_default["name"]]
    assert marker.strip(after["description"]) == before["description"]
    for key in before:
        if key != "description":
            assert after[key] == before[key], key

    second = reconcile(resource, KIND, aqua, options)
    assert second.outcome is Outcome.IN_SYNC


def test_bypass_scope_is_exported_only_where_it_can_be_managed(real_default):
    """Every policy has bypass_scope in the API; only two defaults may manage it."""
    hipaa = {**custom("HIPAA", ["Global"]), "is_ootb_policy": True,
             "bypass_scope": {"enabled": False, "scope": {"expression": "", "variables": []}}}
    mine = {**custom("mine", ["Global"]),
            "bypass_scope": {"enabled": False, "scope": {"expression": "", "variables": None}}}
    aqua = FakeAqua({real_default["name"]: real_default, "HIPAA": hipaa, "mine": mine})
    docs = {e.aqua_name: e.document for e in
            export_kind(aqua, KIND, instance="platform", scope="Global").exported}

    bypass = docs["Aqua default runtime policy"]["spec"]["controls"]["bypassScope"]
    assert bypass["enabled"] is True and bypass["variables"]          # the shipped exemptions
    assert "bypassScope" not in docs["HIPAA"]["spec"].get("controls", {})
    assert "bypassScope" not in docs["mine"]["spec"].get("controls", {})
