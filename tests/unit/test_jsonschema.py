"""Machine-readable schema output, for CI validation now and CRDs in phase 2."""

from __future__ import annotations

import pytest

from aquasec_casc.schema import kinds
from aquasec_casc.schema.jsonschema import all_kinds, crd_for_kind, for_kind


def test_json_schema_is_produced_for_every_kind():
    assert set(all_kinds()) == set(kinds())


def test_json_schema_forbids_unknown_fields():
    """The strictness has to survive into the schema, or CI would not catch typos."""
    schema = for_kind("RuntimePolicy")
    assert schema["additionalProperties"] is False
    for definition in schema.get("$defs", {}).values():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False


def test_json_schema_is_self_identifying():
    schema = for_kind("RuntimePolicy")
    assert schema["$schema"].startswith("https://json-schema.org/")
    assert "config.aquasec.com/v1alpha1" in schema["$id"]


def test_crd_is_shaped_like_a_customresourcedefinition():
    crd = crd_for_kind("RuntimePolicy")

    assert crd["apiVersion"] == "apiextensions.k8s.io/v1"
    assert crd["kind"] == "CustomResourceDefinition"
    assert crd["metadata"]["name"] == "runtimepolicies.config.aquasec.com"
    assert crd["spec"]["names"]["plural"] == "runtimepolicies"
    assert crd["spec"]["group"] == "config.aquasec.com"

    version = crd["spec"]["versions"][0]
    assert version["name"] == "v1alpha1"
    assert version["served"] is True
    assert version["storage"] is True
    assert "status" in version["subresources"]


def test_crd_schema_has_no_keywords_kubernetes_rejects():
    """A structural schema may not contain $ref, allOf, anyOf and friends."""
    crd = crd_for_kind("RuntimePolicy")
    schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]

    forbidden = ("$ref", "$defs", "definitions", "allOf", "anyOf", "oneOf", "not")

    def walk(node, path="openAPIV3Schema"):
        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            assert key not in forbidden, f"{path} still contains {key!r}"
            walk(value, f"{path}.{key}")

    walk(schema)


def test_crd_schema_actually_inlined_the_nested_models():
    """Inlining must preserve content, not just delete the $refs."""
    crd = crd_for_kind("RuntimePolicy")
    schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]

    controls = schema["properties"]["spec"]["properties"]["controls"]
    assert "blockNonCompliantImages" in controls["properties"]

    drift = controls["properties"]["driftPrevention"]
    assert "execLockdown" in drift["properties"]
    assert "exceptions" in drift["properties"]


def test_crd_object_nodes_all_declare_a_type():
    """Kubernetes requires a type on every node of a structural schema."""
    crd = crd_for_kind("RuntimePolicy")
    schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]

    def walk(node, path="openAPIV3Schema"):
        if not isinstance(node, dict):
            return
        if "properties" in node:
            assert node.get("type") == "object", f"{path} has properties but no type"
            for name, child in node["properties"].items():
                walk(child, f"{path}.{name}")

    walk(schema)


@pytest.mark.parametrize(
    "singular,expected",
    [
        ("runtimepolicy", "runtimepolicies"),
        ("assurancepolicy", "assurancepolicies"),
        ("enforcergroup", "enforcergroups"),
        ("applicationscope", "applicationscopes"),
        ("gateway", "gateways"),      # vowel + y keeps the y
        ("policyclass", "policyclasses"),
    ],
)
def test_crd_plurals_are_spelled_correctly(singular, expected):
    """names.plural is what people type and is part of the resource identity.

    Getting it wrong ships 'runtimepolicys' into phase 2 and is awkward to
    change once anything references it.
    """
    from aquasec_casc.schema.jsonschema import _pluralise

    assert _pluralise(singular) == expected
