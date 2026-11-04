"""Nothing the tool offers goes untested, and nothing Aqua has goes unnoticed.

The field maps are checked against the samples the live test uses. They are also
checked against Aqua's own API spec when the private knowledge base is at hand
(``AQUASEC_CASC_KB``): the spec is login-gated and never committed here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aquasec_casc.schema import load_document, registry
from aquasec_casc.schema.assurance_policy import NOT_OFFERED as ASSURANCE_NOT_OFFERED
from aquasec_casc.schema.fieldmap import set_path
from aquasec_casc.schema.runtime_policy import NOT_OFFERED as RUNTIME_NOT_OFFERED

from ..integration import field_samples as samples

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "runtime_policy_aqua_default.json"
KB = Path(os.environ.get("AQUASEC_CASC_KB", "../aquasec-api-knowledge"))


def _covered(kind, table, elsewhere):
    """Canonical paths the samples reach, through the real schema."""
    field_map = registry.get(kind).field_map
    reached = set()
    for path, (value, types) in table.items():
        spec = {"applicationScopes": ["Global"]}
        if kind == "AssurancePolicy":
            spec["assuranceType"] = types[0]
        else:
            spec["runtimeType"] = types[0]
        set_path(spec, path.split("#")[0], value)
        doc = {"apiVersion": "config.aquasec.com/v1alpha1", "kind": kind,
               "metadata": {"name": "x"}, "spec": spec}
        resource, _ = load_document(doc, "sample")
        canonical = resource.model_dump(exclude_unset=True, mode="json")
        from aquasec_casc.schema.fieldmap import MISSING, get_path
        reached |= {m.canonical for m in field_map.mappings
                    if get_path(canonical, m.canonical) is not MISSING}
    return reached | {m.canonical for m in field_map.mappings
                      if any(m.canonical == e or m.canonical.startswith(e + ".") for e in elsewhere)}


@pytest.mark.parametrize("kind,table,elsewhere", [
    ("RuntimePolicy", samples.RUNTIME, samples.RUNTIME_ELSEWHERE),
    ("AssurancePolicy", samples.ASSURANCE,
     samples.ASSURANCE_ELSEWHERE | samples.ASSURANCE_AT_RUN_TIME),
])
def test_every_field_has_a_live_sample(kind, table, elsewhere):
    field_map = registry.get(kind).field_map
    missing = {m.canonical for m in field_map.mappings} - _covered(kind, table, elsewhere)
    assert not missing, f"no sample in tests/integration/field_samples.py for {sorted(missing)}"


def _accounted(path, field_map, not_offered):
    known = {p for m in field_map.mappings for p in (m.api, *m.also_set, *m.api_aliases)}
    return any(path == k or path.startswith(k + ".") for k in (*known, *not_offered))


def test_every_field_of_a_recorded_runtime_policy_is_accounted_for():
    field_map = registry.get("RuntimePolicy").field_map

    def walk(obj, prefix=""):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict) and value:
                yield from walk(value, path)
            else:
                yield path

    policy = json.loads(FIXTURE.read_text(encoding="utf-8"))
    stray = [p for p in walk(policy) if not _accounted(p, field_map, RUNTIME_NOT_OFFERED)]
    assert not stray, f"map these or list them in NOT_OFFERED: {stray}"


def _spec_fields(schema, schemas, prefix="", seen=()):
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        if name in seen:
            return
        yield from _spec_fields(schemas[name], schemas, prefix, (*seen, name))
    elif schema.get("properties"):
        for key, value in schema["properties"].items():
            yield from _spec_fields(value, schemas, f"{prefix}.{key}" if prefix else key, seen)
    else:
        yield prefix


@pytest.mark.parametrize("edition", ["aqua_swagger_saas.json", "aqua_swagger_v2022.4.json"])
@pytest.mark.parametrize("kind,schema_name,not_offered", [
    ("RuntimePolicy", "RuntimePolicy", RUNTIME_NOT_OFFERED),
    ("AssurancePolicy", "AssurancePolicy", ASSURANCE_NOT_OFFERED),
])
def test_every_field_in_aquas_api_spec_is_accounted_for(edition, kind, schema_name, not_offered):
    spec_file = KB / "specs" / edition
    if not spec_file.is_file():
        pytest.skip("the private knowledge base is not here; set AQUASEC_CASC_KB")
    spec = json.loads(spec_file.read_text(encoding="utf-8"))
    schemas = spec.get("components", {}).get("schemas") or spec["definitions"]
    field_map = registry.get(kind).field_map
    fields = list(_spec_fields(schemas[schema_name], schemas))
    stray = sorted(f for f in fields if not _accounted(f, field_map, not_offered))
    assert not stray, f"map these or list them in NOT_OFFERED: {stray}"
