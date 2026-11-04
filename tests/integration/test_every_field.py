"""Every field the tool offers, through the tool, against a real tenant. Opt-in.

    AQUASEC_CASC_LIVE=1 AQUASEC_CASC_PROFILE=lab pytest tests/integration/test_every_field.py

For each control on each type that offers it, one throwaway policy goes through:

  create with it -> stored as written, and plan is clean
  a console-style re-save (Aqua validates create and update differently) -> clean
  export -> fits the schema and plans clean
  removed from the file -> switched off, and plan is clean
  added back by update -> stored as written, and plan is clean

Safe on a shared tenant: container and host runtime policies are disabled. Function
runtime policies and assurance policies have no such switch, so those are scoped to
names that match nothing. Names start with ``aquasec-casc-live-`` and every policy is
deleted at the end of its case.
"""

from __future__ import annotations

import copy
import os
import secrets

import pytest

from aquasec_casc.export import export_kind
from aquasec_casc.reconcile import Options, Outcome, reconcile_all
from aquasec_casc.schema import load_document, registry
from aquasec_casc.schema.fieldmap import set_path

from . import field_samples as samples

pytestmark = pytest.mark.skipif(
    os.environ.get("AQUASEC_CASC_LIVE") != "1",
    reason="live test: set AQUASEC_CASC_LIVE=1 (and credentials) to run against a tenant",
)

PROFILE = os.environ.get("AQUASEC_CASC_PROFILE")
INSTANCE = f"live-{secrets.token_hex(3)}"
TAG = secrets.token_hex(3)

#: What, in each type's own terms, matches nothing.
NOTHING = {"image": "image.name", "host": "os.hostname", "function": "function.name",
           "kubernetes": "kubernetes.namespace", "cf_application": "cf.appname"}


@pytest.fixture(scope="module")
def client():
    from aquasec_casc.client import connect, settings_from_env, settings_from_profile
    return connect(settings_from_profile(PROFILE) if PROFILE else settings_from_env())


def _with(doc: dict, path: str, value) -> dict:
    out = copy.deepcopy(doc)
    set_path(out["spec"], path.split("#")[0], value)
    return out


def _base(kind: str, type_: str, name: str) -> dict:
    spec = {"description": "aquasec-casc live test, safe to delete", "applicationScopes": ["Global"]}
    nothing = {"additionalScopeCriteria": {
        "expression": "v1",
        "variables": [{"attribute": NOTHING.get(type_), "value": f"casc-no-such-{TAG}"}]}}
    if kind == "AssurancePolicy":
        spec |= {"assuranceType": type_, **nothing}
    elif type_ == "function":
        spec |= {"runtimeType": type_, **nothing}
    else:
        spec |= {"enabled": False, "runtimeType": type_}
    return {"apiVersion": "config.aquasec.com/v1alpha1", "kind": kind,
            "metadata": {"name": name}, "spec": spec}


def _run(client, kind_def, doc, dry_run=False):
    resource, _ = load_document(doc, "test")
    options = Options(instance=INSTANCE, dry_run=dry_run, kinds=(kind_def,))
    summary = reconcile_all([resource], client, options)
    return [r for r in summary.results if r.name == doc["metadata"]["name"]][0], kind_def.key(resource)


def _clean(client, kind_def, doc, step):
    r, _ = _run(client, kind_def, doc, dry_run=True)
    if r.outcome is not Outcome.IN_SYNC:
        changes = [(c.path, c.before, c.after) for c in (r.plan.changes if r.plan else [])]
        return [f"{step}: plan is not clean: {r.outcome.value} {r.message} {changes}"]
    return []


def exercise(client, kind: str, type_: str, path: str, value) -> list[str]:
    """Everything wrong with this control on this type; empty when it all holds."""
    kind_def = registry.get(kind)
    name = f"aquasec-casc-live-{TAG}-{secrets.token_hex(3)}"
    base = _base(kind, type_, name)
    full = _with(base, path, value)
    problems: list[str] = []
    key = None
    try:
        r, key = _run(client, kind_def, full)
        if r.outcome is not Outcome.CREATED or r.not_kept:
            return [f"create: {r.outcome.value} {r.message} {r.not_kept}"]
        problems += _clean(client, kind_def, full, "after create")

        client.update(kind_def, key, client.get(kind_def, key))        # as a console save
        problems += _clean(client, kind_def, full, "after a re-save")

        scope = "Global"
        exported = export_kind(client, kind_def, instance=INSTANCE, scope=scope, names=[name])
        if exported.skipped or not exported.exported:
            problems.append(f"export: {exported.skipped}")
        else:
            doc = exported.exported[0].document
            problems += _clean(client, kind_def, doc, "export")

        r, _ = _run(client, kind_def, base)
        if r.outcome not in (Outcome.UPDATED, Outcome.IN_SYNC) or r.not_kept:
            problems.append(f"remove: {r.outcome.value} {r.message} {r.not_kept}")
        problems += _clean(client, kind_def, base, "after removing it")

        r, _ = _run(client, kind_def, full)
        if r.outcome not in (Outcome.UPDATED, Outcome.IN_SYNC) or r.not_kept:
            problems.append(f"add by update: {r.outcome.value} {r.message} {r.not_kept}")
        problems += _clean(client, kind_def, full, "after adding it back")
    finally:
        if key:
            client.delete(kind_def, key)
    return problems


def cases():
    for path, (value, types) in samples.RUNTIME.items():
        for type_ in types:
            yield pytest.param("RuntimePolicy", type_, path, value, id=f"runtime-{type_}-{path}")
    for path, (value, types) in samples.ASSURANCE.items():
        for type_ in types:
            yield pytest.param("AssurancePolicy", type_, path, value, id=f"assurance-{type_}-{path}")


@pytest.mark.parametrize("kind,type_,path,value", cases())
def test_control(client, kind, type_, path, value):
    assert exercise(client, kind, type_, path, value) == []


def test_approved_base_image(client):
    """Aqua refuses a base image it does not know, so this takes one it does."""
    from aquasec.common import _request_with_retry

    res = _request_with_retry("GET", f"{client.server}/api/v2/images", client.token,
                              params={"page": 1, "pagesize": 1}, timeout=client.timeout)
    images = res.json().get("result") or []
    if not images:
        pytest.skip("no image is registered on this tenant")
    value = {"images": [{"registry": images[0]["registry"], "image": images[0]["name"]}]}
    assert exercise(client, "AssurancePolicy", "image", "controls.approvedBaseImage", value) == []
