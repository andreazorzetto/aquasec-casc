"""Every field the tool offers, through the tool, against a real tenant. Opt-in.

    AQUASEC_CASC_LIVE=1 AQUASEC_CASC_PROFILE=lab pytest tests/integration/test_every_field.py

For each control on each type that offers it, one throwaway policy goes through:

  create with it -> stored as written, and plan is clean
  a console-style re-save (Aqua validates create and update differently) -> clean
  export -> fits the schema and plans clean
  removed from the file -> switched off, and plan is clean (or, for what has a default
  that differs from Aqua, a failure that changes nothing)
  added back by update -> stored as written, and plan is clean

Then what says what a policy is, not what it does: enabled, description, scopes, additional
scope criteria, type. ``bypassScope`` needs Aqua's default policies, so it runs only with
``AQUASEC_CASC_LIVE_DEFAULTS=1``, on a tenant of your own.

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
    names = (doc["metadata"]["name"], doc["spec"].get("aquaName"))
    return [r for r in summary.results if r.name in names][0], kind_def.key(resource)


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
        if f"spec.{path}" in kind_def.always_sent:
            # Removed from the file, its default differs from Aqua: that must fail, and
            # change nothing. Say it in the file, to go on.
            if r.reason != "Unstated" or client.get(kind_def, key)[kind_def.field_map.for_canonical(
                    f"spec.{path}").api] != value:
                problems.append(f"remove: wanted a safe failure, got {r.outcome.value} {r.message}")
            return problems
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


@pytest.mark.parametrize("type_", ["image", "cf_application"])
def test_approved_base_image(client, type_):
    """Aqua refuses a base image it does not know, or has not finished scanning, so this
    takes one it has."""
    from aquasec.common import _request_with_retry

    res = _request_with_retry("GET", f"{client.server}/api/v2/images", client.token,
                              params={"page": 1, "pagesize": 200}, timeout=120)    # slow on a big tenant
    images = [i for i in res.json().get("result") or [] if i.get("scan_status") == "finished"]
    if not images:
        pytest.skip("no scanned image in the first 200 on this tenant")
    value = {"images": [{"registry": images[0]["registry"], "image": images[0]["name"]}]}
    assert exercise(client, "AssurancePolicy", type_, "controls.approvedBaseImage", value) == []


@pytest.mark.parametrize("type_,engines,wanted_type", [("image", ("rego", "ab", "sh"), "Image"),
                                                       ("cf_application", ("rego", "ab", "sh"), "Image"),
                                                       ("host", ("yaml",), "Host")])
def test_custom_compliance_checks(client, type_, engines, wanted_type):
    """Scripts are the tenant's, so this takes one it has."""
    from aquasec.common import _request_with_retry

    listed = "image" if type_ == "cf_application" else type_
    res = _request_with_retry("GET", f"{client.server}/api/v2/assurance_policy/{listed}/user_scripts",
                              client.token, timeout=client.timeout)
    scripts = sorted((s for s in res.json() or [] if s.get("engine") in engines and s.get("type") == wanted_type),
                     key=lambda s: engines.index(s["engine"]))
    if not scripts:
        pytest.skip(f"no {wanted_type} script on this tenant")
    value = {"scripts": [{"name": scripts[0]["name"]}]}
    assert exercise(client, "AssurancePolicy", type_, "controls.customComplianceChecks", value) == []


# --------------------------------------------------------------------------- #
# What says what a policy is, not what it does
# --------------------------------------------------------------------------- #

#: Not cf_application: no scope attribute for it is documented, so the scope of our own
#: below does not cover it.
SCOPED_TYPES = [("RuntimePolicy", t) for t in ("container", "host", "function")] + [
    ("AssurancePolicy", t) for t in ("image", "host", "function", "kubernetes")]


def _throwaway():
    return f"aquasec-casc-live-{TAG}-{secrets.token_hex(3)}"


@pytest.fixture(scope="module")
def second_scope(client):
    """A scope of our own that covers nothing, deleted at the end."""
    from aquasec.common import _request_with_retry

    def nothing(attribute):
        return {"expression": "v1", "variables": [{"attribute": attribute, "value": f"casc-no-such-{TAG}"}]}

    name = f"aquasec-casc-live-{TAG}"
    url = f"{client.server}/api/v2/access_management/scopes"
    res = _request_with_retry("POST", url, client.token, timeout=client.timeout, json={
        "name": name, "description": "aquasec-casc live test, safe to delete",
        "categories": {
            "artifacts": {"image": nothing("image.repo"), "function": nothing("aqua.serverless_project")},
            "workloads": {"kubernetes": nothing("kubernetes.namespace"), "os": nothing("aqua.host")},
            "infrastructure": {"kubernetes": nothing("kubernetes.cluster"), "os": nothing("aqua.hostgroup")}}})
    if res.status_code >= 400:
        pytest.skip(f"cannot create a scope here: HTTP {res.status_code} {res.text[:200]}")
    yield name
    _request_with_retry("DELETE", f"{url}/{name}", client.token, timeout=client.timeout)


def _step(client, kind_def, doc, step) -> list[str]:
    """Apply it: it must be kept, and the plan after must be clean."""
    r, _ = _run(client, kind_def, doc)
    problems = [] if r.outcome in (Outcome.CREATED, Outcome.UPDATED, Outcome.IN_SYNC) and not r.not_kept \
        else [f"{step}: {r.outcome.value} {r.message} {r.not_kept}"]
    return problems + _clean(client, kind_def, doc, step)


@pytest.mark.parametrize("kind,type_", SCOPED_TYPES)
def test_application_scopes_can_change(client, second_scope, kind, type_):
    kind_def = registry.get(kind)
    base = _base(kind, type_, _throwaway())
    moved = _with(base, "applicationScopes", [second_scope])
    key = None
    try:
        _, key = _run(client, kind_def, base)
        assert _step(client, kind_def, moved, "moved") == []
        assert client.get(kind_def, key)["application_scopes"] == [second_scope]
        assert _step(client, kind_def, base, "moved back") == []
        assert client.get(kind_def, key)["application_scopes"] == ["Global"]
    finally:
        if key:
            client.delete(kind_def, key)


@pytest.mark.parametrize("type_", ["container", "host", "function"])
def test_exclude_application_scopes_on_a_runtime_policy(client, second_scope, type_):
    assert exercise(client, "RuntimePolicy", type_, "excludeApplicationScopes", [second_scope]) == []


@pytest.mark.parametrize("type_", ["image", "host", "function"])
def test_exclude_application_scopes_on_an_assurance_policy(client, second_scope, type_):
    """Aqua keeps it only with a feature of its own on. Without it, apply has to say so."""
    problems = exercise(client, "AssurancePolicy", type_, "excludeApplicationScopes", [second_scope])
    if len(problems) == 1 and "exclude_application_scopes: sent" in problems[0] and "Aqua holds []" in problems[0]:
        pytest.skip("Aqua does not keep it on this tenant, and read-back reported that")
    assert problems == []


@pytest.mark.parametrize("type_", ["container", "host"])
def test_enabled_both_ways(client, type_):
    """On for a moment, on a policy with no controls, scoped to what does not exist."""
    kind_def = registry.get("RuntimePolicy")
    attribute = "image.name" if type_ == "container" else "os.hostname"
    base = _base("RuntimePolicy", type_, _throwaway())
    base["spec"]["additionalScopeCriteria"] = {"expression": "v1", "variables": [
        {"attribute": attribute, "value": f"casc-no-such-{TAG}"}]}
    on = _with(base, "enabled", True)
    key = None
    try:
        _, key = _run(client, kind_def, on)
        assert client.get(kind_def, key)["enabled"] is True
        assert _clean(client, kind_def, on, "on") == []
        assert _step(client, kind_def, base, "off") == []
        assert client.get(kind_def, key)["enabled"] is False

        # Left out, it means on. That must not switch a policy on: it fails, and changes nothing.
        unstated = copy.deepcopy(on)
        del unstated["spec"]["enabled"]
        r, _ = _run(client, kind_def, unstated)
        assert r.reason == "Unstated"
        assert client.get(kind_def, key)["enabled"] is False

        assert _step(client, kind_def, on, "on again") == []
        assert client.get(kind_def, key)["enabled"] is True
    finally:
        if key:
            client.delete(kind_def, key)


@pytest.mark.parametrize("kind,type_", [("RuntimePolicy", "container"), ("AssurancePolicy", "image")])
def test_description_can_change_and_the_marker_stays(client, kind, type_):
    kind_def = registry.get(kind)
    base = _base(kind, type_, _throwaway())
    changed = _with(base, "description", "aquasec-casc live test, changed, safe to delete")
    key = None
    try:
        _, key = _run(client, kind_def, base)
        assert _step(client, kind_def, changed, "changed") == []
        stored = client.get(kind_def, key)["description"]
        assert "changed, safe to delete" in stored and INSTANCE in stored
    finally:
        if key:
            client.delete(kind_def, key)


@pytest.mark.parametrize("kind,type_", [("RuntimePolicy", "function"),
                                        *[("AssurancePolicy", t) for t in
                                          ("image", "host", "function", "kubernetes", "cf_application")]])
def test_additional_scope_criteria_change_and_leaving_them_out_keeps_them(client, kind, type_):
    kind_def = registry.get(kind)
    base = _base(kind, type_, _throwaway())
    other = _with(base, "additionalScopeCriteria.variables", [
        {"attribute": NOTHING[type_], "value": f"casc-no-such-either-{TAG}"}])
    left_out = copy.deepcopy(base)
    del left_out["spec"]["additionalScopeCriteria"]
    key = None
    try:
        _, key = _run(client, kind_def, base)
        assert _step(client, kind_def, other, "changed") == []
        kept = client.get(kind_def, key)["scope"]
        assert f"casc-no-such-either-{TAG}" in str(kept)
        assert _step(client, kind_def, left_out, "left out") == []
        assert client.get(kind_def, key)["scope"] == kept
    finally:
        if key:
            client.delete(kind_def, key)


def test_a_runtime_policy_cannot_change_type(client):
    kind_def = registry.get("RuntimePolicy")
    base = _base("RuntimePolicy", "container", _throwaway())
    key = None
    try:
        _, key = _run(client, kind_def, base)
        r, _ = _run(client, kind_def, _with(base, "runtimeType", "host"))
        assert r.reason == "Immutable"
        assert client.get(kind_def, key)["runtime_type"] == "container"
    finally:
        if key:
            client.delete(kind_def, key)


@pytest.mark.skipif(os.environ.get("AQUASEC_CASC_LIVE_DEFAULTS") != "1",
                    reason="edits Aqua's default policies for a moment: set AQUASEC_CASC_LIVE_DEFAULTS=1, "
                           "and only on a tenant of your own")
@pytest.mark.parametrize("name", ["Aqua default runtime policy", "Aqua default host runtime policy"])
def test_bypass_scope_on_a_default_policy(client, name):
    """Only the default container and host policies have it, so a throwaway cannot."""
    kind_def = registry.get("RuntimePolicy")
    before = client.get(kind_def, name)
    scope = before["application_scopes"][0]
    exported = export_kind(client, kind_def, instance=INSTANCE, scope=scope, names=[name])
    assert exported.exported, exported.skipped
    doc = exported.exported[0].document
    changed = _with(doc, "controls.bypassScope", {"expression": "v1", "variables": [
        {"attribute": "image.name", "value": f"casc-no-such-{TAG}"}]})
    try:
        assert _run(client, kind_def, doc)[0].outcome is Outcome.ADOPTED
        assert _step(client, kind_def, changed, "changed") == []
        assert f"casc-no-such-{TAG}" in str(client.get(kind_def, name)["bypass_scope"])
        assert _step(client, kind_def, doc, "put back") == []
        assert client.get(kind_def, name)["bypass_scope"]["enabled"] == before["bypass_scope"]["enabled"]
    finally:
        client.update(kind_def, name, before)
    after = client.get(kind_def, name)
    volatile = {"lastupdate", "author", "updated", "last_update"}
    assert {k: v for k, v in after.items() if k not in volatile} == \
        {k: v for k, v in before.items() if k not in volatile}
