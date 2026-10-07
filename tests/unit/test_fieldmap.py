"""Canonical <-> Aqua API field translation.

These tests matter more than they look. ``owned_api_paths`` is the set of
fields the reconciler manages, and if it over-reports -- claiming fields the
user never wrote -- the reconciler will overwrite Aqua's defaults and console
edits on the first apply.
"""

from __future__ import annotations

import textwrap

import pytest

from aqua_casc.schema import FieldMap, FieldMapping, get_path, load_document, set_path
from aqua_casc.schema.fieldmap import MISSING, has_path
from aqua_casc.schema.runtime_policy import FIELD_MAP


def parse(body: str):
    import yaml

    return load_document(yaml.safe_load(textwrap.dedent(body).lstrip()), "test.yaml")[0]


def canonical_of(resource) -> dict:
    """What the reconciler will diff with: only fields the user actually set."""
    return resource.model_dump(exclude_unset=True, mode="json")


# --------------------------------------------------------------------------- #
# Path helpers
# --------------------------------------------------------------------------- #


def test_get_path_distinguishes_absent_from_none():
    obj = {"a": {"b": None}}
    assert get_path(obj, "a.b") is None
    assert get_path(obj, "a.c") is MISSING
    assert has_path(obj, "a.b") is True
    assert has_path(obj, "a.c") is False


def test_set_path_creates_intermediate_dicts():
    obj: dict = {}
    set_path(obj, "container_exec.block_container_exec", True)
    assert obj == {"container_exec": {"block_container_exec": True}}


def test_set_path_replaces_a_non_dict_intermediate():
    obj = {"container_exec": "surprise"}
    set_path(obj, "container_exec.block_container_exec", True)
    assert obj == {"container_exec": {"block_container_exec": True}}


# --------------------------------------------------------------------------- #
# Ownership -- the three-way diff basis
# --------------------------------------------------------------------------- #


def test_owned_paths_contain_only_what_the_user_wrote():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          enforce: false
          controls:
            blockNonCompliantImages: false
        """
    )
    owned = FIELD_MAP.owned_api_paths(canonical_of(resource))

    assert "enforce" in owned
    assert "block_disallowed_images" in owned

    # Never claimed: the user said nothing about these, so they belong to Aqua.
    assert "block_fileless_exec" not in owned
    assert "drift_prevention.enabled" not in owned
    assert "description" not in owned


def test_unset_fields_with_defaults_are_not_owned():
    """A schema default is not a user statement of intent.

    ``enforcement`` defaults to Reconcile and ``enabled`` to true, but a
    document that never mentions them must not claim them -- otherwise the first
    apply would write our defaults over whatever the console has.
    """
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          enforce: false
        """
    )
    canonical = canonical_of(resource)

    assert resource.spec.enabled is True          # default applied in the model
    assert "enabled" not in FIELD_MAP.owned_api_paths(canonical)  # but not owned


# --------------------------------------------------------------------------- #
# Projection to the API shape
# --------------------------------------------------------------------------- #


def test_to_api_nests_controls_the_way_aqua_does():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockContainerExec: true
            driftPrevention:
              enabled: true
              execLockdown: true
              exceptions: ["redis-*"]
        """
    )
    api = FIELD_MAP.to_api(canonical_of(resource))

    assert api["container_exec"]["block_container_exec"] is True
    assert api["drift_prevention"] == {
        "enabled": True,
        "exec_lockdown": True,
        "exec_lockdown_white_list": ["redis-*"],
    }
    # The vestigial top-level flag is never written; the nested one is
    # authoritative. On the lab tenant the top-level field is False even on
    # policies where the control is demonstrably on.
    assert "block_container_exec" not in api


def test_gated_controls_write_their_enabled_flag_too():
    """Aqua gates several controls behind an 'enabled' sibling.

    Writing the inner flag alone produces a policy that diffs clean and does
    nothing in the cluster -- the worst failure this tool could have.
    """
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockContainerExec: true
            blockReverseShell: true
        """
    )
    api = FIELD_MAP.to_api(canonical_of(resource))

    assert api["container_exec"] == {"block_container_exec": True, "enabled": True}
    assert api["reverse_shell"] == {"block_reverse_shell": True, "enabled": True}


def test_gate_follows_the_control_when_turned_off():
    """The gate tracks the flag in both directions, as the tenant data shows."""
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockContainerExec: false
        """
    )
    api = FIELD_MAP.to_api(canonical_of(resource))
    assert api["container_exec"] == {"block_container_exec": False, "enabled": False}


def test_gates_are_owned_so_the_diff_can_revert_them():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockContainerExec: true
        """
    )
    owned = FIELD_MAP.owned_api_paths(canonical_of(resource))
    assert "container_exec.block_container_exec" in owned
    assert "container_exec.enabled" in owned


def test_gates_are_not_read_back_as_canonical_fields():
    """from_api must not invent a canonical field out of a gate."""
    server = {"container_exec": {"enabled": True, "block_container_exec": True}}
    canonical = FIELD_MAP.from_api(server)
    assert canonical["spec"]["controls"]["blockContainerExec"] is True
    assert "enabled" not in canonical["spec"]["controls"]


def test_to_api_omits_everything_the_user_did_not_set():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          enforce: false
        """
    )
    assert FIELD_MAP.to_api(canonical_of(resource)) == {
        "enforce": False, "application_scopes": ["DevTest"],
    }


def test_enum_values_project_as_plain_strings():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          runtimeType: container
        """
    )
    assert FIELD_MAP.to_api(canonical_of(resource)) == {
        "runtime_type": "container", "application_scopes": ["DevTest"],
    }


# --------------------------------------------------------------------------- #
# Projection back from the API -- the export path
# --------------------------------------------------------------------------- #


def test_from_api_ignores_server_owned_fields():
    """Export must not invent spec fields out of Aqua's own metadata."""
    server = {
        "name": "devtest-baseline",
        "enforce": False,
        "container_exec": {"block_container_exec": True},
        # Server-assigned; not in the field map, so not ours.
        "author": "someone@example.com",
        "created": "2026-01-01T00:00:00Z",
        "digest": "abc123",
        "is_ootb_policy": False,
        "version": "2.0",
    }
    canonical = FIELD_MAP.from_api(server)

    assert canonical["spec"]["enforce"] is False
    assert canonical["spec"]["controls"]["blockContainerExec"] is True
    assert "author" not in str(canonical)
    assert "digest" not in str(canonical)


def test_round_trip_is_stable():
    """to_api -> from_api -> to_api must not drift.

    This is the property that makes 'export then apply changes nothing' true.
    """
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          description: Dev/test baseline
          enforce: false
          applicationScopes: ["DevTest"]
          controls:
            blockNonCompliantImages: false
            blockContainerExec: true
            driftPrevention:
              enabled: true
              execLockdown: true
              exceptions: ["redis-*"]
        """
    )
    once = FIELD_MAP.to_api(canonical_of(resource))
    twice = FIELD_MAP.to_api(FIELD_MAP.from_api(once))
    assert once == twice


# --------------------------------------------------------------------------- #
# Version drift: aliases
# --------------------------------------------------------------------------- #


def test_read_falls_back_to_an_older_api_name():
    """An on-prem tenant predating a rename still maps onto current names."""
    old_tenant = {"block_unregistered_images": True, "limit_new_privileges": True}
    canonical = FIELD_MAP.from_api(old_tenant)

    assert canonical["spec"]["controls"]["onlyRegisteredImages"] is True
    assert canonical["spec"]["controls"]["noNewPrivileges"] is True


def test_write_always_uses_the_current_api_name():
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            onlyRegisteredImages: true
        """
    )
    api = FIELD_MAP.to_api(canonical_of(resource))
    assert api == {"only_registered_images": True, "application_scopes": ["DevTest"]}
    assert "block_unregistered_images" not in api


def test_current_name_wins_when_a_tenant_returns_both():
    both = {"only_registered_images": True, "block_unregistered_images": False}
    canonical = FIELD_MAP.from_api(both)
    assert canonical["spec"]["controls"]["onlyRegisteredImages"] is True


def test_resolve_api_path_settles_ambiguity_against_a_real_object():
    """The mechanism that will resolve the block_non_compliant_images question."""
    modern = {"block_disallowed_images": True}
    legacy = {"block_non_compliant_images": True}
    absent: dict = {}

    path = "spec.controls.blockNonCompliantImages"
    assert FIELD_MAP.resolve_api_path(modern, path) == "block_disallowed_images"
    assert FIELD_MAP.resolve_api_path(legacy, path) == "block_non_compliant_images"
    assert FIELD_MAP.resolve_api_path(absent, path) is None


def test_the_demo_field_maps_to_the_name_the_tenant_actually_uses():
    """Settled against the eu-1 lab tenant on 11 Sep 2026.

    All 47 runtime policies carry block_disallowed_images; none carries
    block_non_compliant_images. Writing the wrong one would be ignored silently.
    """
    resource = parse(
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockNonCompliantImages: false
        """
    )
    assert FIELD_MAP.to_api(canonical_of(resource)) == {
        "block_disallowed_images": False, "application_scopes": ["DevTest"],
    }


def test_the_retired_name_is_still_accepted_on_read():
    """Kept for on-prem builds that may predate the rename."""
    legacy = {"block_non_compliant_images": True}
    canonical = FIELD_MAP.from_api(legacy)
    assert canonical["spec"]["controls"]["blockNonCompliantImages"] is True


# --------------------------------------------------------------------------- #
# Table integrity
# --------------------------------------------------------------------------- #


def test_duplicate_canonical_paths_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        FieldMap(
            kind="Test",
            mappings=[
                FieldMapping("spec.a", "a"),
                FieldMapping("spec.a", "b"),
            ],
        )


def test_no_two_canonical_fields_write_to_the_same_api_path():
    """Two canonical fields sharing an API path would silently overwrite."""
    seen: dict[str, str] = {}
    for mapping in FIELD_MAP.mappings:
        assert mapping.api not in seen, (
            f"{mapping.canonical} and {seen.get(mapping.api)} both write to "
            f"{mapping.api}"
        )
        seen[mapping.api] = mapping.canonical


def test_every_mapped_canonical_path_exists_in_the_model():
    """Catches a mapping that outlived the field it refers to."""
    from aqua_casc.schema.runtime_policy import RuntimePolicy

    for mapping in FIELD_MAP.mappings:
        parts = mapping.canonical.split(".")
        assert parts[0] == "spec", mapping.canonical

        model = RuntimePolicy.model_fields["spec"].annotation
        for part in parts[1:]:
            assert part in model.model_fields, (
                f"{mapping.canonical} refers to {part!r}, which the model lacks"
            )
            info = model.model_fields[part]
            from pydantic import BaseModel
            from typing import get_args

            nested = next(
                (
                    c
                    for c in (info.annotation, *get_args(info.annotation or ()))
                    if isinstance(c, type) and issubclass(c, BaseModel)
                ),
                None,
            )
            if nested is not None:
                model = nested
