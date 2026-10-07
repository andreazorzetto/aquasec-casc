"""Schema validation: what loads, what does not, and what the errors say."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aqua_casc.schema import (
    ALLOW_UNKNOWN_ANNOTATION,
    Enforcement,
    RuntimeType,
    SchemaError,
    SchemaErrorGroup,
    load_dir,
    load_file,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "two-scope"


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


MINIMAL = """
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


def test_minimal_document_loads(tmp_path):
    result = load_file(write(tmp_path, "p.yaml", MINIMAL))

    assert len(result.resources) == 1
    policy = result.resources[0]
    assert policy.metadata.name == "devtest-baseline"
    assert policy.spec.enforce is False
    assert policy.spec.controls.blockNonCompliantImages is False
    assert not result.warnings


def test_defaults_are_the_safe_ones(tmp_path):
    policy = load_file(write(tmp_path, "p.yaml", MINIMAL)).resources[0]

    # Removing a file must never silently delete a production policy, and a
    # policy must not start enforcing just because it was created.
    assert policy.spec.enforcement is Enforcement.RECONCILE
    assert policy.spec.runtimeType is RuntimeType.CONTAINER


def test_aqua_name_defaults_to_metadata_name(tmp_path):
    policy = load_file(write(tmp_path, "p.yaml", MINIMAL)).resources[0]
    assert policy.aqua_name == "devtest-baseline"


def test_aqua_name_can_differ_for_adoption(tmp_path):
    """Aqua names allow spaces and capitals; metadata.name does not."""
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          aquaName: "Dev Test Baseline"
        """,
    )
    policy = load_file(path).resources[0]
    assert policy.metadata.name == "devtest-baseline"
    assert policy.aqua_name == "Dev Test Baseline"


def test_unknown_field_is_rejected_with_a_suggestion(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          controls:
            blockContainerExecc: true
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)

    rendered = exc.value.render()
    assert "unknown field" in rendered
    assert "spec.controls.blockContainerExecc" in rendered
    assert "blockContainerExec" in rendered  # the did-you-mean
    assert "p.yaml" in rendered


def test_unknown_field_without_a_near_match_points_at_the_escape_hatch(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          somethingEntirelyMadeUp: true
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert ALLOW_UNKNOWN_ANNOTATION in exc.value.render()


def test_escape_hatch_downgrades_unknown_fields_to_warnings(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        f"""
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
          annotations:
            {ALLOW_UNKNOWN_ANNOTATION}: "true"
        spec:
          applicationScopes: ["DevTest"]
          somethingEntirelyMadeUp: true
          enforce: false
        """,
    )
    result = load_file(path)

    assert len(result.resources) == 1
    assert result.resources[0].spec.enforce is False
    assert any("somethingEntirelyMadeUp" in w for w in result.warnings)
    assert any("dropped" in w for w in result.warnings)


def test_escape_hatch_does_not_suppress_real_type_errors(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        f"""
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
          annotations:
            {ALLOW_UNKNOWN_ANNOTATION}: "true"
        spec:
          applicationScopes: ["DevTest"]
          enforce: "not-a-boolean-at-all"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec.enforce" in exc.value.render()


def test_every_problem_is_reported_not_just_the_first(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: ["DevTest"]
          enforce: "nope"
          enabled: "also-nope"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert len(exc.value.problems) == 2


def test_wrong_api_version_is_rejected(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "apiVersion" in exc.value.render()


def test_unknown_kind_lists_what_is_supported(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: NotAThing
        metadata:
          name: x
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "RuntimePolicy" in exc.value.render()


def test_invalid_metadata_name_points_at_aqua_name(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: "Dev Test Baseline"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec.aquaName" in exc.value.render()


def test_invalid_yaml_names_the_file(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("kind: [unclosed\n", encoding="utf-8")
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "invalid YAML" in exc.value.render()
    assert "broken.yaml" in exc.value.render()


def test_multi_document_file(tmp_path):
    path = write(
        tmp_path,
        "both.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: one
        spec:
          applicationScopes: ["DevTest"]
        ---
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: two
        spec:
          applicationScopes: ["DevTest"]
        """,
    )
    result = load_file(path)
    assert [r.metadata.name for r in result.resources] == ["one", "two"]


def test_directory_load_collects_errors_from_every_file(tmp_path):
    write(tmp_path, "bad1.yaml", "kind: RuntimePolicy\napiVersion: wrong\nmetadata:\n  name: a\n")
    write(tmp_path, "bad2.yaml", "kind: Nope\napiVersion: config.aquasec.com/v1alpha1\nmetadata:\n  name: b\n")

    with pytest.raises(SchemaErrorGroup) as exc:
        load_dir(tmp_path)
    assert len(exc.value.errors) == 2


def test_duplicate_kind_and_name_is_an_error(tmp_path):
    write(tmp_path, "a.yaml", MINIMAL)
    write(tmp_path, "b.yaml", MINIMAL)

    with pytest.raises(SchemaErrorGroup) as exc:
        load_dir(tmp_path)
    assert "duplicate" in str(exc.value)


def test_the_tools_config_file_is_not_treated_as_a_resource(tmp_path):
    write(tmp_path, "p.yaml", MINIMAL)
    (tmp_path / "aqua-casc.yaml").write_text("instance: platform\n", encoding="utf-8")

    result = load_dir(tmp_path)
    assert len(result.resources) == 1


def test_a_config_file_name_in_a_subdirectory_is_still_loaded_as_a_resource(tmp_path):
    """Only the root-level aqua-casc.yaml is settings; elsewhere it is just a file."""
    write(tmp_path, "p.yaml", MINIMAL)
    sub = tmp_path / "team"
    sub.mkdir()
    (sub / "aqua-casc.yaml").write_text("instance: platform\n", encoding="utf-8")

    with pytest.raises(SchemaErrorGroup):
        load_dir(tmp_path)


def test_deletion_policy_is_no_longer_part_of_the_schema(tmp_path):
    """Deletion is decided per run (--no-delete), not per resource."""
    path = write(tmp_path, "p.yaml", MINIMAL + "      deletionPolicy: Orphan\n")
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "deletionPolicy" in exc.value.render()


def test_shipped_examples_are_valid():
    """The examples shipped with the repo must actually parse."""
    result = load_dir(EXAMPLES)

    names = {r.metadata.name for r in result.resources}
    assert {"devtest-baseline", "accprod-baseline"} <= names
    assert not result.warnings

    devtest = next(r for r in result.resources if r.metadata.name == "devtest-baseline")
    assert devtest.spec.enforce is False
    assert devtest.spec.controls.blockNonCompliantImages is False
    assert devtest.spec.controls.driftPrevention.exceptions == ["redis-*"]


# --------------------------------------------------------------------------- #
# applicationScopes is required
# --------------------------------------------------------------------------- #


def test_a_policy_without_scopes_is_rejected_and_the_error_says_why(tmp_path):
    """Aqua's default for no scopes is Global -- every workload.

    Getting that by omission is the mistake this rule prevents; the error must
    explain it, not just say "required".
    """
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          enforce: true
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    rendered = exc.value.render()
    assert "spec.applicationScopes: required" in rendered
    assert "Global" in rendered and "every" in rendered


def test_an_empty_scope_list_is_rejected_too(tmp_path):
    """[] would fall through to the same Global default."""
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          applicationScopes: []
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec.applicationScopes" in exc.value.render()


def test_global_is_allowed_when_written_explicitly(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: everything
        spec:
          applicationScopes: ["Global"]
        """,
    )
    assert load_file(path).resources[0].spec.applicationScopes == ["Global"]


def test_a_document_without_spec_is_rejected(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec: required" in exc.value.render()
