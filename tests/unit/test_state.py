"""State persistence and the identity mapping.

The identity mapping is the thing that silently causes disasters. Aqua keys its
endpoints by name, so without a recorded name-to-name mapping a rename in Git
orphans the old policy and creates a duplicate -- which in an enforce-mode
production scope is a security incident, not a cosmetic bug.
"""

from __future__ import annotations

import pytest
import yaml

from aqua_casc.reconcile.state import (
    STATE_VERSION,
    FileStateBackend,
    ResourceState,
    StateError,
)


@pytest.fixture
def backend(tmp_path) -> FileStateBackend:
    return FileStateBackend(tmp_path).load()


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


def test_missing_state_file_is_an_empty_state_not_an_error(tmp_path):
    """First run against a fresh checkout must just work."""
    b = FileStateBackend(tmp_path).load()
    assert b.all() == []
    assert b.get("RuntimePolicy", "anything") is None


def test_record_then_reload(tmp_path, backend):
    backend.record(
        "RuntimePolicy", "devtest-baseline", "devtest-baseline",
        owned_fields=["enforce", "block_disallowed_images"],
    )
    backend.commit()

    reloaded = FileStateBackend(tmp_path).load()
    state = reloaded.get("RuntimePolicy", "devtest-baseline")

    assert state is not None
    assert state.aquaName == "devtest-baseline"
    assert state.lastAppliedFields == ["block_disallowed_images", "enforce"]
    assert state.observedGeneration == 1
    assert state.lastSyncTime is not None


def test_generation_increments_across_applies(backend):
    for expected in (1, 2, 3):
        s = backend.record("RuntimePolicy", "p", "p", owned_fields=["enforce"])
        assert s.observedGeneration == expected


def test_owned_fields_are_deduplicated_and_sorted(backend):
    s = backend.record(
        "RuntimePolicy", "p", "p", owned_fields=["b", "a", "b", "c"]
    )
    assert s.lastAppliedFields == ["a", "b", "c"]


def test_state_file_is_committable_yaml(tmp_path, backend):
    backend.record("RuntimePolicy", "p", "p", owned_fields=["enforce"])
    backend.commit()

    text = backend.path.read_text(encoding="utf-8")
    assert text.startswith("#")  # explains itself to whoever opens it
    assert "do not edit by hand" in text.lower()

    data = yaml.safe_load(text)
    assert data["version"] == STATE_VERSION
    assert "RuntimePolicy/p" in data["resources"]


def test_entries_are_written_in_a_stable_order(tmp_path):
    """A state file that reorders itself would produce noisy Git diffs."""
    b = FileStateBackend(tmp_path).load()
    for name in ("zeta", "alpha", "mid"):
        b.record("RuntimePolicy", name, name, owned_fields=["enforce"])
    b.commit()
    first = b.path.read_text(encoding="utf-8")

    b2 = FileStateBackend(tmp_path).load()
    b2.commit()
    assert b2.path.read_text(encoding="utf-8") == first


def test_delete_removes_an_entry(backend):
    backend.record("RuntimePolicy", "p", "p", owned_fields=[])
    backend.delete("RuntimePolicy", "p")
    assert backend.get("RuntimePolicy", "p") is None


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "credential_field",
    ["token", "install_command", "command", "pas_deployment_link", "password"],
)
def test_claiming_ownership_of_a_credential_field_is_refused(backend, credential_field):
    """An enforcer group carries its registration token in these fields.

    Owning one would write it to the state file (committed to Git) and push it
    back to Aqua on every apply.
    """
    with pytest.raises(StateError, match="credential"):
        backend.record(
            "EnforcerGroup", "g", "g",
            owned_fields=["gateways", credential_field],
        )


def test_the_refusal_names_the_offending_field_and_the_alternative(backend):
    with pytest.raises(StateError) as exc:
        backend.record("EnforcerGroup", "g", "g", owned_fields=["token"])

    message = str(exc.value)
    assert "token" in message
    assert "EnforcerGroup/g" in message
    assert "tokenSecretRef" in message


def test_a_field_merely_containing_a_credential_word_is_allowed(backend):
    """Guard on whole path segments, not substrings.

    A runtime policy legitimately has a ``user_access_control`` block with a
    ``user_password`` field, and refusing to manage it would be wrong.
    """
    backend.record(
        "RuntimePolicy", "p", "p",
        owned_fields=["auditing.audit_failed_login", "user_access.user_password_policy"],
    )
    backend.commit()  # must not raise


def test_a_credential_path_smuggled_in_after_record_is_still_caught(backend):
    """The check runs at commit too, not only at record."""
    backend.record("EnforcerGroup", "g", "g", owned_fields=["gateways"])
    backend.get("EnforcerGroup", "g").lastAppliedFields.append("token")

    with pytest.raises(StateError, match="credential"):
        backend.commit()


def test_a_failed_commit_leaves_no_stray_temp_file(tmp_path, backend):
    backend.record("EnforcerGroup", "g", "g", owned_fields=["gateways"])
    backend.get("EnforcerGroup", "g").lastAppliedFields.append("token")

    with pytest.raises(StateError):
        backend.commit()

    strays = list((tmp_path / ".aqua-casc").glob("*.tmp"))
    assert strays == []


def test_a_failed_commit_does_not_corrupt_existing_state(tmp_path, backend):
    """Atomic write: a good state file must survive a later bad commit."""
    backend.record("RuntimePolicy", "good", "good", owned_fields=["enforce"])
    backend.commit()
    before = backend.path.read_text(encoding="utf-8")

    backend.record("EnforcerGroup", "g", "g", owned_fields=["gateways"])
    backend.get("EnforcerGroup", "g").lastAppliedFields.append("token")
    with pytest.raises(StateError):
        backend.commit()

    assert backend.path.read_text(encoding="utf-8") == before


# --------------------------------------------------------------------------- #
# Rename detection -- the disaster case
# --------------------------------------------------------------------------- #


def test_an_unmanaged_object_is_never_a_rename(backend):
    """No state entry means no ownership claim, so it is a create or adoption."""
    assert backend.detect_rename("RuntimePolicy", "new-thing", "whatever") is None


def test_same_aqua_name_is_not_a_rename(backend):
    backend.record("RuntimePolicy", "devtest", "devtest-baseline", owned_fields=[])
    assert backend.detect_rename("RuntimePolicy", "devtest", "devtest-baseline") is None


def test_a_changed_aqua_name_under_a_stable_identity_is_a_rename(backend):
    """The whole reason metadata.name and spec.aquaName are separate."""
    backend.record("RuntimePolicy", "devtest", "old-name", owned_fields=["enforce"])

    rename = backend.detect_rename("RuntimePolicy", "devtest", "new-name")

    assert rename is not None
    assert rename.from_name == "old-name"
    assert rename.to_name == "new-name"
    assert "old-name" in rename.render() and "new-name" in rename.render()


# --------------------------------------------------------------------------- #
# Orphans
# --------------------------------------------------------------------------- #


def test_orphans_are_managed_objects_whose_files_vanished(backend):
    backend.record("RuntimePolicy", "kept", "kept", owned_fields=[])
    backend.record("RuntimePolicy", "removed", "removed", owned_fields=[])

    orphans = backend.orphans(present={("RuntimePolicy", "kept")})

    assert [o.name for o in orphans] == ["removed"]


def test_nothing_is_orphaned_when_every_file_is_present(backend):
    backend.record("RuntimePolicy", "a", "a", owned_fields=[])
    assert backend.orphans(present={("RuntimePolicy", "a")}) == []


# --------------------------------------------------------------------------- #
# Malformed input
# --------------------------------------------------------------------------- #


def test_a_future_state_version_is_refused(tmp_path):
    path = tmp_path / ".aqua-casc" / "state.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: 999\nresources: {}\n", encoding="utf-8")

    with pytest.raises(StateError, match="not supported"):
        FileStateBackend(tmp_path).load()


def test_unrecognised_state_keys_are_refused(tmp_path):
    """Better to stop than to silently drop an identity mapping we cannot read."""
    path = tmp_path / ".aqua-casc" / "state.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(
        "version: 1\nresources:\n  RuntimePolicy/p:\n    somethingNew: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(StateError, match="newer version"):
        FileStateBackend(tmp_path).load()


def test_invalid_yaml_is_reported_with_the_path(tmp_path):
    path = tmp_path / ".aqua-casc" / "state.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("resources: [unclosed\n", encoding="utf-8")

    with pytest.raises(StateError, match="invalid YAML"):
        FileStateBackend(tmp_path).load()


def test_malformed_state_key_is_reported(tmp_path):
    path = tmp_path / ".aqua-casc" / "state.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("version: 1\nresources:\n  nokindslash: {}\n", encoding="utf-8")

    with pytest.raises(StateError, match="malformed"):
        FileStateBackend(tmp_path).load()


def test_resource_state_mirrors_the_schema_status_shape():
    """Phase 2 writes this straight to .status, so the fields must line up."""
    from aqua_casc.schema.base import ResourceStatus

    state_fields = set(ResourceState.__dataclass_fields__) - {"kind", "name"}
    status_fields = set(ResourceStatus.model_fields) - {"conditions"}

    assert state_fields == status_fields
