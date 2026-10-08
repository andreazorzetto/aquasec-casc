"""The ownership marker in an object's description."""

from __future__ import annotations

import pytest

from aquasec_casc.reconcile import marker


def test_compose_puts_the_marker_on_its_own_line():
    assert marker.compose("Dev/test baseline", "platform") == (
        "Dev/test baseline\n\nmanaged-by: aquasec-casc/platform"
    )


def test_compose_with_no_text_is_just_the_marker():
    assert marker.compose("", "platform") == "managed-by: aquasec-casc/platform"
    assert marker.compose(None, "platform") == "managed-by: aquasec-casc/platform"


def test_compose_is_idempotent():
    """Re-composing a marked description must not change it -- or it is drift every run."""
    once = marker.compose("Dev/test baseline", "platform")
    assert marker.compose(once, "platform") == once


def test_compose_replaces_another_marker_rather_than_stacking():
    other = marker.compose("text", "team-b")
    assert marker.compose(other, "platform") == "text\n\nmanaged-by: aquasec-casc/platform"


def test_owner():
    assert marker.owner("text\n\nmanaged-by: aquasec-casc/platform") == "platform"
    assert marker.owner("managed-by: aquasec-casc/team-b") == "team-b"
    assert marker.owner("plain description") is None
    assert marker.owner("") is None
    assert marker.owner(None) is None


def test_owner_ignores_a_marker_buried_mid_sentence():
    """Only a line of its own counts; prose that mentions the tool does not."""
    assert marker.owner("see managed-by: aquasec-casc/platform for details") is None


def test_owner_tolerates_surrounding_whitespace_and_crlf():
    assert marker.owner("text\r\n\r\n  managed-by: aquasec-casc/platform  \r\n") == "platform"


def test_last_marker_wins():
    assert marker.owner("managed-by: aquasec-casc/a\nmanaged-by: aquasec-casc/b") == "b"


def test_strip_removes_the_marker_and_tidies():
    assert marker.strip("Dev/test baseline\n\nmanaged-by: aquasec-casc/platform") == "Dev/test baseline"
    assert marker.strip("managed-by: aquasec-casc/platform") == ""
    assert marker.strip("untouched text") == "untouched text"
    assert marker.strip(None) == ""


def test_strip_keeps_other_tools_lines():
    text = "Owner: platform team\nmanaged-by: terraform\n\nmanaged-by: aquasec-casc/platform"
    assert marker.strip(text) == "Owner: platform team\nmanaged-by: terraform"


@pytest.mark.parametrize("name", ["platform", "team-a", "a", "x" * 63, "a1-b2"])
def test_valid_instance_names(name):
    assert marker.validate_instance(name) == name


@pytest.mark.parametrize("name", ["", "Platform", "team_a", "-team", "team-", "x" * 64, "a b", "a/b"])
def test_invalid_instance_names(name):
    with pytest.raises(marker.InvalidInstance):
        marker.validate_instance(name)
