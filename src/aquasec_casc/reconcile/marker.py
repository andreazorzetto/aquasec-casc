"""The ownership marker: how the tool knows which Aqua objects are its own.

There is no state file. Ownership lives on the object itself, in its
description, the same idea as ``kubectl apply``'s annotation or Argo CD's
tracking label:

    Dev/test baseline -- no image-compliance enforcement

    managed-by: aquasec-casc/platform

The instance name after the slash identifies *which* deployment of the tool
owns the object, so two repositories or teams on one tenant never treat each
other's objects as orphans, and never delete them.

Verified on a live tenant: descriptions keep newlines and store at least 10,000
characters exactly, so the marker can sit on its own line without truncation.

Pure functions, no I/O -- like the field map, this is meant to port to another
language as-is.
"""

from __future__ import annotations

import re

from .. import TOOL_NAME

TOOL = TOOL_NAME
PREFIX = f"managed-by: {TOOL}/"

#: Instance names are DNS-1123 labels: short, lowercase, unambiguous in a URL,
#: a label value or a file name.
INSTANCE_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

_LINE = re.compile(r"^\s*managed-by:\s*" + re.escape(TOOL) + r"/(\S+)\s*$", re.MULTILINE)


class InvalidInstance(ValueError):
    pass


def validate_instance(instance: str) -> str:
    if not instance or not INSTANCE_PATTERN.match(instance):
        raise InvalidInstance(
            f"{instance!r} is not a valid instance name: use lowercase letters, "
            "digits and '-', starting and ending with a letter or digit, at "
            "most 63 characters (e.g. 'platform' or 'team-a')."
        )
    return instance


def marker(instance: str) -> str:
    """The marker line for an instance."""
    return PREFIX + validate_instance(instance)


def owner(description: str | None) -> str | None:
    """The instance named by the marker in a description, or None if unmarked.

    If a description somehow carries more than one marker line, the last one
    wins -- that is the one ``compose`` would have written most recently.
    """
    if not description:
        return None
    found = _LINE.findall(description)
    return found[-1] if found else None


def strip(description: str | None) -> str:
    """The description with every marker line removed, tidied at the end."""
    if not description:
        return ""
    without = _LINE.sub("", description)
    return without.rstrip()


def compose(text: str | None, instance: str) -> str:
    """The description to send: the human text, then the marker on its own line.

    Idempotent: composing an already-marked description yields the same
    string, so the marker never shows up as drift on an unchanged object.
    """
    base = strip(text)
    line = marker(instance)
    return f"{base}\n\n{line}" if base else line
