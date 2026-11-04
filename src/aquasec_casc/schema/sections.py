"""What the policy kinds share: the shape of a console control, and scope criteria."""

from __future__ import annotations

from pydantic import Field, model_validator

from .base import StrictModel
from .fieldmap import FieldMapping


class Section(StrictModel):
    """A console control: its "Enable ... control" switch plus its settings.

    ``true`` is shorthand for "on, no settings", ``false`` for off. Writing any
    setting turns the control on unless ``enabled: false`` is written too. In
    the API the switch and the settings are separate fields, and settings under
    a switch that is off do nothing -- silently. Asking for a file block list
    and getting no file block is exactly that trap.

    Names are the console's labels, in camelCase.
    """

    enabled: bool = False

    @model_validator(mode="before")
    @classmethod
    def _settings_turn_the_section_on(cls, data):
        if isinstance(data, bool):
            return {"enabled": data}
        if isinstance(data, dict) and data and "enabled" not in data:
            return {**data, "enabled": True}
        return data


class Heading(StrictModel):
    """The controls, actions or exceptions of a policy.

    With everything under it removed or commented out, ``controls:`` is left with
    nothing, which YAML reads as null. That says the same as leaving it out.
    """

    @model_validator(mode="before")
    @classmethod
    def _nothing_under_it(cls, data):
        return {} if data is None else data


class ScopeVariable(StrictModel):
    """One term of a scope expression, e.g. a container label match."""

    attribute: str
    value: str
    name: str | None = None


class AdditionalScopeCriteria(StrictModel):
    """The console's Additional Scope Criteria: what, within the application
    scopes, a policy applies to. They can narrow a policy, never widen it."""

    expression: str
    """How the variables combine, e.g. ``v1 || v2``; ``v1`` is the first."""

    variables: list[ScopeVariable] = Field(min_length=1)


def control(name: str, switch: str, settings: dict[str, str],
            also_set: tuple[str, ...] = (), under: str = "spec.controls") -> list[FieldMapping]:
    """Mappings for one control section: its switch, then each setting, all as
    full API paths. ``also_set`` are gates written alongside the switch."""
    base = f"{under}.{name}"
    return [FieldMapping(f"{base}.enabled", switch, also_set=also_set),
            *(FieldMapping(f"{base}.{c}", a) for c, a in settings.items())]
