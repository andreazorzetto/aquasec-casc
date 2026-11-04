"""The Kubernetes resource shape shared by every CasC kind.

Phase 1 does not involve Kubernetes, but the objects are shaped as Kubernetes
resources anyway: it is the lingua franca of this space, it gives schema
versioning and validation conventions for free, and it means the phase 2 CRDs
are these same objects rather than a translation of them.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

GROUP = "config.aquasec.com"
VERSION = "v1alpha1"
API_VERSION = f"{GROUP}/{VERSION}"

# DNS-1123 subdomain, as Kubernetes requires of metadata.name. Aqua's own names
# are more permissive (spaces and capitals are legal there), which is precisely
# why spec.aquaName exists -- see ManagedSpec below.
_DNS_1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")


class Enforcement(str, Enum):
    """Whether this resource is actually reconciled, or only reported on."""

    RECONCILE = "Reconcile"
    REPORT_ONLY = "ReportOnly"


class StrictModel(BaseModel):
    """Base for every schema model: unknown fields are an error.

    A mistyped field in a security policy that is silently ignored is the
    failure mode this whole tool exists to prevent, so ``extra='forbid'`` is
    non-negotiable. The escape hatch is per-document, not per-model: see
    ``metadata.annotations['config.aquasec.com/allow-unknown-fields']``.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        use_enum_values=False,
        validate_default=False,
        use_attribute_docstrings=True,
    )


class Metadata(StrictModel):
    """Identity and labelling, as in any Kubernetes object."""

    name: Annotated[str, Field(min_length=1, max_length=253)]
    """The stable identity of this resource, and the key in the state file.

    This never changes over the life of the resource. It is *not* necessarily
    the name Aqua knows the object by -- that is ``spec.aquaName``, which
    defaults to this. Keeping the two separate is what lets a rename in Aqua be
    recognised as a rename rather than as a delete plus a create.
    """

    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _dns_1123(cls, value: str) -> str:
        if not _DNS_1123.match(value):
            raise ValueError(
                f"{value!r} is not a valid name: must be lowercase alphanumeric, "
                "'-' or '.', and start and end with an alphanumeric character "
                "(DNS-1123 subdomain). If the Aqua-side name needs different "
                "characters, set spec.aquaName instead."
            )
        return value


class ConditionStatus(str, Enum):
    TRUE = "True"
    FALSE = "False"
    UNKNOWN = "Unknown"


class Condition(StrictModel):
    """A Kubernetes-style status condition."""

    type: str
    status: ConditionStatus
    reason: str = ""
    message: str = ""
    lastTransitionTime: str | None = None


class ResourceStatus(StrictModel):
    """Written by the tool, never by a human.

    Phase 1 is stateless and writes no status anywhere: ownership lives on the
    Aqua object itself (see ``reconcile.marker``). The shape is kept for phase 2,
    where an operator reports observed state on the custom resource.
    """

    aquaName: str | None = None
    aquaId: int | None = None
    observedGeneration: int = 0
    lastSyncTime: str | None = None
    conditions: list[Condition] = Field(default_factory=list)


class ManagedSpec(StrictModel):
    """Spec fields common to every kind managed by this tool."""

    aquaName: str | None = None
    """The name this object has in Aqua. Defaults to ``metadata.name``.

    Set this when the Aqua-side name cannot be expressed as a DNS-1123 name --
    it has spaces or capitals, as Aqua's own names often do.
    """

    enforcement: Enforcement = Enforcement.RECONCILE

    @field_validator("aquaName")
    @classmethod
    def _addressable(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value in (".", "..") or len(value) > 128):
            raise ValueError("not a name Aqua can address: at most 128 characters, and not "
                             "empty, '.' or '..'")
        return value


class Resource(StrictModel):
    """The outer envelope: apiVersion, kind, metadata, spec, status."""

    apiVersion: str
    kind: str
    metadata: Metadata
    status: ResourceStatus | None = None

    @field_validator("apiVersion")
    @classmethod
    def _known_api_version(cls, value: str) -> str:
        if value != API_VERSION:
            raise ValueError(
                f"unsupported apiVersion {value!r}; this build understands "
                f"{API_VERSION!r}"
            )
        return value

    @property
    def aqua_name(self) -> str:
        """The name Aqua knows this object by."""
        spec: Any = getattr(self, "spec", None)
        return getattr(spec, "aquaName", None) or self.metadata.name

    @property
    def ref(self) -> str:
        """Short human reference, e.g. ``RuntimePolicy/devtest-baseline``."""
        return f"{self.kind}/{self.metadata.name}"
