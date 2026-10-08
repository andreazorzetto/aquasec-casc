"""What the reconciler returns.

Result objects, never printed output. The reconciler does not know whether it is
running under a CLI, an Argo CD hook or a future operator, so it describes what
happened and lets the caller render it. Nothing in this package prints, and
nothing calls ``sys.exit``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .diff import Plan


class Outcome(str, Enum):
    IN_SYNC = "in-sync"
    CREATED = "created"
    UPDATED = "updated"

    ADOPTED = "adopted"
    """An existing object without our marker now carries it. The first apply
    after an export: nothing else changed, the tool has taken ownership."""

    DELETED = "deleted"

    RELEASED = "released"
    """``release``: this instance's marker removed (or rewritten for another
    instance). Nothing else on the object changed."""

    PLANNED = "planned"
    """Dry run: this is what would happen (see ``Result.action``)."""

    DRIFT_DETECTED = "drift-detected"
    """``spec.enforcement: ReportOnly``: drift found, deliberately not corrected."""

    BLOCKED = "blocked"
    """Refused for safety, e.g. the object is owned by another instance."""

    ORPHANED = "orphaned"
    """Carries our marker, has no file, and was not deleted -- because of
    ``--no-delete``, or because Aqua does not allow deleting it."""

    FAILED = "failed"


#: Outcomes that mean the tenant was actually modified.
MUTATING = frozenset({Outcome.CREATED, Outcome.UPDATED, Outcome.ADOPTED, Outcome.DELETED,
                      Outcome.RELEASED})

#: Outcomes that leave Git and Aqua apart.
PENDING = frozenset({Outcome.PLANNED, Outcome.DRIFT_DETECTED, Outcome.BLOCKED, Outcome.ORPHANED})


@dataclass
class Result:
    """The outcome of reconciling one object."""

    kind: str
    name: str
    outcome: Outcome

    aqua_name: str | None = None
    plan: Plan | None = None
    message: str = ""
    reason: str = ""

    action: str = ""
    """For PLANNED: create, adopt, update, delete, release or hand-over.
    For RELEASED: release or hand-over."""

    not_allowed: list[str] = field(default_factory=list)
    """Desired changes withheld because Aqua does not allow them (e.g. the scope
    of a predefined policy). The rest of the change is still applied."""

    informational: bool = False
    """Reported, but nothing anyone could do will resolve it -- so it never
    counts as pending (an orphaned predefined policy, which Aqua cannot delete,
    would otherwise pin exit code 2 forever)."""

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def changed(self) -> bool:
        return self.outcome in MUTATING

    @property
    def pending(self) -> bool:
        if self.informational:
            return False
        return self.outcome in PENDING or bool(self.not_allowed)

    @property
    def failed(self) -> bool:
        return self.outcome is Outcome.FAILED


@dataclass
class RunSummary:
    """Every result from one invocation, plus the pipeline-facing verdict."""

    results: list[Result] = field(default_factory=list)

    def add(self, result: Result) -> Result:
        self.results.append(result)
        return result

    def of(self, outcome: Outcome) -> list[Result]:
        return [r for r in self.results if r.outcome is outcome]

    @property
    def failed(self) -> list[Result]:
        return [r for r in self.results if r.failed]

    @property
    def pending(self) -> list[Result]:
        return [r for r in self.results if r.pending]

    @property
    def changed(self) -> list[Result]:
        return [r for r in self.results if r.changed]

    def exit_code(self, detailed: bool = True) -> int:
        """1 on any failure. Otherwise 2 if ``detailed`` and anything is pending, else 0.

        ``diff`` always runs detailed: reporting pending changes is its job.
        ``apply`` runs detailed only with ``--detailed-exitcode``, because Argo CD
        fails a sync on any non-zero hook exit -- a routine apply that leaves a
        held-back orphan must not block every future sync.
        """
        if self.failed:
            return 1
        if detailed and self.pending:
            return 2
        return 0

    def summary_line(self) -> str:
        """Always printed, e.g. ``3 unchanged, 1 created, 1 updated, 0 adopted, 0 deleted``."""
        counts = {
            "unchanged": len(self.of(Outcome.IN_SYNC)),
            "created": len(self.of(Outcome.CREATED)),
            "updated": len(self.of(Outcome.UPDATED)),
            "adopted": len(self.of(Outcome.ADOPTED)),
            "deleted": len(self.of(Outcome.DELETED)),
            "released": len(self.of(Outcome.RELEASED)),
            "planned": len(self.of(Outcome.PLANNED)),
            "drifted": len(self.of(Outcome.DRIFT_DETECTED)),
            "blocked": len(self.of(Outcome.BLOCKED)),
            "orphaned": len(self.of(Outcome.ORPHANED)),
            "failed": len(self.of(Outcome.FAILED)),
        }
        always = ("unchanged", "created", "updated", "adopted", "deleted")
        parts = [f"{counts[k]} {k}" for k in always]
        parts += [f"{v} {k}" for k, v in counts.items() if k not in always and v]
        not_allowed = sum(1 for r in self.results if r.not_allowed)
        if not_allowed:
            parts.append(f"{not_allowed} with changes not allowed")
        return ", ".join(parts)
