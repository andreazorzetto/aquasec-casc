"""What the reconciler returns.

Result objects, never printed output. The reconciler does not know whether it is
running under a CLI, an Argo CD hook or a future operator, so it describes what
happened and lets the caller render it. This is the rule most easily broken and
the one that makes phase 2 cheap, so it is worth restating: nothing in this
package prints, and nothing calls ``sys.exit``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .diff import Plan
from .state import RenameDetected


class Outcome(str, Enum):
    IN_SYNC = "in-sync"
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    RENAMED = "renamed"

    PLANNED = "planned"
    """Dry run: this is what would happen."""

    DRIFT_DETECTED = "drift-detected"
    """ReportOnly: drift found, deliberately not corrected."""

    BLOCKED = "blocked"
    """Refused for safety. Needs an explicit flag to proceed."""

    FAILED = "failed"


#: Outcomes that mean the tenant was actually modified.
MUTATING = frozenset({Outcome.CREATED, Outcome.UPDATED, Outcome.DELETED, Outcome.RENAMED})

#: Outcomes a pipeline should gate on -- these drive exit code 2.
PENDING = frozenset({Outcome.PLANNED, Outcome.DRIFT_DETECTED, Outcome.BLOCKED})


@dataclass
class Result:
    """The outcome of reconciling one resource."""

    kind: str
    name: str
    outcome: Outcome

    aqua_name: str | None = None
    plan: Plan | None = None
    rename: RenameDetected | None = None
    message: str = ""
    reason: str = ""

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.name}"

    @property
    def changed(self) -> bool:
        return self.outcome in MUTATING

    @property
    def pending(self) -> bool:
        """Something a pipeline should notice but which was not applied."""
        return self.outcome in PENDING

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

    def exit_code(self) -> int:
        """Follows ``terraform plan -detailed-exitcode``.

        0 success and nothing outstanding, 1 error, 2 changes present or drift
        detected. Exit code 2 is what lets a pipeline gate on drift, so it must
        not be conflated with failure.
        """
        if self.failed:
            return 1
        if self.pending:
            return 2
        return 0

    def summary_line(self) -> str:
        """Always printed by the CLI, e.g. ``3 unchanged, 1 updated, 0 created``."""
        counts = {
            "unchanged": len(self.of(Outcome.IN_SYNC)),
            "created": len(self.of(Outcome.CREATED)),
            "updated": len(self.of(Outcome.UPDATED)),
            "renamed": len(self.of(Outcome.RENAMED)),
            "deleted": len(self.of(Outcome.DELETED)),
            "planned": len(self.of(Outcome.PLANNED)),
            "drifted": len(self.of(Outcome.DRIFT_DETECTED)),
            "blocked": len(self.of(Outcome.BLOCKED)),
            "failed": len(self.of(Outcome.FAILED)),
        }
        # Always show the core four; show the rest only when non-zero, so the
        # common case stays short without hiding anything that happened.
        always = ("unchanged", "created", "updated", "deleted")
        parts = [f"{counts[k]} {k}" for k in always]
        parts += [f"{v} {k}" for k, v in counts.items() if k not in always and v]
        return ", ".join(parts)
