"""Validation errors that name the file, the path and the problem.

A silent typo in a security policy is unacceptable, so every error raised here
carries enough context for someone to fix it without opening a debugger:
which file, which field path inside that file, and what was actually wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SchemaProblem:
    """A single validation failure at one location."""

    path: str
    """Dotted path to the offending field, e.g. ``spec.controls.blockContainerExec``."""

    message: str
    """What was wrong, in words a human can act on."""

    hint: str = ""
    """Optional suggestion, e.g. the nearest valid field name for a typo."""

    def render(self) -> str:
        line = f"  {self.path}: {self.message}" if self.path else f"  {self.message}"
        if self.hint:
            line += f"\n    hint: {self.hint}"
        return line


class SchemaError(Exception):
    """One or more validation failures in a single document.

    Collects every problem rather than raising on the first, so a person fixing
    a file sees the whole list in one pass instead of playing whack-a-mole.
    """

    def __init__(
        self,
        source: str,
        problems: list[SchemaProblem],
        kind: str | None = None,
        name: str | None = None,
    ) -> None:
        self.source = source
        self.problems = problems
        self.kind = kind
        self.name = name
        super().__init__(self.render())

    def render(self) -> str:
        subject = self.source
        if self.kind and self.name:
            subject = f"{self.source} ({self.kind}/{self.name})"
        elif self.kind:
            subject = f"{self.source} ({self.kind})"

        body = "\n".join(p.render() for p in self.problems)
        count = len(self.problems)
        plural = "problem" if count == 1 else "problems"
        return f"{subject}: {count} validation {plural}\n{body}"


@dataclass
class SchemaErrorGroup(Exception):
    """Validation failures across a whole directory of documents."""

    errors: list[SchemaError] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.errors)

    def __str__(self) -> str:
        return "\n\n".join(e.render() for e in self.errors)

    @property
    def problem_count(self) -> int:
        return sum(len(e.problems) for e in self.errors)
