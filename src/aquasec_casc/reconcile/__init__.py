"""Layer 2 -- the reconciler.

Desired state from Git and actual state from Aqua in; a plan and a result out.
Stateless: ownership lives on the Aqua object (``marker``), not in a file.

Hard rule, restated because it is the one most easily broken: nothing in this
package imports from the CLI, prints, or calls ``sys.exit``. It returns result
objects and lets the caller render them. That is what makes the phase 2 operator
a wrapper rather than a rewrite.
"""

from . import marker
from .client import AquaClient, ClientError
from .diff import (
    ChangeType,
    FieldChange,
    Plan,
    ReleasePolicy,
    equivalent,
    flatten,
    three_way_diff,
)
from .engine import Options, is_predefined, is_shipped, reconcile, reconcile_all
from .result import MUTATING, PENDING, Outcome, Result, RunSummary
from .state import (
    NoopStateBackend,
    StateBackend,
    StateError,
    assert_not_ownable,
)

__all__ = [
    "AquaClient",
    "ChangeType",
    "ClientError",
    "FieldChange",
    "MUTATING",
    "NoopStateBackend",
    "Options",
    "Outcome",
    "PENDING",
    "Plan",
    "ReleasePolicy",
    "Result",
    "RunSummary",
    "StateBackend",
    "StateError",
    "assert_not_ownable",
    "equivalent",
    "flatten",
    "is_predefined",
    "is_shipped",
    "marker",
    "reconcile",
    "reconcile_all",
    "three_way_diff",
]
