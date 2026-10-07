"""Layer 2 -- the reconciler.

Desired state, actual state and last-applied state in; a plan and a result out.

Hard rule, restated because it is the one most easily broken: nothing in this
package imports from the CLI, prints, or calls ``sys.exit``. It returns result
objects and lets the caller render them. That is what makes the phase 2 operator
a wrapper rather than a rewrite.
"""

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
from .engine import Options, reconcile, reconcile_all
from .result import MUTATING, PENDING, Outcome, Result, RunSummary
from .state import (
    STATE_DIR,
    STATE_FILE,
    STATE_VERSION,
    FileStateBackend,
    RenameDetected,
    ResourceState,
    StateBackend,
    StateError,
    assert_not_ownable,
)

__all__ = [
    "AquaClient",
    "ChangeType",
    "ClientError",
    "FieldChange",
    "FileStateBackend",
    "MUTATING",
    "Options",
    "Outcome",
    "PENDING",
    "Plan",
    "ReleasePolicy",
    "RenameDetected",
    "ResourceState",
    "Result",
    "RunSummary",
    "STATE_DIR",
    "STATE_FILE",
    "STATE_VERSION",
    "StateBackend",
    "StateError",
    "assert_not_ownable",
    "equivalent",
    "flatten",
    "reconcile",
    "reconcile_all",
    "three_way_diff",
]
