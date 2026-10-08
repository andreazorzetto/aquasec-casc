"""The RuntimePolicy kind -- the MVP centrepiece.

Canonical field names are chosen for a human reading a pull request, and are
translated to Aqua's API names by ``FIELD_MAP``. Where Aqua has a good name
already, we keep it; where Aqua nests a control or has renamed it across
versions, the mapping absorbs that.

API paths were mined from terraform-provider-aquasec v0.15.1 (commit 49182c7).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .base import API_VERSION, ManagedSpec, Metadata, Resource, StrictModel
from .fieldmap import FieldMap, FieldMapping

KIND = "RuntimePolicy"


class RuntimeType(str, Enum):
    """Which workload family the policy applies to.

    Aqua models container, host and function runtime policies as one object
    distinguished by this field, rather than as three endpoints.
    """

    CONTAINER = "container"
    HOST = "host"
    FUNCTION = "function"


class DriftPrevention(StrictModel):
    """Drift prevention, including exec lockdown and its allow-list."""

    enabled: bool = False
    execLockdown: bool = False
    imageLockdown: bool = False

    execLockdownScripts: bool = False
    """Extend exec lockdown to scripts, not just binaries."""

    inheritToChild: bool = False
    """Apply the exec lockdown decision to child processes."""

    preventPrivileged: bool | None = None
    """Not present on the lab tenant -- see FIELD_MAP before relying on it."""

    exceptions: list[str] = Field(default_factory=list)
    """Processes exempt from exec lockdown.

    Aqua calls this ``exec_lockdown_white_list``. This is where legitimate
    startup processes go when drift prevention blocks them.
    """


class ScopeVariable(StrictModel):
    """One term of a scope expression, e.g. a container label match."""

    attribute: str
    value: str
    name: str | None = None


class BypassScope(StrictModel):
    """Workloads exempt from this policy.

    Only the default container and host runtime policies have it -- the same as
    in the console. The default container policy ships with it on, exempting
    Aqua's own components, ``kube-system`` and pod sandboxes.
    """

    enabled: bool = False
    expression: str = ""
    """How the variables combine, e.g. ``v1 || v2 || v3``."""

    variables: list[ScopeVariable] = Field(default_factory=list)


class Controls(StrictModel):
    """The security controls a runtime policy turns on or off.

    Flattened relative to the API, which nests several of these inside their own
    objects alongside their exception lists.
    """

    # --- image compliance --------------------------------------------------------
    blockNonCompliantImages: bool | None = None
    """Block images an assurance policy has marked non-compliant.

    Worth understanding before relying on audit mode: the enforcer evaluates
    compliance by image *hash*, so a non-compliant verdict from one policy blocks
    that hash everywhere the enforcer sees it -- including scopes meant to be in
    audit mode. Leaving this control out of a dev/test policy entirely is the
    recommended fix, rather than relying on audit mode to soften it.

    The API field is ``block_disallowed_images``, not the documented
    ``block_non_compliant_images`` -- see FIELD_MAP.
    """

    blockNonCompliantWorkloads: bool | None = None
    """Block containers in non-compliant Kubernetes pods."""

    onlyRegisteredImages: bool | None = None
    """Allow only images registered in Aqua to run."""

    # --- exec and shell --------------------------------------------------------
    blockContainerExec: bool | None = None
    containerExecAllowedProcesses: list[str] | None = None
    blockReverseShell: bool | None = None
    reverseShellAllowedProcesses: list[str] | None = None
    reverseShellAllowedIps: list[str] | None = None
    blockFilelessExec: bool | None = None

    # --- drift -----------------------------------------------------------------
    driftPrevention: DriftPrevention | None = None

    # --- detection -------------------------------------------------------------
    blockCryptocurrencyMining: bool | None = None
    enableForkGuard: bool | None = None
    forkGuardProcessLimit: int | None = None
    enableIpReputation: bool | None = None
    enablePortScanProtection: bool | None = None

    # --- kubernetes / privileges ----------------------------------------------
    blockNonK8sContainers: bool | None = None
    noNewPrivileges: bool | None = None
    auditBruteForceLogin: bool | None = None

    # --- default policies only ---------------------------------------------------
    bypassScope: BypassScope | None = None
    """Only on "Aqua default runtime policy" and "Aqua default host runtime
    policy"; anywhere else it is reported as not allowed and not sent."""


class RuntimePolicySpec(ManagedSpec):
    """Desired state of an Aqua runtime policy."""

    description: str = ""
    enabled: bool = True

    enforce: bool = False
    """False is audit mode, True is enforce mode.

    Defaults to audit: a policy that silently starts enforcing on creation is
    the wrong default for a tool whose first run may be against production.
    """

    enforceAfterDays: int | None = None
    runtimeType: RuntimeType = RuntimeType.CONTAINER

    applicationScopes: list[str] = Field(
        min_length=1,
        description=(
            "The application scopes this policy applies to. Required: when Aqua "
            "is given none it applies the policy to Global, meaning every "
            "workload. Write [\"Global\"] if that is what you intend."
        ),
    )
    """Required, with at least one entry.

    Aqua's own default for a policy with no scopes is ``["Global"]`` -- every
    workload (verified live). Writing ``["Global"]`` here produces exactly that
    policy; what is not allowed is getting it by leaving the field out, because
    in config-as-code an omission is far more often a mistake than a decision,
    and in enforce mode this one blocks workloads everywhere. Export always
    writes the scopes it reads, so adopting existing policies is unaffected.
    """
    excludeApplicationScopes: list[str] | None = None

    controls: Controls = Field(default_factory=Controls)


class RuntimePolicy(Resource):
    apiVersion: str = API_VERSION
    kind: str = KIND
    metadata: Metadata
    spec: RuntimePolicySpec


# --------------------------------------------------------------------------- #
# Canonical path -> Aqua API path
#
# Fields NOT mapped here are deliberately not ours: `type`, `author`, `created`,
# `updated`, `lastupdate`, `digest`, `version`, `is_ootb_policy` and friends are
# server-assigned. The three-way diff leaves anything outside this table alone,
# so omitting them is what stops the tool trying to null out Aqua's own metadata.
# --------------------------------------------------------------------------- #

FIELD_MAP = FieldMap(
    kind=KIND,
    mappings=[
        # --- identity and lifecycle -------------------------------------------
        FieldMapping("spec.description", "description"),
        FieldMapping("spec.enabled", "enabled"),
        FieldMapping("spec.enforce", "enforce"),
        FieldMapping("spec.enforceAfterDays", "enforce_after_days"),
        FieldMapping("spec.runtimeType", "runtime_type"),
        FieldMapping("spec.applicationScopes", "application_scopes"),
        FieldMapping("spec.excludeApplicationScopes", "exclude_application_scopes"),

        # --- image compliance --------------------------------------------------
        FieldMapping(
            "spec.controls.blockNonCompliantImages",
            "block_disallowed_images",
            api_aliases=("block_non_compliant_images",),
            note=(
                "RESOLVED against the eu-1 lab tenant (11 Sep 2026): all 47 "
                "runtime policies carry block_disallowed_images, and none "
                "carries block_non_compliant_images. The Terraform provider is "
                "right to treat the latter as a retired alias. The alias is "
                "kept for read only, in case an older on-prem build still "
                "returns it."
            ),
        ),
        FieldMapping(
            "spec.controls.blockNonCompliantWorkloads",
            "block_non_compliant_workloads",
        ),
        FieldMapping(
            "spec.controls.onlyRegisteredImages",
            "only_registered_images",
            api_aliases=("block_unregistered_images",),
            note="Renamed from block_unregistered_images; older tenants use the alias.",
        ),

        # --- exec and shell ----------------------------------------------------
        FieldMapping(
            "spec.controls.blockContainerExec",
            "container_exec.block_container_exec",
            also_set=("container_exec.enabled",),
            note=(
                "Nested, and gated. There is also a top-level "
                "block_container_exec, but on the lab tenant it is False on all "
                "47 policies including the 5 where the control is actually on -- "
                "it is vestigial, and the nested field is authoritative. The "
                "container_exec.enabled gate tracks the block flag exactly "
                "(42 false/false, 5 true/true, never divergent), so it is "
                "written alongside; setting the inner flag alone would produce "
                "a policy that diffs clean and does nothing."
            ),
        ),
        FieldMapping(
            "spec.controls.containerExecAllowedProcesses",
            "container_exec.container_exec_proc_white_list",
        ),
        FieldMapping(
            "spec.controls.blockReverseShell",
            "reverse_shell.block_reverse_shell",
            also_set=("reverse_shell.enabled",),
            note=(
                "Same gated pattern as container_exec. The top-level "
                "block_reverse_shell is absent entirely on this tenant."
            ),
        ),
        FieldMapping(
            "spec.controls.reverseShellAllowedProcesses",
            "reverse_shell.reverse_shell_proc_white_list",
        ),
        FieldMapping(
            "spec.controls.reverseShellAllowedIps",
            "reverse_shell.reverse_shell_ip_white_list",
        ),
        FieldMapping("spec.controls.blockFilelessExec", "block_fileless_exec"),

        # --- drift prevention ---------------------------------------------------
        FieldMapping("spec.controls.driftPrevention.enabled", "drift_prevention.enabled"),
        FieldMapping(
            "spec.controls.driftPrevention.execLockdown",
            "drift_prevention.exec_lockdown",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.imageLockdown",
            "drift_prevention.image_lockdown",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.execLockdownScripts",
            "drift_prevention.exec_lockdown_scripts",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.inheritToChild",
            "drift_prevention.exec_lockdown_inherit_to_child",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.preventPrivileged",
            "drift_prevention.prevent_privileged",
            unverified=True,
            note=(
                "The Terraform provider declares this (with omitempty), but it "
                "is absent from all 47 policies on the lab tenant -- so it is "
                "either removed, or omitted when false and only appears once "
                "set. Until a write test confirms it is honoured, treat a diff "
                "on this field with suspicion."
            ),
        ),
        FieldMapping(
            "spec.controls.driftPrevention.exceptions",
            "drift_prevention.exec_lockdown_white_list",
            note="Named 'exceptions' in our schema; it is the exec lockdown allow-list.",
        ),

        # --- detection ----------------------------------------------------------
        FieldMapping(
            "spec.controls.blockCryptocurrencyMining",
            "enable_crypto_mining_dns",
            note=(
                "The provider's data source maps block_cryptocurrency_mining onto "
                "EnableCryptoMiningDns, so the two are the same control despite "
                "the names reading differently."
            ),
        ),
        FieldMapping("spec.controls.enableForkGuard", "enable_fork_guard"),
        FieldMapping("spec.controls.forkGuardProcessLimit", "fork_guard_process_limit"),
        FieldMapping(
            "spec.controls.enableIpReputation",
            "enable_ip_reputation",
            api_aliases=("enable_ip_reputation_security",),
        ),
        FieldMapping(
            "spec.controls.enablePortScanProtection",
            "enable_port_scan_protection",
            api_aliases=("enable_port_scan_detection",),
        ),

        # --- kubernetes and privileges -------------------------------------------
        FieldMapping("spec.controls.blockNonK8sContainers", "block_non_k8s_containers"),
        FieldMapping(
            "spec.controls.noNewPrivileges",
            "no_new_privileges",
            api_aliases=("limit_new_privileges",),
        ),
        FieldMapping("spec.controls.auditBruteForceLogin", "audit_brute_force_login"),

        # --- default policies only (see KindDef.only_on) --------------------------
        FieldMapping("spec.controls.bypassScope.enabled", "bypass_scope.enabled"),
        FieldMapping("spec.controls.bypassScope.expression", "bypass_scope.scope.expression"),
        FieldMapping("spec.controls.bypassScope.variables", "bypass_scope.scope.variables"),
    ],
)
