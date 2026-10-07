# Schema examples

Every resource uses the Kubernetes shape — `apiVersion`, `kind`, `metadata`,
`spec`, `status` — even though phase 1 does not involve Kubernetes at all.

Three reasons: it is the lingua franca of this space, it gives schema versioning
and validation conventions for free, and it means the phase 2 CRDs are these
same objects rather than a translation of them.

```
  apiVersion: config.aquasec.com/v1alpha1     the group and schema version
  kind:       RuntimePolicy                   which sort of object
  metadata:                                   identity — name, labels
  spec:                                       what you want. Humans edit this.
  status:                                     what happened. The tool writes this.
```

---

## RuntimePolicy — implemented

This is the real file from `examples/two-scope/`: a dev/test scope in audit
mode and an acceptance/production scope in enforce mode.

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: RuntimePolicy
metadata:
  name: devtest-baseline
spec:
  description: Dev/test baseline -- no image-compliance enforcement
  enabled: true
  enforce: false                      # audit mode
  runtimeType: container
  applicationScopes:
    - DevTest
  controls:
    blockNonCompliantImages: false    # one line in Git
    blockContainerExec: true
    driftPrevention:
      enabled: true
      execLockdown: true
      exceptions:
        - "redis-*"
  enforcement: Reconcile              # Reconcile | ReportOnly
  deletionPolicy: Orphan              # Orphan | Delete
```

Two fields worth explaining, because they are the safety model:

| Field | Meaning |
|---|---|
| `spec.enforcement` | `Reconcile` corrects drift. `ReportOnly` reports it and changes nothing — how you watch a policy before trusting the tool with it. |
| `spec.deletionPolicy` | `Orphan` (the default) means removing the file leaves the policy in Aqua. `Delete` additionally requires `--allow-delete` on the run. |

### The canonical names are ours, not Aqua's

`blockNonCompliantImages` is `block_disallowed_images` in the API. `blockContainerExec`
is `container_exec.block_container_exec`, and it has to be written alongside a
`container_exec.enabled` gate or the control silently does nothing.

A declarative mapping table absorbs all of that, so the YAML stays stable when
Aqua renames a field between versions — which matters, because on-prem and SaaS
are not always on the same one.

---

## status — written by the tool, never by a human

In push mode there is no Kubernetes API server to hold `status`, so it lives in
`.aqua-casc/state.yaml` beside the config. This is genuine output from a run
against the two example policies:

```yaml
version: 1
resources:
  RuntimePolicy/devtest-baseline:
    aquaName: devtest-baseline
    aquaId: 4471
    observedGeneration: 1
    lastAppliedFields:
    - application_scopes
    - block_disallowed_images
    - container_exec.block_container_exec
    - container_exec.enabled
    - description
    - drift_prevention.enabled
    - drift_prevention.exec_lockdown
    - drift_prevention.exec_lockdown_white_list
    - enabled
    - enforce
    - runtime_type
    lastSyncTime: '2026-09-15T13:38:13Z'
```

`lastAppliedFields` is the third input to the three-way diff — the record of
which fields are *ours*. Anything on the server outside that list is an Aqua
default or a console edit, and is left alone.

`aquaName` is the identity mapping. Aqua keys its endpoints by name in the URL,
so this — not a numeric ID — is what ties a file in Git to an object in Aqua.
`aquaId` is recorded for traceability only.

---

## Planned kinds

Not yet implemented. Shapes shown for discussion, and they may move.

### EnforcerGroup

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: EnforcerGroup
metadata:
  name: cluster-acc-prod
spec:
  description: Acceptance/production cluster enforcers
  type: agent
  enforceMode: true
  gateways: ["gw-01"]
  tokenSecretRef:                     # where the token goes. NEVER into Git.
    name: aqua-enforcer-token
    namespace: aqua
    key: token
  enforcement: Reconcile
  deletionPolicy: Orphan
```

The token comes back from Aqua on create and is written only to the destination
named in `tokenSecretRef` — a Kubernetes Secret in-cluster, or a file path when
standalone. It never reaches stdout, logs, or the state file, and there are
tests asserting that.

### AssurancePolicy

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: AssurancePolicy
metadata:
  name: prod-image-assurance
spec:
  type: image                         # image | host | function | kubernetes
  description: Production image assurance
  applicationScopes:
    - AccProd
  controls:
    maxSeverity: high
    blockOnMalware: true
    requiredLabels: ["owner"]
  enforcement: Reconcile
  deletionPolicy: Orphan
```

---

## Why this shape pays off in phase 2

The CRDs are generated from the same models that validate the YAML today, so
they cannot drift apart:

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: runtimepolicies.config.aquasec.com
spec:
  group: config.aquasec.com
  scope: Namespaced
  names:
    kind: RuntimePolicy
    plural: runtimepolicies
    singular: runtimepolicy
  versions:
  - name: v1alpha1
    served: true
    storage: true
    subresources:
      status: {}                      # the same status block as above
    schema:
      openAPIV3Schema: ...            # generated from the same models
```

Same `apiVersion`. Same `kind`. Same `spec`. Same `status`. In phase 2 the files
above stop being read from a directory and start being applied to a cluster —
the documents themselves do not change.
