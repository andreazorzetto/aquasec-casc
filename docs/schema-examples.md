# Schema examples

Every resource uses the Kubernetes shape — `apiVersion`, `kind`, `metadata`,
`spec` — even though phase 1 does not involve Kubernetes at all.

Three reasons: it is the lingua franca of this space, it gives schema versioning
and validation conventions for free, and it means the phase 2 CRDs are these
same objects rather than a translation of them.

```
  apiVersion: config.aquasec.com/v1alpha1     the group and schema version
  kind:       RuntimePolicy                   which sort of object
  metadata:                                   identity — name, labels
  spec:                                       what you want. Humans edit this.
  status:                                     phase 2 only: what the operator observed.
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
    blockContainerExec:
      allowedProcesses:
        # the console's default: AWS ECS Exec's agents
        - /ecs-execute-command-*/amazon-ssm-agent
        - /ecs-execute-command-*/ssm-session-worker
        - /ecs-execute-command-*/ssm-agent-worker
    driftPrevention:
      allowedProcesses:
        - "redis-*"
  enforcement: Reconcile              # Reconcile | ReportOnly
```

Two fields worth explaining, because they are the safety model:

| Field | Meaning |
|---|---|
| `spec.enforcement` | `Reconcile` corrects drift. `ReportOnly` reports it and changes nothing — how you watch a policy before trusting the tool with it. |
| `spec.applicationScopes` | Required. Aqua's default for a policy with no scopes is Global — every workload — so getting that by leaving the field out is refused. Write `["Global"]` if that is what you mean. |
| *(deletion)* | Not a field. Removing a file from Git deletes the object on the next `apply`; `--no-delete` on a run holds deletions back. See `docs/architecture.md`. |

### The names are the console's, not the API's

Every control and setting is named after its label in the console, in camelCase:
*Block Unregistered Images* is `blockUnregisteredImages`, *Blocked Inbound
Ports* is `blockedInboundPorts`. Where a label is a sentence ("Use the host IPC
namespace"), the name is a short form (`hostIpc`).

The API names differ, and some controls span several API fields.
`blockUnregisteredImages` is `only_registered_images`, and
`blockNonCompliantImages` is `block_disallowed_images`. *Block Container Exec*
is `container_exec.block_container_exec` plus a `container_exec.enabled`
switch, which has to be written too or the control silently does nothing.
`plan` shows the API name in brackets after each line.

A declarative mapping table absorbs all of that, so the YAML stays stable when
Aqua renames a field between versions — which matters, because on-prem and SaaS
are not always on the same one.

### Controls with settings

A control with settings in the console (Block Container Exec and its Allowed
Processes, Port Block, File Integrity Monitoring, ...) holds them in the YAML
too. **Writing any setting switches the control on**, `true` switches it on
with no settings, and **a control you leave out is off** -- there is no need to
write `enabled: false` or `false` to switch one off, just remove it:

```yaml
  controls:
    blockContainerExec: true          # on, no exceptions
    blockReverseShell:
      allowedProcesses: ["sshd"]      # on, with exceptions
    portBlock:
      blockedInboundPorts: ["22"]     # port_block.enabled is sent as true
    fileIntegrityMonitoring:
      create: true
      monitor:                        # the console's Monitor tab
        paths: ["/etc/*"]
      exclude:                        # and its Exclude tab
        paths: ["/etc/hosts"]
```

[runtime-policy-all-controls.yaml](../examples/playground/runtime-policy-all-controls.yaml)
shows every one. Each was write-tested on a live tenant through create *and* a
later update, which Aqua validates differently. What that found is built in:

| Setting | Why it is not offered, or is checked |
|---|---|
| File Integrity Monitoring *read* / *attributes* | Not in the console. Aqua accepts them on create, then drops *read* and refuses *attributes* on every update. |
| Malware protection *include directories* | Not in the console. Aqua sets its own list and restores it on every save. |
| Capabilities Block, Read-Only Files, failed Kubernetes checks, drift prevention's *image lockdown*, root executables, File and Package Block's users, processes and exceptions, the *owner user context* privilege | In the API, not in the console, and set by no console-made policy. Not offered. |
| Drift prevention's *exec lockdown* | Not a setting: the console's one switch writes both `drift_prevention.enabled` and `exec_lockdown`, and so does the tool. |
| `driftPrevention.preventPrivileged` | Terraform-only. Aqua accepts and discards it. Use `limitContainerPrivileges.privileged`. |
| `blockOutdatedImages` on a host policy | Container policies only; `validate` says so. |
| Secure AI model lists | Entries are `Service@model` (`OpenAI@gpt-4o`, or `OpenAI@*` for every model); Aqua refuses anything else, so `validate` checks the shape. Service names are Aqua's to check. |

Secure AI (Discovery, Unauthorized Models) is audit only. The console switches it
off when a policy is in enforce mode; the API keeps it as written, so the tool
stores what the file says in either mode. On self-hosted Aqua it needs 2022.4
Update 44 or later.

Not covered yet: Secure AI - Protection (not in the console's list; it needs
prompt protection set up first), Tripwire (serverless; it stores a password, and
the tool never manages credentials) and the forensics `*_config` objects.
Settings that are not covered or not offered are left as Aqua has them.

---

## Ownership — on the object, not in a file

The tool keeps no state. When it writes an object, the object's description
carries an ownership marker on its own line. This is what Aqua holds for the
example above after an `apply`:

```
Dev/test baseline -- no image-compliance enforcement

managed-by: aquasec-casc/platform
```

`platform` is the instance name, from a small committed file at the root of the
config directory:

```yaml
# aquasec-casc.yaml
instance: platform
```

The marker is how the tool tells its own objects from console-made ones and
from another team's, which is what makes deletion safe: only objects carrying
*this* instance's marker are ever deleted. `export` strips it from the YAML it
writes, and an apply puts it back if someone removes it in the console.

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
  tokenSecretRef:                     # where the token goes. NEVER into Git.
    name: aqua-enforcer-token
    namespace: aqua
    key: token
  enforcement: Reconcile
```

Gateways are deliberately not part of the schema: Aqua assigns them by
default, so the tool leaves them to Aqua rather than owning a field nobody sets.

The token comes back from Aqua on create and is written only to the destination
named in `tokenSecretRef` — a Kubernetes Secret in-cluster, or a file path when
standalone. It never reaches stdout or logs, and there are
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
      status: {}                      # filled by the phase 2 operator
    schema:
      openAPIV3Schema: ...            # generated from the same models
```

Same `apiVersion`. Same `kind`. Same `spec`. In phase 2 the files
above stop being read from a directory and start being applied to a cluster —
the documents themselves do not change.
