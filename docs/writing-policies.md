# Writing policies

Every file has the same Kubernetes-style shape: `apiVersion`, `kind`, `metadata` and `spec`. For every field, see the [schema reference](schema-reference.md). `aquasec-casc validate -f DIR` checks your files with no network.

## RuntimePolicy

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: RuntimePolicy
metadata:
  name: devtest-baseline
spec:
  description: Dev/test baseline -- no image-compliance enforcement
  enabled: true
  enforce: false                      # audit mode
  runtimeType: container              # container | host | function
  applicationScopes:
    - DevTest
  controls:
    blockNonCompliantImages: false
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

- **`applicationScopes`** is required. Aqua applies a policy with no scopes to every workload, so write `["Global"]` if that is what you mean. The scope must already exist in Aqua.
- **`enforcement`**: `Reconcile` corrects drift, and `ReportOnly` only reports it, which lets you watch a policy before trusting the tool with it.

### Names

Names are the console's labels in camelCase: *Block Unregistered Images* is `blockUnregisteredImages`. Where a label is a sentence ("Use the host IPC namespace"), the name is a short form (`hostIpc`). `plan` shows the API name in brackets.

### Controls

**A control you leave out is off**, so to switch one off, just remove it. `true` switches a control on, and so does writing any of its settings:

```yaml
  controls:
    blockContainerExec: true          # on, no exceptions
    blockReverseShell:
      allowedProcesses: ["sshd"]      # on, with exceptions
    portBlock:
      blockedInboundPorts: ["22"]
    fileIntegrityMonitoring:
      create: true
      monitor:                        # the console's Monitor tab
        paths: ["/etc/*"]
      exclude:                        # and its Exclude tab
        paths: ["/etc/hosts"]
```

[runtime-policy-all-controls.yaml](../examples/playground/runtime-policy-all-controls.yaml) shows every control. A few have rules of their own:

- **Secure AI** model lists take `Service@model` entries (`OpenAI@gpt-4o`, or `OpenAI@*`). Secure AI is audit only, and on self-hosted Aqua it needs 2022.4 Update 44 or later.
- **`blockOutdatedImages`** is for container policies only.
- **Capabilities Block** is offered by the console in enforce mode only. The tool stores what the file says.

### Additional Scope Criteria

These narrow a policy within its application scopes. Leaving them out of the file leaves them as they are, so to widen a policy again, write that (`value: "*"`).

```yaml
  additionalScopeCriteria:
    expression: v1 && !v2
    variables:
      - { attribute: image.name, value: "registry.example/*" }
      - { attribute: image.name, value: "*:dev" }
```

## AssurancePolicy

One kind covers the console's five, told apart by `assuranceType`. Under `actions`, `exceptions` and `controls`, **what the file leaves out is off**.

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: AssurancePolicy
metadata:
  name: accprod-images
spec:
  assuranceType: image                # image | host | function | kubernetes | cf_application
  description: Acceptance/production image assurance
  applicationScopes:
    - AccProd
  actions:                            # what happens when the policy fails
    createAuditMessage: true
    failCicd: true
    markNonCompliant: true
  exceptions:                         # what evaluating it ignores
    ignoreNoFix: true
    ignoreRecentlyPublished:
      days: 30
  controls:                           # the tests
    vulnerabilitySeverity:
      severity: high
    malware: true
    packagesBlocked:
      packages:
        - name: netcat
          version: "1.0"
          versionRange: Less Than
```

Kubernetes policies run checks by name:

```yaml
  assuranceType: kubernetes
  actions:
    markNonCompliant: true
    blockResources: true
  controls:
    kubernetesControls: ["Privileged", "Access to host network"]
```

- **Not every type offers every control.** `validate` refuses one that its type does not offer.
- **Names repeat across types.** Every type has its own "Default", so a policy's address is `image/Default`. `--name` matches either form.
- **Assurance policies cannot be disabled.** To keep one inert, scope it to names that match nothing, as [the playground's](../examples/playground/assurance-policy-image.yaml) does.

## The config folder

Beside the policies goes `aquasec-casc.yaml`, holding the instance name:

```yaml
instance: platform
```

Each policy the tool writes then carries `managed-by: aquasec-casc/platform` in its description, which is [how it knows the policy is its own](how-it-works.md#ownership).
