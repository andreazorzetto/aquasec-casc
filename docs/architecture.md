# Architecture

Three layers. The schema and the reconciler are the product; how they get
triggered is a thin wrapper.

```
                     YAML in Git
                     the only thing a human edits
                            │
   ╔════════════════════════▼═══════════════════════════════════════╗
   ║  1   SCHEMA                                   the vocabulary   ║
   ║                                                                ║
   ║      Kubernetes-shaped YAML (apiVersion / kind / metadata /    ║
   ║      spec). Validated before anything is sent, so a typo is    ║
   ║      caught in CI rather than in production.                   ║
   ╚════════════════════════╤═══════════════════════════════════════╝
                            │
   ╔════════════════════════▼═══════════════════════════════════════╗
   ║  2   RECONCILER                                   the engine   ║
   ║                                              ◄── the product   ║
   ║      Reads Aqua, compares against Git, decides the minimum     ║
   ║      safe change. All of the difficulty lives here.            ║
   ╚════════════════════════╤═══════════════════════════════════════╝
                            │
   ╔════════════════════════▼═══════════════════════════════════════╗
   ║  3   RUNNER                                      the trigger   ║
   ║                                                                ║
   ║      "run once and exit"      ← phase 1, a CLI                 ║
   ║      "run forever and watch"  ← phase 2, an operator           ║
   ╚════════════════════════╤═══════════════════════════════════════╝
                            │
                     Aqua REST API
```

**Why it is split this way.** Layer 3 is the only part that knows how it was
invoked. Swap it and the engine underneath is untouched — so phase 2 is a
wrapper, not a rewrite, and phase 1 is not throwaway.

The reconciler imports nothing from the CLI, prints nothing, and never calls
`sys.exit`. It returns result objects and the caller renders them. Only the
client adapter (`aquasec_casc/client/`) talks to aquasec-lib. Both rules are
enforced by tests (`tests/unit/test_layering.py`), not by discipline.

---

## Stateless by design

> **Departure from the original brief.** The brief recommended a state file
> committed alongside the config (`.aquasec-casc/state.yaml`). The tool has no
> state at all: no state file, no in-cluster backend, nothing to persist or
> commit back.

**Why.** In the Argo CD hook the config arrives as a read-only ConfigMap mount
that is discarded after each run, so a state file could neither be written nor
survive. The alternatives were an in-cluster ConfigMap backend — which needs
RBAC that a security team has to approve — or behaving differently in Argo
than on a laptop or in CI. Stateless avoids both: the tool behaves identically
everywhere, with nothing to set up and nothing to commit back.

**How it works without state.** Ownership lives on the Aqua object itself, the
same idea as `kubectl apply`'s annotation or Argo CD's tracking label. When the
tool writes an object, its description carries an ownership marker on its own
line:

```
  Dev/test baseline -- no image-compliance enforcement

  managed-by: aquasec-casc/platform
```

- The part after the slash is the **instance name**, set in a committed
  `aquasec-casc.yaml` at the config root (`instance: platform`), overridable with
  `--instance` or `AQUASEC_CASC_INSTANCE`. It is required: two repositories or
  teams on one tenant must never treat each other's objects as their own.
- The marker is part of the desired value: it is appended to the description
  before diffing, so it never shows up as drift.
- `export` strips it when writing YAML. If someone removes it in the console,
  the next apply restores it.
- Verified on a live tenant: descriptions keep newlines and store at least
  10,000 characters exactly.

Kinds declare whether they are **collections** (policies, scopes, enforcer
groups — many named objects, which carry the marker and take part in orphan
detection) or **singletons** (settings objects, which carry no marker and are
simply configured as Git says).

**What was given up, deliberately.**

| Lost | Why it is acceptable |
|---|---|
| "Released field" bookkeeping — knowing a field the YAML used to set and no longer does | The tool never reset released fields anyway (see below), so this was close to cosmetic |
| Rename detection | Aqua cannot rename an object. A Git-side rename is a new object plus an orphan, handled by deletion below |

The `StateBackend` interface remains as the seam for phase 2, where an operator
would report observed state on the custom resource's `.status`. Phase 1 uses a
no-op backend.

---

## Inside the reconciler: desired against actual

Aqua returns dozens of fields the YAML never mentions — defaults, timestamps,
computed values, things somebody configured in the console. A naive diff reads
every one of those as drift and tries to null them.

The rule that prevents it: **the fields the YAML mentions are ours, and so are
the security controls, whether the YAML mentions them or not. Every other field
belongs to Aqua or the console and is left alone.**

```
     DESIRED                         ACTUAL
     what Git says, plus             the complete object,
     the ownership marker            as Aqua returns it
         │                                │
         └───────────────┬────────────────┘
                         ▼
                  ┌──────────────┐
                  │     PLAN     │   the minimum set of changes,
                  └──────────────┘   shown before anything is written
```

```
  ┌────────────────────────────────┬──────────────────────────────────────┐
  │ In the YAML, and Aqua differs  │ Drift. Put it back to what Git says. │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ A control not in the YAML      │ Off. Switched off if it is on.       │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ Anything else not in the YAML  │ An Aqua default, or a console edit.  │
  │                                │ LEFT ALONE.                          │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ In the YAML, missing in Aqua   │ Added.                               │
  └────────────────────────────────┴──────────────────────────────────────┘
```

**The file is the whole policy.** A control the YAML leaves out is off, as on a
new policy, where Aqua starts every control off (verified live). So the same
file gives the same policy whether it creates the object or updates it, and a
control switched on only in the console shows up in `plan` as drift and is
switched off. Removing a control from the YAML switches it off; `plan` shows
`true -> false`, so a review sees it.

Two levels:

- **A control left out:** only its switch goes off. Its settings stay as Aqua
  has them: under an off switch they do nothing, and the console writes its own
  defaults into them on every save (a 365-day outdated-images threshold, the
  malware forensics options on). Managing them would report drift after every
  console save, for settings with no effect.
- **A control in the YAML** is the whole of that control: a setting it leaves
  out is off -- `false`, an empty list, `0`, `""`, as on a new policy. A Port
  Block with only inbound ports blocks no outbound ones.

This replaced an earlier rule, "a field removed from the YAML stops being
managed and keeps its value". It needed state to tell a removed field from one
never written; without state it meant the repository described only part of
each policy, and a control enabled in the console was invisible to `plan`.

On an assurance policy the same goes for its **actions** and **exceptions**: removing
them from the file removes them.

Left as Aqua has them, because they are not controls or not covered:

- fields outside those -- description, `enabled`, `enforce`, application scopes --
  when the YAML leaves them out (the marker is still added to the description);
- **Bypass Scope** -- scope, not a control, and on by default on the default
  container policy, exempting Aqua's own components;
- **Additional Scope Criteria**: Aqua fills in its own when a policy is created
  without them (`container.name` is `*`), so having none is not a state the file can
  ask for. To widen a policy again, write that criterion;
- settings the tool does not offer, each with its reason in
  [schema-reference.md](schema-reference.md#not-offered);
- a control this Aqua version does not have: nothing to switch off, and writing
  it would never converge.

`export` follows the same rule: it writes only the controls that are on, so an
exported file reads as what the policy does. A control that is off is left out
whole, settings included; applying the export leaves them as they are.

Updates always send the **complete** object with only our fields changed. Aqua's
update is a full replace (verified live): a partial body resets every field it
leaves out.

**Then it reads the object back.** Aqua answers success for a field it does not
know and drops it, and which fields exist depends on the version:
`block_outdated_images` arrived in 2022.4 Update 47, for instance. So after each write
`apply` compares what it sent with what Aqua now holds. A field not kept is reported
as `not kept by Aqua`, with both values, and fails the run: the policy is not what the
file says, and saying so beats a plan that silently never settles.

### What each run does

| Situation | Result |
|---|---|
| In Git, missing in Aqua | **Created.** Also how an object deleted in the console is put back — that is the guardrail working. |
| In Aqua without a marker | **Adopted**: the marker is added, plus any drift. The first apply after `export` reports only adoptions. |
| Ours, and it drifted | **Updated.** |
| Marked by *another* instance | **Blocked** and reported. Two instances must never manage one object. |
| `spec.enforcement: ReportOnly` | Drift and missing objects are reported; nothing is written. |

---

## Deletion: GitOps semantics

> **Departure from the original brief.** The brief required deletion to be
> opted into twice — `spec.deletionPolicy: Delete` on the resource *and*
> `--allow-delete` on the run. Neither exists. **Removing a file from Git
> deletes the object on the next apply**, the same as Argo CD with pruning on.

**Why.** It is what Git-as-the-source-of-truth means, and what anyone using
Argo CD already expects. A per-resource opt-in also has a structural problem in
a stateless tool: once the file is deleted, nothing records whether that
resource had opted in.

**The opt-out is per run:** `--no-delete`. Orphans are then reported as
"orphaned, not deleted (--no-delete)" and never deleted — for runs that must
never delete, such as a first rollout or a read-mostly pipeline. Under
`--detailed-exitcode` a held-back orphan counts as pending (exit 2).

**Guardrails that stay:**

- Only objects carrying **this instance's** marker are ever deleted — never
  another instance's, never an unmarked console object.
- **Aqua-shipped policies are never deleted.** They are reported and kept.
- `plan` lists every pending deletion.
- Within one apply, **all creates and updates run before any delete**, so a
  Git-side rename never leaves a moment with neither policy in place.
- **A run that loads no resources at all deletes nothing**, unless
  `--allow-empty` is given. An empty config directory — a wrong path, a
  ConfigMap that did not mount — is far more likely a mistake than an
  instruction to delete everything. Argo CD's automated sync has the same
  default (`allowEmpty: false`).

---

## Leaving: release and hand-over

Deleting the files deletes the objects, so it cannot be the way to *stop
managing* them. `--no-delete` is not either: the objects keep the marker, and
the first run without the flag deletes them.

`release` removes this instance's marker and changes nothing else. The objects
carry on exactly as they are, unmanaged. `--to <instance>` rewrites the marker
instead, moving the objects to another instance (another team or repository, or
a renamed instance) without an unmanaged moment in between.

```
  aquasec-casc release --dry-run            what would be released
  aquasec-casc release [--name 'prod-*']    remove the marker
  aquasec-casc release --to team-b          hand over to another instance
```

- **It needs no YAML.** Objects are found by this instance's marker, so it still
  works after the repository is gone. The instance name comes from the usual
  place (`--instance`, `$AQUASEC_CASC_INSTANCE`, or `aquasec-casc.yaml`).
- **Only the description is written**, and in it only the marker line. The
  whole object is re-read just before the write, because update is a full
  replace; one that changed owner in the meantime is left alone.
- **It is reversible.** `export` and `apply` adopt the objects again.
- **Order matters: release first, then remove the files or stop the pipeline.**
  While both remain, the next apply adopts the objects again. After a hand-over,
  the old instance's runs report the objects as blocked until its files go.
- On runtime policies the API rewrites `author` on every edit, so released
  policies still show the tool's identity as author.

**`destroy` is the other way out**, for when the objects should go too:
`destroy -f DIR` deletes what those files describe, plain `destroy` everything
carrying this instance's marker. The same ownership rule applies -- an object
without this instance's marker is reported as blocked, never deleted -- and a
policy Aqua ships, which cannot be deleted, is released instead. It shows the
plan and asks for the instance name to be typed (`--yes` for scripts), because
it is the one command that deletes without a change in Git.

---

## Built-in policies

Aqua ships policies of its own: 18 runtime policies, and a Default and others for
each assurance type. Verified on a live tenant:

- **They cannot be deleted.** Aqua refuses: "Action forbidden: runtime policy is
  a system policy". The tool never tries; an orphaned one is reported and kept.
- **Their controls can change. Their scope can too -- except on the three runtime
  defaults** ("Aqua default runtime / host runtime / function runtime policy"),
  where Aqua refuses: "can't change application scope for default policies". Aqua's
  docs say the same of its predefined assurance policies.
- **No field identifies them everywhere.** `is_ootb_policy` is true on them on SaaS,
  and false on every one in a 2022.4 export. Assurance policies have no flag, and
  `author` does not survive an edit: an API edit rewrites it to the editing identity.

So **the registry lists them by name** and also honours the flag and `author:
system`. A custom policy that takes one of those names is treated as Aqua's: the
worst that does is that the tool will not delete it.

- **Bypass Scope exists only on the default container and host policies**, as in
  the console (`controls.bypassScope`). The default container policy ships with
  it on, exempting Aqua's own components, `kube-system` and pod sandboxes.
  Setting it anywhere else is reported as not allowed and not sent; `export`
  writes it only for those two, so adopting a default keeps its exemptions.

So built-ins are **adopt-only**: never created or deleted by the tool, otherwise
managed like any policy, marker included. `export` includes them -- the default
policy is usually the first one a customer changes. A scope change on a locked one is
reported as not allowed and not sent; the rest of the change still applies.

---

## Identity

Aqua keys policy and enforcer-group endpoints by **name in the URL**, not by a
numeric ID, and has no rename operation. `metadata.name` must be a DNS-1123
name, which Aqua names often are not ("Aqua default runtime policy"), so
`spec.aquaName` carries the real name when they differ:

```
  metadata.name   aqua-default-runtime-policy     ← file-safe, CRD-safe
  spec.aquaName   Aqua default runtime policy     ← what Aqua calls it
```

`export` sets both automatically.

Assurance policies are addressed by type and name
(`/assurance_policy/{type}/{name}`), since each type has its own "Default". So their
key is `image/Default`, what `plan` shows in brackets and `--name` also matches, and
`export` writes `metadata.name: image-default`. Changing `spec.assuranceType` in Git
describes a different object: the new one is created, and the old one deleted.

---

## Safety defaults

- **Unknown fields are rejected**, not ignored. Aqua ignores unknown fields on
  write, so a typo'd control would otherwise return HTTP 200 and change nothing.
- **`applicationScopes` is required.** Aqua applies a policy with no scopes to
  Global — every workload. Write `["Global"]` if that is what you mean.
- **TLS verification is on**, including for sign-in. `AQUA_CA_BUNDLE` for an
  internal CA; `AQUA_TLS_INSECURE=true` is a visible, deliberate escape hatch.
- **No credential reaches output.** Errors, `repr`s and verbose output are
  redacted; the tool refuses to manage credential-bearing fields.
- **A write is checked.** Each object is read back, and a field Aqua did not keep
  fails the run.
- **A control a type does not offer is refused** at `validate`: Aqua would store a
  CIS benchmark on an image policy, where it does nothing.

---

## Exit codes

```
  validate   0 valid      1 invalid
  plan       0 success    1 error     2 changes pending (incl. deletions) -- only
                                        with --detailed-exitcode
  apply      0 done       1 error     2 something left pending -- only with
                                        --detailed-exitcode
  export     0 done       1 error
  release    0 done       1 error       (also 0 when there is nothing to release)
  destroy    0 done       1 error, or not confirmed
```

A field Aqua did not keep counts as an error. `apply` exits 0 on success by default because Argo CD fails a sync on any
non-zero hook exit: a routine apply that leaves, say, a held-back orphan must
not block every future sync. `--detailed-exitcode` is for pipelines that want
to gate on it, following `terraform plan -detailed-exitcode`.
