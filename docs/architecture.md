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
client adapter (`aqua_casc/client/`) talks to aquasec-lib. Both rules are
enforced by tests (`tests/unit/test_layering.py`), not by discipline.

---

## Stateless by design

> **Departure from the original brief.** The brief recommended a state file
> committed alongside the config (`.aqua-casc/state.yaml`). The tool has no
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

  managed-by: aqua-casc/platform
```

- The part after the slash is the **instance name**, set in a committed
  `aqua-casc.yaml` at the config root (`instance: platform`), overridable with
  `--instance` or `AQUA_CASC_INSTANCE`. It is required: two repositories or
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

The rule that prevents it: **the fields the YAML mentions are ours; every other
field belongs to Aqua or the console and is left alone.**

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
  │ Not in the YAML                │ An Aqua default, or a console edit.  │
  │                                │ LEFT ALONE.                          │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ In the YAML, missing in Aqua   │ Added.                               │
  └────────────────────────────────┴──────────────────────────────────────┘
```

A field removed from the YAML simply stops being managed: its value stays on the
server. `kubectl apply` would delete it, because the Kubernetes API server
re-applies its own default afterwards. Aqua offers no such guarantee — on a
whole-object update a missing boolean becomes `false` — and silently switching a
security control off because somebody tidied a YAML file is not acceptable.

Updates always send the **complete** object with only our fields changed. Aqua's
update is a full replace (verified live): a partial body resets every field it
leaves out.

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
- `diff` lists every pending deletion.
- Within one apply, **all creates and updates run before any delete**, so a
  Git-side rename never leaves a moment with neither policy in place.
- **A run that loads no resources at all deletes nothing**, unless
  `--allow-empty` is given. An empty config directory — a wrong path, a
  ConfigMap that did not mount — is far more likely a mistake than an
  instruction to delete everything. Argo CD's automated sync has the same
  default (`allowEmpty: false`).

---

## Built-in policies

Aqua ships runtime policies of its own (18 on the lab tenant), flagged
`is_ootb_policy: true` in the API. The flag survives edits (verified). `author`
does not: an API edit rewrites it to the editing identity, so it cannot identify
built-ins.

- **Shipped policies are adopt-only.** The tool never creates or deletes them.
  `export` includes them — the default policy is usually the first one a
  customer changes — and they carry the marker like anything else.
- **Predefined policies**, a subset of the shipped ones, cannot be deleted and
  their scope cannot change. No API field distinguishes them, so they are listed
  by name in the registry, and a policy must match **both** the flag and the
  name. A scope change on one is reported as not allowed and not sent; the rest
  of the change still applies.

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

---

## Exit codes

```
  validate   0 valid      1 invalid
  diff       0 no changes 1 error     2 changes pending (incl. deletions)
  apply      0 done       1 error     2 something left pending -- only with
                                        --detailed-exitcode
  export     0 done       1 error
```

`apply` exits 0 on success by default because Argo CD fails a sync on any
non-zero hook exit: a routine apply that leaves, say, a held-back orphan must
not block every future sync. `--detailed-exitcode` is for pipelines that want
to gate on it, following `terraform plan -detailed-exitcode`.
