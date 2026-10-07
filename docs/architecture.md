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
   ║      spec / status). Validated before anything is sent, so a   ║
   ║      typo is caught in CI rather than in production.           ║
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
`sys.exit`. It returns result objects and the caller renders them. That rule is
enforced by a test (`tests/unit/test_layering.py`), not by discipline.

---

## Inside the reconciler: three inputs, not two

Comparing Git against Aqua alone is what makes a tool like this dangerous. Aqua
returns dozens of fields we never set — defaults, timestamps, computed values,
things somebody configured in the console. A two-way diff reads every one of
those as drift and tries to null them.

The third input is what we set *last time*.

```
     DESIRED                ACTUAL               LAST APPLIED
     what Git says          what Aqua has        what WE set last run
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │     PLAN     │   the minimum set of changes,
                         └──────────────┘   shown before anything is written
```

That third input is what lets it tell your configuration apart from ours:

```
  ┌────────────────────────────────┬──────────────────────────────────────┐
  │ We set it, and Aqua differs    │ Drift. Put it back to what Git says. │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ We never set it                │ An Aqua default, or a console edit.  │
  │                                │ LEFT ALONE.                          │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ We set it before, not now      │ Released. Value kept on the server,  │
  │                                │ ownership dropped.                   │
  ├────────────────────────────────┼──────────────────────────────────────┤
  │ In Git, missing in Aqua        │ Added.                               │
  └────────────────────────────────┴──────────────────────────────────────┘
```

Row 3 diverges from `kubectl apply`, deliberately. kubectl deletes a released
field because the API server re-applies its own default afterwards. Aqua offers
no such guarantee, and on a whole-object PUT a missing boolean unmarshals as
`false`. Silently switching a security control off because somebody tidied a
YAML file is not acceptable here, so the default is to keep the value and stop
tracking it. `Reset` is available for anyone who wants kubectl semantics and has
thought about it.

---

## Identity, and why renames are dangerous

Aqua keys its policy and enforcer-group endpoints by **name in the URL**, not by
a numeric ID:

```
  GET|PUT|DELETE  /api/v2/runtime_policies/{name}
  GET|PUT|DELETE  /api/v2/assurance_policy/{type}/{name}
  GET|DELETE      /api/v1/hostsbatch/{name}
```

So there is no rename primitive. A rename can only be expressed as create-new +
delete-old. The Terraform provider's answer is `ForceNew` — it destroys and
recreates, which in an enforce-mode production scope is a live security
incident rather than a cosmetic bug.

We separate the two names so a rename is never inferred:

```
  metadata.name   ours, stable, never changes      ← the key in the state file
       │
       └── spec.aquaName   what Aqua calls it      ← may change; that IS the rename
```

A changed `spec.aquaName` under a stable `metadata.name` is unambiguously a
rename. We create the new one first, then delete the old — never the reverse, so
a failure in the middle leaves the policy in place rather than absent. In an
enforce-mode scope it stops and asks, because for a moment both policies exist
and both apply.

---

## Safety defaults

Each one is the cautious option, chosen for environments where a wrong
change is a security incident:

- **Deleting needs opt-in twice** — `spec.deletionPolicy: Delete` on the
  resource *and* `--allow-delete` on the run. Removing a file defaults to
  orphaning, never deleting.
- **Renaming inside an enforce-mode scope stops and asks.**
- **A managed object missing from Aqua stops and asks** rather than silently
  recreating something that may have been deliberately removed.
- **Unknown fields are rejected**, not ignored. Aqua ignores unknown fields on
  write, so a typo'd control would otherwise return HTTP 200 and change nothing.
- **Enforcer tokens never reach Git, logs, or the state file.** Enforced by a
  test.

---

## Exit codes

Follows `terraform plan -detailed-exitcode`, so a pipeline can gate on drift:

```
  0    success, nothing outstanding
  1    error
  2    changes present (diff), or drift detected in ReportOnly (apply)
```

Exit code 2 must not be conflated with failure — it is the signal that makes
drift detection useful in CI.

---

## Where state lives

There is no Kubernetes API server in push mode, so `status` goes in a file
committed alongside the config (`.aqua-casc/state.yaml`): visible, diffable,
survives in Git, works air-gapped, needs no infrastructure.

The backend sits behind a `StateBackend` interface so phase 2 can swap the file
for the Kubernetes API without the reconciler noticing. `ResourceState` mirrors
`ResourceStatus` field for field — there is a test asserting it — so the
operator can write the same structure to `.status` unchanged.
