# How it works

Each run reads the YAML, reads Aqua, works out the smallest change, and makes it. There is no state file, so it behaves the same on a laptop, in CI and in an Argo CD hook.

## Ownership

A policy the tool manages carries a marker on its own line in its description:

```
Dev/test baseline -- no image-compliance enforcement

managed-by: aquasec-casc/platform
```

- **`platform` is the instance name**, set in `aquasec-casc.yaml` at the config root, or with `--instance` or `AQUASEC_CASC_INSTANCE`. It is required, so two teams on one tenant never treat each other's policies as their own.
- **A policy marked by another instance is blocked** and reported, never changed.
- **The marker never shows as drift.** `export` strips it, and if someone removes it in the console, the next apply restores it.
- **A policy duplicated in the console carries the marker too.** No file describes the copy, so the next apply deletes it. Remove the marker line from the copy.

## What a run changes

| Situation | Result |
|---|---|
| In Git, missing in Aqua | **Created.** This is also how a policy deleted in the console comes back. |
| In Aqua without a marker | **Adopted**: the marker is added, plus any differences. |
| Ours, and it differs from Git | **Updated.** |
| Ours, with no file | **Deleted**: see [Deletion](#deletion). |
| `spec.enforcement: ReportOnly` | Differences and missing policies are reported, and nothing is written. |

**The file is the whole policy.** A control the file leaves out is off, so one switched on only in the console shows in `plan` and gets switched off. The same goes for an assurance policy's actions and exceptions.

- **A control left out:** only its switch goes off. Its settings stay as Aqua has them, because the console rewrites them on every save and they do nothing under an off switch.
- **A control in the file** is the whole of that control. A Port Block with only inbound ports blocks no outbound ones.

**Left as Aqua has them:**

- the description, if the file leaves it out;
- Bypass Scope, which exempts Aqua's own components on the default container policy;
- Additional Scope Criteria, because Aqua fills in its own when there are none;
- a control your Aqua version does not have;
- settings the tool [does not offer](schema-reference.md#not-offered). If a policy holds `excludeApplicationScopes`, `plan`, `apply` and `export` warn, without changing the exit code. Deleting or renaming that policy loses it.

**Three fields have defaults.** Left out, a new runtime policy is `enabled: true`, `enforce: false` and `runtimeType: container`. On an existing policy, a left-out field whose default differs from Aqua **fails the run and changes nothing**, since applying the default could disable a policy or stop it enforcing. `export` writes all three, so this only comes up in hand-written files. A policy's type cannot change either.

**Updates send the whole object**, with only these fields changed, because Aqua's update is a full replace.

**Then it reads the policy back.** Aqua answers success for a field it does not know and drops it, and fields vary by version. A field it did not keep is reported as `not kept by Aqua` and fails the run.

## Deletion

**Removing a file deletes the policy on the next apply**, as Argo CD does with pruning on. `plan` lists every pending deletion, and `--no-delete` holds them back for a run.

Nothing is deleted when:

- it does not carry **this instance's** marker;
- **Aqua ships it**;
- **the run has no files of that kind**, unless you pass `--allow-empty`, because an empty folder is more likely a wrong path than an instruction;
- **another file of that kind did not land**, because the orphan may be what it replaces;
- **`-f` was given a single file**, since that says nothing about the rest.

Creates and updates run before deletes, so a rename never leaves you with neither policy. `export` fails if it leaves out a policy that does not fit the schema, because with no file, an apply of that folder could delete it.

## Leaving: release and hand-over

Removing the files deletes the policies, so that is not how to stop managing them.

```
aquasec-casc release --dry-run            what would be released
aquasec-casc release [--name 'prod-*']    remove the marker
aquasec-casc release --to team-b          hand over to another instance
```

- **Only the marker line changes.** It needs no YAML, and `export` and `apply` adopt the policies again.
- **Release first, then remove the files.** While both remain, the next apply adopts the policies again, and then removing the files deletes them.
- **For a hand-over, put the files in the receiving configuration first.** Without them, its next apply deletes the policies.
- **On runtime policies, `author` stays as the tool's identity**, because the API rewrites it on every edit.

**`destroy` is for when the policies should go too.** `destroy -f DIR` deletes what those files describe, and plain `destroy` deletes everything carrying this instance's marker. It shows the plan and asks you to type the instance name, or `--yes` for scripts. An object without this instance's marker is blocked, and a policy Aqua ships is released instead.

## Aqua's own policies

Aqua ships about 18 runtime policies, and a Default and others for each assurance type.

- **They cannot be deleted**, and the tool never tries. Otherwise they are managed like any policy.
- **Their controls can change, and mostly their scope too.** The three runtime defaults and the predefined assurance policies lock their scope, so that change is reported as not allowed and the rest still applies.
- **Bypass Scope exists only on the default container and host policies.** Anywhere else it is reported as not allowed and not sent.

## Names

Aqua addresses policies by name and has no rename. `metadata.name` must be a DNS-style name, which Aqua's names often are not, so `spec.aquaName` holds the real one when they differ. `export` sets both.

```
metadata.name   aqua-default-runtime-policy
spec.aquaName   Aqua default runtime policy
```

Assurance policies are addressed by type and name, such as `image/Default`, which exports as `metadata.name: image-default`. Changing `assuranceType` describes a different policy: the new one is created, and the old one deleted.

## Safety defaults

- **Unknown fields are refused**, since Aqua would accept a mistyped control and change nothing.
- **`applicationScopes` is required**, since Aqua applies a policy with none to every workload.
- **A control its type does not offer is refused.** Aqua would store a CIS benchmark on an image policy, where it does nothing.
- **TLS is verified**, sign-in included.
- **No credential reaches output**, and the tool refuses to manage credential fields.

## Exit codes

```
validate   0 valid      1 invalid
plan       0 success    1 error     2 changes pending, with --detailed-exitcode
apply      0 done       1 error     2 something left pending, with --detailed-exitcode
export     0 done       1 error
release    0 done       1 error
destroy    0 done       1 error, or not confirmed
```

`apply` exits 0 by default because Argo CD fails a sync on any non-zero exit, and a routine apply that holds back an orphan must not block every future sync.
