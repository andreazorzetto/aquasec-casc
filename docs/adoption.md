# Bringing existing configuration under management

A tenant that is already configured does not start again. `export` writes what is
there as YAML; you commit it; the first `apply` adds the ownership marker and
changes nothing else.

```
aquasec-casc export --scope Global -o aqua/policies --instance platform
```

`export` is read-only. It writes one file per policy, runtime and assurance alike
(`--kind` for only one), and `aquasec-casc.yaml` with the instance name:

```
+ runtime-policy-devtest-baseline.yaml  ('devtest-baseline')
+ assurance-policy-image-default.yaml  ('image/Default', shipped by Aqua)
+ aquasec-casc.yaml  (instance: platform)
2 exported, 0 skipped -> aqua/policies
```

Check that it holds, then adopt:

```
$ aquasec-casc plan -f aqua/policies
~ AssurancePolicy/image-default ('image/Default'): will be adopted
    + ownership marker (managed-by: aquasec-casc/platform)
~ RuntimePolicy/devtest-baseline: will be adopted
    + ownership marker (managed-by: aquasec-casc/platform)

$ aquasec-casc apply -f aqua/policies
~ AssurancePolicy/image-default ('image/Default'): adopted
    + ownership marker (managed-by: aquasec-casc/platform)
~ RuntimePolicy/devtest-baseline: adopted
    + ownership marker (managed-by: aquasec-casc/platform)
0 unchanged, 0 created, 0 updated, 2 adopted, 0 deleted

$ aquasec-casc plan -f aqua/policies --detailed-exitcode
2 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted
```

**If `plan` shows anything but the marker, stop and read it.** It should not; please
report it. `apply` would make that change.

## What to know before adopting

- **`--scope` is required**, and exports what applies to that application scope.
  Repeat it into the same folder for others (`--force` overwrites).
- **Adopt only what you want managed.** Everything exported and applied is from then
  on the file's: a control switched on in the console goes back off at the next
  apply. Delete a file before the first apply to leave that policy with the console,
  or pick with `--name 'prod-*'`.
- **Policies Aqua ships** are included, because the default policy is usually the
  first one changed. The tool never creates or deletes them. An API edit rewrites
  a policy's `author` to your identity, which cannot be undone, and on a shared tenant
  that may matter: delete their files if you are not going to change them.
- **Objects another instance manages** are skipped, with a message.
- **A policy that does not fit the schema** gets no file, and `export` exits 1. The
  message says why, and it stays with the console until that is fixed.
- **Export into a folder you will apply covers the whole instance.** Anything this
  instance already manages that `--scope` or `--name` leaves out has no file there, and
  an apply deletes it. `export` warns, and names them.
- **Exported files say what is on.** Off controls are left out, since left out means
  off. Their settings stay in Aqua, as the console wrote them.

## Settings the tool does not cover

They stay with the console, and an apply never changes them. The list and the reason
for each is in [schema-reference.md](schema-reference.md#not-offered).

One of them changes what a policy covers, so it gets a warning: if Aqua holds
`excludeApplicationScopes` on a policy, `export` says it left it out, and `plan` and `apply`
say it stays as it is. Renaming that policy loses it, because a rename is a delete and a create.

## Getting out again

`release` removes the marker and changes nothing else, so policies carry on unmanaged;
`release --to other` hands them to another instance. See
[how-it-works.md](how-it-works.md#leaving-release-and-hand-over). Removing a *file*
is not the way out: that deletes the policy.
