# Adopting existing policies

A tenant that is already configured does not start again. `export` writes what is there as YAML, you commit it, and the first `apply` adds an ownership marker and changes nothing else.

```
$ aquasec-casc export --scope Global -o aqua/policies --instance platform
+ runtime-policy-devtest-baseline.yaml  ('devtest-baseline')
+ assurance-policy-image-default.yaml  ('image/Default', shipped by Aqua)
+ aquasec-casc.yaml  (instance: platform)
2 exported, 0 skipped -> aqua/policies

$ aquasec-casc plan -f aqua/policies
~ AssurancePolicy/image-default ('image/Default'): will be adopted
    + ownership marker (managed-by: aquasec-casc/platform)
~ RuntimePolicy/devtest-baseline: will be adopted
    + ownership marker (managed-by: aquasec-casc/platform)

$ aquasec-casc apply -f aqua/policies
```

`export` is read-only. **If `plan` shows anything but the marker, stop and read it**, because `apply` would make that change. It should not happen, so please report it.

## Before you adopt

- **`--scope` is required.** Repeat it into the same folder for other scopes, with `--force` to overwrite. `--kind` and `--name 'prod-*'` narrow what is exported.
- **Adopt only what you want managed.** From then on the file decides: a control switched on in the console goes back off at the next apply. Delete a file before the first apply to leave that policy with the console.
- **Aqua's own policies are included**, because the default policy is usually the first one changed. The tool never creates or deletes them. An API edit rewrites a policy's `author` to your identity, which cannot be undone, so delete their files if you will not change them.
- **Export into a folder you will apply covers the whole instance.** A policy this instance already manages that has no file there gets deleted by the next apply. `export` warns, and names them.
- **Some policies are not exported.** Another instance's are skipped, with a message. One that does not fit the schema gets no file and `export` exits 1, with the reason.

Settings the tool does not cover stay with the console, and an apply never changes them: [here is the list](schema-reference.md#not-offered). If a policy holds `excludeApplicationScopes`, `export`, `plan` and `apply` warn that it stays as it is. Renaming that policy loses it, because a rename is a delete and a create.

## Getting out again

`release` removes the marker and changes nothing else, so policies carry on unmanaged. `release --to other` hands them to another instance. Do not remove the files first, because that deletes the policies. See [Leaving](how-it-works.md#leaving-release-and-hand-over).
