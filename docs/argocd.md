# Running it from Argo CD

Argo CD runs the tool as a **hook**: a Kubernetes `Job` that applies the
configuration to Aqua, once, on each sync. Argo CD knows nothing about Aqua. It
runs the Job and reads its exit code, so a failed apply fails the sync.

```
  Git repository                      Kubernetes                         Aqua
  ┌───────────────────┐  Argo CD      ┌─────────────────────────┐       ┌─────────┐
  │ aqua/             │  syncs        │ ConfigMap: the policies │       │         │
  │  policies/*.yaml  │ ────────────► │ Job: aquasec-casc apply │ ────► │ REST API│
  │  kustomization    │               │ Secret: credentials     │       │         │
  └───────────────────┘               └─────────────────────────┘       └─────────┘
```

**How a change reaches Aqua.** The policies are in a ConfigMap, an ordinary resource
Argo CD tracks. Merge a change and the ConfigMap is out of sync, so Argo CD syncs: it
applies the ConfigMap, then runs the Job against it. The Job is a `Sync` hook, and comes
after the ConfigMap, so that it reads the new files. (A `PreSync` hook would run first,
and read the old ones.)

**What this does not do.** The Job runs when Argo CD syncs, and at no other time. A
change made in the Aqua console between syncs stays until the next one, and nothing in
Argo CD notices it. To correct or report drift on a schedule, see
[Between syncs](#between-syncs).

## What you need

- Argo CD, and a Git repository it can read.
- The `aquasec-casc` image in a registry your cluster can pull from
  ([mirroring it](#mirroring-the-image)).
- An Aqua user for the tool. It needs to read and write runtime and assurance
  policies. On self-hosted Aqua that is a user name and password.
- HTTPS access from the Job's namespace to the Aqua console, and nothing else.

## 1. Put the credentials in a Secret

Create it by hand or with your secrets tooling. It does not go in Git.

```sh
kubectl create namespace aqua-casc

read -rs AQUA_PASSWORD                  # not on the command line, nor in shell history

kubectl -n aqua-casc create secret generic aqua-casc-credentials \
  --from-literal=AQUA_URL=https://aqua.internal.example \
  --from-literal=AQUA_USER=aquasec-casc \
  --from-file=AQUA_PASSWORD=<(printf %s "$AQUA_PASSWORD")
unset AQUA_PASSWORD
```

The console's address must be `https://`: the tool refuses to send credentials over
plain HTTP, and does not follow redirects.

If the console's certificate comes from an internal CA, add that CA too. Verifying
it is the default, and this is how it stays on:

```sh
kubectl -n aqua-casc create configmap aqua-casc-ca --from-file=ca.pem=internal-ca.pem
```

## 2. Lay out the repository

A small Helm chart, with the policies in a folder. Argo CD renders it itself; you do not
need Helm installed.

```
aqua/
├── Chart.yaml
├── policies/
│   ├── aquasec-casc.yaml                instance: platform
│   ├── runtime-policy-devtest.yaml
│   ├── runtime-policy-prod.yaml
│   └── assurance-policy-prod.yaml
└── templates/
    ├── configmap.yaml
    └── job.yaml
```

`policies/` is what `aquasec-casc validate -f aqua/policies` checks on a laptop or in a
pull request. `export` writes this layout too, for what already exists in Aqua: see
[adoption.md](adoption.md). Keep it flat, with `.yaml` names: a ConfigMap's keys cannot
hold folders, and the chart refuses to render anything else, rather than leave a file out.

`Chart.yaml`:

```yaml
apiVersion: v2
name: aqua-config
version: 1.0.0
```

`templates/configmap.yaml` takes every file in `policies/`, so a new file needs nothing
else, and **removing a file deletes its policy from Aqua on the next sync**. That is what
Git-driven deletion means. (The exceptions are safety nets: nothing is deleted of a kind
with no file at all, nor while another file of that kind has not landed.) Argo CD stores
a ConfigMap in an annotation as well, which limits it to about 256 KB: that holds a lot of
policies, but not without limit.

```yaml
{{- /* A file the glob below would miss has no policy in the Job, which deletes it. */ -}}
{{- range $path, $_ := .Files.Glob "policies/**" }}
{{- if not (regexMatch "^policies/[^/]+\\.yaml$" $path) }}
{{- fail (printf "%s will not reach the ConfigMap: keep policies/ flat, with .yaml names" $path) }}
{{- end }}
{{- end }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: aqua-casc-config
data:
{{ (.Files.Glob "policies/*.yaml").AsConfig | indent 2 }}
```

`templates/job.yaml`, with the internal CA's lines marked. Remove them if you have none:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  generateName: aqua-casc-apply-                 # see below: not a fixed name
  annotations:
    argocd.argoproj.io/hook: Sync
    argocd.argoproj.io/sync-wave: "1"            # after the ConfigMap, at wave 0
spec:
  backoffLimit: 0                   # do not retry a failed apply on its own
  ttlSecondsAfterFinished: 86400    # the Job and its log stay for a day
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false    # it never talks to Kubernetes
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      # imagePullSecrets: [{ name: your-registry }]    # if your mirror needs one
      containers:
        - name: aquasec-casc
          image: registry.internal.example/aquasec-casc:0.1.0   # your mirror; pin the digest
          args: ["apply", "-f", "/config"]
          envFrom:
            - secretRef:
                name: aqua-casc-credentials
          env:
            - { name: AQUA_CA_BUNDLE, value: /etc/aqua-ca/ca.pem }    # internal CA
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: 50m, memory: 64Mi }
            limits: { memory: 128Mi }
          volumeMounts:
            - { name: config, mountPath: /config, readOnly: true }
            - { name: ca, mountPath: /etc/aqua-ca, readOnly: true }   # internal CA
      volumes:
        - name: config
          configMap:
            name: aqua-casc-config
        - name: ca                                                    # internal CA
          configMap:                                                  # internal CA
            name: aqua-casc-ca                                        # internal CA
```

**Keep `generateName`.** With a fixed name and `BeforeHookCreation`, Argo CD can read the
previous Job's status when it checks the new one, and report a failed apply as a
successful sync. We saw exactly that on Argo CD 3.6. It is also why this is a Helm chart:
kustomize refuses `generateName`.

The tool needs no ServiceAccount permissions and writes nothing to the cluster:
there is no state to keep.

To hold it to the Aqua console and nothing else, add a NetworkPolicy to `templates/`.
Its sync wave puts it in place before the Job:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aqua-casc
  annotations:
    argocd.argoproj.io/sync-wave: "-1"
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  egress:
    - to:
        - ipBlock: { cidr: 10.0.0.10/32 }   # the Aqua console
      ports:
        - { protocol: TCP, port: 443 }
    - to:                                   # DNS, if the console has a name
        - namespaceSelector: {}
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

## 3. Create the Argo CD Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: aqua-config
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://git.internal.example/platform/aqua-config.git
    targetRevision: main
    path: aqua
  destination:
    server: https://kubernetes.default.svc
    namespace: aqua-casc
  syncPolicy:
    automated:
      prune: true
```

Leave out `automated` to press Sync yourself for the first runs.

There is deliberately no `retry`. Aqua locks an account after repeated failed sign-ins,
and a wrong password retried automatically gets there quickly. A failed revision stays
failed until you press Sync or merge a fix.

## 4. Try it

Start safely: make the Job's arguments `["plan", "-f", "/config"]`. `plan` never writes,
and the sync shows you what `apply` would do. When that reads right, change it to
`apply`. To watch a policy for a while first, set `spec.enforcement: ReportOnly` on it:
that policy is then reported and not corrected. It does not hold back deletions, so
add `--no-delete` to the arguments if files may be missing.

**A file with the name of a policy already in Aqua takes that policy over**, and turns off
every control it leaves out. Under automated sync nobody reads a plan first, so start from
`export`, which writes what is there: see [adoption.md](adoption.md).

Sync, then read the log of the latest Job:

```sh
kubectl -n aqua-casc logs "$(kubectl -n aqua-casc get jobs --sort-by=.metadata.creationTimestamp -o name | tail -1)"
```

```
Using environment.
~ RuntimePolicy/devtest-baseline: adopted
    + ownership marker (managed-by: aquasec-casc/platform)
0 unchanged, 0 created, 0 updated, 1 adopted, 0 deleted
```

`--output json` in the arguments makes standard output JSON for your tooling. The
`Using environment.` line goes to standard error, and `kubectl logs` shows both.

## When a sync fails

The Job exits non-zero, and the sync operation fails: *one or more synchronization tasks
completed unsuccessfully*. **The Application can still read `Synced`**, since its
ConfigMap matches Git, so alert on the last operation's phase and not on the sync status.
The log says why:

| Log line | What it means | What to do |
|---|---|---|
| `error: ...: N validation problem` | A file does not match the schema. Nothing was sent. | Fix the file. `validate` catches this before a merge. |
| `x ...: FAILED` | Aqua refused it, or the tool did, and the message says which. The other policies still applied, and nothing of that kind was deleted. | Often a scope that does not exist in Aqua, or a file that does not say `enabled`, `enforce` or `runtimeType` where Aqua differs from their defaults. |
| `not kept by Aqua: ...` | Aqua accepted the write and did not keep a field. Usually a field this Aqua version lacks. | Update Aqua, or remove the setting from the file. |
| `error: Sign-in failed` | The credentials, or the console's address. | Check the Secret. Aqua locks an account after repeated failures. |
| `error: ... could not connect to Aqua` | No route, or the NetworkPolicy. | Check the address and egress. |
| `the console's TLS certificate could not be verified` | The CA is not trusted. | Set `AQUA_CA_BUNDLE`. |

These do **not** fail the sync, because they need a person and not a retry. Read the log
if a sync looks too quiet:

| Log line | What it means |
|---|---|
| `x ...: blocked` | Another instance manages this policy. Nothing of that kind is deleted in this run. Remove it from one of them, or `release --to`. |
| `? ...: orphaned` | A policy with no file was not deleted, and the message says why. |
| `not allowed: ...` | A change Aqua does not allow, such as the scope of a default policy. The rest applied. |

`--detailed-exitcode` exists for scripts. Do not use it in this Job: exit 2 fails the sync.

**Tested** on Argo CD 3.6 on a local cluster, following this page, against a SaaS tenant: a
merged change reaching Aqua, a schema error failing the sync, and a renamed policy being
created and the old one deleted.

## Between syncs

A console change stays until the next sync, and Argo CD does not know about it. Where
that gap matters, run the same image on a schedule, as a `CronJob` with the same
`jobTemplate`, the ConfigMap and the Secret:

- to report: `args: ["plan", "-f", "/config", "--detailed-exitcode"]`, and alert on a failed
  job (exit 2 means drift);
- to correct: `args: ["apply", "-f", "/config"]`.

## Mirroring the image

The image is a single artifact with its dependencies pinned, and needs nothing at
run time other than the Aqua API.

Where there is a connected machine, with your cluster's architecture:

```sh
docker pull --platform linux/amd64 andreazorzetto/aquasec-casc:0.1.0
docker save andreazorzetto/aquasec-casc:0.1.0 -o aquasec-casc-0.1.0.tar
sha256sum aquasec-casc-0.1.0.tar > aquasec-casc-0.1.0.tar.sha256
```

Carry both files across, then on the inside:

```sh
sha256sum -c aquasec-casc-0.1.0.tar.sha256
docker load -i aquasec-casc-0.1.0.tar
docker tag andreazorzetto/aquasec-casc:0.1.0 registry.internal.example/aquasec-casc:0.1.0
docker push registry.internal.example/aquasec-casc:0.1.0
```

Or build it yourself from a clean checkout. It needs the base image and PyPI, or your
mirrors of them. A mirror behind an internal CA also needs that CA in the build, so
mirroring the image above is simpler:

```sh
docker build -t aquasec-casc:0.1.0 \
  --build-arg BASE_IMAGE=registry.internal.example/python:3.12-slim \
  --build-arg PIP_INDEX_URL=https://pypi.internal.example/simple .
```
