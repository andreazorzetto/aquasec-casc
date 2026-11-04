# Running it from Argo CD

Argo CD runs the tool as a **PreSync hook**: a Kubernetes `Job` that applies the
configuration to Aqua, once, before each sync. Argo CD knows nothing about Aqua.
It runs the Job and reads its exit code, so a failed apply fails the sync.

```
  Git repository                      Kubernetes                         Aqua
  ┌───────────────────┐  Argo CD      ┌─────────────────────────┐       ┌─────────┐
  │ aqua/             │  syncs        │ ConfigMap: the policies │       │         │
  │  policies/*.yaml  │ ────────────► │ Job: aquasec-casc apply │ ────► │ REST API│
  │  kustomization    │               │ Secret: credentials     │       │         │
  └───────────────────┘               └─────────────────────────┘       └─────────┘
```

**What this does not do.** The Job runs when Argo CD syncs, and at no other time.
A change made in the Aqua console between syncs stays until the next one. To
correct drift on a schedule, make the Argo CD Application sync periodically, or
run `plan --detailed-exitcode` as a scheduled job and alert on exit code 2.

## What you need

- Argo CD, and a Git repository it can read.
- The `aquasec-casc` image in a registry your cluster can pull from
  ([mirroring it](#mirroring-the-image)).
- An Aqua user for the tool. It needs to read and write runtime and assurance
  policies. On self-hosted Aqua that is a user name and password.
- Network access from the Job's namespace to the Aqua console, and nothing else.

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

```
aqua/
├── kustomization.yaml
├── job.yaml
└── policies/
    ├── aquasec-casc.yaml                instance: platform
    ├── runtime-policy-devtest.yaml
    ├── runtime-policy-prod.yaml
    └── assurance-policy-prod.yaml
```

`policies/` is what `aquasec-casc validate -f policies` checks on a laptop or in a
pull request. `export` writes this layout too, for what already exists in Aqua:
see [adoption.md](adoption.md).

`kustomization.yaml` turns the folder into a ConfigMap. A ConfigMap's keys cannot
hold folders, so keep `policies/` flat, and list each file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: aqua-casc
resources:
  - job.yaml
configMapGenerator:
  - name: aqua-casc-config
    files:
      - policies/aquasec-casc.yaml
      - policies/runtime-policy-devtest.yaml
      - policies/runtime-policy-prod.yaml
      - policies/assurance-policy-prod.yaml
generatorOptions:
  disableNameSuffixHash: true      # the Job refers to it by this name
  annotations:
    # Argo CD runs PreSync hooks before it applies anything else, so the
    # ConfigMap has to be a hook too, and go first.
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/sync-wave: "-1"
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
```

**A file left out of this list is deleted from Aqua on the next sync**, since no
file then describes the object. That is what Git-driven deletion means, so review
this list like the policies themselves. (The exceptions are safety nets: nothing is
deleted of a kind with no file at all, nor while another file of that kind fails.) A ConfigMap also has a size limit of about
1 MB, which holds a lot of policies, but not without limit.

`job.yaml`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: aqua-casc-apply
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  backoffLimit: 0                   # do not retry a failed apply on its own
  ttlSecondsAfterFinished: 86400
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false    # it never talks to Kubernetes
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: aquasec-casc
          image: registry.internal.example/aquasec-casc:0.1.0   # your mirror; pin the digest
          args: ["apply", "-f", "/config"]
          envFrom:
            - secretRef:
                name: aqua-casc-credentials
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
      volumes:
        - name: config
          configMap:
            name: aqua-casc-config
```

With an internal CA, add `AQUA_CA_BUNDLE` and mount the CA:

```yaml
          env:
            - { name: AQUA_CA_BUNDLE, value: /etc/aqua-ca/ca.pem }
          volumeMounts:
            - { name: ca, mountPath: /etc/aqua-ca, readOnly: true }
      volumes:
        - name: ca
          configMap: { name: aqua-casc-ca }
```

The tool needs no ServiceAccount permissions and writes nothing to the cluster:
there is no state to keep. To hold it to the Aqua console and nothing else:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aqua-casc
  namespace: aqua-casc
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
    automated: {}
```

Everything this Application creates is a hook, so Argo CD shows it as *Synced* with
no resources of its own. Start without `automated` if you want to press Sync
yourself for the first runs.

## 4. Try it

Start safely. Set `spec.enforcement: ReportOnly` on each policy: the run then
reports drift and changes nothing. Or use `plan` as the Job's first argument
instead of `apply`, which never writes.

Sync, then read the Job's log:

```sh
kubectl -n aqua-casc logs job/aqua-casc-apply
```

```
Using environment.
~ RuntimePolicy/devtest-baseline: adopted
    + ownership marker (managed-by: aquasec-casc/platform)
0 unchanged, 0 created, 0 updated, 1 adopted, 0 deleted
```

Add `--output json` to the Job's arguments for a log your tooling can parse.

## When a sync fails

The Job exits non-zero, and Argo CD marks the sync failed. The log says why:

| Log line | What it means | What to do |
|---|---|---|
| `error: ... unknown field` | A file does not match the schema. Nothing was sent. | Fix the file. `validate` catches this before a merge. |
| `FAILED` on a policy | Aqua refused it; the message is Aqua's. The other policies still applied. | Often a scope that does not exist in Aqua. |
| `not kept by Aqua: ...` | Aqua accepted the write and did not keep a field. Usually a field this Aqua version lacks. | Update Aqua, or remove the setting from the file. |
| `blocked` | Another instance manages this policy. Does not fail the run. | Remove it from one of them, or `release --to`. |
| `the console's TLS certificate could not be verified` | The CA is not trusted. | Set `AQUA_CA_BUNDLE`. |

The default exit code of `apply` does not fail a sync over something left pending,
such as a blocked policy, only over an error. `--detailed-exitcode` exists for
scripts; do not use it in this Job, because exit 2 fails the sync.

## Mirroring the image

The image is a single artifact with its dependencies pinned, and needs nothing at
run time other than the Aqua API.

Where there is a connected machine:

```sh
docker pull andreazorzetto/aquasec-casc:0.1.0
docker save andreazorzetto/aquasec-casc:0.1.0 -o aquasec-casc-0.1.0.tar
sha256sum aquasec-casc-0.1.0.tar
```

Carry the file across, then on the inside:

```sh
sha256sum -c ...                   # check it against the sum above
docker load -i aquasec-casc-0.1.0.tar
docker tag andreazorzetto/aquasec-casc:0.1.0 registry.internal.example/aquasec-casc:0.1.0
docker push registry.internal.example/aquasec-casc:0.1.0
```

Or build it yourself from a clean checkout: `docker build -t aquasec-casc:0.1.0 .`
needs the base image and PyPI, or your mirrors of them.
