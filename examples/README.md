# Examples

| Folder | Use it for |
|---|---|
| [playground](playground) | **Start here.** Three disabled runtime policies -- a baseline, a stricter profile, and one with every control on -- and an assurance policy scoped to match nothing: safe to apply on any tenant, shared ones included. Walkthrough: [docs/try-it.md](../docs/try-it.md). |
| [two-scope](two-scope) | A realistic layout: an audit-only dev/test baseline and an enforcing acceptance/production one, runtime and assurance. Needs application scopes named `DevTest` and `AccProd` -- Aqua refuses a policy whose scope does not exist (HTTP 400), and the tool does not create scopes yet. The policies are **enabled**: apply only to a tenant you own. |
| [github-actions](github-actions) | A workflow for your configuration repository: plan on a pull request, apply on merge. For Argo CD, see [docs/argocd.md](../docs/argocd.md). |
