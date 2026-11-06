# Examples

| Folder | Use it for |
|---|---|
| [playground](playground) | **Start here.** Safe on any tenant: disabled runtime policies, and an assurance policy that matches nothing. Follow the [guided tour](../docs/try-it.md). |
| [two-scope](two-scope) | A realistic layout: audit-only dev/test and enforcing acceptance/production. It needs application scopes named `DevTest` and `AccProd` in Aqua, and its policies are **enabled**, so apply it only to a tenant you own. |
| [github-actions](github-actions) | A workflow for your configuration repository: plan on a pull request, apply on merge. |
