# Examples

| Folder | Use it for |
|---|---|
| [playground](playground) | **Start here.** Three disabled policies scoped to `Global` -- a baseline, a stricter profile, and one with every control on: safe to apply on any tenant, shared ones included. Walkthrough: [docs/try-it.md](../docs/try-it.md). |
| [two-scope](two-scope) | A realistic layout: an audit-only dev/test baseline and an enforcing acceptance/production one. Needs application scopes named `DevTest` and `AccProd` -- Aqua refuses a policy whose scope does not exist (HTTP 400), and the tool does not create scopes yet. The policies are **enabled**: apply only to a tenant you own. |
