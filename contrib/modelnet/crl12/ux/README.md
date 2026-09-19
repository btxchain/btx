# Offline neutral UX prototype

Open `index.html` in a browser. All data is synthetic and all actions only change local display state. The prototype makes no external requests and contains no credentials. It illustrates the six-screen experience, separated financial/operational metrics, role bindings and draft-only interactions.

The in-tree portal copy is `contrib/modelnet/crl12-portal/index.html` and must stay identical. Static a11y (44px targets, aria-live, family-group read-only, no network) is `contrib/modelnet/crl12-sdk/python/test_portal_a11y.py`. Optional Playwright interaction is `contrib/modelnet/crl12/scripts/test_ux_prototype.py` (HONEST_NOT_RUN if Playwright/Chromium is absent).

`desktop-context.example.json` uses an application-specific context namespace. It is not a new standard FDC3 context type. A production desktop adapter validates tenant/scope and opens a view or explicit draft; the context never authorizes execution.
