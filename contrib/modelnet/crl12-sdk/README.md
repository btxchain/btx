# SDK integration — Cognitive Reserve Layer v1.2

Typed Python and TypeScript clients over the **43** additive CRL/1.2 HCP
operations. They do **not** rewrite `contrib/modelnet/hcp-sdk` or the v1.1
CRF client. There is **no** `/rpc` passthrough, **no** brand dispatch, and
**no** `executeAllocation` route: institutional instructions stay on the
existing v1.1 draft and approval flow.

`automatic_spend_atoms` stays **0**. Import is not custody credit. Desktop
context payloads are view/draft only and never call localhost execute.

```bash
python3 -m unittest -v python/test_body_id.py python/test_desktop_context.py python/test_portal_a11y.py
node --experimental-strip-types --test typescript/src/body_id.test.ts typescript/src/desktop_context.test.ts
python3 ../crl12/scripts/test_ux_prototype.py
```

Body-id formula (same HCP domain as native `HcpBodyId`):

```text
body_id = SHA384( UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
                  LE64(len(canonical_body)) || canonical_body )
```
