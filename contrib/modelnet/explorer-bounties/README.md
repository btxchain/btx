# Read-only bounty explorer (static)

Static reference UI for third-party bounty discovery. Serve these files from the
same origin as an implementation of the documented **read-only** browser bridge.

## Allowed HTTP surface

This sample calls **only**:

- `GET /api/v1/bounties` — list/search (`items[]`, `next_cursor`)
- `GET /api/v1/bounties/<id>` — single bounty detail (same card fields)

It never calls wallet RPCs, evaluation runners, mandate APIs, funding
`sign*`/`submit*`, or recovery import. Requests use `credentials: "omit"`, bounded
query input, explicit Search/Cancel, and `textContent` rendering (no
`innerHTML`). Production CSP should allow only self-hosted script/style/connect.

The bridge must normalize helper or proxy responses into the list contract
before this page can render. This directory is a front-end contract example,
not a verified live BTX deployment.

Normative RPC and schema docs: [../../../doc/bounties.md](../../../doc/bounties.md),
[../../../doc/bounty-rpc.md](../../../doc/bounty-rpc.md).
